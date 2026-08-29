package io.just.sast.knowledge.engine;

import io.just.sast.analysis.taint.ForwardOrigins;
import io.just.sast.analysis.taint.OriginSupport;
import io.just.sast.analysis.taint.ValueOrigin;
import io.just.sast.blackboard.Blackboard;
import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.HopKind;
import io.just.sast.config.Rule;
import io.just.sast.cpg.build.Cfg;
import io.just.sast.cpg.build.CfgEdge;
import io.just.sast.cpg.build.CfgLabel;
import io.just.sast.cpg.build.CpgIndex;
import io.just.sast.cpg.graph.Edge;
import io.just.sast.cpg.graph.EdgeType;
import io.just.sast.cpg.graph.Node;
import io.just.sast.cpg.graph.NodeType;
import io.just.sast.model.ClassInfo;
import io.just.sast.model.Descriptor;
import io.just.sast.model.HandleRef;
import io.just.sast.model.InsnFact;
import io.just.sast.model.InvokeDynamicRef;
import io.just.sast.model.MethodInfo;
import io.just.sast.model.MethodRef;
import io.just.sast.model.Op;
import io.just.sast.model.TypeRef;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 前向对象污点引擎（引擎库，非知识源；一个实例依次跑粗扫与精扫两轮，共享索引与事实）。
 * GadgetInspector 式正向：从 magic entry / OIS 读出发，方法摘要 + 事实不动点，
 * worklist 只处理受影响方法；不动点后一次性做 sink 判定。
 * 事实单调只增，路径取最短；死胡同按记录时的事实版本失效（版本推进后清理）。
 * 两轮共享：粗扫（类级事实）产出的污点事实是精扫的初值——精扫只增量补充接口/代理/反射边。
 *
 * 精扫选项：
 * - expandInterfaces：污点 receiver/实参命中接口调用且仅声明目标（实现>枚举上限）时，
 *   按上限展开实现类 addThis/addParam
 * - threadProxy：receiver 为 Proxy.newProxyInstance 结果时，handler 实参的解析目标类 addThis
 * - reflectiveResolve：Method.invoke 的 Method 对象来自 getMethod/getDeclaredMethod 且方法名
 *   为常量时，向同名方法 addParam/addThis
 *
 * model 规则（YAML 声明式摘要）在两轮中都消费：actions 的 this←argN 为容器投毒（Map.put 语义）、
 * return←src 为透传（Map.get 语义）。
 */
public final class ForwardEngine {

    private static final int MAX_DEPTH = 20;
    private static final int MAX_ROUNDS = 32;
    private static final int MAX_HOPS = 10;
    /** 判定步数预算（有界恢复：预算耗尽停止扩散，保留已有事实与 sink 判定）。 */
    private static final int STEP_BUDGET = 20_000_000;
    /** 方法效果处理上限。 */
    private static final int METHOD_PASS_CAP = 1_000_000;
    /** 死胡同缓存清理阈值（条目数超过即清除过期版本）。 */
    private static final int DEAD_END_SWEEP = 65_536;
    /**
     * 事实：键 → 前向路径（首元素为 ENTRY hop）。引擎由一个 ANALYSIS 知识源独占，
     * 因而这里使用普通容器；并行化的知识源之间不会共享此实例。把单所有者状态写成
     * ConcurrentHashMap 会让每一次事实读取和合并都支付不必要的并发协议成本。
     */
    private final Map<String, List<ChainHop>> thisTainted = new HashMap<>();
    private final Map<String, List<ChainHop>> fieldTainted = new HashMap<>();
    private final Map<String, List<ChainHop>> returnTainted = new HashMap<>();
    private final Map<String, List<ChainHop>> paramTainted = new HashMap<>();
    /** 方法 + 来源的结构化键，避免热路径为每次递归分配 origin.toString()。 */
    private record TaintKey(String methodKey, ValueOrigin origin) {}

    /** 死胡同缓存：值为记录时的事实版本（factVersion 单调递增，跨轮有效）。 */
    private final Map<TaintKey, Long> deadEnds = new HashMap<>();
    /** 正向摘要缓存：只缓存已证明的污点路径；事实版本变化后自动失效，避免
     * 把一个暂时受益于环守卫的 null 误记为全局死胡同。 */
    private record TaintMemo(long factVersion, List<ChainHop> path) {}
    private final Map<TaintKey, TaintMemo> taintMemo = new HashMap<>();

    /** 字段读者索引：fieldKey → 方法集合（新字段事实时入队）。构造期单线程构建。 */
    private final Map<String, Set<String>> fieldReaders = new HashMap<>();
    /** 方法内会产生跨方法/字段效果的指令；无效果方法无需触发 origin 抽象解释。 */
    private final Map<String, List<InsnFact>> effectInstructions = new HashMap<>();
    /** 调用者索引：方法键 → 调用点（return 事实传播用，含接口反向分发）。构造期单线程构建。 */
    private final Map<String, List<Node>> callers = new HashMap<>();

    /** 反序列化可达方法集（前向 BFS 边界：只在该子集内传播；两轮共用，首轮构建）。 */
    private final Set<String> reachable = new HashSet<>();
    private static final int REACHABLE_CAP = 200_000;
    private static final int INTERFACE_EXPAND_CAP = 2000;
    private static final int REFLECTIVE_REACHABLE_CAP = 2000;
    /** lambda 绑定：方法#实参槽 → 该参数将持有的 lambda 实现方法（含接口实参→实现参数的槽位偏移）。 */
    private final Map<String, List<LambdaBind>> lambdaBinds = new HashMap<>();
    /** lambda 实现绑定（实现方法的定位三元组；槽位偏移在消费时按实际接口调用点计算）。 */
    private record LambdaBind(String implOwner, String implName, String implDesc) {}
    /** LambdaMetafactory 的实现句柄与 SAM 描述符；仅用于通用 invokedynamic 数据流映射。 */
    private record LambdaShape(HandleRef implementation, String samDescriptor) {}
    /** 虚分派候选键；同一签名在粗/精扫和多个调用点之间共享解析结果。 */
    private record DispatchKey(String owner, String name, String desc) {}
    /** 已通过可序列化与 JVM 可覆写门的候选，保留原候选 owner 以支持精确类型分派。 */
    private record DispatchTarget(String candidateOwner, String resolvedOwner) {}
    /** 层次版本对应的完整子类型闭包；精确 receiver 路径只需消费 raw。 */
    private record DispatchCandidates(long revision, List<String> raw) {}
    /** 层次版本对应的已过滤分派目标；按需构造，避免精确类型路径先扫描全闭包。 */
    private record ResolvedDispatchCandidates(long revision, List<DispatchTarget> targets) {}
    private final Map<DispatchKey, DispatchCandidates> dispatchCache = new HashMap<>();
    private final Map<DispatchKey, ResolvedDispatchCandidates> resolvedDispatchCache = new HashMap<>();
    /** Unknown Method.invoke targets are resolved against the already indexed sink calls;
     * the result is cached by name/parameter shape so reflective-heavy jars do not rescan
     * the complete call graph for every metadata object. */
    private final Map<String, List<MethodInfo>> reflectiveSinkCache = new HashMap<>();
    private final Blackboard bb;
    private final OriginSupport support;
    /**
     * Stable per-method view shared by both coarse/refined rounds. ForwardOrigins already owns
     * the canonical cache; this second index avoids rebuilding CfgKey strings at every callsite
     * and lets the hot engine use a small per-exploration map below.
     */
    private Options options;
    /** 事实版本：单调递增，永不重置（死胡同缓存跨轮失效判定；事实集合跨轮单调只增）。 */
    private long factVersion;
    /** 本轮统计/预算（每轮重置；引擎单所有者，使用普通计数器）。 */
    private long factCount;
    private long steps;
    private long methodPasses;
    private final Deque<String> queue = new ArrayDeque<>();
    /** 队列去重伴随集：queue 中现存的方法键（事实驱动的大语料入队有 5-6 倍重复；
     *  poll 时移除——处理期间的新入队会进下一轮）。 */
    private final Set<String> pending = new HashSet<>();
    /** 调用图后序号（GadgetInspector 技术：被调者先、调用者后，事实沿调用链单遍向下流动，
     *  消除"调用者先于被调者处理→事实迟到→重复处理"的 worklist churn）。 */
    private Map<String, Integer> topoOrder;

    /** 引擎选项（每轮指定）。 */
    public record Options(boolean expandInterfaces, boolean threadProxy, boolean reflectiveResolve,
                          boolean reachablePrune) {

        /** 粗扫：类级事实 + 可达剪枝，快。 */
        public static Options coarse() {
            return new Options(false, false, false, true);
        }

        /** 精扫：分配点敏感 + 接口/代理/反射补全（可达剪枝同样生效，可达集与粗扫共用）。 */
        public static Options refined() {
            return new Options(true, true, true, true);
        }
    }

    /** 单次探索的私有上下文：环守卫 + 截断标记（深度/预算截断产生的 null 不进死胡同缓存）。 */
    private static final class Explore {
        final Set<TaintKey> visiting = new HashSet<>();
        final Map<String, ForwardOrigins.Result> origins = new HashMap<>(4);
        boolean truncated;
    }


    public ForwardEngine(Blackboard bb) {
        this.bb = bb;
        this.support = bb.originSupport();
        buildIndexes();
    }

    private ForwardOrigins.Result origins(MethodInfo method, Explore exploration) {
        String key = OriginSupport.methodKey(method);
        if (exploration != null) {
            ForwardOrigins.Result local = exploration.origins.get(key);
            if (local != null) {
                return local;
            }
            ForwardOrigins.Result result = support.origins().compute(method);
            exploration.origins.put(key, result);
            return result;
        }
        return support.origins().compute(method);
    }

    private ForwardOrigins.State stateAt(MethodInfo method, int offset, Explore exploration) {
        return origins(method, exploration).stateBefore().get(offset);
    }

    private void buildIndexes() {
        for (Node method : bb.graph().nodesOfType(NodeType.METHOD)) {
            MethodInfo info = support.methodOf(method.owner(), method.name(), method.descriptor());
            if (info == null) {
                continue;
            }
            String key = OriginSupport.methodKey(info);
            List<InsnFact> effects = new ArrayList<>();
            CpgIndex.MethodSlice slice = support.cpgIndex().slice(key);
            if (slice != null) {
                for (int offset : slice.fieldReadOffsets()) {
                    InsnFact insn = info.insnAt(offset);
                    fieldReaders.computeIfAbsent(insn.fieldRef().owner() + "#" + insn.fieldRef().name(),
                            k -> new HashSet<>()).add(key);
                }
                for (int offset : slice.effectOffsets()) {
                    effects.add(info.insnAt(offset));
                }
            } else {
                // Direct Blackboard construction remains supported for extensions/tests
                // that do not have a frontend-produced CpgIndex.
                for (InsnFact insn : info.instructions()) {
                    if (insn.op().isFieldRead()) {
                        fieldReaders.computeIfAbsent(insn.fieldRef().owner() + "#" + insn.fieldRef().name(),
                                k -> new HashSet<>()).add(key);
                    }
                    Op op = insn.op();
                    if (op.isFieldWrite() || op == Op.AASTORE || op.isInvoke()
                            || (op.isReturn() && op != Op.RETURN && op != Op.ATHROW)) {
                        effects.add(insn);
                    }
                }
            }
            if (!effects.isEmpty()) {
                effectInstructions.put(key, List.copyOf(effects));
            }
            for (Edge edge : method.in()) {
                if (edge.type() == EdgeType.INVOKES || edge.type() == EdgeType.DISPATCHES) {
                    callers.computeIfAbsent(key, k -> new ArrayList<>()).add(edge.from());
                }
            }
        }
        // 接口反向分发：接口方法节点的调用点并入实现类方法（同反向引擎语义）
        for (Node method : bb.graph().nodesOfType(NodeType.METHOD)) {
            String owner = method.owner();
            MethodInfo info = support.methodOf(owner, method.name(), method.descriptor());
            if (info == null || !method.in().isEmpty()) {
                continue;
            }
            for (String itf : bb.hierarchy().transitiveInterfaces(owner)) {
                Node itfNode = bb.graph().findMethodNode(itf, info.name(), info.descriptor());
                if (itfNode != null) {
                    for (Edge edge : itfNode.in()) {
                        if (edge.type() == EdgeType.INVOKES || edge.type() == EdgeType.DISPATCHES) {
                            callers.computeIfAbsent(OriginSupport.methodKey(info), k -> new ArrayList<>()).add(edge.from());
                        }
                    }
                }
            }
        }
    }

    public void run(Options options) {
        this.options = options;
        if (options.reachablePrune() && reachable.isEmpty()) {
            computeReachable();
        }
        boolean firstRun = factVersion == 0;
        // 预算按轮重置（每轮独立预算）。非首轮只重入队"受影响方法"：
        // 已污点类的方法 + 已有参数/返回事实的方法 + 已污点字段的读者——
        // 与独立精扫引擎的种子+事实驱动增长等价，规模受控（全量可达集重处理会烧尽预算）；
        // 新事实派生的受影响方法由 addThis/addField/addReturn/addParam 的入队机制自动扩散。
        steps = 0;
        methodPasses = 0;
        factCount = 0;
        taintMemo.clear();
        deadEnds.clear();
        if (!firstRun) {
            requeueAffected();
        }
        seedEntries();
        ensureTopoOrder();
        int rounds = 0;
        while (!queue.isEmpty() && rounds < MAX_ROUNDS && steps < STEP_BUDGET
                && methodPasses < METHOD_PASS_CAP) {
            rounds++;
            List<String> current = new ArrayList<>();
            for (String key; (key = queue.pollFirst()) != null; ) {
                pending.remove(key);
                current.add(key);
            }
            // 后序处理（被调者先）：事实合流依赖这个确定顺序；副作用传播保持串行，
            // 避免全局步数预算在并行调度下改变覆盖范围。origin 仍按需计算，只有真实
            // 消费到某个方法时才支付 CFG/抽象解释成本。
            if (topoOrder != null) {
                current.sort(java.util.Comparator
                        .comparingInt((String k) -> topoOrder.getOrDefault(k, Integer.MAX_VALUE))
                        .thenComparing(String::compareTo));
            }
            processCurrentSerial(current);
        }
        if (!queue.isEmpty()) {
            // 截断未收敛：剩余事实未处理，本轮结果可能欠完备（不静默）
            if (steps >= STEP_BUDGET) {
                bb.markIncomplete("FORWARD_STEP_CAP");
            }
            if (methodPasses >= METHOD_PASS_CAP) {
                bb.markIncomplete("FORWARD_METHOD_CAP");
            }
            if (rounds >= MAX_ROUNDS) {
                bb.markIncomplete("FORWARD_ROUND_CAP");
            }
            if (steps < STEP_BUDGET && methodPasses < METHOD_PASS_CAP && rounds < MAX_ROUNDS) {
                bb.markIncomplete("FORWARD_QUEUE_REMAINS");
            }
            io.just.sast.util.JustLogger.warn("前向污点[{}]：轮数/预算截断，剩余队列 {} 个方法（结果可能欠完备）",
                    options.expandInterfaces() ? "精扫" : "粗扫", queue.size());
            queue.clear();
            pending.clear();
        }
        // 不动点后一次性 sink 判定（仅可达子集内的 sink）
        for (Node call : bb.graph().nodesOfType(NodeType.CALL)) {
            if (options.reachablePrune() && !reachable.contains(OriginSupport.methodKey(call))) {
                continue;
            }
            bb.ruleEngine().matchingSink(call).ifPresent(rule -> checkSink(call, rule));
        }
        io.just.sast.util.JustLogger.info("前向污点[{}]：可达 {} 个方法，事实 {} 个，轮数 {}",
                options.expandInterfaces() ? "精扫" : "粗扫", reachable.size(), factCount, rounds);
    }

    private void processCurrentSerial(List<String> current) {
        for (String key : current) {
            MethodInfo method = resolveMethodKey(key);
            if (method != null) {
                methodPasses++;
                processEffects(method);
            }
        }
    }


    /** 精扫重入队（受影响方法）：已污点类的全部方法 + 参数/返回事实方法 + 已污点字段的读者。 */
    private void requeueAffected() {
        for (String cls : thisTainted.keySet()) {
            ClassInfo info = bb.hierarchy().classInfo(cls);
            if (info == null) {
                continue;
            }
            for (MethodInfo method : info.methods()) {
                if (!options.reachablePrune() || reachable.contains(OriginSupport.methodKey(method))) {
                    enqueue(OriginSupport.methodKey(method));
                }
            }
        }
        for (String key : paramTainted.keySet()) {
            enqueue(key.substring(0, key.lastIndexOf('#')));
        }
        returnTainted.keySet().forEach(this::enqueue);
        for (Map.Entry<String, List<ChainHop>> e : fieldTainted.entrySet()) {
            Set<String> readers = fieldReaders.get(e.getKey());
            if (readers != null) {
                readers.forEach(this::enqueue);
            }
        }
    }

    /** 前向可达集：从 magic entry、OIS 宿主与反序列化 source 宿主出发，沿调用边 BFS。 */
    private void computeReachable() {
        Deque<String> bfs = new ArrayDeque<>();
        for (Node method : bb.graph().nodesOfType(NodeType.METHOD)) {
            // JDK 自身的 readObject/hashCode 等是机制实现，不应作为每个扫描任务的独立污点根；
            // 它们仍会作为应用调用图中的被调者进入可达集。对象图/组合知识源负责把
            // 反序列化容器的回调语义补回，避免把完整 JDK 图扩散成数万条 worklist 根。
            if (isMagicEntry(method) && !isJdkOwner(method.owner())
                    && isDeserializationEntry(method)
                    && reachable.add(methodNodeKey(method))) {
                bfs.add(methodNodeKey(method));
            }
        }
        for (Node call : bb.graph().nodesOfType(NodeType.CALL)) {
            MethodInfo enclosing = support.enclosingMethod(call);
            // An OIS read in an application/framework boundary is a source.  A read
            // performed inside a JDK collection's own readObject implementation is
            // deserialization plumbing, not an independent attacker root; treating it
            // as one makes every JDK container a shorter class-level taint source and
            // can hide the real application entry behind unrelated paths.
            if (OriginSupport.isOisRead(call) && enclosing != null
                    && !isJdkOwner(enclosing.owner())
                    && reachable.add(OriginSupport.methodKey(call))) {
                bfs.add(OriginSupport.methodKey(call));
            }
            var source = bb.ruleEngine().matchingSource(call.owner(), call.name(), call.descriptor());
            if (source.isPresent() && isDeserializationSource(source.get())
                    && reachable.add(OriginSupport.methodKey(call))) {
                bfs.add(OriginSupport.methodKey(call));
            }
        }
        while (!bfs.isEmpty() && reachable.size() < REACHABLE_CAP) {
            String key = bfs.poll();
            if (resolveMethodKey(key) == null) {
                continue;
            }
            for (Node call : bb.graph().callsOfMethod(key)) {
                for (Edge edge : call.out()) {
                    // LAMBDA 边仅跟随应用类实现：JDK 内部 lambda（Stream/Function 管道）会把
                    // 可达集经 JDK 图引爆（54k 方法，前向预算轮数=1 即截断）；gadget 的
                    // lambda 实现在应用/库代码中
                    if (edge.type() == EdgeType.LAMBDA && isJdkOwner(edge.to().owner())) {
                        continue;
                    }
                    if ((edge.type() == EdgeType.INVOKES || edge.type() == EdgeType.DISPATCHES
                            || edge.type() == EdgeType.LAMBDA)
                            && reachable.add(methodNodeKey(edge.to()))) {
                        bfs.add(methodNodeKey(edge.to()));
                    }
                }
                // 仅当调用边未物化实现（出边 ≤1，即声明目标）时按上限展开接口
                if (call.out().size() > 1) {
                    continue;
                }
                // JVM invokespecial/invokestatic/invokedynamic are statically bound here.
                // Expanding their owner through the subtype hierarchy both adds work and
                // invents dispatch paths (for example Base.m -> Object.m).  Only virtual
                // and interface calls have a runtime receiver selection to complete.
                String invokeKind = call.invokeKind();
                if (!"VIRTUAL".equals(invokeKind) && !"INTERFACE".equals(invokeKind)) {
                    continue;
                }
                List<String> impls = bb.hierarchy().implementers(call.owner(), 10_000);
                if (impls != null) {
                    int expanded = 0;
                    for (String impl : impls) {
                        if (expanded >= INTERFACE_EXPAND_CAP) {
                            break;
                        }
                        expanded++;
                        String resolved = bb.hierarchy().resolveMethod(impl, call.name(), call.descriptor());
                        if (resolved != null && reachable.add(OriginSupport.methodKeyOf(resolved, call.name(),
                                call.descriptor()))) {
                            bfs.add(OriginSupport.methodKeyOf(resolved, call.name(), call.descriptor()));
                        }
                    }
                }
            }
        }
        if (!bfs.isEmpty()) {
            bb.markIncomplete("REACHABLE_CAP:" + REACHABLE_CAP);
        }
    }

    /** 种子：magic entry 的 this 是反序列化对象；入队其所在类的全部方法。入口按规则自匹配。 */
    private void seedEntries() {
        for (Node method : bb.graph().nodesOfType(NodeType.METHOD)) {
            if (isJdkOwner(method.owner()) || !isDeserializationEntry(method)) {
                continue;
            }
            bb.ruleEngine().matchingEntry(method.owner(), method.name(), method.descriptor())
                    .ifPresent(rule -> {
                        String owner = method.owner();
                        ChainHop entryHop = new ChainHop(owner, method.name(),
                                owner, method.name(), HopKind.ENTRY, null, rule.entryKind(),
                                method.descriptor(), null);
                        addThis(owner, List.of(entryHop));
                    });
        }
    }

    private boolean isMagicEntry(Node method) {
        return bb.ruleEngine().matchingEntry(method.owner(), method.name(), method.descriptor()).isPresent();
    }

    /**
     * A proxy callback is an attacker-controlled deserialization entry only when the
     * handler itself can cross the serialization boundary.  Non-serializable handlers
     * remain analyzable when ordinary application code constructs a proxy; they must
     * enter through normal data/call flow rather than as a synthetic source root.
     */
    private boolean isDeserializationEntry(Node method) {
        var entry = bb.ruleEngine().matchingEntry(method.owner(), method.name(), method.descriptor());
        return entry.isEmpty() || !"proxyInvoke".equals(entry.get().entryKind())
                || bb.hierarchy().isSerializable(method.owner());
    }

    /** 方法效果：PUTFIELD 存污点值 → 字段事实；RETURN 污点值 → 返回事实；AASTORE 污点值 → 数组容器污点。 */
    private void processEffects(MethodInfo method) {
        String methodKey = OriginSupport.methodKey(method);
        List<InsnFact> effects = effectInstructions.get(methodKey);
        if (effects == null) {
            return;
        }
        Explore ex = new Explore();
        ForwardOrigins.Result originResult = origins(method, ex);
        for (InsnFact insn : effects) {
            Op op = insn.op();
            if (op.isFieldWrite()) {
                ForwardOrigins.State state = originResult.stateBefore().get(insn.offset());
                if (state == null || state.stack().isEmpty()) {
                    continue;
                }
                for (ValueOrigin value : state.stack().get(state.stack().size() - 1).origins()) {
                    if (!mayCarryTaint(value)) {
                        continue;
                    }
                    List<ChainHop> path = tainted(value, method, 0, ex);
                    if (path != null) {
                        addField(insn.fieldRef().owner(), insn.fieldRef().name(), path);
                    }
                }
            } else if (op == Op.AASTORE) {
                // 数组元素流（field/param 粒度）：AASTORE 污点值 → 数组容器污点。
                // 栈形 ..., arrayref, index, value → arrayref 在 size-3。对象数组是 gadget 中转载体；
                // 原始类型数组（IASTORE 等）不承载引用污点，不处理。
                ForwardOrigins.State state = originResult.stateBefore().get(insn.offset());
                if (state == null || state.stack().size() < 3) {
                    continue;
                }
                for (ValueOrigin value : state.stack().get(state.stack().size() - 1).origins()) {
                    if (!mayCarryTaint(value)) {
                        continue;
                    }
                    List<ChainHop> path = tainted(value, method, 0, ex);
                    if (path == null) {
                        continue;
                    }
                    for (ValueOrigin arrayRef : state.stack().get(state.stack().size() - 3).origins()) {
                        if (arrayRef instanceof ValueOrigin.FieldRead f && !f.isStatic()) {
                            addField(f.owner(), f.field(), path);
                        } else if (arrayRef instanceof ValueOrigin.Param p) {
                            addParam(method.owner(), method.name(), method.descriptor(), p.slot(), path);
                        }
                    }
                }
            } else if (op.isInvoke()) {
                // lambda 桥接驱动器：仅对携带函数式结果实参（indy 结果经函数式接口传递）的
                // 调用点做主动传播——这类调用在需求驱动下永不被评估，lambda 绑定/消费无法发生。
                // 其余调用维持需求驱动：全量主动传播会制造短路径挤占事实表
                // （被校验拒绝的形态替换可用长路径）与预算爆炸。
                Node callNode = support.callNode(methodKey, insn.offset());
                if (callNode != null && hasRelevantCallInputs(callNode, method, originResult)) {
                    // Constant-only calls cannot create a taint fact. Keep the lambda
                    // structural bind in the same path while skipping needless propagation.
                    propagateCallArgs(callNode, method, 0, ex, originResult);
                    if (options.reflectiveResolve()) {
                        // Reflection metadata can be constant while the Method/Constructor
                        // receiver or its Object[] arguments carry the taint. Resolve the
                        // target at the same effect point so a void/ignored reflective
                        // return value cannot hide the target sink.
                        reflectiveResolve(callNode, method, 0, ex);
                    }
                }
            } else if (op.isReturn() && op != Op.RETURN && op != Op.ATHROW) {
                ForwardOrigins.State state = originResult.stateBefore().get(insn.offset());
                if (state == null || state.stack().isEmpty()) {
                    continue;
                }
                for (ValueOrigin value : state.stack().get(state.stack().size() - 1).origins()) {
                    if (!mayCarryTaint(value)) {
                        continue;
                    }
                    List<ChainHop> path = tainted(value, method, 0, ex);
                    if (path != null) {
                        addReturn(OriginSupport.methodKey(method), path);
                    }
                }
            }
        }
    }

    /** sink 判定：污点位置的值带污点 → 链达成。 */
    private void checkSink(Node call, Rule.SinkRule rule) {
        MethodInfo method = support.enclosingMethod(call);
        if (method == null) {
            return;
        }
        Explore ex = new Explore();
        ForwardOrigins.State state = stateAt(method, (Integer) call.prop("offset"), ex);
        if (state == null) {
            return;
        }
        if (support.catchProvablyUnreachable(method, (Integer) call.prop("offset"))) {
            return; // catch 不可达守卫（与反向引擎同谓词）
        }
        if (support.sinkPathProvablyUnreachable(method, (Integer) call.prop("offset"))) {
            // Keep the forward and backward engines on the same exact local-feasibility
            // boundary.  The taint fixed point stays path-insensitive for recall, while
            // an independently proven impossible branch is not allowed to re-introduce a
            // finding after backward analysis has removed it.
            return;
        }
        int paramCount = Descriptor.paramCount(call.descriptor());
        for (Rule.TaintedPos pos : rule.tainted()) {
            int depthFromTop;
            if (pos instanceof Rule.TaintedPos.Arg a) {
                depthFromTop = paramCount - 1 - a.index();
            } else {
                depthFromTop = paramCount;
            }
            if (depthFromTop < 0 || depthFromTop >= state.stack().size()) {
                continue;
            }
            for (ValueOrigin origin : state.stack().get(state.stack().size() - 1 - depthFromTop).origins()) {
                if (!mayCarryTaint(origin)) {
                    continue;
                }
                List<ChainHop> path = tainted(origin, method, 0, ex);
                if (path == null) {
                    continue;
                }
                List<ChainHop> hops = new ArrayList<>(path);
                Collections.reverse(hops); // 前向路径翻转为 sink→entry
                ChainHop entry = hops.get(hops.size() - 1);
                Chain chain = new Chain(rule.id(), rule.category(), rule.severity(),
                        entry.fromOwner(), entry.fromName(), entry.reason() == null ? "?" : entry.reason(),
                        call.owner(), call.name(), hops, 0, call.descriptor());
                bb.addChain(chain);
            }
        }
    }

    /**
     * 值污点判定：返回前向路径（含 ENTRY hop 在首），无污点返回 null。
     * ex 为本次探索私有的上下文：环守卫（并行批中不同 worker/不同方法不得共享——
     * 共享会把他人进行中的探索误判为环，产生假阴性）+ 截断标记
     * （深度/预算截断产生的 null 不写死胡同缓存——截断是探索不完整，不是可证明无污点）。
     */
    private List<ChainHop> tainted(ValueOrigin origin, MethodInfo method, int depth, Explore ex) {
        if (depth > MAX_DEPTH || steps > STEP_BUDGET) {
            ex.truncated = true;
            return null;
        }
        steps++;
        TaintKey key = new TaintKey(OriginSupport.methodKey(method), origin);
        if (ex.visiting.contains(key)) {
            return null; // 当前摘要递归环：不能写入全局 null 缓存
        }
        TaintMemo memo = taintMemo.get(key);
        if (memo != null && memo.factVersion() == factVersion) {
            return memo.path();
        }
        Long deadAt = deadEnds.get(key);
        if (deadAt != null && deadAt == factVersion) {
            return null; // 版本未推进时的死胡同有效；新事实到达（版本推进）后重查
        }
        ex.visiting.add(key);
        boolean truncatedAtEntry = ex.truncated;
        List<ChainHop> path;
        if (origin instanceof ValueOrigin.Param p) {
            path = taintedParam(p.slot(), method);
        } else if (origin instanceof ValueOrigin.FieldRead f) {
            path = taintedFieldRead(f);
        } else if (origin instanceof ValueOrigin.CallResult c) {
            path = taintedCallResult(c.callNodeId(), method, depth, ex);
        } else if (origin instanceof ValueOrigin.Insn i) {
            path = taintedInsn(i.offset(), method, depth, ex);
        } else {
            path = null; // 常量不可控
        }
        ex.visiting.remove(key);
        // 仅当截断发生在本帧子树内才跳过记忆化（此前兄弟分支的截断不影响本帧结论）
        boolean subtreeTruncated = ex.truncated && !truncatedAtEntry;
        if (path != null) {
            // 只有正结果进入摘要缓存；它代表一条已经验证的具体路径，不依赖
            // 当前 Explore 的环守卫上下文。版本号保证后续新事实可以重新求值。
            taintMemo.put(key, new TaintMemo(factVersion, path));
        } else if (!subtreeTruncated) {
            deadEnds.put(key, factVersion);
            if (deadEnds.size() > DEAD_END_SWEEP) {
                long version = factVersion;
                deadEnds.values().removeIf(v -> v < version);
            }
        }
        return path;
    }

    /** 参数污点：实例方法 slot 0 为 this（类级污点）；静态方法 slot 0 是首个实参，不吃类级污点。 */
    private List<ChainHop> taintedParam(int slot, MethodInfo method) {
        if (slot == 0 && !method.isStatic()) {
            List<ChainHop> path = thisTainted.get(method.owner());
            if (path != null) {
                return path;
            }
        }
        return paramTainted.get(OriginSupport.methodKey(method) + "#" + slot);
    }

    private List<ChainHop> taintedCallResult(long callNodeId, MethodInfo method, int depth, Explore ex) {
        if (callNodeId < 0) {
            return null;
        }
        Node call = support.callNode(callNodeId);
        var source = bb.ruleEngine().matchingSource(call.owner(), call.name(), call.descriptor());
        if (source.isPresent() && isDeserializationSource(source.get())) {
            String entryKind = source.get().bridge() == null ? "deserialize" : source.get().bridge();
            ChainHop entryHop = new ChainHop(method.owner(), method.name(),
                    method.owner(), method.name(), HopKind.ENTRY, null, entryKind,
                    method.descriptor(), null);
            return List.of(entryHop);
        }
        if (OriginSupport.isOisRead(call) && !isJdkOwner(method.owner())) {
            ChainHop entryHop = new ChainHop(method.owner(), method.name(),
                    method.owner(), method.name(), HopKind.ENTRY, null, "deserialization", "", null);
            return List.of(entryHop);
        }
        ForwardOrigins.State state = stateAt(method, (Integer) call.prop("offset"), ex);
        if (state == null) {
            return null;
        }
        // 驱动输入侧事实（参数/receiver、lambda、代理/反射分派），但不要把输入路径
        // 直接当成返回值。返回值只能来自声明式 return model、已收敛的被调方法
        // return summary，或专门的 source 语义。
        propagateCallArgs(call, method, depth + 1, ex);
        List<ChainHop> best = null;
        List<ChainHop> proxyReturn = proxyReturnPath(call, method, depth, ex);
        if (proxyReturn != null) {
            best = proxyReturn;
        }
        List<ChainHop> arrayReadPath = taintedReflectiveArrayRead(call, method, depth, ex);
        if (arrayReadPath != null && (best == null || arrayReadPath.size() < best.size())) {
            best = arrayReadPath;
        }
        String kind = call.invokeKind();
        boolean calleeStatic = isStaticLike(kind);
        // model 规则（声明式摘要）：return←src 透传、this←argN 容器投毒
        var model = bb.ruleEngine().matchingModel(call.owner(), call.name(), call.descriptor());
        if (model.isPresent()) {
            best = applyModel(model.get(), call, method, depth, best, ex);
        }
        for (Edge edge : call.out()) {
            if (edge.type() != EdgeType.INVOKES && edge.type() != EdgeType.DISPATCHES) {
                continue;
            }
            List<ChainHop> returnPath = returnTainted.get(methodNodeKey(edge.to()));
            if (returnPath != null) {
                List<ChainHop> candidate = hopTo(returnPath, method, edge.to().owner(),
                        edge.to().name(), edge.to().descriptor(), edge.type());
                if (best == null || better(best, candidate)) {
                    best = candidate;
                }
            }
        }
        if (options.expandInterfaces()) {
            expandInterfaces(call, method, depth, best != null, ex);
        }
        if (options.threadProxy() && !calleeStatic) {
            threadProxy(call, method, depth, ex);
        }
        if (options.reflectiveResolve()) {
            reflectiveResolve(call, method, depth, ex);
        }
        return best;
    }

    /**
     * Resolve the value returned by java.lang.reflect.Array.get from the indexed local
     * summary.  This keeps reflective array semantics in the generic value-flow layer;
     * callers such as Method.invoke then consume the same source as an ordinary AALOAD.
     */
    private List<ChainHop> taintedReflectiveArrayRead(Node call, MethodInfo method,
                                                       int depth, Explore ex) {
        if (!"java/lang/reflect/Array".equals(call.owner())
                || !"get".equals(call.name())
                || !"(Ljava/lang/Object;I)Ljava/lang/Object;".equals(call.descriptor())) {
            return null;
        }
        Set<ValueOrigin> values = origins(method, ex).arrayElements()
                .getOrDefault(new ValueOrigin.CallResult(call.id()), Set.of());
        for (ValueOrigin value : values) {
            if (!mayCarryTaint(value) || value.equals(new ValueOrigin.CallResult(call.id()))) {
                continue;
            }
            List<ChainHop> path = tainted(value, method, depth + 1, ex);
            if (path != null) {
                return path;
            }
        }
        return null;
    }

    /**
     * lambda 实参绑定：实参 origin 为 invokedynamic 结果时，沿其 LAMBDA 边找到实现方法，
     * 记录「被调方法#槽 → 实现方法」。实现参数布局 = 捕获变量前缀 + 函数式接口方法参数，
     * 槽位偏移 = 实现描述符前（实现参数数 − 接口参数数）个参数的槽宽和。
     */
    private void bindLambdaArg(ValueOrigin argOrigin, Node call, int slot) {
        if (!(argOrigin instanceof ValueOrigin.CallResult indy) || indy.callNodeId() < 0) {
            return;
        }
        Node indyCall = support.callNode(indy.callNodeId());
        if (indyCall == null) {
            return;
        }
        String calleeKey = methodNodeKey(call);
        String bindKey = calleeKey + "#" + slot;
        for (Edge edge : indyCall.out()) {
            if (edge.type() != EdgeType.LAMBDA) {
                continue;
            }
            String implOwner = edge.to().owner();
            String implName = edge.to().name();
            String implDesc = edge.to().descriptor();
            if (support.methodOf(implOwner, implName, implDesc) == null) {
                continue;
            }
            List<LambdaBind> binds = lambdaBinds.computeIfAbsent(bindKey, k -> new ArrayList<>(1));
            LambdaBind bind = new LambdaBind(implOwner, implName, implDesc);
            if (!binds.contains(bind)) {
                binds.add(bind);
            }
        }
    }

    /**
     * 调用点污点传播（接收者 + 实参 + lambda 绑定/消费）：void 中转调用无返回值消费，
     * 需求驱动（sink 求值链）不会评估它——processEffects 对每个调用点主动驱动本方法。
     *
     * 这个方法返回的是“输入中发现的最佳污点路径”，供调用方决定是否把它当作返回值
     * 语义使用；它本身不会假定任意方法都把 receiver/argument 原样返回。这个区分很
     * 重要：sink 读取一个调用结果时，调用的参数可能是污点，但方法也可能返回常量或
     * 无关对象（代理回调正是这种形态）。
     */
    private List<ChainHop> propagateCallArgs(Node call, MethodInfo method, int depth, Explore ex) {
        return propagateCallArgs(call, method, depth, ex, origins(method, ex));
    }

    private List<ChainHop> propagateCallArgs(Node call, MethodInfo method, int depth, Explore ex,
                                             ForwardOrigins.Result originResult) {
        ForwardOrigins.State state = originResult.stateBefore().get(call.offset());
        if (state == null) {
            return null;
        }
        boolean calleeStatic = isStaticLike(call.invokeKind());
        List<ChainHop> best = null;
        Set<ValueOrigin> receiverOrigins = Set.of();
        if (!calleeStatic) {
            int receiverDepth = state.stack().size() - 1 - Descriptor.paramCount(call.descriptor());
            if (receiverDepth >= 0 && receiverDepth < state.stack().size()) {
                receiverOrigins = state.stack().get(receiverDepth).origins();
                for (ValueOrigin receiver : receiverOrigins) {
                    if (!mayCarryTaint(receiver)) {
                        continue;
                    }
                    List<ChainHop> receiverPath = tainted(receiver, method, depth, ex);
                    if (receiverPath != null) {
                        for (Edge edge : call.out()) {
                            if (edge.type() == EdgeType.INVOKES || edge.type() == EdgeType.DISPATCHES) {
                                if (!support.receiverMayDispatchTo(call, method, edge.to().owner(),
                                        edge.to().name(), edge.to().descriptor())) {
                                    continue;
                                }
                                addThis(edge.to().owner(), hopTo(receiverPath, method,
                                        edge.to().owner(), edge.to().name(),
                                        edge.to().descriptor(), edge.type()), false);
                            }
                        }
                        if (best == null) {
                            best = receiverPath;
                        }
                    }
                }
            }
        }
        // 实参污点传播（按被调方法实参槽遍历，wide 参数占 2 槽）
        List<Integer> argSlots = Descriptor.argSlots(call.descriptor(), calleeStatic);
        int paramCount = calleeStatic ? argSlots.size() : Math.max(0, argSlots.size() - 1);
        int slot = 0;
        for (int i = 0; i < argSlots.size(); i++) {
            int argumentOrdinal = calleeStatic ? i : i - 1;
            for (ValueOrigin argOrigin : stackOriginsAt(state, paramCount, argumentOrdinal)) {
                // lambda 绑定（结构性，与污点无关）：实参为 indy 结果时，记录被调方法的该槽位
                // 将持有 lambda 实现方法——消费端在被调方法体内经此 receiver 调接口方法时定向分发
                bindLambdaArg(argOrigin, call, slot);
                if (!mayCarryTaint(argOrigin)) {
                    continue;
                }
                List<ChainHop> argPath = tainted(argOrigin, method, depth, ex);
                if (argPath == null) {
                    continue;
                }
                if (best == null) {
                    best = argPath;
                }
                for (Edge edge : call.out()) {
                    if (edge.type() == EdgeType.INVOKES || edge.type() == EdgeType.DISPATCHES) {
                        if (!support.receiverMayDispatchTo(call, method, edge.to().owner(),
                                edge.to().name(), edge.to().descriptor())) {
                            continue;
                        }
                        addParam(edge.to().owner(), edge.to().name(),
                                edge.to().descriptor(), slot, hopTo(argPath, method,
                                        edge.to().owner(), edge.to().name(),
                                        // argOrdinal 不设：前向 hop 是调用路径记录而非值流轨迹，
                                        // 类型流校验的相邻跳配对语义只适用反向链（历史回归：CC BeanMap 链被误拒）
                                        edge.to().descriptor(), edge.type(), null));
                    }
                }
                // lambda 消费：接口调用的 receiver 是已绑定 lambda 的参数时，污点实参传给实现方法。
                // 实现参数布局 = 捕获变量前缀 + 函数式接口方法参数；captured 数 = 实现参数数 - 接口参数数
                // （接口参数数取本调用点的描述符——indy 自身的 desc 是 factory 签名，不含接口参数）。
                // 实现槽位 = 捕获前缀槽宽和（实例实现含 receiver 槽）+ 实参序数（不含接收者）。
                if (receiverOrigins.stream().anyMatch(o -> o instanceof ValueOrigin.Param)) {
                    int ordinal = Descriptor.paramOrdinal(call.descriptor(), calleeStatic, slot);
                    if (ordinal >= 0) {
                        for (ValueOrigin receiver : receiverOrigins) {
                            if (!(receiver instanceof ValueOrigin.Param rp)) {
                                continue;
                            }
                            for (LambdaBind bind : lambdaBinds.getOrDefault(
                                    OriginSupport.methodKey(method) + "#" + rp.slot(), List.of())) {
                                addParam(bind.implOwner(), bind.implName(), bind.implDesc(),
                                        implArgSlotOf(bind, call, ordinal), argPath);
                            }
                        }
                    }
                }
                if (options.expandInterfaces()) {
                    expandParams(call, method, slot, argPath);
                }
                if (argPath != null && !calleeStatic) {
                    // A lambda object is created by the preceding invokedynamic factory,
                    // not by the interface declaration reached through CHA.  Map the SAM
                    // argument directly to the implementation method so a direct
                    // lambda call remains visible even when the synthetic class is absent.
                    propagateLambdaSamArgument(call, method, depth, argumentOrdinal, argPath,
                            receiverOrigins);
                }
            }
            slot += argSlots.get(i);
        }
        if ("DYNAMIC".equals(call.invokeKind())) {
            // The factory's captured receiver/variables are data-flow inputs too.  This
            // creates the implementation receiver/parameter facts before its sink is
            // evaluated, including lambdas whose implementation is an instance method.
            best = propagateLambdaFactory(call, method, depth, ex, originResult, best);
        }
        return best;
    }

    /**
     * Propagate one functional-interface argument to the implementation behind a lambda
     * factory.  CHA can only see the interface declaration for a lambda object; the
     * implementation handle in LambdaMetafactory is the authoritative target.
     */
    private void propagateLambdaSamArgument(Node ifaceCall, MethodInfo caller, int depth,
                                             int samOrdinal, List<ChainHop> argPath,
                                             Set<ValueOrigin> receiverOrigins) {
        if (receiverOrigins.isEmpty()) {
            return;
        }
        for (ValueOrigin receiver : receiverOrigins) {
            if (!(receiver instanceof ValueOrigin.CallResult result) || result.callNodeId() < 0) {
                continue;
            }
            Node factory = support.callNode(result.callNodeId());
            LambdaShape shape = lambdaShape(factory);
            if (shape == null) {
                continue;
            }
            for (Edge edge : factory.out()) {
                if (edge.type() != EdgeType.LAMBDA) {
                    continue;
                }
                MethodInfo implementation = support.methodOf(edge.to().owner(), edge.to().name(),
                        edge.to().descriptor());
                if (implementation == null) {
                    continue;
                }
                int slot = lambdaParameterSlot(implementation, shape, samOrdinal);
                if (slot < 0) {
                    continue;
                }
                addParam(implementation.owner(), implementation.name(), implementation.descriptor(),
                        slot, lambdaHop(argPath, caller, implementation, "lambda-argument"));
            }
        }
    }

    /**
     * Propagate tainted captured values at an invokedynamic factory.  For an instance method
     * handle, capture ordinal zero is the implementation receiver; remaining captures are
     * the synthetic prefix in the implementation descriptor.  Static handles have no hidden
     * receiver.  Invalid/adapted layouts are ignored conservatively rather than inventing a
     * target slot; the ordinary interface path remains available for the caller.
     */
    private List<ChainHop> propagateLambdaFactory(Node factory, MethodInfo caller, int depth,
                                                   Explore ex, ForwardOrigins.Result originResult,
                                                   List<ChainHop> best) {
        LambdaShape shape = lambdaShape(factory);
        if (shape == null) {
            return best;
        }
        ForwardOrigins.State state = originResult.stateBefore().get(factory.offset());
        if (state == null) {
            return best;
        }
        int capturedCount = Descriptor.paramCount(factory.descriptor());
        boolean receiverCapture = lambdaHasCapturedReceiver(shape.implementation().tag());
        for (Edge edge : factory.out()) {
            if (edge.type() != EdgeType.LAMBDA) {
                continue;
            }
            MethodInfo implementation = support.methodOf(edge.to().owner(), edge.to().name(),
                    edge.to().descriptor());
            if (implementation == null) {
                continue;
            }
            int explicitCaptured = Math.max(0, Descriptor.paramCount(implementation.descriptor())
                    - Descriptor.paramCount(shape.samDescriptor()));
            for (int captureOrdinal = 0; captureOrdinal < capturedCount; captureOrdinal++) {
                Set<ValueOrigin> origins = stackOriginsAt(state, capturedCount, captureOrdinal);
                for (ValueOrigin captured : origins) {
                    if (!mayCarryTaint(captured)) {
                        continue;
                    }
                    List<ChainHop> capturedPath = tainted(captured, caller, depth + 1, ex);
                    if (capturedPath == null) {
                        continue;
                    }
                    if (receiverCapture && captureOrdinal == 0) {
                        addThis(implementation.owner(), lambdaHop(capturedPath, caller,
                                implementation, "lambda-capture"), false);
                        if (best == null) {
                            best = capturedPath;
                        }
                        continue;
                    }
                    int prefixOrdinal = captureOrdinal - (receiverCapture ? 1 : 0);
                    if (prefixOrdinal < 0 || prefixOrdinal >= explicitCaptured) {
                        continue;
                    }
                    int slot = implementationParameterSlot(implementation, prefixOrdinal);
                    if (slot < 0) {
                        continue;
                    }
                    addParam(implementation.owner(), implementation.name(),
                            implementation.descriptor(), slot,
                            lambdaHop(capturedPath, caller, implementation, "lambda-capture"));
                    if (best == null) {
                        best = capturedPath;
                    }
                }
            }
        }
        return best;
    }

    private LambdaShape lambdaShape(Node factory) {
        if (factory == null || !"DYNAMIC".equals(factory.invokeKind())) {
            return null;
        }
        Object value = factory.prop("indy");
        if (!(value instanceof InvokeDynamicRef indy)
                || indy.bootstrap() == null
                || !"java/lang/invoke/LambdaMetafactory".equals(indy.bootstrap().owner())
                || indy.bootstrapArgs().size() < 2
                || !(indy.bootstrapArgs().get(1) instanceof HandleRef implementation)) {
            return null;
        }
        String samDescriptor = null;
        if (!indy.bootstrapArgs().isEmpty() && indy.bootstrapArgs().get(0) instanceof TypeRef type) {
            samDescriptor = type.descriptor();
        }
        if (samDescriptor == null && indy.bootstrapArgs().size() > 2
                && indy.bootstrapArgs().get(2) instanceof TypeRef type) {
            samDescriptor = type.descriptor();
        }
        if (samDescriptor == null || !samDescriptor.startsWith("(")) {
            return null;
        }
        return new LambdaShape(implementation, samDescriptor);
    }

    private static boolean lambdaHasCapturedReceiver(int handleTag) {
        // REF_invokeVirtual, REF_invokeSpecial and REF_invokeInterface have an
        // implicit receiver supplied by the factory's first captured argument.
        return handleTag == 5 || handleTag == 7 || handleTag == 9;
    }

    private int lambdaParameterSlot(MethodInfo implementation, LambdaShape shape, int samOrdinal) {
        int explicitCaptured = Math.max(0, Descriptor.paramCount(implementation.descriptor())
                - Descriptor.paramCount(shape.samDescriptor()));
        // The implementation descriptor does not contain the bound receiver.  The receiver is
        // represented by local slot 0 for an instance target, so adding it to the descriptor
        // ordinal shifts every SAM argument one slot too far (and drops the common no-capture
        // instance lambda).  Only explicit captured parameters precede the SAM parameters.
        return parameterSlot(implementation.descriptor(), implementation.isStatic(),
                explicitCaptured + samOrdinal);
    }

    private static int implementationParameterSlot(MethodInfo implementation, int ordinal) {
        return parameterSlot(implementation.descriptor(), implementation.isStatic(), ordinal);
    }

    private static int parameterSlot(String descriptor, boolean isStatic, int ordinal) {
        if (ordinal < 0) {
            return -1;
        }
        List<Integer> slots = Descriptor.argSlots(descriptor, isStatic);
        int slot = 0;
        int start = isStatic ? 0 : 1;
        int index = start + ordinal;
        if (index < start || index >= slots.size()) {
            return -1;
        }
        for (int i = 0; i < index; i++) {
            slot += slots.get(i);
        }
        return slot;
    }

    private static List<ChainHop> lambdaHop(List<ChainHop> parent, MethodInfo from,
                                             MethodInfo implementation, String reason) {
        if (parent.size() >= MAX_HOPS) {
            return parent;
        }
        List<ChainHop> path = new ArrayList<>(parent);
        path.add(new ChainHop(from.owner(), from.name(), implementation.owner(),
                implementation.name(), HopKind.LAMBDA, null, reason,
                implementation.descriptor(), null));
        return path;
    }

    /**
     * Same semantic precondition as propagateCallArgs: a non-constant origin or an
     * invokedynamic lambda result. The CFG result is already available in processEffects,
     * so this guard avoids another abstract-state lookup and preserves lambda binding.
     */
    private boolean hasRelevantCallInputs(Node call, MethodInfo method,
                                          ForwardOrigins.Result originResult) {
        ForwardOrigins.State state = originResult.stateBefore().get(call.offset());
        if (state == null) {
            return false;
        }
        boolean calleeStatic = isStaticLike(call.invokeKind());
        if (!calleeStatic) {
            int receiverDepth = state.stack().size() - 1 - Descriptor.paramCount(call.descriptor());
            if (receiverDepth >= 0 && receiverDepth < state.stack().size()
                    && state.stack().get(receiverDepth).origins().stream()
                    .anyMatch(origin -> relevantCallOrigin(origin, method, originResult))) {
                return true;
            }
        }
        List<Integer> argSlots = Descriptor.argSlots(call.descriptor(), calleeStatic);
        int paramCount = calleeStatic ? argSlots.size() : Math.max(0, argSlots.size() - 1);
        int slot = 0;
        for (int i = 0; i < argSlots.size(); i++) {
            int argumentOrdinal = calleeStatic ? i : i - 1;
            if (stackOriginsAt(state, paramCount, argumentOrdinal).stream()
                    .anyMatch(origin -> relevantCallOrigin(origin, method, originResult))) {
                return true;
            }
            slot += argSlots.get(i);
        }
        return false;
    }

    private static Set<ValueOrigin> stackOriginsAt(ForwardOrigins.State state, int paramCount,
                                                    int ordinal) {
        if (ordinal < -1 || ordinal >= paramCount) {
            return Set.of();
        }
        int depthFromTop = ordinal == -1 ? paramCount : paramCount - 1 - ordinal;
        if (depthFromTop < 0 || depthFromTop >= state.stack().size()) {
            return Set.of();
        }
        return state.stack().get(state.stack().size() - 1 - depthFromTop).origins();
    }

    private boolean relevantCallOrigin(ValueOrigin origin, MethodInfo method,
                                       ForwardOrigins.Result originResult) {
        return isLambdaResult(origin) || mayReachTaint(origin, method, originResult,
                new HashSet<>());
    }

    /**
     * Conservative, side-effect-free prefilter for a call effect.  An {@link ValueOrigin.Insn}
     * is not automatically attacker-controlled: NEW followed by a chain of constant-only
     * casts/arithmetic is a common shape in large libraries.  Walking only that local origin
     * subgraph lets the forward engine skip such calls without consulting facts or mutating the
     * worklist.  Unknown non-local origins remain relevant, so this filter can only remove a
     * call that is provably independent of a source/parameter/field/call result.
     */
    private boolean mayReachTaint(ValueOrigin origin, MethodInfo method,
                                  ForwardOrigins.Result originResult,
                                  Set<Integer> visiting) {
        if (origin instanceof ValueOrigin.Constant || origin instanceof ValueOrigin.Unknown) {
            return false;
        }
        if (!(origin instanceof ValueOrigin.Insn insn)) {
            // Param, FieldRead and CallResult may be connected to a fact or a semantic model;
            // do not guess them away here.  Lambda results are also retained by isLambdaResult.
            return true;
        }
        if (insn.offset() < 0 || insn.offset() >= method.instructions().size()) {
            return true;
        }
        if (!visiting.add(insn.offset())) {
            // A cyclic local origin is not a proof of safety.  Keep it for the real taint query.
            return true;
        }
        try {
            InsnFact producer = method.insnAt(insn.offset());
            // IINC reads a local value that is not represented as a stack operand in the
            // abstract state. Treat it conservatively so this speed filter cannot introduce
            // a false negative for values derived from an incremented local.
            if (producer.op() == Op.IINC) {
                return true;
            }
            // NEW has no stack operand, but the allocated object can acquire tainted state
            // through field writes before it reaches this call. Pruning it as a constant
            // would create a false negative for stateful gadget edges.
            if (producer.op() == Op.NEW) {
                return true;
            }
            if (producer.op() == Op.NEWARRAY || producer.op() == Op.ANEWARRAY
                    || producer.op() == Op.MULTIANEWARRAY) {
                Set<ValueOrigin> elements = originResult.arrayElements()
                        .getOrDefault(insn, Set.of());
                for (ValueOrigin element : elements) {
                    if (mayReachTaint(element, method, originResult, visiting)) {
                        return true;
                    }
                }
                return false;
            }
            ForwardOrigins.State state = originResult.stateBefore().get(insn.offset());
            if (state == null) {
                return true;
            }
            int consumed = OriginSupport.consumedCount(producer.op());
            int start = Math.max(0, state.stack().size() - consumed);
            for (int i = start; i < state.stack().size(); i++) {
                for (ValueOrigin operand : state.stack().get(i).origins()) {
                    if (mayReachTaint(operand, method, originResult, visiting)) {
                        return true;
                    }
                }
            }
            return false;
        } finally {
            visiting.remove(insn.offset());
        }
    }

    private boolean isLambdaResult(ValueOrigin origin) {
        if (!(origin instanceof ValueOrigin.CallResult result) || result.callNodeId() < 0) {
            return false;
        }
        Node lambdaFactory = support.callNode(result.callNodeId());
        if (lambdaFactory == null) {
            return false;
        }
        for (Edge edge : lambdaFactory.out()) {
            if (edge.type() == EdgeType.LAMBDA) {
                return true;
            }
        }
        return false;
    }

    /** lambda 实现方法中接口实参 ordinal 的局部槽位（捕获前缀 + 序数）。 */
    private int implArgSlotOf(LambdaBind bind, Node ifaceCall, int ordinal) {
        MethodInfo impl = support.methodOf(bind.implOwner(), bind.implName(), bind.implDesc());
        boolean implStatic = impl == null || impl.isStatic();
        int captured = Math.max(0, Descriptor.paramCount(bind.implDesc())
                - Descriptor.paramCount(ifaceCall.descriptor()));
        List<Integer> slots = Descriptor.argSlots(bind.implDesc(), implStatic);
        int skip = captured + (implStatic ? 0 : 1);
        int index = skip + ordinal;
        if (ordinal < 0 || index >= slots.size()) {
            return -1;
        }
        int offset = 0;
        for (int c = 0; c < index; c++) {
            offset += slots.get(c);
        }
        return offset;
    }



    /** model 规则消费：actions 里 return←src 为透传，this←argN 为容器投毒（类级语义）。 */    private List<ChainHop> applyModel(Rule.ModelRule model, Node call, MethodInfo method, int depth,
                                      List<ChainHop> best, Explore ex) {
        for (Map.Entry<String, List<String>> action : model.actions().entrySet()) {
            for (String src : action.getValue()) {
                List<ChainHop> srcPath = modelSourcePath(src, call, method, depth, ex);
                if (srcPath == null) {
                    continue;
                }
                if ("return".equals(action.getKey())) {
                    if (best == null) {
                        // 透传也须经该调用的规范跳衔接——裸拼 srcPath 会造成链跳类型对不上，
                        // 被 chain-validator 的类型流误拒（历史回归：CC BeanMap 链全灭）
                        best = hopTo(srcPath, method, call.owner(), call.name(),
                                call.descriptor(), EdgeType.INVOKES);
                    }
                } else if ("this".equals(action.getKey())) {
                    addThis(call.owner(), srcPath, false);
                }
            }
        }
        return best;
    }

    /** model 动作来源位置的污点路径：this（receiver）或 argN（第 N 实参）。 */
    private List<ChainHop> modelSourcePath(String src, Node call, MethodInfo method, int depth,
                                           Explore ex) {
        ForwardOrigins.State state = stateAt(method, (Integer) call.prop("offset"), ex);
        if (state == null) {
            return null;
        }
        boolean calleeStatic = isStaticLike(call.invokeKind());
        if ("this".equals(src)) {
            if (calleeStatic) {
                return null;
            }
            int receiverDepth = state.stack().size() - 1 - Descriptor.paramCount(call.descriptor());
            if (receiverDepth < 0 || receiverDepth >= state.stack().size()) {
                return null;
            }
            for (ValueOrigin receiver : state.stack().get(receiverDepth).origins()) {
                List<ChainHop> path = tainted(receiver, method, depth + 1, ex);
                if (path != null) {
                    return path;
                }
            }
            return null;
        }
        if (src.startsWith("arg")) {
            int ordinal = Integer.parseInt(src.substring(3));
            List<Integer> argSlots = Descriptor.argSlots(call.descriptor(), calleeStatic);
            int slot = 0;
            for (int i = 0; i < argSlots.size(); i++) {
                if (i == ordinal) {
                    for (ValueOrigin origin : support.argOriginAt(call, method, slot,
                            origins(method, ex))) {
                        List<ChainHop> path = tainted(origin, method, depth + 1, ex);
                        if (path != null) {
                            return path;
                        }
                    }
                    return null;
                }
            slot += argSlots.get(i);
            }
        }
        return null;
    }

    /** 字段读污点：程序字段事实；回退——反序列化对象（thisTainted 类）的全部实例字段可控。 */
    private List<ChainHop> taintedFieldRead(ValueOrigin.FieldRead f) {
        List<ChainHop> path = fieldTainted.get(f.owner() + "#" + f.field());
        if (path != null) {
            return path;
        }
        // Static fields have no receiver. Instance fields still fall back to the
        // receiver's object fact when the field itself has no writer summary.
        return f.isStatic() ? null : thisTainted.get(f.owner());
    }

    /**
     * 取得一个虚调用签名的候选实现。候选顺序、300 条上限以及可覆写判定均与原始
     * 逐调用点实现保持一致；只把结果移到层次版本缓存中。JDK 懒加载期间若层次发生
     * 变化，则丢弃本次快照并重算，避免把不完整闭包当成稳定结果。
     */
    private DispatchCandidates rawDispatchCandidates(String owner, String name, String desc) {
        DispatchKey key = new DispatchKey(owner, name, desc);
        DispatchCandidates cached = dispatchCache.get(key);
        long currentRevision = bb.hierarchy().revision();
        if (cached != null && cached.revision() == currentRevision) {
            return cached;
        }
        for (;;) {
            long startRevision = bb.hierarchy().revision();
            List<String> raw = bb.hierarchy().transitiveSubtypes(owner);
            long endRevision = bb.hierarchy().revision();
            if (startRevision != endRevision) {
                continue;
            }
            DispatchCandidates result = new DispatchCandidates(endRevision, raw);
            dispatchCache.put(key, result);
            return result;
        }
    }

    private ResolvedDispatchCandidates resolvedDispatchCandidates(String owner, String name, String desc,
                                                                   DispatchCandidates rawSnapshot) {
        DispatchKey key = new DispatchKey(owner, name, desc);
        ResolvedDispatchCandidates cached = resolvedDispatchCache.get(key);
        long currentRevision = bb.hierarchy().revision();
        if (cached != null && cached.revision() == currentRevision) {
            return cached;
        }
        for (;;) {
            long startRevision = bb.hierarchy().revision();
            List<String> raw = rawSnapshot.revision() == startRevision
                    ? rawSnapshot.raw()
                    : rawDispatchCandidates(owner, name, desc).raw();
            List<DispatchTarget> accepted = new ArrayList<>(Math.min(300, raw.size()));
            for (String candidate : raw) {
                if (accepted.size() >= 300) {
                    break;
                }
                DispatchTarget target = dispatchTarget(owner, candidate, name, desc);
                if (target != null) {
                    accepted.add(target);
                }
            }
            long endRevision = bb.hierarchy().revision();
            if (startRevision != endRevision) {
                rawSnapshot = rawDispatchCandidates(owner, name, desc);
                continue;
            }
            ResolvedDispatchCandidates result = new ResolvedDispatchCandidates(endRevision, List.copyOf(accepted));
            resolvedDispatchCache.put(key, result);
            return result;
        }
    }

    /** 单个候选的 JVM 语义过滤；null 表示该候选不能成为污点动态目标。 */
    private DispatchTarget dispatchTarget(String owner, String candidate, String name, String desc) {
        if (!bb.hierarchy().isSerializable(candidate)) {
            return null;
        }
        String resolved = bb.hierarchy().resolveMethod(candidate, name, desc);
        if (resolved == null || !bb.hierarchy().isOverridableDispatchTarget(owner, candidate, name, desc)) {
            return null;
        }
        return new DispatchTarget(candidate, resolved);
    }

    /** 精扫：污点命中接口调用且仅声明目标（实现>枚举上限未物化）时，按上限展开实现类。 */
    private void expandInterfaces(Node call, MethodInfo method, int depth, boolean hasTaint,
                                  Explore ex) {
        if (call.out().size() > 1) {
            return; // 实现已物化
        }
        String invokeKind = call.invokeKind();
        if (!"VIRTUAL".equals(invokeKind) && !"INTERFACE".equals(invokeKind)) {
            return; // invokespecial/invokestatic/invokedynamic 不发生接收者动态分派
        }
        String owner = call.owner();
        ClassInfo ownerInfo = bb.hierarchy().classInfo(owner);
        if (ownerInfo == null) {
            return;
        }
        List<ChainHop> receiverPath = null;
        ForwardOrigins.State state = stateAt(method, (Integer) call.prop("offset"), ex);
        String kind = call.invokeKind();
        if (state != null && !isStaticLike(kind)) {
            // A Proxy instance is not an arbitrary implementation of every interface
            // implementation found by CHA. Its target is the InvocationHandler selected
            // at the allocation site; proxyReturnPath/threadProxy model that callback and
            // ordinary interface expansion would manufacture unrelated return paths.
            if (isProxyReceiver(call, method, state, ex)) {
                return;
            }
            int receiverDepth = state.stack().size() - 1 - Descriptor.paramCount(call.descriptor());
            if (receiverDepth >= 0 && receiverDepth < state.stack().size()) {
                for (ValueOrigin receiver : state.stack().get(receiverDepth).origins()) {
                    List<ChainHop> path = tainted(receiver, method, depth + 1, ex);
                    if (path != null) {
                        receiverPath = path;
                        break;
                    }
                }
            }
        }
        // A dispatch expansion must carry the concrete receiver's source path.  An
        // argument-only taint at an interface call is not evidence that every
        // implementation object is attacker controlled.
        if (receiverPath == null) {
            return;
        }
        // 候选实现：接口用 implementers，类用子类型（Serializable 过滤限噪声）；
        // 解析结果在同一层次版本内跨调用点复用，避免每个 tainted call 重复做
        // isSerializable + resolveMethod + 可覆写检查。
        DispatchCandidates dispatch = rawDispatchCandidates(owner, call.name(), call.descriptor());
        List<String> rawCandidates = dispatch.raw();
        List<DispatchTarget> candidates = null;
        // A1+#1 FLASH 混合分派增强：receiver 的运行时类型精确解析
        // NEW→精确类名 | FieldRead→字段声明类型（具体类时精确） | 其他→保持 CHA
        if (receiverPath != null && rawCandidates.size() > 1) {
            ForwardOrigins.State rState = state;
            if (rState != null) {
                int rDepth = rState.stack().size() - 1 - Descriptor.paramCount(call.descriptor());
                if (rDepth >= 0 && rDepth < rState.stack().size()) {
                    Set<String> preciseTypes = support.exactConcreteTypes(
                            rState.stack().get(rDepth).origins(), method, call.offset());
                    for (String preciseType : preciseTypes) {
                        if (!rawCandidates.contains(preciseType)) {
                            continue;
                        }
                        DispatchTarget precise = dispatchTarget(owner, preciseType,
                                call.name(), call.descriptor());
                        candidates = precise == null ? List.of() : List.of(precise);
                        break;
                    }
                }
            }
        }
        if (candidates == null) {
            candidates = resolvedDispatchCandidates(owner, call.name(), call.descriptor(), dispatch)
                    .targets();
        }
        for (DispatchTarget target : candidates) {
            String resolved = target.resolvedOwner();
            addThis(resolved, hopTo(receiverPath, method, resolved, call.name(),
                    call.descriptor(), EdgeType.DISPATCHES), false);
        }
    }

    /** 精扫：实参污点命中仅声明目标的调用时，向候选实现展开 addParam。 */
    private void expandParams(Node call, MethodInfo method, int slot, List<ChainHop> argPath) {
        if (call.out().size() > 1) {
            return;
        }
        ForwardOrigins.State state = stateAt(method, (Integer) call.prop("offset"), null);
        if (state != null && isProxyReceiver(call, method, state, null)) {
            return;
        }
        String invokeKind = call.invokeKind();
        if (!"VIRTUAL".equals(invokeKind) && !"INTERFACE".equals(invokeKind)) {
            return; // 参数也只需沿可能被覆写的调用传播
        }
        String owner = call.owner();
        ClassInfo ownerInfo = bb.hierarchy().classInfo(owner);
        if (ownerInfo == null) {
            return;
        }
        for (DispatchTarget target : resolvedDispatchCandidates(owner, call.name(), call.descriptor(),
                rawDispatchCandidates(owner, call.name(), call.descriptor())).targets()) {
            String resolved = target.resolvedOwner();
            if (!support.receiverMayDispatchTo(call, method, resolved, call.name(),
                    call.descriptor())) {
                continue;
            }
            addParam(resolved, call.name(), call.descriptor(), slot,
                    hopTo(argPath, method, resolved, call.name(),
                            call.descriptor(), EdgeType.DISPATCHES));
        }
    }

    /** 精扫：receiver 为 Proxy.newProxyInstance 结果时，handler 实参的解析目标类 this 污点。 */
    private void threadProxy(Node call, MethodInfo method, int depth, Explore ex) {
        ForwardOrigins.State state = stateAt(method, (Integer) call.prop("offset"), ex);
        if (state == null) {
            return;
        }
        int receiverDepth = state.stack().size() - 1 - Descriptor.paramCount(call.descriptor());
        if (receiverDepth < 0 || receiverDepth >= state.stack().size()) {
            return;
        }
        for (ValueOrigin receiver : state.stack().get(receiverDepth).origins()) {
            Node originCall = proxyAllocationOf(receiver, method, ex);
            if (!isProxyAllocation(originCall)) {
                continue;
            }
            MethodInfo originMethod = support.enclosingMethod(originCall);
            if (originMethod == null) {
                continue;
            }
            ForwardOrigins.Result originResult = origins(originMethod, ex);
            if (!proxyMethodMatches(originCall, call, originResult)) {
                continue;
            }
            for (ValueOrigin handlerOrigin : support.argOriginAtOrdinal(originCall, 2, originResult)) {
                List<ChainHop> handlerPath = tainted(handlerOrigin, originMethod, depth + 1, ex);
                if (handlerPath == null) {
                    handlerPath = constructedObjectPath(handlerOrigin, originMethod, depth + 1, ex);
                }
                if (handlerPath == null) {
                    continue;
                }
                String handlerType = concreteObjectType(handlerOrigin, originMethod);
                if (handlerType == null) {
                    bb.markIncomplete("PROXY_HANDLER_METADATA");
                    continue;
                }
                String resolved = bb.hierarchy().resolveMethod(handlerType, "invoke",
                        PROXY_HANDLER_DESCRIPTOR);
                if (resolved == null) {
                    continue;
                }
                addThis(resolved, hopTo(handlerPath, originMethod, resolved, "invoke",
                        PROXY_HANDLER_DESCRIPTOR, EdgeType.INVOKES), false);
            }
        }
    }

    private static final String PROXY_HANDLER_DESCRIPTOR =
            "(Ljava/lang/Object;Ljava/lang/reflect/Method;[Ljava/lang/Object;)Ljava/lang/Object;";

    private enum ProxyValueKind { UNKNOWN, METHOD_OBJECT, METHOD_NAME, STRING, BOOLEAN, NULL }

    private record ProxyValue(ProxyValueKind kind, String text, Boolean truth) {
        private static final ProxyValue UNKNOWN = new ProxyValue(ProxyValueKind.UNKNOWN, null, null);

        private static ProxyValue methodObject() {
            return new ProxyValue(ProxyValueKind.METHOD_OBJECT, null, null);
        }

        private static ProxyValue methodName() {
            return new ProxyValue(ProxyValueKind.METHOD_NAME, null, null);
        }

        private static ProxyValue string(String value) {
            return new ProxyValue(ProxyValueKind.STRING, value, null);
        }

        private static ProxyValue bool(boolean value) {
            return new ProxyValue(ProxyValueKind.BOOLEAN, null, value);
        }

        private static ProxyValue nullValue() {
            return new ProxyValue(ProxyValueKind.NULL, null, null);
        }
    }

    private record ProxyFlow(List<ProxyValue> stack, Map<Integer, ProxyValue> locals) {
        private ProxyFlow {
            stack = List.copyOf(stack);
            locals = Map.copyOf(locals);
        }
    }

    /**
     * Return the taint summary of the handler branch selected by the proxy method name.
     * An InvocationHandler receives a Method object rather than the interface call as a
     * normal Java call edge.  A whole-method return summary therefore conflates branches such
     * as {@code if (method.getName().equals("foo")) return taint; return ""}.  This small,
     * bounded CFG interpreter resolves only that metadata predicate; the original origin
     * interpreter remains the authority for the returned value and its taint provenance.
     */
    private List<ChainHop> proxyReturnPath(Node proxyCall, MethodInfo caller, int depth, Explore ex) {
        ForwardOrigins.State state = stateAt(caller, (Integer) proxyCall.prop("offset"), ex);
        if (state == null) {
            return null;
        }
        for (ValueOrigin receiver : receiverOrigins(proxyCall, state)) {
            Node originCall = proxyAllocationOf(receiver, caller, ex);
            if (!isProxyAllocation(originCall)) {
                continue;
            }
            MethodInfo originMethod = support.enclosingMethod(originCall);
            boolean methodMatches = originMethod != null && proxyMethodMatches(originCall, proxyCall,
                    origins(originMethod, ex));
            if (!methodMatches) {
                continue;
            }
            for (ValueOrigin handlerOrigin : support.argOriginAtOrdinal(originCall, 2,
                    origins(originMethod, ex))) {
                String handlerType = concreteObjectType(handlerOrigin, originMethod);
                if (handlerType == null) {
                    continue;
                }
                String resolved = bb.hierarchy().resolveMethod(handlerType, "invoke",
                        PROXY_HANDLER_DESCRIPTOR);
                MethodInfo handler = resolved == null ? null : support.methodOf(resolved,
                        "invoke", PROXY_HANDLER_DESCRIPTOR);
                if (handler == null) {
                    continue;
                }
                ForwardOrigins.Result handlerOrigins = origins(handler, ex);
                Set<Integer> returns = proxyMethodReturnOffsets(handler, proxyCall.name(), support::cfg);
                if (returns.isEmpty()) {
                    // Unknown handler bytecode must not silently become a negative result.
                    // The ordinary summary is conservative, while the incomplete marker tells
                    // the caller that this proxy needs a richer metadata model.
                    bb.markIncomplete("PROXY_RETURN_METADATA");
                    List<ChainHop> fallback = returnTainted.get(OriginSupport.methodKey(handler));
                    if (fallback != null) {
                        return fallback;
                    }
                    continue;
                }
                for (int offset : returns) {
                    ForwardOrigins.State returnState = handlerOrigins.stateBefore().get(offset);
                    if (returnState == null || returnState.stack().isEmpty()) {
                        continue;
                    }
                    for (ValueOrigin returned : returnState.stack()
                            .get(returnState.stack().size() - 1).origins()) {
                        if (!mayCarryTaint(returned)) {
                            continue;
                        }
                        List<ChainHop> path = tainted(returned, handler, depth + 1, ex);
                        if (path != null) {
                            return path;
                        }
                    }
                }
            }
        }
        return null;
    }

    private boolean isProxyReceiver(Node call, MethodInfo method, ForwardOrigins.State state,
                                    Explore ex) {
        for (ValueOrigin receiver : receiverOrigins(call, state)) {
            if (isProxyAllocation(proxyAllocationOf(receiver, method, ex))) {
                return true;
            }
        }
        return false;
    }

    /**
     * ForwardOrigins deliberately collapses CHECKCAST to an instruction origin. Recover the
     * allocation behind that cast so proxy calls are not widened to unrelated CHA targets.
     */
    private Node proxyAllocationOf(ValueOrigin origin, MethodInfo method, Explore ex) {
        return proxyAllocationOf(origin, method, ex, new HashSet<>());
    }

    private Node proxyAllocationOf(ValueOrigin origin, MethodInfo method, Explore ex,
                                   Set<ValueOrigin> visiting) {
        if (origin instanceof ValueOrigin.CallResult result && result.callNodeId() >= 0) {
            return support.callNode(result.callNodeId());
        }
        if (!(origin instanceof ValueOrigin.Insn instruction)
                || !visiting.add(origin)
                || instruction.offset() < 0
                || instruction.offset() >= method.instructions().size()) {
            return null;
        }
        try {
            if (method.insnAt(instruction.offset()).op() != Op.CHECKCAST) {
                return null;
            }
            ForwardOrigins.State before = origins(method, ex).stateBefore()
                    .get(instruction.offset());
            if (before == null || before.stack().isEmpty()) {
                return null;
            }
            for (ValueOrigin candidate : before.stack().get(before.stack().size() - 1).origins()) {
                Node allocation = proxyAllocationOf(candidate, method, ex, visiting);
                if (allocation != null) {
                    return allocation;
                }
            }
            return null;
        } finally {
            visiting.remove(origin);
        }
    }

    private static boolean isProxyAllocation(Node call) {
        return call != null && "java/lang/reflect/Proxy".equals(call.owner())
                && "newProxyInstance".equals(call.name())
                && Descriptor.returnType(call.descriptor()).equals("Ljava/lang/Object;");
    }

    /** Recover source provenance for a freshly allocated handler from its constructor inputs. */
    private List<ChainHop> constructedObjectPath(ValueOrigin origin, MethodInfo method, int depth,
                                                  Explore ex) {
        if (!(origin instanceof ValueOrigin.Insn allocation) || allocation.offset() < 0
                || allocation.offset() >= method.instructions().size()) {
            return null;
        }
        InsnFact newInsn = method.insnAt(allocation.offset());
        if (newInsn.op() != Op.NEW || newInsn.typeRef() == null) {
            return null;
        }
        String allocatedType = internalClassName(newInsn.typeRef().descriptor());
        if (allocatedType == null) {
            return null;
        }
        ForwardOrigins.Result result = origins(method, ex);
        for (InsnFact candidate : method.instructions()) {
            if (candidate.offset() <= allocation.offset() || candidate.op() != Op.INVOKESPECIAL
                    || candidate.operands().isEmpty()) {
                continue;
            }
            MethodRef ref = candidate.methodRef();
            if (!"<init>".equals(ref.name()) || !allocatedType.equals(ref.owner())) {
                continue;
            }
            Node call = support.callNode(OriginSupport.methodKey(method), candidate.offset());
            ForwardOrigins.State before = result.stateBefore().get(candidate.offset());
            if (call == null || before == null || receiverOrigins(call, before).stream()
                    .noneMatch(allocation::equals)) {
                continue;
            }
            for (int ordinal = 0; ordinal < Descriptor.paramCount(candidate.methodRef().descriptor());
                 ordinal++) {
                for (ValueOrigin argument : support.argOriginAtOrdinal(call, ordinal, result)) {
                    if (!mayCarryTaint(argument)) {
                        continue;
                    }
                    List<ChainHop> path = tainted(argument, method, depth + 1, ex);
                    if (path != null) {
                        return path;
                    }
                }
            }
        }
        return null;
    }

    /** Shared by the forward and backward engines so proxy branch semantics cannot drift. */
    public static Set<Integer> proxyMethodReturnOffsets(MethodInfo method, String requestedName) {
        return proxyMethodReturnOffsets(method, requestedName, Cfg::computeIndexed);
    }

    /** Shared proxy analysis with the scan-wide CPG CFG provider. */
    public static Set<Integer> proxyMethodReturnOffsets(MethodInfo method, String requestedName,
                                                        CpgIndex.CfgProvider cfgProvider) {
        if (method == null || requestedName == null || method.instructions().isEmpty()) {
            return Set.of();
        }
        CpgIndex.CfgProvider provider = cfgProvider == null ? Cfg::computeIndexed : cfgProvider;
        Cfg.Indexed cfg = provider.cfg(method);
        Map<Integer, Set<ProxyFlow>> states = new HashMap<>();
        Deque<Integer> work = new ArrayDeque<>();
        Map<Integer, ProxyValue> initialLocals = new HashMap<>();
        // InvocationHandler.invoke(Object proxy, Method method, Object[] args): slot 2 is Method.
        initialLocals.put(2, ProxyValue.methodObject());
        ProxyFlow initial = new ProxyFlow(List.of(), initialLocals);
        states.computeIfAbsent(0, ignored -> new LinkedHashSet<>()).add(initial);
        work.add(0);
        Set<Integer> returns = new LinkedHashSet<>();
        int transitions = 0;
        while (!work.isEmpty() && transitions++ < 20_000) {
            int offset = work.removeFirst();
            InsnFact insn = method.insnAt(offset);
            Set<ProxyFlow> current = states.getOrDefault(offset, Set.of());
            for (ProxyFlow flow : current) {
                if (insn.op().isReturn() && insn.op() != Op.RETURN && insn.op() != Op.ATHROW) {
                    returns.add(offset);
                    continue;
                }
                ProxyValue condition = flow.stack().isEmpty()
                        ? ProxyValue.UNKNOWN : flow.stack().get(flow.stack().size() - 1);
                ProxyFlow next = proxyTransfer(flow, insn, requestedName);
                for (CfgEdge edge : cfg.successorsAt(offset)) {
                    if (edge.label() == CfgLabel.EXCEPTION || !proxyBranchAllowed(insn.op(),
                            condition, edge.label())) {
                        continue;
                    }
                    if (edge.targetOffset() < 0 || edge.targetOffset() >= method.instructions().size()) {
                        continue;
                    }
                    Set<ProxyFlow> target = states.computeIfAbsent(edge.targetOffset(),
                            ignored -> new LinkedHashSet<>());
                    // Unknown bytecode can otherwise create a state cross-product in a large
                    // handler. Capping states affects only metadata feasibility, not the core
                    // taint result; an empty result falls back conservatively above.
                    if (target.size() >= 96 || !target.add(next)) {
                        continue;
                    }
                    work.addLast(edge.targetOffset());
                }
            }
        }
        if (transitions >= 20_000) {
            returns.clear();
        }
        return Set.copyOf(returns);
    }

    private static boolean proxyBranchAllowed(Op op, ProxyValue condition, CfgLabel label) {
        if (!op.isCondJump() || label == CfgLabel.EXCEPTION) {
            return true;
        }
        Boolean equals = condition.kind() == ProxyValueKind.BOOLEAN ? condition.truth() : null;
        Boolean branch = null;
        if (equals != null && (op == Op.IFEQ || op == Op.IFNE)) {
            branch = op == Op.IFNE ? equals : !equals;
        } else if (condition.kind() == ProxyValueKind.NULL
                && (op == Op.IFNULL || op == Op.IFNONNULL)) {
            branch = op == Op.IFNULL;
        } else if (condition.kind() != ProxyValueKind.UNKNOWN
                && (op == Op.IFNULL || op == Op.IFNONNULL)) {
            branch = op == Op.IFNONNULL;
        }
        return branch == null || (branch == (label == CfgLabel.JUMP));
    }

    private static ProxyFlow proxyTransfer(ProxyFlow input, InsnFact insn, String requestedName) {
        List<ProxyValue> stack = new ArrayList<>(input.stack());
        Map<Integer, ProxyValue> locals = new HashMap<>(input.locals());
        Op op = insn.op();
        switch (op) {
            case ACONST_NULL -> stack.add(ProxyValue.nullValue());
            case ICONST_M1, ICONST_0, ICONST_1, ICONST_2, ICONST_3, ICONST_4, ICONST_5,
                    BIPUSH, SIPUSH, LCONST_0, LCONST_1, FCONST_0, FCONST_1, FCONST_2,
                    DCONST_0, DCONST_1 -> stack.add(ProxyValue.UNKNOWN);
            case LDC -> stack.add(insn.constant() instanceof String
                    ? ProxyValue.string((String) insn.constant()) : ProxyValue.UNKNOWN);
            case ALOAD, ILOAD, FLOAD, LLOAD, DLOAD -> stack.add(
                    locals.getOrDefault(insn.varIndex(), ProxyValue.UNKNOWN));
            case ASTORE, ISTORE, FSTORE, LSTORE, DSTORE -> locals.put(insn.varIndex(), popProxy(stack));
            case GETFIELD -> {
                popProxy(stack);
                stack.add(ProxyValue.UNKNOWN);
            }
            case GETSTATIC -> stack.add(ProxyValue.UNKNOWN);
            case PUTFIELD -> {
                popProxy(stack);
                popProxy(stack);
            }
            case PUTSTATIC -> popProxy(stack);
            case NEW -> stack.add(ProxyValue.UNKNOWN);
            case CHECKCAST -> {
                ProxyValue value = popProxy(stack);
                stack.add(value);
            }
            case INSTANCEOF, ARRAYLENGTH -> {
                popProxy(stack);
                stack.add(ProxyValue.UNKNOWN);
            }
            case AALOAD, IALOAD, FALOAD, BALOAD, CALOAD, SALOAD, LALOAD, DALOAD -> {
                popProxy(stack);
                popProxy(stack);
                stack.add(ProxyValue.UNKNOWN);
            }
            case AASTORE, IASTORE, FASTORE, BASTORE, CASTORE, SASTORE, LASTORE, DASTORE -> {
                popProxy(stack);
                popProxy(stack);
                popProxy(stack);
            }
            case INVOKESTATIC, INVOKEVIRTUAL, INVOKESPECIAL, INVOKEINTERFACE,
                    INVOKEDYNAMIC -> proxyInvoke(stack, insn, requestedName, op);
            case POP -> popProxy(stack);
            case POP2 -> {
                popProxy(stack);
                popProxy(stack);
            }
            case DUP -> {
                ProxyValue top = stack.isEmpty() ? ProxyValue.UNKNOWN : stack.get(stack.size() - 1);
                stack.add(top);
            }
            case SWAP -> {
                if (stack.size() >= 2) {
                    int top = stack.size() - 1;
                    ProxyValue first = stack.get(top);
                    stack.set(top, stack.get(top - 1));
                    stack.set(top - 1, first);
                }
            }
            case IFEQ, IFNE, IFLT, IFGE, IFGT, IFLE, IFNULL, IFNONNULL -> popProxy(stack);
            case IF_ICMPEQ, IF_ICMPNE, IF_ICMPLT, IF_ICMPGE, IF_ICMPGT, IF_ICMPLE,
                    IF_ACMPEQ, IF_ACMPNE -> {
                popProxy(stack);
                popProxy(stack);
            }
            case IADD, ISUB, IMUL, IDIV, IREM, ISHL, ISHR, IUSHR, IAND, IOR, IXOR,
                    LADD, LSUB, LMUL, LDIV, LREM, LSHL, LSHR, LUSHR -> {
                popProxy(stack);
                popProxy(stack);
                stack.add(ProxyValue.UNKNOWN);
            }
            case IRETURN, LRETURN, FRETURN, DRETURN, ARETURN, ATHROW, MONITORENTER,
                    MONITOREXIT -> popProxy(stack);
            default -> {
                // Metadata feasibility is intentionally bounded. Unsupported instructions
                // keep the stack shape; the fallback summary preserves soundness.
            }
        }
        return new ProxyFlow(stack, locals);
    }

    private static void proxyInvoke(List<ProxyValue> stack, InsnFact insn, String requestedName, Op op) {
        String descriptor;
        MethodRef ref = null;
        if (op == Op.INVOKEDYNAMIC) {
            descriptor = insn.operands().isEmpty() ? "()V"
                    : ((io.just.sast.model.InvokeDynamicRef) insn.operands().get(0)).descriptor();
        } else {
            ref = insn.methodRef();
            descriptor = ref.descriptor();
        }
        int args = Descriptor.paramCount(descriptor);
        ProxyValue firstArgument = ProxyValue.UNKNOWN;
        for (int i = 0; i < args; i++) {
            ProxyValue value = popProxy(stack);
            if (i == 0) {
                firstArgument = value;
            }
        }
        ProxyValue receiver = op == Op.INVOKESTATIC || op == Op.INVOKEDYNAMIC
                ? ProxyValue.UNKNOWN : popProxy(stack);
        String result = Descriptor.returnType(descriptor);
        if ("V".equals(result)) {
            return;
        }
        if (ref != null && "java/lang/reflect/Method".equals(ref.owner())
                && "getName".equals(ref.name()) && "()Ljava/lang/String;".equals(ref.descriptor())) {
            stack.add(ProxyValue.methodName());
            return;
        }
        if (ref != null && "java/lang/String".equals(ref.owner())
                && "equals".equals(ref.name()) && "(Ljava/lang/Object;)Z".equals(ref.descriptor())) {
            if (receiver.kind() == ProxyValueKind.METHOD_NAME
                    && firstArgument.kind() == ProxyValueKind.STRING) {
                stack.add(ProxyValue.bool(requestedName.equals(firstArgument.text())));
            } else if (receiver.kind() == ProxyValueKind.STRING
                    && firstArgument.kind() == ProxyValueKind.METHOD_NAME) {
                stack.add(ProxyValue.bool(requestedName.equals(receiver.text())));
            } else {
                stack.add(ProxyValue.UNKNOWN);
            }
            return;
        }
        stack.add(ProxyValue.UNKNOWN);
    }

    private static ProxyValue popProxy(List<ProxyValue> stack) {
        return stack.isEmpty() ? ProxyValue.UNKNOWN : stack.remove(stack.size() - 1);
    }

    /**
     * Restrict a proxy callback to the interfaces passed to this allocation site.  A
     * whole-world InvocationHandler expansion is both expensive and unsound: an
     * unrelated serializable handler cannot service this proxy's method signature.
     */
    private boolean proxyMethodMatches(Node proxyCall, Node dispatchedCall,
                                       ForwardOrigins.Result result) {
        Set<ValueOrigin> arrays = support.argOriginAtOrdinal(proxyCall, 1, result);
        boolean metadataSeen = false;
        for (ValueOrigin array : arrays) {
            Map<Integer, Set<ValueOrigin>> indexed = result.indexedArrayElements().get(array);
            if (indexed == null || indexed.isEmpty()) {
                continue;
            }
            metadataSeen = true;
            for (Set<ValueOrigin> values : indexed.values()) {
                if (values.size() != 1) {
                    metadataSeen = false;
                    break;
                }
                String interfaceName = classLiteralName(values.iterator().next());
                if (interfaceName == null) {
                    metadataSeen = false;
                    break;
                }
                if ("java/lang/Object".equals(dispatchedCall.owner())
                        || interfaceName.equals(dispatchedCall.owner())
                        || bb.hierarchy().isSubtypeOf(interfaceName, dispatchedCall.owner())) {
                    String resolved = bb.hierarchy().resolveMethod(interfaceName,
                            dispatchedCall.name(), dispatchedCall.descriptor());
                    if (resolved != null || "java/lang/Object".equals(dispatchedCall.owner())) {
                        return true;
                    }
                }
            }
        }
        if (!metadataSeen) {
            bb.markIncomplete("PROXY_INTERFACE_METADATA");
        }
        return false;
    }

    private static String classLiteralName(ValueOrigin origin) {
        if (origin instanceof ValueOrigin.Constant constant) {
            if (constant.value() instanceof TypeRef type) {
                return internalClassName(type.descriptor());
            }
            if (constant.value() instanceof String name) {
                return name.replace('.', '/');
            }
        }
        return null;
    }

    /** Recover a concrete handler type without enumerating unrelated implementers. */
    private String concreteObjectType(ValueOrigin origin, MethodInfo method) {
        if (origin instanceof ValueOrigin.Insn instruction) {
            InsnFact fact = method.insnAt(instruction.offset());
            if (fact.op() == Op.NEW && fact.typeRef() != null) {
                return internalClassName(fact.typeRef().descriptor());
            }
        }
        if (origin instanceof ValueOrigin.FieldRead field) {
            String declaring = bb.hierarchy().resolveField(field.owner(), field.field());
            ClassInfo cls = bb.hierarchy().classInfo(declaring == null ? field.owner() : declaring);
            if (cls != null && cls.field(field.field()) != null) {
                return internalClassName(cls.field(field.field()).descriptor());
            }
        }
        if (origin instanceof ValueOrigin.CallResult callResult && callResult.callNodeId() >= 0) {
            Node call = support.callNode(callResult.callNodeId());
            if (call != null) {
                if ("<init>".equals(call.name())) {
                    return call.owner();
                }
                return internalClassName(Descriptor.returnType(call.descriptor()));
            }
        }
        return null;
    }

    /** 精扫：按 Class 元对象与签名来源解析 Method/Constructor 反射调用。 */
    private void reflectiveResolve(Node call, MethodInfo method, int depth, Explore ex) {
        if ("java/lang/reflect/Constructor".equals(call.owner())
                && "newInstance".equals(call.name())) {
            reflectiveConstructorResolve(call, method, depth, ex);
            return;
        }
        if (!"java/lang/reflect/Method".equals(call.owner())
                || !"invoke".equals(call.name())) {
            return;
        }
        ForwardOrigins.Result invokeOrigins = origins(method, ex);
        ForwardOrigins.State state = invokeOrigins.stateBefore().get(call.offset());
        if (state == null) {
            return;
        }
        for (ValueOrigin receiver : receiverOrigins(call, state)) {
            if (!(receiver instanceof ValueOrigin.CallResult cr)) {
                continue;
            }
            Node getMethod = support.callNode(cr.callNodeId());
            if (getMethod == null) {
                continue;
            }
            String gmName = getMethod.name();
            if (!"getMethod".equals(gmName) && !"getDeclaredMethod".equals(gmName)) {
                continue;
            }
            MethodInfo gmMethod = support.enclosingMethod(getMethod);
            if (gmMethod == null) {
                continue;
            }
            ForwardOrigins.Result lookupOrigins = origins(gmMethod, ex);
            String targetName = null;
            String targetClass = null;
            boolean controllableName = false;
            for (ValueOrigin nameOrigin : support.argOriginAtOrdinal(getMethod, 0, lookupOrigins)) {
                if (nameOrigin instanceof ValueOrigin.Constant c && c.value() instanceof String s) {
                    targetName = s;
                } else if (mayCarryTaint(nameOrigin)) {
                    controllableName = true;
                }
            }
            for (ValueOrigin clsOrigin : receiverOrigins(getMethod,
                    lookupOrigins.stateBefore().get(getMethod.offset()))) {
                targetClass = classNameOf(clsOrigin, ex);
                if (targetClass != null) {
                    break;
                }
            }
            String targetDescriptor = classArrayDescriptor(getMethod, lookupOrigins, 1);
            if (targetClass == null || (targetName == null && !controllableName)) {
                if (targetClass == null && (targetName != null || controllableName)) {
                    for (MethodInfo target : unresolvedReflectiveTargets(targetName, targetDescriptor)) {
                        propagateReflectiveInvocation(call, method, depth, ex, invokeOrigins,
                                target, 1, false, true);
                    }
                }
                continue;
            }
            List<MethodInfo> targets = reflectiveTargets(targetClass, targetName, targetDescriptor);
            for (MethodInfo target : targets) {
                propagateReflectiveInvocation(call, method, depth, ex, invokeOrigins,
                        target, 1, false, false);
            }
        }
    }

    private void reflectiveConstructorResolve(Node call, MethodInfo method, int depth, Explore ex) {
        ForwardOrigins.Result invokeOrigins = origins(method, ex);
        ForwardOrigins.State state = invokeOrigins.stateBefore().get(call.offset());
        if (state == null) {
            return;
        }
        for (ValueOrigin receiver : receiverOrigins(call, state)) {
            if (!(receiver instanceof ValueOrigin.CallResult cr) || cr.callNodeId() < 0) {
                continue;
            }
            Node lookup = support.callNode(cr.callNodeId());
            if (lookup == null || (!"getConstructor".equals(lookup.name())
                    && !"getDeclaredConstructor".equals(lookup.name()))) {
                continue;
            }
            MethodInfo lookupMethod = support.enclosingMethod(lookup);
            if (lookupMethod == null) {
                continue;
            }
            ForwardOrigins.Result lookupOrigins = origins(lookupMethod, ex);
            String targetClass = null;
            ForwardOrigins.State lookupState = lookupOrigins.stateBefore().get(lookup.offset());
            for (ValueOrigin classOrigin : receiverOrigins(lookup,
                    lookupState)) {
                targetClass = classNameOf(classOrigin, ex);
                if (targetClass != null) {
                    break;
                }
            }
            if (targetClass == null) {
                continue;
            }
            String descriptor = classArrayDescriptor(lookup, lookupOrigins, 0);
            List<MethodInfo> targets = reflectiveTargets(targetClass, "<init>", descriptor);
            for (MethodInfo target : targets) {
                propagateReflectiveInvocation(call, method, depth, ex, invokeOrigins,
                        target, 0, true, false);
            }
        }
    }

    private void propagateReflectiveInvocation(Node call, MethodInfo caller, int depth,
                                                Explore ex, ForwardOrigins.Result invokeOrigins,
                                                MethodInfo target, int argumentArrayOrdinal,
                                                boolean constructor, boolean unresolvedTarget) {
        if (support.sinkPathProvablyUnreachable(caller, call.offset())) {
            // The reflective operation itself is behind a proven-failed lookup or a local
            // impossible guard.  Do not manufacture a target fact merely because the
            // metadata resolver found a syntactic candidate.
            return;
        }
        if (!constructor && !unresolvedTarget
                && !support.reflectiveInvokeMayReach(target, call)) {
            // Method.invoke has JVM-level receiver/access preconditions.  Exact null or
            // inaccessible targets are not dispatch edges; unknown values stay conservative
            // inside OriginSupport.reflectiveInvokeMayReach.
            return;
        }
        activateReachable(target);
        if (!constructor && !target.isStatic()) {
            Set<ValueOrigin> targetReceivers = support.argOriginAtOrdinal(call, 0, invokeOrigins);
            for (ValueOrigin targetReceiver : targetReceivers) {
                if (!mayCarryTaint(targetReceiver)) {
                    continue;
                }
                List<ChainHop> path = tainted(targetReceiver, caller, depth + 1, ex);
                if (path != null) {
                    addThis(target.owner(), hopTo(path, caller, target.owner(), target.name(),
                            target.descriptor(), EdgeType.INVOKES), false);
                }
            }
        }
        Set<ValueOrigin> arrayOrigins = support.argOriginAtOrdinal(call, argumentArrayOrdinal,
                invokeOrigins);
        int parameters = Descriptor.paramCount(target.descriptor());
        for (int ordinal = 0; ordinal < parameters; ordinal++) {
            for (ValueOrigin argument : arrayElementOrigins(invokeOrigins, arrayOrigins, ordinal,
                    !unresolvedTarget)) {
                if (!mayCarryTaint(argument)) {
                    continue;
                }
                List<ChainHop> path = tainted(argument, caller, depth + 1, ex);
                if (path == null) {
                    continue;
                }
                int slot = parameterSlot(target.descriptor(), target.isStatic(), ordinal);
                if (slot >= 0) {
                    addParam(target.owner(), target.name(), target.descriptor(), slot,
                            hopTo(path, caller, target.owner(), target.name(),
                                    target.descriptor(), EdgeType.INVOKES));
                }
            }
        }
        emitReflectiveSinks(call, caller, ex, invokeOrigins, target,
                argumentArrayOrdinal, constructor, depth, unresolvedTarget);
    }

    /**
     * Reflection targets are not represented by ordinary call-graph edges.  Once a
     * descriptor/class constraint resolves one, add its bounded downstream closure to the
     * same reachability set used by ordinary calls; otherwise the new facts would be silently
     * discarded by the worklist and the final sink pass.
     */
    private void activateReachable(MethodInfo target) {
        String root = OriginSupport.methodKey(target);
        if (!reachable.add(root)) {
            return;
        }
        Deque<String> work = new ArrayDeque<>();
        work.add(root);
        int added = 0;
        while (!work.isEmpty() && added++ < REFLECTIVE_REACHABLE_CAP) {
            String key = work.removeFirst();
            for (Node call : bb.graph().callsOfMethod(key)) {
                for (Edge edge : call.out()) {
                    if (edge.type() == EdgeType.LAMBDA && isJdkOwner(edge.to().owner())) {
                        continue;
                    }
                    if (edge.type() != EdgeType.INVOKES && edge.type() != EdgeType.DISPATCHES
                            && edge.type() != EdgeType.LAMBDA) {
                        continue;
                    }
                    String next = methodNodeKey(edge.to());
                    if (reachable.add(next)) {
                        work.addLast(next);
                    }
                }
            }
        }
        if (!work.isEmpty()) {
            bb.markIncomplete("REFLECTIVE_REACHABLE_CAP:" + REFLECTIVE_REACHABLE_CAP);
        }
    }

    private List<MethodInfo> reflectiveTargets(String owner, String name, String descriptor) {
        ClassInfo cls = bb.hierarchy().classInfo(owner);
        if (cls == null) {
            return List.of();
        }
        List<MethodInfo> result = new ArrayList<>();
        for (MethodInfo candidate : cls.methods()) {
            if (name != null && !candidate.name().equals(name)) {
                continue;
            }
            if (name == null && !methodMatchesSink(candidate)) {
                continue;
            }
            if (descriptor != null && !descriptor.equals(candidate.descriptor())
                    && !sameParameters(candidate.descriptor(), descriptor)) {
                continue;
            }
            result.add(candidate);
            if (result.size() >= 32) {
                break;
            }
        }
        if (result.isEmpty() && descriptor != null) {
            String resolved = bb.hierarchy().resolveMethod(owner, name, descriptor);
            MethodInfo inherited = resolved == null ? null
                    : support.methodOf(resolved, name, descriptor);
            if (inherited != null) {
                result.add(inherited);
            }
        }
        return List.copyOf(result);
    }

    /**
     * Conservative reflection fallback: when Class/receiver metadata is not statically
     * recoverable, enumerate only methods that are already represented by a configured
     * sink call in this graph.  This preserves the rule boundary and avoids a whole-world
     * method search; the resulting chain carries one unresolved hop so callers can see that
     * exact receiver/signature proof is unavailable.
     */
    private List<MethodInfo> unresolvedReflectiveTargets(String name, String descriptor) {
        String key = String.valueOf(name) + "|" + String.valueOf(descriptor);
        List<MethodInfo> cached = reflectiveSinkCache.get(key);
        if (cached != null) {
            return cached;
        }
        Map<String, MethodInfo> unique = new LinkedHashMap<>();
        for (Node candidate : bb.graph().nodesOfType(NodeType.CALL)) {
            if (name != null && !name.equals(candidate.name())) {
                continue;
            }
            if (descriptor != null && !sameParameters(candidate.descriptor(), descriptor)) {
                continue;
            }
            if (!methodMatchesSink(candidate.owner(), candidate.name(), candidate.descriptor())) {
                continue;
            }
            MethodInfo target = support.methodOf(candidate.owner(), candidate.name(), candidate.descriptor());
            if (target != null) {
                unique.putIfAbsent(OriginSupport.methodKey(target), target);
            }
            if (unique.size() >= 32) {
                break;
            }
        }
        List<MethodInfo> result = List.copyOf(unique.values());
        reflectiveSinkCache.put(key, result);
        return result;
    }

    private boolean methodMatchesSink(MethodInfo method) {
        for (Rule.SinkRule sink : bb.rules().sinks()) {
            if (sink.call().matches(method.owner(), method.name(), method.descriptor())) {
                return true;
            }
        }
        return false;
    }

    private boolean methodMatchesSink(String owner, String name, String descriptor) {
        for (Rule.SinkRule sink : bb.rules().sinks()) {
            if (sink.call().matches(owner, name, descriptor)) {
                return true;
            }
        }
        return false;
    }

    private static boolean sameParameters(String left, String right) {
        int leftClose = left.indexOf(')');
        int rightClose = right.indexOf(')');
        return leftClose >= 0 && rightClose >= 0
                && left.substring(0, leftClose + 1).equals(right.substring(0, rightClose + 1));
    }

    /**
     * A reflective sink has no CALL node for the target method.  Emit the same rule-driven
     * chain that a normal sink CALL would produce once the Method object, target class and
     * attacker-controlled argument slot have all been resolved.
     */
    private void emitReflectiveSinks(Node call, MethodInfo caller, Explore ex,
                                     ForwardOrigins.Result invokeOrigins, MethodInfo target,
                                     int argumentArrayOrdinal, boolean constructor, int depth,
                                     boolean unresolvedTarget) {
        if (constructor) {
            return;
        }
        for (Rule.SinkRule rule : bb.rules().sinks()) {
            if (!rule.call().matches(target.owner(), target.name(), target.descriptor())) {
                continue;
            }
            List<ChainHop> path = null;
            for (Rule.TaintedPos position : rule.tainted()) {
                if (position instanceof Rule.TaintedPos.Receiver && !target.isStatic()) {
                    for (ValueOrigin receiver : support.argOriginAtOrdinal(call, 0, invokeOrigins)) {
                        if (!mayCarryTaint(receiver)) {
                            continue;
                        }
                        List<ChainHop> receiverPath = tainted(receiver, caller, depth + 1, ex);
                        if (receiverPath != null) {
                            path = hopTo(receiverPath, caller, target.owner(), target.name(),
                                    target.descriptor(), EdgeType.INVOKES);
                            break;
                        }
                    }
                } else if (position instanceof Rule.TaintedPos.Arg argument
                        && argument.index() >= 0
                        && argument.index() < Descriptor.paramCount(target.descriptor())) {
                    Set<ValueOrigin> arrays = support.argOriginAtOrdinal(call, argumentArrayOrdinal,
                            invokeOrigins);
                    for (ValueOrigin source : arrayElementOrigins(invokeOrigins, arrays,
                            argument.index(), !unresolvedTarget)) {
                        if (!mayCarryTaint(source)) {
                            continue;
                        }
                        List<ChainHop> argumentPath = tainted(source, caller, depth + 1, ex);
                        if (argumentPath != null) {
                            path = hopTo(argumentPath, caller, target.owner(), target.name(),
                                    target.descriptor(), EdgeType.INVOKES);
                            break;
                        }
                    }
                }
                if (path != null) {
                    break;
                }
            }
            if (path == null || path.isEmpty()) {
                continue;
            }
            List<ChainHop> hops = new ArrayList<>(path);
            Collections.reverse(hops);
            ChainHop entry = hops.get(hops.size() - 1);
            bb.addChain(new Chain(rule.id(), rule.category(), rule.severity(),
                    entry.fromOwner(), entry.fromName(),
                    entry.reason() == null ? "?" : entry.reason(),
                    target.owner(), target.name(), hops, unresolvedTarget ? 1 : 0,
                    target.descriptor()));
        }
    }

    private Set<ValueOrigin> receiverOrigins(Node call, ForwardOrigins.State state) {
        if (state == null) {
            return Set.of();
        }
        int depth = state.stack().size() - 1 - Descriptor.paramCount(call.descriptor());
        if (depth < 0 || depth >= state.stack().size()) {
            return Set.of();
        }
        return state.stack().get(depth).origins();
    }

    private Set<ValueOrigin> arrayElementOrigins(ForwardOrigins.Result result,
                                                  Set<ValueOrigin> arrays, int index) {
        return arrayElementOrigins(result, arrays, index, true);
    }

    private Set<ValueOrigin> arrayElementOrigins(ForwardOrigins.Result result,
                                                  Set<ValueOrigin> arrays, int index,
                                                  boolean allowOpaqueFallback) {
        Set<ValueOrigin> exact = new LinkedHashSet<>();
        Set<ValueOrigin> fallback = new LinkedHashSet<>();
        for (ValueOrigin array : arrays) {
            Map<Integer, Set<ValueOrigin>> indexed = result.indexedArrayElements().get(array);
            if (indexed != null && indexed.containsKey(index)) {
                exact.addAll(indexed.get(index));
            } else if (allowOpaqueFallback) {
                fallback.addAll(result.arrayElements().getOrDefault(array, Set.of()));
                // An opaque array (for example a serialized Object[] field) has no
                // static element map. Its value is still a valid conservative source
                // for each target parameter.
                if (indexed == null && result.arrayElements().get(array) == null) {
                    fallback.add(array);
                }
            }
        }
        return exact.isEmpty() && allowOpaqueFallback ? fallback : exact;
    }

    private String classNameOf(ValueOrigin origin, Explore ex) {
        if (origin instanceof ValueOrigin.Constant constant) {
            if (constant.value() instanceof TypeRef type) {
                return internalClassName(type.descriptor());
            }
            if (constant.value() instanceof String name) {
                return name.replace('.', '/');
            }
        }
        if (origin instanceof ValueOrigin.CallResult result && result.callNodeId() >= 0) {
            Node call = support.callNode(result.callNodeId());
            if (call != null && "java/lang/Class".equals(call.owner())
                    && "forName".equals(call.name())) {
                MethodInfo method = support.enclosingMethod(call);
                if (method != null) {
                    for (ValueOrigin name : support.argOriginAtOrdinal(call, 0, origins(method, ex))) {
                        if (name instanceof ValueOrigin.Constant constant
                                && constant.value() instanceof String text) {
                            return text.replace('.', '/');
                        }
                    }
                }
            }
        }
        return null;
    }

    private String classArrayDescriptor(Node lookup, ForwardOrigins.Result result, int ordinal) {
        Set<ValueOrigin> arrays = support.argOriginAtOrdinal(lookup, ordinal, result);
        Map<Integer, Set<ValueOrigin>> selected = null;
        for (ValueOrigin array : arrays) {
            Map<Integer, Set<ValueOrigin>> candidate = result.indexedArrayElements().get(array);
            if (candidate != null && !candidate.isEmpty()) {
                selected = candidate;
                break;
            }
        }
        if (selected == null) {
            return null;
        }
        int max = selected.keySet().stream().mapToInt(Integer::intValue).max().orElse(-1);
        StringBuilder descriptor = new StringBuilder("(");
        for (int i = 0; i <= max; i++) {
            Set<ValueOrigin> values = selected.get(i);
            if (values == null || values.size() != 1) {
                return null;
            }
            String type = classDescriptor(values.iterator().next());
            if (type == null) {
                return null;
            }
            descriptor.append(type);
        }
        return descriptor.append(")V").toString();
    }

    private static String classDescriptor(ValueOrigin origin) {
        if (!(origin instanceof ValueOrigin.Constant constant)
                || !(constant.value() instanceof TypeRef type)) {
            return null;
        }
        return type.descriptor();
    }

    private static String internalClassName(String descriptor) {
        if (descriptor == null) {
            return null;
        }
        if (descriptor.startsWith("L") && descriptor.endsWith(";")) {
            return descriptor.substring(1, descriptor.length() - 1);
        }
        // ASM represents NEW/ANEWARRAY operands as raw internal names while field and
        // method descriptors use L...; form. Accept both without treating primitive/array
        // descriptors as classes.
        if (!descriptor.isEmpty() && descriptor.indexOf('/') >= 0
                && descriptor.charAt(0) != '[' && descriptor.charAt(0) != '(') {
            return descriptor;
        }
        return null;
    }

    private List<ChainHop> taintedInsn(int offset, MethodInfo method, int depth, Explore ex) {
        ForwardOrigins.Result result = origins(method, ex);
        ForwardOrigins.State state = result.stateBefore().get(offset);
        if (state == null) {
            return null;
        }
        Op op = method.insnAt(offset).op();
        if (op == Op.NEWARRAY || op == Op.ANEWARRAY || op == Op.MULTIANEWARRAY) {
            for (ValueOrigin element : result.arrayElements().getOrDefault(new ValueOrigin.Insn(offset), Set.of())) {
                if (!mayCarryTaint(element)) {
                    continue;
                }
                List<ChainHop> path = tainted(element, method, depth + 1, ex);
                if (path != null) {
                    return path;
                }
            }
        }
        int consumed = OriginSupport.consumedCount(op);
        int start = Math.max(0, state.stack().size() - consumed);
        for (int i = start; i < state.stack().size(); i++) {
            for (ValueOrigin operand : state.stack().get(i).origins()) {
                if (!mayCarryTaint(operand)) {
                    continue;
                }
                List<ChainHop> path = tainted(operand, method, depth + 1, ex);
                if (path != null) {
                    return path;
                }
            }
        }
        return null;
    }

    // ---- 事实写入（键去重，全序取最小才替换；受影响方法入队） ----


    /** 调用图后序号（惰性一次）：沿 INVOKES/DISPATCHES/LAMBDA 边迭代 DFS 后序编号；
     *  回边（环）剪断不重入——环上节点接受单次摘要（GadgetInspector 同款简化）。 */
    private void ensureTopoOrder() {
        if (topoOrder != null) {
            return;
        }
        Map<String, List<String>> succ = new HashMap<>();
        for (String key : reachable) {
            if (resolveMethodKey(key) == null) {
                continue;
            }
            List<String> out = new ArrayList<>(2);
            for (Node call : bb.graph().callsOfMethod(key)) {
                for (Edge edge : call.out()) {
                    if (edge.type() == EdgeType.INVOKES || edge.type() == EdgeType.DISPATCHES
                            || edge.type() == EdgeType.LAMBDA) {
                        String callee = methodNodeKey(edge.to());
                        if (reachable.contains(callee)) {
                            out.add(callee);
                        }
                    }
                }
            }
            out.sort(String::compareTo);
            if (out.size() > 1) {
                int unique = 1;
                for (int i = 1; i < out.size(); i++) {
                    if (!out.get(i).equals(out.get(unique - 1))) {
                        out.set(unique++, out.get(i));
                    }
                }
                out.subList(unique, out.size()).clear();
            }
            succ.put(key, List.copyOf(out));
        }
        Map<String, Integer> order = new HashMap<>(succ.size() * 2);
        Set<String> done = new HashSet<>();
        Set<String> onPath = new HashSet<>();
        Deque<Object[]> stack = new ArrayDeque<>(); // [方法键, 出边迭代位置]
        List<String> starts = new ArrayList<>(succ.keySet());
        starts.sort(String::compareTo);
        for (String start : starts) {
            if (done.contains(start)) {
                continue;
            }
            stack.push(new Object[]{start, 0});
            onPath.add(start);
            while (!stack.isEmpty()) {
                Object[] frame = stack.peek();
                String key = (String) frame[0];
                int i = (Integer) frame[1];
                List<String> out = succ.getOrDefault(key, List.of());
                boolean descended = false;
                for (; i < out.size(); i++) {
                    String next = out.get(i);
                    if (done.contains(next) || onPath.contains(next)) {
                        continue; // 回边剪断
                    }
                    frame[1] = i + 1;
                    stack.push(new Object[]{next, 0});
                    onPath.add(next);
                    descended = true;
                    break;
                }
                if (!descended) {
                    stack.pop();
                    onPath.remove(key);
                    done.add(key);
                    order.put(key, order.size()); // 后序：被调者编号小（先处理）
                }
            }
        }
        topoOrder = order;
    }

    /**
     * 去重入队：已在队列（未处理）的方法不重复排队；可达剪枝开启时限可达集
     * （污点实参传入 JDK 调用点曾把整个 JDK 宇宙拉进 worklist——队列 33 万，
     * 步数预算轮数=1 即截断）。事实本身仍记录（demand 求值可消费），只挡处理调度。
     */
    private void enqueue(String methodKey) {
        if (options.reachablePrune() && !reachable.contains(methodKey)) {
            return;
        }
        if (pending.add(methodKey)) {
            queue.add(methodKey);
        }
    }
    // 替换序为全序（链长，其次跳序列规范形）：并行下同长度路径的代表选择与处理顺序无关（NFR8 确定性）。

    private void addThis(String className, List<ChainHop> path) {
        addThis(className, path, true);
    }

    /**
     * Add a receiver fact for an already selected call target.  A call edge is a
     * concrete dispatch result, not a new source for every subtype of the target's
     * declaration.  Widening {@code Object.hashCode()} (or an interface method) here
     * poisons unrelated serializable objects and can replace a real, longer path with
     * a short false path.  Entry seeds retain the widening mode because an inherited
     * callback is a genuine runtime entry for a subtype without an override.
     */
    private void addThis(String className, List<ChainHop> path, boolean propagateSubtypes) {
        if (!sourceBacked(path) || path.size() > MAX_HOPS) {
            return;
        }
        List<ChainHop> existing = thisTainted.get(className);
        if (!better(existing, path)) {
            return;
        }
        List<ChainHop> snapshot = List.copyOf(path);
        thisTainted.put(className, snapshot);
        factVersion++;
        factCount++;
        ClassInfo cls = bb.hierarchy().classInfo(className);
        if (cls != null) {
            for (MethodInfo method : cls.methods()) {
                if (!options.reachablePrune() || reachable.contains(OriginSupport.methodKey(method))) {
                    enqueue(OriginSupport.methodKey(method));
                }
            }
        }
        if (!propagateSubtypes) {
            return;
        }
        // 类级对象污点向加载的传递子类型传递（运行时对象必是某子类型），有界防爆
        int subTainted = 0;
        for (String sub : bb.hierarchy().transitiveSubtypes(className)) {
            if (subTainted++ >= 100) {
                break;
            }
            // A base-class callback is not a source for an overriding subclass method:
            // JVM virtual dispatch selects the override and never executes the base body
            // unless it explicitly calls super.  Copying the same ENTRY path to every
            // subtype previously manufactured chains such as Base.hashCode -> Sink in a
            // child override.  Keep subtype propagation for inherited callbacks and for
            // non-callback object facts; the child's own matching entry will seed the
            // override with its real provenance.
            if (!entryCanBeInherited(className, sub, snapshot)) {
                continue;
            }
            List<ChainHop> subExisting = thisTainted.get(sub);
            if (better(subExisting, snapshot)) {
                thisTainted.put(sub, snapshot);
                factVersion++;
                factCount++;
                ClassInfo subInfo = bb.hierarchy().classInfo(sub);
                if (subInfo != null) {
                    for (MethodInfo method : subInfo.methods()) {
                        if (!options.reachablePrune() || reachable.contains(OriginSupport.methodKey(method))) {
                            enqueue(OriginSupport.methodKey(method));
                        }
                    }
                }
            }
        }
    }

    private boolean entryCanBeInherited(String baseClass, String subtype, List<ChainHop> path) {
        ChainHop entry = null;
        for (ChainHop hop : path) {
            if (hop.kind() == HopKind.ENTRY) {
                entry = hop;
                break;
            }
        }
        if (entry == null || !baseClass.equals(entry.fromOwner())) {
            return true;
        }
        ClassInfo child = bb.hierarchy().classInfo(subtype);
        if (child == null) {
            return true;
        }
        for (MethodInfo method : child.methods()) {
            if (method.name().equals(entry.fromName())
                    && method.descriptor().equals(entry.desc())) {
                return false;
            }
        }
        return true;
    }

    private void addField(String owner, String field, List<ChainHop> path) {
        String key = owner + "#" + field;
        if (!sourceBacked(path) || path.size() > MAX_HOPS) {
            return;
        }
        if (!better(fieldTainted.get(key), path)) {
            return;
        }
        List<ChainHop> snapshot = List.copyOf(path);
        fieldTainted.put(key, snapshot);
        factVersion++;
        factCount++;
        Set<String> readers = fieldReaders.get(key);
        if (readers != null) {
            readers.forEach(this::enqueue);
        }
    }

    private static boolean isDeserializationSource(Rule.SourceRule source) {
        return source != null && !"serialize".equalsIgnoreCase(source.bridge());
    }

    private void addReturn(String methodKey, List<ChainHop> path) {
        if (!sourceBacked(path) || path.size() > MAX_HOPS) {
            return;
        }
        if (!better(returnTainted.get(methodKey), path)) {
            return;
        }
        List<ChainHop> snapshot = List.copyOf(path);
        returnTainted.put(methodKey, snapshot);
        factVersion++;
        factCount++;
        List<Node> callerCalls = callers.get(methodKey);
        if (callerCalls != null) {
            for (Node caller : callerCalls) {
                if (!options.reachablePrune() || reachable.contains(OriginSupport.methodKey(caller))) {
                    enqueue(OriginSupport.methodKey(caller));
                }
            }
        }
    }

    private void addParam(String owner, String name, String desc, int slot, List<ChainHop> path) {
        String methodKey = OriginSupport.methodKeyOf(owner, name, desc);
        String key = methodKey + "#" + slot;
        if (!sourceBacked(path) || path.size() > MAX_HOPS) {
            return;
        }
        if (!better(paramTainted.get(key), path)) {
            return;
        }
        List<ChainHop> snapshot = List.copyOf(path);
        paramTainted.put(key, snapshot);
        factVersion++;
        factCount++;
        enqueue(methodKey);
    }

    /** 候选是否严格优于现存：短者优先；同长按跳序列规范形字典序——总序，消除并行平局随机性。 */
    private static boolean better(List<ChainHop> existing, List<ChainHop> candidate) {
        if (existing == null) {
            return true;
        }
        if (candidate.size() != existing.size()) {
            return candidate.size() < existing.size();
        }
        // Most propagation attempts rediscover the same immutable path.  Equality is
        // semantically identical to canonical comparison but avoids allocating two
        // transient StringBuilders for the common no-op update.
        if (existing.equals(candidate)) {
            return false;
        }
        return compareCanonical(candidate, existing) < 0;
    }

    /**
     * Forward facts are only meaningful when they retain a source provenance.  A
     * dispatch edge created while exploring an already incomplete summary must not
     * become a new, shorter taint root; otherwise it can overwrite a real ENTRY path
     * in a class/field summary and hide an otherwise valid chain.  All source kinds
     * (magic entry, ObjectInputStream and framework deserialize bridges) materialize
     * an ENTRY hop in taintedCallResult/seedEntries.
     */
    private static boolean sourceBacked(List<ChainHop> path) {
        if (path == null || path.isEmpty()) {
            return false;
        }
        for (ChainHop hop : path) {
            if (hop.kind() == HopKind.ENTRY) {
                return true;
            }
        }
        return false;
    }

    /** 与旧的 ChainHop.toString() 拼接顺序一致，但不为每次平局比较构造字符串。 */
    private static int compareCanonical(List<ChainHop> left, List<ChainHop> right) {
        for (int i = 0; i < left.size(); i++) {
            ChainHop a = left.get(i);
            ChainHop b = right.get(i);
            int comparison = compareNullable(a.fromOwner(), b.fromOwner());
            if (comparison != 0) return comparison;
            comparison = compareNullable(a.fromName(), b.fromName());
            if (comparison != 0) return comparison;
            comparison = compareNullable(a.toOwner(), b.toOwner());
            if (comparison != 0) return comparison;
            comparison = compareNullable(a.toName(), b.toName());
            if (comparison != 0) return comparison;
            comparison = compareNullable(a.kind(), b.kind());
            if (comparison != 0) return comparison;
            comparison = compareNullable(a.field(), b.field());
            if (comparison != 0) return comparison;
            comparison = compareNullable(a.reason(), b.reason());
            if (comparison != 0) return comparison;
            comparison = compareNullable(a.desc(), b.desc());
            if (comparison != 0) return comparison;
            comparison = compareNullable(a.argOrdinal(), b.argOrdinal());
            if (comparison != 0) return comparison;
        }
        return Integer.compare(left.size(), right.size());
    }

    private static int compareNullable(Object left, Object right) {
        return String.valueOf(left).compareTo(String.valueOf(right));
    }

    private static List<ChainHop> hopTo(List<ChainHop> parent, MethodInfo from,
                                        String toOwner, String toName, String toDesc, EdgeType type) {
        return hopTo(parent, from, toOwner, toName, toDesc, type, null);
    }

    private static List<ChainHop> hopTo(List<ChainHop> parent, MethodInfo from,
                                        String toOwner, String toName, String toDesc, EdgeType type,
                                        Integer argOrdinal) {
        if (parent.size() >= MAX_HOPS) {
            return parent;
        }
        List<ChainHop> path = new ArrayList<>(parent);
        path.add(new ChainHop(from.owner(), from.name(), toOwner, toName,
                type == EdgeType.DISPATCHES ? HopKind.VIRTUAL_DISPATCH : HopKind.DIRECT_CALL, null, "call", toDesc,
                argOrdinal));
        return path;
    }

    // ---- 工具 ----

    private MethodInfo resolveMethodKey(String key) {
        int sep = key.indexOf('#');
        int paren = key.indexOf('(', sep);
        if (sep < 0 || paren < 0) {
            return null;
        }
        return support.methodOf(key.substring(0, sep), key.substring(sep + 1, paren), key.substring(paren));
    }


    private static boolean isJdkOwner(String owner) {
        return owner.startsWith("java/") || owner.startsWith("javax/") || owner.startsWith("jdk/")
                || owner.startsWith("sun/") || owner.startsWith("com/sun/");
    }

    /** invokedynamic 的描述符只包含真实参数，没有隐含 receiver；与 JVM 栈语义一致。 */
    private static boolean isStaticLike(String invokeKind) {
        return "STATIC".equals(invokeKind) || "DYNAMIC".equals(invokeKind);
    }

    /**
     * 常量/不可解析来源在本引擎中不能形成入口污点；lambda 绑定在调用方单独驱动，
     * 因此该判断只用于跳过不必要的污点递归，不改变结构性传播。
     */
    private static boolean mayCarryTaint(ValueOrigin origin) {
        return !(origin instanceof ValueOrigin.Constant || origin instanceof ValueOrigin.Unknown);
    }

    private static String methodNodeKey(Node method) {
        return OriginSupport.methodKeyOf(method.owner(), method.name(), method.descriptor());
    }
}
