package io.just.sast.knowledge.engine;

import io.just.sast.analysis.taint.ForwardOrigins;
import io.just.sast.analysis.taint.OriginSupport;
import io.just.sast.analysis.taint.ValueOrigin;
import io.just.sast.blackboard.Blackboard;
import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.HopKind;
import io.just.sast.config.Rule;
import io.just.sast.cpg.graph.Edge;
import io.just.sast.cpg.graph.EdgeType;
import io.just.sast.cpg.graph.Node;
import io.just.sast.cpg.graph.NodeType;
import io.just.sast.model.ClassInfo;
import io.just.sast.model.Descriptor;
import io.just.sast.model.InsnFact;
import io.just.sast.model.MethodInfo;
import io.just.sast.model.Op;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.LongAdder;

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
    /** B1: 精扫并行 worker 数（与反向引擎一致）。 */

    /** 事实：键 → 前向路径（首元素为 ENTRY hop）。并发容器：精扫并行批中 worker 直接写入。 */
    private final Map<String, List<ChainHop>> thisTainted = new ConcurrentHashMap<>();
    private final Map<String, List<ChainHop>> fieldTainted = new ConcurrentHashMap<>();
    private final Map<String, List<ChainHop>> returnTainted = new ConcurrentHashMap<>();
    private final Map<String, List<ChainHop>> paramTainted = new ConcurrentHashMap<>();
    /** 死胡同缓存：键 = 方法键|origin，值 = 记录时的事实版本（factVersion 单调递增，跨轮有效）。 */
    private final Map<String, Long> deadEnds = new ConcurrentHashMap<>();

    /** 字段读者索引：fieldKey → 方法集合（新字段事实时入队）。构造期单线程构建。 */
    private final Map<String, Set<String>> fieldReaders = new HashMap<>();
    /** 调用者索引：方法键 → 调用点（return 事实传播用，含接口反向分发）。构造期单线程构建。 */
    private final Map<String, List<Node>> callers = new HashMap<>();

    /** 反序列化可达方法集（前向 BFS 边界：只在该子集内传播；两轮共用，首轮构建）。 */
    private final Set<String> reachable = new HashSet<>();
    private static final int REACHABLE_CAP = 200_000;
    private static final int INTERFACE_EXPAND_CAP = 2000;
    /** lambda 绑定：方法#实参槽 → 该参数将持有的 lambda 实现方法（含接口实参→实现参数的槽位偏移）。 */
    private final Map<String, List<LambdaBind>> lambdaBinds = new ConcurrentHashMap<>();
    /** lambda 实现绑定（实现方法的定位三元组；槽位偏移在消费时按实际接口调用点计算）。 */
    private record LambdaBind(String implOwner, String implName, String implDesc) {}
    private final Blackboard bb;
    private final OriginSupport support;
    private Options options;
    /** 事实版本：单调递增，永不重置（死胡同缓存跨轮失效判定；事实集合跨轮单调只增）。 */
    private final AtomicLong factVersion = new AtomicLong();
    /** 本轮统计/预算（每轮重置；精扫并行批中 worker 并发递增）。 */
    private final LongAdder factCount = new LongAdder();
    private final LongAdder steps = new LongAdder();
    private final LongAdder methodPasses = new LongAdder();
    private final Queue<String> queue = new ConcurrentLinkedQueue<>();
    /** 队列去重伴随集：queue 中现存的方法键（事实驱动的大语料入队有 5-6 倍重复；
     *  poll 时移除——处理期间的新入队会进下一轮）。 */
    private final Set<String> pending = ConcurrentHashMap.newKeySet();
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
        final Set<String> visiting = new HashSet<>();
        boolean truncated;
    }


    public ForwardEngine(Blackboard bb) {
        this.bb = bb;
        this.support = bb.originSupport();
        buildIndexes();
    }

    private void buildIndexes() {
        for (Node method : bb.graph().nodesOfType(NodeType.METHOD)) {
            MethodInfo info = support.methodOf(method.strProp("owner"), method.strProp("name"), method.strProp("desc"));
            if (info == null) {
                continue;
            }
            String key = OriginSupport.methodKey(info);
            for (InsnFact insn : info.instructions()) {
                if (insn.op().isFieldRead()) {
                    fieldReaders.computeIfAbsent(insn.fieldRef().owner() + "#" + insn.fieldRef().name(),
                            k -> new HashSet<>()).add(key);
                }
            }
            for (Edge edge : method.in()) {
                if (edge.type() == EdgeType.INVOKES || edge.type() == EdgeType.DISPATCHES) {
                    callers.computeIfAbsent(key, k -> new ArrayList<>()).add(edge.from());
                }
            }
        }
        // 接口反向分发：接口方法节点的调用点并入实现类方法（同反向引擎语义）
        for (Node method : bb.graph().nodesOfType(NodeType.METHOD)) {
            String owner = method.strProp("owner");
            MethodInfo info = support.methodOf(owner, method.strProp("name"), method.strProp("desc"));
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
        boolean firstRun = factVersion.get() == 0;
        // 预算按轮重置（每轮独立预算）。非首轮只重入队"受影响方法"：
        // 已污点类的方法 + 已有参数/返回事实的方法 + 已污点字段的读者——
        // 与独立精扫引擎的种子+事实驱动增长等价，规模受控（全量可达集重处理会烧尽预算）；
        // 新事实派生的受影响方法由 addThis/addField/addReturn/addParam 的入队机制自动扩散。
        steps.reset();
        methodPasses.reset();
        factCount.reset();
        if (!firstRun) {
            requeueAffected();
        }
        seedEntries();
        ensureTopoOrder();
        int rounds = 0;
        // B1: 精扫并行化——processEffects 按 batch 并行（refined pass 专用，coarse 保持串行）。
        // 共享结构均为并发容器（事实表/死胡同缓存 CHM、队列 CLQ、计数 LongAdder）；
        // 环守卫（visiting）按探索私有——作为参数在递归内传递，不跨线程共享。
        while (!queue.isEmpty() && rounds < MAX_ROUNDS && steps.sum() < STEP_BUDGET
                && methodPasses.sum() < METHOD_PASS_CAP) {
            rounds++;
            List<String> current = new ArrayList<>();
            for (String key; (key = queue.poll()) != null; ) {
                pending.remove(key);
                current.add(key);
            }
            // 后序处理（被调者先）：单调事实集的收敛与顺序无关（Soufflé 并行合流结论），
            // 但步数预算受限时拓扑序显著降低 churn——批内串行换轮数收敛
            if (topoOrder != null) {
                current.sort(java.util.Comparator.comparingInt(k -> topoOrder.getOrDefault(k, Integer.MAX_VALUE)));
            }
            for (String key : current) {
                MethodInfo method = resolveMethodKey(key);
                if (method != null) {
                    methodPasses.increment();
                    processEffects(method);
                }
            }
        }
        if (!queue.isEmpty()) {
            // 截断未收敛：剩余事实未处理，本轮结果可能欠完备（不静默）
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
                options.expandInterfaces() ? "精扫" : "粗扫", reachable.size(), factCount.sum(), rounds);
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

    /** 前向可达集：从 magic entry 与 OIS 宿主出发，沿调用边 BFS（接口按上限展开）。入口按规则自匹配。 */
    private void computeReachable() {
        Deque<String> bfs = new ArrayDeque<>();
        for (Node method : bb.graph().nodesOfType(NodeType.METHOD)) {
            if (isMagicEntry(method) && reachable.add(methodNodeKey(method))) {
                bfs.add(methodNodeKey(method));
            }
        }
        for (Node call : bb.graph().nodesOfType(NodeType.CALL)) {
            if (OriginSupport.isOisRead(call) && reachable.add(OriginSupport.methodKey(call))) {
                bfs.add(OriginSupport.methodKey(call));
            }
        }
        while (!bfs.isEmpty() && reachable.size() < REACHABLE_CAP) {
            String key = bfs.poll();
            MethodInfo method = resolveMethodKey(key);
            if (method == null) {
                continue;
            }
            for (InsnFact insn : method.instructions()) {
                if (!insn.op().isInvoke()) {
                    continue;
                }
                Long callId = support.callId(key, insn.offset());
                if (callId == null) {
                    continue;
                }
                Node call = bb.graph().node(callId);
                for (Edge edge : call.out()) {
                    // LAMBDA 边仅跟随应用类实现：JDK 内部 lambda（Stream/Function 管道）会把
                    // 可达集经 JDK 图引爆（54k 方法，前向预算轮数=1 即截断）；gadget 的
                    // lambda 实现在应用/库代码中
                    if (edge.type() == EdgeType.LAMBDA && isJdkOwner(edge.to().strProp("owner"))) {
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
                List<String> impls = bb.hierarchy().implementers(call.strProp("owner"), 10_000);
                if (impls != null) {
                    int expanded = 0;
                    for (String impl : impls) {
                        if (expanded >= INTERFACE_EXPAND_CAP) {
                            break;
                        }
                        expanded++;
                        String resolved = bb.hierarchy().resolveMethod(impl, call.strProp("name"),
                                call.strProp("desc"));
                        if (resolved != null && reachable.add(OriginSupport.methodKeyOf(resolved, call.strProp("name"),
                                call.strProp("desc")))) {
                            bfs.add(OriginSupport.methodKeyOf(resolved, call.strProp("name"),
                                    call.strProp("desc")));
                        }
                    }
                }
            }
        }
    }

    /** 种子：magic entry 的 this 是反序列化对象；入队其所在类的全部方法。入口按规则自匹配。 */
    private void seedEntries() {
        for (Node method : bb.graph().nodesOfType(NodeType.METHOD)) {
            bb.ruleEngine().matchingEntry(method.strProp("owner"), method.strProp("name"),
                            method.strProp("desc"))
                    .ifPresent(rule -> {
                        String owner = method.strProp("owner");
                        ChainHop entryHop = new ChainHop(owner, method.strProp("name"),
                                owner, method.strProp("name"), HopKind.ENTRY, null, rule.entryKind(),
                                method.strProp("desc"), null);
                        addThis(owner, List.of(entryHop));
                    });
        }
    }

    private boolean isMagicEntry(Node method) {
        return bb.ruleEngine().matchingEntry(method.strProp("owner"), method.strProp("name"),
                method.strProp("desc")).isPresent();
    }

    /** 方法效果：PUTFIELD 存污点值 → 字段事实；RETURN 污点值 → 返回事实；AASTORE 污点值 → 数组容器污点。 */
    private void processEffects(MethodInfo method) {
        Explore ex = new Explore();
        for (InsnFact insn : method.instructions()) {
            Op op = insn.op();
            if (op.isFieldWrite() && op != Op.PUTSTATIC) {
                ForwardOrigins.State state = support.origins().compute(method).stateBefore().get(insn.offset());
                if (state == null || state.stack().isEmpty()) {
                    continue;
                }
                for (ValueOrigin value : state.stack().get(state.stack().size() - 1).origins()) {
                    List<ChainHop> path = tainted(value, method, 0, ex);
                    if (path != null) {
                        addField(insn.fieldRef().owner(), insn.fieldRef().name(), path);
                    }
                }
            } else if (op == Op.AASTORE) {
                // 数组元素流（field/param 粒度）：AASTORE 污点值 → 数组容器污点。
                // 栈形 ..., arrayref, index, value → arrayref 在 size-3。对象数组是 gadget 中转载体；
                // 原始类型数组（IASTORE 等）不承载引用污点，不处理。
                ForwardOrigins.State state = support.origins().compute(method).stateBefore().get(insn.offset());
                if (state == null || state.stack().size() < 3) {
                    continue;
                }
                for (ValueOrigin value : state.stack().get(state.stack().size() - 1).origins()) {
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
                // 其余调用维持需求驱动：全量主动传播会在真实语料上制造短路径挤占事实表
                // （被校验拒绝的形态替换可用长路径）与预算爆炸（历史回归：demo 语料 findings -24%）。
                Long callId = support.callId(OriginSupport.methodKey(method), insn.offset());
                if (callId != null) {
                    Node callNode = bb.graph().node(callId);
                    if (callNode != null) {
                        propagateCallArgs(callNode, method, 0, ex);
                    }
                }
            } else if (op.isReturn() && op != Op.RETURN && op != Op.ATHROW) {
                ForwardOrigins.State state = support.origins().compute(method).stateBefore().get(insn.offset());
                if (state == null || state.stack().isEmpty()) {
                    continue;
                }
                for (ValueOrigin value : state.stack().get(state.stack().size() - 1).origins()) {
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
        ForwardOrigins.State state = support.origins().compute(method).stateBefore().get(call.prop("offset"));
        if (state == null) {
            return;
        }
        if (support.catchProvablyUnreachable(method, (Integer) call.prop("offset"))) {
            return; // catch 不可达守卫（与反向引擎同谓词）
        }
        Explore ex = new Explore();
        int paramCount = Descriptor.paramCount(call.strProp("desc"));
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
                List<ChainHop> path = tainted(origin, method, 0, ex);
                if (path == null) {
                    continue;
                }
                List<ChainHop> hops = new ArrayList<>(path);
                Collections.reverse(hops); // 前向路径翻转为 sink→entry
                ChainHop entry = hops.get(hops.size() - 1);
                Chain chain = new Chain(rule.id(), rule.category(), rule.severity(),
                        entry.fromOwner(), entry.fromName(), entry.reason() == null ? "?" : entry.reason(),
                        call.strProp("owner"), call.strProp("name"), hops, 0);
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
        if (depth > MAX_DEPTH || steps.sum() > STEP_BUDGET) {
            ex.truncated = true;
            return null;
        }
        steps.increment();
        String key = OriginSupport.methodKey(method) + "|" + origin;
        Long deadAt = deadEnds.get(key);
        if ((deadAt != null && deadAt == factVersion.get()) || ex.visiting.contains(key)) {
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
        if (path == null && !subtreeTruncated) {
            deadEnds.put(key, factVersion.get());
            if (deadEnds.size() > DEAD_END_SWEEP) {
                long version = factVersion.get();
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
        Node call = bb.graph().node(callNodeId);
        if (OriginSupport.isOisRead(call)) {
            ChainHop entryHop = new ChainHop(method.owner(), method.name(),
                    method.owner(), method.name(), HopKind.ENTRY, null, "deserialization", "", null);
            return List.of(entryHop);
        }
        ForwardOrigins.State state = support.origins().compute(method).stateBefore().get(call.prop("offset"));
        if (state == null) {
            return null;
        }
        List<ChainHop> best = propagateCallArgs(call, method, depth + 1, ex);
        String kind = call.strProp("invokeKind");
        boolean calleeStatic = "STATIC".equals(kind);
        // model 规则（声明式摘要）：return←src 透传、this←argN 容器投毒
        var model = bb.ruleEngine().matchingModel(call.strProp("owner"), call.strProp("name"),
                call.strProp("desc"));
        if (model.isPresent()) {
            best = applyModel(model.get(), call, method, depth, best, ex);
        }
        for (Edge edge : call.out()) {
            if (edge.type() != EdgeType.INVOKES && edge.type() != EdgeType.DISPATCHES) {
                continue;
            }
            List<ChainHop> returnPath = returnTainted.get(methodNodeKey(edge.to()));
            if (returnPath != null && best == null) {
                best = returnPath;
            }
        }
        if (options.expandInterfaces()) {
            expandInterfaces(call, method, depth, best != null, ex);
        }
        if (options.threadProxy() && best != null && !calleeStatic) {
            threadProxy(call, method, depth, ex);
        }
        if (options.reflectiveResolve()) {
            reflectiveResolve(call, method, depth);
        }
        return best;
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
        Node indyCall = bb.graph().node(indy.callNodeId());
        if (indyCall == null) {
            return;
        }
        String calleeKey = methodNodeKey(call);
        String bindKey = calleeKey + "#" + slot;
        for (Edge edge : indyCall.out()) {
            if (edge.type() != EdgeType.LAMBDA) {
                continue;
            }
            String implOwner = edge.to().strProp("owner");
            String implName = edge.to().strProp("name");
            String implDesc = edge.to().strProp("desc");
            if (support.methodOf(implOwner, implName, implDesc) == null) {
                continue;
            }
            List<LambdaBind> binds = lambdaBinds.computeIfAbsent(bindKey, k -> new CopyOnWriteArrayList<>());
            LambdaBind bind = new LambdaBind(implOwner, implName, implDesc);
            if (!binds.contains(bind)) {
                binds.add(bind);
            }
        }
    }

    /**
     * 调用点污点传播（接收者 + 实参 + lambda 绑定/消费）：void 中转调用无返回值消费，
     * 需求驱动（sink 求值链）不会评估它——processEffects 对每个调用点主动驱动本方法；
     * taintedCallResult 的实参求值复用同一实现。返回首个命中的污点路径（无则 null）。
     */
    private List<ChainHop> propagateCallArgs(Node call, MethodInfo method, int depth, Explore ex) {
        ForwardOrigins.State state = support.origins().compute(method).stateBefore().get(call.prop("offset"));
        if (state == null) {
            return null;
        }
        List<ChainHop> best = null;
        String kind = call.strProp("invokeKind");
        boolean calleeStatic = "STATIC".equals(kind);
        Set<ValueOrigin> receiverOrigins = Set.of();
        if (!calleeStatic) {
            int receiverDepth = state.stack().size() - 1 - Descriptor.paramCount(call.strProp("desc"));
            if (receiverDepth >= 0 && receiverDepth < state.stack().size()) {
                receiverOrigins = state.stack().get(receiverDepth).origins();
                for (ValueOrigin receiver : receiverOrigins) {
                    List<ChainHop> receiverPath = tainted(receiver, method, depth, ex);
                    if (receiverPath != null) {
                        for (Edge edge : call.out()) {
                            if (edge.type() == EdgeType.INVOKES || edge.type() == EdgeType.DISPATCHES) {
                                addThis(edge.to().strProp("owner"), hopTo(receiverPath, method,
                                        edge.to().strProp("owner"), edge.to().strProp("name"),
                                        edge.to().strProp("desc"), edge.type()));
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
        List<Integer> argSlots = Descriptor.argSlots(call.strProp("desc"), calleeStatic);
        int slot = 0;
        for (int i = 0; i < argSlots.size(); i++) {
            for (ValueOrigin argOrigin : support.argOriginAt(call, method, slot)) {
                // lambda 绑定（结构性，与污点无关）：实参为 indy 结果时，记录被调方法的该槽位
                // 将持有 lambda 实现方法——消费端在被调方法体内经此 receiver 调接口方法时定向分发
                bindLambdaArg(argOrigin, call, slot);
                List<ChainHop> argPath = tainted(argOrigin, method, depth, ex);
                if (argPath == null) {
                    continue;
                }
                if (best == null) {
                    best = argPath;
                }
                for (Edge edge : call.out()) {
                    if (edge.type() == EdgeType.INVOKES || edge.type() == EdgeType.DISPATCHES) {
                        addParam(edge.to().strProp("owner"), edge.to().strProp("name"),
                                edge.to().strProp("desc"), slot, hopTo(argPath, method,
                                        edge.to().strProp("owner"), edge.to().strProp("name"),
                                        // argOrdinal 不设：前向 hop 是调用路径记录而非值流轨迹，
                                        // 类型流校验的相邻跳配对语义只适用反向链（历史回归：CC BeanMap 链被误拒）
                                        edge.to().strProp("desc"), edge.type(), null));
                    }
                }
                // lambda 消费：接口调用的 receiver 是已绑定 lambda 的参数时，污点实参传给实现方法。
                // 实现参数布局 = 捕获变量前缀 + 函数式接口方法参数；captured 数 = 实现参数数 - 接口参数数
                // （接口参数数取本调用点的描述符——indy 自身的 desc 是 factory 签名，不含接口参数）。
                // 实现槽位 = 捕获前缀槽宽和（实例实现含 receiver 槽）+ 实参序数（不含接收者）。
                if (receiverOrigins.stream().anyMatch(o -> o instanceof ValueOrigin.Param)) {
                    int ordinal = Descriptor.paramOrdinal(call.strProp("desc"), calleeStatic, slot);
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
            }
            slot += argSlots.get(i);
        }
        return best;
    }


    /** lambda 实现方法中接口实参 ordinal 的局部槽位（捕获前缀 + 序数）。 */
    private int implArgSlotOf(LambdaBind bind, Node ifaceCall, int ordinal) {
        MethodInfo impl = support.methodOf(bind.implOwner(), bind.implName(), bind.implDesc());
        boolean implStatic = impl == null || impl.isStatic();
        int captured = Math.max(0, Descriptor.paramCount(bind.implDesc())
                - Descriptor.paramCount(ifaceCall.strProp("desc")));
        List<Integer> slots = Descriptor.argSlots(bind.implDesc(), implStatic);
        int offset = 0;
        int skip = captured + (implStatic ? 0 : 1);
        for (int c = 0; c < skip && c < slots.size(); c++) {
            offset += slots.get(c);
        }
        return offset + ordinal;
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
                        best = hopTo(srcPath, method, call.strProp("owner"), call.strProp("name"),
                                call.strProp("desc"), EdgeType.INVOKES);
                    }
                } else if ("this".equals(action.getKey())) {
                    addThis(call.strProp("owner"), srcPath);
                }
            }
        }
        return best;
    }

    /** model 动作来源位置的污点路径：this（receiver）或 argN（第 N 实参）。 */
    private List<ChainHop> modelSourcePath(String src, Node call, MethodInfo method, int depth,
                                           Explore ex) {
        ForwardOrigins.State state = support.origins().compute(method).stateBefore().get(call.prop("offset"));
        if (state == null) {
            return null;
        }
        boolean calleeStatic = "STATIC".equals(call.strProp("invokeKind"));
        if ("this".equals(src)) {
            if (calleeStatic) {
                return null;
            }
            int receiverDepth = state.stack().size() - 1 - Descriptor.paramCount(call.strProp("desc"));
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
            List<Integer> argSlots = Descriptor.argSlots(call.strProp("desc"), calleeStatic);
            int slot = 0;
            for (int i = 0; i < argSlots.size(); i++) {
                if (i == ordinal) {
                    for (ValueOrigin origin : support.argOriginAt(call, method, slot)) {
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
        if (f.isStatic()) {
            return null;
        }
        List<ChainHop> path = fieldTainted.get(f.owner() + "#" + f.field());
        if (path != null) {
            return path;
        }
        return thisTainted.get(f.owner());
    }

    /** 精扫：污点命中接口调用且仅声明目标（实现>枚举上限未物化）时，按上限展开实现类。 */
    private void expandInterfaces(Node call, MethodInfo method, int depth, boolean hasTaint,
                                  Explore ex) {
        if (call.out().size() > 1) {
            return; // 实现已物化
        }
        String owner = call.strProp("owner");
        ClassInfo ownerInfo = bb.hierarchy().classInfo(owner);
        if (ownerInfo == null) {
            return;
        }
        List<ChainHop> receiverPath = null;
        ForwardOrigins.State state = support.origins().compute(method).stateBefore().get(call.prop("offset"));
        String kind = call.strProp("invokeKind");
        if (state != null && !"STATIC".equals(kind)) {
            int receiverDepth = state.stack().size() - 1 - Descriptor.paramCount(call.strProp("desc"));
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
        if (receiverPath == null && !hasTaint) {
            return;
        }
        // 候选实现：接口用 implementers，类用子类型（Serializable 过滤限噪声）；超上限放弃
        List<String> candidates = new ArrayList<>(bb.hierarchy().transitiveSubtypes(owner));
        if (candidates == null) {
            return;
        }
        // A1+#1 FLASH 混合分派增强：receiver 的运行时类型精确解析
        // NEW→精确类名 | FieldRead→字段声明类型（具体类时精确） | 其他→保持 CHA
        if (receiverPath != null && !candidates.isEmpty() && candidates.size() > 1) {
            ForwardOrigins.State rState = support.origins().compute(method)
                    .stateBefore().get(call.prop("offset"));
            if (rState != null && !ownerInfo.isInterface()) {
                int rDepth = rState.stack().size() - 1 - Descriptor.paramCount(call.strProp("desc"));
                if (rDepth >= 0 && rDepth < rState.stack().size()) {
                    for (ValueOrigin vo : rState.stack().get(rDepth).origins()) {
                        String preciseType = null;
                        if (vo instanceof ValueOrigin.Insn ins
                                && method.insnAt(ins.offset()).op() == io.just.sast.model.Op.NEW) {
                            // NEW → 精确类名
                            String d = method.insnAt(ins.offset()).typeRef().descriptor();
                            preciseType = d.startsWith("L") && d.endsWith(";")
                                    ? d.substring(1, d.length() - 1) : d;
                        } else if (vo instanceof ValueOrigin.FieldRead fr && !fr.isStatic()) {
                            // FieldRead → 字段声明类型（具体类时可用）
                            String declaring = bb.hierarchy().resolveField(fr.owner(), fr.field());
                            var ci = bb.hierarchy().classInfo(declaring != null ? declaring : fr.owner());
                            var field = ci != null ? ci.field(fr.field()) : null;
                            if (field != null && field.descriptor().startsWith("L")) {
                                String ft = field.descriptor().substring(1, field.descriptor().length() - 1);
                                var fci = bb.hierarchy().classInfo(ft);
                                if (fci != null && !fci.isInterface()
                                        && !java.lang.reflect.Modifier.isAbstract(fci.access())) {
                                    preciseType = ft; // 具体类 → 精确类型
                                }
                            }
                        }
                        if (preciseType != null && candidates.contains(preciseType)) {
                            candidates = List.of(preciseType);
                            break;
                        }
                    }
                }
            }
        }
        int expanded = 0;
        for (String impl : candidates) {
            if (expanded >= 300) {
                return;
            }
            if (!bb.hierarchy().isSerializable(impl)) {
                continue;
            }
            String resolved = bb.hierarchy().resolveMethod(impl, call.strProp("name"), call.strProp("desc"));
            // 可见性剪枝：与调用图同语义，不可覆写目标不展开
            if (resolved != null && bb.hierarchy().isOverridableDispatchTarget(
                    owner, impl, call.strProp("name"), call.strProp("desc"))) {
                addThis(resolved, List.of(new ChainHop(method.owner(), method.name(), resolved,
                        call.strProp("name"), HopKind.VIRTUAL_DISPATCH, null, "dispatch-expand",
                        call.strProp("desc"), null)));
                expanded++;
            }
        }
        // 代理分发：污点 receiver 上的接口调用，其 handler（Serializable InvocationHandler）串入
        if (ownerInfo.isInterface()) {
            List<String> handlers = bb.hierarchy().implementers("java/lang/reflect/InvocationHandler", 500);
            if (handlers != null) {
                int handlerCount = 0;
                for (String handler : handlers) {
                    if (handlerCount >= 50 || !bb.hierarchy().isSerializable(handler)) {
                        handlerCount++;
                        continue;
                    }
                    handlerCount++;
                    String resolved = bb.hierarchy().resolveMethod(handler, "invoke",
                            "(Ljava/lang/Object;Ljava/lang/reflect/Method;[Ljava/lang/Object;)Ljava/lang/Object;");
                    if (resolved != null) {
                        addThis(resolved, List.of(new ChainHop(method.owner(), method.name(), resolved,
                                "invoke", HopKind.DIRECT_CALL, null, "proxy-handler",
                                "(Ljava/lang/Object;Ljava/lang/reflect/Method;[Ljava/lang/Object;)Ljava/lang/Object;", null)));
                    }
                }
            }
        }
    }

    /** 精扫：实参污点命中仅声明目标的调用时，向候选实现展开 addParam。 */
    private void expandParams(Node call, MethodInfo method, int slot, List<ChainHop> argPath) {
        if (call.out().size() > 1) {
            return;
        }
        String owner = call.strProp("owner");
        ClassInfo ownerInfo = bb.hierarchy().classInfo(owner);
        if (ownerInfo == null) {
            return;
        }
        List<String> candidates = new ArrayList<>(bb.hierarchy().transitiveSubtypes(owner));
        if (candidates == null) {
            return;
        }
        // A1 FLASH 混合分派轻量版：receiver origin 为 NEW 指令时类型精确——只展开该类
        if (false && !candidates.isEmpty()) { // A1: expandParams 暂不支持 origin-guided
            ForwardOrigins.State rState = support.origins().compute(method)
                    .stateBefore().get(call.prop("offset"));
            if (rState != null && !ownerInfo.isInterface()) {
                int rDepth = rState.stack().size() - 1 - Descriptor.paramCount(call.strProp("desc"));
                if (rDepth >= 0 && rDepth < rState.stack().size()) {
                    for (ValueOrigin vo : rState.stack().get(rDepth).origins()) {
                        if (vo instanceof ValueOrigin.Insn ins && method.insnAt(ins.offset()).op() == io.just.sast.model.Op.NEW) {
                            String newType = method.insnAt(ins.offset()).typeRef().descriptor()
                                    .replaceAll("^L|;$", "");
                            if (newType != null && candidates.contains(newType)) {
                                candidates = List.of(newType);
                                break;
                            }
                        }
                    }
                }
            }
        }
        int expanded = 0;
        for (String impl : candidates) {
            if (expanded >= 300) {
                return;
            }
            if (!bb.hierarchy().isSerializable(impl)) {
                continue;
            }
            String resolved = bb.hierarchy().resolveMethod(impl, call.strProp("name"), call.strProp("desc"));
            // 可见性剪枝：与调用图同语义，不可覆写目标不展开
            if (resolved != null && bb.hierarchy().isOverridableDispatchTarget(
                    owner, impl, call.strProp("name"), call.strProp("desc"))) {
                addParam(resolved, call.strProp("name"), call.strProp("desc"), slot,
                        hopTo(argPath, method, resolved, call.strProp("name"),
                                call.strProp("desc"), EdgeType.DISPATCHES));
                expanded++;
            }
        }
    }

    /** 精扫：receiver 为 Proxy.newProxyInstance 结果时，handler 实参的解析目标类 this 污点。 */
    private void threadProxy(Node call, MethodInfo method, int depth, Explore ex) {
        ForwardOrigins.State state = support.origins().compute(method).stateBefore().get(call.prop("offset"));
        if (state == null) {
            return;
        }
        int receiverDepth = state.stack().size() - 1 - Descriptor.paramCount(call.strProp("desc"));
        if (receiverDepth < 0 || receiverDepth >= state.stack().size()) {
            return;
        }
        for (ValueOrigin receiver : state.stack().get(receiverDepth).origins()) {
            if (!(receiver instanceof ValueOrigin.CallResult cr)) {
                continue;
            }
            Node originCall = bb.graph().node(cr.callNodeId());
            if (!"java/lang/reflect/Proxy".equals(originCall.strProp("owner"))
                    || !"newProxyInstance".equals(originCall.strProp("name"))) {
                continue;
            }
            // handler = newProxyInstance 的第 2 个实参
            MethodInfo originMethod = support.enclosingMethod(originCall);
            if (originMethod == null) {
                continue;
            }
            for (ValueOrigin handlerOrigin : support.argOriginAt(originCall, originMethod, 2)) {
                if (tainted(handlerOrigin, originMethod, depth + 1, ex) == null) {
                    continue;
                }
                if (handlerOrigin instanceof ValueOrigin.CallResult hc) {
                    Node handlerCall = bb.graph().node(hc.callNodeId());
                    for (Edge edge : handlerCall.out()) {
                        if (edge.type() == EdgeType.INVOKES || edge.type() == EdgeType.DISPATCHES) {
                            addThis(edge.to().strProp("owner"), List.of(new ChainHop(
                                    originMethod.owner(), originMethod.name(),
                                    edge.to().strProp("owner"), "invoke", HopKind.DIRECT_CALL, null,
                                    "proxy-handler", edge.to().strProp("desc"), null)));
                        }
                    }
                }
            }
        }
    }

    /** 精扫：Method.invoke 的 Method 对象来自 getMethod 且方法名为常量时，同名方法污点。 */
    private void reflectiveResolve(Node call, MethodInfo method, int depth) {
        if (!"java/lang/reflect/Method".equals(call.strProp("owner"))
                || !"invoke".equals(call.strProp("name"))) {
            return;
        }
        ForwardOrigins.State state = support.origins().compute(method).stateBefore().get(call.prop("offset"));
        if (state == null) {
            return;
        }
        int receiverDepth = state.stack().size() - 1 - Descriptor.paramCount(call.strProp("desc"));
        if (receiverDepth < 0 || receiverDepth >= state.stack().size()) {
            return;
        }
        for (ValueOrigin receiver : state.stack().get(receiverDepth).origins()) {
            if (!(receiver instanceof ValueOrigin.CallResult cr)) {
                continue;
            }
            Node getMethod = bb.graph().node(cr.callNodeId());
            String gmName = getMethod.strProp("name");
            if (!"getMethod".equals(gmName) && !"getDeclaredMethod".equals(gmName)) {
                continue;
            }
            MethodInfo gmMethod = support.enclosingMethod(getMethod);
            if (gmMethod == null) {
                continue;
            }
            String targetName = null;
            String targetClass = null;
            for (ValueOrigin nameOrigin : support.argOriginAt(getMethod, gmMethod, 1)) {
                if (nameOrigin instanceof ValueOrigin.Constant c && c.value() instanceof String s) {
                    targetName = s;
                }
            }
            for (ValueOrigin clsOrigin : support.argOriginAt(getMethod, gmMethod, 0)) {
                if (clsOrigin instanceof ValueOrigin.Constant c && c.value() instanceof String s) {
                    targetClass = s;
                } else if (clsOrigin instanceof ValueOrigin.CallResult cc) {
                    Node clsCall = bb.graph().node(cc.callNodeId());
                    if ("forName".equals(clsCall.strProp("name"))) {
                        MethodInfo fm = support.enclosingMethod(clsCall);
                        if (fm != null) {
                            for (ValueOrigin n : support.argOriginAt(clsCall, fm, 0)) {
                                if (n instanceof ValueOrigin.Constant c2 && c2.value() instanceof String s2) {
                                    targetClass = s2.replace('.', '/');
                                }
                            }
                        }
                    }
                }
            }
            if (targetName == null || targetClass == null) {
                continue;
            }
            ClassInfo cls = bb.hierarchy().classInfo(targetClass);
            if (cls == null) {
                continue;
            }
            int resolved = 0;
            for (MethodInfo m : cls.methods()) {
                if (m.name().equals(targetName) && resolved < 10) {
                    addThis(targetClass, List.of(new ChainHop(method.owner(), method.name(), targetClass,
                            targetName, HopKind.DIRECT_CALL, null, "reflective", m.descriptor(), null)));
                    resolved++;
                }
            }
        }
    }

    private List<ChainHop> taintedInsn(int offset, MethodInfo method, int depth, Explore ex) {
        ForwardOrigins.Result result = support.origins().compute(method);
        ForwardOrigins.State state = result.stateBefore().get(offset);
        if (state == null) {
            return null;
        }
        Op op = method.insnAt(offset).op();
        if (op == Op.NEWARRAY || op == Op.ANEWARRAY || op == Op.MULTIANEWARRAY) {
            for (ValueOrigin element : result.arrayElements().getOrDefault(new ValueOrigin.Insn(offset), Set.of())) {
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
            MethodInfo method = resolveMethodKey(key);
            if (method == null) {
                continue;
            }
            List<String> out = new ArrayList<>(2);
            for (InsnFact insn : method.instructions()) {
                if (!insn.op().isInvoke()) {
                    continue;
                }
                Long callId = support.callId(key, insn.offset());
                if (callId == null) {
                    continue;
                }
                for (Edge edge : bb.graph().node(callId).out()) {
                    if (edge.type() == EdgeType.INVOKES || edge.type() == EdgeType.DISPATCHES
                            || edge.type() == EdgeType.LAMBDA) {
                        String callee = methodNodeKey(edge.to());
                        if (reachable.contains(callee)) {
                            out.add(callee);
                        }
                    }
                }
            }
            succ.put(key, out);
        }
        Map<String, Integer> order = new HashMap<>(succ.size() * 2);
        Set<String> done = new HashSet<>();
        Set<String> onPath = new HashSet<>();
        Deque<Object[]> stack = new ArrayDeque<>(); // [方法键, 出边迭代位置]
        for (String start : succ.keySet()) {
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
        if (path.size() > MAX_HOPS || !better(thisTainted.get(className), path)) {
            return;
        }
        thisTainted.put(className, path);
        factVersion.incrementAndGet();
        factCount.increment();
        ClassInfo cls = bb.hierarchy().classInfo(className);
        if (cls != null) {
            for (MethodInfo method : cls.methods()) {
                if (!options.reachablePrune() || reachable.contains(OriginSupport.methodKey(method))) {
                    enqueue(OriginSupport.methodKey(method));
                }
            }
        }
        // 类级对象污点向加载子类型传递（运行时对象必是某子类型），有界防爆
        int subTainted = 0;
        for (String sub : new ArrayList<>(bb.hierarchy().loadedSubtypes(className))) {
            if (subTainted >= 100 || !better(thisTainted.get(sub), path)) {
                if (++subTainted >= 100) {
                    return;
                }
                continue;
            }
            thisTainted.put(sub, path);
            factVersion.incrementAndGet();
            factCount.increment();
            ClassInfo subInfo = bb.hierarchy().classInfo(sub);
            if (subInfo != null) {
                for (MethodInfo method : subInfo.methods()) {
                    if (!options.reachablePrune() || reachable.contains(OriginSupport.methodKey(method))) {
                        enqueue(OriginSupport.methodKey(method));
                    }
                }
            }
            if (++subTainted >= 100) {
                return;
            }
        }
    }

    private void addField(String owner, String field, List<ChainHop> path) {
        String key = owner + "#" + field;
        if (path.size() > MAX_HOPS || !better(fieldTainted.get(key), path)) {
            return;
        }
        fieldTainted.put(key, path);
        factVersion.incrementAndGet();
        factCount.increment();
        Set<String> readers = fieldReaders.get(key);
        if (readers != null) {
            queue.addAll(readers);
        }
    }

    private void addReturn(String methodKey, List<ChainHop> path) {
        if (path.size() > MAX_HOPS || !better(returnTainted.get(methodKey), path)) {
            return;
        }
        returnTainted.put(methodKey, path);
        factVersion.incrementAndGet();
        factCount.increment();
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
        if (path.size() > MAX_HOPS || !better(paramTainted.get(key), path)) {
            return;
        }
        paramTainted.put(key, path);
        factVersion.incrementAndGet();
        factCount.increment();
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
        return canonical(candidate).compareTo(canonical(existing)) < 0;
    }

    private static String canonical(List<ChainHop> path) {
        StringBuilder sb = new StringBuilder(path.size() * 32);
        for (ChainHop hop : path) {
            sb.append(hop);
        }
        return sb.toString();
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

    private static String methodNodeKey(Node method) {
        return OriginSupport.methodKeyOf(method.strProp("owner"), method.strProp("name"), method.strProp("desc"));
    }
}
