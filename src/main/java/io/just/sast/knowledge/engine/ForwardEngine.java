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
    private static final int STEP_BUDGET = 5_000_000;
    /** 方法效果处理上限。 */
    private static final int METHOD_PASS_CAP = 1_000_000;
    /** 死胡同缓存清理阈值（条目数超过即清除过期版本）。 */
    private static final int DEAD_END_SWEEP = 65_536;
    /** B1: 精扫并行 worker 数（与反向引擎一致）。 */
    private static final int WORKERS = Math.max(1, Math.min(16, Runtime.getRuntime().availableProcessors()));

    /** 事实：键 → 前向路径（首元素为 ENTRY hop）。 */
    private final Map<String, List<ChainHop>> thisTainted = new HashMap<>();
    private final Map<String, List<ChainHop>> fieldTainted = new HashMap<>();
    private final Map<String, List<ChainHop>> returnTainted = new HashMap<>();
    private final Map<String, List<ChainHop>> paramTainted = new HashMap<>();
    /** 死胡同缓存：键 = 方法键|origin，值 = 记录时的事实版本（factVersion 单调递增，跨轮有效）。 */
    private final Map<String, Long> deadEnds = new HashMap<>();
    private final Set<String> visiting = new HashSet<>();

    /** 字段读者索引：fieldKey → 方法集合（新字段事实时入队）。 */
    private final Map<String, Set<String>> fieldReaders = new HashMap<>();
    /** 调用者索引：方法键 → 调用点（return 事实传播用，含接口反向分发）。 */
    private final Map<String, List<Node>> callers = new HashMap<>();

    /** 反序列化可达方法集（前向 BFS 边界：只在该子集内传播；两轮共用，首轮构建）。 */
    private final Set<String> reachable = new HashSet<>();
    private static final int REACHABLE_CAP = 200_000;
    private static final int INTERFACE_EXPAND_CAP = 2000;
    private final Blackboard bb;
    private final OriginSupport support;
    private Options options;
    /** 事实版本：单调递增，永不重置（死胡同缓存跨轮失效判定；事实集合跨轮单调只增）。 */
    private long factVersion;
    /** 本轮统计/预算（每轮重置）。 */
    private int factCount;
    private int steps;
    private int methodPasses;
    private final Deque<String> queue = new ArrayDeque<>();

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
        boolean firstRun = factVersion == 0;
        // 预算按轮重置（每轮独立预算）。非首轮只重入队"受影响方法"：
        // 已污点类的方法 + 已有参数/返回事实的方法 + 已污点字段的读者——
        // 与独立精扫引擎的种子+事实驱动增长等价，规模受控（全量可达集重处理会烧尽预算）；
        // 新事实派生的受影响方法由 addThis/addField/addReturn/addParam 的入队机制自动扩散。
        steps = 0;
        methodPasses = 0;
        factCount = 0;
        if (!firstRun) {
            requeueAffected();
        }
        seedEntries();
        int rounds = 0;
        // B1: 精扫并行化——processEffects 按 batch 并行（refined pass 专用，coarse 保持串行）
        boolean parallel = options.expandInterfaces() && WORKERS > 1;
        while (!queue.isEmpty() && rounds < MAX_ROUNDS && steps < STEP_BUDGET
                && methodPasses < METHOD_PASS_CAP) {
            rounds++;
            List<String> current = new ArrayList<>(queue);
            queue.clear();
            if (!parallel) {
                for (String key : current) {
                    MethodInfo method = resolveMethodKey(key);
                    if (method != null) {
                        methodPasses++;
                        processEffects(method);
                    }
                }
            } else {
                // 并行处理当前 batch（不可变方法效果列表——add* 事实写入内部 CHM 并发安全）
                current.parallelStream().forEach(key -> {
                    MethodInfo method = resolveMethodKey(key);
                    if (method != null) {
                        methodPasses++;
                        processEffects(method);
                    }
                });
            }
        }
        if (!queue.isEmpty()) {
            // 截断未收敛：剩余事实未处理，本轮结果可能欠完备（不静默）
            io.just.sast.util.JustLogger.warn("前向污点[{}]：轮数/预算截断，剩余队列 {} 个方法（结果可能欠完备）",
                    options.expandInterfaces() ? "精扫" : "粗扫", queue.size());
            queue.clear();
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

    /** 精扫重入队（受影响方法）：已污点类的全部方法 + 参数/返回事实方法 + 已污点字段的读者。 */
    private void requeueAffected() {
        for (String cls : thisTainted.keySet()) {
            ClassInfo info = bb.hierarchy().classInfo(cls);
            if (info == null) {
                continue;
            }
            for (MethodInfo method : info.methods()) {
                if (!options.reachablePrune() || reachable.contains(OriginSupport.methodKey(method))) {
                    queue.add(OriginSupport.methodKey(method));
                }
            }
        }
        for (String key : paramTainted.keySet()) {
            queue.add(key.substring(0, key.lastIndexOf('#')));
        }
        queue.addAll(returnTainted.keySet());
        for (Map.Entry<String, List<ChainHop>> e : fieldTainted.entrySet()) {
            Set<String> readers = fieldReaders.get(e.getKey());
            if (readers != null) {
                queue.addAll(readers);
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
                    if ((edge.type() == EdgeType.INVOKES || edge.type() == EdgeType.DISPATCHES)
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

    /** 方法效果：PUTFIELD 存污点值 → 字段事实；RETURN 污点值 → 返回事实。 */
    private void processEffects(MethodInfo method) {
        for (InsnFact insn : method.instructions()) {
            Op op = insn.op();
            if (op.isFieldWrite() && op != Op.PUTSTATIC) {
                ForwardOrigins.State state = support.origins().compute(method).stateBefore().get(insn.offset());
                if (state == null || state.stack().isEmpty()) {
                    continue;
                }
                for (ValueOrigin value : state.stack().get(state.stack().size() - 1).origins()) {
                    List<ChainHop> path = tainted(value, method, 0);
                    if (path != null) {
                        addField(insn.fieldRef().owner(), insn.fieldRef().name(), path);
                    }
                }
            } else if (op.isReturn() && op != Op.RETURN && op != Op.ATHROW) {
                ForwardOrigins.State state = support.origins().compute(method).stateBefore().get(insn.offset());
                if (state == null || state.stack().isEmpty()) {
                    continue;
                }
                for (ValueOrigin value : state.stack().get(state.stack().size() - 1).origins()) {
                    List<ChainHop> path = tainted(value, method, 0);
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
                List<ChainHop> path = tainted(origin, method, 0);
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

    /** 值污点判定：返回前向路径（含 ENTRY hop 在首），无污点返回 null。 */
    private List<ChainHop> tainted(ValueOrigin origin, MethodInfo method, int depth) {
        if (depth > MAX_DEPTH || steps > STEP_BUDGET) {
            return null;
        }
        steps++;
        String key = OriginSupport.methodKey(method) + "|" + origin;
        Long deadAt = deadEnds.get(key);
        if ((deadAt != null && deadAt == factVersion) || visiting.contains(key)) {
            return null; // 版本未推进时的死胡同有效；新事实到达（版本推进）后重查
        }
        visiting.add(key);
        List<ChainHop> path;
        if (origin instanceof ValueOrigin.Param p) {
            path = taintedParam(p.slot(), method);
        } else if (origin instanceof ValueOrigin.FieldRead f) {
            path = taintedFieldRead(f);
        } else if (origin instanceof ValueOrigin.CallResult c) {
            path = taintedCallResult(c.callNodeId(), method, depth);
        } else if (origin instanceof ValueOrigin.Insn i) {
            path = taintedInsn(i.offset(), method, depth);
        } else {
            path = null; // 常量不可控
        }
        visiting.remove(key);
        if (path == null) {
            deadEnds.put(key, factVersion);
            if (deadEnds.size() > DEAD_END_SWEEP) {
                deadEnds.values().removeIf(v -> v < factVersion);
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

    private List<ChainHop> taintedCallResult(long callNodeId, MethodInfo method, int depth) {
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
        List<ChainHop> best = null;
        String kind = call.strProp("invokeKind");
        boolean calleeStatic = "STATIC".equals(kind);
        if (!calleeStatic) {
            int receiverDepth = state.stack().size() - 1 - Descriptor.paramCount(call.strProp("desc"));
            if (receiverDepth >= 0 && receiverDepth < state.stack().size()) {
                for (ValueOrigin receiver : state.stack().get(receiverDepth).origins()) {
                    List<ChainHop> receiverPath = tainted(receiver, method, depth + 1);
                    if (receiverPath != null) {
                        for (Edge edge : call.out()) {
                            if (edge.type() == EdgeType.INVOKES || edge.type() == EdgeType.DISPATCHES) {
                                addThis(edge.to().strProp("owner"), hopTo(receiverPath, method,
                                        edge.to().strProp("owner"), edge.to().strProp("name"),
                                        edge.to().strProp("desc"), edge.type()));
                            }
                        }
                        best = receiverPath;
                    }
                }
            }
        }
        // 实参污点传播（按被调方法实参槽遍历，wide 参数占 2 槽）
        List<Integer> argSlots = Descriptor.argSlots(call.strProp("desc"), calleeStatic);
        int slot = 0;
        for (int i = 0; i < argSlots.size(); i++) {
            for (ValueOrigin argOrigin : support.argOriginAt(call, method, slot)) {
                List<ChainHop> argPath = tainted(argOrigin, method, depth + 1);
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
                if (options.expandInterfaces()) {
                    expandParams(call, method, slot, argPath);
                }
            }
            slot += argSlots.get(i);
        }
        // model 规则（声明式摘要）：return←src 透传、this←argN 容器投毒
        var model = bb.ruleEngine().matchingModel(call.strProp("owner"), call.strProp("name"),
                call.strProp("desc"));
        if (model.isPresent()) {
            best = applyModel(model.get(), call, method, depth, best);
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
            expandInterfaces(call, method, depth, best != null);
        }
        if (options.threadProxy() && best != null && !calleeStatic) {
            threadProxy(call, method, depth);
        }
        if (options.reflectiveResolve()) {
            reflectiveResolve(call, method, depth);
        }
        return best;
    }

    /** model 规则消费：actions 里 return←src 为透传，this←argN 为容器投毒（类级语义）。 */
    private List<ChainHop> applyModel(Rule.ModelRule model, Node call, MethodInfo method, int depth,
                                      List<ChainHop> best) {
        for (Map.Entry<String, List<String>> action : model.actions().entrySet()) {
            for (String src : action.getValue()) {
                List<ChainHop> srcPath = modelSourcePath(src, call, method, depth);
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
    private List<ChainHop> modelSourcePath(String src, Node call, MethodInfo method, int depth) {
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
                List<ChainHop> path = tainted(receiver, method, depth + 1);
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
                        List<ChainHop> path = tainted(origin, method, depth + 1);
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
    private void expandInterfaces(Node call, MethodInfo method, int depth, boolean hasTaint) {
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
                    List<ChainHop> path = tainted(receiver, method, depth + 1);
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
        List<String> candidates = ownerInfo.isInterface()
                ? bb.hierarchy().implementers(owner, 10_000)
                : new ArrayList<>(bb.hierarchy().loadedSubtypes(owner));
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
        List<String> candidates = ownerInfo.isInterface()
                ? bb.hierarchy().implementers(owner, 10_000)
                : new ArrayList<>(bb.hierarchy().loadedSubtypes(owner));
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
    private void threadProxy(Node call, MethodInfo method, int depth) {
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
                if (tainted(handlerOrigin, originMethod, depth + 1) == null) {
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

    private List<ChainHop> taintedInsn(int offset, MethodInfo method, int depth) {
        ForwardOrigins.Result result = support.origins().compute(method);
        ForwardOrigins.State state = result.stateBefore().get(offset);
        if (state == null) {
            return null;
        }
        Op op = method.insnAt(offset).op();
        if (op == Op.NEWARRAY || op == Op.ANEWARRAY || op == Op.MULTIANEWARRAY) {
            for (ValueOrigin element : result.arrayElements().getOrDefault(new ValueOrigin.Insn(offset), Set.of())) {
                List<ChainHop> path = tainted(element, method, depth + 1);
                if (path != null) {
                    return path;
                }
            }
        }
        int consumed = OriginSupport.consumedCount(op);
        int start = Math.max(0, state.stack().size() - consumed);
        for (int i = start; i < state.stack().size(); i++) {
            for (ValueOrigin operand : state.stack().get(i).origins()) {
                List<ChainHop> path = tainted(operand, method, depth + 1);
                if (path != null) {
                    return path;
                }
            }
        }
        return null;
    }

    // ---- 事实写入（键去重，路径更短才替换；受影响方法入队） ----

    private void addThis(String className, List<ChainHop> path) {
        if (path.size() > MAX_HOPS || !shorter(thisTainted.get(className), path)) {
            return;
        }
        thisTainted.put(className, path);
        factVersion++;
        factCount++;
        ClassInfo cls = bb.hierarchy().classInfo(className);
        if (cls != null) {
            for (MethodInfo method : cls.methods()) {
                if (!options.reachablePrune() || reachable.contains(OriginSupport.methodKey(method))) {
                    queue.add(OriginSupport.methodKey(method));
                }
            }
        }
        // 类级对象污点向加载子类型传递（运行时对象必是某子类型），有界防爆
        int subTainted = 0;
        for (String sub : new ArrayList<>(bb.hierarchy().loadedSubtypes(className))) {
            if (subTainted >= 100 || !shorter(thisTainted.get(sub), path)) {
                if (++subTainted >= 100) {
                    return;
                }
                continue;
            }
            thisTainted.put(sub, path);
            factVersion++;
            factCount++;
            ClassInfo subInfo = bb.hierarchy().classInfo(sub);
            if (subInfo != null) {
                for (MethodInfo method : subInfo.methods()) {
                    if (!options.reachablePrune() || reachable.contains(OriginSupport.methodKey(method))) {
                        queue.add(OriginSupport.methodKey(method));
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
        if (path.size() > MAX_HOPS || !shorter(fieldTainted.get(key), path)) {
            return;
        }
        fieldTainted.put(key, path);
        factVersion++;
        factCount++;
        Set<String> readers = fieldReaders.get(key);
        if (readers != null) {
            queue.addAll(readers);
        }
    }

    private void addReturn(String methodKey, List<ChainHop> path) {
        if (path.size() > MAX_HOPS || !shorter(returnTainted.get(methodKey), path)) {
            return;
        }
        returnTainted.put(methodKey, path);
        factVersion++;
        factCount++;
        List<Node> callerCalls = callers.get(methodKey);
        if (callerCalls != null) {
            for (Node caller : callerCalls) {
                if (!options.reachablePrune() || reachable.contains(OriginSupport.methodKey(caller))) {
                    queue.add(OriginSupport.methodKey(caller));
                }
            }
        }
    }

    private void addParam(String owner, String name, String desc, int slot, List<ChainHop> path) {
        String methodKey = OriginSupport.methodKeyOf(owner, name, desc);
        String key = methodKey + "#" + slot;
        if (path.size() > MAX_HOPS || !shorter(paramTainted.get(key), path)) {
            return;
        }
        paramTainted.put(key, path);
        factVersion++;
        factCount++;
        queue.add(methodKey);
    }

    private static boolean shorter(List<ChainHop> existing, List<ChainHop> candidate) {
        return existing == null || candidate.size() < existing.size();
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

    private static String methodNodeKey(Node method) {
        return OriginSupport.methodKeyOf(method.strProp("owner"), method.strProp("name"), method.strProp("desc"));
    }
}
