package io.just.sast.knowledge.backward;

import io.just.sast.analysis.taint.ForwardOrigins;
import io.just.sast.analysis.taint.OriginSupport;
import io.just.sast.analysis.taint.ValueOrigin;
import io.just.sast.blackboard.Blackboard;
import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.Event;
import io.just.sast.blackboard.EventType;
import io.just.sast.blackboard.HopKind;
import io.just.sast.blackboard.KnowledgeSource;
import io.just.sast.blackboard.SinkOutcome;
import io.just.sast.config.Rule;
import io.just.sast.cpg.build.FieldWriterIndex;
import io.just.sast.cpg.graph.Edge;
import io.just.sast.cpg.graph.EdgeType;
import io.just.sast.cpg.graph.Node;
import io.just.sast.cpg.graph.NodeType;
import io.just.sast.model.ClassInfo;
import io.just.sast.model.Descriptor;
import io.just.sast.model.MethodInfo;
import io.just.sast.model.Op;
import io.just.sast.util.JustLogger;

import java.lang.reflect.Modifier;
import java.nio.file.Files;
import java.nio.file.Path;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * 反向污点引擎（独立知识源，ANALYSIS 阶段）。
 * 自行按规则枚举 sink 候选，反向回答"该值是否攻击者可控"，产物（链 + 裁决）写黑板。
 * 上下文不敏感（所有调用点合并），靠预算、去环与校准层控制噪声。
 *
 * 可控语义（controlled）：
 * 1. ObjectInputStream.readObject/readUnshared/readFields 调用结果无条件可控（反序列化威胁模型）
 * 2. magic entry 的 this / proxy-invoke 的 args 可控
 * 3. 可控对象的字段可控（Serializable 且非 transient；GadgetInspector 传递对象语义）
 * 4. 存入可控值的字段可控（程序字段污点，写者回溯）
 * 5. 可控数组的元素可控；数组元素可控则数组可控
 * 6. 可控 receiver 的方法返回值可控；任一实参可控的返回值可控（passthrough）
 */
public final class BackwardTaintAnalysis implements KnowledgeSource {

    /** sink 标记（内部传递的规则事实）。 */
    private record SinkMark(String ruleId, String category, String severity, List<Rule.TaintedPos> tainted) {}

    private static final int MAX_CHAINS_PER_SINK = 20;
    /** 每 sink 步数预算：须覆盖分发图扇出（层次修复后图正确变宽），全局预算另行兜底。 */
    private static final int STEP_BUDGET = 200_000;
    /** 全局步数兜底（终止保证）：须随分发图规模放宽，图表越大首达探索越多。per-sink 并行下按核数摊薄墙钟。 */
    private static final int GLOBAL_BUDGET = 60_000_000;
    /** 并行 worker 数：sink 分析相互独立，按核数自适应并行（上限 16）。 */
    private static final int WORKERS = Math.max(1, Math.min(16, Runtime.getRuntime().availableProcessors()));
    private static final int MAX_WRITERS_PER_FIELD = 10;
    /** 链跳数上限：V7 语义改为"动态分派跳数"（VIRTUAL_DISPATCH+FIELD_FLOW），静态直连不计——
     * JDD 复杂度论证：top-down 爆炸因子是动态分派候选数，静态调用链长不构成组合爆炸。 */
    private static final int MAX_HOPS = 40;
    /** 单方法调用者枚举上限：OIS.readObject 等枢纽方法调用者极多，上限过低会按边序误截深链。 */
    private static final int MAX_CALLERS = 10_000;
    /** 祖先反向分发（入边为空时的启发式补全）调用点枚举上限：控制探索成本。 */
    private static final int MAX_MERGED_CALLERS = 300;

    /** V11：按闭包大小调整的每 sink 预算。 */
    private static volatile int STEP_BUDGET_ADJUSTED = 200_000;
    /** B5: per-thread 死胡同缓存（减少 CHM 争用），每 sink 开始时合并到全局 */
    private final ThreadLocal<Set<String>> localDeadEnds = ThreadLocal.withInitial(java.util.HashSet::new);
    private final Set<String> deadEnds = java.util.concurrent.ConcurrentHashMap.newKeySet();
    /** V9-lite 段级记忆化（JDD IOCD 精神）：方法键 → 最近成功入口（类，kind，跳数）——
     * 跨 sink 复用"从此方法可达某入口"的结论，避免重复回溯。 */
    private final java.util.concurrent.ConcurrentHashMap<String, String[]> segmentCache =
            new java.util.concurrent.ConcurrentHashMap<>();
    private final Map<String, Optional<Rule.MagicEntryRule>> entryRuleCache =
            new java.util.concurrent.ConcurrentHashMap<>();
    /** 双向剪枝：入口下游闭包（与链剪枝共享同一份，黑板分发）。 */
    private Set<String> entryReaching = Set.of();
    private Blackboard bb;
    private OriginSupport support;
    /** 全局步数（per-sink 并行下原子累加；预算本是有界近似，竞态误差可接受）。 */
    private final java.util.concurrent.atomic.AtomicLong globalSteps = new java.util.concurrent.atomic.AtomicLong();

    @Override
    public String id() {
        return "backward-taint";
    }

    @Override
    public Set<EventType> interests() {
        return Set.of(EventType.SCAN_START);
    }

    @Override
    public int priority() {
        return 100;
    }

    @Override
    public void init(Blackboard blackboard) {
        this.bb = blackboard;
        this.support = blackboard.originSupport();
        this.entryReaching = support.entryDownstream(blackboard.graph());
        // V11 大语料自适应：闭包越大→每 sink 预算越小（总预算不变但分配更均匀），大语料不超线性
        if (entryReaching.size() > 100_000) {
            STEP_BUDGET_ADJUSTED = 50_000;
        } else if (entryReaching.size() > 50_000) {
            STEP_BUDGET_ADJUSTED = 100_000;
        } else {
            STEP_BUDGET_ADJUSTED = STEP_BUDGET;
        }
        JustLogger.info("入口下游闭包：{} 个方法（每 sink 预算 {}）", entryReaching.size(), STEP_BUDGET_ADJUSTED);
    }

    @Override
    public void onEvent(Blackboard bb, Event event) {
        if (event.type() != EventType.SCAN_START) {
            return;
        }
        long startTime = System.currentTimeMillis();
        // 独立枚举 sink 候选（规则自匹配），按入口距离升序——离反序列化入口近的 sink 先分析，
        // 全局预算优先花在可达成链密度最高的地方（JDD bottom-up 导向）
        record SinkTask(long callId, SinkMark mark) {}
        List<SinkTask> sinks = new ArrayList<>();
        for (Node call : bb.graph().nodesOfType(NodeType.CALL)) {
            bb.ruleEngine().matchingSink(call).ifPresent(rule -> sinks.add(new SinkTask(call.id(),
                    new SinkMark(rule.id(), rule.category(), rule.severity(), rule.tainted()))));
        }
        sinks.sort(java.util.Comparator.comparingInt(task -> {
            MethodInfo host = support.methodOf(bb.graph().node(task.callId()).strProp("methodOwner"),
                    bb.graph().node(task.callId()).strProp("methodName"),
                    bb.graph().node(task.callId()).strProp("methodDesc"));
            return host != null ? support.entryDepthOf(OriginSupport.methodKey(host)) : Integer.MAX_VALUE;
        }));
        // per-sink 并行：sink 分析相互独立（Trace 线程本地），共享结构已并发化
        java.util.concurrent.atomic.AtomicInteger cursor = new java.util.concurrent.atomic.AtomicInteger();
        Runnable worker = () -> {
            while (globalSteps.get() < GLOBAL_BUDGET) {
                int i = cursor.getAndIncrement();
                if (i >= sinks.size()) {
                    return;
                }
                SinkTask task = sinks.get(i);
                try {
                    analyzeSink(task.callId(), task.mark());
                } catch (Throwable e) {
                    JustLogger.error("反向污点 sink 分析失败（已隔离）: {}", e.toString());
                }
            }
        };
        if (WORKERS <= 1) {
            worker.run();
        } else {
            Thread[] threads = new Thread[WORKERS - 1];
            for (int i = 0; i < threads.length; i++) {
                threads[i] = new Thread(worker, "backward-taint-" + i);
                threads[i].start();
            }
            worker.run();
            for (Thread t : threads) {
                try {
                    t.join();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }
        JustLogger.info("反向污点[{} workers]：{} ms（全局步数 {}，段缓存 {} 条）",
                WORKERS, System.currentTimeMillis() - startTime, globalSteps.get(), segmentCache.size());
        // D2: 段缓存持久化——跨扫描复用（同一 jar 重扫时直接命中）
        if (!segmentCache.isEmpty()) {
            try {
                Path fragFile = Path.of("just-fragments.ser");
                if (Files.exists(fragFile)) {
                    try (ObjectInputStream oin = new ObjectInputStream(Files.newInputStream(fragFile))) {
                        @SuppressWarnings("unchecked")
                        var saved = (java.util.concurrent.ConcurrentHashMap<String, String[]>) oin.readObject();
                        saved.putAll(segmentCache);
                        segmentCache.putAll(saved);
                    }
                }
                try (ObjectOutputStream oout = new ObjectOutputStream(Files.newOutputStream(fragFile))) {
                    oout.writeObject(new java.util.HashMap<>(segmentCache));
                }
            } catch (Exception e) {
                JustLogger.debug("段缓存持久化失败: {}", e.getMessage());
            }
        }
    }

    private void analyzeSink(long callNodeId, SinkMark mark) {
        Node call = bb.graph().node(callNodeId);
        MethodInfo method = support.enclosingMethod(call);
        if (method == null) {
            bb.recordOutcome(callNodeId, outcome(call, mark, 0, 0, 0, 0, "UNRESOLVED"));
            return;
        }
        if (!entryReaching.contains(OriginSupport.methodKey(method))) {
            // sink 宿主方法不在入口下游集内：可证明无链
            bb.recordOutcome(callNodeId, outcome(call, mark, 0, 0, 0, 0, "NO_PATH"));
            return;
        }
        // catch 可达性守卫（U1/U4，可判定才剪）：sink 位于 CCE handler 且守卫区为"类型安全的 Class.cast"
        // ——cast 目标是实参静态声明类型的（严格）父类时 cast 必成功，handler 不可达
        if (support.catchProvablyUnreachable(method, (Integer) call.prop("offset"))) {
            bb.recordOutcome(callNodeId, outcome(call, mark, 0, 0, 0, 0, "NO_PATH"));
            return;
        }
        ForwardOrigins.Result result = support.origins().compute(method);
        ForwardOrigins.State state = result.stateBefore().get(call.prop("offset"));
        if (state == null) {
            bb.recordOutcome(callNodeId, outcome(call, mark, 0, 0, 0, 0, "NO_STATE"));
            return;
        }
        int paramCount = Descriptor.paramCount(call.strProp("desc"));
        int produced = 0;
        Trace trace = new Trace(call.strProp("owner"), call.strProp("name"));
        for (Rule.TaintedPos pos : mark.tainted()) {
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
                if (produced >= MAX_CHAINS_PER_SINK) {
                    break;
                }
                produced += controlled(origin, method, 0, trace, mark);
            }
        }
        String verdict;
        if (produced > 0) {
            verdict = "CHAIN";
        } else if (trace.steps > STEP_BUDGET) {
            verdict = "TRUNCATED";
        } else if (trace.tooLong > 0) {
            verdict = "TOO_LONG";
        } else if (trace.unresolved > 0) {
            verdict = "UNRESOLVED";
        } else {
            verdict = "NO_PATH";
        }
        deadEnds.addAll(localDeadEnds.get());
        localDeadEnds.get().clear();
        bb.recordOutcome(callNodeId, outcome(call, mark, produced, trace.steps, trace.unresolved, trace.tooLong, verdict));
    }

    /** 返回：该值可控所产出的链数。 */
    private int controlled(ValueOrigin origin, MethodInfo method, int depth, Trace trace, SinkMark mark) {
        long stepsSoFar = globalSteps.get();
        if (depth > bb.maxDepth() || trace.steps > STEP_BUDGET_ADJUSTED || stepsSoFar > GLOBAL_BUDGET) {
            return 0;
        }
        // 预算尾部截断的结果不可靠，不写入死胡同缓存（防假阴性污染）
        boolean nearBudget = stepsSoFar > GLOBAL_BUDGET * 4L / 5
                || trace.steps > STEP_BUDGET_ADJUSTED * 4 / 5;
        // 深度接近上限的结果受截断影响，不记忆化也不查询（深度无关键的不健全）
        boolean memoizable = depth <= bb.maxDepth() / 2;
        globalSteps.incrementAndGet();
        String memoKey = OriginSupport.methodKey(method) + "|" + origin;
        Set<String> localDead = localDeadEnds.get();
        if ((memoizable && (localDead.contains(memoKey) || deadEnds.contains(memoKey)))
                || trace.visited.contains(memoKey)) {
            return 0;
        }
        trace.visited.add(memoKey);
        int produced;
        if (origin instanceof ValueOrigin.Param p) {
            produced = controlledParam(p.slot(), method, depth, trace, mark);
        } else if (origin instanceof ValueOrigin.Insn insn) {
            produced = controlledInsn(insn.offset(), method, depth, trace, mark);
        } else if (origin instanceof ValueOrigin.CallResult callResult) {
            produced = controlledCallResult(callResult.callNodeId(), method, depth, trace, mark);
        } else if (origin instanceof ValueOrigin.FieldRead fieldRead) {
            produced = controlledFieldRead(fieldRead, method, depth, trace, mark);
        } else {
            produced = 0; // 常量不可控
        }
        trace.visited.remove(memoKey);
        if (produced == 0 && memoizable && !nearBudget) {
            localDead.add(memoKey);
        }
        return produced;
    }

    /** 参数：magic entry 的 this 可控、proxy 入口 args 可控；否则回溯调用者实参（上下文不敏感）。 */
    private int controlledParam(int slot, MethodInfo method, int depth, Trace trace, SinkMark mark) {
        trace.steps++;
        Rule.MagicEntryRule entry = entryRuleOf(method);
        if (entry != null) {
            if (slot == 0) {
                // 入口对象本身由反序列化构造，可控（对象图语义的根）
                return completeChain(mark, entry.entryKind(), method, trace, "this-object");
            }
            if (entry.entryKind().equals("proxyInvoke") && bb.hierarchy().isSerializable(method.owner())) {
                return completeChain(mark, entry.entryKind(), method, trace, "proxy-args");
            }
        }
        Node methodNode = bb.graph().findMethodNode(method.owner(), method.name(), method.descriptor());
        if (methodNode == null) {
            return 0;
        }
        // 调用点收集：自身入边；为空时并入祖先类型（传递接口/父类链）上同名方法的入边
        // （接口实现数超 CHA 上限时分发边未物化，具体实现类须经祖先方法节点反查调用点——同前向引擎语义）
        Set<Node> callSites = new java.util.LinkedHashSet<>();
        collectCallSites(methodNode, callSites);
        // 反射跳伪调用者（FLASH 向后版）：public 方法可被"常量类反射查找 + invoke"位点调用
        addReflectiveCallers(method, callSites);
        boolean merged = callSites.isEmpty();
        if (merged) {
            for (String ancestor : ancestorTypes(method.owner())) {
                Node ancestorNode = bb.graph().findMethodNode(ancestor, method.name(), method.descriptor());
                if (ancestorNode != null) {
                    collectCallSites(ancestorNode, callSites);
                }
            }
        }
        // V9-lite：段缓存命中——此方法已知可达某入口，直接完成链
        String[] cached = segmentCache.get(OriginSupport.methodKey(method));
        if (cached != null) {
            ChainHop shortcutHop = new ChainHop(method.owner(), method.name(),
                    cached[0], cached[1], HopKind.DIRECT_CALL, null,
                    "segment-reuse(" + cached[2] + ")", "", null);
            trace.hops.add(shortcutHop);
            int result = completeChain(mark, cached[1],
                    bb.hierarchy().classInfo(cached[0]) != null
                            ? support.methodOf(cached[0], cached[1],
                                    firstDescriptorOfEntry(cached[0], cached[1]))
                            : null, trace, "segment-reuse");
            trace.hops.remove(trace.hops.size() - 1);
            if (result > 0) {
                return result;
            }
        }
        int callerCap = merged ? MAX_MERGED_CALLERS : MAX_CALLERS;
        int produced = 0;
        int callers = 0;
        // 入口距离优先（JDD bottom-up / FLASH 入口导向的探索序）：离反序列化入口近的调用者先走，
        // 链在预算内更快闭合——预算截断下的可复现优先级，替代边序的随机性
        List<Node> orderedCallSites = new ArrayList<>(callSites);
        orderedCallSites.sort(java.util.Comparator.comparingInt(site -> {
            MethodInfo caller = support.enclosingMethod(site);
            return caller != null ? support.entryDepthOf(OriginSupport.methodKey(caller)) : Integer.MAX_VALUE;
        }));
        for (Node callerCall : orderedCallSites) {
            if (callers >= callerCap) {
                break;
            }
            MethodInfo callerMethod = support.enclosingMethod(callerCall);
            if (callerMethod == null) {
                trace.unresolved++;
                continue;
            }
            if (!entryReaching.contains(OriginSupport.methodKey(callerMethod))) {
                continue; // 调用者祖先链不可达入口：可证明无链，剪枝
            }
            callers++;
            Set<ValueOrigin> argOrigins = support.argOriginAt(callerCall, callerMethod, slot);
            if (argOrigins.isEmpty()) {
                continue;
            }
            // 类型流可断言类型同一性的前提是"纯参数直传"（调用方把自己的参数原样传入）；
            // 来源含派生（调用结果/指令产物/字段读——passthrough 会合法换类型，如 method.getDeclaringClass()）
            // 时 argOrdinal 置空，chain-validator 的类型流校验据此跳过该跳（历史回归：CC BeanMap 链被误拒）
            boolean directParam = argOrigins.stream().allMatch(o -> o instanceof ValueOrigin.Param);
            ChainHop hop = new ChainHop(callerMethod.owner(), callerMethod.name(),
                    method.owner(), method.name(), HopKind.VIRTUAL_DISPATCH, null, "call",
                    method.descriptor(), directParam
                            ? Descriptor.paramOrdinal(method.descriptor(), method.isStatic(), slot)
                            : null);
            int unresolvedBefore = trace.unresolved;
            trace.hops.add(hop);
            for (ValueOrigin argOrigin : argOrigins) {
                produced += controlled(argOrigin, callerMethod, depth + 1, trace, mark);
            }
            trace.hops.remove(trace.hops.size() - 1);
            trace.unresolved = unresolvedBefore;
        }
        return produced;
    }

    /** 反射跳伪调用者：方法为 public 且声明类存在常量类反射查找的 invoke 位点时并入。 */
    private void addReflectiveCallers(MethodInfo method, Set<Node> out) {
        int access = bb.hierarchy().methodAccess(method.owner(), method.name(), method.descriptor());
        if (access >= 0 && !java.lang.reflect.Modifier.isPublic(access)) {
            return; // public 即可（static 可被 Method.invoke 调用）
        }
        String declared = bb.hierarchy().resolveMethod(method.owner(), method.name(), method.descriptor());
        String cls = declared != null ? declared : method.owner();
        // 精确（类+名常量）与粗粒度（类常量、名不可解）两种位点都算
        Node precise = support.reflectiveInvokeSiteOf(cls, method.name());
        if (precise != null) {
            out.add(precise);
        }
        for (Node site : support.reflectiveInvokeSitesOf(cls)) {
            if (site.id() != (precise == null ? -1 : precise.id())) {
                out.add(site);
            }
        }
        // JavaBean 反射跳（FLASH 第三支柱）：getReadMethod/getWriteMethod 产出的 invoke 位点
        // 是 JavaBean 前缀方法的伪调用者（类可解精确匹配 + wildcard 位点对任意前缀方法）
        for (Node site : support.javaBeanInvokeSitesOf(cls, method.name())) {
            out.add(site);
        }
        // 框架反射供给（性能优化版）：仅 setter/getter/isXxx 接受框架伪调用者——
        // 且仅限闭包内的 invoke 位点（不可达的框架代码无意义）
        if (!Boolean.getBoolean("just.fast") && isJavaBeanMethod(method.name())) {
            for (Node site : support.frameworkMethodInvokeSites()) {
                String hostKey = OriginSupport.methodKeyOf(
                        site.strProp("methodOwner"), site.strProp("methodName"), site.strProp("methodDesc"));
                if (entryReaching.contains(hostKey)) {
                    out.add(site);
                }
            }
        }
    }

    private static boolean isJavaBeanMethod(String name) {
        if (name == null) return false;
        return (name.startsWith("set") && name.length() > 3)
                || (name.startsWith("get") && name.length() > 3)
                || (name.startsWith("is") && name.length() > 2);
    }

    private void collectCallSites(Node methodNode, Set<Node> out) {
        for (Edge edge : methodNode.in()) {
            if (edge.type() == EdgeType.INVOKES || edge.type() == EdgeType.DISPATCHES
                    || edge.type() == EdgeType.LAMBDA) {
                out.add(edge.from());
            }
        }
    }

    /** 祖先类型集合：传递接口 + 父类链（含自身之外的全部祖先，去自身）。 */
    private Set<String> ancestorTypes(String owner) {
        Set<String> result = new java.util.LinkedHashSet<>();
        Set<String> visited = new HashSet<>();
        Deque<String> queue = new ArrayDeque<>();
        ClassInfo ci = bb.hierarchy().classInfo(owner);
        if (ci != null) {
            if (ci.superName() != null) {
                queue.add(ci.superName());
            }
            queue.addAll(bb.hierarchy().transitiveInterfaces(owner));
        }
        while (!queue.isEmpty()) {
            String cur = queue.poll();
            if (!visited.add(cur) || cur.equals(owner)) {
                continue;
            }
            result.add(cur);
            ClassInfo c = bb.hierarchy().classInfo(cur);
            if (c == null) {
                continue;
            }
            if (c.superName() != null) {
                queue.add(c.superName());
            }
            queue.addAll(bb.hierarchy().transitiveInterfaces(cur));
        }
        return result;
    }

    /** 指令产物：数组分配←元素；数组读←数组；其余←消耗的操作数。 */
    private int controlledInsn(int offset, MethodInfo method, int depth, Trace trace, SinkMark mark) {
        trace.steps++;
        ForwardOrigins.Result result = support.origins().compute(method);
        ForwardOrigins.State state = result.stateBefore().get(offset);
        if (state == null) {
            return 0;
        }
        Op op = method.insnAt(offset).op();
        int produced = 0;
        if (op == Op.NEWARRAY || op == Op.ANEWARRAY || op == Op.MULTIANEWARRAY) {
            for (ValueOrigin element : result.arrayElements().getOrDefault(new ValueOrigin.Insn(offset), Set.of())) {
                produced += controlled(element, method, depth + 1, trace, mark);
            }
        }
        if (produced > 0) {
            return produced;
        }
        int consumed = OriginSupport.consumedCount(op);
        int start = Math.max(0, state.stack().size() - consumed);
        for (int i = start; i < state.stack().size(); i++) {
            for (ValueOrigin operand : state.stack().get(i).origins()) {
                produced += controlled(operand, method, depth + 1, trace, mark);
            }
        }
        return produced;
    }

    /** 调用返回值：OIS 读无条件可控；可控 receiver 的返回值可控；可控实参的返回值可控。 */
    private int controlledCallResult(long callNodeId, MethodInfo method, int depth, Trace trace, SinkMark mark) {
        trace.steps++;
        if (callNodeId < 0) {
            trace.unresolved++;
            return 0;
        }
        Node call = bb.graph().node(callNodeId);
        if (OriginSupport.isOisRead(call)) {
            // 反序列化威胁模型：OIS 读结果无条件可控（entry = 调用所在方法）
            return completeChain(mark, "deserialization", method, trace,
                    "ois-read:" + call.strProp("name"));
        }
        ForwardOrigins.State state = support.origins().compute(method).stateBefore().get(call.prop("offset"));
        if (state == null) {
            return 0;
        }
        int produced = 0;
        String kind = call.strProp("invokeKind");
        boolean calleeStatic = "STATIC".equals(kind);
        if (!calleeStatic) {
            // 可控 receiver → 返回值可控（GadgetInspector 对象语义）
            int receiverDepth = state.stack().size() - 1 - Descriptor.paramCount(call.strProp("desc"));
            if (receiverDepth >= 0 && receiverDepth < state.stack().size()) {
                for (ValueOrigin receiverOrigin : state.stack().get(receiverDepth).origins()) {
                    produced += controlled(receiverOrigin, method, depth + 1, trace, mark);
                }
            }
        }
        // passthrough：任一实参可控 → 返回值可控（按被调方法实参槽遍历，wide 参数占 2 槽）
        if (produced == 0) {
            List<Integer> argSlots = Descriptor.argSlots(call.strProp("desc"), calleeStatic);
            int slot = 0;
            for (int i = 0; i < argSlots.size() && produced == 0; i++) {
                for (ValueOrigin argOrigin : support.argOriginAt(call, method, slot)) {
                    produced += controlled(argOrigin, method, depth + 1, trace, mark);
                    if (produced > 0) {
                        break;
                    }
                }
                slot += argSlots.get(i);
            }
        }
        return produced;
    }

    /** 字段读取：静态不可控；可控 receiver 的可序列化字段可控；写入可控值的字段可控。 */
    private int controlledFieldRead(ValueOrigin.FieldRead fieldRead, MethodInfo method, int depth,
                                    Trace trace, SinkMark mark) {
        trace.steps++;
        if (fieldRead.isStatic()) {
            return 0;
        }
        int produced = 0;
        if (isSerializedField(fieldRead.owner(), fieldRead.field())) {
            ChainHop hop = new ChainHop(method.owner(), method.name(),
                    method.owner(), method.name(), HopKind.FIELD_FLOW, fieldRead.field(), "field-read", "", null);
            int unresolvedBefore = trace.unresolved;
            trace.hops.add(hop);
            produced += controlled(fieldRead.receiver(), method, depth + 1, trace, mark);
            trace.hops.remove(trace.hops.size() - 1);
            trace.unresolved = unresolvedBefore;
            if (produced > 0) {
                return produced;
            }
        }
        int writers = 0;
        for (FieldWriterIndex.Writer writer : bb.fieldWriters().writersOf(fieldRead.owner(), fieldRead.field())) {
            if (writers >= MAX_WRITERS_PER_FIELD) {
                trace.unresolved++;
                break;
            }
            MethodInfo writerMethod = support.methodOf(writer.methodOwner(), writer.methodName(), writer.methodDesc());
            if (writerMethod == null) {
                trace.unresolved++;
                continue;
            }
            if (!entryReaching.contains(OriginSupport.methodKey(writerMethod))) {
                continue; // 写者祖先链不可达入口：剪枝
            }
            writers++;
            ForwardOrigins.State state = support.origins().compute(writerMethod).stateBefore().get(writer.insnOffset());
            if (state == null || state.stack().isEmpty()) {
                continue;
            }
            ChainHop hop = new ChainHop(writerMethod.owner(), writerMethod.name(),
                    method.owner(), method.name(), HopKind.FIELD_FLOW, fieldRead.field(), "field-write", "", null);
            int unresolvedBefore = trace.unresolved;
            trace.hops.add(hop);
            for (ValueOrigin valueOrigin : state.stack().get(state.stack().size() - 1).origins()) {
                produced += controlled(valueOrigin, writerMethod, depth + 1, trace, mark);
            }
            trace.hops.remove(trace.hops.size() - 1);
            trace.unresolved = unresolvedBefore;
            if (produced > 0) {
                return produced;
            }
        }
        return produced;
    }

    /** 链达成：构建 Chain（hops 为 sink→entry 顺序，ENTRY 跳携带入口方法描述符）；跳数超限拒绝。 */
    private int completeChain(SinkMark mark, String entryKind, MethodInfo entryMethod,
                              Trace trace, String reason) {
        long dynamicHops = trace.hops.stream()
                .filter(h -> h.kind() == HopKind.VIRTUAL_DISPATCH || h.kind() == HopKind.FIELD_FLOW)
                .count();
        if (dynamicHops > MAX_HOPS) {
            trace.tooLong++;
            return 0;
        }
        String entryClass = entryMethod.owner();
        String entryName = entryMethod.name();
        List<ChainHop> hops = new ArrayList<>(trace.hops);
        hops.add(new ChainHop(entryClass, entryName, entryClass, entryName, HopKind.ENTRY,
                null, reason, entryMethod.descriptor(), null));
        Chain chain = new Chain(mark.ruleId(), mark.category(), mark.severity(),
                entryClass, entryName, entryKind,
                trace.sinkOwner, trace.sinkMethod, hops, trace.unresolved);
        // V9-lite：记录"此方法可经 N 跳到入口"——下次其他 sink 的 trace 经同一方法时直接完成
        if (trace.hops.size() >= 3) {
            String midKey = trace.hops.get(trace.hops.size() / 2).toOwner();
            segmentCache.putIfAbsent(midKey, new String[] {entryClass, entryKind, String.valueOf(trace.hops.size())});
        }
        return bb.addChain(chain) ? 1 : 0;
    }

    // ---- 工具 ----

    private String firstDescriptorOfEntry(String owner, String name) {
        var ci = bb.hierarchy().classInfo(owner);
        if (ci == null) {
            return "()V";
        }
        for (var m : ci.methods()) {
            if (m.name().equals(name)) {
                return m.descriptor();
            }
        }
        return "()V";
    }

    /** 入口规则判定（自足契约：经黑板 RuleEngine 匹配，含 implementsType 层次校验与 access 过滤），带缓存。 */
    private Rule.MagicEntryRule entryRuleOf(MethodInfo method) {
        String key = OriginSupport.methodKey(method);
        Optional<Rule.MagicEntryRule> cached = entryRuleCache.get(key);
        if (cached != null) {
            return cached.orElse(null);
        }
        Optional<Rule.MagicEntryRule> rule = bb.ruleEngine().matchingEntry(
                method.owner(), method.name(), method.descriptor());
        entryRuleCache.put(key, rule);
        return rule.orElse(null);
    }

    /** 字段是否为序列化字段（非静态、非 transient）；类不可解析时保守视为是。 */
    private boolean isSerializedField(String owner, String field) {
        if (!bb.hierarchy().isSerializable(owner)) {
            return false;
        }
        ClassInfo cls = bb.hierarchy().classInfo(owner);
        if (cls == null || cls.field(field) == null) {
            return true; // 类不可解析时保守
        }
        return !Modifier.isTransient(cls.field(field).access());
    }

    private SinkOutcome outcome(Node call, SinkMark mark, int chains, int steps, int unresolved,
                                int tooLong, String verdict) {
        return new SinkOutcome(mark.ruleId(), mark.category(),
                call.strProp("owner"), call.strProp("name"),
                call.strProp("methodOwner"), call.strProp("methodName"),
                chains, verdict, steps, unresolved, tooLong);
    }

    /** 一次回溯的路径与统计。 */
    private static final class Trace {
        final String sinkOwner;
        final String sinkMethod;
        final List<ChainHop> hops = new ArrayList<>();
        final Set<String> visited = new HashSet<>();
        int unresolved;
        int tooLong;
        int steps;

        Trace(String sinkOwner, String sinkMethod) {
            this.sinkOwner = sinkOwner;
            this.sinkMethod = sinkMethod;
        }
    }
}
