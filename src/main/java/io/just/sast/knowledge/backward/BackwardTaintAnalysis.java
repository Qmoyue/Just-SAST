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
import io.just.sast.model.HandleRef;
import io.just.sast.model.InvokeDynamicRef;
import io.just.sast.model.MethodInfo;
import io.just.sast.model.MethodRef;
import io.just.sast.model.Op;
import io.just.sast.knowledge.engine.ForwardEngine;
import io.just.sast.util.JustLogger;
import io.just.sast.util.AdaptiveParallelism;

import java.lang.reflect.Modifier;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

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
    private record LambdaMetadata(HandleRef implementation) {}

    private static final int MAX_CHAINS_PER_SINK = 20;
    /** 每 sink 步数预算：须覆盖分发图扇出（层次修复后图正确变宽），全局预算另行兜底。 */
    private static final int STEP_BUDGET = 200_000;
    /** 全局步数兜底（终止保证）：须随分发图规模放宽，图表越大首达探索越多。per-sink 并行下按核数摊薄墙钟。 */
    private static final int GLOBAL_BUDGET = 60_000_000;
    /** 并行 worker 数上限：实际值按主机负载与同 JVM 其他知识源共享配额决定。 */
    private static final int MAX_WORKERS = 16;
    private static final int MAX_WRITERS_PER_FIELD = 10;
    /** 链跳数上限：V7 语义改为"动态分派跳数"（VIRTUAL_DISPATCH+FIELD_FLOW），静态直连不计——
     * JDD 复杂度论证：top-down 爆炸因子是动态分派候选数，静态调用链长不构成组合爆炸。 */
    private static final int MAX_HOPS = 40;
    /** 单方法调用者枚举上限：OIS.readObject 等枢纽方法调用者极多，上限过低会按边序误截深链。 */
    private static final int MAX_CALLERS = 10_000;
    /** 祖先反向分发（入边为空时的启发式补全）调用点枚举上限：控制探索成本。 */
    private static final int MAX_MERGED_CALLERS = 300;

    /** V11：按闭包大小调整的每 sink 预算；实例级，避免同 JVM 多扫描互相污染。 */
    private int stepBudgetAdjusted = STEP_BUDGET;
    /** 每个 sink 独立的死胡同缓存；不能跨 sink 复用，因为路径跳数、预算和规则上下文不同。 */
    private record DeadKey(String methodKey, ValueOrigin origin) {}
    private record CallerSites(List<Node> sites, boolean merged) {}

    private final ThreadLocal<Set<DeadKey>> localDeadEnds = ThreadLocal.withInitial(java.util.HashSet::new);
    /** 方法/入口槽的调用者列表只依赖冻结图，按方法缓存后不再为每个 sink 重建和排序。 */
    private final java.util.concurrent.ConcurrentHashMap<String, CallerSites> callerSitesCache =
            new java.util.concurrent.ConcurrentHashMap<>();
    private final java.util.concurrent.ConcurrentHashMap<String, Set<String>> ancestorTypesCache =
            new java.util.concurrent.ConcurrentHashMap<>();
    private final Map<String, Optional<Rule.MagicEntryRule>> entryRuleCache =
            new java.util.concurrent.ConcurrentHashMap<>();
    /** 双向剪枝：入口下游闭包（与链剪枝共享同一份，黑板分发）。 */
    private Set<String> entryReaching = Set.of();
    private Blackboard bb;
    private OriginSupport support;
    /** 只用于统计，不参与热路径预算判定；预算按稳定 sink 序号预分配，结果可复现。 */
    private final java.util.concurrent.atomic.LongAdder totalSteps = new java.util.concurrent.atomic.LongAdder();

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
            stepBudgetAdjusted = 50_000;
        } else if (entryReaching.size() > 50_000) {
            stepBudgetAdjusted = 100_000;
        } else {
            stepBudgetAdjusted = STEP_BUDGET;
        }
        totalSteps.reset();
        callerSitesCache.clear();
        ancestorTypesCache.clear();
        JustLogger.info("入口下游闭包：{} 个方法（每 sink 上限 {}）", entryReaching.size(), stepBudgetAdjusted);
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
        sinks.sort(java.util.Comparator.comparingInt((SinkTask task) -> {
            MethodInfo host = support.methodOf(bb.graph().node(task.callId()).methodOwner(),
                    bb.graph().node(task.callId()).methodName(),
                    bb.graph().node(task.callId()).methodDescriptor());
            return host != null ? support.entryDepthOf(OriginSupport.methodKey(host)) : Integer.MAX_VALUE;
        }).thenComparingLong(SinkTask::callId));
        // per-sink 并行：sink 分析相互独立（Trace 线程本地），共享结构已并发化
        java.util.concurrent.atomic.AtomicInteger cursor = new java.util.concurrent.atomic.AtomicInteger();
        AdaptiveParallelism.Decision decision = AdaptiveParallelism.choose(sinks.size(), MAX_WORKERS);
        AdaptiveParallelism.Lease lease = AdaptiveParallelism.reserve(decision);
        int workerCount = Math.max(1, lease.workers());
        FairBudgetAllocator budgetAllocator = new FairBudgetAllocator(
                GLOBAL_BUDGET, stepBudgetAdjusted, sinks.size());
        Runnable worker = () -> {
            while (true) {
                int i = cursor.getAndIncrement();
                if (i >= sinks.size()) {
                    return;
                }
                SinkTask task = sinks.get(i);
                int perSinkBudget = budgetAllocator.claim(i);
                localDeadEnds.get().clear();
                try {
                    analyzeSink(task.callId(), task.mark(), perSinkBudget);
                } catch (Throwable e) {
                    JustLogger.error("反向污点 sink 分析失败（已隔离）: {}", e.toString());
                } finally {
                    localDeadEnds.get().clear();
                }
            }
        };
        try {
            if (workerCount <= 1) {
                worker.run();
            } else {
                Thread[] threads = new Thread[workerCount - 1];
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
        } finally {
            lease.close();
        }
        if (support.constantProofBudgetExceeded()) {
            bb.markIncomplete("CONSTANT_PROOF_CAP:" + OriginSupport.CONSTANT_PROOF_BUDGET);
        }
        if (budgetAllocator.exhausted()) {
            bb.markIncomplete("BACKWARD_GLOBAL_BUDGET");
        }
        JustLogger.info("反向污点[{} workers/{}]：{} ms（总步数 {}，每 sink 上限 {}）",
                workerCount, decision.reason(), System.currentTimeMillis() - startTime,
                totalSteps.sum(), stepBudgetAdjusted);
    }

    private void analyzeSink(long callNodeId, SinkMark mark, int stepBudget) {
        Node call = bb.graph().node(callNodeId);
        MethodInfo method = support.enclosingMethod(call);
        if (method == null) {
            bb.recordOutcome(callNodeId, outcome(call, mark, 0, 0, 0, 0, "UNRESOLVED"));
            return;
        }
        if (!entryReaching.contains(OriginSupport.methodKey(method))) {
            // sink 宿主方法不在入口下游集内：可证明无链。
            // 注：子类覆写下钻不足（implementers 不穿透实现类）的豁免尝试（覆写感知门/闭包下钻）
            // 均实测会经全局预算重分配挤掉多态类链——预算按序分配的敏感性是根因，见 development.md
            bb.recordOutcome(callNodeId, outcome(call, mark, 0, 0, 0, 0, "NO_PATH"));
            return;
        }
        // catch 可达性守卫（U1/U4，可判定才剪）：sink 位于 CCE handler 且守卫区为"类型安全的 Class.cast"
        // ——cast 目标是实参静态声明类型的（严格）父类时 cast 必成功，handler 不可达
        if (support.catchProvablyUnreachable(method, (Integer) call.prop("offset"))) {
            bb.recordOutcome(callNodeId, outcome(call, mark, 0, 0, 0, 0, "NO_PATH"));
            return;
        }
        if (support.sinkPathProvablyUnreachable(method, (Integer) call.prop("offset"))) {
            // The normal taint transfer remains deliberately path-insensitive.  This exact
            // local feasibility pass only suppresses a sink when every entry-to-sink path
            // requires a proven-impossible branch/reflective continuation/cast.
            bb.recordOutcome(callNodeId, outcome(call, mark, 0, 0, 0, 0, "NO_PATH"));
            return;
        }
        ForwardOrigins.Result result = support.origins().compute(method);
        ForwardOrigins.State state = result.stateBefore().get(call.prop("offset"));
        if (state == null) {
            bb.recordOutcome(callNodeId, outcome(call, mark, 0, 0, 0, 0, "NO_STATE"));
            return;
        }
        int paramCount = Descriptor.paramCount(call.descriptor());
        int produced = 0;
        Trace trace = new Trace(call.owner(), call.name(), call.descriptor(), stepBudget);
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
        } else if (trace.truncated > 0 || trace.steps > trace.stepBudget) {
            verdict = "TRUNCATED";
        } else if (trace.tooLong > 0) {
            verdict = "TOO_LONG";
        } else if (trace.unresolved > 0) {
            verdict = "UNRESOLVED";
        } else {
            verdict = "NO_PATH";
        }
        if (trace.produced >= MAX_CHAINS_PER_SINK) {
            bb.markIncomplete("BACKWARD_CHAIN_CAP:" + MAX_CHAINS_PER_SINK);
        }
        if (trace.truncated > 0) {
            bb.markIncomplete("BACKWARD_STEP_OR_DEPTH_CAP");
        }
        if (trace.tooLong > 0) {
            bb.markIncomplete("BACKWARD_HOP_CAP");
        }
        if (trace.unresolved > 0) {
            bb.markIncomplete("BACKWARD_UNRESOLVED");
        }
        totalSteps.add(trace.steps);
        localDeadEnds.get().clear();
        bb.recordOutcome(callNodeId, outcome(call, mark, produced, trace.steps, trace.unresolved, trace.tooLong, verdict));
    }

    /**
     * Fair, deterministic-by-input-order allocation of the global backward budget. A fixed
     * GLOBAL_BUDGET/sink division starves the useful tail when the sink population changes;
     * this allocator gives every sink a bounded minimum share where the global budget permits
     * it, then distributes the remainder. Allocation is a pure function of the sorted sink
     * index, so worker scheduling cannot change the analysis depth or chain set.
     */
    private static final class FairBudgetAllocator {
        private final long totalBudget;
        private final int sinkCount;
        private final int maxPerSink;
        private final int minimumPerSink;

        private FairBudgetAllocator(long totalBudget, int maxPerSink, int sinkCount) {
            this.totalBudget = Math.max(0L, totalBudget);
            this.sinkCount = Math.max(0, sinkCount);
            this.maxPerSink = Math.max(1, maxPerSink);
            this.minimumPerSink = Math.min(2_048, this.maxPerSink);
        }

        private int claim(int sinkIndex) {
            if (sinkCount == 0 || sinkIndex < 0 || sinkIndex >= sinkCount) {
                return 0;
            }
            long usable = Math.min(totalBudget, (long) maxPerSink * sinkCount);
            long share;
            long guaranteed = (long) minimumPerSink * sinkCount;
            if (usable >= guaranteed) {
                long extra = usable - guaranteed;
                share = minimumPerSink + extra / sinkCount
                        + (sinkIndex < extra % sinkCount ? 1L : 0L);
            } else {
                share = usable / sinkCount + (sinkIndex < usable % sinkCount ? 1L : 0L);
            }
            return (int) Math.min(maxPerSink, share);
        }

        private boolean exhausted() {
            return sinkCount > 0 && totalBudget <= (long) maxPerSink * sinkCount;
        }
    }

    /** 返回：该值可控所产出的链数。 */
    private int controlled(ValueOrigin origin, MethodInfo method, int depth, Trace trace, SinkMark mark) {
        if (trace.produced >= MAX_CHAINS_PER_SINK) {
            return 0;
        }
        if (depth > bb.maxDepth() || trace.steps > trace.stepBudget) {
            trace.truncated++;
            return 0;
        }
        // 预算尾部截断的结果不可靠，不写入死胡同缓存（防假阴性污染）
        boolean nearBudget = trace.steps > trace.stepBudget * 4 / 5;
        // 深度接近上限的结果受截断影响，不记忆化也不查询（深度无关键的不健全）
        boolean memoizable = depth <= bb.maxDepth() / 2;
        DeadKey memoKey = new DeadKey(OriginSupport.methodKey(method), origin);
        Set<DeadKey> localDead = localDeadEnds.get();
        if ((memoizable && localDead.contains(memoKey))
                || trace.visited.contains(memoKey)) {
            return 0;
        }
        trace.visited.add(memoKey);
        int truncatedBefore = trace.truncated;
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
        // 子树内发生过深度/预算截断的"无链"结论是探索不完整，不是可证明无链——不记忆化
        if (produced == 0 && memoizable && !nearBudget && trace.truncated == truncatedBefore) {
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
        // 通用框架对象绑定边界：bridge=deserialize 明确声明框架会把外部对象属性
        // 写入 JavaBean setter。该语义不依赖具体框架、题目或类名；仅接受 public
        // 非静态单参数 setter，避免把任意公共方法泛化为外部输入。
        if (slot > 0 && support.frameworkDeserializeSourceAvailable()
                && isJavaBeanSetter(method)) {
            return completeChain(mark, "deserialize", method, trace, "framework-bean-input");
        }
        int lambdaProduced = controlledLambdaParam(slot, method, depth, trace, mark);
        if (lambdaProduced > 0) {
            return lambdaProduced;
        }
        Node methodNode = bb.graph().findMethodNode(method.owner(), method.name(), method.descriptor());
        if (methodNode == null) {
            return 0;
        }
        // 调用点收集：自身入边；为空时并入祖先类型（传递接口/父类链）上同名方法的入边
        // （接口实现数超 CHA 上限时分发边未物化，具体实现类须经祖先方法节点反查调用点——同前向引擎语义）
        CallerSites callerSites = callerSitesOf(method, methodNode);
        List<Node> callSites = callerSites.sites();
        boolean merged = callerSites.merged();
        int callerCap = merged ? MAX_MERGED_CALLERS : MAX_CALLERS;
        int produced = 0;
        int callers = 0;
        // 入口距离优先（JDD bottom-up / FLASH 入口导向的探索序）：离反序列化入口近的调用者先走，
        // 链在预算内更快闭合——预算截断下的可复现优先级，替代边序的随机性
        for (Node callerCall : callSites) {
            if (callers >= callerCap || trace.produced >= MAX_CHAINS_PER_SINK) {
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
            // An argument reaching a virtual/interface call does not make every
            // implementation receiver possible.  When the receiver is a concrete NEW
            // or a field freshly initialized by a dominating local write, honor JVM
            // resolution here as well as in the forward engine.  Unknown aliases remain
            // conservative, which preserves ordinary deserialization object graphs.
            if (!method.isStatic() && !support.receiverMayDispatchTo(callerCall, callerMethod,
                    method.owner(), method.name(), method.descriptor())) {
                continue;
            }
            // A reflective lookup/invocation is a call edge only after its exact local
            // preconditions hold.  The backward sink itself lives in the reflected target,
            // so checking only the target method misses a failed Class.get* lookup (and a
            // null/inaccessible Method.invoke) in the caller.  This is a generic CFG proof;
            // unknown metadata remains conservative.
            if (support.sinkPathProvablyUnreachable(callerMethod, callerCall.offset())) {
                continue;
            }
            callers++;
            ForwardOrigins.Result callerResult = support.origins().compute(callerMethod);
            boolean nativeCallback = support.nativeCallbackSite(callerCall, method);
            boolean reflectiveInvoke = isReflectiveMethodInvoke(callerCall);
            Set<ValueOrigin> argOrigins = nativeCallback
                    ? support.nativeTargetArgumentAt(callerCall, method, slot, callerResult)
                    : reflectiveInvoke
                    ? support.reflectiveTargetArgumentAt(callerCall, method, slot, callerResult)
                    : support.argOriginAt(callerCall, callerMethod, slot, callerResult);
            if (argOrigins.isEmpty()) {
                continue;
            }
            // 类型流可断言类型同一性的前提是"纯参数直传"（调用方把自己的参数原样传入）；
            // 来源含派生（调用结果/指令产物/字段读——passthrough 会合法换类型，如 method.getDeclaringClass()）
            // 时 argOrdinal 置空，chain-validator 的类型流校验据此跳过该跳（历史回归：CC BeanMap 链被误拒）
            boolean directParam = argOrigins.stream().allMatch(o -> o instanceof ValueOrigin.Param);
            Integer argumentOrdinal = directParam
                    ? Descriptor.paramOrdinal(method.descriptor(), method.isStatic(), slot) : null;
            HopKind hopKind = nativeCallback ? HopKind.NATIVE_CALLBACK : HopKind.VIRTUAL_DISPATCH;
            String reason = nativeCallback ? "native-callback" : "call";
            ChainHop hop = new ChainHop(callerMethod.owner(), callerMethod.name(),
                    method.owner(), method.name(), hopKind, null, reason,
                    method.descriptor(), argumentOrdinal);
            int unresolvedBefore = trace.unresolved;
            trace.hops.add(hop);
            for (ValueOrigin argOrigin : argOrigins) {
                produced += controlled(argOrigin, callerMethod, depth + 1, trace, mark);
                if (trace.produced >= MAX_CHAINS_PER_SINK) {
                    break;
                }
            }
            trace.hops.remove(trace.hops.size() - 1);
            trace.unresolved = unresolvedBefore;
        }
        return produced;
    }

    /** Native callback sites are explicit semantic callers, not graph call edges. */
    private void addNativeCallbackCallers(MethodInfo method, Set<Node> out) {
        for (Node site : support.nativeCallbackSitesOf(method)) {
            String hostKey = OriginSupport.methodKeyOf(site.methodOwner(), site.methodName(),
                    site.methodDescriptor());
            if (entryReaching.contains(hostKey)) {
                out.add(site);
            }
        }
    }

    /**
     * Reverse the SAM argument/capture mapping that javac encodes in LambdaMetafactory.  The
     * normal call graph only has the factory-to-implementation edge; the later interface call
     * carries the actual invocation argument and is therefore the point where a lambda body
     * parameter becomes attacker-controlled.  This is structural and works for arbitrary
     * functional interfaces, captured receivers, and explicit captured values.
     */
    private int controlledLambdaParam(int slot, MethodInfo implementation, int depth,
                                      Trace trace, SinkMark mark) {
        Node methodNode = bb.graph().findMethodNode(implementation.owner(), implementation.name(),
                implementation.descriptor());
        if (methodNode == null) {
            return 0;
        }
        int produced = 0;
        for (Edge edge : methodNode.in()) {
            if (edge.type() != EdgeType.LAMBDA) {
                continue;
            }
            Node factory = edge.from();
            LambdaMetadata metadata = lambdaMetadata(factory);
            if (metadata == null || !sameMethod(edge.to(), implementation)) {
                continue;
            }
            MethodInfo caller = support.enclosingMethod(factory);
            if (caller == null || !entryReaching.contains(OriginSupport.methodKey(caller))) {
                continue;
            }
            ForwardOrigins.Result callerResult = support.origins().compute(caller);
            int capturedCount = Descriptor.paramCount(factory.descriptor());
            boolean receiverCapture = lambdaHasCapturedReceiver(metadata.implementation().tag());
            int explicitCaptured = Math.max(0, implementation.paramCount()
                    - Descriptor.paramCount(samDescriptor(factory, caller)));

            // An instance implementation receives its bound receiver in local slot 0, even
            // though that receiver is absent from the method descriptor.
            if (receiverCapture && slot == 0 && capturedCount > 0) {
                produced += controlledLambdaCapture(factory, caller, callerResult, 0,
                        implementation, depth, trace, mark);
            }
            for (int captureOrdinal = receiverCapture ? 1 : 0;
                 captureOrdinal < capturedCount; captureOrdinal++) {
                int prefixOrdinal = captureOrdinal - (receiverCapture ? 1 : 0);
                int captureSlot = implementationParameterSlot(implementation, prefixOrdinal);
                if (captureSlot == slot) {
                    produced += controlledLambdaCapture(factory, caller, callerResult,
                            captureOrdinal, implementation, depth, trace, mark);
                }
            }

            for (Node samCall : bb.graph().callsOfMethod(OriginSupport.methodKey(caller))) {
                if (samCall == factory || !lambdaReceiverMatches(samCall, factory, callerResult)) {
                    continue;
                }
                int samCount = Descriptor.paramCount(samCall.descriptor());
                for (int ordinal = 0; ordinal < samCount; ordinal++) {
                    int samSlot = lambdaParameterSlot(implementation, explicitCaptured, ordinal);
                    if (samSlot != slot || support.sinkPathProvablyUnreachable(caller,
                            samCall.offset())) {
                        continue;
                    }
                    Set<ValueOrigin> values = support.argOriginAtOrdinal(samCall, ordinal,
                            callerResult);
                    if (values.isEmpty()) {
                        continue;
                    }
                    ChainHop hop = new ChainHop(caller.owner(), caller.name(), implementation.owner(),
                            implementation.name(), HopKind.VIRTUAL_DISPATCH, null,
                            "lambda-sam", implementation.descriptor(), ordinal);
                    trace.hops.add(hop);
                    int unresolvedBefore = trace.unresolved;
                    for (ValueOrigin value : values) {
                        produced += controlled(value, caller, depth + 1, trace, mark);
                        if (trace.produced >= MAX_CHAINS_PER_SINK) {
                            break;
                        }
                    }
                    trace.hops.remove(trace.hops.size() - 1);
                    trace.unresolved = unresolvedBefore;
                }
            }
            if (trace.produced >= MAX_CHAINS_PER_SINK) {
                return produced;
            }
        }
        return produced;
    }

    private int controlledLambdaCapture(Node factory, MethodInfo caller,
                                        ForwardOrigins.Result callerResult, int captureOrdinal,
                                        MethodInfo implementation, int depth, Trace trace,
                                        SinkMark mark) {
        Set<ValueOrigin> values = support.argOriginAtOrdinal(factory, captureOrdinal, callerResult);
        if (values.isEmpty()) {
            return 0;
        }
        ChainHop hop = new ChainHop(caller.owner(), caller.name(), implementation.owner(),
                implementation.name(), HopKind.VIRTUAL_DISPATCH, null, "lambda-capture",
                implementation.descriptor(), null);
        trace.hops.add(hop);
        int unresolvedBefore = trace.unresolved;
        int produced = 0;
        for (ValueOrigin value : values) {
            produced += controlled(value, caller, depth + 1, trace, mark);
            if (trace.produced >= MAX_CHAINS_PER_SINK) {
                break;
            }
        }
        trace.hops.remove(trace.hops.size() - 1);
        trace.unresolved = unresolvedBefore;
        return produced;
    }

    private LambdaMetadata lambdaMetadata(Node factory) {
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
        return new LambdaMetadata(implementation);
    }

    private String samDescriptor(Node factory, MethodInfo caller) {
        Object value = factory.prop("indy");
        if (!(value instanceof InvokeDynamicRef indy)) {
            return factory.descriptor();
        }
        // LambdaMetafactory's first bootstrap argument is the erased SAM descriptor.  The
        // interface call is used as a fallback for unusual compiler encodings.
        if (!indy.bootstrapArgs().isEmpty() && indy.bootstrapArgs().get(0) instanceof io.just.sast.model.TypeRef type) {
            return type.descriptor();
        }
        return factory.descriptor();
    }

    private boolean lambdaReceiverMatches(Node samCall, Node factory,
                                          ForwardOrigins.Result callerResult) {
        ValueOrigin factoryOrigin = new ValueOrigin.CallResult(factory.id());
        for (ValueOrigin receiver : support.argOriginAtOrdinal(samCall, -1, callerResult)) {
            if (sameLambdaOrigin(receiver, factoryOrigin, callerResult,
                    support.enclosingMethod(samCall), new HashSet<>())) {
                return true;
            }
        }
        return false;
    }

    private boolean sameLambdaOrigin(ValueOrigin value, ValueOrigin expected,
                                     ForwardOrigins.Result result, MethodInfo method,
                                     Set<ValueOrigin> visiting) {
        if (value.equals(expected)) {
            return true;
        }
        if (!(value instanceof ValueOrigin.Insn instruction) || method == null
                || !visiting.add(value) || instruction.offset() < 0
                || instruction.offset() >= method.instructions().size()
                || method.insnAt(instruction.offset()).op() != Op.CHECKCAST) {
            return false;
        }
        try {
            ForwardOrigins.State before = result.stateBefore().get(instruction.offset());
            if (before == null || before.stack().isEmpty()) {
                return false;
            }
            for (ValueOrigin candidate : before.stack().get(before.stack().size() - 1).origins()) {
                if (sameLambdaOrigin(candidate, expected, result, method, visiting)) {
                    return true;
                }
            }
            return false;
        } finally {
            visiting.remove(value);
        }
    }

    private static boolean sameMethod(Node node, MethodInfo method) {
        return node != null && node.owner().equals(method.owner()) && node.name().equals(method.name())
                && node.descriptor().equals(method.descriptor());
    }

    private static boolean lambdaHasCapturedReceiver(int handleTag) {
        return handleTag == 5 || handleTag == 7 || handleTag == 9;
    }

    private static int lambdaParameterSlot(MethodInfo implementation, int explicitCaptured,
                                           int samOrdinal) {
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
        int start = isStatic ? 0 : 1;
        int index = start + ordinal;
        if (index < start || index >= slots.size()) {
            return -1;
        }
        int slot = 0;
        for (int i = 0; i < index; i++) {
            slot += slots.get(i);
        }
        return slot;
    }

    /** 冻结图上的调用者索引：收集、反射补边、祖先回查和距离排序只做一次。 */
    private CallerSites callerSitesOf(MethodInfo method, Node methodNode) {
        String key = OriginSupport.methodKey(method);
        return callerSitesCache.computeIfAbsent(key, ignored -> {
            Set<Node> sites = new java.util.LinkedHashSet<>();
            collectCallSites(methodNode, sites);
            addNativeCallbackCallers(method, sites);
            addReflectiveCallers(method, sites);
            boolean merged = sites.isEmpty();
            if (merged) {
                for (String ancestor : ancestorTypes(method.owner())) {
                    Node ancestorNode = bb.graph().findMethodNode(ancestor, method.name(), method.descriptor());
                    if (ancestorNode != null) {
                        collectCallSites(ancestorNode, sites);
                    }
                }
            }
            List<Node> ordered = new ArrayList<>(sites);
            ordered.sort(java.util.Comparator
                    .comparingInt((Node site) -> {
                        MethodInfo caller = support.enclosingMethod(site);
                        return caller != null ? support.entryDepthOf(OriginSupport.methodKey(caller)) : Integer.MAX_VALUE;
                    })
                    .thenComparingLong(Node::id));
            return new CallerSites(List.copyOf(ordered), merged);
        });
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
            if (support.reflectiveInvokeMayReach(method, precise)) {
                out.add(precise);
            }
        }
        for (Node site : support.reflectiveInvokeSitesOf(cls)) {
            if (site.id() != (precise == null ? -1 : precise.id())
                    && support.reflectiveInvokeMayReach(method, site)) {
                out.add(site);
            }
        }
        // JavaBean 反射跳（FLASH 第三支柱）：getReadMethod/getWriteMethod 产出的 invoke 位点
        // 是 JavaBean 前缀方法的伪调用者（类可解精确匹配 + wildcard 位点对任意前缀方法）
        for (Node site : support.javaBeanInvokeSitesOf(cls, method.name())) {
            if (support.reflectiveInvokeMayReach(method, site)) {
                out.add(site);
            }
        }
        // 框架反射供给（性能优化版）：仅 setter/getter/isXxx 接受框架伪调用者——
        // 且仅限闭包内的 invoke 位点（不可达的框架代码无意义）
        // 框架 Method.invoke 位点来自已加载的依赖字节码，快速模式只跳过 JDK
        // 全量类，不应关闭 JavaBean setter/getter 的反射调用者建模。
        if (isJavaBeanMethod(method.name())) {
            for (Node site : support.frameworkMethodInvokeSites()) {
                String hostKey = OriginSupport.methodKeyOf(
                        site.methodOwner(), site.methodName(), site.methodDescriptor());
                if (entryReaching.contains(hostKey)) {
                    if (support.reflectiveInvokeMayReach(method, site)) {
                        out.add(site);
                    }
                }
            }
        }
        // A serialized proxy may be assembled by the caller, so its handler bytecode does not
        // contain Proxy.newProxyInstance.  When the handler passes the runtime Method argument
        // to Method.invoke, restrict the wildcard to public instance methods exposed by one of
        // the target's interfaces—the exact JVM proxy contract.
        if (support.proxyCallable(method)) {
            for (Node site : support.proxyMethodInvokeSites()) {
                String hostKey = OriginSupport.methodKeyOf(
                        site.methodOwner(), site.methodName(), site.methodDescriptor());
                if (entryReaching.contains(hostKey)
                        && support.reflectiveInvokeMayReach(method, site)) {
                    out.add(site);
                }
            }
        }
        if (isJavaBeanMethod(method.name()) && Descriptor.paramCount(method.descriptor()) == 0) {
            for (Node site : support.methodCollectionInvokeSites()) {
                String hostKey = OriginSupport.methodKeyOf(
                        site.methodOwner(), site.methodName(), site.methodDescriptor());
                if (entryReaching.contains(hostKey)
                        && support.reflectiveInvokeMayReach(method, site)) {
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

    private static boolean isReflectiveMethodInvoke(Node call) {
        return call != null && "java/lang/reflect/Method".equals(call.owner())
                && "invoke".equals(call.name());
    }

    /** invokedynamic 没有隐含 receiver；其 descriptor 的参数都是真实参数。 */
    private static boolean isStaticLike(String invokeKind) {
        return "STATIC".equals(invokeKind) || "DYNAMIC".equals(invokeKind);
    }

    private static boolean isJavaBeanSetter(MethodInfo method) {
        return !method.isStatic()
                && Modifier.isPublic(method.access())
                && method.name() != null
                && method.name().startsWith("set")
                && method.name().length() > 3
                && Descriptor.paramCount(method.descriptor()) == 1;
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
        Set<String> cached = ancestorTypesCache.get(owner);
        if (cached != null) {
            return cached;
        }
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
        Set<String> immutable = Set.copyOf(result);
        ancestorTypesCache.put(owner, immutable);
        return immutable;
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
                if (trace.produced >= MAX_CHAINS_PER_SINK) {
                    return produced;
                }
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
                if (trace.produced >= MAX_CHAINS_PER_SINK) {
                    return produced;
                }
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
                    "ois-read:" + call.name());
        }
        ForwardOrigins.State state = support.origins().compute(method).stateBefore().get(call.prop("offset"));
        if (state == null) {
            return 0;
        }
        if (isProxyInvocation(call, method, state)) {
            // A proxy result is the selected InvocationHandler return value. Treating any
            // argument as a returned value manufactures a chain when the handler returns a
            // constant for this interface method (the common proxy FP shape).
            return controlledProxyResult(call, method, depth, trace, mark, state);
        }
        int produced = 0;
        String kind = call.invokeKind();
        boolean calleeStatic = isStaticLike(kind);
        if (!calleeStatic) {
            // 可控 receiver → 返回值可控（GadgetInspector 对象语义）
            int receiverDepth = state.stack().size() - 1 - Descriptor.paramCount(call.descriptor());
            if (receiverDepth >= 0 && receiverDepth < state.stack().size()) {
                for (ValueOrigin receiverOrigin : state.stack().get(receiverDepth).origins()) {
                    produced += controlled(receiverOrigin, method, depth + 1, trace, mark);
                    if (trace.produced >= MAX_CHAINS_PER_SINK) {
                        return produced;
                    }
                }
            }
        }
        // passthrough：任一实参可控 → 返回值可控（按被调方法实参槽遍历，wide 参数占 2 槽）
        if (produced == 0) {
            List<Integer> argSlots = Descriptor.argSlots(call.descriptor(), calleeStatic);
            int slot = 0;
            for (int i = 0; i < argSlots.size() && produced == 0; i++) {
                for (ValueOrigin argOrigin : support.argOriginAt(call, method, slot)) {
                    produced += controlled(argOrigin, method, depth + 1, trace, mark);
                    if (produced > 0) {
                        break;
                    }
                }
                if (trace.produced >= MAX_CHAINS_PER_SINK) {
                    return produced;
                }
                slot += argSlots.get(i);
            }
        }
        return produced;
    }

    private int controlledProxyResult(Node call, MethodInfo caller, int depth, Trace trace,
                                      SinkMark mark, ForwardOrigins.State state) {
        int produced = 0;
        for (ValueOrigin receiver : receiverOrigins(call, state)) {
            Node allocation = proxyAllocationOf(receiver, caller);
            if (allocation == null) {
                continue;
            }
            MethodInfo allocationMethod = support.enclosingMethod(allocation);
            if (allocationMethod == null) {
                continue;
            }
            ForwardOrigins.Result allocationOrigins = support.origins().compute(allocationMethod);
            for (ValueOrigin handlerOrigin : support.argOriginAtOrdinal(allocation, 2,
                    allocationOrigins)) {
                String handlerType = concreteType(handlerOrigin, allocationMethod);
                if (handlerType == null) {
                    continue;
                }
                String resolved = bb.hierarchy().resolveMethod(handlerType, "invoke",
                        "(Ljava/lang/Object;Ljava/lang/reflect/Method;[Ljava/lang/Object;)Ljava/lang/Object;");
                MethodInfo handler = resolved == null ? null : support.methodOf(resolved, "invoke",
                        "(Ljava/lang/Object;Ljava/lang/reflect/Method;[Ljava/lang/Object;)Ljava/lang/Object;");
                if (handler == null) {
                    continue;
                }
                Set<Integer> returnOffsets = ForwardEngine.proxyMethodReturnOffsets(handler, call.name(),
                        support::cfg);
                if (returnOffsets.isEmpty()) {
                    bb.markIncomplete("PROXY_RETURN_METADATA");
                    returnSummary(handler, depth, trace, mark);
                    continue;
                }
                ForwardOrigins.Result handlerOrigins = support.origins().compute(handler);
                for (int offset : returnOffsets) {
                    ForwardOrigins.State returnState = handlerOrigins.stateBefore().get(offset);
                    if (returnState == null || returnState.stack().isEmpty()) {
                        continue;
                    }
                    for (ValueOrigin returned : returnState.stack()
                            .get(returnState.stack().size() - 1).origins()) {
                        produced += controlled(returned, handler, depth + 1, trace, mark);
                        if (trace.produced >= MAX_CHAINS_PER_SINK) {
                            return produced;
                        }
                    }
                }
            }
        }
        return produced;
    }

    private void returnSummary(MethodInfo handler, int depth, Trace trace, SinkMark mark) {
        for (var instruction : handler.instructions()) {
            if (!instruction.op().isReturn() || instruction.op() == Op.RETURN
                    || instruction.op() == Op.ATHROW) {
                continue;
            }
            ForwardOrigins.State state = support.origins().compute(handler).stateBefore()
                    .get(instruction.offset());
            if (state == null || state.stack().isEmpty()) {
                continue;
            }
            for (ValueOrigin returned : state.stack().get(state.stack().size() - 1).origins()) {
                controlled(returned, handler, depth + 1, trace, mark);
            }
        }
    }

    private boolean isProxyInvocation(Node call, MethodInfo method, ForwardOrigins.State state) {
        return !isStaticLike(call.invokeKind())
                && receiverOrigins(call, state).stream()
                .map(origin -> proxyAllocationOf(origin, method))
                .anyMatch(allocation -> allocation != null
                        && "java/lang/reflect/Proxy".equals(allocation.owner())
                        && "newProxyInstance".equals(allocation.name()));
    }

    private Node proxyAllocationOf(ValueOrigin origin, MethodInfo method) {
        return proxyAllocationOf(origin, method, new HashSet<>());
    }

    private Node proxyAllocationOf(ValueOrigin origin, MethodInfo method, Set<ValueOrigin> visiting) {
        if (origin instanceof ValueOrigin.CallResult result && result.callNodeId() >= 0) {
            Node call = support.callNode(result.callNodeId());
            return call != null && "java/lang/reflect/Proxy".equals(call.owner())
                    && "newProxyInstance".equals(call.name()) ? call : null;
        }
        if (!(origin instanceof ValueOrigin.Insn instruction) || !visiting.add(origin)
                || instruction.offset() < 0 || instruction.offset() >= method.instructions().size()) {
            return null;
        }
        try {
            if (method.insnAt(instruction.offset()).op() != Op.CHECKCAST) {
                return null;
            }
            ForwardOrigins.State before = support.origins().compute(method).stateBefore()
                    .get(instruction.offset());
            if (before == null || before.stack().isEmpty()) {
                return null;
            }
            for (ValueOrigin candidate : before.stack().get(before.stack().size() - 1).origins()) {
                Node allocation = proxyAllocationOf(candidate, method, visiting);
                if (allocation != null) {
                    return allocation;
                }
            }
            return null;
        } finally {
            visiting.remove(origin);
        }
    }

    private String concreteType(ValueOrigin origin, MethodInfo method) {
        if (origin instanceof ValueOrigin.Insn instruction && instruction.offset() >= 0
                && instruction.offset() < method.instructions().size()) {
            var fact = method.insnAt(instruction.offset());
            if (fact.op() == Op.NEW && fact.typeRef() != null) {
                return internalType(fact.typeRef().descriptor());
            }
        }
        if (origin instanceof ValueOrigin.FieldRead field) {
            String declaring = bb.hierarchy().resolveField(field.owner(), field.field());
            ClassInfo info = bb.hierarchy().classInfo(declaring == null ? field.owner() : declaring);
            if (info != null && info.field(field.field()) != null) {
                return internalType(info.field(field.field()).descriptor());
            }
        }
        return null;
    }

    private static String internalType(String descriptor) {
        if (descriptor == null) {
            return null;
        }
        if (descriptor.startsWith("L") && descriptor.endsWith(";")) {
            return descriptor.substring(1, descriptor.length() - 1);
        }
        return descriptor.indexOf('/') >= 0 && descriptor.charAt(0) != '[' ? descriptor : null;
    }

    private Set<ValueOrigin> receiverOrigins(Node call, ForwardOrigins.State state) {
        if (state == null) {
            return Set.of();
        }
        int depth = state.stack().size() - 1 - Descriptor.paramCount(call.descriptor());
        return depth >= 0 && depth < state.stack().size()
                ? state.stack().get(depth).origins() : Set.of();
    }

    /** 字段读取：静态不可控；可控 receiver 的可序列化字段可控；写入可控值的字段可控。 */
    private int controlledFieldRead(ValueOrigin.FieldRead fieldRead, MethodInfo method, int depth,
                                    Trace trace, SinkMark mark) {
        trace.steps++;
        int produced = 0;
        if (!fieldRead.isStatic() && isSerializedField(fieldRead.owner(), fieldRead.field())) {
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
                if (trace.produced >= MAX_CHAINS_PER_SINK) {
                    break;
                }
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
        if (trace.produced >= MAX_CHAINS_PER_SINK) {
            return 0;
        }
        long dynamicHops = trace.hops.stream()
                .filter(h -> h.kind() == HopKind.VIRTUAL_DISPATCH
                        || h.kind() == HopKind.FIELD_FLOW
                        || h.kind() == HopKind.NATIVE_CALLBACK)
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
                trace.sinkOwner, trace.sinkMethod, hops, trace.unresolved, trace.sinkDescriptor);
        if (!bb.addChain(chain)) {
            return 0;
        }
        trace.produced++;
        return 1;
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
                call.owner(), call.name(),
                call.methodOwner(), call.methodName(),
                chains, verdict, steps, unresolved, tooLong);
    }

    /** 一次回溯的路径与统计。truncated：深度/预算截断发生次数（子树结论作废判定）。 */
    private static final class Trace {
        final String sinkOwner;
        final String sinkMethod;
        final String sinkDescriptor;
        final int stepBudget;
        final List<ChainHop> hops = new ArrayList<>();
        final Set<DeadKey> visited = new HashSet<>();
        int unresolved;
        int tooLong;
        int steps;
        int truncated;
        int produced;

        Trace(String sinkOwner, String sinkMethod, String sinkDescriptor, int stepBudget) {
            this.sinkOwner = sinkOwner;
            this.sinkMethod = sinkMethod;
            this.sinkDescriptor = sinkDescriptor;
            this.stepBudget = stepBudget;
        }
    }
}
