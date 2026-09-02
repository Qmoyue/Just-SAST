package io.just.sast.knowledge.backward;

import io.just.sast.analysis.taint.ForwardOrigins;
import io.just.sast.analysis.taint.ContainerElementSources;
import io.just.sast.analysis.taint.OriginSupport;
import io.just.sast.analysis.taint.ValueOrigin;
import io.just.sast.analysis.taint.ValueOriginOrder;
import io.just.sast.blackboard.Blackboard;
import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.Event;
import io.just.sast.blackboard.EventType;
import io.just.sast.blackboard.HopKind;
import io.just.sast.blackboard.KnowledgeSource;
import io.just.sast.blackboard.SinkOutcome;
import io.just.sast.config.Rule;
import io.just.sast.config.ModelSource;
import io.just.sast.cpg.build.FieldWriterIndex;
import io.just.sast.cpg.graph.Edge;
import io.just.sast.cpg.graph.EdgeType;
import io.just.sast.cpg.graph.Node;
import io.just.sast.cpg.graph.NodeType;
import io.just.sast.model.ClassInfo;
import io.just.sast.model.Descriptor;
import io.just.sast.model.HandleRef;
import io.just.sast.model.InvokeDynamicRef;
import io.just.sast.model.InsnFact;
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
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
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
    private record SinkMark(String ruleId, String category, String severity, List<Rule.TaintedPos> tainted,
                            Rule.SinkRole role) {}
    private record LambdaMetadata(List<HandleRef> implementations) {}

    /** 每 sink 链上限；全局黑板负责跨 sink 去重，避免并行 worker 持有大批临时链。 */
    private static final int MAX_CHAINS_PER_SINK = 20;
    /** Dead-end reuse is a performance cache only; cap it independently of sink count. */
    private static final int MAX_WORKER_DEAD_ENDS = 200_000;
    /** 每 sink 步数预算：须覆盖分发图扇出（层次修复后图正确变宽），全局预算另行兜底。 */
    private static final int STEP_BUDGET = 200_000;
    /** 全局步数兜底（终止保证）：须随分发图规模放宽，图表越大首达探索越多。per-sink 并行下按核数摊薄墙钟。 */
    private static final int GLOBAL_BUDGET = 60_000_000;
    /** 并行 worker 数上限：实际值按主机负载与同 JVM 其他知识源共享配额决定。 */
    private static final int MAX_WORKERS = 16;
    /** 反向分析是有界阶段；不能用裸 Thread.join 无限等待。 */
    private static final long WORKER_TIMEOUT_SECONDS = 300L;
    private static final int MAX_WRITERS_PER_FIELD = 10;
    /** 链跳数上限：V7 语义改为"动态分派跳数"（VIRTUAL_DISPATCH+FIELD_FLOW），静态直连不计——
     * JDD 复杂度论证：top-down 爆炸因子是动态分派候选数，静态调用链长不构成组合爆炸。 */
    private static final int MAX_HOPS = 40;
    /** 单方法调用者枚举上限：OIS.readObject 等枢纽方法调用者极多，上限过低会按边序误截深链。 */
    private static final int MAX_CALLERS = 10_000;
    /** 祖先反向分发（入边为空时的启发式补全）调用点枚举上限：控制探索成本。 */
    private static final int MAX_MERGED_CALLERS = 300;
    /** Bound the wildcard callback family supplied by an external serialized proxy. */
    private static final int MAX_SERIALIZED_PROXY_CALLBACK_SITES = 256;
    /** Bound interface callback expansion for proxies assembled outside the artifact. */
    private static final int MAX_SERIALIZED_PROXY_INTERFACE_SITES = 256;
    /** Bound structural lambda bridge discovery; ordinary interface calls remain demand-driven. */
    private static final int MAX_LAMBDA_BRIDGE_STATES = 512;
    private static final int MAX_LAMBDA_BRIDGE_DEPTH = 8;
    private static final int MAX_LAMBDA_SAM_ROUTES = 256;
    /** Bound body-level return recovery; models remain the cheaper first choice. */
    private static final int MAX_CALLEE_RETURN_TARGETS = 8;
    private static final int MAX_CALLEE_RETURN_SITES = 24;
    /** Do not interpret large/platform bodies as a fallback for every call-result origin. */
    private static final int MAX_CALLEE_RETURN_BODY_INSNS = 256;

    /** V11：按闭包大小调整的每 sink 预算；实例级，避免同 JVM 多扫描互相污染。 */
    private int stepBudgetAdjusted = STEP_BUDGET;
    /** 每个 sink 独立的死胡同缓存；不能跨 sink 复用，因为路径跳数、预算和规则上下文不同。 */
    private record DeadKey(String methodKey, ValueOrigin origin) {}
    private record CallerSite(Node call, MethodInfo caller, String methodKey, int entryDepth) {}
    private record CallerSites(List<CallerSite> sites, boolean merged) {}
    private record ParamRoute(MethodInfo caller, Node call, List<ValueOrigin> origins,
                              Integer argumentOrdinal, HopKind hopKind, String reason) {}
    private record ParamRoutes(List<ParamRoute> routes, int unresolved) {}
    private record LambdaCarrier(MethodInfo method, int slot, int depth) {}
    private record LambdaSamRoute(Node factory, Node samCall, MethodInfo samHost) {}

    private final ThreadLocal<Set<DeadKey>> localDeadEnds = ThreadLocal.withInitial(java.util.HashSet::new);
    /**
     * A sink trace revisits the same method many times while following fields, callbacks and
     * passthrough arguments.  ForwardOrigins already has a scan-wide cache, but calling it for
     * every revisit still paid for key construction and concurrent-map bookkeeping.  Keep a
     * bounded per-worker identity cache across sinks: method summaries are immutable for a
     * frozen scan, and this lets the worker reuse a hot dependency summary when the next sink
     * starts.  The cap and eviction order only affect memoization cost, never semantics.
     */
    private static final int MAX_WORKER_ORIGIN_CACHE_ENTRIES = 16_384;
    private static final class WorkerOriginCache {
        private final IdentityHashMap<MethodInfo, ForwardOrigins.Result> values =
                new IdentityHashMap<>(256);
        private final Deque<MethodInfo> order = new ArrayDeque<>();

        private ForwardOrigins.Result get(MethodInfo method) {
            return values.get(method);
        }

        private void put(MethodInfo method, ForwardOrigins.Result result) {
            if (method == null || result == null || values.containsKey(method)) {
                return;
            }
            while (values.size() >= MAX_WORKER_ORIGIN_CACHE_ENTRIES
                    && !order.isEmpty()) {
                MethodInfo evicted = order.removeFirst();
                values.remove(evicted);
            }
            values.put(method, result);
            order.addLast(method);
        }

    }
    private final ThreadLocal<WorkerOriginCache> localOriginResults =
            ThreadLocal.withInitial(WorkerOriginCache::new);
    /**
     * The caller/argument mapping for a target parameter is scan-invariant, while the path
     * walk that consumes it is sink-local.  Cache the immutable mapping per worker so a large
     * sink set does not repeat receiver feasibility, reflection precondition, and origin-set
     * ordering work.  This is deliberately bounded and local: it cannot change semantics or
     * retain an entire dependency closure after a worker finishes.
     */
    private static final int MAX_WORKER_PARAM_ROUTE_ENTRIES = 8_192;
    private record ParamRouteKey(MethodInfo method, int slot) {}
    private static final class WorkerParamRouteCache {
        private final Map<ParamRouteKey, ParamRoutes> values = new HashMap<>();
        private final Deque<ParamRouteKey> order = new ArrayDeque<>();

        private ParamRoutes get(ParamRouteKey key) {
            return values.get(key);
        }

        private void put(ParamRouteKey key, ParamRoutes value) {
            if (key == null || value == null || values.containsKey(key)) {
                return;
            }
            while (values.size() >= MAX_WORKER_PARAM_ROUTE_ENTRIES && !order.isEmpty()) {
                values.remove(order.removeFirst());
            }
            values.put(key, value);
            order.addLast(key);
        }

        private void clear() {
            values.clear();
            order.clear();
        }
    }
    private final ThreadLocal<WorkerParamRouteCache> localParamRoutes =
            ThreadLocal.withInitial(WorkerParamRouteCache::new);
    /** 方法/入口槽的调用者列表只依赖冻结图，按方法缓存后不再为每个 sink 重建和排序。 */
    private final java.util.concurrent.ConcurrentHashMap<String, CallerSites> callerSitesCache =
            new java.util.concurrent.ConcurrentHashMap<>();
    /** Completed sink traces are published only after the parallel analysis barrier. */
    private final java.util.concurrent.ConcurrentHashMap<Long, List<Chain>> pendingSinkChains =
            new java.util.concurrent.ConcurrentHashMap<>();
    private final java.util.concurrent.ConcurrentHashMap<String, List<String>> ancestorTypesCache =
            new java.util.concurrent.ConcurrentHashMap<>();
    /** Factory + SAM-shape keyed immutable routes; route discovery is shared across sink workers. */
    private record LambdaRouteKey(long factoryId, String samDescriptor) {}
    private final java.util.concurrent.ConcurrentHashMap<LambdaRouteKey, List<LambdaSamRoute>> lambdaRoutesCache =
            new java.util.concurrent.ConcurrentHashMap<>();
    private record ProxyInterfaceMetadataKey(String handlerKey, String methodName) {}
    private final java.util.concurrent.ConcurrentHashMap<ProxyInterfaceMetadataKey, Set<Integer>>
            proxyInterfaceFeasibleOffsets = new java.util.concurrent.ConcurrentHashMap<>();
    private final Map<String, Optional<Rule.MagicEntryRule>> entryRuleCache =
            new java.util.concurrent.ConcurrentHashMap<>();
    /** 双向剪枝：入口下游闭包（与链剪枝共享同一份，黑板分发）。 */
    private Set<String> entryReaching = Set.of();
    /** An external serialized proxy may supply a handler only after a real deserialize root. */
    private boolean deserializeRootPresent;
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
        this.deserializeRootPresent = hasDeserializeRoot(blackboard.graph());
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
        pendingSinkChains.clear();
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
                    new SinkMark(rule.id(), rule.category(), rule.severity(), rule.tainted(), rule.role()))));
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
            // Keep the cache worker-local for allocation-free lookup, but clear it at the
            // sink boundary below.  A dead-end result also depends on the current trace's
            // sink/entry context and on which bounded frontier was already explored; sharing
            // it across sinks would make the result depend on worker scheduling.
            localDeadEnds.get().clear();
            localParamRoutes.get().clear();
            while (true) {
                int i = cursor.getAndIncrement();
                if (i >= sinks.size()) {
                    return;
                }
                SinkTask task = sinks.get(i);
                int perSinkBudget = budgetAllocator.claim(i);
                try {
                    int steps = analyzeSink(task.callId(), task.mark(), perSinkBudget);
                    budgetAllocator.record(i, perSinkBudget, steps);
                } catch (Throwable e) {
                    budgetAllocator.record(i, perSinkBudget, 0);
                    JustLogger.error("反向污点 sink 分析失败（已隔离）: {}", e.toString());
                }
            }
        };
        ExecutorService executor = null;
        try {
            ThreadFactory factory = runnable -> {
                Thread thread = new Thread(runnable, "backward-taint-worker");
                thread.setDaemon(true);
                return thread;
            };
            executor = Executors.newFixedThreadPool(workerCount, factory);
            List<Callable<Void>> tasks = new ArrayList<>(workerCount);
            for (int i = 0; i < workerCount; i++) {
                tasks.add(() -> {
                    worker.run();
                    return null;
                });
            }
            List<Future<Void>> futures = executor.invokeAll(tasks, WORKER_TIMEOUT_SECONDS,
                    TimeUnit.SECONDS);
            for (Future<Void> future : futures) {
                if (future.isCancelled()) {
                    bb.markIncomplete("BACKWARD_WORKER_TIMEOUT:" + WORKER_TIMEOUT_SECONDS);
                    continue;
                }
                try {
                    future.get();
                } catch (ExecutionException e) {
                    bb.markIncomplete("BACKWARD_WORKER_FAILURE");
                    JustLogger.error("反向污点 worker 失败（结果可能欠完备）: {}",
                            e.getCause() == null ? e.toString() : e.getCause().toString());
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            bb.markIncomplete("BACKWARD_INTERRUPTED");
        } finally {
            if (executor != null) {
                executor.shutdownNow();
                try {
                    if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                        bb.markIncomplete("BACKWARD_WORKER_NOT_TERMINATED");
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    bb.markIncomplete("BACKWARD_INTERRUPTED");
                }
            }
            lease.close();
        }
        publishPendingSinkChains();
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

    /**
     * Lifecycle trigger methods are candidate endpoints, not deserialize roots. Keep their
     * local sink paths available for calibration so a missing trigger context is reported as
     * {@code no-trigger} instead of disappearing behind the entry-closure gate. Platform
     * lifecycle implementations stay excluded; their callers are modeled through the
     * application-side dispatch/bridge paths when justified.
     */
    private boolean isLifecycleEntryHost(MethodInfo method) {
        if (method == null || isPlatformOwner(method.owner())) {
            return false;
        }
        Rule.MagicEntryRule entry = entryRuleOf(method);
        return entry != null && "lifecycle".equalsIgnoreCase(entry.direction());
    }

    /**
     * A typed Method collection is an external callback boundary. Its selected
     * getter has no ordinary caller edge in the scanned artifact, so it is
     * activated on demand by the forward engine instead of being inserted into
     * the broad entry closure. Keep the backward sink gate in agreement with
     * that bounded semantic family.
     */
    private boolean isMethodCollectionTarget(MethodInfo method) {
        if (method == null || support.methodCollectionTargetMethods().isEmpty()) {
            return false;
        }
        String key = OriginSupport.methodKey(method);
        return support.methodCollectionTargetMethods().stream()
                .anyMatch(node -> key.equals(OriginSupport.methodKeyOf(
                        node.owner(), node.name(), node.descriptor())));
    }

    /**
     * Check the threat-model root once per scan.  A serializable handler is not an attacker
     * source by itself; it becomes one only when the same artifact contains an actual
     * deserialization boundary.  Keeping this fact separate from {@code entryReaching} is
     * important because the external-proxy index is intentionally admitted lazily.
     */
    private boolean hasDeserializeRoot(io.just.sast.cpg.graph.Graph graph) {
        for (Node methodNode : graph.nodesOfType(NodeType.METHOD)) {
            if (isPlatformOwner(methodNode.owner())) {
                continue;
            }
            Optional<Rule.MagicEntryRule> entry = bb.ruleEngine().matchingEntry(
                    methodNode.owner(), methodNode.name(), methodNode.descriptor());
            if (entry.isPresent() && "deserialize".equalsIgnoreCase(entry.get().direction())
                    && !"proxyInvoke".equals(entry.get().entryKind())) {
                return true;
            }
        }
        for (Node call : graph.nodesOfType(NodeType.CALL)) {
            if (OriginSupport.isOisRead(call)) {
                return true;
            }
            Optional<Rule.SourceRule> source = bb.ruleEngine().matchingSource(
                    call.owner(), call.name(), call.descriptor());
            if (source.isPresent() && isUnconditionalDeserializeSource(source.get())) {
                return true;
            }
        }
        return false;
    }

    private static boolean isUnconditionalDeserializeSource(Rule.SourceRule source) {
        return source != null && !"serialize".equalsIgnoreCase(source.bridge())
                && (source.tainted() == null || source.tainted().isEmpty());
    }

    /**
     * A serializable InvocationHandler is an object-graph value, not a global entry.  Once a
     * real deserialize root and a resolved interface callback are both present, its own
     * serialized fields are a valid reverse boundary even when the proxy object is assembled
     * outside the scanned artifact.  The site check keeps an unrelated handler from becoming
     * a standalone finding and remains independent of framework/package names.
     */
    private boolean externalProxyObjectBoundaryAvailable(MethodInfo handler) {
        if (!deserializeRootPresent || handler == null
                || support.serializedProxyInterfaceCallSites().isEmpty()) {
            return false;
        }
        for (Node call : support.serializedProxyInterfaceCallSites()) {
            MethodInfo caller = support.enclosingMethod(call);
            if (caller == null || !entryReaching.contains(OriginSupport.methodKey(caller))) {
                continue;
            }
            ForwardOrigins.Result result = originsOf(caller);
            Set<ValueOrigin> receivers = support.argOriginAtOrdinal(call, -1, result);
            if (receivers.stream().anyMatch(value -> !(value instanceof ValueOrigin.Constant)
                    && !(value instanceof ValueOrigin.Unknown))) {
                return true;
            }
        }
        return false;
    }

    private static boolean isPlatformOwner(String owner) {
        return owner != null && (owner.startsWith("java/") || owner.startsWith("javax/")
                || owner.startsWith("jdk/") || owner.startsWith("sun/")
                || owner.startsWith("com/sun/"));
    }

    private int analyzeSink(long callNodeId, SinkMark mark, int stepBudget) {
        Node call = bb.graph().node(callNodeId);
        MethodInfo method = support.enclosingMethod(call);
        if (method == null) {
            bb.recordOutcome(callNodeId, outcome(call, mark, 0, 0, 0, 0, "UNRESOLVED"));
            return 0;
        }
        if (!entryReaching.contains(OriginSupport.methodKey(method))
                && !isLifecycleEntryHost(method)
                && !isMethodCollectionTarget(method)) {
            // sink 宿主方法不在入口下游集内：可证明无链。
            // lifecycle trigger（equals/hashCode/toString 等）本身不是反序列化根，
            // 但仍需生成候选交给 calibration 的 no-trigger 门；否则“无触发调用”的
            // 触发器会在分析阶段被静默丢弃，报告无法解释该候选为何不成立。
            bb.recordOutcome(callNodeId, outcome(call, mark, 0, 0, 0, 0, "NO_PATH"));
            return 0;
        }
        ForwardOrigins.Result result = originsOf(method);
        ForwardOrigins.State state = result.stateBefore().get(call.prop("offset"));
        if (state == null) {
            bb.recordOutcome(callNodeId, outcome(call, mark, 0, 0, 0, 0, "NO_STATE"));
            return 0;
        }
        // catch 可达性守卫（U1/U4，可判定才剪）：sink 位于 CCE handler 且守卫区为"类型安全的 Class.cast"
        // ——cast 目标是实参静态声明类型的（严格）父类时 cast 必成功，handler 不可达
        if (support.catchProvablyUnreachable(method, (Integer) call.prop("offset"))) {
            bb.recordOutcome(callNodeId, outcome(call, mark, 0, 0, 0, 0, "NO_PATH"));
            return 0;
        }
        if (support.sinkPathProvablyUnreachable(method, (Integer) call.prop("offset"), result)) {
            // The normal taint transfer remains deliberately path-insensitive.  This exact
            // local feasibility pass only suppresses a sink when every entry-to-sink path
            // requires a proven-impossible branch/reflective continuation/cast.
            bb.recordOutcome(callNodeId, outcome(call, mark, 0, 0, 0, 0, "NO_PATH"));
            return 0;
        }
        int paramCount = Descriptor.paramCount(call.descriptor());
        int produced = 0;
        Trace trace = new Trace(call.owner(), call.name(), call.descriptor(), stepBudget);
        for (Rule.TaintedPos pos : mark.tainted()) {
            if (abortIfInterrupted(trace)) {
                break;
            }
            int depthFromTop;
            if (pos instanceof Rule.TaintedPos.Arg a) {
                depthFromTop = paramCount - 1 - a.index();
            } else {
                depthFromTop = paramCount;
            }
            if (depthFromTop < 0 || depthFromTop >= state.stack().size()) {
                continue;
            }
            for (ValueOrigin origin : ValueOriginOrder.sorted(
                    state.stack().get(state.stack().size() - 1 - depthFromTop).origins())) {
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
        List<Chain> completedChains = trace.completedChains();
        if (!completedChains.isEmpty()) {
            pendingSinkChains.put(callNodeId, completedChains);
        }
        bb.recordOutcome(callNodeId, outcome(call, mark, produced, trace.steps, trace.unresolved, trace.tooLong, verdict));
        return trace.steps;
    }

    /** Publish worker-local findings in sink-id order so finite downstream phases see one input. */
    private void publishPendingSinkChains() {
        List<Long> callIds = new ArrayList<>(pendingSinkChains.keySet());
        callIds.sort(Long::compareTo);
        for (Long callId : callIds) {
            List<Chain> chains = pendingSinkChains.get(callId);
            if (chains == null) {
                continue;
            }
            for (Chain chain : chains) {
                bb.addChain(chain);
            }
        }
        pendingSinkChains.clear();
    }

    /** Return the forward summary once per method visited by the current sink trace. */
    private ForwardOrigins.Result originsOf(MethodInfo method) {
        if (method == null) {
            return support.origins().compute(null);
        }
        WorkerOriginCache cache = localOriginResults.get();
        ForwardOrigins.Result cached = cache.get(method);
        if (cached != null) {
            return cached;
        }
        ForwardOrigins.Result result = support.origins().compute(method);
        if (result != null && !(result.incomplete()
                && (result.incompleteReasons().contains("INTERRUPTED")
                || result.incompleteReasons().contains("ANALYSIS_FAILURE")))) {
            cache.put(method, result);
        }
        return result;
    }

    /**
     * Fair, deterministic-by-input-order allocation of the global backward budget. A fixed
     * GLOBAL_BUDGET/sink division starves the useful tail when the sink population changes;
     * this allocator gives every sink a bounded minimum share where the global budget permits
     * it, then distributes the remainder. Allocation is a pure function of the sorted sink
     * index, so worker scheduling cannot change the analysis depth or chain set.
     */
    static final class FairBudgetAllocator {
        private final long totalBudget;
        private final int sinkCount;
        private final int maxPerSink;
        private final int minimumPerSink;
        private final long usableBudget;
        private final java.util.concurrent.atomic.AtomicLong consumed =
                new java.util.concurrent.atomic.AtomicLong();

        FairBudgetAllocator(long totalBudget, int maxPerSink, int sinkCount) {
            this.totalBudget = Math.max(0L, totalBudget);
            this.sinkCount = Math.max(0, sinkCount);
            this.maxPerSink = Math.max(1, maxPerSink);
            this.minimumPerSink = Math.min(2_048, this.maxPerSink);
            this.usableBudget = Math.min(this.totalBudget,
                    (long) this.maxPerSink * this.sinkCount);
        }

        int claim(int sinkIndex) {
            if (sinkCount == 0 || sinkIndex < 0 || sinkIndex >= sinkCount) {
                return 0;
            }
            long usable = usableBudget;
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

        void record(int sinkIndex, int allocation, int actualSteps) {
            if (sinkIndex < 0 || sinkIndex >= sinkCount || allocation <= 0) {
                return;
            }
            consumed.addAndGet(Math.min(allocation, Math.max(0, actualSteps)));
        }

        boolean exhausted() {
            return usableBudget > 0 && consumed.get() >= usableBudget;
        }
    }

    /** 返回：该值可控所产出的链数。 */
    private int controlled(ValueOrigin origin, MethodInfo method, int depth, Trace trace, SinkMark mark) {
        if (abortIfInterrupted(trace)) {
            return 0;
        }
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
        DeadKey memoKey = new DeadKey(trace.methodKey(method), origin);
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
        if (produced == 0 && memoizable && !nearBudget && trace.truncated == truncatedBefore
                && localDead.size() < MAX_WORKER_DEAD_ENDS) {
            localDead.add(memoKey);
        }
        return produced;
    }

    /** 参数：magic entry 的 this 可控、proxy 入口 args 可控；否则回溯调用者实参（上下文不敏感）。 */
    private int controlledParam(int slot, MethodInfo method, int depth, Trace trace, SinkMark mark) {
        trace.steps++;
        if (slot == 0 && !method.isStatic() && support.isSerializedProxyHandler(method)) {
            int external = controlledSerializedProxyHandler(method, depth, trace, mark);
            if (external == 0 && !support.serializedProxyInterfaceCallSites().isEmpty()) {
                external = controlledSerializedProxyInterfaceHandler(method, depth, trace, mark);
            }
            if (external > 0) {
                return external;
            }
            if (externalProxyObjectBoundaryAvailable(method)) {
                return completeChain(mark, "proxyInvoke", method, trace,
                        "serialized-proxy-handler-object");
            }
        }
        Rule.MagicEntryRule entry = entryRuleOf(method);
        if (entry != null && slot == 0 && !"proxyInvoke".equals(entry.entryKind())) {
            // 入口对象本身由反序列化构造，可控（对象图语义的根）。
            // InvocationHandler.invoke is intentionally excluded: the proxy callback
            // must be justified by a serialized-proxy callback bridge or ordinary
            // in-artifact Proxy.newProxyInstance flow, never by a global root.
            return completeChain(mark, entry.entryKind(), method, trace, "this-object");
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
        ParamRoutes routes = parameterRoutes(method, slot);
        trace.unresolved += routes.unresolved();
        int produced = 0;
        // 入口距离优先（JDD bottom-up / FLASH 入口导向的探索序）：离反序列化入口近的调用者先走，
        // 链在预算内更快闭合——预算截断下的可复现优先级，替代边序的随机性。参数路由已在
        // worker-local cache 中完成所有与 sink 无关的资格判断；此处只消费不可变来源集合。
        for (ParamRoute route : routes.routes()) {
            if (abortIfInterrupted(trace)) {
                break;
            }
            MethodInfo callerMethod = route.caller();
            Node callerCall = route.call();
            ChainHop hop = new ChainHop(callerMethod.owner(), callerMethod.name(),
                    method.owner(), method.name(), route.hopKind(), null, route.reason(),
                    method.descriptor(), route.argumentOrdinal());
            int unresolvedBefore = trace.unresolved;
            trace.hops.add(hop);
            for (ValueOrigin argOrigin : route.origins()) {
                if (abortIfInterrupted(trace)) {
                    break;
                }
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

    /**
     * Build the sink-independent reverse routes for one target parameter.  The old code did
     * this work on every sink trace, including descriptor mapping, receiver precision, and
     * origin-set sorting.  Keeping the resulting route list immutable preserves the original
     * path semantics while making the hot trace loop proportional to actual controllable
     * origins rather than to repeated call-site qualification.
     */
    private ParamRoutes parameterRoutes(MethodInfo method, int slot) {
        ParamRouteKey key = new ParamRouteKey(method, slot);
        WorkerParamRouteCache cache = localParamRoutes.get();
        ParamRoutes cached = cache.get(key);
        if (cached != null) {
            return cached;
        }
        Node methodNode = bb.graph().findMethodNode(method.owner(), method.name(), method.descriptor());
        if (methodNode == null) {
            ParamRoutes empty = new ParamRoutes(List.of(), 0);
            cache.put(key, empty);
            return empty;
        }
        CallerSites callerSites = callerSitesOf(method, methodNode);
        int callerCap = callerSites.merged() ? MAX_MERGED_CALLERS : MAX_CALLERS;
        List<ParamRoute> routes = new ArrayList<>();
        int unresolved = 0;
        int callers = 0;
        for (CallerSite callerSite : callerSites.sites()) {
            if (callers >= callerCap) {
                break;
            }
            Node callerCall = callerSite.call();
            MethodInfo callerMethod = callerSite.caller();
            if (callerMethod == null) {
                unresolved++;
                continue;
            }
            if (!entryReaching.contains(callerSite.methodKey())) {
                continue;
            }
            ForwardOrigins.Result callerResult = originsOf(callerMethod);
            if (callerResult == null) {
                unresolved++;
                continue;
            }
            if (!method.isStatic() && !support.receiverMayDispatchTo(callerCall, callerMethod,
                    method.owner(), method.name(), method.descriptor(), callerResult)) {
                continue;
            }
            if (support.sinkPathProvablyUnreachable(callerMethod, callerCall.offset(), callerResult)) {
                continue;
            }
            callers++;
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
            boolean directParam = argOrigins.stream().allMatch(o -> o instanceof ValueOrigin.Param);
            Integer argumentOrdinal = directParam
                    ? Descriptor.paramOrdinal(method.descriptor(), method.isStatic(), slot) : null;
            String receiverPrecision = support.receiverPrecision(callerCall, callerMethod,
                    method.owner(), method.name(), method.descriptor(), callerResult);
            String receiverReason = switch (receiverPrecision) {
                case "CONCRETE" -> "receiver-exact";
                case "SEALED_SET" -> "receiver-sealed-set";
                case "POINTS_TO_BOUNDED" -> "receiver-points-to-bounded";
                case "CHA_BOUNDED" -> "receiver-cha-bounded";
                default -> "receiver-unknown";
            };
            String reason = nativeCallback ? "native-callback;" + receiverReason : receiverReason;
            routes.add(new ParamRoute(callerMethod, callerCall,
                    ValueOriginOrder.sorted(argOrigins), argumentOrdinal,
                    nativeCallback ? HopKind.NATIVE_CALLBACK : HopKind.VIRTUAL_DISPATCH, reason));
        }
        ParamRoutes result = new ParamRoutes(List.copyOf(routes), unresolved);
        cache.put(key, result);
        return result;
    }

    /**
     * Reverse a handler receiver through a Method.invoke whose Method value came
     * from a typed collection.  The proxy object is external to the scanned
     * artifact; the explicit invoke receiver is the only concrete object edge
     * available for the callback, so the model keeps that edge and bounds the
     * wildcard by the indexed site list.
     */
    private int controlledSerializedProxyHandler(MethodInfo handler, int depth,
                                                  Trace trace, SinkMark mark) {
        int produced = 0;
        int inspected = 0;
        for (Node invoke : support.methodCollectionInvokeSites()) {
            if (abortIfInterrupted(trace)) {
                break;
            }
            if (inspected++ >= MAX_SERIALIZED_PROXY_CALLBACK_SITES) {
                bb.markIncomplete("BACKWARD_SERIALIZED_PROXY_CALLBACK_SITE_CAP:"
                        + MAX_SERIALIZED_PROXY_CALLBACK_SITES);
                break;
            }
            MethodInfo caller = support.enclosingMethod(invoke);
            if (caller == null || OriginSupport.methodKey(caller).equals(OriginSupport.methodKey(handler))
                    || !entryReaching.contains(OriginSupport.methodKey(caller))) {
                continue;
            }
            ForwardOrigins.Result callerOrigins = originsOf(caller);
            if (support.sinkPathProvablyUnreachable(caller, invoke.offset(), callerOrigins)) {
                continue;
            }
            Set<ValueOrigin> receivers = support.argOriginAtOrdinal(invoke, 0, callerOrigins);
            if (receivers.isEmpty()) {
                continue;
            }
            bb.markIncomplete("BACKWARD_SERIALIZED_PROXY_CALLBACK_WILDCARD");
            ChainHop hop = new ChainHop(caller.owner(), caller.name(), handler.owner(),
                    handler.name(), HopKind.VIRTUAL_DISPATCH, null,
                    "serialized-proxy-handler", handler.descriptor(), null);
            int unresolvedBefore = trace.unresolved;
            trace.hops.add(hop);
            for (ValueOrigin receiver : ValueOriginOrder.sorted(receivers)) {
                if (abortIfInterrupted(trace) || trace.produced >= MAX_CHAINS_PER_SINK) {
                    break;
                }
                if (!(receiver instanceof ValueOrigin.Constant)
                        && !(receiver instanceof ValueOrigin.Unknown)) {
                    produced += controlled(receiver, caller, depth + 1, trace, mark);
                }
            }
            trace.hops.remove(trace.hops.size() - 1);
            trace.unresolved = unresolvedBefore;
            if (trace.produced >= MAX_CHAINS_PER_SINK) {
                break;
            }
        }
        return produced;
    }

    /**
     * Reverse a serialized handler receiver through interface calls whose proxy object is
     * outside the scan unit.  This is a structural JVM contract: only resolved interface
     * call sites and serializable InvocationHandler implementations participate, and the
     * bounded method-name analysis filters mutually exclusive handler branches.
     */
    private int controlledSerializedProxyInterfaceHandler(MethodInfo handler, int depth,
                                                            Trace trace, SinkMark mark) {
        int produced = 0;
        int inspected = 0;
        String handlerKey = OriginSupport.methodKey(handler);
        for (Node call : support.serializedProxyInterfaceCallSites()) {
            if (abortIfInterrupted(trace)) {
                break;
            }
            if (inspected++ >= MAX_SERIALIZED_PROXY_INTERFACE_SITES) {
                bb.markIncomplete("BACKWARD_SERIALIZED_PROXY_INTERFACE_SITE_CAP:"
                        + MAX_SERIALIZED_PROXY_INTERFACE_SITES);
                break;
            }
            if (!proxyInterfaceCallbackMayReach(handler, call.name(), -1)) {
                continue;
            }
            MethodInfo caller = support.enclosingMethod(call);
            if (caller == null) {
                continue;
            }
            String callerKey = OriginSupport.methodKey(caller);
            if (!entryReaching.contains(callerKey) && !handlerKey.equals(callerKey)) {
                continue;
            }
            ForwardOrigins.Result callerOrigins = originsOf(caller);
            if (support.sinkPathProvablyUnreachable(caller, call.offset(), callerOrigins)) {
                continue;
            }
            Set<ValueOrigin> receivers = support.argOriginAtOrdinal(call, -1, callerOrigins);
            if (receivers.isEmpty()) {
                continue;
            }
            bb.markIncomplete("BACKWARD_SERIALIZED_PROXY_INTERFACE_WILDCARD");
            ChainHop hop = new ChainHop(caller.owner(), caller.name(), handler.owner(),
                    handler.name(), HopKind.VIRTUAL_DISPATCH, null,
                    "serialized-proxy-interface", handler.descriptor(), null);
            int unresolvedBefore = trace.unresolved;
            trace.hops.add(hop);
            for (ValueOrigin receiver : ValueOriginOrder.sorted(receivers)) {
                if (abortIfInterrupted(trace) || trace.produced >= MAX_CHAINS_PER_SINK) {
                    break;
                }
                if (!(receiver instanceof ValueOrigin.Constant)
                        && !(receiver instanceof ValueOrigin.Unknown)) {
                    produced += controlled(receiver, caller, depth + 1, trace, mark);
                }
            }
            trace.hops.remove(trace.hops.size() - 1);
            trace.unresolved = unresolvedBefore;
            if (trace.produced >= MAX_CHAINS_PER_SINK) {
                break;
            }
        }
        return produced;
    }

    /**
     * Reverse a handler field only through callbacks whose requested method can reach that
     * exact field read.  Receiver-wide handler bridging is intentionally avoided: an
     * InvocationHandler is a shared runtime contract, while the serialized object fields are
     * the only bytecode-local evidence that ties a callback to a handler state.
     */
    private int controlledSerializedProxyInterfaceFieldReceiver(ValueOrigin.FieldRead field,
                                                                  MethodInfo handler,
                                                                  int depth, Trace trace,
                                                                  SinkMark mark) {
        List<Integer> fieldOffsets = new ArrayList<>();
        for (InsnFact instruction : handler.instructions()) {
            if (!instruction.op().isFieldRead() || instruction.fieldRef() == null
                    || !field.owner().equals(instruction.fieldRef().owner())
                    || !field.field().equals(instruction.fieldRef().name())
                    || (field.descriptor() != null && !field.descriptor().isBlank()
                    && !field.descriptor().equals(instruction.fieldRef().descriptor()))) {
                continue;
            }
            fieldOffsets.add(instruction.offset());
        }
        if (fieldOffsets.isEmpty()) {
            return 0;
        }
        int produced = 0;
        int inspected = 0;
        String handlerKey = OriginSupport.methodKey(handler);
        for (Node call : support.serializedProxyInterfaceCallSites()) {
            if (abortIfInterrupted(trace)) {
                break;
            }
            if (inspected++ >= MAX_SERIALIZED_PROXY_INTERFACE_SITES) {
                bb.markIncomplete("BACKWARD_SERIALIZED_PROXY_INTERFACE_SITE_CAP:"
                        + MAX_SERIALIZED_PROXY_INTERFACE_SITES);
                break;
            }
            boolean allowed = false;
            for (int fieldOffset : fieldOffsets) {
                if (proxyInterfaceCallbackMayReach(handler, call.name(), fieldOffset)) {
                    allowed = true;
                    break;
                }
            }
            if (!allowed) {
                continue;
            }
            MethodInfo caller = support.enclosingMethod(call);
            if (caller == null) {
                continue;
            }
            String callerKey = OriginSupport.methodKey(caller);
            if (!entryReaching.contains(callerKey) && !handlerKey.equals(callerKey)) {
                continue;
            }
            ForwardOrigins.Result callerOrigins = originsOf(caller);
            if (support.sinkPathProvablyUnreachable(caller, call.offset(), callerOrigins)) {
                continue;
            }
            Set<ValueOrigin> receivers = support.argOriginAtOrdinal(call, -1, callerOrigins);
            if (receivers.isEmpty()) {
                continue;
            }
            bb.markIncomplete("BACKWARD_SERIALIZED_PROXY_INTERFACE_WILDCARD");
            ChainHop hop = new ChainHop(caller.owner(), caller.name(), handler.owner(),
                    handler.name(), HopKind.VIRTUAL_DISPATCH, null,
                    "serialized-proxy-interface", handler.descriptor(), null);
            int unresolvedBefore = trace.unresolved;
            trace.hops.add(hop);
            for (ValueOrigin receiver : ValueOriginOrder.sorted(receivers)) {
                if (abortIfInterrupted(trace) || trace.produced >= MAX_CHAINS_PER_SINK) {
                    break;
                }
                if (receiver instanceof ValueOrigin.Constant
                        || receiver instanceof ValueOrigin.Unknown) {
                    continue;
                }
                produced += controlled(receiver, caller, depth + 1, trace, mark);
            }
            trace.hops.remove(trace.hops.size() - 1);
            trace.unresolved = unresolvedBefore;
            if (trace.produced >= MAX_CHAINS_PER_SINK) {
                break;
            }
        }
        return produced;
    }

    /**
     * Map an InvocationHandler Object[] element to the argument at the corresponding
     * external interface call.  The array index is known for the common constant-index form;
     * unknown indexes conservatively consider every argument of the bounded call site.
     */
    private int controlledSerializedProxyInterfaceArgument(MethodInfo handler, int offset,
                                                             ForwardOrigins.State state,
                                                             int depth, Trace trace,
                                                             SinkMark mark) {
        if (!support.isSerializedProxyHandler(handler) || state == null
                || state.stack().isEmpty()) {
            return 0;
        }
        Integer arrayIndex = constantStackIndex(state);
        int produced = 0;
        int inspected = 0;
        String handlerKey = OriginSupport.methodKey(handler);
        for (Node call : support.serializedProxyInterfaceCallSites()) {
            if (abortIfInterrupted(trace)) {
                break;
            }
            if (inspected++ >= MAX_SERIALIZED_PROXY_INTERFACE_SITES) {
                bb.markIncomplete("BACKWARD_SERIALIZED_PROXY_INTERFACE_SITE_CAP:"
                        + MAX_SERIALIZED_PROXY_INTERFACE_SITES);
                break;
            }
            if (!proxyInterfaceCallbackMayReach(handler, call.name(), offset)) {
                continue;
            }
            MethodInfo caller = support.enclosingMethod(call);
            if (caller == null) {
                continue;
            }
            String callerKey = OriginSupport.methodKey(caller);
            if (!entryReaching.contains(callerKey) && !handlerKey.equals(callerKey)) {
                continue;
            }
            ForwardOrigins.Result callerOrigins = originsOf(caller);
            if (support.sinkPathProvablyUnreachable(caller, call.offset(), callerOrigins)) {
                continue;
            }
            int argumentCount = Descriptor.paramCount(call.descriptor());
            int first = arrayIndex == null ? 0 : arrayIndex;
            int last = arrayIndex == null ? argumentCount - 1 : arrayIndex;
            if (first < 0 || first >= argumentCount) {
                continue;
            }
            for (int ordinal = first; ordinal <= last; ordinal++) {
                for (ValueOrigin value : ValueOriginOrder.sorted(
                        support.argOriginAtOrdinal(call, ordinal, callerOrigins))) {
                    if (abortIfInterrupted(trace) || trace.produced >= MAX_CHAINS_PER_SINK) {
                        break;
                    }
                    if (value instanceof ValueOrigin.Constant
                            || value instanceof ValueOrigin.Unknown) {
                        continue;
                    }
                    bb.markIncomplete("BACKWARD_SERIALIZED_PROXY_INTERFACE_WILDCARD");
                    ChainHop hop = new ChainHop(caller.owner(), caller.name(), handler.owner(),
                            handler.name(), HopKind.VIRTUAL_DISPATCH, null,
                            "serialized-proxy-interface", handler.descriptor(), ordinal);
                    int unresolvedBefore = trace.unresolved;
                    trace.hops.add(hop);
                    produced += controlled(value, caller, depth + 1, trace, mark);
                    trace.hops.remove(trace.hops.size() - 1);
                    trace.unresolved = unresolvedBefore;
                }
            }
        }
        return produced;
    }

    private Set<Integer> proxyInterfaceFeasibleOffsets(MethodInfo handler, String methodName) {
        if (handler == null || methodName == null || methodName.isBlank()) {
            return Set.of();
        }
        ProxyInterfaceMetadataKey key = new ProxyInterfaceMetadataKey(
                OriginSupport.methodKey(handler), methodName);
        Set<Integer> cached = proxyInterfaceFeasibleOffsets.get(key);
        if (cached != null) {
            return cached;
        }
        Set<Integer> computed = ForwardEngine.proxyMethodFeasibleOffsets(handler,
                Set.of(methodName), support::cfg);
        Set<Integer> result = computed == null ? Set.of() : Set.copyOf(computed);
        proxyInterfaceFeasibleOffsets.putIfAbsent(key, result);
        if (result.isEmpty()) {
            bb.markIncomplete("BACKWARD_SERIALIZED_PROXY_INTERFACE_METADATA");
        }
        return result;
    }

    private boolean proxyInterfaceCallbackMayReach(MethodInfo handler, String methodName,
                                                     int offset) {
        Set<Integer> feasible = proxyInterfaceFeasibleOffsets(handler, methodName);
        // Empty metadata denotes an analysis boundary, not proof of an impossible callback.
        return feasible.isEmpty() || offset < 0 || feasible.contains(offset);
    }

    private static Integer constantStackIndex(ForwardOrigins.State state) {
        if (state == null || state.stack().isEmpty()) {
            return null;
        }
        Integer answer = null;
        for (ValueOrigin origin : state.stack().get(state.stack().size() - 1).origins()) {
            if (!(origin instanceof ValueOrigin.Constant constant)
                    || !(constant.value() instanceof Number number)) {
                return null;
            }
            int value = number.intValue();
            if (answer != null && answer != value) {
                return null;
            }
            answer = value;
        }
        return answer;
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
            if (abortIfInterrupted(trace)) {
                break;
            }
            if (edge.type() != EdgeType.LAMBDA) {
                continue;
            }
            Node factory = edge.from();
            LambdaMetadata metadata = lambdaMetadata(factory);
            if (metadata == null || !sameMethod(edge.to(), implementation)) {
                continue;
            }
            HandleRef implementationHandle = metadata.implementations().stream()
                    .filter(handle -> handle.owner().equals(edge.to().owner())
                            && handle.name().equals(edge.to().name())
                            && handle.descriptor().equals(edge.to().descriptor()))
                    .findFirst()
                    .orElse(metadata.implementations().size() == 1
                            ? metadata.implementations().get(0) : null);
            if (implementationHandle == null) {
                continue;
            }
            MethodInfo caller = support.enclosingMethod(factory);
            if (caller == null || !entryReaching.contains(OriginSupport.methodKey(caller))) {
                continue;
            }
            ForwardOrigins.Result callerResult = originsOf(caller);
            int capturedCount = Descriptor.paramCount(factory.descriptor());
            boolean receiverCapture = lambdaHasCapturedReceiver(implementationHandle.tag());
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

            for (LambdaSamRoute route : lambdaSamRoutes(factory, caller, callerResult,
                    samDescriptor(factory, caller))) {
                if (abortIfInterrupted(trace)) {
                    break;
                }
                Node samCall = route.samCall();
                MethodInfo samHost = route.samHost();
                if (!entryReaching.contains(OriginSupport.methodKey(samHost))) {
                    continue;
                }
                ForwardOrigins.Result samResult = originsOf(samHost);
                if (support.sinkPathProvablyUnreachable(samHost, samCall.offset(), samResult)) {
                    continue;
                }
                int samCount = Descriptor.paramCount(samCall.descriptor());
                for (int ordinal = 0; ordinal < samCount; ordinal++) {
                    int samSlot = lambdaParameterSlot(implementation, explicitCaptured, ordinal);
                    if (samSlot != slot) {
                        continue;
                    }
                    Set<ValueOrigin> values = support.argOriginAtOrdinal(samCall, ordinal,
                            samResult);
                    if (values.isEmpty()) {
                        continue;
                    }
                    ChainHop hop = new ChainHop(samHost.owner(), samHost.name(), implementation.owner(),
                            implementation.name(), HopKind.VIRTUAL_DISPATCH, null,
                            "lambda-sam", implementation.descriptor(), ordinal);
                    trace.hops.add(hop);
                    int unresolvedBefore = trace.unresolved;
                    for (ValueOrigin value : ValueOriginOrder.sorted(values)) {
                        if (abortIfInterrupted(trace)) {
                            break;
                        }
                        produced += controlled(value, samHost, depth + 1, trace, mark);
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

    /**
     * Discover the bounded consumer path of a lambda factory.  The factory result may be
     * consumed directly in its enclosing method or passed through one or more ordinary Java
     * bridge methods before an {@code invokeinterface} SAM call.  The call graph deliberately
     * does not invent an edge from that interface call back to the factory, so this small
     * carrier search supplies the missing data-flow relation without opening a whole-graph
     * lambda scan.
     */
    private List<LambdaSamRoute> lambdaSamRoutes(Node factory, MethodInfo caller,
                                                   ForwardOrigins.Result callerResult,
                                                   String samDescriptor) {
        if (factory == null || caller == null || callerResult == null || samDescriptor == null) {
            return List.of();
        }
        return lambdaRoutesCache.computeIfAbsent(new LambdaRouteKey(factory.id(), samDescriptor), ignored ->
                discoverLambdaSamRoutes(factory, caller, callerResult, samDescriptor));
    }

    private List<LambdaSamRoute> discoverLambdaSamRoutes(Node factory, MethodInfo caller,
                                                          ForwardOrigins.Result callerResult,
                                                          String samDescriptor) {
        Deque<LambdaCarrier> work = new ArrayDeque<>();
        Set<String> visited = new HashSet<>();
        Set<Long> routeIds = new HashSet<>();
        List<LambdaSamRoute> routes = new ArrayList<>();
        work.addLast(new LambdaCarrier(caller, -1, 0));
        int inspected = 0;
        while (!work.isEmpty()) {
            if (abortForLambdaRouteSearch()) {
                break;
            }
            if (inspected++ >= MAX_LAMBDA_BRIDGE_STATES) {
                bb.markIncomplete("BACKWARD_LAMBDA_BRIDGE_STATE_CAP:" + MAX_LAMBDA_BRIDGE_STATES);
                break;
            }
            LambdaCarrier carrier = work.removeFirst();
            MethodInfo host = carrier.method();
            if (host == null) {
                continue;
            }
            String hostKey = OriginSupport.methodKey(host);
            String stateKey = hostKey + "#" + carrier.slot();
            if (!visited.add(stateKey) || !entryReaching.contains(hostKey)) {
                continue;
            }
            ForwardOrigins.Result result = carrier.slot() < 0
                    ? callerResult : originsOf(host);
            for (Node call : bb.graph().callsOfMethod(hostKey)) {
                if (abortForLambdaRouteSearch()) {
                    return List.copyOf(routes);
                }
                boolean receiverMatches = carrier.slot() < 0
                        ? lambdaReceiverMatches(call, factory, result)
                        : lambdaParameterMatches(call, carrier.slot(), host, result);
                if (receiverMatches && isLambdaSamCall(call, samDescriptor)) {
                    if (routeIds.add(call.id())) {
                        routes.add(new LambdaSamRoute(factory, call, host));
                        if (routes.size() >= MAX_LAMBDA_SAM_ROUTES) {
                            bb.markIncomplete("BACKWARD_LAMBDA_SAM_ROUTE_CAP:" + MAX_LAMBDA_SAM_ROUTES);
                            return List.copyOf(routes);
                        }
                    }
                }
                if (carrier.depth() >= MAX_LAMBDA_BRIDGE_DEPTH) {
                    continue;
                }
                int argumentCount = Descriptor.paramCount(call.descriptor());
                for (int ordinal = 0; ordinal < argumentCount; ordinal++) {
                    Set<ValueOrigin> values = support.argOriginAtOrdinal(call, ordinal, result);
                    boolean argumentMatches = carrier.slot() < 0
                            ? values.stream().anyMatch(value -> sameLambdaOrigin(value,
                            new ValueOrigin.CallResult(factory.id()), result, host,
                            new HashSet<>()))
                            : values.stream().anyMatch(value -> lambdaParameterMatches(value,
                            carrier.slot(), host, result, new HashSet<>()));
                    if (!argumentMatches) {
                        continue;
                    }
                    int targetSlot = targetParameterSlot(call, ordinal);
                    if (targetSlot < 0) {
                        continue;
                    }
                    for (Edge edge : call.out()) {
                        if (edge.type() != EdgeType.INVOKES && edge.type() != EdgeType.DISPATCHES) {
                            continue;
                        }
                        MethodInfo target = support.methodOf(edge.to().owner(), edge.to().name(),
                                edge.to().descriptor());
                        if (target == null) {
                            continue;
                        }
                        work.addLast(new LambdaCarrier(target, targetSlot,
                                carrier.depth() + 1));
                    }
                }
            }
        }
        return routes.isEmpty() ? List.of() : List.copyOf(routes);
    }

    private boolean abortForLambdaRouteSearch() {
        return Thread.currentThread().isInterrupted();
    }

    private static int targetParameterSlot(Node call, int ordinal) {
        if (call == null || ordinal < 0) {
            return -1;
        }
        boolean staticLike = isStaticLike(call.invokeKind());
        List<Integer> slots = Descriptor.argSlots(call.descriptor(), staticLike);
        int index = staticLike ? ordinal : ordinal + 1;
        if (index < 0 || index >= slots.size()) {
            return -1;
        }
        int slot = 0;
        for (int i = 0; i < index; i++) {
            slot += slots.get(i);
        }
        return slot;
    }

    private boolean isLambdaSamCall(Node call, String samDescriptor) {
        if (call == null || !"INTERFACE".equals(call.invokeKind()) || samDescriptor == null) {
            return false;
        }
        // Generic interfaces are invoked with erased descriptors while the implementation
        // handle may retain a more specific adapted type.  Arity and return type are stable
        // enough here; the receiver is already proven to carry this exact lambda object.
        return Descriptor.paramCount(call.descriptor()) == Descriptor.paramCount(samDescriptor)
                && Descriptor.returnType(call.descriptor()).equals(Descriptor.returnType(samDescriptor));
    }

    private boolean lambdaParameterMatches(Node call, int slot, MethodInfo method,
                                            ForwardOrigins.Result result) {
        return support.argOriginAtOrdinal(call, -1, result).stream()
                .anyMatch(value -> lambdaParameterMatches(value, slot, method, result,
                        new HashSet<>()));
    }

    private boolean lambdaParameterMatches(ValueOrigin value, int slot, MethodInfo method,
                                            ForwardOrigins.Result result,
                                            Set<ValueOrigin> visiting) {
        if (value instanceof ValueOrigin.Param parameter) {
            return parameter.slot() == slot;
        }
        if (!(value instanceof ValueOrigin.Insn instruction) || method == null
                || result == null || !visiting.add(value) || instruction.offset() < 0
                || instruction.offset() >= method.instructions().size()
                || method.insnAt(instruction.offset()).op() != Op.CHECKCAST) {
            return false;
        }
        try {
            ForwardOrigins.State before = result.stateBefore().get(instruction.offset());
            if (before == null || before.stack().isEmpty()) {
                return false;
            }
            for (ValueOrigin candidate : ValueOriginOrder.sorted(
                    before.stack().get(before.stack().size() - 1).origins())) {
                if (lambdaParameterMatches(candidate, slot, method, result, visiting)) {
                    return true;
                }
            }
            return false;
        } finally {
            visiting.remove(value);
        }
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
        for (ValueOrigin value : ValueOriginOrder.sorted(values)) {
            if (abortIfInterrupted(trace)) {
                break;
            }
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
                || !("metafactory".equals(indy.bootstrap().name())
                || "altMetafactory".equals(indy.bootstrap().name()))) {
            return null;
        }
        List<HandleRef> implementations = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        for (int i = 1; i < indy.bootstrapArgs().size(); i++) {
            Object argument = indy.bootstrapArgs().get(i);
            if (argument instanceof HandleRef handle
                    && seen.add(handle.tag() + "|" + handle.owner() + "#"
                    + handle.name() + handle.descriptor())) {
                implementations.add(handle);
            }
        }
        return implementations.isEmpty() ? null
                : new LambdaMetadata(List.copyOf(implementations));
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
        for (ValueOrigin receiver : ValueOriginOrder.sorted(
                support.argOriginAtOrdinal(samCall, -1, callerResult))) {
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
            for (ValueOrigin candidate : ValueOriginOrder.sorted(
                    before.stack().get(before.stack().size() - 1).origins())) {
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
            List<CallerSite> prepared = new ArrayList<>(sites.size());
            for (Node site : sites) {
                MethodInfo caller = support.enclosingMethod(site);
                String callerKey = caller == null ? "" : OriginSupport.methodKey(caller);
                int entryDepth = caller == null ? Integer.MAX_VALUE
                        : support.entryDepthOf(callerKey);
                prepared.add(new CallerSite(site, caller, callerKey, entryDepth));
            }
            prepared.sort(java.util.Comparator.comparingInt(CallerSite::entryDepth)
                    .thenComparingLong(site -> site.call().id()));
            return new CallerSites(List.copyOf(prepared), merged);
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
        for (Node site : support.methodCollectionSitesOf(method)) {
            // Opaque iterator/list collections retain the historical JavaBean-only family;
            // concrete Class metadata sites can select any bounded public method relevant to
            // the current sink.  The reverse index keeps this lookup independent of the
            // number of other collection targets in the graph.
            String hostKey = OriginSupport.methodKeyOf(
                    site.methodOwner(), site.methodName(), site.methodDescriptor());
            if (entryReaching.contains(hostKey)
                    && support.reflectiveInvokeMayReach(method, site)) {
                out.add(site);
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
    private List<String> ancestorTypes(String owner) {
        List<String> cached = ancestorTypesCache.get(owner);
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
        List<String> immutable = new ArrayList<>(result);
        immutable.sort(String::compareTo);
        immutable = List.copyOf(immutable);
        ancestorTypesCache.put(owner, immutable);
        return immutable;
    }




    /** 指令产物：数组分配←元素；数组读←数组；其余←消耗的操作数。 */
    private int controlledInsn(int offset, MethodInfo method, int depth, Trace trace, SinkMark mark) {
        trace.steps++;
        ForwardOrigins.Result result = originsOf(method);
        ForwardOrigins.State state = result.stateBefore().get(offset);
        if (state == null) {
            return 0;
        }
        Op op = method.insnAt(offset).op();
        int produced = 0;
        if (op == Op.NEW) {
            produced += controlledAllocatedObject(new ValueOrigin.Insn(offset), method,
                    result, depth, trace, mark);
            if (trace.produced >= MAX_CHAINS_PER_SINK) {
                return produced;
            }
        }
        if (op == Op.AALOAD && support.isSerializedProxyHandler(method)) {
            produced += controlledSerializedProxyInterfaceArgument(method, offset, state,
                    depth, trace, mark);
            if (trace.produced >= MAX_CHAINS_PER_SINK) {
                return produced;
            }
        }
        if (op == Op.NEWARRAY || op == Op.ANEWARRAY || op == Op.MULTIANEWARRAY) {
            for (ValueOrigin element : ValueOriginOrder.sorted(
                    result.arrayElements().getOrDefault(new ValueOrigin.Insn(offset), Set.of()))) {
                if (abortIfInterrupted(trace)) {
                    break;
                }
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
            if (abortIfInterrupted(trace)) {
                break;
            }
            for (ValueOrigin operand : ValueOriginOrder.sorted(state.stack().get(i).origins())) {
                if (abortIfInterrupted(trace)) {
                    break;
                }
                produced += controlled(operand, method, depth + 1, trace, mark);
                if (trace.produced >= MAX_CHAINS_PER_SINK) {
                    return produced;
                }
            }
        }
        return produced;
    }

    /**
     * Recover values carried by a locally allocated object.  This is the reverse counterpart
     * of the forward container model: a {@code new List}; followed by {@code add(value)} or a
     * field write is not itself attacker-controlled, but it can carry an attacker-controlled
     * element into a later modeled read.  Matching the receiver origin exactly keeps this
     * bounded to the allocation under analysis and avoids class-wide container widening.
     */
    private int controlledAllocatedObject(ValueOrigin.Insn allocation, MethodInfo method,
                                          ForwardOrigins.Result result, int depth,
                                          Trace trace, SinkMark mark) {
        int produced = 0;
        int inspected = 0;
        for (Node call : bb.graph().callsOfMethod(OriginSupport.methodKey(method))) {
            if (abortIfInterrupted(trace) || trace.produced >= MAX_CHAINS_PER_SINK) {
                break;
            }
            if (call.offset() <= allocation.offset() || inspected++ >= MAX_CALLEE_RETURN_SITES) {
                continue;
            }
            Rule.ModelRule model = bb.ruleEngine().matchingModel(
                    call.owner(), call.name(), call.descriptor()).orElse(null);
            if (model == null || !model.actions().containsKey("this")
                    || !model.actions().getOrDefault("this", List.of()).stream()
                    .map(ModelSource::parse)
                    .anyMatch(source -> source != null && source.argumentOrdinal() != null)) {
                continue;
            }
            Set<ValueOrigin> receivers = support.argOriginAtOrdinal(call, -1, result);
            if (!receivers.contains(allocation)) {
                continue;
            }
            for (String source : model.actions().getOrDefault("this", List.of())) {
                ModelSource modelSource = ModelSource.parse(source);
                Integer ordinal = modelSource == null ? null : modelSource.argumentOrdinal();
                if (ordinal == null) {
                    continue;
                }
                Set<ValueOrigin> values = support.argOriginAtOrdinal(call, ordinal, result);
                if (modelSource.element() && !values.isEmpty()) {
                    Set<ValueOrigin> elements = new java.util.LinkedHashSet<>();
                    for (ValueOrigin value : ValueOriginOrder.sorted(values)) {
                        elements.addAll(ContainerElementSources.resolve(value, result));
                    }
                    values = elements;
                }
                if (values.isEmpty()) {
                    continue;
                }
                ChainHop hop = new ChainHop(method.owner(), method.name(), call.owner(),
                        call.name(), HopKind.DIRECT_CALL, null,
                        "model:" + model.id(), call.descriptor(), ordinal);
                int unresolvedBefore = trace.unresolved;
                trace.hops.add(hop);
                for (ValueOrigin value : ValueOriginOrder.sorted(values)) {
                    if (abortIfInterrupted(trace) || trace.produced >= MAX_CHAINS_PER_SINK) {
                        break;
                    }
                    produced += controlled(value, method, depth + 1, trace, mark);
                }
                trace.hops.remove(trace.hops.size() - 1);
                trace.unresolved = unresolvedBefore;
            }
        }
        return produced;
    }

    private static boolean isDeserializationSource(Rule.SourceRule source) {
        return source != null && !"serialize".equalsIgnoreCase(source.bridge());
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
        ForwardOrigins.Result result = originsOf(method);
        ForwardOrigins.State state = result.stateBefore().get(call.prop("offset"));
        if (state == null) {
            return 0;
        }
        var source = bb.ruleEngine().matchingSource(call.owner(), call.name(), call.descriptor());
        if (source.isPresent() && isDeserializationSource(source.get())) {
            if (source.get().tainted() == null || source.get().tainted().isEmpty()) {
                return completeChain(mark, source.get().bridge(), method, trace,
                        "bridge-source-deserialize");
            }
            trace.hops.add(new ChainHop(method.owner(), method.name(), call.owner(), call.name(),
                    HopKind.DIRECT_CALL, null, "bridge-source-deserialize", call.descriptor(), null));
            int produced = controlledSourceInput(source.get(), call, method, state, depth, trace, mark);
            trace.hops.remove(trace.hops.size() - 1);
            if (produced > 0) {
                return produced;
            }
        }
        if (isProxyInvocation(call, method, state)) {
            // A proxy result is the selected InvocationHandler return value. Treating any
            // argument as a returned value manufactures a chain when the handler returns a
            // constant for this interface method (the common proxy FP shape).
            return controlledProxyResult(call, method, depth, trace, mark, state);
        }
        int modeled = controlledModelReturn(call, method, result, state, depth, trace, mark);
        if (modeled > 0 || trace.produced >= MAX_CHAINS_PER_SINK) {
            return modeled;
        }
        int produced = 0;
        String kind = call.invokeKind();
        boolean calleeStatic = isStaticLike(kind);
        if (!calleeStatic) {
            // 可控 receiver → 返回值可控（GadgetInspector 对象语义）
            int receiverDepth = state.stack().size() - 1 - Descriptor.paramCount(call.descriptor());
            if (receiverDepth >= 0 && receiverDepth < state.stack().size()) {
                for (ValueOrigin receiverOrigin : ValueOriginOrder.sorted(
                        state.stack().get(receiverDepth).origins())) {
                    if (abortIfInterrupted(trace)) {
                        break;
                    }
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
                if (abortIfInterrupted(trace)) {
                    break;
                }
                for (ValueOrigin argOrigin : ValueOriginOrder.sorted(
                        support.argOriginAt(call, method, slot, result))) {
                    if (abortIfInterrupted(trace)) {
                        break;
                    }
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
        if (produced > 0 || trace.produced >= MAX_CHAINS_PER_SINK) {
            return produced;
        }
        // Body recovery is the expensive compatibility fallback for small application
        // accessors.  Run it only after the cheap receiver/argument summaries fail and never
        // interpret platform bodies, whose opaque implementation details do not add a sound
        // application-side source boundary.
        return controlledCalleeReturns(call, method, depth, trace, mark);
    }

    /** Reverse a declarative return summary before applying the deliberately conservative passthrough. */
    private int controlledModelReturn(Node call, MethodInfo caller, ForwardOrigins.Result result,
                                      ForwardOrigins.State state, int depth, Trace trace,
                                      SinkMark mark) {
        Rule.ModelRule model = bb.ruleEngine().matchingModel(
                call.owner(), call.name(), call.descriptor()).orElse(null);
        if (model == null || model.actions() == null) {
            return 0;
        }
        List<String> sources = model.actions().getOrDefault("return", List.of());
        if (sources.isEmpty()) {
            return 0;
        }
        int produced = 0;
        for (String source : sources) {
            if (abortIfInterrupted(trace) || trace.produced >= MAX_CHAINS_PER_SINK) {
                break;
            }
            Set<ValueOrigin> origins = modelSourceOrigins(source, call, caller, result, state);
            if (origins.isEmpty()) {
                continue;
            }
            ChainHop hop = new ChainHop(caller.owner(), caller.name(), call.owner(), call.name(),
                    HopKind.DIRECT_CALL, null, "model:" + model.id(), call.descriptor(),
                    modelSourceOrdinal(source));
            int unresolvedBefore = trace.unresolved;
            trace.hops.add(hop);
            for (ValueOrigin origin : ValueOriginOrder.sorted(origins)) {
                if (abortIfInterrupted(trace) || trace.produced >= MAX_CHAINS_PER_SINK) {
                    break;
                }
                produced += controlled(origin, caller, depth + 1, trace, mark);
            }
            trace.hops.remove(trace.hops.size() - 1);
            trace.unresolved = unresolvedBefore;
        }
        return produced;
    }

    private Set<ValueOrigin> modelSourceOrigins(String source, Node call, MethodInfo caller,
                                                ForwardOrigins.Result result,
                                                ForwardOrigins.State state) {
        ModelSource modelSource = ModelSource.parse(source);
        if (modelSource == null) {
            return Set.of();
        }
        Set<ValueOrigin> origins;
        if (modelSource.receiver()) {
            origins = isStaticLike(call.invokeKind()) ? Set.of() : receiverOrigins(call, state);
        } else {
            Integer ordinal = modelSource.argumentOrdinal();
            origins = ordinal == null ? Set.of() : support.argOriginAtOrdinal(call, ordinal, result);
        }
        if (!modelSource.element() || origins.isEmpty()) {
            return origins;
        }
        Set<ValueOrigin> elements = new java.util.LinkedHashSet<>();
        for (ValueOrigin origin : ValueOriginOrder.sorted(origins)) {
            elements.addAll(ContainerElementSources.resolve(origin, result));
        }
        return elements;
    }

    private static Integer modelSourceOrdinal(String source) {
        ModelSource parsed = ModelSource.parse(source);
        return parsed == null ? null : parsed.argumentOrdinal();
    }

    /**
     * Analyze a loaded callee's return instructions when no model has closed the value flow.
     * This handles small application/dependency accessors (for example a getter returning a
     * serialized field) without pretending that opaque JDK/native bodies are observable.
     */
    private int controlledCalleeReturns(Node call, MethodInfo caller, int depth,
                                        Trace trace, SinkMark mark) {
        List<Edge> edges = call.out().stream()
                .filter(edge -> edge.type() == EdgeType.INVOKES || edge.type() == EdgeType.DISPATCHES)
                .sorted(java.util.Comparator.comparing((Edge edge) -> OriginSupport.methodKeyOf(
                                edge.to().owner(), edge.to().name(), edge.to().descriptor()))
                        .thenComparing(edge -> edge.type().name()))
                .toList();
        int produced = 0;
        int targets = 0;
        for (Edge edge : edges) {
            if (abortIfInterrupted(trace) || trace.produced >= MAX_CHAINS_PER_SINK
                    || targets++ >= MAX_CALLEE_RETURN_TARGETS) {
                break;
            }
            MethodInfo target = support.methodOf(edge.to().owner(), edge.to().name(),
                    edge.to().descriptor());
            if (target == null || target.instructions().isEmpty()
                    || isPlatformOwner(target.owner())
                    || target.instructions().size() > MAX_CALLEE_RETURN_BODY_INSNS
                    || Modifier.isAbstract(target.access()) || Modifier.isNative(target.access())
                    || "<init>".equals(target.name())) {
                continue;
            }
            ForwardOrigins.Result targetResult = originsOf(target);
            ChainHop hop = new ChainHop(caller.owner(), caller.name(), target.owner(),
                    target.name(), edge.type() == EdgeType.DISPATCHES
                    ? HopKind.VIRTUAL_DISPATCH : HopKind.DIRECT_CALL,
                    null, "return-body", target.descriptor(), null);
            int unresolvedBefore = trace.unresolved;
            trace.hops.add(hop);
            int sites = 0;
            for (InsnFact instruction : target.instructions()) {
                if (abortIfInterrupted(trace) || trace.produced >= MAX_CHAINS_PER_SINK
                        || sites++ >= MAX_CALLEE_RETURN_SITES) {
                    break;
                }
                if (!instruction.op().isReturn() || instruction.op() == Op.RETURN
                        || instruction.op() == Op.ATHROW) {
                    continue;
                }
                ForwardOrigins.State returnState = targetResult.stateBefore()
                        .get(instruction.offset());
                if (returnState == null || returnState.stack().isEmpty()) {
                    continue;
                }
                for (ValueOrigin returned : ValueOriginOrder.sorted(returnState.stack()
                        .get(returnState.stack().size() - 1).origins())) {
                    if (abortIfInterrupted(trace) || trace.produced >= MAX_CHAINS_PER_SINK) {
                        break;
                    }
                    produced += controlled(returned, target, depth + 1, trace, mark);
                }
            }
            trace.hops.remove(trace.hops.size() - 1);
            trace.unresolved = unresolvedBefore;
        }
        return produced;
    }

    /** Apply a source rule's declared input positions without turning the bridge into a root. */
    private int controlledSourceInput(Rule.SourceRule source, Node call, MethodInfo method,
                                      ForwardOrigins.State state, int depth, Trace trace,
                                      SinkMark mark) {
        int parameterCount = Descriptor.paramCount(call.descriptor());
        int produced = 0;
        for (Rule.TaintedPos position : source.tainted()) {
            int fromTop;
            if (position instanceof Rule.TaintedPos.Arg arg) {
                fromTop = parameterCount - 1 - arg.index();
            } else {
                fromTop = parameterCount;
            }
            int stackIndex = state.stack().size() - 1 - fromTop;
            if (stackIndex < 0 || stackIndex >= state.stack().size()) {
                continue;
            }
            for (ValueOrigin origin : ValueOriginOrder.sorted(
                    state.stack().get(stackIndex).origins())) {
                if (abortIfInterrupted(trace)) {
                    return produced;
                }
                produced += controlled(origin, method, depth + 1, trace, mark);
                if (trace.produced >= MAX_CHAINS_PER_SINK) {
                    return produced;
                }
            }
        }
        return produced;
    }

    private int controlledProxyResult(Node call, MethodInfo caller, int depth, Trace trace,
                                      SinkMark mark, ForwardOrigins.State state) {
        int produced = 0;
        for (ValueOrigin receiver : ValueOriginOrder.sorted(receiverOrigins(call, state))) {
            if (abortIfInterrupted(trace)) {
                break;
            }
            Node allocation = proxyAllocationOf(receiver, caller);
            if (allocation == null) {
                continue;
            }
            MethodInfo allocationMethod = support.enclosingMethod(allocation);
            if (allocationMethod == null) {
                continue;
            }
            ForwardOrigins.Result allocationOrigins = originsOf(allocationMethod);
            for (ValueOrigin handlerOrigin : ValueOriginOrder.sorted(
                    support.argOriginAtOrdinal(allocation, 2, allocationOrigins))) {
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
                ForwardOrigins.Result handlerOrigins = originsOf(handler);
                for (int offset : returnOffsets) {
                    if (abortIfInterrupted(trace)) {
                        break;
                    }
                    ForwardOrigins.State returnState = handlerOrigins.stateBefore().get(offset);
                    if (returnState == null || returnState.stack().isEmpty()) {
                        continue;
                    }
                    for (ValueOrigin returned : ValueOriginOrder.sorted(returnState.stack()
                            .get(returnState.stack().size() - 1).origins())) {
                        if (abortIfInterrupted(trace)) {
                            break;
                        }
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
            if (abortIfInterrupted(trace)) {
                break;
            }
            if (!instruction.op().isReturn() || instruction.op() == Op.RETURN
                    || instruction.op() == Op.ATHROW) {
                continue;
            }
            ForwardOrigins.State state = originsOf(handler).stateBefore()
                    .get(instruction.offset());
            if (state == null || state.stack().isEmpty()) {
                continue;
            }
            for (ValueOrigin returned : ValueOriginOrder.sorted(
                    state.stack().get(state.stack().size() - 1).origins())) {
                if (abortIfInterrupted(trace)) {
                    break;
                }
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
            ForwardOrigins.State before = originsOf(method).stateBefore()
                    .get(instruction.offset());
            if (before == null || before.stack().isEmpty()) {
                return null;
            }
            for (ValueOrigin candidate : ValueOriginOrder.sorted(
                    before.stack().get(before.stack().size() - 1).origins())) {
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
                    method.owner(), method.name(), HopKind.FIELD_FLOW, fieldRead.field(), "field-read", "", null,
                    fieldRead.owner());
            int unresolvedBefore = trace.unresolved;
            trace.hops.add(hop);
            if (support.isSerializedProxyHandler(method)
                    && fieldRead.receiver() instanceof ValueOrigin.Param receiver
                    && receiver.slot() == 0) {
                produced += controlledSerializedProxyInterfaceFieldReceiver(fieldRead, method,
                        depth, trace, mark);
            }
            if (produced == 0) {
                produced += controlled(fieldRead.receiver(), method, depth + 1, trace, mark);
            }
            trace.hops.remove(trace.hops.size() - 1);
            trace.unresolved = unresolvedBefore;
            if (produced > 0) {
                return produced;
            }
        }
        int writers = 0;
        String fieldDescriptor = fieldRead.descriptor() == null || fieldRead.descriptor().isBlank()
                ? fieldDescriptor(fieldRead.owner(), fieldRead.field()) : fieldRead.descriptor();
        for (FieldWriterIndex.Writer writer : bb.fieldWriters().writersOf(
                fieldRead.owner(), fieldRead.field(), fieldDescriptor, fieldRead.isStatic())) {
            if (abortIfInterrupted(trace)) {
                break;
            }
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
            ForwardOrigins.State state = originsOf(writerMethod).stateBefore().get(writer.insnOffset());
            if (state == null || state.stack().isEmpty()) {
                continue;
            }
            ChainHop hop = new ChainHop(writerMethod.owner(), writerMethod.name(),
                    method.owner(), method.name(), HopKind.FIELD_FLOW, fieldRead.field(), "field-write", "", null,
                    fieldRead.owner());
            int unresolvedBefore = trace.unresolved;
            trace.hops.add(hop);
            for (ValueOrigin valueOrigin : ValueOriginOrder.sorted(
                    state.stack().get(state.stack().size() - 1).origins())) {
                if (abortIfInterrupted(trace)) {
                    break;
                }
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

    private String fieldDescriptor(String owner, String name) {
        var cls = bb.hierarchy().classInfo(owner);
        if (cls != null) {
            var field = cls.field(name);
            if (field != null) {
                return field.descriptor();
            }
        }
        // The bytecode FieldRef descriptor is not carried by the current FieldRead origin;
        // an unknown descriptor is deliberately kept as a conservative no-match rather than
        // crossing hidden fields. Callers with a class model can still recover the exact type.
        return "";
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
                trace.sinkOwner, trace.sinkMethod, hops, trace.unresolved, trace.sinkDescriptor,
                mark.role().name());
        if (!trace.recordChain(chain)) {
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

    /** Make cancellation cooperative even while a sink is walking a large origin set. */
    private static boolean abortIfInterrupted(Trace trace) {
        if (Thread.currentThread().isInterrupted()) {
            if (trace != null) {
                trace.truncated++;
            }
            return true;
        }
        return false;
    }

    /** 一次回溯的路径与统计。truncated：深度/预算截断发生次数（子树结论作废判定）。 */
    private static final class Trace {
        private static final int MAX_VARIANTS_PER_SEMANTIC_CHAIN = 4;
        final String sinkOwner;
        final String sinkMethod;
        final String sinkDescriptor;
        final int stepBudget;
        final List<ChainHop> hops = new ArrayList<>();
        final Set<DeadKey> visited = new HashSet<>();
        /** Semantic identity is local to a sink before publication; values are stable snapshots. */
        final Map<String, List<Chain>> completed = new TreeMap<>();
        /**
         * A trace revisits the same canonical MethodInfo while following fields and
         * passthrough arguments.  Cache its stable key locally so the hot recursion does not
         * repeatedly allocate and hash the same owner/name/descriptor string.
         */
        final IdentityHashMap<MethodInfo, String> methodKeys = new IdentityHashMap<>(64);
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

        String methodKey(MethodInfo method) {
            String cached = methodKeys.get(method);
            if (cached != null) {
                return cached;
            }
            String key = OriginSupport.methodKey(method);
            methodKeys.put(method, key);
            return key;
        }

        boolean recordChain(Chain chain) {
            String semantic = io.just.sast.blackboard.ChainMerge.semanticKey(chain);
            List<Chain> variants = completed.computeIfAbsent(semantic,
                    ignored -> new ArrayList<>(1));
            for (Chain existing : variants) {
                if (existing.key().equals(chain.key())) {
                    return false;
                }
            }
            if (variants.isEmpty()) {
                variants.add(chain);
                return true;
            }
            if (variants.size() < MAX_VARIANTS_PER_SEMANTIC_CHAIN) {
                variants.add(chain);
            } else {
                // Keep a bounded, deterministic evidence sample. The preferred variant is
                // always retained; alternate hop reasons are secondary annotations.
                int worst = 0;
                for (int index = 1; index < variants.size(); index++) {
                    Chain currentWorst = variants.get(worst);
                    Chain candidate = variants.get(index);
                    if (io.just.sast.blackboard.ChainMerge.preferred(currentWorst, candidate)
                            == currentWorst) {
                        worst = index;
                    }
                }
                Chain currentWorst = variants.get(worst);
                if (io.just.sast.blackboard.ChainMerge.preferred(currentWorst, chain) == chain) {
                    variants.set(worst, chain);
                }
            }
            variants.sort(java.util.Comparator.comparing(Chain::key));
            return false;
        }

        List<Chain> completedChains() {
            List<Chain> result = new ArrayList<>();
            for (List<Chain> variants : completed.values()) {
                result.addAll(variants);
            }
            result.sort(java.util.Comparator.comparing(Chain::key));
            return List.copyOf(result);
        }
    }
}
