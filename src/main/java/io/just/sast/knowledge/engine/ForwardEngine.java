package io.just.sast.knowledge.engine;

import io.just.sast.analysis.taint.ForwardOrigins;
import io.just.sast.analysis.taint.ContainerElementSources;
import io.just.sast.analysis.taint.OriginSupport;
import io.just.sast.analysis.taint.ValueOrigin;
import io.just.sast.analysis.taint.ValueOriginOrder;
import io.just.sast.blackboard.Blackboard;
import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.HopKind;
import io.just.sast.config.Rule;
import io.just.sast.config.ModelSource;
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
import io.just.sast.util.JustLogger;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IdentityHashMap;
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
 *   为常量时，向同名方法 addParam/addThis；MethodHandle lookup 的目标由 Class、名称、
 *   调用描述符约束后，按直接参数向目标方法投影
 *
 * model 规则（YAML 声明式摘要）在两轮中都消费：actions 的 this←argN 为容器投毒（Map.put 语义）、
 * return←src 为透传（Map.get 语义）。
 */
public final class ForwardEngine {

    private static final int MAX_DEPTH = 20;
    private static final int MAX_ROUNDS = 32;
    /**
     * A real nested-deserialization path commonly crosses an object callback, a proxy
     * handler, a container read, one or more conversion dispatches, and the secondary sink.
     * Ten hops truncated that generic shape before the sink.  Keep the bound finite and
     * aligned with MAX_DEPTH while leaving the completeness marker active when it is hit.
     */
    private static final int MAX_HOPS = 20;
    /**
     * Keep a small deterministic frontier for facts that have more than one source
     * provenance.  The shortest path remains the hot-path summary, while the bounded
     * frontier prevents an unrelated lifecycle root from hiding a longer, but valid,
     * deserialization path at a sink.
     */
    private static final int MAX_PATH_ALTERNATIVES = 8;
    /** External Method-collection callbacks are a bounded semantic wildcard. */
    private static final int MAX_SERIALIZED_PROXY_CALLBACK_SITES = 256;
    /** External interface callbacks share the same finite dispatch boundary. */
    private static final int MAX_SERIALIZED_PROXY_INTERFACE_SITES = 256;
    /**
     * Keep the callback metadata bounded by the already bounded Method collection.  The
     * names are not benchmark knowledge: they are the names recovered from the typed
     * collection candidates and are used only to resolve method-name predicates in an
     * InvocationHandler body.
     */
    private static final int MAX_SERIALIZED_PROXY_CALLBACK_NAMES = 512;
    private static final Set<String> JAVA_SERIALIZATION_ENTRY_KINDS = Set.of(
            "readObject", "readObjectNoData", "readResolve", "readExternal", "validateObject");
    /**
     * These callbacks are activated by a deserialized container/object graph, not by the
     * serialization runtime as an independent source.  Keeping them out of the forward root
     * set prevents every Serializable class from manufacturing a shorter path that hides the
     * actual container/read boundary; composition and calibration still retain the callback
     * entry kinds for trigger reasoning.
     */
    private static final Set<String> SERIALIZED_TRIGGER_ENTRY_KINDS = Set.of(
            "hashCode", "equals", "compareTo", "compare", "toString");
    /** 默认判定步数预算（有界恢复：预算耗尽停止扩散，保留已有事实与 sink 判定）。 */
    private static final int DEFAULT_STEP_BUDGET = 20_000_000;
    /** 默认方法效果处理上限。 */
    private static final int DEFAULT_METHOD_PASS_CAP = 1_000_000;
    /** 死胡同缓存清理阈值（条目数超过即清除过期版本）。 */
    private static final int DEAD_END_SWEEP = 65_536;
    /** Avoid walking the full dead-end map for every fact-version insertion. */
    private static final int DEAD_END_SWEEP_BURST = 4_096;
    /**
     * 事实：键 → 前向路径（首元素为 ENTRY hop）。引擎由一个 ANALYSIS 知识源独占，
     * 因而这里使用普通容器；并行化的知识源之间不会共享此实例。把单所有者状态写成
     * ConcurrentHashMap 会让每一次事实读取和合并都支付不必要的并发协议成本。
     */
    private final Map<String, List<ChainHop>> thisTainted = new HashMap<>();
    private final Map<String, List<ChainHop>> fieldTainted = new HashMap<>();
    /** Compatibility lookup only for old extension-created FieldRead values without a descriptor. */
    private final Map<String, List<ChainHop>> fieldTaintedByName = new HashMap<>();
    private final Map<String, List<ChainHop>> returnTainted = new HashMap<>();
    private final Map<String, List<ChainHop>> paramTainted = new HashMap<>();
    /**
     * Bounded alternatives for the same facts.  These maps are deliberately separate from
     * the primary summaries so existing propagation remains allocation-light; sink checks and
     * effect propagation can opt into the full, auditable frontier.
     */
    private final Map<String, List<List<ChainHop>>> thisTaintedAlternatives = new HashMap<>();
    private final Map<String, List<List<ChainHop>>> fieldTaintedAlternatives = new HashMap<>();
    private final Map<String, List<List<ChainHop>>> fieldTaintedByNameAlternatives = new HashMap<>();
    private final Map<String, List<List<ChainHop>>> returnTaintedAlternatives = new HashMap<>();
    private final Map<String, List<List<ChainHop>>> paramTaintedAlternatives = new HashMap<>();
    private boolean pathAlternativeCapReported;
    /** 方法 + 来源的结构化键，避免热路径为每次递归分配 origin.toString()。 */
    private record TaintKey(String methodKey, ValueOrigin origin) {}
    /** 探索级 frontier 键；深度保留在键中，避免把受深度上限影响的部分结果复用到别的上下文。 */
    private record CandidateKey(String methodKey, ValueOrigin origin, int depth) {}
    /** 只在事实版本未变化且本次探索未截断时复用的有限候选集合。 */
    private record CandidateMemo(long factVersion, List<List<ChainHop>> paths) {}
    /**
     * Top-level candidate frontiers are safe to share between independent Explore contexts
     * only after the recursion/ truncation guards have completed.  Bound this cache because
     * fact versions are monotone and stale entries are intentionally lazy-invalidated.
     */
    private static final int MAX_CANDIDATE_MEMO_ENTRIES = 65_536;
    /** Batch eviction keeps the bounded memo from turning into an O(n) hot-path operation. */
    private static final int MAX_CANDIDATE_MEMO_BURST = 4_096;
    private final Map<CandidateKey, CandidateMemo> candidateMemoCache = new HashMap<>();

    /** Result of the bounded symbolic Method-name interpreter used by proxy callbacks. */
    private record ProxyMetadata(Set<Integer> feasibleOffsets, Set<Integer> returnOffsets,
                                 boolean complete) {}

    /** Per-handler callback branch metadata; computed lazily after OriginSupport indexing. */
    private record SerializedProxyCallbackMetadata(Set<Integer> feasibleOffsets,
                                                   boolean complete) {}
    private record SerializedProxyInterfaceMetadataKey(String handlerKey, String methodName) {}

    /** 死胡同缓存：值为记录时的主事实版本（替代 frontier 不会令其失效）。 */
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
    /** Sink 调用点按宿主方法分桶，允许事实更新后增量重查而不再扫描整个 CPG。 */
    private final Map<String, List<Node>> sinkCallsByMethod = new HashMap<>();
    /** 同一 sink 在同一事实版本只检查一次；新事实到达后由受影响方法再次触发。 */
    private final Map<Long, Long> sinkCheckVersions = new HashMap<>();
    /** Methods that contain an unconditional deserialization source or OIS read. */
    private final Set<String> sourceHostMethods = new HashSet<>();
    /** Methods whose receiver/parameter/field facts can activate forward propagation. */
    private final Set<String> activeMethods = new HashSet<>();
    /** Sink-relevant lambda factory callers → ordinary bridge targets needed by forward demand. */
    private final Map<String, Set<String>> lambdaDemandTargetsByCaller = new HashMap<>();
    private boolean lambdaDemandIndexed;
    /** Number of late callback implementations admitted to the forward demand workset. */
    private int dynamicCallbackDemandAdds;

    /** 反序列化可达方法集（前向 BFS 边界：只在该子集内传播；两轮共用，首轮构建）。 */
    private final Set<String> reachable = new HashSet<>();
    /**
     * Sink-demanded forward workset.  {@link #reachable} is intentionally conservative and
     * includes the semantic callback closure used by the backward engine; scheduling every
     * member of that closure would make a large dependency jar pay for facts that cannot fit
     * inside the bounded chain.  This second index is a sound scheduler gate: it starts at
     * sink-near methods and closes over ordinary callers plus field writers, while preserving
     * real deserialization and external-callback roots.  It is never used to erase the
     * reachable set or to change backward findings.
    */
    /**
     * Sink-relevant scheduler workset.  It is seeded once from the static graph, then may
     * grow when a bounded semantic edge (reflection/proxy/native) resolves a target that was
     * not reachable through an ordinary call edge.  Keeping this separate from {@link
     * #reachable} preserves the cheap demand filter while avoiding a false negative at a
     * semantically discovered target.
     */
    private Set<String> forwardDemand;
    private static final int REACHABLE_CAP = 200_000;
    private static final int INTERFACE_EXPAND_CAP = 2000;
    /** Keep runtime callback expansion finite on interface-heavy dependency closures. */
    private static final int DYNAMIC_CALLBACK_DEMAND_CAP = 2000;
    private static final int RAW_DISPATCH_CAP = 10_000;
    private static final int REFLECTIVE_REACHABLE_CAP = 2000;
    /** lambda 绑定：方法#实参槽 → 该参数将持有的 lambda 实现方法（含接口实参→实现参数的槽位偏移）。 */
    private final Map<String, List<LambdaBind>> lambdaBinds = new HashMap<>();
    /** lambda 实现绑定（实现方法的定位三元组；槽位偏移在消费时按实际接口调用点计算）。 */
    private record LambdaBind(String implOwner, String implName, String implDesc) {}
    /** LambdaMetafactory 的一个实现句柄与 SAM 描述符；仅用于通用 invokedynamic 数据流映射。 */
    private record LambdaShape(HandleRef implementation, String samDescriptor) {}
    /** 虚分派候选键；同一签名在粗/精扫和多个调用点之间共享解析结果。 */
    private record DispatchKey(String owner, String name, String desc) {}
    /** Contextual finite dispatch selection; receiver type/provenance changes the ordering. */
    private record DispatchSelectionKey(String declaredOwner, String universeOwner,
                                        String name, String desc, boolean serializedValue) {}
    /** 已通过可序列化与 JVM 可覆写门的候选，保留原候选 owner 以支持精确类型分派。 */
    private record DispatchTarget(String candidateOwner, String resolvedOwner) {}
    /** 层次版本对应的完整子类型闭包；精确 receiver 路径只需消费 raw。 */
    private record DispatchCandidates(long revision, List<String> raw, boolean truncated) {}
    /** 层次版本对应的已过滤分派目标；按需构造，避免精确类型路径先扫描全闭包。 */
    private record ResolvedDispatchCandidates(long revision, List<DispatchTarget> targets,
                                              boolean truncated) {}
    private final Map<DispatchKey, DispatchCandidates> dispatchCache = new HashMap<>();
    private final Map<DispatchKey, ResolvedDispatchCandidates> resolvedDispatchCache = new HashMap<>();
    private final Map<DispatchSelectionKey, ResolvedDispatchCandidates> contextualDispatchCache = new HashMap<>();
    /** Unknown Method.invoke targets are resolved against the already indexed sink calls;
     * the result is cached by name/parameter shape so reflective-heavy jars do not rescan
     * the complete call graph for every metadata object. */
    private final Map<String, List<MethodInfo>> reflectiveSinkCache = new HashMap<>();
    /**
     * A forward pass revisits the same call node from the primary summary, the bounded
     * frontier, and the sink/effect consumers.  RuleEngine's shared cache still has to build
     * a string key and enter a concurrent map for each visit.  The graph is frozen while this
     * engine runs, so a per-engine identity cache removes that repeated bookkeeping while the
     * hierarchy revision guard preserves lazy-class-loading correctness.
     */
    private record CallRules(long hierarchyRevision, Rule.SinkRule sink,
                             Rule.SourceRule source, Rule.ModelRule model) {}
    private final IdentityHashMap<Node, CallRules> callRulesCache = new IdentityHashMap<>();
    private final Map<String, SerializedProxyCallbackMetadata> serializedProxyCallbackMetadata =
            new HashMap<>();
    /** Per-handler/method-name branch metadata for externally assembled proxy callbacks. */
    private final Map<SerializedProxyInterfaceMetadataKey, Set<Integer>>
            serializedProxyInterfaceFeasibleOffsets = new HashMap<>();
    /**
     * Bounded identity cache for repeated forward worklist visits to the same method summary.
     *
     * <p>The shared {@link ForwardOrigins} cache is intentionally small because it is also
     * used by concurrent backward/metadata consumers.  This engine, however, is the single
     * owner of a scan-local fixed point: keeping the larger scan-local working set here avoids
     * evicting and re-interpreting short summaries merely because a fat jar has more than one
     * cache window of reachable methods.  The cap remains finite so a long-lived controller
     * cannot retain an unbounded artifact.</p>
     */
    private static final int MAX_ENGINE_ORIGIN_CACHE_ENTRIES = 32_768;
    private final IdentityHashMap<MethodInfo, ForwardOrigins.Result> originResultCache =
            new IdentityHashMap<>();
    private final Deque<MethodInfo> originResultOrder = new ArrayDeque<>();
    private long originRequests;
    private long originCacheHits;
    private final Blackboard bb;
    private final OriginSupport support;
    /**
     * Stable per-method view shared by both coarse/refined rounds. ForwardOrigins already owns
     * the canonical cache; this second index avoids rebuilding CfgKey strings at every callsite
     * and lets the hot engine use a small per-exploration map below.
     */
    private Options options;
    /** 总事实版本：主摘要和替代 frontier 的任一变化都会递增，用于 sink 检查失效。 */
    private long factVersion;
    /** 主摘要版本：仅 primary summary 变化时递增，用于廉价 primary memo 失效。 */
    private long primaryFactVersion;
    /** 候选版本：primary 或 alternative frontier 变化时递增，用于 frontier memo 失效。 */
    private long candidateFactVersion;
    /** 本轮统计/预算（每轮重置；引擎单所有者，使用普通计数器）。 */
    private long factCount;
    private long steps;
    private long methodPasses;
    private long primaryFactUpdates;
    private long alternativeFactUpdates;
    private final Deque<String> queue = new ArrayDeque<>();
    /** 队列去重伴随集：queue 中现存的方法键（事实驱动的大语料入队有 5-6 倍重复；
     *  poll 时移除——处理期间的新入队会进下一轮）。 */
    private final Set<String> pending = new HashSet<>();
    /**
     * Controller 的阶段超时通过 Future.cancel(true) 传入。ForwardOrigins 自身能够
     * 响应中断，但正向引擎还包含可达闭包、分派、反射和事实队列循环；这些循环也
     * 必须及时停止，否则超时后仍会占用 CPU 并与后续阶段重叠。
     */
    private boolean cancellationRecorded;
    /** 取消发生时保留已计算事实对应的 bounded sink 证据，避免超时直接丢弃已有链。 */
    private boolean cancellationSalvaged;
    private static final int CANCELLATION_SINK_SALVAGE_CAP = 8192;
    /**
     * Forward analysis is an optional precision refinement on top of the independent
     * backward engine. A dependency-heavy fat jar can contain a very large reachable
     * closure; using the small-jar budget there made the refinement monopolize the
     * controller deadline and prevented calibration/verification from running at all.
     * The budget is selected from graph size, never from an artifact/class name, and every
     * early stop is reported as an explicit completeness reason.
     */
    private int stepBudget = DEFAULT_STEP_BUDGET;
    private int methodPassCap = DEFAULT_METHOD_PASS_CAP;
    private static final int TOPOLOGY_BUILD_CAP = 120_000;
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
        final Set<Long> candidateCallResults = new HashSet<>();
        final Set<TaintKey> candidateInstructions = new HashSet<>();
        final Map<CandidateKey, CandidateMemo> candidateMemo = new HashMap<>(16);
        final IdentityHashMap<MethodInfo, ForwardOrigins.Result> origins = new IdentityHashMap<>(4);
        final IdentityHashMap<MethodInfo, String> methodKeys = new IdentityHashMap<>(16);
        boolean truncated;
    }


    public ForwardEngine(Blackboard bb) {
        this.bb = bb;
        this.support = bb.originSupport();
        buildIndexes();
    }

    /** 保留中断标记，避免把取消误报为“无链”；同一引擎只记录一次原因。 */
    private boolean cancellationRequested() {
        if (!Thread.currentThread().isInterrupted()) {
            return false;
        }
        if (!cancellationRecorded) {
            cancellationRecorded = true;
            bb.markIncomplete("FORWARD_INTERRUPTED");
        }
        if (!cancellationSalvaged) {
            cancellationSalvaged = true;
            salvageSinksOnCancellation();
        }
        return true;
    }

    /**
     * Future.cancel(true) may arrive after useful forward facts were already computed.
     * The normal sink pass is intentionally after the fixed point, so returning immediately
     * on interruption used to discard every sink observation from that partial state.  Clear
     * the interrupt only for this bounded, non-executing evidence pass, then restore it before
     * returning to the controller.  This never invokes a target sink body.
     */
    private void salvageSinksOnCancellation() {
        boolean interrupted = Thread.interrupted();
        int inspected = 0;
        try {
            List<String> methods = new ArrayList<>(sinkCallsByMethod.keySet());
            methods.sort(String::compareTo);
            for (String methodKey : methods) {
                List<Node> calls = sinkCallsByMethod.getOrDefault(methodKey, List.of());
                for (Node call : calls) {
                    if (inspected++ >= CANCELLATION_SINK_SALVAGE_CAP) {
                        bb.markIncomplete("FORWARD_CANCELLATION_SINK_SALVAGE_CAP:"
                                + CANCELLATION_SINK_SALVAGE_CAP);
                        return;
                    }
                    Rule.SinkRule rule = callRules(call).sink();
                    if (rule != null) {
                        checkSink(call, rule);
                    }
                }
            }
        } finally {
            if (interrupted || Thread.currentThread().isInterrupted()) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private ForwardOrigins.Result origins(MethodInfo method, Explore exploration) {
        originRequests++;
        if (exploration != null) {
            ForwardOrigins.Result local = exploration.origins.get(method);
            if (local != null) {
                originCacheHits++;
                return local;
            }
            ForwardOrigins.Result result = originResultCache.get(method);
            if (result != null) {
                originCacheHits++;
            } else {
                result = support.origins().compute(method);
                rememberOriginResult(method, result);
            }
            if (result.incomplete()) {
                result.incompleteReasons().forEach(reason ->
                        bb.markIncomplete("FORWARD_ORIGINS:" + reason));
            }
            exploration.origins.put(method, result);
            return result;
        }
        ForwardOrigins.Result result = originResultCache.get(method);
        if (result != null) {
            originCacheHits++;
        } else {
            result = support.origins().compute(method);
            rememberOriginResult(method, result);
        }
        if (result.incomplete()) {
            result.incompleteReasons().forEach(reason ->
                    bb.markIncomplete("FORWARD_ORIGINS:" + reason));
        }
        return result;
    }

    private void rememberOriginResult(MethodInfo method, ForwardOrigins.Result result) {
        if (method == null || result == null || originResultCache.containsKey(method)) {
            return;
        }
        while (originResultCache.size() >= MAX_ENGINE_ORIGIN_CACHE_ENTRIES
                && !originResultOrder.isEmpty()) {
            MethodInfo evicted = originResultOrder.removeFirst();
            originResultCache.remove(evicted);
        }
        originResultCache.put(method, result);
        originResultOrder.addLast(method);
    }

    /** Reuse the canonical method key across one bounded value exploration. */
    private static String methodKey(MethodInfo method, Explore exploration) {
        if (method == null) {
            return "";
        }
        if (exploration == null) {
            return OriginSupport.methodKey(method);
        }
        String cached = exploration.methodKeys.get(method);
        if (cached != null) {
            return cached;
        }
        String key = OriginSupport.methodKey(method);
        exploration.methodKeys.put(method, key);
        return key;
    }

    private CallRules callRules(Node call) {
        if (call == null) {
            return new CallRules(bb.hierarchy().revision(), null, null, null);
        }
        long revision = bb.hierarchy().revision();
        CallRules cached = callRulesCache.get(call);
        if (cached != null && cached.hierarchyRevision() == revision) {
            return cached;
        }
        var ruleEngine = bb.ruleEngine();
        CallRules resolved = new CallRules(revision,
                ruleEngine.matchingSink(call.owner(), call.name(), call.descriptor()).orElse(null),
                ruleEngine.matchingSource(call.owner(), call.name(), call.descriptor()).orElse(null),
                ruleEngine.matchingModel(call.owner(), call.name(), call.descriptor()).orElse(null));
        callRulesCache.put(call, resolved);
        return resolved;
    }

    private ForwardOrigins.State stateAt(MethodInfo method, int offset, Explore exploration) {
        return origins(method, exploration).stateBefore().get(offset);
    }

    private void buildIndexes() {
        indexSinkCalls();
        if (cancellationRequested()) {
            return;
        }
        for (Node method : bb.graph().nodesOfType(NodeType.METHOD)) {
            if (cancellationRequested()) {
                return;
            }
            MethodInfo info = support.methodOf(method.owner(), method.name(), method.descriptor());
            if (info == null) {
                continue;
            }
            String key = OriginSupport.methodKey(info);
            List<InsnFact> effects = new ArrayList<>();
            CpgIndex.MethodSlice slice = support.cpgIndex().slice(key);
            if (slice != null) {
                slice.forEachFieldReadOffset(offset -> {
                    if (cancellationRequested()) {
                        return;
                    }
                    InsnFact insn = info.insnAt(offset);
                    fieldReaders.computeIfAbsent(fieldKey(insn.fieldRef(), insn.op()),
                            k -> new HashSet<>()).add(key);
                });
                slice.forEachEffectOffset(offset -> {
                    if (cancellationRequested()) {
                        return;
                    }
                    effects.add(info.insnAt(offset));
                });
            } else {
                // Direct Blackboard construction remains supported for extensions/tests
                // that do not have a frontend-produced CpgIndex.
                for (InsnFact insn : info.instructions()) {
                    if (insn.op().isFieldRead()) {
                        fieldReaders.computeIfAbsent(fieldKey(insn.fieldRef(), insn.op()),
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
                if (cancellationRequested()) {
                    return;
                }
                if (edge.type() == EdgeType.INVOKES || edge.type() == EdgeType.DISPATCHES) {
                    callers.computeIfAbsent(key, k -> new ArrayList<>()).add(edge.from());
                }
            }
        }
        // 接口反向分发：接口方法节点的调用点并入实现类方法（同反向引擎语义）
        for (Node method : bb.graph().nodesOfType(NodeType.METHOD)) {
            if (cancellationRequested()) {
                return;
            }
            String owner = method.owner();
            MethodInfo info = support.methodOf(owner, method.name(), method.descriptor());
            if (info == null || !method.in().isEmpty()) {
                continue;
            }
            for (String itf : bb.hierarchy().transitiveInterfaces(owner)) {
                if (cancellationRequested()) {
                    return;
                }
                Node itfNode = bb.graph().findMethodNode(itf, info.name(), info.descriptor());
                if (itfNode != null) {
                    for (Edge edge : itfNode.in()) {
                        if (cancellationRequested()) {
                            return;
                        }
                        if (edge.type() == EdgeType.INVOKES || edge.type() == EdgeType.DISPATCHES) {
                            callers.computeIfAbsent(OriginSupport.methodKey(info), k -> new ArrayList<>()).add(edge.from());
                        }
                    }
                }
            }
        }
    }

    /** Build the sink work index once; the final pass and partial-state salvage share it. */
    private void indexSinkCalls() {
        for (Node call : bb.graph().nodesOfType(NodeType.CALL)) {
            if (cancellationRequested()) {
                return;
            }
            if (call.methodOwner() == null || call.methodName() == null
                    || call.methodDescriptor() == null) {
                continue;
            }
            String methodKey = OriginSupport.methodKey(call);
            CallRules rules = callRules(call);
            Rule.SourceRule source = rules.source();
            if (OriginSupport.isOisRead(call)
                    || isUnconditionalDeserializeSource(source)) {
                sourceHostMethods.add(methodKey);
            }
            if (rules.sink() != null) {
                sinkCallsByMethod.computeIfAbsent(methodKey, ignored -> new ArrayList<>()).add(call);
            }
        }
        for (List<Node> calls : sinkCallsByMethod.values()) {
            calls.sort(Comparator.comparingInt(Node::offset).thenComparingLong(Node::id));
        }
    }

    public void run(Options options) {
        this.options = options;
        long startedAt = System.nanoTime();
        if (cancellationRequested()) {
            return;
        }
        if (options.reachablePrune() && reachable.isEmpty()) {
            if (!computeReachable()) {
                return;
            }
        }
        if (options.reachablePrune() && forwardDemand == null) {
            buildForwardDemand();
        }
        configureBudgets();
        boolean firstRun = factVersion == 0;
        // 预算按轮重置（每轮独立预算）。非首轮只重入队"受影响方法"：
        // 已污点类的方法 + 已有参数/返回事实的方法 + 已污点字段的读者——
        // 与独立精扫引擎的种子+事实驱动增长等价，规模受控（全量可达集重处理会烧尽预算）；
        // 新事实派生的受影响方法由 addThis/addField/addReturn/addParam 的入队机制自动扩散。
        steps = 0;
        methodPasses = 0;
        factCount = 0;
        primaryFactUpdates = 0;
        alternativeFactUpdates = 0;
        taintMemo.clear();
        candidateMemoCache.clear();
        deadEnds.clear();
        sinkCheckVersions.clear();
        cancellationSalvaged = false;
        if (!firstRun) {
            requeueAffected();
            if (cancellationRequested()) {
                queue.clear();
                pending.clear();
                return;
            }
        }
        seedEntries();
        if (cancellationRequested() || !ensureTopoOrder()) {
            queue.clear();
            pending.clear();
            return;
        }
        int rounds = 0;
        while (!queue.isEmpty() && rounds < MAX_ROUNDS && steps < stepBudget
                && methodPasses < methodPassCap) {
            if (cancellationRequested()) {
                queue.clear();
                pending.clear();
                return;
            }
            rounds++;
            List<String> current = new ArrayList<>();
            for (String key; (key = queue.pollFirst()) != null; ) {
                if (cancellationRequested()) {
                    queue.clear();
                    pending.clear();
                    return;
                }
                pending.remove(key);
                current.add(key);
            }
            // 后序处理（被调者先）：事实合流依赖这个确定顺序；副作用传播保持串行，
            // 避免全局步数预算在并行调度下改变覆盖范围。origin 仍按需计算，只有真实
            // 消费到某个方法时才支付 CFG/抽象解释成本。
            if (topoOrder != null) {
                if (!topoOrder.isEmpty()) {
                    current.sort(java.util.Comparator
                            .comparingInt((String k) -> topoOrder.getOrDefault(k, Integer.MAX_VALUE))
                            .thenComparing(String::compareTo));
                } else {
                    // Large closures deliberately skip the O(V+E) topology materialization.
                    // A lexical queue is deterministic but has no relation to data-flow
                    // direction, so dependency-library methods can consume the finite budget
                    // before an entry's sink-near path is revisited.  Entry depth keeps source
                    // propagation moving outward; within one layer, a finite sink distance is
                    // preferred and larger distances run first so values flow toward the sink.
                    // This is scheduling only: every fact remains bounded and every generated
                    // update still re-enqueues its consumer.
                    current.sort(java.util.Comparator
                            .comparingInt(this::entryDepthForScheduling)
                            .thenComparing(java.util.Comparator
                                    .comparingInt(this::sinkDistanceForScheduling).reversed())
                            .thenComparing(String::compareTo));
                }
            }
            processCurrentSerial(current);
            if (cancellationRequested()) {
                queue.clear();
                pending.clear();
                return;
            }
        }
        if (!queue.isEmpty()) {
            // 截断未收敛：剩余事实未处理，本轮结果可能欠完备（不静默）
            if (steps >= stepBudget) {
                bb.markIncomplete("FORWARD_STEP_CAP:" + stepBudget);
            }
            if (methodPasses >= methodPassCap) {
                bb.markIncomplete("FORWARD_METHOD_CAP:" + methodPassCap);
            }
            if (rounds >= MAX_ROUNDS) {
                bb.markIncomplete("FORWARD_ROUND_CAP");
            }
            if (steps < stepBudget && methodPasses < methodPassCap && rounds < MAX_ROUNDS) {
                bb.markIncomplete("FORWARD_QUEUE_REMAINS");
            }
            io.just.sast.util.JustLogger.warn("前向污点[{}]：轮数/预算截断，剩余队列 {} 个方法（结果可能欠完备）",
                    options.expandInterfaces() ? "精扫" : "粗扫", queue.size());
            queue.clear();
            pending.clear();
        }
        // 不动点后补查尚未由增量 worklist 检查的 sink（仅可达子集内）。
        // 绝大多数 sink 已在宿主方法事实更新后检查；这里保留完整兜底，避免未入队
        // 的无效果宿主或空事实方法被增量路径遗漏。
        List<String> sinkMethods = new ArrayList<>(sinkCallsByMethod.keySet());
        sinkMethods.sort(String::compareTo);
        for (String methodKey : sinkMethods) {
            if (cancellationRequested()) {
                return;
            }
            checkSinksForMethod(methodKey, false);
        }
        io.just.sast.util.JustLogger.info("前向污点[{}]：可达 {} 个方法，调度 {} 个方法，激活 {} 个方法，处理 {} 次，事实 {} 个（主 {}/替代 {}），轮数 {}，耗时 {} ms",
                options.expandInterfaces() ? "精扫" : "粗扫", reachable.size(),
                forwardDemand == null ? reachable.size() : forwardDemand.size(), activeMethods.size(), methodPasses,
                factCount, primaryFactUpdates, alternativeFactUpdates, rounds,
                (System.nanoTime() - startedAt) / 1_000_000L);
    }

    /** Select a bounded precision budget from the actual graph size. */
    private void configureBudgets() {
        int closure = forwardDemand != null ? forwardDemand.size() : reachable.size();
        if (closure > 150_000) {
            stepBudget = 4_000_000;
            methodPassCap = 120_000;
        } else if (closure > 100_000) {
            stepBudget = 8_000_000;
            methodPassCap = 250_000;
        } else if (closure > 50_000) {
            stepBudget = 12_000_000;
            methodPassCap = 500_000;
        } else {
            stepBudget = DEFAULT_STEP_BUDGET;
            methodPassCap = DEFAULT_METHOD_PASS_CAP;
        }
    }

    /**
     * Build the scheduler workset from the current graph rather than from artifact names.
     *
     * A valid bounded chain must have a method that can reach a configured sink within the
     * engine's hop budget.  OriginSupport already computes the reverse ordinary-call distance
     * for the shared closure.  Intersecting that distance with the entry depth is a cheap,
     * monotone demand seed; field writers and ordinary callers are then added until a fixed
     * point.  The extra roots cover edges that are deliberately not represented as ordinary
     * call edges (serialized proxy/method-collection/native callbacks and source hosts).
     *
     * If the reverse index itself was capped, its absence is no longer a proof of
     * irrelevance.  In that case retain the old reachable scheduler and make the loss of the
     * optimization explicit in the completeness record.
     */
    private void buildForwardDemand() {
        if (reachable.isEmpty()) {
            forwardDemand = Set.of();
            return;
        }
        boolean sinkIndexCapped = support.completenessReasons().stream()
                .anyMatch(reason -> reason.startsWith("SINK_REACHABILITY_CAP:"));
        if (sinkIndexCapped) {
            bb.markIncomplete("FORWARD_DEMAND_FALLBACK:SINK_REACHABILITY_CAP");
            forwardDemand = new HashSet<>(reachable);
            return;
        }

        indexSinkRelevantLambdaBridges();

        Set<String> demanded = new HashSet<>();
        Map<String, Integer> demandCosts = new HashMap<>();
        Set<String> roots = new HashSet<>();
        for (Node method : bb.graph().nodesOfType(NodeType.METHOD)) {
            if (cancellationRequested()) {
                return;
            }
            String key = methodNodeKey(method);
            if (!reachable.contains(key)) {
                continue;
            }
            if ((!isJdkOwner(method.owner()) && isDeserializationEntry(method))
                    || support.deserializationCallbackEntries().contains(key)) {
                roots.add(key);
            }
            // A reflective-only path has no ordinary sink distance: Method.invoke is the
            // missing graph edge by design.  Admit only hosts whose statically recovered
            // Class literal can reach a configured sink, keeping the optimization intact
            // for unrelated reflection-heavy library code.
            if (hasSinkRelevantReflectiveSite(key)) {
                roots.add(key);
            }
        }
        // Application/framework deserialization boundaries are source roots even when the
        // source rule is a call rather than a magic entry.
        for (Node call : bb.graph().nodesOfType(NodeType.CALL)) {
            if (cancellationRequested()) {
                return;
            }
            MethodInfo host = support.enclosingMethod(call);
            if (host == null) {
                continue;
            }
            Rule.SourceRule source = callRules(call).source();
            if (OriginSupport.isOisRead(call)
                    || isUnconditionalDeserializeSource(source)) {
                String key = OriginSupport.methodKey(host);
                if (reachable.contains(key)) {
                    roots.add(key);
                }
            }
            // Native callbacks are not ordinary graph edges.  Retain their host and targets
            // as semantic participants so the demand closure can still be fed by the native
            // adapter without inventing a source.
            if (!support.nativeCallbackTargets(call).isEmpty()) {
                String key = OriginSupport.methodKey(host);
                if (reachable.contains(key)) {
                    roots.add(key);
                }
                for (Node target : support.nativeCallbackTargets(call)) {
                    String targetKey = methodNodeKey(target);
                    if (reachable.contains(targetKey)) {
                        roots.add(targetKey);
                    }
                }
            }
        }
        // These bounded semantic participants do not always have a materialized call edge.
        // Hosts are added as roots; their ordinary callers are recovered below.
        for (Node invoke : support.methodCollectionInvokeSites()) {
            MethodInfo host = support.enclosingMethod(invoke);
            if (host != null && reachable.contains(OriginSupport.methodKey(host))) {
                roots.add(OriginSupport.methodKey(host));
            }
        }
        for (Node handler : support.serializedProxyHandlerMethods()) {
            String key = methodNodeKey(handler);
            if (reachable.contains(key)) {
                roots.add(key);
            }
        }

        // A method is interesting when the lower-bound entry/sink distance fits the bounded
        // path.  The root entry hop is intentionally not subtracted here: the conservative
        // <= MAX_HOPS test retains one extra layer for depth-0 entries and therefore cannot
        // turn a valid path into a false negative.
        for (String key : reachable) {
            if (cancellationRequested()) {
                return;
            }
            int sinkDistance = support.sinkDistanceOf(key);
            if (sinkCallsByMethod.containsKey(key)
                    || (sinkDistance != Integer.MAX_VALUE
                    && sinkDistance <= MAX_HOPS
                    && fitsForwardDemandDepth(key, sinkDistance))) {
                addDemandCost(demanded, demandCosts, key,
                        sinkDistance == Integer.MAX_VALUE ? 0 : sinkDistance);
            }
        }
        demanded.addAll(roots);
        for (String root : roots) {
            demandCosts.putIfAbsent(root, 0);
        }

        Map<String, Set<String>> fieldWritersByField = new HashMap<>();
        for (Map.Entry<String, List<InsnFact>> entry : effectInstructions.entrySet()) {
            if (!reachable.contains(entry.getKey())) {
                continue;
            }
            for (InsnFact insn : entry.getValue()) {
                if (insn.op().isFieldWrite()) {
                    fieldWritersByField.computeIfAbsent(fieldKey(insn), ignored -> new HashSet<>())
                            .add(entry.getKey());
                }
            }
        }

        /*
         * Demand is a monotone minimum-cost closure.  The old fixed-point loop rebuilt a
         * snapshot of every demanded method and rescanned every field on every round.  On a
         * large dependency closure that turns a bounded reverse BFS into O(rounds * fields +
         * rounds * callers), even though a field only needs to be inspected when one of its
         * readers first becomes demanded or gets a cheaper cost.  A worklist is equivalent:
         * every successful cost decrease schedules exactly the three reverse relations that
         * can derive new demand (ordinary callers, field writers and lambda bridge targets).
         * The queue is seeded in lexical order so the resulting minimum-cost map and all
         * completeness decisions remain independent of HashMap iteration order.
         */
        Map<String, List<String>> fieldsReadByMethod = new HashMap<>();
        for (Map.Entry<String, Set<String>> entry : fieldReaders.entrySet()) {
            List<String> readers = new ArrayList<>(entry.getValue());
            readers.sort(String::compareTo);
            for (String reader : readers) {
                if (reachable.contains(reader)) {
                    fieldsReadByMethod.computeIfAbsent(reader, ignored -> new ArrayList<>(1))
                            .add(entry.getKey());
                }
            }
        }
        for (List<String> fields : fieldsReadByMethod.values()) {
            fields.sort(String::compareTo);
        }
        Map<String, List<String>> orderedFieldWriters = new HashMap<>();
        for (Map.Entry<String, Set<String>> entry : fieldWritersByField.entrySet()) {
            List<String> writers = new ArrayList<>(entry.getValue());
            writers.sort(String::compareTo);
            orderedFieldWriters.put(entry.getKey(), List.copyOf(writers));
        }

        List<String> initialDemand = new ArrayList<>(demandCosts.keySet());
        initialDemand.sort(String::compareTo);
        Deque<String> demandWork = new ArrayDeque<>(initialDemand);
        Set<String> queuedDemand = new HashSet<>(initialDemand);
        while (!demandWork.isEmpty()) {
            if (cancellationRequested()) {
                return;
            }
            String demandedMethod = demandWork.removeFirst();
            queuedDemand.remove(demandedMethod);
            Integer currentCostValue = demandCosts.get(demandedMethod);
            if (currentCostValue == null) {
                continue;
            }
            int currentCost = currentCostValue;

            // Return/argument facts flow back through ordinary callers.
            int callerCost = currentCost + 1;
            if (callerCost <= MAX_HOPS) {
                for (Node caller : callers.getOrDefault(demandedMethod, List.of())) {
                    String callerKey = methodNodeKey(caller);
                    if (!reachable.contains(callerKey)
                            || !fitsForwardDemandDepth(callerKey, callerCost)
                            || !addDemandCost(demanded, demandCosts, callerKey, callerCost)) {
                        continue;
                    }
                    if (queuedDemand.add(callerKey)) {
                        demandWork.addLast(callerKey);
                    }
                }
            }

            // A serialized field can be written in one method and consumed in a different
            // method without an ordinary call edge.  Reverse only the fields read by this
            // newly processed method; unrelated fields no longer pay a full scan per round.
            int writerCost = currentCost + 1;
            if (writerCost <= MAX_HOPS) {
                for (String field : fieldsReadByMethod.getOrDefault(demandedMethod, List.of())) {
                    for (String writer : orderedFieldWriters.getOrDefault(field, List.of())) {
                        if (!fitsForwardDemandDepth(writer, writerCost)
                                || !addDemandCost(demanded, demandCosts, writer, writerCost)) {
                            continue;
                        }
                        if (queuedDemand.add(writer)) {
                            demandWork.addLast(writer);
                        }
                    }
                }
            }

            // A LambdaMetafactory edge points from the factory to the implementation, but a
            // lambda passed into a static/virtual bridge has no ordinary reverse call edge
            // from the later SAM invocation. Admit only bridge targets of factories whose
            // implementation is already sink-relevant; ordinary dependency lambdas remain
            // outside the demand workset.
            Set<String> lambdaTargets = lambdaDemandTargetsByCaller.get(demandedMethod);
            if (lambdaTargets != null) {
                int targetCost = currentCost + 1;
                if (targetCost <= MAX_HOPS) {
                    List<String> orderedTargets = new ArrayList<>(lambdaTargets);
                    orderedTargets.sort(String::compareTo);
                    for (String target : orderedTargets) {
                        if (!reachable.contains(target)
                                || !addDemandCost(demanded, demandCosts, target, targetCost)) {
                            continue;
                        }
                        if (queuedDemand.add(target)) {
                            demandWork.addLast(target);
                        }
                    }
                }
            }
        }

        // Keep this set mutable: reflective/semantic resolution can discover a sink-relevant
        // method after the initial ordinary-call demand pass.  The set is still owned by this
        // single-threaded engine and only grows through admitDynamicDemand(), so iteration
        // order and the bounded scheduler remain deterministic.
        forwardDemand = new HashSet<>(demanded);
        io.just.sast.util.JustLogger.info(
                "前向需求范围：可达 {} 个方法，调度 {} 个方法，sink 种子 {} 个，入口/语义根 {} 个",
                reachable.size(), forwardDemand.size(),
                demanded.stream().filter(sinkCallsByMethod::containsKey).count(), roots.size());
    }

    /**
     * Build the small structural part of the lambda demand graph that ordinary call edges
     * cannot express. This runs after entry/sink indexes exist and only interprets factories
     * whose implementation can reach a configured sink. The per-caller origin summary is
     * shared across all relevant factories, so the cost is proportional to relevant lambda
     * sites rather than every method in a fat jar.
     */
    private void indexSinkRelevantLambdaBridges() {
        if (lambdaDemandIndexed) {
            return;
        }
        lambdaDemandIndexed = true;
        Map<String, List<Node>> factoriesByCaller = new HashMap<>();
        for (Node factory : bb.graph().nodesOfType(NodeType.CALL)) {
            if (cancellationRequested() || !"DYNAMIC".equals(factory.invokeKind())) {
                continue;
            }
            String callerKey = OriginSupport.methodKey(factory);
            if (!reachable.contains(callerKey) || !sinkRelevantLambdaFactory(factory)) {
                continue;
            }
            factoriesByCaller.computeIfAbsent(callerKey, ignored -> new ArrayList<>(1))
                    .add(factory);
        }
        List<String> callerKeys = new ArrayList<>(factoriesByCaller.keySet());
        callerKeys.sort(String::compareTo);
        for (String callerKey : callerKeys) {
            if (cancellationRequested()) {
                return;
            }
            List<Node> factories = factoriesByCaller.getOrDefault(callerKey, List.of());
            MethodInfo caller = resolveMethodKey(callerKey);
            if (caller == null) {
                continue;
            }
            ForwardOrigins.Result result = origins(caller, null);
            Map<Long, Node> relevantFactories = new HashMap<>();
            for (Node factory : factories) {
                relevantFactories.put(factory.id(), factory);
            }
            // Scan each consumer once. The previous factory-first loop revisited the same
            // call/argument state for every sink-relevant factory in one method, which is
            // disproportionately expensive in generated lambda-heavy dependency jars.
            for (Node consumer : bb.graph().callsOfMethod(callerKey)) {
                boolean isFactory = relevantFactories.containsKey(consumer.id());
                Set<Long> matchedFactories = new HashSet<>();
                int argumentCount = Descriptor.paramCount(consumer.descriptor());
                for (int ordinal = 0; ordinal < argumentCount; ordinal++) {
                    Set<ValueOrigin> values = support.argOriginAtOrdinal(consumer, ordinal, result);
                    for (ValueOrigin value : ValueOriginOrder.sorted(values)) {
                        collectRelevantLambdaFactories(value, relevantFactories, caller, result,
                                matchedFactories, new HashSet<>());
                    }
                }
                if (isFactory || matchedFactories.isEmpty()) {
                    continue;
                }
                for (Edge edge : consumer.out()) {
                    if (edge.type() != EdgeType.INVOKES && edge.type() != EdgeType.DISPATCHES) {
                        continue;
                    }
                        String target = methodNodeKey(edge.to());
                    if (reachable.contains(target)) {
                        lambdaDemandTargetsByCaller
                                .computeIfAbsent(callerKey, ignored -> new HashSet<>())
                                .add(target);
                    }
                }
            }
        }
        if (!lambdaDemandTargetsByCaller.isEmpty()) {
            JustLogger.debug("前向 lambda 需求桥：{} 个调用方，{} 个目标",
                    lambdaDemandTargetsByCaller.size(),
                    lambdaDemandTargetsByCaller.values().stream().mapToInt(Set::size).sum());
        }
    }

    private boolean sinkRelevantLambdaFactory(Node factory) {
        for (Edge edge : factory.out()) {
            if (edge.type() != EdgeType.LAMBDA) {
                continue;
            }
            String target = methodNodeKey(edge.to());
            if (sinkCallsByMethod.containsKey(target)
                    || support.sinkDistanceOf(target) != Integer.MAX_VALUE) {
                return true;
            }
        }
        return false;
    }

    private void collectRelevantLambdaFactories(ValueOrigin value,
                                                Map<Long, Node> relevantFactories,
                                                MethodInfo method,
                                                ForwardOrigins.Result result,
                                                Set<Long> matches,
                                                Set<ValueOrigin> visiting) {
        if (value == null || method == null || result == null || !visiting.add(value)) {
            return;
        }
        try {
            if (value instanceof ValueOrigin.CallResult callResult
                    && relevantFactories.containsKey(callResult.callNodeId())) {
                matches.add(callResult.callNodeId());
                return;
            }
            if (!(value instanceof ValueOrigin.Insn instruction)
                    || instruction.offset() < 0
                    || instruction.offset() >= method.instructions().size()
                    || method.insnAt(instruction.offset()).op() != Op.CHECKCAST) {
                return;
            }
            ForwardOrigins.State before = result.stateBefore().get(instruction.offset());
            if (before == null || before.stack().isEmpty()) {
                return;
            }
            for (ValueOrigin candidate : ValueOriginOrder.sorted(
                    before.stack().get(before.stack().size() - 1).origins())) {
                collectRelevantLambdaFactories(candidate, relevantFactories, method, result,
                        matches, visiting);
            }
        } finally {
            visiting.remove(value);
        }
    }

    private static boolean addDemandCost(Set<String> demanded, Map<String, Integer> costs,
                                         String methodKey, int cost) {
        if (methodKey == null || cost < 0 || cost > MAX_HOPS) {
            return false;
        }
        Integer previous = costs.get(methodKey);
        if (previous != null && previous <= cost) {
            return false;
        }
        costs.put(methodKey, cost);
        demanded.add(methodKey);
        return true;
    }

    private boolean fitsForwardDemandDepth(String methodKey, int sinkDistance) {
        int entryDepth = support.entryDepthOf(methodKey);
        return entryDepth == Integer.MAX_VALUE || entryDepth + sinkDistance <= MAX_HOPS;
    }

    private void processCurrentSerial(List<String> current) {
        for (String key : current) {
            if (cancellationRequested()) {
                return;
            }
            MethodInfo method = resolveMethodKey(key);
            if (method != null) {
                methodPasses++;
                // Share the method-local exploration between effect transfer and all sinks
                // hosted by this method.  The CFG/origin result is immutable and the
                // exploration guards are empty again after each query, so this preserves
                // recursion semantics while avoiding repeated frontier walks for sibling
                // sinks in the same method.
                Explore exploration = new Explore();
                processEffects(method, exploration);
                checkSinksForMethod(key, false, exploration);
            }
        }
    }

    /** Check the sink calls hosted by one method at most once per current fact version. */
    private void checkSinksForMethod(String methodKey, boolean force) {
        checkSinksForMethod(methodKey, force, new Explore());
    }

    private void checkSinksForMethod(String methodKey, boolean force, Explore exploration) {
        if (methodKey == null || (options.reachablePrune() && !reachable.contains(methodKey))
                || (options.reachablePrune() && forwardDemand != null
                && !forwardDemand.contains(methodKey))) {
            return;
        }
        for (Node call : sinkCallsByMethod.getOrDefault(methodKey, List.of())) {
            if (cancellationRequested()) {
                return;
            }
            if (!force && sinkCheckVersions.getOrDefault(call.id(), Long.MIN_VALUE) == factVersion) {
                continue;
            }
            sinkCheckVersions.put(call.id(), factVersion);
            Rule.SinkRule rule = callRules(call).sink();
            if (rule != null) {
                checkSink(call, rule, exploration);
            }
        }
    }

    private int entryDepthForScheduling(String methodKey) {
        int depth = support.entryDepthOf(methodKey);
        return depth == Integer.MAX_VALUE ? Integer.MAX_VALUE : depth;
    }

    private int sinkDistanceForScheduling(String methodKey) {
        int distance = support.sinkDistanceOf(methodKey);
        return distance == Integer.MAX_VALUE ? -1 : distance;
    }


    /** 精扫重入队（受影响方法）：已污点类的全部方法 + 参数/返回事实方法 + 已污点字段的读者。 */
    private void requeueAffected() {
        List<String> taintedClasses = new ArrayList<>(thisTainted.keySet());
        taintedClasses.sort(String::compareTo);
        for (String cls : taintedClasses) {
            if (cancellationRequested()) {
                return;
            }
            ClassInfo info = bb.hierarchy().classInfo(cls);
            if (info == null) {
                continue;
            }
            for (MethodInfo method : info.methods()) {
                if (cancellationRequested()) {
                    return;
                }
                if (!options.reachablePrune() || reachable.contains(OriginSupport.methodKey(method))) {
                    activateAndEnqueue(OriginSupport.methodKey(method));
                }
            }
        }
        List<String> taintedParameters = new ArrayList<>(paramTainted.keySet());
        taintedParameters.sort(String::compareTo);
        for (String key : taintedParameters) {
            if (cancellationRequested()) {
                return;
            }
            activateAndEnqueue(key.substring(0, key.lastIndexOf('#')));
        }
        List<String> taintedReturns = new ArrayList<>(returnTainted.keySet());
        taintedReturns.sort(String::compareTo);
        for (String key : taintedReturns) {
            activateAndEnqueue(key);
        }
        List<String> taintedFields = new ArrayList<>(fieldTainted.keySet());
        taintedFields.sort(String::compareTo);
        for (String field : taintedFields) {
            if (cancellationRequested()) {
                return;
            }
            Set<String> readers = fieldReaders.get(field);
            if (readers != null) {
                List<String> orderedReaders = new ArrayList<>(readers);
                orderedReaders.sort(String::compareTo);
                for (String reader : orderedReaders) {
                    activateAndEnqueue(reader);
                }
            }
        }
    }

    /** 前向可达集：从 magic entry、OIS 宿主与反序列化 source 宿主出发，沿调用边 BFS。 */
    private boolean computeReachable() {
        Deque<String> bfs = new ArrayDeque<>();
        // The backward engine and the calibration layer share OriginSupport's semantic
        // closure, which includes field-mediated callbacks, reflective Method.invoke sites,
        // and externally assembled proxy/method-collection edges.  A plain call-graph BFS
        // cannot see those edges and used to make forward sink gating disagree with the
        // backward result.  Admit the same bounded closure first; the ordinary BFS below
        // remains as a fallback for graph-only extensions that do not populate the shared
        // index.  Sorting is required because entryDownstream is a set and finite budgets
        // must not depend on HashSet iteration order.
        Set<String> semanticClosure = support.entryDownstream(bb.graph());
        if (!semanticClosure.isEmpty()) {
            List<String> orderedClosure = semanticClosure.stream().sorted().toList();
            int admitted = 0;
            for (String key : orderedClosure) {
                if (reachable.size() >= REACHABLE_CAP) {
                    bb.markIncomplete("REACHABLE_CAP:" + REACHABLE_CAP);
                    break;
                }
                if (reachable.add(key)) {
                    admitted++;
                }
            }
            if (admitted > 0) {
                io.just.sast.util.JustLogger.debug("入口语义闭包并入前向可达集：{} 个方法", admitted);
            }
        }
        for (Node method : bb.graph().nodesOfType(NodeType.METHOD)) {
            if (cancellationRequested()) {
                return false;
            }
            // JDK 自身的 readObject/hashCode 等是机制实现，不应作为每个扫描任务的独立污点根；
            // 它们仍会作为应用调用图中的被调者进入可达集。对象图/组合知识源负责把
            // 反序列化容器的回调语义补回，避免把完整 JDK 图扩散成数万条 worklist 根。
            if (isMagicEntry(method) && !isJdkOwner(method.owner())
                    && isAnalysisEntry(method)
                    && reachable.add(methodNodeKey(method))) {
                bfs.add(methodNodeKey(method));
            }
        }
        for (Node call : bb.graph().nodesOfType(NodeType.CALL)) {
            if (cancellationRequested()) {
                return false;
            }
            MethodInfo enclosing = support.enclosingMethod(call);
            // An OIS read in an application/framework boundary is a source.  A read
            // performed inside a JDK collection's own readObject implementation is
            // deserialization plumbing, not an independent attacker root; treating it
            // as one makes every JDK container a shorter class-level taint source and
            // can hide the real application entry behind unrelated paths.
            if (OriginSupport.isOisRead(call) && enclosing != null
                    && !isJdkOwner(enclosing.owner())
                    && reachable.add(OriginSupport.methodKey(enclosing))) {
                bfs.add(OriginSupport.methodKey(enclosing));
            }
            Rule.SourceRule source = callRules(call).source();
            if (isUnconditionalDeserializeSource(source)
                    && enclosing != null
                    && reachable.add(OriginSupport.methodKey(enclosing))) {
                bfs.add(OriginSupport.methodKey(enclosing));
            }
        }
        while (!bfs.isEmpty() && reachable.size() < REACHABLE_CAP) {
            if (cancellationRequested()) {
                return false;
            }
            String key = bfs.poll();
            if (resolveMethodKey(key) == null) {
                continue;
            }
            for (Node call : bb.graph().callsOfMethod(key)) {
                if (cancellationRequested()) {
                    return false;
                }
                for (Edge edge : call.out()) {
                    if (cancellationRequested()) {
                        return false;
                    }
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
        return true;
    }

    /**
     * Seed real deserialization entries with a receiver fact on the selected method only.
     *
     * A class-wide receiver summary is intentionally not used here: it activates every
     * method on a large dependency class and makes an entry source pay for unrelated glue
     * methods.  Ordinary call/field/return propagation still activates concrete consumers
     * when a fact reaches them.  This keeps the seed sound for instance entry methods while
     * making the initial workset demand-driven.
     */
    private void seedEntries() {
        // Platform serialization callbacks are real mechanism roots, but their bytecode is
        // usually admitted only to close a sink-relevant object graph.  Queue them before the
        // much larger application magic-entry family so a finite work budget spends its first
        // pass on the callback data that can actually reach a sink.  The order is deterministic
        // and bounded by OriginSupport; it changes scheduling priority, not source semantics.
        for (String callbackKey : support.deserializationCallbackEntries().stream().sorted().toList()) {
            if (cancellationRequested()) {
                return;
            }
            Node method = bb.graph().findMethodNodeKey(callbackKey);
            if (method == null) {
                continue;
            }
            bb.ruleEngine().matchingEntry(method.owner(), method.name(), method.descriptor())
                    .ifPresent(rule -> seedEntryReceiver(method, List.of(new ChainHop(
                            method.owner(), method.name(), method.owner(), method.name(),
                            HopKind.ENTRY, null, rule.entryKind(), method.descriptor(), null))));
        }
        for (Node method : bb.graph().nodesOfType(NodeType.METHOD)) {
            if (cancellationRequested()) {
                return;
            }
            if (isJdkOwner(method.owner()) || !isAnalysisEntry(method)) {
                continue;
            }
            bb.ruleEngine().matchingEntry(method.owner(), method.name(), method.descriptor())
                    .ifPresent(rule -> {
                        String owner = method.owner();
                        ChainHop entryHop = new ChainHop(owner, method.name(),
                                owner, method.name(), HopKind.ENTRY, null, rule.entryKind(),
                                method.descriptor(), null);
                        seedEntryReceiver(method, List.of(entryHop));
                    });
        }
        seedSemanticCallbacks();
    }

    private void seedEntryReceiver(Node method, List<ChainHop> path) {
        if (method == null) {
            return;
        }
        MethodInfo info = support.methodOf(method.owner(), method.name(), method.descriptor());
        if (info != null && !info.isStatic()) {
            addParam(info.owner(), info.name(), info.descriptor(), 0, path);
            return;
        }
        // Static lifecycle hooks have no receiver slot.  Keep the old class summary only for
        // this uncommon shape; it cannot be replaced by a parameter fact.
        addThis(method.owner(), path, false);
    }

    /**
     * Ordinary BFS cannot enqueue a method that is connected only by an external
     * reflective callback.  Add the bounded semantic participants after entry
     * seeds are installed so their effects can contribute facts and sink checks.
     */
    private void seedSemanticCallbacks() {
        Set<String> semanticMethods = new java.util.TreeSet<>();
        for (Node invoke : support.methodCollectionInvokeSites()) {
            MethodInfo host = support.enclosingMethod(invoke);
            if (host != null) {
                semanticMethods.add(OriginSupport.methodKey(host));
            }
        }
        for (Node target : support.methodCollectionTargetMethods()) {
            semanticMethods.add(OriginSupport.methodKeyOf(target.owner(), target.name(),
                    target.descriptor()));
        }
        for (Node handler : support.serializedProxyHandlerMethods()) {
            String handlerKey = OriginSupport.methodKeyOf(handler.owner(), handler.name(),
                    handler.descriptor());
            semanticMethods.add(handlerKey);
            // A serialized InvocationHandler is not an independent source.  When a
            // reachable typed Method-collection callback supplies the proxy receiver,
            // materialize exactly that bounded callback path as the handler's receiver
            // fact.  This keeps external proxy support while removing the global
            // proxyInvoke root that otherwise pollutes ranking and sink provenance.
            if (reachable.contains(handlerKey)) {
                MethodInfo handlerMethod = support.methodOf(handler.owner(), handler.name(),
                        handler.descriptor());
                if (handlerMethod != null) {
                    List<ChainHop> callbackPath = serializedProxyHandlerPath(handlerMethod, 0,
                            new Explore());
                    if (callbackPath != null) {
                        // This is a fact about the handler receiver of this one callback
                        // method, not a fact about every instance method in the handler's
                        // class.  Keeping it at parameter-slot granularity prevents an
                        // external proxy callback from activating unrelated helper methods
                        // such as Map/bean conversion utilities on the same object.
                        addParam(handler.owner(), handler.name(), handler.descriptor(), 0,
                                callbackPath);
                    }
                }
            }
        }
        for (String methodKey : semanticMethods) {
            if (reachable.contains(methodKey)) {
                activateAndEnqueue(methodKey);
            }
        }
    }

    private boolean isMagicEntry(Node method) {
        return bb.ruleEngine().matchingEntry(method.owner(), method.name(), method.descriptor()).isPresent();
    }

    /**
     * Lifecycle methods remain visible as independent trigger candidates. They are not
     * deserialization source bridges; chain calibration must prove that a lifecycle trigger
     * is reachable from a real deserialize entry before a finding survives.
     */
    private boolean isAnalysisEntry(Node method) {
        return isDeserializationEntry(method);
    }

    /**
     * InvocationHandler.invoke is never a standalone deserialization entry.  A proxy
     * callback enters through an actual Proxy.newProxyInstance flow or the bounded
     * serialized-proxy callback model in seedSemanticCallbacks().
     */
    private boolean isDeserializationEntry(Node method) {
        var entry = bb.ruleEngine().matchingEntry(method.owner(), method.name(), method.descriptor());
        if (entry.isEmpty() || !"deserialize".equals(entry.get().direction())) {
            return false;
        }
        String entryKind = entry.get().entryKind();
        return !"proxyInvoke".equals(entryKind)
                && !SERIALIZED_TRIGGER_ENTRY_KINDS.contains(entryKind);
    }

    /** 方法效果：PUTFIELD 存污点值 → 字段事实；RETURN 污点值 → 返回事实；AASTORE 污点值 → 数组容器污点。 */
    private void processEffects(MethodInfo method, Explore ex) {
        String methodKey = OriginSupport.methodKey(method);
        if (!activeMethods.contains(methodKey) && !sourceHostMethods.contains(methodKey)) {
            // The demand workset is deliberately conservative, but a reachable dependency
            // method with no source/receiver/parameter/field fact cannot produce a
            // source-backed cross-method effect.  Do not materialize its CFG merely because
            // it has an invocation or return instruction; it remains available to later
            // fact-driven requeueing through addParam/addField/addReturn.
            return;
        }
        List<InsnFact> effects = effectInstructions.get(methodKey);
        if (effects == null) {
            return;
        }
        Map<ValueOrigin, Boolean> relevantOrigins = new HashMap<>();
        ForwardOrigins.Result originResult = origins(method, ex);
        for (InsnFact insn : effects) {
            if (cancellationRequested()) {
                return;
            }
            if (!externalProxyCallbackAllows(method, insn.offset())) {
                // ForwardOrigins intentionally merges local branches.  For a serialized
                // proxy the Method argument supplies a bounded discriminator, so do not
                // let effects from a method-name branch that no candidate callback can
                // select enter the global summaries.
                continue;
            }
            Op op = insn.op();
            if (op.isFieldWrite()) {
                ForwardOrigins.State state = originResult.stateBefore().get(insn.offset());
                if (state == null || state.stack().isEmpty()) {
                    continue;
                }
                for (ValueOrigin value : ValueOriginOrder.sorted(
                        state.stack().get(state.stack().size() - 1).origins())) {
                    if (cancellationRequested()) {
                        return;
                    }
                    if (!mayCarryTaint(value)) {
                        continue;
                    }
                    for (List<ChainHop> path : primaryCandidate(value, method, 0, ex)) {
                        if (cancellationRequested()) {
                            return;
                        }
                        addField(insn.fieldRef().owner(), insn.fieldRef().name(),
                                insn.fieldRef().descriptor(), insn.op() == Op.PUTSTATIC, path);
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
                for (ValueOrigin value : ValueOriginOrder.sorted(
                        state.stack().get(state.stack().size() - 1).origins())) {
                    if (cancellationRequested()) {
                        return;
                    }
                    if (!mayCarryTaint(value)) {
                        continue;
                    }
                    for (List<ChainHop> path : primaryCandidate(value, method, 0, ex)) {
                        if (cancellationRequested()) {
                            return;
                        }
                        for (ValueOrigin arrayRef : ValueOriginOrder.sorted(
                                state.stack().get(state.stack().size() - 3).origins())) {
                            if (cancellationRequested()) {
                                return;
                            }
                            if (arrayRef instanceof ValueOrigin.FieldRead f && !f.isStatic()) {
                                addField(f.owner(), f.field(), f.descriptor(), false, path);
                            } else if (arrayRef instanceof ValueOrigin.Param p) {
                                addParam(method.owner(), method.name(), method.descriptor(), p.slot(), path);
                            }
                        }
                    }
                }
            } else if (op.isInvoke()) {
                // lambda 桥接驱动器：仅对携带函数式结果实参（indy 结果经函数式接口传递）的
                // 调用点做主动传播——这类调用在需求驱动下永不被评估，lambda 绑定/消费无法发生。
                // 其余调用维持需求驱动：全量主动传播会制造短路径挤占事实表
                // （被校验拒绝的形态替换可用长路径）与预算爆炸。
                Node callNode = support.callNode(methodKey, insn.offset());
                if (callNode != null && hasRelevantCallInputs(callNode, method, originResult,
                        relevantOrigins)) {
                    // Constant-only calls cannot create a taint fact. Keep the lambda
                    // structural bind in the same path while skipping needless propagation.
                    propagateCallArgs(callNode, method, 0, ex, originResult);
                    methodCollectionResolve(callNode, method, 0, ex, originResult);
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
                for (ValueOrigin value : ValueOriginOrder.sorted(
                        state.stack().get(state.stack().size() - 1).origins())) {
                    if (cancellationRequested()) {
                        return;
                    }
                    if (!mayCarryTaint(value)) {
                        continue;
                    }
                    for (List<ChainHop> path : primaryCandidate(value, method, 0, ex)) {
                        if (cancellationRequested()) {
                            return;
                        }
                        addReturn(methodKey(method, ex), path);
                    }
                }
            }
        }
    }

    /** sink 判定：污点位置的值带污点 → 链达成。 */
    private void checkSink(Node call, Rule.SinkRule rule) {
        checkSink(call, rule, new Explore());
    }

    private void checkSink(Node call, Rule.SinkRule rule, Explore ex) {
        if (cancellationRequested()) {
            return;
        }
        MethodInfo method = support.enclosingMethod(call);
        if (method == null) {
            return;
        }
        Object sinkOffset = call.prop("offset");
        if (sinkOffset instanceof Integer offset && !externalProxyCallbackAllows(method, offset)) {
            return;
        }
        ForwardOrigins.Result originResult = origins(method, ex);
        ForwardOrigins.State state = originResult.stateBefore().get((Integer) call.prop("offset"));
        if (state == null) {
            return;
        }
        if (support.catchProvablyUnreachable(method, (Integer) call.prop("offset"))) {
            return; // catch 不可达守卫（与反向引擎同谓词）
        }
        if (support.sinkPathProvablyUnreachable(method, (Integer) call.prop("offset"), originResult)) {
            // Keep the forward and backward engines on the same exact local-feasibility
            // boundary.  The taint fixed point stays path-insensitive for recall, while
            // an independently proven impossible branch is not allowed to re-introduce a
            // finding after backward analysis has removed it.
            return;
        }
        int paramCount = Descriptor.paramCount(call.descriptor());
        for (Rule.TaintedPos pos : rule.tainted()) {
            if (cancellationRequested()) {
                return;
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
                if (cancellationRequested()) {
                    return;
                }
                if (!mayCarryTaint(origin)) {
                    continue;
                }
                for (List<ChainHop> path : taintedCandidates(origin, method, 0, ex)) {
                    if (cancellationRequested()) {
                        return;
                    }
                    List<ChainHop> hops = new ArrayList<>(path);
                    Collections.reverse(hops); // 前向路径翻转为 sink→entry
                    ChainHop entry = hops.get(hops.size() - 1);
                    Chain chain = new Chain(rule.id(), rule.category(), rule.severity(),
                            entry.fromOwner(), entry.fromName(),
                            entry.reason() == null ? "?" : entry.reason(),
                            call.owner(), call.name(), hops, 0, call.descriptor(), rule.role().name());
                    bb.addChain(chain);
                }
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
        if (cancellationRequested()) {
            ex.truncated = true;
            return null;
        }
        if (depth > MAX_DEPTH || steps > stepBudget) {
            ex.truncated = true;
            return null;
        }
        steps++;
        TaintKey key = new TaintKey(methodKey(method, ex), origin);
        if (ex.visiting.contains(key)) {
            return null; // 当前摘要递归环：不能写入全局 null 缓存
        }
        TaintMemo memo = taintMemo.get(key);
        if (memo != null && memo.factVersion() == primaryFactVersion) {
            return memo.path();
        }
        Long deadAt = deadEnds.get(key);
        if (deadAt != null && deadAt == primaryFactVersion) {
            return null; // 版本未推进时的死胡同有效；新事实到达（版本推进）后重查
        }
        ex.visiting.add(key);
        boolean truncatedAtEntry = ex.truncated;
        List<ChainHop> path;
        if (origin instanceof ValueOrigin.Param p) {
            path = taintedParam(p.slot(), method, ex);
            // A serializable InvocationHandler may be invoked by a proxy assembled
            // outside the scanned artifact.  Prefer that concrete callback path over
            // the synthetic proxyInvoke entry root whenever a typed Method collection
            // supplies a possible proxy receiver.
            if (p.slot() == 0 && !method.isStatic()
                    && support.isSerializedProxyHandler(method)) {
                List<ChainHop> external = serializedProxyHandlerPath(method, depth, ex);
                if (external != null) {
                    path = external;
                }
            }
        } else if (origin instanceof ValueOrigin.FieldRead f) {
            path = taintedFieldRead(f, method, depth, ex);
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
            taintMemo.put(key, new TaintMemo(primaryFactVersion, path));
        } else if (!subtreeTruncated) {
            deadEnds.put(key, primaryFactVersion);
            if (deadEnds.size() > DEAD_END_SWEEP + DEAD_END_SWEEP_BURST) {
                long version = primaryFactVersion;
                deadEnds.values().removeIf(v -> v < version);
                if (deadEnds.size() > DEAD_END_SWEEP) {
                    int remove = deadEnds.size() - DEAD_END_SWEEP;
                    var iterator = deadEnds.keySet().iterator();
                    while (remove-- > 0 && iterator.hasNext()) {
                        iterator.next();
                        iterator.remove();
                    }
                }
            }
        }
        return path;
    }

    /**
     * Resolve a value to a small auditable frontier.  Most analysis code still consumes the
     * shortest path through {@link #tainted(ValueOrigin, MethodInfo, int, Explore)}; this
     * opt-in view is used where collapsing provenance would change the finding set, notably
     * sink checks and stateful effect propagation.
     */
    private List<List<ChainHop>> taintedCandidates(ValueOrigin origin, MethodInfo method,
                                                    int depth, Explore ex) {
        if (origin == null || method == null) {
            return List.of();
        }
        CandidateKey memoKey = ex == null
                ? null
                : new CandidateKey(methodKey(method, ex), origin, depth);
        // A candidate frontier is context-sensitive even though its key is structural: a
        // nested tainted() call may see the same value while an ancestor is on the recursion
        // stack.  Reusing that partial view would change cycle behavior and inflate or drop
        // findings.  Only top-level consumers (sink/effect boundaries) may read/write this
        // exploration memo; nested expansion still benefits from the primary taint memo.
        boolean memoEligible = ex != null && ex.visiting.isEmpty()
                && ex.candidateCallResults.isEmpty() && ex.candidateInstructions.isEmpty();
        long memoVersion = candidateFactVersion;
        if (memoEligible) {
            CandidateMemo memo = ex.candidateMemo.get(memoKey);
            if (memo != null && memo.factVersion() == candidateFactVersion) {
                return memo.paths();
            }
            CandidateMemo shared = candidateMemoCache.get(memoKey);
            if (shared != null && shared.factVersion() == candidateFactVersion) {
                ex.candidateMemo.put(memoKey, shared);
                return shared.paths();
            }
        }
        boolean truncatedAtEntry = ex != null && ex.truncated;
        boolean recursionSuppressed = false;
        List<List<ChainHop>> paths;
        if (origin instanceof ValueOrigin.Param p) {
            paths = new ArrayList<>(taintedParamCandidates(p.slot(), method, ex));
            if (p.slot() == 0 && !method.isStatic()
                    && support.isSerializedProxyHandler(method)) {
                List<ChainHop> external = serializedProxyHandlerPath(method, depth, ex);
                if (external != null) {
                    paths.add(external);
                }
            }
        } else if (origin instanceof ValueOrigin.FieldRead f) {
            paths = new ArrayList<>(taintedFieldCandidates(f, method, depth, ex));
        } else if (origin instanceof ValueOrigin.CallResult c) {
            paths = new ArrayList<>();
            List<ChainHop> primary = tainted(origin, method, depth, ex);
            if (primary != null) {
                paths.add(primary);
            }
            // Return summaries and models can have several valid provenance roots.  The
            // ordinary tainted() result intentionally remains one-best for speed, but a
            // call-result consumed as an argument must expose the bounded frontier or a
            // longer serialized-container path can disappear before it reaches a sink.
            if (ex == null || c.callNodeId() < 0
                    || ex.candidateCallResults.add(c.callNodeId())) {
                try {
                    paths.addAll(callResultAlternativePaths(c.callNodeId(), method, depth, ex));
                } finally {
                    if (ex != null && c.callNodeId() >= 0) {
                        ex.candidateCallResults.remove(c.callNodeId());
                    }
                }
            } else {
                recursionSuppressed = true;
            }
        } else if (origin instanceof ValueOrigin.Insn i) {
            paths = new ArrayList<>();
            List<ChainHop> primary = tainted(origin, method, depth, ex);
            if (primary != null) {
                paths.add(primary);
            }
            TaintKey instructionKey = new TaintKey(methodKey(method, ex), origin);
            if (ex == null || ex.candidateInstructions.add(instructionKey)) {
                try {
                    paths.addAll(instructionAlternativePaths(i.offset(), method, depth, ex));
                } finally {
                    if (ex != null) {
                        ex.candidateInstructions.remove(instructionKey);
                    }
                }
            } else {
                recursionSuppressed = true;
            }
        } else {
            List<ChainHop> path = tainted(origin, method, depth, ex);
            paths = path == null ? new ArrayList<>() : new ArrayList<>(List.of(path));
        }
        List<List<ChainHop>> result = distinctBestPaths(paths);
        boolean subtreeTruncated = ex != null && ex.truncated && !truncatedAtEntry;
        if (memoEligible && !recursionSuppressed && !subtreeTruncated
                && ex.visiting.isEmpty() && ex.candidateCallResults.isEmpty()
                && ex.candidateInstructions.isEmpty()
                && memoVersion == candidateFactVersion) {
            CandidateMemo memo = new CandidateMemo(memoVersion, List.copyOf(result));
            ex.candidateMemo.put(memoKey, memo);
            candidateMemoCache.put(memoKey, memo);
            trimCandidateMemoCache();
        }
        return result;
    }

    private void trimCandidateMemoCache() {
        if (candidateMemoCache.size() <= MAX_CANDIDATE_MEMO_ENTRIES
                + MAX_CANDIDATE_MEMO_BURST) {
            return;
        }
        candidateMemoCache.entrySet().removeIf(entry ->
                entry.getValue().factVersion() != candidateFactVersion);
        if (candidateMemoCache.size() > MAX_CANDIDATE_MEMO_ENTRIES) {
            int remove = candidateMemoCache.size() - MAX_CANDIDATE_MEMO_ENTRIES;
            var iterator = candidateMemoCache.keySet().iterator();
            while (remove-- > 0 && iterator.hasNext()) {
                iterator.next();
                iterator.remove();
            }
        }
    }

    /** Primary-only view for the hot call-argument scheduler. */
    private List<List<ChainHop>> primaryCandidate(ValueOrigin origin, MethodInfo method,
                                                   int depth, Explore ex) {
        List<ChainHop> path = tainted(origin, method, depth, ex);
        return path == null ? List.of() : List.of(path);
    }

    /** Expand bounded alternatives for a value produced by an instruction. */
    private List<List<ChainHop>> instructionAlternativePaths(int offset, MethodInfo method,
                                                               int depth, Explore ex) {
        if (method == null || offset < 0 || offset >= method.instructions().size()
                || !externalProxyCallbackAllows(method, offset)) {
            return List.of();
        }
        ForwardOrigins.Result result = origins(method, ex);
        ForwardOrigins.State state = result.stateBefore().get(offset);
        if (state == null) {
            return List.of();
        }
        InsnFact instruction = method.insnAt(offset);
        List<List<ChainHop>> paths = new ArrayList<>();
        if (instruction.op() == Op.NEWARRAY || instruction.op() == Op.ANEWARRAY
                || instruction.op() == Op.MULTIANEWARRAY || instruction.op() == Op.AALOAD) {
            for (ValueOrigin element : result.arrayElements()
                    .getOrDefault(new ValueOrigin.Insn(offset), Set.of())) {
                if (mayCarryTaint(element)) {
                    paths.addAll(taintedCandidates(element, method, depth + 1, ex));
                }
            }
        }
        int consumed = OriginSupport.consumedCount(instruction.op());
        int start = Math.max(0, state.stack().size() - consumed);
        for (int index = start; index < state.stack().size(); index++) {
            for (ValueOrigin operand : ValueOriginOrder.sorted(
                    state.stack().get(index).origins())) {
                if (mayCarryTaint(operand)) {
                    paths.addAll(taintedCandidates(operand, method, depth + 1, ex));
                }
            }
        }
        return distinctBestPaths(paths);
    }

    /**
     * Expand the bounded alternatives that can explain a call result.  This is deliberately
     * a consumer-side view: the primary summary and all side-effect propagation continue to
     * use taintedCallResult(), while argument/field/sink consumers receive at most the same
     * finite frontier retained by the fact store.
     */
    private List<List<ChainHop>> callResultAlternativePaths(long callNodeId, MethodInfo method,
                                                              int depth, Explore ex) {
        if (callNodeId < 0 || method == null) {
            return List.of();
        }
        Node call = support.callNode(callNodeId);
        if (call == null) {
            return List.of();
        }
        Object callOffset = call.prop("offset");
        if (callOffset instanceof Integer offset && !externalProxyCallbackAllows(method, offset)) {
            return List.of();
        }
        // Most call results are ordinary values with no source/model/return summary.  They
        // still need the primary tainted() lookup, but expanding the bounded frontier for
        // them repeatedly walks the same call edges and model inputs without adding a path.
        // Keep this guard cheap and fact-driven; a newly learned return fact changes
        // factVersion, so a previously skipped call is reconsidered in the next exploration.
        if (!hasCallResultAlternative(call)) {
            return List.of();
        }
        List<List<ChainHop>> paths = new ArrayList<>();
        CallRules rules = callRules(call);
        Rule.SourceRule source = rules.source();
        if (isDeserializationSource(source) && !source.tainted().isEmpty()) {
            for (List<ChainHop> inputPath : sourceInputPaths(source, call, method,
                    depth, ex)) {
                List<ChainHop> candidate = sourceBridgePath(inputPath, method, call);
                if (candidate != null) {
                    paths.add(candidate);
                }
            }
        }
        Rule.ModelRule model = rules.model();
        if (model != null) {
            boolean allowReturnModel = isExactModel(model, call)
                    || !hasResolvedReturnSummary(call);
            if (allowReturnModel) {
                for (Map.Entry<String, List<String>> action : model.actions().entrySet()) {
                    if (!"return".equals(action.getKey())) {
                        continue;
                    }
                    for (String src : action.getValue()) {
                        for (List<ChainHop> sourcePath : modelSourcePaths(src, call, method,
                                depth, ex)) {
                            List<ChainHop> candidate = hopTo(sourcePath, method, call.owner(),
                                    call.name(), call.descriptor(), EdgeType.INVOKES);
                            if (candidate != null) {
                                paths.add(candidate);
                            }
                        }
                    }
                }
            }
        }
        for (Edge edge : call.out()) {
            if (edge.type() != EdgeType.INVOKES && edge.type() != EdgeType.DISPATCHES) {
                continue;
            }
            String targetKey = methodNodeKey(edge.to());
            for (List<ChainHop> returnPath : candidatePaths(returnTainted,
                    returnTaintedAlternatives, targetKey)) {
                List<ChainHop> candidate = appendReturnHop(returnPath, method, edge, true);
                if (candidate != null) {
                    paths.add(candidate);
                }
            }
        }
        return distinctBestPaths(paths);
    }

    /**
     * Whether a call result has a second provenance family worth expanding.  This is a
     * semantic prefilter, not a benchmark shortcut: only declared deserialize sources,
     * return models, or already learned return summaries qualify.  The primary summary path
     * remains available for every call result.
     */
    private boolean hasCallResultAlternative(Node call) {
        if (call == null) {
            return false;
        }
        CallRules rules = callRules(call);
        Rule.SourceRule source = rules.source();
        if (isDeserializationSource(source) && !source.tainted().isEmpty()) {
            return true;
        }
        Rule.ModelRule model = rules.model();
        if (model != null && model.actions().entrySet().stream()
                .anyMatch(action -> "return".equals(action.getKey())
                        && action.getValue() != null && !action.getValue().isEmpty())) {
            return true;
        }
        for (Edge edge : call.out()) {
            if (edge.type() != EdgeType.INVOKES && edge.type() != EdgeType.DISPATCHES) {
                continue;
            }
            String targetKey = methodNodeKey(edge.to());
            if (returnTainted.containsKey(targetKey)
                    || returnTaintedAlternatives.containsKey(targetKey)) {
                return true;
            }
        }
        return false;
    }

    /** 参数污点：实例方法 slot 0 为 this（类级污点）；静态方法 slot 0 是首个实参，不吃类级污点。 */
    private List<ChainHop> taintedParam(int slot, MethodInfo method, Explore ex) {
        List<ChainHop> parameterPath = paramTainted.get(methodKey(method, ex) + "#" + slot);
        if (parameterPath != null) {
            return parameterPath;
        }
        if (slot == 0 && !method.isStatic()) {
            List<ChainHop> path = thisTainted.get(method.owner());
            if (path != null) {
                return path;
            }
        }
        return null;
    }

    /**
     * Return the bounded provenance frontier for a parameter.  The primary summary is always
     * included even for facts produced by older extension hooks that did not populate the
     * alternative index.
     */
    private List<List<ChainHop>> taintedParamCandidates(int slot, MethodInfo method, Explore ex) {
        if (method == null) {
            return List.of();
        }
        if (slot == 0 && !method.isStatic()) {
            // A selected call target carries a receiver fact for this method only.  If
            // such a fact exists, mixing it with the class-wide summary recreates the
            // cross-object contamination that the method-local receiver slot is meant to
            // prevent.  Fall back to the class summary only for methods reached through
            // an actual entry seed or an inherited callback without a selected receiver.
            List<List<ChainHop>> methodPaths = candidatePaths(paramTainted,
                    paramTaintedAlternatives, methodKey(method, ex) + "#" + slot);
            if (!methodPaths.isEmpty()) {
                return methodPaths;
            }
            List<List<ChainHop>> paths = new ArrayList<>(candidatePaths(thisTainted,
                    thisTaintedAlternatives, method.owner()));
            return distinctBestPaths(paths);
        }
        return candidatePaths(paramTainted, paramTaintedAlternatives,
                methodKey(method, ex) + "#" + slot);
    }

    /**
     * Connect a serialized proxy handler back to the explicit receiver of a
     * reflective Method.invoke whose Method object came from a typed collection.
     * The proxy itself is an external object, so this is intentionally a bounded
     * callback family rather than a fabricated ordinary call-graph edge.
     */
    private List<ChainHop> serializedProxyHandlerPath(MethodInfo handler, int depth,
                                                        Explore ex) {
        if (!support.isSerializedProxyHandler(handler)) {
            return null;
        }
        List<ChainHop> best = null;
        int inspected = 0;
        for (Node invoke : support.methodCollectionInvokeSites()) {
            if (cancellationRequested()) {
                return best;
            }
            if (inspected++ >= MAX_SERIALIZED_PROXY_CALLBACK_SITES) {
                bb.markIncomplete("FORWARD_SERIALIZED_PROXY_CALLBACK_SITE_CAP:"
                        + MAX_SERIALIZED_PROXY_CALLBACK_SITES);
                break;
            }
            MethodInfo caller = support.enclosingMethod(invoke);
            if (caller == null || methodKey(caller, ex).equals(methodKey(handler, ex))
                    || !reachable.contains(methodKey(caller, ex))) {
                continue;
            }
            ForwardOrigins.Result callerOrigins = origins(caller, ex);
            if (support.sinkPathProvablyUnreachable(caller, invoke.offset(), callerOrigins)) {
                continue;
            }
            Set<ValueOrigin> receivers = support.argOriginAtOrdinal(invoke, 0, callerOrigins);
            if (receivers.isEmpty()) {
                continue;
            }
            bb.markIncomplete("FORWARD_SERIALIZED_PROXY_CALLBACK_WILDCARD");
            for (ValueOrigin receiver : receivers) {
                if (!mayCarryTaint(receiver)) {
                    continue;
                }
                List<ChainHop> receiverPath = tainted(receiver, caller, depth + 1, ex);
                if (receiverPath == null || receiverPath.size() >= MAX_HOPS) {
                    if (receiverPath != null) {
                        bb.markIncomplete("FORWARD_HOP_CAP:" + MAX_HOPS);
                    }
                    continue;
                }
                List<ChainHop> candidate = appendMethodHop(receiverPath, caller, handler.owner(),
                        handler.name(), handler.descriptor(), HopKind.VIRTUAL_DISPATCH,
                        "serialized-proxy-handler", null);
                if (candidate == null) {
                    continue;
                }
                if (best == null || better(best, candidate)) {
                    best = candidate;
                }
            }
        }
        return best;
    }

    /**
     * Connect a serialized InvocationHandler to an interface call whose proxy object is
     * supplied by the surrounding object graph.  This is the external-proxy counterpart of
     * {@link #threadProxy(Node, MethodInfo, int, Explore)}: there is no
     * Proxy.newProxyInstance bytecode in the scan unit, so the callback is admitted only when
     * the handler is serializable, the call owner is a resolved interface, and the bounded
     * method-name interpreter accepts the requested callback name.
     */
    private List<ChainHop> serializedProxyInterfaceHandlerPath(MethodInfo handler, int depth,
                                                                 Explore ex) {
        if (!support.isSerializedProxyHandler(handler)) {
            return null;
        }
        List<ChainHop> best = null;
        int inspected = 0;
        String handlerKey = methodKey(handler, ex);
        for (Node call : support.serializedProxyInterfaceCallSites()) {
            if (cancellationRequested()) {
                return best;
            }
            if (inspected++ >= MAX_SERIALIZED_PROXY_INTERFACE_SITES) {
                bb.markIncomplete("FORWARD_SERIALIZED_PROXY_INTERFACE_SITE_CAP:"
                        + MAX_SERIALIZED_PROXY_INTERFACE_SITES);
                break;
            }
            if (!serializedProxyCallbackMayReach(handler, call.name(), -1)) {
                continue;
            }
            MethodInfo caller = support.enclosingMethod(call);
            String callerKey = caller == null ? "" : methodKey(caller, ex);
            if (caller == null || (!reachable.contains(callerKey) && !callerKey.equals(handlerKey))) {
                continue;
            }
            ForwardOrigins.Result callerOrigins = origins(caller, ex);
            if (support.sinkPathProvablyUnreachable(caller, call.offset(), callerOrigins)) {
                continue;
            }
            Set<ValueOrigin> receivers = support.argOriginAtOrdinal(call, -1, callerOrigins);
            if (receivers.isEmpty()) {
                continue;
            }
            bb.markIncomplete("FORWARD_SERIALIZED_PROXY_INTERFACE_WILDCARD");
            for (ValueOrigin receiver : ValueOriginOrder.sorted(receivers)) {
                if (!mayCarryTaint(receiver)) {
                    continue;
                }
                List<ChainHop> receiverPath = tainted(receiver, caller, depth + 1, ex);
                if (receiverPath == null || receiverPath.size() >= MAX_HOPS) {
                    if (receiverPath != null) {
                        bb.markIncomplete("FORWARD_HOP_CAP:" + MAX_HOPS);
                    }
                    continue;
                }
                List<ChainHop> candidate = appendMethodHop(receiverPath, caller, handler.owner(),
                        handler.name(), handler.descriptor(), HopKind.VIRTUAL_DISPATCH,
                        "serialized-proxy-interface", null);
                if (candidate != null && (best == null || better(best, candidate))) {
                    best = candidate;
                }
            }
        }
        return best;
    }

    /**
     * Map one Object[] element supplied to InvocationHandler.invoke back to an external
     * interface call argument.  The array index is recovered from the local CFG state; an
     * unknown index falls back to all arguments of that bounded call site.
     */
    private List<ChainHop> serializedProxyInterfaceArgumentPath(MethodInfo handler, int offset,
                                                                  ForwardOrigins.State state,
                                                                  int depth, Explore ex) {
        if (!support.isSerializedProxyHandler(handler) || state == null
                || state.stack().isEmpty()) {
            return null;
        }
        Integer arrayIndex = constantStackIndex(state);
        List<ChainHop> best = null;
        int inspected = 0;
        String handlerKey = methodKey(handler, ex);
        for (Node call : support.serializedProxyInterfaceCallSites()) {
            if (cancellationRequested()) {
                return best;
            }
            if (inspected++ >= MAX_SERIALIZED_PROXY_INTERFACE_SITES) {
                bb.markIncomplete("FORWARD_SERIALIZED_PROXY_INTERFACE_SITE_CAP:"
                        + MAX_SERIALIZED_PROXY_INTERFACE_SITES);
                break;
            }
            if (!serializedProxyCallbackMayReach(handler, call.name(), offset)) {
                continue;
            }
            MethodInfo caller = support.enclosingMethod(call);
            String callerKey = caller == null ? "" : methodKey(caller, ex);
            if (caller == null || (!reachable.contains(callerKey) && !callerKey.equals(handlerKey))) {
                continue;
            }
            ForwardOrigins.Result callerOrigins = origins(caller, ex);
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
                Set<ValueOrigin> values = support.argOriginAtOrdinal(call, ordinal, callerOrigins);
                for (ValueOrigin value : ValueOriginOrder.sorted(values)) {
                    if (cancellationRequested()) {
                        return best;
                    }
                    if (!mayCarryTaint(value)) {
                        continue;
                    }
                    List<ChainHop> argumentPath = tainted(value, caller, depth + 1, ex);
                    if (argumentPath == null) {
                        continue;
                    }
                    List<ChainHop> candidate = appendMethodHop(argumentPath, caller,
                            handler.owner(), handler.name(), handler.descriptor(),
                            HopKind.VIRTUAL_DISPATCH, "serialized-proxy-interface", ordinal);
                    if (candidate != null && (best == null || better(best, candidate))) {
                        best = candidate;
                    }
                }
            }
        }
        return best;
    }

    /** Cache the small method-name feasibility proof for an external proxy callback. */
    private Set<Integer> serializedProxyFeasibleOffsets(MethodInfo handler, String methodName) {
        if (handler == null || methodName == null || methodName.isBlank()) {
            return Set.of();
        }
        SerializedProxyInterfaceMetadataKey key = new SerializedProxyInterfaceMetadataKey(
                OriginSupport.methodKey(handler), methodName);
        Set<Integer> cached = serializedProxyInterfaceFeasibleOffsets.get(key);
        if (cached != null) {
            return cached;
        }
        Set<Integer> computed = ForwardEngine.proxyMethodFeasibleOffsets(handler,
                Set.of(methodName), support::cfg);
        Set<Integer> result = computed == null ? Set.of() : Set.copyOf(computed);
        serializedProxyInterfaceFeasibleOffsets.put(key, result);
        if (result.isEmpty()) {
            bb.markIncomplete("FORWARD_SERIALIZED_PROXY_INTERFACE_METADATA");
        }
        return result;
    }

    private boolean serializedProxyCallbackMayReach(MethodInfo handler, String methodName,
                                                      int offset) {
        Set<Integer> feasible = serializedProxyFeasibleOffsets(handler, methodName);
        // Empty metadata means the bounded interpreter could not establish a finite region.
        // Preserve soundness by retaining the callback wildcard; the completeness marker
        // makes the loss of precision visible to ranking and reports.
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

    /**
     * Resolve the feasible instruction region for a serialized InvocationHandler callback.
     * The handler is still a bounded wildcard because the proxy interface is external, but
     * the Method values observed by the in-artifact collection provide a finite discriminator.
     * If metadata cannot be recovered, callers deliberately keep the conservative
     * whole-method behavior and the completeness marker remains visible.
     */
    private boolean externalProxyCallbackAllows(MethodInfo method, int offset) {
        if (!support.isSerializedProxyHandler(method)) {
            return true;
        }
        boolean sawInterfaceCallback = false;
        for (Node call : support.serializedProxyInterfaceCallSites()) {
            sawInterfaceCallback = true;
            if (serializedProxyCallbackMayReach(method, call.name(), offset)) {
                return true;
            }
        }
        if (sawInterfaceCallback) {
            // A resolved external interface site set is a finite discriminator.  If none of
            // its method-name branches can reach this instruction, the instruction belongs to
            // an unreachable proxy callback branch and must not inherit another branch's taint.
            return false;
        }
        String key = OriginSupport.methodKey(method);
        SerializedProxyCallbackMetadata metadata = serializedProxyCallbackMetadata.get(key);
        if (metadata == null) {
            LinkedHashSet<String> names = new LinkedHashSet<>();
            for (Node target : support.methodCollectionTargetMethods()) {
                if (target == null || target.name() == null || target.name().isBlank()) {
                    continue;
                }
                if (names.size() >= MAX_SERIALIZED_PROXY_CALLBACK_NAMES) {
                    bb.markIncomplete("FORWARD_SERIALIZED_PROXY_CALLBACK_NAME_CAP:"
                            + MAX_SERIALIZED_PROXY_CALLBACK_NAMES);
                    break;
                }
                names.add(target.name());
            }
            if (names.isEmpty()) {
                metadata = new SerializedProxyCallbackMetadata(Set.of(), false);
            } else {
                ProxyMetadata resolved = proxyMethodMetadata(method, names, support::cfg);
                if (!resolved.complete()) {
                    bb.markIncomplete("FORWARD_SERIALIZED_PROXY_CALLBACK_METADATA");
                }
                metadata = new SerializedProxyCallbackMetadata(resolved.feasibleOffsets(),
                        resolved.complete());
            }
            serializedProxyCallbackMetadata.put(key, metadata);
        }
        // Unknown or empty metadata must not create a false negative.  The wildcard path is
        // intentionally retained until a complete finite callback region is available.
        return !metadata.complete() || metadata.feasibleOffsets().isEmpty()
                || metadata.feasibleOffsets().contains(offset);
    }

    private List<ChainHop> taintedCallResult(long callNodeId, MethodInfo method, int depth, Explore ex) {
        if (callNodeId < 0) {
            return null;
        }
        Node call = support.callNode(callNodeId);
        if (call == null) {
            return null;
        }
        Object callOffset = call.prop("offset");
        if (callOffset instanceof Integer offset && !externalProxyCallbackAllows(method, offset)) {
            return null;
        }
        CallRules rules = callRules(call);
        Rule.SourceRule source = rules.source();
        if (isDeserializationSource(source)) {
            List<ChainHop> inputPath = sourceInputPath(source, call, method, depth, ex);
            if (inputPath == null) {
                // A constrained source is a secondary object-graph boundary.  Its result
                // cannot become a fresh root until the declared byte[]/receiver/argument
                // is already backed by a real deserialization source.
                return null;
            }
            if (!source.tainted().isEmpty()) {
                return sourceBridgePath(inputPath, method, call);
            }
            String entryKind = source.bridge() == null ? "deserialize" : source.bridge();
            ChainHop entryHop = new ChainHop(method.owner(), method.name(),
                    method.owner(), method.name(), HopKind.ENTRY, null, entryKind,
                    method.descriptor(), null);
            return List.of(entryHop);
        }
        if (OriginSupport.isOisRead(call)
                && (!isJdkOwner(method.owner()) || isAdmittedJdkCallback(method, ex))) {
            // An ObjectInputStream read performed by an admitted platform callback is still
            // attacker-controlled object-graph data.  The ordinary non-JDK source rule is not
            // enough here because HashMap/IdentityHashMap/etc. implement their callback in the
            // platform class itself.  Keep the callback as the provenance root rather than
            // creating a second global source; callbacks not admitted by OriginSupport remain
            // intentionally opaque.
            String entryKind = bb.ruleEngine().matchingEntry(method.owner(), method.name(),
                    method.descriptor()).map(Rule.MagicEntryRule::entryKind)
                    .orElse("deserialization");
            ChainHop entryHop = new ChainHop(method.owner(), method.name(),
                    method.owner(), method.name(), HopKind.ENTRY, null, entryKind,
                    method.descriptor(), null);
            return List.of(entryHop);
        }
        ForwardOrigins.State state = stateAt(method, (Integer) call.prop("offset"), ex);
        if (state == null) {
            return null;
        }
        boolean proxyReceiver = isProxyReceiver(call, method, state, ex);
        // 驱动输入侧事实（参数/receiver、lambda、代理/反射分派），但不要把输入路径
        // 直接当成返回值。返回值只能来自声明式 return model、已收敛的被调方法
        // return summary，或专门的 source 语义。
        if (!proxyReceiver) {
            propagateCallArgs(call, method, depth + 1, ex);
        }
        List<ChainHop> best = null;
        List<ChainHop> proxyReturn = proxyReturnPath(call, method, depth, ex);
        if (proxyReturn != null) {
            best = proxyReturn;
        }
        if (proxyReceiver) {
            // A JDK proxy never dispatches to the implementation class recorded by the
            // ordinary interface call graph.  Falling through to those return summaries
            // turns a handler branch that returns a constant (or throws) into a false
            // tainted result.  The handler-specific model above is the only valid return
            // source; threadProxy still materializes the handler receiver for side effects.
            if (options.threadProxy()) {
                threadProxy(call, method, depth, ex);
            }
            return best;
        }
        List<ChainHop> arrayReadPath = taintedReflectiveArrayRead(call, method, depth, ex);
        if (arrayReadPath != null && (best == null || arrayReadPath.size() < best.size())) {
            best = arrayReadPath;
        }
        String kind = call.invokeKind();
        boolean calleeStatic = isStaticLike(kind);
        // model 规则（声明式摘要）：return←src 透传、this←argN 容器投毒
        Rule.ModelRule model = rules.model();
        if (model != null) {
            // A broad supertype model is a fallback for an unresolved implementation.  If
            // the call already has a concrete return summary, prefer that method-body fact:
            // MapProxy#get is the canonical example where Map.get return←this would erase
            // the serialized map field that the concrete implementation actually reads.
            // Container side effects (this←argN) still apply even when the return model is
            // suppressed.  Exact API models remain authoritative for the current call and
            // can carry a value through an implementation whose global summary came from a
            // different caller or recursive overload.
            boolean allowReturnModel = isExactModel(model, call)
                    || !hasResolvedReturnSummary(call);
            best = applyModel(model, call, method, depth, best, ex, allowReturnModel);
        }
        for (Edge edge : call.out()) {
            if (edge.type() != EdgeType.INVOKES && edge.type() != EdgeType.DISPATCHES) {
                continue;
            }
            List<ChainHop> returnPath = returnTainted.get(methodNodeKey(edge.to()));
            if (returnPath != null) {
                // A return summary may already contain this same caller/target context when
                // the value was learned through a serialized field plus a container read
                // (for example Map.get inside a method that is itself the selected receiver).
                // Reusing that summary is safe only under the explicit context predicate;
                // otherwise the cycle guard remains strict.
                List<ChainHop> candidate = appendReturnHop(returnPath, method, edge, true);
                if (candidate != null && (best == null || better(best, candidate))) {
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
     * Append a call edge to a return summary, with a bounded context-reuse fallback.  A
     * method-level return fact can already contain the same target method when it was learned
     * through a recursive container/adapter path.  Re-appending that target is correctly
     * rejected by the cycle guard, but dropping the summary entirely loses a valid return
     * value.  Reuse the already materialized path only in that case and expose the loss of
     * context sensitivity as an explicit completeness reason.
     */
    private List<ChainHop> appendReturnHop(List<ChainHop> returnPath, MethodInfo caller,
                                            Edge edge) {
        return appendReturnHop(returnPath, caller, edge, false);
    }

    /**
     * Consumer-side alternative expansion may reuse a summary that already contains the same
     * target edge. Keep this out of the primary fact scheduler so context-insensitive summaries
     * do not recursively amplify the global frontier.
     */
    private List<ChainHop> appendReturnHop(List<ChainHop> returnPath, MethodInfo caller,
                                            Edge edge, boolean allowContextReuse) {
        if (returnPath == null || caller == null || edge == null) {
            return null;
        }
        List<ChainHop> candidate = hopTo(returnPath, caller, edge.to().owner(), edge.to().name(),
                edge.to().descriptor(), edge.type());
        if (candidate != null) {
            return candidate;
        }
        if (allowContextReuse && containsMethodTarget(returnPath, edge.to().owner(),
                edge.to().name(), edge.to().descriptor())
                && containsCallContext(returnPath, caller, edge.to())) {
            bb.markIncomplete("FORWARD_RETURN_CONTEXT_REUSE");
            return returnPath;
        }
        return null;
    }

    /** Require the reused summary to have been learned through this same caller/target edge. */
    private static boolean containsCallContext(List<ChainHop> path, MethodInfo caller,
                                                Node target) {
        if (path == null || caller == null || target == null) {
            return false;
        }
        for (ChainHop hop : path) {
            if (hop.kind() == HopKind.FIELD_FLOW) {
                continue;
            }
            if (caller.owner().equals(hop.fromOwner()) && caller.name().equals(hop.fromName())
                    && target.owner().equals(hop.toOwner()) && target.name().equals(hop.toName())
                    && target.descriptor().equals(hop.desc())) {
                return true;
            }
        }
        return false;
    }

    /** Whether a model names this call directly rather than matching through a supertype. */
    private static boolean isExactModel(Rule.ModelRule model, Node call) {
        if (model == null || call == null || model.call() == null) {
            return false;
        }
        var matcher = model.call();
        if (matcher.owner().isRegex() || !matcher.owner().pattern().equals(call.owner())
                || matcher.name().isRegex() || !matcher.name().pattern().equals(call.name())) {
            return false;
        }
        return matcher.descriptor() == null || (!matcher.descriptor().isRegex()
                && matcher.descriptor().pattern().equals(call.descriptor()));
    }

    /** Resolve the input precondition of a data-declared secondary source. */
    private List<ChainHop> sourceInputPath(Rule.SourceRule source, Node call, MethodInfo method,
                                           int depth, Explore ex) {
        if (source == null || source.tainted() == null || source.tainted().isEmpty()) {
            return List.of();
        }
        List<ChainHop> best = null;
        for (List<ChainHop> candidate : sourceInputPaths(source, call, method, depth, ex)) {
            if (best == null || better(best, candidate)) {
                best = candidate;
            }
        }
        return best;
    }

    /** Return all bounded provenances that satisfy a secondary source's tainted positions. */
    private List<List<ChainHop>> sourceInputPaths(Rule.SourceRule source, Node call,
                                                    MethodInfo method, int depth, Explore ex) {
        if (source == null || source.tainted() == null || source.tainted().isEmpty()
                || call == null || method == null) {
            return List.of();
        }
        ForwardOrigins.State state = stateAt(method, (Integer) call.prop("offset"), ex);
        if (state == null) {
            return List.of();
        }
        int parameterCount = Descriptor.paramCount(call.descriptor());
        List<List<ChainHop>> result = new ArrayList<>();
        for (Rule.TaintedPos position : source.tainted()) {
            int stackIndex;
            if (position instanceof Rule.TaintedPos.Arg arg) {
                int fromTop = parameterCount - 1 - arg.index();
                stackIndex = state.stack().size() - 1 - fromTop;
            } else {
                stackIndex = state.stack().size() - 1 - parameterCount;
            }
            if (stackIndex < 0 || stackIndex >= state.stack().size()) {
                continue;
            }
            for (ValueOrigin origin : state.stack().get(stackIndex).origins()) {
                if (!mayCarryTaint(origin)) {
                    continue;
                }
                result.addAll(taintedCandidates(origin, method, depth + 1, ex));
            }
        }
        return distinctBestPaths(result);
    }

    /** Keep the secondary boundary visible while retaining the outer source provenance. */
    private List<ChainHop> sourceBridgePath(List<ChainHop> inputPath, MethodInfo method, Node call) {
        if (inputPath == null || inputPath.size() >= MAX_HOPS) {
            bb.markIncomplete("FORWARD_HOP_CAP:" + MAX_HOPS);
            return null;
        }
        return appendMethodHop(inputPath, method, call.owner(), call.name(), call.descriptor(),
                HopKind.DIRECT_CALL, "bridge-source-deserialize", null);
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
            if (cancellationRequested()) {
                return;
            }
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
     * 这是高频调度路径，只传播 primary summary；有限 frontier 由 sink 和状态性 effect
     * 消费点单独调用 taintedCandidates()，避免在每个普通调用边上递归展开替代来源。
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
                    if (cancellationRequested()) {
                        return best;
                    }
                    if (!mayCarryTaint(receiver)) {
                        continue;
                    }
                    for (List<ChainHop> receiverPath : primaryCandidate(receiver, method, depth, ex)) {
                        if (cancellationRequested()) {
                            return best;
                        }
                        for (Edge edge : call.out()) {
                            if (edge.type() == EdgeType.INVOKES || edge.type() == EdgeType.DISPATCHES) {
                                if (!support.receiverMayDispatchTo(call, method, edge.to().owner(),
                                        edge.to().name(), edge.to().descriptor(), originResult)) {
                                    continue;
                                }
                                String targetKey = methodNodeKey(edge.to());
                                admitDynamicDispatchTarget(targetKey,
                                        isJavaSerializationValue(receiverPath));
                                if (!scheduledMethod(targetKey)) {
                                    continue;
                                }
                                List<ChainHop> targetPath = hopTo(receiverPath, method,
                                        edge.to().owner(), edge.to().name(),
                                        edge.to().descriptor(), edge.type());
                                if (targetPath == null) {
                                    continue;
                                }
                                // This is a selected receiver value for one concrete target,
                                // not proof that every instance of the target class is tainted.
                                // Keep it on the target method's receiver slot. Class-level
                                // this facts remain the fallback for real serialization entry
                                // seeds and inherited callbacks, while method-local facts avoid
                                // cross-object provenance pollution in nested gadget paths.
                                addParam(edge.to().owner(), edge.to().name(),
                                        edge.to().descriptor(), 0, targetPath);
                            }
                        }
                        if (best == null || better(best, receiverPath)) {
                            best = receiverPath;
                        }
                    }
                }
            }
            // A serialization callback is often invoked for a value whose return value is
            // ignored (hashCode/equals/compareTo/toString). The ordinary return-demand path
            // therefore never gets a chance to expand the receiver's concrete implementation.
            // Reuse the same bounded CHA resolver here so ignored callback results can still
            // reach an object-graph sink. This only runs for an already tainted receiver.
            if (options.expandInterfaces() && best != null && !receiverOrigins.isEmpty()) {
                expandInterfaces(call, method, depth, true, ex);
            }
        }
        // 实参污点传播（按被调方法实参槽遍历，wide 参数占 2 槽）
        List<Integer> argSlots = Descriptor.argSlots(call.descriptor(), calleeStatic);
        int paramCount = calleeStatic ? argSlots.size() : Math.max(0, argSlots.size() - 1);
        int slot = 0;
        for (int i = 0; i < argSlots.size(); i++) {
            if (cancellationRequested()) {
                return best;
            }
            int argumentOrdinal = calleeStatic ? i : i - 1;
            for (ValueOrigin argOrigin : stackOriginsAt(state, paramCount, argumentOrdinal)) {
                if (cancellationRequested()) {
                    return best;
                }
                // lambda 绑定（结构性，与污点无关）：实参为 indy 结果时，记录被调方法的该槽位
                // 将持有 lambda 实现方法——消费端在被调方法体内经此 receiver 调接口方法时定向分发
                bindLambdaArg(argOrigin, call, slot);
                if (!mayCarryTaint(argOrigin)) {
                    continue;
                }
                for (List<ChainHop> argPath : primaryCandidate(argOrigin, method, depth, ex)) {
                    if (cancellationRequested()) {
                        return best;
                    }
                    if (best == null || better(best, argPath)) {
                        best = argPath;
                    }
                    for (Edge edge : call.out()) {
                        if (edge.type() == EdgeType.INVOKES || edge.type() == EdgeType.DISPATCHES) {
                            if (!scheduledMethod(methodNodeKey(edge.to()))) {
                                continue;
                            }
                            if (!support.receiverMayDispatchTo(call, method, edge.to().owner(),
                                    edge.to().name(), edge.to().descriptor(), originResult)) {
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
                                if (cancellationRequested()) {
                                    return best;
                                }
                                if (!(receiver instanceof ValueOrigin.Param rp)) {
                                    continue;
                                }
                                for (LambdaBind bind : lambdaBinds.getOrDefault(
                                        methodKey(method, ex) + "#" + rp.slot(), List.of())) {
                                    addParam(bind.implOwner(), bind.implName(), bind.implDesc(),
                                            implArgSlotOf(bind, call, ordinal), argPath);
                                }
                            }
                        }
                    }
                    if (options.expandInterfaces()) {
                        expandParams(call, method, slot, argPath);
                    }
                    // A lambda object is created by the preceding invokedynamic factory,
                    // not by the interface declaration reached through CHA.  Map the SAM
                    // argument directly to the implementation method so a direct
                    // lambda call remains visible even when the synthetic class is absent.
                    if (!calleeStatic) {
                        propagateLambdaSamArgument(call, method, depth, argumentOrdinal, argPath,
                                receiverOrigins);
                    }
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
            if (cancellationRequested()) {
                return;
            }
            if (!(receiver instanceof ValueOrigin.CallResult result) || result.callNodeId() < 0) {
                continue;
            }
            Node factory = support.callNode(result.callNodeId());
            List<LambdaShape> shapes = lambdaShapes(factory);
            if (shapes.isEmpty()) {
                continue;
            }
            for (Edge edge : factory.out()) {
                if (cancellationRequested()) {
                    return;
                }
                if (edge.type() != EdgeType.LAMBDA) {
                    continue;
                }
                MethodInfo implementation = support.methodOf(edge.to().owner(), edge.to().name(),
                        edge.to().descriptor());
                if (implementation == null) {
                    continue;
                }
                LambdaShape shape = shapeFor(shapes, edge.to());
                if (shape == null) {
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
        List<LambdaShape> shapes = lambdaShapes(factory);
        if (shapes.isEmpty()) {
            return best;
        }
        ForwardOrigins.State state = originResult.stateBefore().get(factory.offset());
        if (state == null) {
            return best;
        }
        int capturedCount = Descriptor.paramCount(factory.descriptor());
        for (Edge edge : factory.out()) {
            if (cancellationRequested()) {
                return best;
            }
            if (edge.type() != EdgeType.LAMBDA) {
                continue;
            }
            MethodInfo implementation = support.methodOf(edge.to().owner(), edge.to().name(),
                    edge.to().descriptor());
            if (implementation == null) {
                continue;
            }
            LambdaShape shape = shapeFor(shapes, edge.to());
            if (shape == null) {
                continue;
            }
            boolean receiverCapture = lambdaHasCapturedReceiver(shape.implementation().tag());
            int explicitCaptured = Math.max(0, Descriptor.paramCount(implementation.descriptor())
                    - Descriptor.paramCount(shape.samDescriptor()));
            for (int captureOrdinal = 0; captureOrdinal < capturedCount; captureOrdinal++) {
                if (cancellationRequested()) {
                    return best;
                }
                Set<ValueOrigin> origins = stackOriginsAt(state, capturedCount, captureOrdinal);
                for (ValueOrigin captured : origins) {
                    if (cancellationRequested()) {
                        return best;
                    }
                    if (!mayCarryTaint(captured)) {
                        continue;
                    }
                    List<ChainHop> capturedPath = tainted(captured, caller, depth + 1, ex);
                    if (capturedPath == null) {
                        continue;
                    }
                    if (receiverCapture && captureOrdinal == 0) {
                        addParam(implementation.owner(), implementation.name(),
                                implementation.descriptor(), 0,
                                lambdaHop(capturedPath, caller, implementation, "lambda-capture"));
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

    private List<LambdaShape> lambdaShapes(Node factory) {
        if (factory == null || !"DYNAMIC".equals(factory.invokeKind())) {
            return List.of();
        }
        Object value = factory.prop("indy");
        if (!(value instanceof InvokeDynamicRef indy)
                || indy.bootstrap() == null
                || !"java/lang/invoke/LambdaMetafactory".equals(indy.bootstrap().owner())
                || !("metafactory".equals(indy.bootstrap().name())
                || "altMetafactory".equals(indy.bootstrap().name()))) {
            return List.of();
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
            return List.of();
        }
        List<LambdaShape> result = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        for (int i = 1; i < indy.bootstrapArgs().size(); i++) {
            Object argument = indy.bootstrapArgs().get(i);
            if (!(argument instanceof HandleRef handle)) {
                continue;
            }
            String key = handle.tag() + "|" + handle.owner() + "#"
                    + handle.name() + handle.descriptor();
            if (seen.add(key)) {
                result.add(new LambdaShape(handle, samDescriptor));
            }
        }
        return result.isEmpty() ? List.of() : List.copyOf(result);
    }

    private static LambdaShape shapeFor(List<LambdaShape> shapes, Node target) {
        if (shapes == null || target == null) {
            return null;
        }
        for (LambdaShape shape : shapes) {
            HandleRef handle = shape.implementation();
            if (handle.owner().equals(target.owner()) && handle.name().equals(target.name())
                    && handle.descriptor().equals(target.descriptor())) {
                return shape;
            }
        }
        // Some hierarchy resolutions replace an inherited handle owner with the actual
        // declaration owner. A single shape can still be used as a conservative fallback;
        // for multiple shapes an unmatched edge is intentionally left unresolved.
        return shapes.size() == 1 ? shapes.get(0) : null;
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

    private List<ChainHop> lambdaHop(List<ChainHop> parent, MethodInfo from,
                                     MethodInfo implementation, String reason) {
        if (parent == null) {
            return null;
        }
        return appendMethodHop(parent, from, implementation.owner(), implementation.name(),
                implementation.descriptor(), HopKind.LAMBDA, reason, null);
    }

    /**
     * Same semantic precondition as propagateCallArgs: a non-constant origin or an
     * invokedynamic lambda result. The CFG result is already available in processEffects,
     * so this guard avoids another abstract-state lookup and preserves lambda binding.
     */
    private boolean hasRelevantCallInputs(Node call, MethodInfo method,
                                          ForwardOrigins.Result originResult,
                                          Map<ValueOrigin, Boolean> relevantOrigins) {
        ForwardOrigins.State state = originResult.stateBefore().get(call.offset());
        if (state == null) {
            return false;
        }
        boolean calleeStatic = isStaticLike(call.invokeKind());
        if (!calleeStatic) {
            int receiverDepth = state.stack().size() - 1 - Descriptor.paramCount(call.descriptor());
            if (receiverDepth >= 0 && receiverDepth < state.stack().size()
                    && state.stack().get(receiverDepth).origins().stream()
                    .anyMatch(origin -> relevantCallOrigin(origin, method, originResult,
                            relevantOrigins))) {
                return true;
            }
        }
        List<Integer> argSlots = Descriptor.argSlots(call.descriptor(), calleeStatic);
        int paramCount = calleeStatic ? argSlots.size() : Math.max(0, argSlots.size() - 1);
        int slot = 0;
        for (int i = 0; i < argSlots.size(); i++) {
            int argumentOrdinal = calleeStatic ? i : i - 1;
            if (stackOriginsAt(state, paramCount, argumentOrdinal).stream()
                    .anyMatch(origin -> relevantCallOrigin(origin, method, originResult,
                            relevantOrigins))) {
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
                                       ForwardOrigins.Result originResult,
                                       Map<ValueOrigin, Boolean> relevantOrigins) {
        Boolean cached = relevantOrigins.get(origin);
        if (cached != null) {
            return cached;
        }
        boolean relevant = isLambdaResult(origin) || mayReachTaint(origin, method,
                originResult, new HashSet<>(), relevantOrigins);
        relevantOrigins.put(origin, relevant);
        return relevant;
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
                                  Set<Integer> visiting,
                                  Map<ValueOrigin, Boolean> relevanceMemo) {
        if (cancellationRequested()) {
            return true;
        }
        Boolean cached = relevanceMemo.get(origin);
        if (cached != null) {
            return cached;
        }
        if (origin instanceof ValueOrigin.Constant || origin instanceof ValueOrigin.Unknown) {
            relevanceMemo.put(origin, false);
            return false;
        }
        if (!(origin instanceof ValueOrigin.Insn insn)) {
            // Param, FieldRead and CallResult may be connected to a fact or a semantic model;
            // do not guess them away here.  Lambda results are also retained by isLambdaResult.
            relevanceMemo.put(origin, true);
            return true;
        }
        if (insn.offset() < 0 || insn.offset() >= method.instructions().size()) {
            relevanceMemo.put(origin, true);
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
                relevanceMemo.put(origin, true);
                return true;
            }
            if (producer.op() == Op.NEWARRAY || producer.op() == Op.ANEWARRAY
                    || producer.op() == Op.MULTIANEWARRAY) {
                Set<ValueOrigin> elements = originResult.arrayElements()
                        .getOrDefault(insn, Set.of());
                for (ValueOrigin element : elements) {
                    if (cancellationRequested()) {
                        return true;
                    }
                    if (mayReachTaint(element, method, originResult, visiting,
                            relevanceMemo)) {
                        relevanceMemo.put(origin, true);
                        return true;
                    }
                }
                relevanceMemo.put(origin, false);
                return false;
            }
            ForwardOrigins.State state = originResult.stateBefore().get(insn.offset());
            if (state == null) {
                relevanceMemo.put(origin, true);
                return true;
            }
            int consumed = OriginSupport.consumedCount(producer.op());
            int start = Math.max(0, state.stack().size() - consumed);
            for (int i = start; i < state.stack().size(); i++) {
                for (ValueOrigin operand : state.stack().get(i).origins()) {
                    if (cancellationRequested()) {
                        return true;
                    }
                    if (mayReachTaint(operand, method, originResult, visiting,
                            relevanceMemo)) {
                        relevanceMemo.put(origin, true);
                        return true;
                    }
                }
            }
            relevanceMemo.put(origin, false);
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
                                      List<ChainHop> best, Explore ex, boolean allowReturnModel) {
        List<Map.Entry<String, List<String>>> actions = new ArrayList<>(model.actions().entrySet());
        actions.sort(Map.Entry.comparingByKey());
        for (Map.Entry<String, List<String>> action : actions) {
            for (String src : action.getValue()) {
                List<ChainHop> srcPath = modelSourcePath(src, call, method, depth, ex);
                if (srcPath == null) {
                    continue;
                }
                if ("return".equals(action.getKey()) && allowReturnModel) {
                    // A model is a return candidate, not a fallback that is consulted only
                    // when the bytecode summary is empty.  A method body may contain an
                    // unrelated overload/branch whose shortest return path otherwise hides
                    // the declared data-flow contract (for example Convert.convert's
                    // recursive overloads).  Use the same deterministic provenance ordering
                    // as ordinary return summaries after adding the call hop.
                    // 透传也须经该调用的规范跳衔接——裸拼 srcPath 会造成链跳类型对不上，
                    // 被 chain-validator 的类型流误拒（历史回归：CC BeanMap 链全灭）
                    List<ChainHop> candidate = hopTo(srcPath, method, call.owner(), call.name(),
                            call.descriptor(), EdgeType.INVOKES);
                    if (candidate != null && (best == null || better(best, candidate))) {
                        best = candidate;
                    }
                } else if ("this".equals(action.getKey())) {
                    addModelReceiver(call, method, srcPath);
                }
            }
        }
        return best;
    }

    /**
     * Apply a model's receiver side effect to the selected call target.  A class-wide
     * receiver fact is only a compatibility fallback for a call with no materialized target;
     * widening every model consumer to all methods of the owner class is particularly costly
     * for collection interfaces in dependency jars.
     */
    private void addModelReceiver(Node call, MethodInfo caller, List<ChainHop> sourcePath) {
        boolean selected = false;
        for (Edge edge : call.out()) {
            if (edge.type() != EdgeType.INVOKES && edge.type() != EdgeType.DISPATCHES) {
                continue;
            }
            List<ChainHop> targetPath = hopTo(sourcePath, caller, edge.to().owner(),
                    edge.to().name(), edge.to().descriptor(), edge.type());
            if (targetPath == null) {
                continue;
            }
            selected = true;
            addParam(edge.to().owner(), edge.to().name(), edge.to().descriptor(), 0, targetPath);
        }
        if (!selected) {
            addThis(call.owner(), sourcePath, false);
        }
    }

    /** Whether a loaded dispatch target has already produced a concrete return summary. */
    private boolean hasResolvedReturnSummary(Node call) {
        if (call == null) {
            return false;
        }
        for (Edge edge : call.out()) {
            if (edge.type() != EdgeType.INVOKES && edge.type() != EdgeType.DISPATCHES) {
                continue;
            }
            if (returnTainted.containsKey(methodNodeKey(edge.to()))) {
                return true;
            }
        }
        return false;
    }

    /** model 动作来源位置的污点路径：this、argN 或有限的 element(this/argN)。 */
    private List<ChainHop> modelSourcePath(String src, Node call, MethodInfo method, int depth,
                                           Explore ex) {
        if (src == null || call == null || method == null) {
            return null;
        }
        ForwardOrigins.Result originResult = origins(method, ex);
        ForwardOrigins.State state = originResult.stateBefore().get((Integer) call.prop("offset"));
        if (state == null) {
            return null;
        }
        for (ValueOrigin origin : modelSourceOrigins(src, call, method, originResult, state)) {
            List<ChainHop> path = tainted(origin, method, depth + 1, ex);
            if (path != null) {
                return path;
            }
        }
        return null;
    }

    /** Return all bounded receiver/argument provenances used by a return model. */
    private List<List<ChainHop>> modelSourcePaths(String src, Node call, MethodInfo method,
                                                   int depth, Explore ex) {
        if (src == null || call == null || method == null) {
            return List.of();
        }
        ForwardOrigins.Result originResult = origins(method, ex);
        ForwardOrigins.State state = originResult.stateBefore().get((Integer) call.prop("offset"));
        if (state == null) {
            return List.of();
        }
        List<List<ChainHop>> result = new ArrayList<>();
        for (ValueOrigin origin : modelSourceOrigins(src, call, method, originResult, state)) {
            result.addAll(taintedCandidates(origin, method, depth + 1, ex));
        }
        return distinctBestPaths(result);
    }

    /** Resolve one declarative model source to a bounded set of forward origins. */
    private List<ValueOrigin> modelSourceOrigins(String source, Node call, MethodInfo method,
                                                 ForwardOrigins.Result result,
                                                 ForwardOrigins.State state) {
        ModelSource modelSource = ModelSource.parse(source);
        if (modelSource == null) {
            return List.of();
        }
        Set<ValueOrigin> origins = new LinkedHashSet<>();
        if (modelSource.receiver()) {
            if (isStaticLike(call.invokeKind())) {
                return List.of();
            }
            int receiverDepth = state.stack().size() - 1 - Descriptor.paramCount(call.descriptor());
            if (receiverDepth < 0 || receiverDepth >= state.stack().size()) {
                return List.of();
            }
            origins.addAll(state.stack().get(receiverDepth).origins());
        } else {
            Integer ordinal = modelSource.argumentOrdinal();
            if (ordinal == null) {
                return List.of();
            }
            List<Integer> argSlots = Descriptor.argSlots(call.descriptor(),
                    isStaticLike(call.invokeKind()));
            int slot = 0;
            for (int i = 0; i < argSlots.size(); i++) {
                if (i == ordinal) {
                    origins.addAll(support.argOriginAt(call, method, slot, result));
                    break;
                }
                slot += argSlots.get(i);
            }
        }
        if (!modelSource.element()) {
            return ValueOriginOrder.sorted(origins);
        }
        Set<ValueOrigin> elements = new LinkedHashSet<>();
        for (ValueOrigin origin : ValueOriginOrder.sorted(origins)) {
            elements.addAll(ContainerElementSources.resolve(origin, result));
        }
        return ValueOriginOrder.sorted(elements);
    }

    /** 字段读污点：程序字段事实；回退——反序列化对象（thisTainted 类）的全部实例字段可控。 */
    private List<ChainHop> taintedFieldRead(ValueOrigin.FieldRead f, MethodInfo method,
                                            int depth, Explore ex) {
        // A non-transient instance field of a serializable object is part of that
        // object's serialized state. Prefer the concrete receiver provenance and keep the
        // field boundary visible; a class-wide handler wildcard can otherwise replace a
        // MapProxy value with an unrelated InvocationHandler's shortest path.
        List<ChainHop> serializedField = serializedFieldPath(f, method, depth, ex);
        if (serializedField != null) {
            return serializedField;
        }
        List<ChainHop> path = f.descriptor() == null || f.descriptor().isBlank()
                ? fieldTaintedByName.get(fieldNameKey(f.owner(), f.field(), f.isStatic()))
                : fieldTainted.get(fieldKey(f.owner(), f.field(), f.descriptor(), f.isStatic()));
        if (path != null) {
            return path;
        }
        // If the concrete receiver is unavailable, retain the bounded external callback
        // fallback for a serialized InvocationHandler. This is intentionally after the
        // receiver-derived field path so it cannot cross-contaminate sibling handlers.
        if (receiverIsUnknown(f.receiver())) {
            MethodInfo serializedHandler = serializedProxyHandlerForOwner(f.owner());
            if (serializedHandler != null) {
                List<ChainHop> external = serializedProxyHandlerPath(serializedHandler, depth, ex);
                if (external != null) {
                    return external;
                }
            }
            if (method != null && support.isSerializedProxyHandler(method)) {
                List<ChainHop> external = serializedProxyHandlerPath(method, depth, ex);
                if (external != null) {
                    return external;
                }
            }
        }
        // A concrete receiver with no proven provenance is not interchangeable with an
        // arbitrary instance of the same class.  The class-level fallback remains only for
        // an unknown receiver; otherwise it would let an unrelated lifecycle root replace
        // the serialized object field path and hide the real container flow.
        return f.isStatic() || !receiverIsUnknown(f.receiver()) ? null : thisTainted.get(f.owner());
    }

    /**
     * Recover the serialized-state provenance of an instance field from its concrete
     * receiver. The field is not treated as an unconditional global source: the receiver
     * must already be backed by a deserialization entry or an admitted external callback.
     */
    private List<ChainHop> serializedFieldPath(ValueOrigin.FieldRead field, MethodInfo method,
                                                int depth, Explore ex) {
        List<List<ChainHop>> paths = serializedFieldPaths(field, method, depth, ex);
        return paths.isEmpty() ? null : paths.get(0);
    }

    /**
     * Recover all bounded receiver provenances for a serialized field.  A single class-level
     * receiver summary is insufficient for nested object graphs: the same field class can be
     * reached from multiple serialized containers, and selecting only the shortest one can
     * hide the container callback that actually supplies the field value.  The recursive
     * value frontier is finite and the normal hop bound stops self-referential field graphs.
     */
    private List<List<ChainHop>> serializedFieldPaths(ValueOrigin.FieldRead field,
                                                       MethodInfo method, int depth,
                                                       Explore ex) {
        if (field == null || field.isStatic() || method == null
                || !isSerializedField(field.owner(), field.field())) {
            return List.of();
        }
        if (depth >= MAX_DEPTH) {
            bb.markIncomplete("FORWARD_HOP_CAP:" + MAX_HOPS);
            return List.of();
        }
        List<List<ChainHop>> result = new ArrayList<>();
        List<List<ChainHop>> receiverPaths = support.isSerializedProxyHandler(method)
                && field.receiver() instanceof ValueOrigin.Param receiver
                && receiver.slot() == 0
                ? serializedProxyInterfaceReceiverPaths(field, method, depth, ex)
                : taintedCandidates(field.receiver(), method, depth + 1, ex);
        for (List<ChainHop> receiverPath : receiverPaths) {
            if (receiverPath == null) {
                continue;
            }
            if (receiverPath.size() >= MAX_HOPS) {
                bb.markIncomplete("FORWARD_HOP_CAP:" + MAX_HOPS);
                continue;
            }
            if (containsSerializedFieldFlow(receiverPath, method, field)) {
                bb.markIncomplete("FORWARD_FIELD_CYCLE_CUT");
                continue;
            }
            List<ChainHop> path = new ArrayList<>(receiverPath);
            path.add(new ChainHop(method.owner(), method.name(), method.owner(), method.name(),
                    HopKind.FIELD_FLOW, field.field(), "serialized-field", field.descriptor(), null,
                    field.owner()));
            result.add(List.copyOf(path));
        }
        return distinctBestPaths(result);
    }

    /**
     * Resolve the receiver of a handler field only through callback names whose feasible CFG
     * region contains this particular field read.  Keeping the branch discriminator at the
     * field boundary avoids turning an unrelated {@code invokeSink} branch into a source when
     * the only external callback actually invokes another interface method.
     */
    private List<List<ChainHop>> serializedProxyInterfaceReceiverPaths(
            ValueOrigin.FieldRead field, MethodInfo handler, int depth, Explore ex) {
        List<List<ChainHop>> paths = new ArrayList<>();
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
            return List.of();
        }
        int inspected = 0;
        String handlerKey = methodKey(handler, ex);
        for (Node call : support.serializedProxyInterfaceCallSites()) {
            if (cancellationRequested()) {
                break;
            }
            if (inspected++ >= MAX_SERIALIZED_PROXY_INTERFACE_SITES) {
                bb.markIncomplete("FORWARD_SERIALIZED_PROXY_INTERFACE_SITE_CAP:"
                        + MAX_SERIALIZED_PROXY_INTERFACE_SITES);
                break;
            }
            boolean allowed = false;
            for (int fieldOffset : fieldOffsets) {
                if (serializedProxyCallbackMayReach(handler, call.name(), fieldOffset)) {
                    allowed = true;
                    break;
                }
            }
            if (!allowed) {
                continue;
            }
            MethodInfo caller = support.enclosingMethod(call);
            String callerKey = caller == null ? "" : methodKey(caller, ex);
            if (caller == null || (!reachable.contains(callerKey) && !callerKey.equals(handlerKey))) {
                continue;
            }
            ForwardOrigins.Result callerOrigins = origins(caller, ex);
            if (support.sinkPathProvablyUnreachable(caller, call.offset(), callerOrigins)) {
                continue;
            }
            for (ValueOrigin receiver : ValueOriginOrder.sorted(
                    support.argOriginAtOrdinal(call, -1, callerOrigins))) {
                if (!mayCarryTaint(receiver)) {
                    continue;
                }
                for (List<ChainHop> receiverPath : taintedCandidates(receiver, caller,
                        depth + 1, ex)) {
                    List<ChainHop> candidate = appendMethodHop(receiverPath, caller,
                            handler.owner(), handler.name(), handler.descriptor(),
                            HopKind.VIRTUAL_DISPATCH, "serialized-proxy-interface", null);
                    if (candidate != null) {
                        paths.add(candidate);
                    }
                }
            }
        }
        return distinctBestPaths(paths);
    }

    /** Return all bounded field/class alternatives used by sink and effect consumers. */
    private List<List<ChainHop>> taintedFieldCandidates(ValueOrigin.FieldRead f,
                                                         MethodInfo method, int depth,
                                                         Explore ex) {
        List<List<ChainHop>> paths = new ArrayList<>();
        paths.addAll(serializedFieldPaths(f, method, depth, ex));
        String key = f.descriptor() == null || f.descriptor().isBlank()
                ? fieldNameKey(f.owner(), f.field(), f.isStatic())
                : fieldKey(f.owner(), f.field(), f.descriptor(), f.isStatic());
        if (f.descriptor() == null || f.descriptor().isBlank()) {
            paths.addAll(candidatePaths(fieldTaintedByName, fieldTaintedByNameAlternatives, key));
        } else {
            paths.addAll(candidatePaths(fieldTainted, fieldTaintedAlternatives, key));
        }
        if (!f.isStatic() && receiverIsUnknown(f.receiver())) {
            paths.addAll(candidatePaths(thisTainted, thisTaintedAlternatives, f.owner()));
        }
        if (receiverIsUnknown(f.receiver())) {
            MethodInfo serializedHandler = serializedProxyHandlerForOwner(f.owner());
            if (serializedHandler != null) {
                List<ChainHop> external = serializedProxyHandlerPath(serializedHandler, depth, ex);
                if (external != null) {
                    paths.add(external);
                }
            }
            if (method != null && support.isSerializedProxyHandler(method)) {
                List<ChainHop> external = serializedProxyHandlerPath(method, depth, ex);
                if (external != null) {
                    paths.add(external);
                }
            }
        }
        return distinctBestPaths(paths);
    }

    /** A field read with a concrete receiver must wait for that receiver's own fact. */
    private static boolean receiverIsUnknown(ValueOrigin receiver) {
        return receiver == null || receiver instanceof ValueOrigin.Unknown;
    }

    /** Resolve the exact serialized InvocationHandler callback for any method in its class. */
    private MethodInfo serializedProxyHandlerForOwner(String owner) {
        if (owner == null || owner.isBlank()) {
            return null;
        }
        for (Node candidate : support.serializedProxyHandlerMethods()) {
            if (!owner.equals(candidate.owner())) {
                continue;
            }
            MethodInfo method = support.methodOf(candidate.owner(), candidate.name(),
                    candidate.descriptor());
            if (method != null) {
                return method;
            }
        }
        return null;
    }

    private boolean isAdmittedJdkCallback(MethodInfo method, Explore ex) {
        return method != null && support.deserializationCallbackEntries()
                .contains(methodKey(method, ex));
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
            var subtypeResult = bb.hierarchy().transitiveSubtypes(owner, RAW_DISPATCH_CAP);
            List<String> raw = subtypeResult.values();
            long endRevision = bb.hierarchy().revision();
            if (startRevision != endRevision) {
                continue;
            }
            DispatchCandidates result = new DispatchCandidates(endRevision, raw, !subtypeResult.complete());
            dispatchCache.put(key, result);
            if (result.truncated()) {
                bb.markIncomplete("DISPATCH_SUBTYPE_CAP:" + RAW_DISPATCH_CAP);
            }
            return result;
        }
    }

    private ResolvedDispatchCandidates resolvedDispatchCandidates(String owner, String name, String desc,
                                                                   DispatchCandidates rawSnapshot) {
        return resolvedDispatchCandidates(owner, owner, name, desc, rawSnapshot, false);
    }

    /**
     * Resolve a bounded dispatch family with the receiver context available at the call
     * site.  A plain lexical prefix is a poor finite approximation for deserialization:
     * Object/equals and Object/toString have thousands of loaded subtypes, while the
     * useful gadget implementation may be well past the first few hundred names.  The
     * contextual variant narrows to the receiver's declared type when that fact is known
     * and, for a value proven to come from Java serialization, orders serializable concrete
     * overrides by an already-built sink-relevance index.  The fallback remains conservative
     * and every cap continues to surface as an explicit completeness reason.
     */
    private ResolvedDispatchCandidates resolvedDispatchCandidates(String declaredOwner,
                                                                   String universeOwner,
                                                                   String name,
                                                                   String desc,
                                                                   DispatchCandidates rawSnapshot,
                                                                   boolean serializedValue) {
        if (declaredOwner.equals(universeOwner) && !serializedValue) {
            return resolvedDispatchCandidatesPlain(declaredOwner, name, desc, rawSnapshot);
        }
        DispatchSelectionKey key = new DispatchSelectionKey(declaredOwner, universeOwner,
                name, desc, serializedValue);
        ResolvedDispatchCandidates cached = contextualDispatchCache.get(key);
        long currentRevision = bb.hierarchy().revision();
        if (cached != null && cached.revision() == currentRevision) {
            return cached;
        }
        for (;;) {
            long startRevision = bb.hierarchy().revision();
            DispatchCandidates effectiveRaw = rawSnapshot.revision() == startRevision
                    ? rawSnapshot : rawDispatchCandidates(universeOwner, name, desc);
            List<String> raw = effectiveRaw.revision() == startRevision
                    ? effectiveRaw.raw() : List.of();
            List<DispatchTarget> accepted = contextualDispatchTargets(declaredOwner, universeOwner,
                    name, desc, effectiveRaw, serializedValue);
            long endRevision = bb.hierarchy().revision();
            if (startRevision != endRevision) {
                rawSnapshot = rawDispatchCandidates(universeOwner, name, desc);
                continue;
            }
            boolean truncated = effectiveRaw.truncated() || accepted.size() >= 300
                    && raw.size() > accepted.size();
            ResolvedDispatchCandidates result = new ResolvedDispatchCandidates(endRevision,
                    List.copyOf(accepted), truncated);
            contextualDispatchCache.put(key, result);
            if (truncated) {
                bb.markIncomplete("DISPATCH_TARGET_CAP:300");
            }
            return result;
        }
    }

    /** Existing deterministic lexical resolver for ordinary non-serialization dispatch. */
    private ResolvedDispatchCandidates resolvedDispatchCandidatesPlain(String owner, String name,
                                                                        String desc,
                                                                        DispatchCandidates rawSnapshot) {
        DispatchKey key = new DispatchKey(owner, name, desc);
        ResolvedDispatchCandidates cached = resolvedDispatchCache.get(key);
        long currentRevision = bb.hierarchy().revision();
        if (cached != null && cached.revision() == currentRevision) {
            return cached;
        }
        for (;;) {
            long startRevision = bb.hierarchy().revision();
            DispatchCandidates effectiveRaw = rawSnapshot.revision() == startRevision
                    ? rawSnapshot : rawDispatchCandidates(owner, name, desc);
            List<String> raw = effectiveRaw.revision() == startRevision
                    ? effectiveRaw.raw() : List.of();
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
            boolean truncated = effectiveRaw.truncated() || accepted.size() >= 300 && raw.size() > accepted.size();
            ResolvedDispatchCandidates result = new ResolvedDispatchCandidates(endRevision,
                    List.copyOf(accepted), truncated);
            resolvedDispatchCache.put(key, result);
            if (truncated) {
                bb.markIncomplete("DISPATCH_TARGET_CAP:300");
            }
            return result;
        }
    }

    private List<DispatchTarget> contextualDispatchTargets(String declaredOwner,
                                                            String universeOwner,
                                                            String name, String desc,
                                                            DispatchCandidates rawSnapshot,
                                                            boolean serializedValue) {
        List<DispatchTarget> all = new ArrayList<>(rawSnapshot.raw().size());
        ClassInfo universe = bb.hierarchy().classInfo(universeOwner);
        if (universe != null && !universe.isInterface()
                && !java.lang.reflect.Modifier.isAbstract(universe.access())) {
            DispatchTarget base = dispatchTarget(declaredOwner, universeOwner, name, desc);
            if (base != null) {
                all.add(base);
            }
        }
        for (String candidate : rawSnapshot.raw()) {
            DispatchTarget target = dispatchTarget(declaredOwner, candidate, name, desc);
            if (target != null) {
                all.add(target);
            }
        }
        if (serializedValue) {
            List<DispatchTarget> serializable = all.stream()
                    .filter(target -> bb.hierarchy().isSerializable(target.candidateOwner()))
                    .toList();
            // An incomplete hierarchy/JDK slice must not turn a useful approximation into a
            // false negative.  If no candidate can be classified, retain the conservative
            // family and let the existing raw/target caps describe the uncertainty.
            if (!serializable.isEmpty()) {
                all = new ArrayList<>(serializable);
            } else if (!all.isEmpty()) {
                bb.markIncomplete("SERIALIZED_DISPATCH_TYPE_UNKNOWN");
            }
            all.sort(java.util.Comparator
                    // A serialized Object/collection receiver is a bounded runtime
                    // dispatch problem.  Lexical order and ordinary sink distance are
                    // insufficient here: a callback implementation may only become
                    // sink-relevant through a later object-graph or reflective bridge.
                    // Prefer a concrete, rule-declared lifecycle callback and a method
                    // body that already exhibits a generic callback shape before applying
                    // the ordinary sink-distance tie breaker.  This is only candidate
                    // scheduling; every accepted target remains subject to the same
                    // serializable/JVM-overridable gates and the 300 target cap.
                    .comparingInt((DispatchTarget target) ->
                            serializedDispatchPriority(target, name, desc)).reversed()
                    .thenComparingInt((DispatchTarget target) -> sinkDistanceRank(target, name, desc))
                    .thenComparing((DispatchTarget target) -> directDeclarationRank(target, name, desc))
                    .thenComparing(DispatchTarget::resolvedOwner)
                    .thenComparing(DispatchTarget::candidateOwner));
        }
        List<DispatchTarget> result = new ArrayList<>(Math.min(300, all.size()));
        Set<String> resolved = new HashSet<>();
        for (DispatchTarget target : all) {
            // Multiple serializable subclasses commonly inherit the same implementation.
            // Re-emitting that target consumes the finite target budget without adding a
            // distinct forward fact.
            if (!resolved.add(target.resolvedOwner())) {
                continue;
            }
            if (result.size() >= 300) {
                break;
            }
            result.add(target);
        }
        return result;
    }

    /**
     * Rank a finite serialized receiver family by generic callback evidence.  Java
     * serialization commonly reaches a user object through Object.hashCode/equals/
     * toString or a collection/reflective adapter, so a candidate can be a valid gadget
     * even when no ordinary call-graph path reaches a configured sink.  Keeping this
     * ordering in the engine (rather than in rules or benchmark code) makes the cap
     * deterministic while preserving the existing conservative wildcard boundary.
     */
    private int serializedDispatchPriority(DispatchTarget target, String name, String desc) {
        MethodInfo method = support.methodOf(target.resolvedOwner(), name, desc);
        if (method == null) {
            return 0;
        }
        int score = 0;
        var entry = bb.ruleEngine().matchingEntry(method.owner(), method.name(), method.descriptor());
        if (entry.isPresent() && isSerializedCallbackKind(entry.get().entryKind())) {
            score += 100;
        }
        for (InsnFact insn : method.instructions()) {
            if (!insn.op().isInvoke()) {
                continue;
            }
            Node call = support.callNode(OriginSupport.methodKey(method), insn.offset());
            if (call == null) {
                continue;
            }
            if (bb.ruleEngine().matchingSink(call).isPresent()) {
                score += 64;
            }
            if (bb.ruleEngine().matchingSource(call.owner(), call.name(), call.descriptor())
                    .filter(ForwardEngine::isDeserializationSource).isPresent()) {
                score += 48;
            }
            if (isSerializedCallbackMethodName(call.name())) {
                score += 16;
            } else if (isCallbackAdapterMethodName(call.name())) {
                score += 4;
            }
        }
        return score;
    }

    private static boolean isSerializedCallbackKind(String entryKind) {
        return "hashCode".equals(entryKind) || "equals".equals(entryKind)
                || "compareTo".equals(entryKind) || "compare".equals(entryKind)
                || "toString".equals(entryKind) || JAVA_SERIALIZATION_ENTRY_KINDS.contains(entryKind);
    }

    private static boolean isSerializedCallbackMethodName(String name) {
        return "hashCode".equals(name) || "equals".equals(name)
                || "compareTo".equals(name) || "compare".equals(name)
                || "toString".equals(name);
    }

    private static boolean isCallbackAdapterMethodName(String name) {
        return "apply".equals(name) || "get".equals(name) || "invoke".equals(name)
                || "convert".equals(name) || "deserialize".equals(name);
    }

    private int sinkDistanceRank(DispatchTarget target, String name, String desc) {
        return support.sinkDistanceOf(OriginSupport.methodKeyOf(target.resolvedOwner(), name, desc));
    }

    private int directDeclarationRank(DispatchTarget target, String name, String desc) {
        return support.methodOf(target.candidateOwner(), name, desc) == null ? 1 : 0;
    }

    /** 单个候选的 JVM 语义过滤；null 表示该候选不能成为污点动态目标。 */
    private DispatchTarget dispatchTarget(String owner, String candidate, String name, String desc) {
        // Do not impose an OIS Serializable constraint here. This resolver is also used by
        // framework-source and ordinary object-flow chains, where a non-serializable receiver
        // is valid (for example a deserializer callback delegates into an application helper).
        // Serialization-specific entry rules constrain the source boundary; applying the same
        // predicate to every virtual dispatch silently deletes framework targets.
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
        Set<ValueOrigin> receiverOrigins = Set.of();
        ForwardOrigins.Result originResult = origins(method, ex);
        ForwardOrigins.State state = originResult.stateBefore().get((Integer) call.prop("offset"));
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
                receiverOrigins = state.stack().get(receiverDepth).origins();
                for (ValueOrigin receiver : receiverOrigins) {
                    if (cancellationRequested()) {
                        return;
                    }
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
        // 候选实现：接口用 implementers，类用有界子类型闭包；是否需要
        // Serializable 由 source/entry 语义决定，而不是由通用分派解析器硬编码。
        // 解析结果在同一层次版本内跨调用点复用，避免每个 tainted call 重复做
        // resolveMethod + 可覆写检查。
        String universeOwner = dispatchUniverseOwner(owner, receiverOrigins, method);
        boolean serializedValue = isJavaSerializationValue(receiverPath);
        DispatchCandidates dispatch = rawDispatchCandidates(universeOwner, call.name(), call.descriptor());
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
                            rState.stack().get(rDepth).origins(), method, call.offset(),
                            originResult);
                    for (String preciseType : preciseTypes) {
                        if (cancellationRequested()) {
                            return;
                        }
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
            candidates = resolvedDispatchCandidates(owner, universeOwner, call.name(),
                            call.descriptor(), dispatch, serializedValue)
                    .targets();
        }
        for (DispatchTarget target : candidates) {
            if (cancellationRequested()) {
                return;
            }
            String resolved = target.resolvedOwner();
            String targetKey = OriginSupport.methodKeyOf(resolved, call.name(),
                    call.descriptor());
            admitDynamicDispatchTarget(targetKey, serializedValue);
            if (!scheduledMethod(targetKey)) {
                continue;
            }
            addParam(resolved, call.name(), call.descriptor(), 0,
                    hopTo(receiverPath, method, resolved, call.name(),
                            call.descriptor(), EdgeType.DISPATCHES));
        }
    }

    /**
     * Admit a CHA target discovered from a concrete serialized receiver. The initial demand
     * graph cannot see the runtime subtype edge, and a callback may only become sink-relevant
     * through a later reflective/container edge. Keep that late admission finite and tied to
     * a configured serialization callback; ordinary dispatch still uses the normal sink
     * distance gate.
     */
    private void admitDynamicDispatchTarget(String methodKey, boolean serializedValue) {
        if (methodKey == null || forwardDemand == null) {
            return;
        }
        MethodInfo target = resolveMethodKey(methodKey);
        boolean callback = serializedValue && target != null
                && bb.ruleEngine().matchingEntry(target.owner(), target.name(), target.descriptor())
                .map(entry -> isSerializedCallbackKind(entry.entryKind()))
                .orElse(false);
        if (!callback && !reachable.contains(methodKey)) {
            admitDynamicDemand(methodKey);
            return;
        }
        if (!forwardDemand.contains(methodKey)) {
            if (dynamicCallbackDemandAdds >= DYNAMIC_CALLBACK_DEMAND_CAP) {
                bb.markIncomplete("FORWARD_DYNAMIC_CALLBACK_DEMAND_CAP:"
                        + DYNAMIC_CALLBACK_DEMAND_CAP);
                return;
            }
            dynamicCallbackDemandAdds++;
            forwardDemand.add(methodKey);
        }
        if (!reachable.contains(methodKey) && target != null) {
            activateReachable(target);
        }
    }

    /** 精扫：实参污点命中仅声明目标的调用时，向候选实现展开 addParam。 */
    private void expandParams(Node call, MethodInfo method, int slot, List<ChainHop> argPath) {
        if (call.out().size() > 1) {
            return;
        }
        ForwardOrigins.Result originResult = origins(method, null);
        ForwardOrigins.State state = originResult.stateBefore().get((Integer) call.prop("offset"));
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
            if (cancellationRequested()) {
                return;
            }
            String resolved = target.resolvedOwner();
            if (!support.receiverMayDispatchTo(call, method, resolved, call.name(),
                    call.descriptor(), originResult)) {
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
            if (cancellationRequested()) {
                return;
            }
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
                if (cancellationRequested()) {
                    return;
                }
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
                addParam(resolved, "invoke", PROXY_HANDLER_DESCRIPTOR, 0,
                        hopTo(handlerPath, originMethod, resolved, "invoke",
                                PROXY_HANDLER_DESCRIPTOR, EdgeType.INVOKES));
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
            if (cancellationRequested()) {
                return null;
            }
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
                if (cancellationRequested()) {
                    return null;
                }
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
                    List<ChainHop> fallback = returnTainted.get(methodKey(handler, ex));
                    if (fallback != null) {
                        return fallback;
                    }
                    continue;
                }
                for (int offset : returns) {
                    if (cancellationRequested()) {
                        return null;
                    }
                    ForwardOrigins.State returnState = handlerOrigins.stateBefore().get(offset);
                    if (returnState == null || returnState.stack().isEmpty()) {
                        continue;
                    }
                    for (ValueOrigin returned : returnState.stack()
                            .get(returnState.stack().size() - 1).origins()) {
                        if (cancellationRequested()) {
                            return null;
                        }
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
            Node call = support.callNode(methodKey(method, ex), candidate.offset());
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
        return proxyMethodMetadata(method, requestedName == null ? Set.of() : Set.of(requestedName),
                cfgProvider).returnOffsets();
    }

    /**
     * Return all instruction offsets feasible for at least one bounded proxy callback method
     * name.  This is intentionally separate from return offsets: callers that consume field,
     * call and sink effects must suppress mutually exclusive method-name branches before the
     * path-insensitive origin summary is used.
     */
    public static Set<Integer> proxyMethodFeasibleOffsets(MethodInfo method,
                                                          Collection<String> requestedNames) {
        return proxyMethodFeasibleOffsets(method, requestedNames, Cfg::computeIndexed);
    }

    /** Shared multi-name proxy analysis with the scan-wide CPG CFG provider. */
    public static Set<Integer> proxyMethodFeasibleOffsets(MethodInfo method,
                                                          Collection<String> requestedNames,
                                                          CpgIndex.CfgProvider cfgProvider) {
        return proxyMethodMetadata(method, requestedNames, cfgProvider).feasibleOffsets();
    }

    private static ProxyMetadata proxyMethodMetadata(MethodInfo method,
                                                      Collection<String> requestedNames,
                                                      CpgIndex.CfgProvider cfgProvider) {
        if (method == null || method.instructions().isEmpty()
                || requestedNames == null || requestedNames.isEmpty()) {
            return new ProxyMetadata(Set.of(), Set.of(), false);
        }
        CpgIndex.CfgProvider provider = cfgProvider == null ? Cfg::computeIndexed : cfgProvider;
        LinkedHashSet<Integer> feasibleOffsets = new LinkedHashSet<>();
        LinkedHashSet<Integer> returnOffsets = new LinkedHashSet<>();
        boolean complete = true;
        LinkedHashSet<String> names = new LinkedHashSet<>();
        for (String requestedName : requestedNames) {
            if (requestedName != null && !requestedName.isBlank()) {
                names.add(requestedName);
            }
        }
        if (names.isEmpty()) {
            return new ProxyMetadata(Set.of(), Set.of(), false);
        }
        for (String requestedName : names) {
            ProxyMetadata one = proxyMethodMetadataForName(method, requestedName, provider);
            feasibleOffsets.addAll(one.feasibleOffsets());
            returnOffsets.addAll(one.returnOffsets());
            complete &= one.complete();
        }
        return new ProxyMetadata(Set.copyOf(feasibleOffsets), Set.copyOf(returnOffsets), complete);
    }

    private static ProxyMetadata proxyMethodMetadataForName(MethodInfo method, String requestedName,
                                                            CpgIndex.CfgProvider provider) {
        Cfg.Indexed cfg = provider.cfg(method);
        Map<Integer, Set<ProxyFlow>> states = new HashMap<>();
        Deque<Integer> work = new ArrayDeque<>();
        Map<Integer, ProxyValue> initialLocals = new HashMap<>();
        // InvocationHandler.invoke(Object proxy, Method method, Object[] args): slot 2 is Method.
        initialLocals.put(2, ProxyValue.methodObject());
        ProxyFlow initial = new ProxyFlow(List.of(), initialLocals);
        states.computeIfAbsent(0, ignored -> new LinkedHashSet<>()).add(initial);
        work.add(0);
        Set<Integer> feasibleOffsets = new LinkedHashSet<>();
        Set<Integer> returns = new LinkedHashSet<>();
        int transitions = 0;
        while (!work.isEmpty() && transitions++ < 20_000) {
            int offset = work.removeFirst();
            feasibleOffsets.add(offset);
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
                for (int edgeIndex = cfg.edgeStart(offset); edgeIndex < cfg.edgeEnd(offset); edgeIndex++) {
                    CfgLabel edgeLabel = cfg.labelAt(edgeIndex);
                    if (edgeLabel == CfgLabel.EXCEPTION || !proxyBranchAllowed(insn.op(),
                            condition, edgeLabel)) {
                        continue;
                    }
                    int targetOffset = cfg.targetAt(edgeIndex);
                    if (targetOffset < 0 || targetOffset >= method.instructions().size()) {
                        continue;
                    }
                    Set<ProxyFlow> target = states.computeIfAbsent(targetOffset,
                            ignored -> new LinkedHashSet<>());
                    // Unknown bytecode can otherwise create a state cross-product in a large
                    // handler. Capping states affects only metadata feasibility, not the core
                    // taint result; an empty result falls back conservatively above.
                    if (target.size() >= 96 || !target.add(next)) {
                        continue;
                    }
                    work.addLast(targetOffset);
                }
            }
        }
        boolean complete = transitions < 20_000;
        if (transitions >= 20_000) {
            returns.clear();
        }
        return new ProxyMetadata(Set.copyOf(feasibleOffsets), Set.copyOf(returns), complete);
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
                && "startsWith".equals(ref.name())
                && "(Ljava/lang/String;)Z".equals(ref.descriptor())) {
            if (receiver.kind() == ProxyValueKind.METHOD_NAME
                    && firstArgument.kind() == ProxyValueKind.STRING) {
                stack.add(ProxyValue.bool(requestedName.startsWith(firstArgument.text())));
            } else if (receiver.kind() == ProxyValueKind.STRING
                    && firstArgument.kind() == ProxyValueKind.STRING) {
                stack.add(ProxyValue.bool(receiver.text().startsWith(firstArgument.text())));
            } else {
                stack.add(ProxyValue.UNKNOWN);
            }
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
            if (cancellationRequested()) {
                return false;
            }
            Map<Integer, Set<ValueOrigin>> indexed = result.indexedArrayElements().get(array);
            if (indexed == null || indexed.isEmpty()) {
                continue;
            }
            metadataSeen = true;
            for (Set<ValueOrigin> values : indexed.values()) {
                if (cancellationRequested()) {
                    return false;
                }
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
        if ("java/lang/invoke/MethodHandle".equals(call.owner())
                && ("invoke".equals(call.name()) || "invokeExact".equals(call.name()))) {
            methodHandleResolve(call, method, depth, ex);
            return;
        }
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
            List<MethodInfo> targets = reflectiveTargets(targetClass, targetName, targetDescriptor,
                    getMethod, gmMethod, lookupOrigins);
            for (MethodInfo target : targets) {
                propagateReflectiveInvocation(call, method, depth, ex, invokeOrigins,
                        target, 1, false, false);
            }
        }
    }

    /**
     * Resolve a MethodHandle lookup without turning the polymorphic invoke into a whole-world
     * call.  The bytecode descriptor at {@code invokeExact/invoke} is the handle invocation
     * shape; for virtual/special handles its first argument is the receiver, while static
     * handles use it unchanged.  The lookup class/name and the bounded call shape therefore
     * provide the same kind of proof as Class.getMethod, but preserve direct argument slots.
     */
    private void methodHandleResolve(Node call, MethodInfo method, int depth, Explore ex) {
        ForwardOrigins.Result invokeOrigins = origins(method, ex);
        ForwardOrigins.State state = invokeOrigins.stateBefore().get(call.offset());
        if (state == null) {
            return;
        }
        for (ValueOrigin handleOrigin : ValueOriginOrder.sorted(receiverOrigins(call, state))) {
            if (!(handleOrigin instanceof ValueOrigin.CallResult handleResult)
                    || handleResult.callNodeId() < 0) {
                continue;
            }
            Node lookup = support.callNode(handleResult.callNodeId());
            if (lookup == null || !isMethodHandleLookup(lookup.name())) {
                continue;
            }
            MethodInfo lookupHost = support.enclosingMethod(lookup);
            if (lookupHost == null) {
                continue;
            }
            ForwardOrigins.Result lookupOrigins = origins(lookupHost, ex);
            int classOrdinal = 0;
            int nameOrdinal = "findConstructor".equals(lookup.name()) ? -1 : 1;
            int typeOrdinal = "findConstructor".equals(lookup.name()) ? 1 : 2;
            if (support.argOriginAtOrdinal(lookup, typeOrdinal, lookupOrigins).isEmpty()) {
                // The MethodType is part of the lookup contract.  Without a stack fact the
                // invocation descriptor would be an unverified guess, so retain the ordinary
                // MethodHandle capability boundary and report no target edge.
                continue;
            }
            Set<String> targetClasses = new LinkedHashSet<>();
            for (ValueOrigin classOrigin : support.argOriginAtOrdinal(lookup, classOrdinal,
                    lookupOrigins)) {
                String targetClass = classNameOf(classOrigin, ex);
                if (targetClass != null) {
                    targetClasses.add(targetClass);
                }
            }
            if (targetClasses.isEmpty()) {
                continue;
            }
            String targetName = null;
            boolean exactName = "findConstructor".equals(lookup.name());
            if (nameOrdinal >= 0) {
                Set<ValueOrigin> names = support.argOriginAtOrdinal(lookup, nameOrdinal,
                        lookupOrigins);
                String candidate = null;
                boolean ambiguous = false;
                for (ValueOrigin nameOrigin : names) {
                    if (!(nameOrigin instanceof ValueOrigin.Constant constant)
                            || !(constant.value() instanceof String value)) {
                        ambiguous = true;
                        continue;
                    }
                    if (candidate != null && !candidate.equals(value)) {
                        ambiguous = true;
                    }
                    candidate = value;
                }
                if (!ambiguous && candidate != null) {
                    targetName = candidate;
                    exactName = true;
                }
            }
            String lookupKind = lookup.name();
            String targetDescriptor = methodHandleTargetDescriptor(call, lookupKind);
            if (targetDescriptor == null) {
                continue;
            }
            for (String targetClass : targetClasses) {
                String resolvedName = "findConstructor".equals(lookupKind)
                        ? "<init>" : targetName;
                List<MethodInfo> targets = methodHandleTargets(targetClass, resolvedName,
                        targetDescriptor, lookupKind);
                if (targets.isEmpty()) {
                    continue;
                }
                boolean unresolvedTarget = !exactName;
                if (unresolvedTarget) {
                    bb.markIncomplete("FORWARD_METHODHANDLE_NAME_WILDCARD");
                }
                for (MethodInfo target : targets) {
                    boolean constructor = "findConstructor".equals(lookupKind);
                    int firstArgumentOrdinal = constructor || target.isStatic() ? 0 : 1;
                    propagateMethodHandleInvocation(call, method, depth, ex, invokeOrigins,
                            target, firstArgumentOrdinal, constructor, unresolvedTarget);
                }
            }
        }
    }

    private static boolean isMethodHandleLookup(String name) {
        return "findStatic".equals(name) || "findVirtual".equals(name)
                || "findSpecial".equals(name) || "findConstructor".equals(name);
    }

    /** Remove the explicit receiver from a virtual MethodHandle invocation descriptor. */
    private static String methodHandleTargetDescriptor(Node invoke, String lookupKind) {
        String descriptor = invoke.descriptor();
        if (descriptor == null || descriptor.indexOf(')') < 0) {
            return null;
        }
        if ("findVirtual".equals(lookupKind) || "findSpecial".equals(lookupKind)) {
            String first = io.just.sast.model.Descriptor.paramType(descriptor, 0);
            if (first == null) {
                return null;
            }
            int open = descriptor.indexOf('(');
            int firstStart = open + 1;
            int firstEnd = firstStart + first.length();
            if (firstEnd > descriptor.indexOf(')')) {
                return null;
            }
            return "(" + descriptor.substring(firstEnd, descriptor.indexOf(')')) + ")"
                    + io.just.sast.model.Descriptor.returnType(descriptor);
        }
        if ("findConstructor".equals(lookupKind)) {
            return descriptor.substring(0, descriptor.indexOf(')') + 1) + "V";
        }
        return descriptor;
    }

    /**
     * Lookup targets are exact when the name is constant.  An opaque name is intentionally
     * restricted to already configured sink methods in the target class; this gives useful
     * evidence without expanding a MethodHandle into every public method in the hierarchy.
     */
    private List<MethodInfo> methodHandleTargets(String owner, String name, String descriptor,
                                                   String lookupKind) {
        List<MethodInfo> candidates = reflectiveTargets(owner, name, descriptor);
        if (name != null && !name.isBlank() && candidates.isEmpty()) {
            return List.of();
        }
        List<MethodInfo> result = new ArrayList<>();
        boolean constructor = "findConstructor".equals(lookupKind);
        boolean staticLookup = "findStatic".equals(lookupKind);
        for (MethodInfo candidate : candidates) {
            if (constructor && !"<init>".equals(candidate.name())) {
                continue;
            }
            if (!constructor && "<init>".equals(candidate.name())) {
                continue;
            }
            if (staticLookup != candidate.isStatic()) {
                continue;
            }
            if (!staticLookup && candidate.isStatic()) {
                continue;
            }
            result.add(candidate);
            if (result.size() >= 32) {
                break;
            }
        }
        return List.copyOf(result);
    }

    /** Propagate taint through the direct invocation arguments of a resolved MethodHandle. */
    private void propagateMethodHandleInvocation(Node call, MethodInfo caller, int depth,
                                                  Explore ex, ForwardOrigins.Result invokeOrigins,
                                                  MethodInfo target, int firstArgumentOrdinal,
                                                  boolean constructor, boolean unresolvedTarget) {
        if (support.sinkPathProvablyUnreachable(caller, call.offset(), invokeOrigins)) {
            return;
        }
        activateReachable(target);
        if (!constructor && !target.isStatic()) {
            for (ValueOrigin receiver : support.argOriginAtOrdinal(call, 0, invokeOrigins)) {
                if (!mayCarryTaint(receiver)) {
                    continue;
                }
                List<ChainHop> path = tainted(receiver, caller, depth + 1, ex);
                if (path != null) {
                    addParam(target.owner(), target.name(), target.descriptor(), 0,
                            hopTo(path, caller, target.owner(), target.name(),
                                    target.descriptor(), EdgeType.INVOKES));
                }
            }
        }
        int parameters = Descriptor.paramCount(target.descriptor());
        for (int ordinal = 0; ordinal < parameters; ordinal++) {
            for (ValueOrigin argument : support.argOriginAtOrdinal(call,
                    firstArgumentOrdinal + ordinal, invokeOrigins)) {
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
        emitResolvedSinks(call, caller, ex, invokeOrigins, target,
                target.isStatic() ? -1 : 0, firstArgumentOrdinal, false, constructor, depth,
                unresolvedTarget);
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
        if (support.sinkPathProvablyUnreachable(caller, call.offset(), invokeOrigins)) {
            // The reflective operation itself is behind a proven-failed lookup or a local
            // impossible guard.  Do not manufacture a target fact merely because the
            // metadata resolver found a syntactic candidate.
            return;
        }
        if (!constructor && !unresolvedTarget
                && !support.reflectiveInvokeMayReach(target, call, invokeOrigins)) {
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
                    addParam(target.owner(), target.name(), target.descriptor(), 0,
                            hopTo(path, caller, target.owner(), target.name(),
                                    target.descriptor(), EdgeType.INVOKES));
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
     * Resolve a Method.invoke whose Method value came from a typed collection.
     * The collection is externally populated, so the target family is limited to
     * loaded public no-argument bean readers.  This supplies the receiver fact
     * needed by sinks inside the selected reader (for example a TemplatesImpl
     * getter) without assuming a concrete proxy allocation in the scan unit.
     */
    private void methodCollectionResolve(Node invoke, MethodInfo caller, int depth,
                                         Explore ex, ForwardOrigins.Result invokeOrigins) {
        if (!support.methodCollectionReflectiveInvokeSite(invoke)) {
            return;
        }
        Set<ValueOrigin> targetReceivers = support.argOriginAtOrdinal(invoke, 0, invokeOrigins);
        Set<ValueOrigin> argumentArray = support.argOriginAtOrdinal(invoke, 1, invokeOrigins);
        if (targetReceivers.isEmpty() && argumentArray.isEmpty()) {
            return;
        }
        boolean preciseSite = support.methodCollectionSiteIsPrecise(invoke);
        if (!preciseSite) {
            bb.markIncomplete("FORWARD_METHOD_COLLECTION_TARGET_WILDCARD");
        }
        String collectionReason = preciseSite
                ? "method-collection-exact;receiver-exact"
                : "method-collection;receiver-unknown";
        for (Node targetNode : support.methodCollectionTargetMethodsOf(invoke)) {
            if (cancellationRequested()) {
                return;
            }
            MethodInfo target = support.methodOf(targetNode.owner(), targetNode.name(),
                    targetNode.descriptor());
            if (target == null) {
                continue;
            }
            activateReachable(target);
            if (!target.isStatic()) {
                for (ValueOrigin targetReceiver : targetReceivers) {
                    if (!mayCarryTaint(targetReceiver)) {
                        continue;
                    }
                    List<ChainHop> receiverPath = tainted(targetReceiver, caller, depth + 1, ex);
                    if (receiverPath == null || receiverPath.size() >= MAX_HOPS) {
                        if (receiverPath != null) {
                            bb.markIncomplete("FORWARD_HOP_CAP:" + MAX_HOPS);
                        }
                        continue;
                    }
                    List<ChainHop> targetPath = appendMethodHop(receiverPath, caller, target.owner(),
                            target.name(), target.descriptor(), HopKind.VIRTUAL_DISPATCH,
                            collectionReason, null);
                    if (targetPath != null) {
                        addParam(target.owner(), target.name(), target.descriptor(), 0, targetPath);
                    }
                }
            }
            int parameters = Descriptor.paramCount(target.descriptor());
            for (int ordinal = 0; ordinal < parameters; ordinal++) {
                for (ValueOrigin argument : arrayElementOrigins(invokeOrigins, argumentArray,
                        ordinal, !preciseSite)) {
                    if (!mayCarryTaint(argument)) {
                        continue;
                    }
                    List<ChainHop> argumentPath = tainted(argument, caller, depth + 1, ex);
                    if (argumentPath == null || argumentPath.size() >= MAX_HOPS) {
                        if (argumentPath != null) {
                            bb.markIncomplete("FORWARD_HOP_CAP:" + MAX_HOPS);
                        }
                        continue;
                    }
                    int slot = parameterSlot(target.descriptor(), target.isStatic(), ordinal);
                    if (slot < 0) {
                        continue;
                    }
                    List<ChainHop> targetPath = appendMethodHop(argumentPath, caller, target.owner(),
                            target.name(), target.descriptor(), HopKind.VIRTUAL_DISPATCH,
                            collectionReason, ordinal);
                    if (targetPath != null) {
                        addParam(target.owner(), target.name(), target.descriptor(), slot, targetPath);
                    }
                }
            }
        }
    }

    /**
     * Reflection targets are not represented by ordinary call-graph edges.  Once a
     * descriptor/class constraint resolves one, add its bounded downstream closure to the
     * same reachability set used by ordinary calls; otherwise the new facts would be silently
     * discarded by the worklist and the final sink pass.
     */
    private void activateReachable(MethodInfo target) {
        String root = OriginSupport.methodKey(target);
        admitDynamicDemand(root);
        if (!reachable.add(root)) {
            return;
        }
        Deque<String> work = new ArrayDeque<>();
        work.add(root);
        int added = 0;
        while (!work.isEmpty() && added++ < REFLECTIVE_REACHABLE_CAP) {
            String key = work.removeFirst();
            admitDynamicDemand(key);
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
                        admitDynamicDemand(next);
                        work.addLast(next);
                    }
                }
            }
        }
        if (!work.isEmpty()) {
            bb.markIncomplete("REFLECTIVE_REACHABLE_CAP:" + REFLECTIVE_REACHABLE_CAP);
        }
    }

    /**
     * Admit only the sink-relevant part of a late semantic closure to the workset.  The
     * initial demand pass cannot see reflection/constructor/proxy edges, but dropping every
     * late target at {@code scheduledMethod()} turns a successfully resolved semantic edge
     * into a silent false negative.  A method is admitted when it directly hosts a sink or
     * has a bounded ordinary-call distance to one; unrelated helpers remain filtered out.
     */
    private void admitDynamicDemand(String methodKey) {
        if (methodKey == null || forwardDemand == null
                || (options != null && options.reachablePrune() && !reachable.contains(methodKey))) {
            // The root is added before reachable.add(root) in activateReachable().  Semantic
            // target activation is nevertheless allowed to seed the workset; the caller will
            // add it to reachable immediately afterwards.
            if (methodKey == null || forwardDemand == null) {
                return;
            }
        }
        if (sinkCallsByMethod.containsKey(methodKey)
                || support.sinkDistanceOf(methodKey) != Integer.MAX_VALUE) {
            forwardDemand.add(methodKey);
        }
    }

    private boolean hasSinkRelevantReflectiveSite(String methodKey) {
        for (Node call : bb.graph().callsOfMethod(methodKey)) {
            List<String> classes = support.reflectiveSites().get(call.id());
            if (classes == null) {
                continue;
            }
            for (String className : classes) {
                if (classHostsConfiguredSink(className)) {
                    return true;
                }
            }
        }
        return false;
    }

    private boolean classHostsConfiguredSink(String className) {
        if (className == null || className.isBlank()) {
            return false;
        }
        Deque<String> work = new ArrayDeque<>();
        Set<String> seen = new HashSet<>();
        work.add(className);
        while (!work.isEmpty()) {
            String current = work.removeFirst();
            if (!seen.add(current)) {
                continue;
            }
            ClassInfo cls = bb.hierarchy().classInfo(current);
            if (cls == null) {
                continue;
            }
            if (cls.methods().stream().anyMatch(this::methodMatchesSink)) {
                return true;
            }
            if (cls.superName() != null) {
                work.addLast(cls.superName());
            }
            work.addAll(cls.interfaces());
        }
        return false;
    }

    private List<MethodInfo> reflectiveTargets(String owner, String name, String descriptor) {
        return reflectiveTargets(owner, name, descriptor, null, null, null);
    }

    private List<MethodInfo> reflectiveTargets(String owner, String name, String descriptor,
                                               Node lookup, MethodInfo lookupHost,
                                               ForwardOrigins.Result lookupOrigins) {
        ClassInfo cls = bb.hierarchy().classInfo(owner);
        if (cls == null) {
            return List.of();
        }
        List<MethodInfo> result = new ArrayList<>();
        for (MethodInfo candidate : cls.methods()) {
            if (name != null && !candidate.name().equals(name)) {
                continue;
            }
            if (name == null) {
                if (!methodMatchesSink(candidate)) {
                    continue;
                }
                if (lookup != null && !support.reflectiveNameMayMatch(lookup, lookupHost,
                        lookupOrigins, candidate.name())) {
                    continue;
                }
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
        emitResolvedSinks(call, caller, ex, invokeOrigins, target,
                target.isStatic() ? -1 : 0, argumentArrayOrdinal, true, constructor, depth,
                unresolvedTarget);
    }

    /** Emit configured sinks for either packed reflection arguments or direct handle arguments. */
    private void emitResolvedSinks(Node call, MethodInfo caller, Explore ex,
                                   ForwardOrigins.Result invokeOrigins, MethodInfo target,
                                   int receiverOrdinal, int firstArgumentOrdinal,
                                   boolean packedArray, boolean constructor, int depth,
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
                if (position instanceof Rule.TaintedPos.Receiver && !target.isStatic()
                        && receiverOrdinal >= 0) {
                    for (ValueOrigin receiver : support.argOriginAtOrdinal(call, receiverOrdinal,
                            invokeOrigins)) {
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
                    Set<ValueOrigin> sources;
                    if (packedArray) {
                        Set<ValueOrigin> arrays = support.argOriginAtOrdinal(call,
                                firstArgumentOrdinal, invokeOrigins);
                        sources = arrayElementOrigins(invokeOrigins, arrays, argument.index(),
                                !unresolvedTarget);
                    } else {
                        sources = support.argOriginAtOrdinal(call,
                                firstArgumentOrdinal + argument.index(), invokeOrigins);
                    }
                    for (ValueOrigin source : sources) {
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
                    target.descriptor(), rule.role().name()));
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

    /**
     * Recover the declared receiver type carried by a local value origin.  This is not a
     * points-to guess: a field descriptor and a method return descriptor are JVM facts.  If
     * origins disagree, or the value is an opaque deserialized/aliased object, keep the
     * original call-site owner and let the bounded CHA resolver decide.
     */
    private String declaredReceiverType(ValueOrigin origin, MethodInfo method) {
        if (origin instanceof ValueOrigin.FieldRead field) {
            return internalClassName(field.descriptor());
        }
        if (origin instanceof ValueOrigin.CallResult result && result.callNodeId() >= 0) {
            Node producer = support.callNode(result.callNodeId());
            if (producer != null) {
                return internalClassName(Descriptor.returnType(producer.descriptor()));
            }
        }
        if (origin instanceof ValueOrigin.Insn instruction && method != null
                && instruction.offset() >= 0 && instruction.offset() < method.instructions().size()) {
            InsnFact fact = method.insnAt(instruction.offset());
            if (fact.op() == Op.CHECKCAST && fact.typeRef() != null) {
                return internalClassName(fact.typeRef().descriptor());
            }
        }
        return null;
    }

    /**
     * Select a sound static receiver universe.  A descriptor may narrow Object to an
     * interface/base class, but it may never widen the bytecode declaration.  A concrete
     * class is included by the contextual resolver itself when it has no loaded subtype.
     */
    private String dispatchUniverseOwner(String declaredOwner, Set<ValueOrigin> origins,
                                          MethodInfo method) {
        if (origins == null || origins.isEmpty()) {
            return declaredOwner;
        }
        String candidate = null;
        for (ValueOrigin origin : origins) {
            String type = declaredReceiverType(origin, method);
            if (type == null) {
                return declaredOwner;
            }
            if (candidate == null) {
                candidate = type;
            } else if (!candidate.equals(type)) {
                return declaredOwner;
            }
        }
        if (candidate == null || candidate.equals(declaredOwner)) {
            return declaredOwner;
        }
        if (bb.hierarchy().isSubtypeOf(candidate, declaredOwner)) {
            return candidate;
        }
        return declaredOwner;
    }

    /**
     * Java serialization returns objects whose runtime class participates in the
     * Serializable boundary.  The special OIS root uses the explicit "deserialization"
     * reason; constrained framework/secondary sources carry a bridge hop and deliberately
     * do not enter this filter because their runtime object model need not implement
     * Serializable.
     */
    private static boolean isJavaSerializationValue(List<ChainHop> path) {
        if (path == null || path.isEmpty()) {
            return false;
        }
        for (ChainHop hop : path) {
            if ("bridge-source-deserialize".equals(hop.reason())) {
                return false;
            }
        }
        for (ChainHop hop : path) {
            if (hop.kind() != HopKind.ENTRY) {
                continue;
            }
            if ("deserialization".equals(hop.reason())) {
                return true;
            }
            if (JAVA_SERIALIZATION_ENTRY_KINDS.contains(hop.reason())) {
                return true;
            }
        }
        return false;
    }

    private List<ChainHop> taintedInsn(int offset, MethodInfo method, int depth, Explore ex) {
        if (!externalProxyCallbackAllows(method, offset)) {
            return null;
        }
        ForwardOrigins.Result result = origins(method, ex);
        ForwardOrigins.State state = result.stateBefore().get(offset);
        if (state == null) {
            return null;
        }
        Op op = method.insnAt(offset).op();
        List<ChainHop> best = null;
        if (op == Op.AALOAD && support.isSerializedProxyHandler(method)) {
            best = serializedProxyInterfaceArgumentPath(method, offset, state, depth, ex);
        }
        if (op == Op.NEWARRAY || op == Op.ANEWARRAY || op == Op.MULTIANEWARRAY
                || op == Op.AALOAD) {
            for (ValueOrigin element : result.arrayElements().getOrDefault(new ValueOrigin.Insn(offset), Set.of())) {
                if (!mayCarryTaint(element)) {
                    continue;
                }
                List<ChainHop> path = tainted(element, method, depth + 1, ex);
                if (path != null && (best == null || better(best, path))) {
                    best = path;
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
                if (path != null && (best == null || better(best, path))) {
                    best = path;
                }
            }
        }
        return best;
    }

    // ---- 事实写入（键去重，全序取最小才替换；受影响方法入队） ----


    /** 调用图后序号（惰性一次）：沿 INVOKES/DISPATCHES/LAMBDA 边迭代 DFS 后序编号；
     *  回边（环）剪断不重入——环上节点接受单次摘要（GadgetInspector 同款简化）。 */
    private boolean ensureTopoOrder() {
        if (topoOrder != null) {
            return true;
        }
        // The semantic reachable set is intentionally conservative and can contain every
        // method of a dependency closure.  The fixed-point scheduler, however, only needs
        // the sink-demanded workset plus its bounded semantic roots.  Building the ordering
        // over that smaller set preserves the scheduling contract while avoiding a second
        // whole-closure adjacency pass on fat jars.
        Set<String> schedulingSet = forwardDemand == null ? reachable : forwardDemand;
        if (schedulingSet.size() > TOPOLOGY_BUILD_CAP) {
            // Topological ordering is a scheduling optimization, not a semantic input.
            // Building a full adjacency copy for a huge closure can cost more than the
            // bounded refinement itself, so retain deterministic queue order and expose
            // the omitted optimization through completeness metadata.
            bb.markIncomplete("FORWARD_TOPOLOGY_SKIPPED:" + TOPOLOGY_BUILD_CAP);
            topoOrder = Map.of();
            return true;
        }
        Map<String, List<String>> succ = new HashMap<>();
        for (String key : schedulingSet) {
            if (cancellationRequested()) {
                return false;
            }
            if (resolveMethodKey(key) == null) {
                continue;
            }
            List<String> out = new ArrayList<>(2);
            for (Node call : bb.graph().callsOfMethod(key)) {
                if (cancellationRequested()) {
                    return false;
                }
                for (Edge edge : call.out()) {
                    if (cancellationRequested()) {
                        return false;
                    }
                    if (edge.type() == EdgeType.INVOKES || edge.type() == EdgeType.DISPATCHES
                            || edge.type() == EdgeType.LAMBDA) {
                        String callee = methodNodeKey(edge.to());
                        if (schedulingSet.contains(callee)) {
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
            if (cancellationRequested()) {
                return false;
            }
            if (done.contains(start)) {
                continue;
            }
            stack.push(new Object[]{start, 0});
            onPath.add(start);
            while (!stack.isEmpty()) {
                if (cancellationRequested()) {
                    return false;
                }
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
        return true;
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
        if (options.reachablePrune() && forwardDemand != null
                && !forwardDemand.contains(methodKey)) {
            return;
        }
        // A method without a field write, array store, invocation, or value return
        // cannot consume a cross-method fact or create a sink-relevant summary.  Keep
        // sink calls in the effect index by construction; this guard only removes
        // receiver/subtype requeue noise from pure glue methods in large closures.
        if (!effectInstructions.containsKey(methodKey) && !sinkCallsByMethod.containsKey(methodKey)) {
            return;
        }
        if (pending.add(methodKey)) {
            queue.add(methodKey);
        }
    }

    private void activateAndEnqueue(String methodKey) {
        if (methodKey == null) {
            return;
        }
        if (forwardDemand == null || forwardDemand.contains(methodKey)) {
            activeMethods.add(methodKey);
        }
        enqueue(methodKey);
    }

    /**
     * Keep fact creation consistent with the existing enqueue gate.  A dispatch edge can
     * point into a large dependency closure that is reachable from an entry but cannot reach
     * any configured sink within the bounded demand distance.  Such a target was already
     * ineligible for processing; constructing and retaining its path facts only added GC and
     * hash-map pressure before that fact was discarded by activateAndEnqueue().
     */
    private boolean scheduledMethod(String methodKey) {
        return methodKey != null && (!options.reachablePrune() || reachable.contains(methodKey))
                && (forwardDemand == null || forwardDemand.contains(methodKey));
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
    private void recordPrimaryFact() {
        factVersion++;
        primaryFactVersion++;
        candidateFactVersion++;
        factCount++;
        primaryFactUpdates++;
    }

    private void recordAlternativeFact() {
        factVersion++;
        candidateFactVersion++;
        factCount++;
        alternativeFactUpdates++;
    }

    private void addThis(String className, List<ChainHop> path, boolean propagateSubtypes) {
        if (!sourceBacked(path) || path.size() > MAX_HOPS) {
            return;
        }
        List<ChainHop> snapshot = List.copyOf(path);
        // The bounded frontier is an audit aid, not the admission gate for the primary
        // summary.  A candidate can be the best provenance even when eight shorter
        // alternatives already occupy the frontier.
        boolean alternativeRetained = rememberAlternative(thisTaintedAlternatives, className,
                snapshot);
        List<ChainHop> existing = thisTainted.get(className);
        if (!betterReceiverFact(className, existing, path)) {
            if (alternativeRetained) {
                recordAlternativeFact();
            }
            // The ordinary effect transfer intentionally consumes the primary receiver
            // summary.  Alternatives are read lazily by sink/semantic boundaries; queueing
            // the whole class for an alternative-only update recreates the frontier explosion
            // this bounded store is meant to avoid.
            if (!propagateSubtypes || !alternativeRetained) {
                return;
            }
        } else {
            thisTainted.put(className, snapshot);
            recordPrimaryFact();
            enqueueClassMethods(className);
        }
        if (!propagateSubtypes) {
            return;
        }
        // 类级对象污点向加载的传递子类型传递（运行时对象必是某子类型），有界防爆
        int subTainted = 0;
        var subtypeResult = bb.hierarchy().transitiveSubtypes(className, 100);
        if (!subtypeResult.complete()) {
            bb.markIncomplete("OBJECT_SUBTYPE_CAP:100");
        }
        for (String sub : subtypeResult.values()) {
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
            boolean subAlternativeRetained = rememberAlternative(thisTaintedAlternatives, sub,
                    snapshot);
            List<ChainHop> subExisting = thisTainted.get(sub);
            if (better(subExisting, snapshot)) {
                thisTainted.put(sub, snapshot);
                recordPrimaryFact();
                enqueueClassMethods(sub);
            } else if (subAlternativeRetained) {
                recordAlternativeFact();
            }
        }
    }

    /** Reprocess every loaded method whose class-level receiver frontier changed. */
    private void enqueueClassMethods(String className) {
        ClassInfo cls = bb.hierarchy().classInfo(className);
        if (cls == null) {
            return;
        }
        for (MethodInfo method : cls.methods()) {
            String methodKey = OriginSupport.methodKey(method);
            if (!options.reachablePrune() || reachable.contains(methodKey)) {
                activateAndEnqueue(methodKey);
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

    /**
     * Merge a class-level receiver fact without letting a path for a different object
     * replace the class's own serialization callback.  {@code thisTainted} is intentionally
     * a bounded class summary, so it must distinguish a direct lifecycle entry for
     * {@code className} from an object-graph/proxy path that merely happens to reach a call
     * on the same class.  The latter is still retained in the alternative frontier and can
     * be consumed by precise parameter/field propagation; it must not become the summary
     * used by every method on the class.  A synthetic proxyInvoke root remains replaceable
     * by its concrete callback path because it is not a real serialized object entry.
     */
    private static boolean betterReceiverFact(String className, List<ChainHop> existing,
                                              List<ChainHop> candidate) {
        if (existing == null) {
            return true;
        }
        boolean existingOwnEntry = hasEntryForClass(existing, className);
        boolean candidateOwnEntry = hasEntryForClass(candidate, className);
        if (existingOwnEntry != candidateOwnEntry) {
            return candidateOwnEntry;
        }
        if (existingOwnEntry && candidateOwnEntry) {
            // Both are genuine entries for this receiver class.  Keep the normal total
            // order, including the concrete-proxy preference for equivalent roots.
            return better(existing, candidate);
        }
        if (hasSyntheticProxyRoot(existing) && isExternalProxyPath(candidate)) {
            return true;
        }
        // No class-local entry is being compared; ordinary provenance/length ordering is
        // safe for a summary that was introduced by an actual selected receiver path.
        return better(existing, candidate);
    }

    private static boolean hasEntryForClass(List<ChainHop> path, String className) {
        if (path == null || className == null) {
            return false;
        }
        return path.stream().anyMatch(hop -> hop.kind() == HopKind.ENTRY
                && className.equals(hop.fromOwner()));
    }

    private static boolean hasSyntheticProxyRoot(List<ChainHop> path) {
        return path != null && path.stream().anyMatch(hop -> hop.kind() == HopKind.ENTRY
                && "proxyInvoke".equals(hop.reason()));
    }

    private void addField(String owner, String field, String descriptor, boolean isStatic,
                          List<ChainHop> path) {
        String key = fieldKey(owner, field, descriptor, isStatic);
        if (!sourceBacked(path) || path.size() > MAX_HOPS) {
            return;
        }
        List<ChainHop> snapshot = List.copyOf(path);
        boolean exactAlternativeRetained = rememberAlternative(fieldTaintedAlternatives, key,
                snapshot);
        String nameKey = fieldNameKey(owner, field, isStatic);
        boolean nameAlternativeRetained = rememberAlternative(fieldTaintedByNameAlternatives,
                nameKey, snapshot);
        if (!better(fieldTainted.get(key), path)) {
            if (exactAlternativeRetained || nameAlternativeRetained) {
                recordAlternativeFact();
            }
            return;
        }
        fieldTainted.put(key, snapshot);
        recordPrimaryFact();
        if (better(fieldTaintedByName.get(nameKey), path)) {
            fieldTaintedByName.put(nameKey, snapshot);
        }
        Set<String> readers = fieldReaders.get(key);
        if (readers != null) {
            readers.forEach(this::activateAndEnqueue);
        }
    }

    private static String fieldKey(InsnFact insn) {
        return fieldKey(insn.fieldRef(), insn.op());
    }

    private static String fieldKey(io.just.sast.model.FieldRef ref, Op op) {
        return fieldKey(ref.owner(), ref.name(), ref.descriptor(),
                op == Op.GETSTATIC || op == Op.PUTSTATIC);
    }

    private static String fieldKey(String owner, String field, String descriptor, boolean isStatic) {
        return owner + "#" + field + "#" + (descriptor == null ? "" : descriptor)
                + "#" + isStatic;
    }

    private static String fieldNameKey(String owner, String field, boolean isStatic) {
        return owner + "#" + field + "#" + isStatic;
    }

    private static boolean isDeserializationSource(Rule.SourceRule source) {
        return source != null && !"serialize".equalsIgnoreCase(source.bridge());
    }

    private static boolean isUnconditionalDeserializeSource(Rule.SourceRule source) {
        return isDeserializationSource(source) && (source.tainted() == null || source.tainted().isEmpty());
    }

    private void addReturn(String methodKey, List<ChainHop> path) {
        if (!sourceBacked(path) || path.size() > MAX_HOPS) {
            return;
        }
        List<ChainHop> snapshot = List.copyOf(path);
        boolean alternativeRetained = rememberAlternative(returnTaintedAlternatives, methodKey,
                snapshot);
        if (!better(returnTainted.get(methodKey), path)) {
            if (alternativeRetained) {
                recordAlternativeFact();
            }
            return;
        }
        returnTainted.put(methodKey, snapshot);
        recordPrimaryFact();
        enqueueReturnCallers(methodKey);
    }

    /** Reprocess callers when a method return frontier gains a new bounded alternative. */
    private void enqueueReturnCallers(String methodKey) {
        List<Node> callerCalls = callers.get(methodKey);
        if (callerCalls != null) {
            for (Node caller : callerCalls) {
                if (!options.reachablePrune() || reachable.contains(OriginSupport.methodKey(caller))) {
                    activateAndEnqueue(OriginSupport.methodKey(caller));
                }
            }
        }
    }

    private void addParam(String owner, String name, String desc, int slot, List<ChainHop> path) {
        String methodKey = OriginSupport.methodKeyOf(owner, name, desc);
        if (!scheduledMethod(methodKey)) {
            return;
        }
        String key = methodKey + "#" + slot;
        if (!sourceBacked(path) || path.size() > MAX_HOPS) {
            return;
        }
        List<ChainHop> snapshot = List.copyOf(path);
        boolean alternativeRetained = rememberAlternative(paramTaintedAlternatives, key,
                snapshot);
        if (!better(paramTainted.get(key), path)) {
            if (alternativeRetained) {
                recordAlternativeFact();
            }
            return;
        }
        paramTainted.put(key, snapshot);
        recordPrimaryFact();
        activateAndEnqueue(methodKey);
    }

    /** 候选是否严格优于现存：短者优先；同长按跳序列规范形字典序——总序，消除并行平局随机性。 */
    private static boolean better(List<ChainHop> existing, List<ChainHop> candidate) {
        if (existing == null) {
            return true;
        }
        // Provenance quality is meaningful only within the same source boundary.  A
        // concrete proxy callback must not outrank a shorter path rooted at a different
        // serialized object merely because it carries the callback marker; doing so turns
        // the class-level one-best summary into cross-object contamination (for example a
        // HashMap.readObject fact being replaced by a NestedMethodProperty path).  The
        // bounded alternative frontier still retains both roots for sink consumers.
        String existingEntry = entrySignature(existing);
        String candidateEntry = entrySignature(candidate);
        if (existingEntry != null && candidateEntry != null
                && !existingEntry.equals(candidateEntry)) {
            return shorterOrCanonical(candidate, existing);
        }
        int existingProvenance = provenanceQuality(existing);
        int candidateProvenance = provenanceQuality(candidate);
        if (existingProvenance != candidateProvenance) {
            return candidateProvenance > existingProvenance;
        }
        return shorterOrCanonical(candidate, existing);
    }

    private static boolean shorterOrCanonical(List<ChainHop> candidate, List<ChainHop> existing) {
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

    /** First serialized/source boundary in a forward path, used to scope provenance ranking. */
    private static String entrySignature(List<ChainHop> path) {
        if (path == null) {
            return null;
        }
        for (ChainHop hop : path) {
            if (hop.kind() == HopKind.ENTRY) {
                return hop.fromOwner() + "#" + hop.fromName() + "#"
                        + (hop.desc() == null ? "" : hop.desc()) + "#"
                        + (hop.reason() == null ? "" : hop.reason());
            }
        }
        return null;
    }

    /**
     * Prefer a concrete serialized-proxy callback over the synthetic proxyInvoke root when
     * both describe the same value.  This is provenance quality, not a benchmark-specific
     * ranking rule: the former has an observed Method-collection callback site and therefore
     * explains the runtime dispatch more precisely.  All other paths retain the historical
     * shortest-path ordering.
     */
    private static int provenanceQuality(List<ChainHop> path) {
        int quality = 0;
        for (ChainHop hop : path) {
            if ("serialized-proxy-handler".equals(hop.reason())
                    || "serialized-proxy-interface".equals(hop.reason())) {
                quality += 100;
            }
            if (hop.kind() == HopKind.ENTRY && "proxyInvoke".equals(hop.reason())) {
                quality -= 10;
            }
        }
        return quality;
    }

    /** Whether a path was introduced by the external serialized-proxy callback bridge. */
    private static boolean isExternalProxyPath(List<ChainHop> path) {
        return path != null && path.stream()
                .anyMatch(hop -> "serialized-proxy-handler".equals(hop.reason())
                        || "serialized-proxy-interface".equals(hop.reason()));
    }

    /**
     * Retain one candidate in a bounded fact frontier.  The primary summary remains the
     * shortest/most-specific fact; the frontier is ordered by a small structural value score
     * before length.  A longer path that crosses a platform serialization callback into a
     * concrete trigger override is more useful for later object dispatch than a collection of
     * shorter, unrelated lifecycle paths.  The score is generic and bounded; it is not tied to
     * a package, artifact, or known gadget.
     */
    private boolean rememberAlternative(Map<String, List<List<ChainHop>>> store, String key,
                                        List<ChainHop> path) {
        if (key == null || path == null || path.isEmpty()) {
            return false;
        }
        List<List<ChainHop>> paths = store.computeIfAbsent(key, ignored -> new ArrayList<>(2));
        if (paths.contains(path)) {
            return false;
        }
        // Once the frontier is full, avoid copying and sorting candidates that are already
        // no better than the current worst retained path.  This is a hot path during fact
        // convergence: the bounded frontier remains exact, while rejected lower-ranked
        // alternatives no longer pay O(k log k) work on every rediscovery.
        if (paths.size() >= MAX_PATH_ALTERNATIVES
                && comparePaths(path, paths.get(paths.size() - 1)) >= 0) {
            return false;
        }
        List<ChainHop> snapshot = List.copyOf(path);
        paths.add(snapshot);
        paths.sort(ForwardEngine::comparePaths);
        if (paths.size() > MAX_PATH_ALTERNATIVES) {
            paths.remove(paths.size() - 1);
            if (!pathAlternativeCapReported) {
                pathAlternativeCapReported = true;
                bb.markIncomplete("FORWARD_PATH_ALTERNATIVE_CAP:" + MAX_PATH_ALTERNATIVES);
            }
        }
        return paths.contains(snapshot);
    }

    /** Include the primary path for compatibility, then return a stable bounded frontier. */
    private static List<List<ChainHop>> candidatePaths(Map<String, List<ChainHop>> primary,
                                                        Map<String, List<List<ChainHop>>> alternatives,
                                                        String key) {
        List<List<ChainHop>> result = new ArrayList<>();
        List<ChainHop> main = primary.get(key);
        if (main != null) {
            result.add(main);
        }
        List<List<ChainHop>> extra = alternatives.get(key);
        if (extra != null) {
            result.addAll(extra);
        }
        return distinctPaths(result);
    }

    private List<List<ChainHop>> distinctBestPaths(List<List<ChainHop>> paths) {
        if (paths == null || paths.isEmpty()) {
            return List.of();
        }
        // Keep the bounded frontier online.  The old implementation materialized and sorted
        // every distinct path before dropping all but eight; model/return expansion can feed
        // hundreds of paths here, making the discarded tail the dominant allocation and
        // comparator cost.  Replacing only the current worst path is equivalent to a final
        // stable sort+prefix because comparePaths is a total order for all retained ties.
        List<List<ChainHop>> result = new ArrayList<>(Math.min(MAX_PATH_ALTERNATIVES,
                paths.size()));
        boolean exceeded = false;
        for (List<ChainHop> path : paths) {
            if (path == null || path.isEmpty()) {
                continue;
            }
            List<ChainHop> snapshot = List.copyOf(path);
            if (result.contains(snapshot)) {
                continue;
            }
            if (result.size() < MAX_PATH_ALTERNATIVES) {
                result.add(snapshot);
                continue;
            }
            exceeded = true;
            int worst = worstPathIndex(result);
            if (comparePaths(snapshot, result.get(worst)) < 0) {
                result.set(worst, snapshot);
            }
        }
        if (exceeded && !pathAlternativeCapReported) {
            pathAlternativeCapReported = true;
            bb.markIncomplete("FORWARD_PATH_ALTERNATIVE_CAP:" + MAX_PATH_ALTERNATIVES);
        }
        result.sort(ForwardEngine::comparePaths);
        return result.isEmpty() ? List.of() : List.copyOf(result);
    }

    private static int worstPathIndex(List<List<ChainHop>> paths) {
        int worst = 0;
        for (int i = 1; i < paths.size(); i++) {
            if (comparePaths(paths.get(worst), paths.get(i)) < 0) {
                worst = i;
            }
        }
        return worst;
    }

    private static List<List<ChainHop>> distinctPaths(List<List<ChainHop>> paths) {
        if (paths == null || paths.isEmpty()) {
            return List.of();
        }
        Set<List<ChainHop>> unique = new LinkedHashSet<>();
        for (List<ChainHop> path : paths) {
            if (path != null && !path.isEmpty()) {
                unique.add(List.copyOf(path));
            }
        }
        if (unique.isEmpty()) {
            return List.of();
        }
        List<List<ChainHop>> result = new ArrayList<>(unique);
        result.sort(ForwardEngine::comparePaths);
        return result;
    }

    private static int comparePaths(List<ChainHop> left, List<ChainHop> right) {
        if (left == right) {
            return 0;
        }
        if (left == null) {
            return 1;
        }
        if (right == null) {
            return -1;
        }
        int leftQuality = frontierQuality(left);
        int rightQuality = frontierQuality(right);
        if (leftQuality != rightQuality) {
            return Integer.compare(rightQuality, leftQuality);
        }
        if (left.size() != right.size()) {
            return Integer.compare(left.size(), right.size());
        }
        return compareCanonical(left, right);
    }

    /**
     * Structural ordering for the bounded provenance frontier.  Ordinary shortest-path
     * summaries intentionally do not use this score; it only decides which alternatives remain
     * auditable when many independent callbacks compete for the same method/field fact.
     */
    private static int frontierQuality(List<ChainHop> path) {
        if (path == null || path.isEmpty()) {
            return Integer.MIN_VALUE;
        }
        int score = 0;
        ChainHop entry = null;
        for (ChainHop hop : path) {
            if ("serialized-proxy-handler".equals(hop.reason())
                    || "serialized-proxy-interface".equals(hop.reason())) {
                score += 100;
            }
            if (hop.kind() == HopKind.ENTRY) {
                if (entry == null) {
                    entry = hop;
                }
                if ("proxyInvoke".equals(hop.reason())) {
                    score -= 10;
                }
            }
            if (isSerializedTriggerMethodName(hop.toName())) {
                score += 4;
                if (isJdkOwner(hop.fromOwner()) && !isJdkOwner(hop.toOwner())) {
                    // This is the generic shape of a JDK collection/adapter activating an
                    // override on a deserialized object (for example Object.hashCode/toString).
                    score += 24;
                } else if ("java/lang/Object".equals(hop.fromOwner())
                        && !isJdkOwner(hop.toOwner())) {
                    score += 12;
                }
            }
            if ("serialized-field".equals(hop.reason())) {
                score += 2;
            } else if (hop.reason() != null && hop.reason().startsWith("method-collection")) {
                // Exact Class metadata selection is still weaker than an explicit bytecode
                // call edge, while the fallback path is deliberately wildcard evidence.
                // Keep both auditable and below an observed bytecode trigger bridge.
                score += hop.reason().contains("-exact") ? 1 : -1;
            }
        }
        if (entry != null && isJdkOwner(entry.fromOwner())
                && JAVA_SERIALIZATION_ENTRY_KINDS.contains(entry.reason())) {
            score += 8;
        }
        return score;
    }

    private static boolean isSerializedTriggerMethodName(String name) {
        return "hashCode".equals(name) || "equals".equals(name)
                || "compareTo".equals(name) || "compare".equals(name)
                || "toString".equals(name);
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

    private List<ChainHop> hopTo(List<ChainHop> parent, MethodInfo from,
                                 String toOwner, String toName, String toDesc, EdgeType type) {
        return hopTo(parent, from, toOwner, toName, toDesc, type, null);
    }

    private List<ChainHop> hopTo(List<ChainHop> parent, MethodInfo from,
                                 String toOwner, String toName, String toDesc, EdgeType type,
                                 Integer argOrdinal) {
        return appendMethodHop(parent, from, toOwner, toName, toDesc,
                type == EdgeType.DISPATCHES ? HopKind.VIRTUAL_DISPATCH : HopKind.DIRECT_CALL,
                "call", argOrdinal);
    }

    /**
     * Append a method-level provenance hop while cutting recursive summaries.  Forward facts
     * are method summaries, not object identities: revisiting the same exact method therefore
     * cannot add distinguishable value-flow information, but it can consume the whole bounded
     * path frontier (notably through reflective method-collection callbacks).  Keep the cut
     * explicit in completeness so a recursive/alias-heavy result is never presented as fully
     * explored.
     */
    private List<ChainHop> appendMethodHop(List<ChainHop> parent, MethodInfo from,
                                           String toOwner, String toName, String toDesc,
                                           HopKind kind, String reason, Integer argOrdinal) {
        if (parent == null) {
            return null;
        }
        if (parent.size() >= MAX_HOPS) {
            bb.markIncomplete("FORWARD_HOP_CAP:" + MAX_HOPS);
            return null;
        }
        if (containsMethodTarget(parent, toOwner, toName, toDesc)) {
            bb.markIncomplete("FORWARD_PATH_CYCLE_CUT");
            return null;
        }
        List<ChainHop> path = new ArrayList<>(parent);
        path.add(new ChainHop(from.owner(), from.name(), toOwner, toName,
                kind, null, reason, toDesc, argOrdinal));
        return List.copyOf(path);
    }

    /** Exact method identity used by the cycle cut; FIELD_FLOW hops are deliberately ignored. */
    private static boolean containsMethodTarget(List<ChainHop> path, String owner,
                                                String name, String descriptor) {
        if (path == null || owner == null || name == null || descriptor == null) {
            return false;
        }
        for (ChainHop hop : path) {
            if (hop.kind() == HopKind.FIELD_FLOW || hop.kind() == null) {
                continue;
            }
            if (owner.equals(hop.toOwner()) && name.equals(hop.toName())
                    && descriptor.equals(hop.desc())) {
                return true;
            }
        }
        return false;
    }

    /** A serialized field flow repeated on one summary is an object-graph cycle, not new data. */
    private static boolean containsSerializedFieldFlow(List<ChainHop> path, MethodInfo method,
                                                       ValueOrigin.FieldRead field) {
        if (path == null || method == null || field == null) {
            return false;
        }
        for (ChainHop hop : path) {
            if (hop.kind() == HopKind.FIELD_FLOW
                    && method.owner().equals(hop.fromOwner())
                    && method.name().equals(hop.fromName())
                    && field.field().equals(hop.field())) {
                return true;
            }
        }
        return false;
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

    /** Non-static, non-transient instance state restored by Java serialization. */
    private boolean isSerializedField(String owner, String field) {
        if (owner == null || field == null || !bb.hierarchy().isSerializable(owner)) {
            return false;
        }
        ClassInfo cls = bb.hierarchy().classInfo(owner);
        if (cls == null || cls.field(field) == null) {
            // An unresolved class/field is an explicit uncertainty boundary. Keep the
            // conservative serialized-field interpretation rather than silently dropping
            // data that defaultReadObject may restore.
            return true;
        }
        return !java.lang.reflect.Modifier.isTransient(cls.field(field).access());
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
