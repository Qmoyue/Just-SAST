package io.just.sast.analysis.taint;

import io.just.sast.analysis.hierarchy.ClassHierarchy;
import io.just.sast.config.RuleEngine;
import io.just.sast.cpg.build.Cfg;
import io.just.sast.cpg.build.CfgLabel;
import io.just.sast.cpg.build.CpgIndex;
import io.just.sast.cpg.graph.Edge;
import io.just.sast.cpg.graph.EdgeType;
import io.just.sast.cpg.graph.Graph;
import io.just.sast.cpg.graph.Node;
import io.just.sast.cpg.graph.NodeType;
import io.just.sast.model.ClassInfo;
import io.just.sast.model.Descriptor;
import io.just.sast.model.FieldRef;
import io.just.sast.model.InsnFact;
import io.just.sast.model.MethodInfo;
import io.just.sast.model.MethodRef;
import io.just.sast.model.Op;
import io.just.sast.model.TypeRef;
import io.just.sast.model.TryCatchFact;
import io.just.sast.util.JustLogger;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.BitSet;
import java.util.Collection;
import java.util.Collections;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.Arrays;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * 共享分析支撑（经黑板分发，全部知识源复用同一实例）：
 * 调用点索引、方法解析缓存、跨方法实参定位、公共判定谓词、入口下游闭包。
 */
public final class OriginSupport {

    /** JVM descriptor of the callback method supplied by the proxy runtime. */
    public static final String SERIALIZED_PROXY_HANDLER_DESCRIPTOR =
            "(Ljava/lang/Object;Ljava/lang/reflect/Method;[Ljava/lang/Object;)Ljava/lang/Object;";
    private static final int MAX_SERIALIZED_PROXY_HANDLERS = 1024;

    private final Graph graph;
    private final CpgIndex cpgIndex;
    private final ForwardOrigins origins;
    private final Map<String, Long> callIdByKey = new HashMap<>();
    private final Map<String, MethodInfo> methodCache = new java.util.concurrent.ConcurrentHashMap<>();
    /**
     * 负方法解析缓存带层次版本。大型 JAR 的调用图包含大量外部/未加载方法节点；
     * 在没有这个集合时，每个 sink 回溯都会重复走 classInfo + 父类解析。JDK 懒加载
     * 会改变层次，所以不能使用无版本的永久负缓存。
     */
    private final Map<String, Long> missingMethodCache = new java.util.concurrent.ConcurrentHashMap<>();
    private final ClassHierarchy hierarchy;
    private final RuleEngine ruleEngine;
    /** 入口下游闭包（惰性一次构建）：反向剪枝与链剪枝共用。 */
    private Set<String> entryDownstream;
    /** 入口 BFS 距离（与下游闭包同一次遍历产出）：反向探索按离入口近者优先。 */
    private Map<String, Integer> entryDepths;
    /**
     * Sink-relevance index used by bounded dynamic dispatch.  The index is built together
     * with the semantic entry closure, so a dispatch candidate can be ranked by an
     * already-proven ordinary path to a configured sink without rescanning the graph for
     * every call site.  It is a hint for finite candidate ordering, never a soundness gate.
     */
    private Map<String, Integer> sinkDistanceIndex = Map.of();
    /**
     * JDK-owned serialization callbacks that are safe to admit as roots because their
     * already-materialized body has an ordinary path to a configured sink.  JDK callbacks
     * are not global roots: this bounded, sink-relevant set bridges the ObjectInputStream
     * runtime callback that is absent from ordinary bytecode edges without re-expanding the
     * whole JDK image.
     */
    private Set<String> deserializationCallbackEntries = Set.of();
    /** 接口分发解析记忆：owner#name+desc → (解析类, 方法节点) 列表——闭包展开对同一
     * 接口签名的全部调用点复用（transitiveSubtypes + resolveMethod + findMethodNode 只算一次）。 */
    private final Map<String, List<Object[]>> ifaceDispatchCache = new HashMap<>();
    /** 反射跳索引（FLASH 反射跳边的向后版）：常量类 → Method.invoke 调用点（名字常量时精确映射）。 */
    private final Map<String, List<Node>> reflectiveInvokeByClass = new HashMap<>();
    private final Map<String, Node> reflectiveInvokeByMethod = new HashMap<>();
    private final Map<Long, List<String>> reflectiveClassesBySite = new HashMap<>();
    /** Reflective calls are also queried by constant-feasibility proofs. Keep a compact
     * call-site list so those proofs never rescan every CALL node in a large artifact. */
    private final List<Node> reflectiveInvokeCalls = new ArrayList<>();
    /** 框架包内的 Method.invoke 位点——框架反射供给的调用者池（包前缀源自 source 规则声明）。 */
    private final List<Node> frameworkMethodInvokeSites = new ArrayList<>();
    /** InvocationHandler 内由代理运行时提供 Method 参数的反射调用位点。 */
    private final List<Node> proxyMethodInvokeSites = new ArrayList<>();
    /** Method.invoke sites consuming a Method object obtained from a typed iterator/list read. */
    private final List<Node> methodCollectionInvokeSites = new ArrayList<>();
    /** Serializable InvocationHandler implementations callable by an externally assembled JDK proxy. */
    private final List<Node> serializedProxyHandlerMethods = new ArrayList<>();
    /**
     * Interface call sites that may be dispatched by a proxy assembled outside the scanned
     * artifact.  The ordinary call graph cannot connect these sites to an
     * {@code InvocationHandler}; keeping the bounded site index here lets both taint engines
     * apply the same external-proxy bridge without inventing a whole-world call edge.
     */
    private final List<Node> serializedProxyInterfaceCallSites = new ArrayList<>();
    /** Cached target family for typed Method-collection callbacks. */
    private List<Node> methodCollectionTargetMethods = List.of();
    /** Per-site target family after recovering Class.getMethods/getDeclaredMethods metadata. */
    private final Map<Long, List<Node>> methodCollectionTargetsBySite = new HashMap<>();
    /** Reverse index used by backward traces to avoid site × target rescans. */
    private final Map<String, List<Node>> methodCollectionSitesByTarget = new HashMap<>();
    /** Sites whose Method array came from a concrete Class metadata call. */
    private final Set<Long> preciseMethodCollectionSites = new HashSet<>();
    /**
     * Native call sites whose same-receiver callback family is structurally recoverable.
     * JNI bytecode is outside the Java class file, so this index deliberately models only
     * the bounded contract that can be justified from both sides: an instance native call
     * may call a public/protected, no-argument, void Java method on the same receiver type.
     * Unknown native callbacks remain an explicit completeness boundary instead of turning
     * every native call into a call to every application method.
     */
    private final Map<String, List<Node>> nativeCallbackSitesByTarget = new HashMap<>();
    private final Map<Long, List<Node>> nativeCallbackTargetsBySite = new HashMap<>();
    /** JavaBean 反射位点是否存在于框架包内（入口闭包的框架供给门）。 */
    private boolean frameworkJavabeanSite;
    /** 图中存在 bridge=deserialize 的框架源调用：JavaBean setter 参数可由外部对象绑定提供。 */
    private boolean frameworkDeserializeSourceAvailable;
    /** 框架包前缀（source 规则声明的框架入口类派生，前 3 段——框架反射供给门的数据源）。 */
    private final Set<String> frameworkPackages;
    /** JavaBean 反射跳：接收者类型 → invoke 位点；类型不可解 → wildcard 位点。 */
    private final Map<String, List<Long>> javabeanSitesByClass = new HashMap<>();
    /** 反向索引：invoke 位点 → 已解析接收者类型，避免闭包阶段逐类扫描 site id。 */
    private final Map<Long, String> javabeanClassBySite = new HashMap<>();
    private final List<Long> javabeanWildcardSites = new ArrayList<>();
    private final Map<Long, String> javabeanSiteKinds = new HashMap<>();
    /** 占位类型集（JavaBean wildcard 精度门，惰性）。 */
    private java.util.Set<String> occupiableTypes;
    /** Shared semantic completeness boundaries discovered by hierarchy/reflection helpers. */
    private final Set<String> completenessReasons = ConcurrentHashMap.newKeySet();
    private static final int SUBTYPE_TRAVERSAL_CAP = 10_000;
    private static final int SINK_REACHABILITY_CAP = 200_000;
    private static final int METHOD_COLLECTION_TARGET_CAP = 512;
    private static final int METHOD_COLLECTION_SITE_TARGET_CAP = 128;
    private static final int SERIALIZED_PROXY_INTERFACE_SITE_CAP = 4096;
    private static final int JDK_SERIALIZATION_CALLBACK_CAP = 128;
    private static final int JDK_CALLBACK_TRIGGER_SEARCH_CAP = 256;
    private static final Set<String> JDK_SERIALIZATION_ENTRY_KINDS = Set.of(
            "readObject", "readObjectNoData", "readResolve", "readExternal", "validateObject");
    /**
     * These lifecycle names describe a callback activated by a deserialized object graph;
     * they are not independent bytecode sources.  Keeping this boundary identical to the
     * forward engine prevents a short hashCode/equals/toString root from hiding the actual
     * readObject/container boundary in class-level summaries.
     */
    private static final Set<String> SERIALIZED_TRIGGER_ENTRY_KINDS = Set.of(
            "hashCode", "equals", "compareTo", "compare", "toString");

    /**
     * 方法内字段重初始化的支配关系只在 receiver 精度查询时按需建立。
     * 大工件绝不能为每个方法预分配 O(n^2) dominator 位图，因此超过上限的
     * 方法不进入缓存，调用方回退到未知 receiver 的保守语义。
     */
    private final ConcurrentHashMap<String, DominatorIndex> fieldDominators =
            new ConcurrentHashMap<>();
    /** Lazily materialized field-write offsets. The CPG already records these offsets; the
     * cache avoids scanning every instruction when a receiver proof asks about one field. */
    private final ConcurrentHashMap<String, int[]> fieldWriteOffsetsByMethod =
            new ConcurrentHashMap<>();
    /**
     * The reverse proof asks for the same method's write slice from several sink traces.  The
     * scan graph is frozen, so a worker-local identity fast path avoids rebuilding the method
     * key and entering the shared map on every field/receiver proof.  The shared map remains
     * the bounded-cross-thread fallback; this cache is only an allocation-saving projection.
     */
    private static final int LOCAL_FIELD_WRITE_CACHE_LIMIT = 16_384;
    private final ThreadLocal<IdentityHashMap<MethodInfo, int[]>> localFieldWriteOffsets =
            ThreadLocal.withInitial(() -> new IdentityHashMap<>(256));
    /** Receiver facts are pure for a fixed hierarchy revision, but the same call site is
     * visited by many sink traces and target declarations. Cache the expensive origin proof
     * once per call site, not once per call/target pair; the bound prevents a broad CHA graph
     * from trading CPU for an unbounded table. */
    private static final int RECEIVER_SUMMARY_CACHE_LIMIT = 250_000;
    private record ReceiverDispatchSummary(ForwardOrigins.Result originResult,
                                           Set<String> exactTypes,
                                           Set<String> possibleTypes, boolean platformBound) {
    }
    private final ConcurrentHashMap<Long, ReceiverDispatchSummary> receiverSummaries =
            new ConcurrentHashMap<>();
    private static final int DOMINATOR_METHOD_LIMIT = 4096;

    /**
     * Exact CFG feasibility is a precision refinement, not the source of taint facts.  It
     * must therefore fail open when constant propagation becomes expensive.  Large JARs
     * commonly contain many callers of a small method; without a per-proof memo/budget the
     * interprocedural parameter walk becomes exponential and can dominate the scan.
     */
    public static final int CONSTANT_PROOF_BUDGET = 4096;
    private final Map<CfgProofKey, Boolean> sinkPathCache = new ConcurrentHashMap<>();
    private final ThreadLocal<ConstantProofContext> constantProof = new ThreadLocal<>();
    private final AtomicBoolean constantProofBudgetExceeded = new AtomicBoolean();

    private record CfgProofKey(String methodKey, int offset) {
    }

    private record ConstantFactKey(String methodKey, ValueOrigin value) {
    }

    private static final class ConstantProofContext {
        private int remaining = CONSTANT_PROOF_BUDGET;
        private final Map<ConstantFactKey, Integer> facts = new HashMap<>();
        private final Set<ConstantFactKey> active = new HashSet<>();

        private boolean consume() {
            return remaining-- > 0;
        }
    }

    private record DominatorIndex(BitSet[] dominators, boolean[] reachable) {
    }

    private final java.util.Map<Long, Node> callNodes = new HashMap<>();
    /**
     * Exact sink-path feasibility is only useful for methods containing a path-sensitive
     * construct (a conditional, CHECKCAST, or reflective lookup/invocation). Ordinary
     * dependency methods have the same reachability semantics as the forward state map;
     * doing a reverse fixed-point walk for every ordinary call site was pure overhead on
     * large closures.
     */
    private final ConcurrentHashMap<String, Boolean> pathProofFeatureCache =
            new ConcurrentHashMap<>();

    public OriginSupport(Graph graph, ClassHierarchy hierarchy, RuleEngine ruleEngine, boolean fast) {
        this(graph, hierarchy, ruleEngine, fast, CpgIndex.empty());
    }

    public OriginSupport(Graph graph, ClassHierarchy hierarchy, RuleEngine ruleEngine,
                         boolean fast, CpgIndex cpgIndex) {
        this.graph = graph;
        this.cpgIndex = cpgIndex == null ? CpgIndex.empty() : cpgIndex;
        this.hierarchy = hierarchy;
        this.ruleEngine = ruleEngine;
        this.frameworkPackages = deriveFrameworkPackages();
        // CALL ids are already grouped by host method in the frozen CPG. Forward transfer
        // can therefore resolve an invoke by (method key, offset) without allocating the
        // transient "method@offset" string used by the compatibility map.
        this.origins = new ForwardOrigins((methodKey, offset) -> {
            Node call = graph.findCallNode(methodKey, offset);
            return call == null ? null : call.id();
        }, this.cpgIndex::cfg);
        for (Node call : graph.nodesOfType(NodeType.CALL)) {
            callIdByKey.put(methodKey(call) + "@" + call.strProp("offset"), call.id());
            callNodes.put(call.id(), call);
        }
        frameworkDeserializeSourceAvailable = hasDeserializeSource(graph);
        indexReflectiveJumps(graph);
        indexSerializedProxyHandlers(graph);
        indexSerializedProxyInterfaceCalls(graph);
        indexNativeCallbacks(graph);
    }

    /** Shared CFG access for all semantic consumers, including bounded metadata analyses. */
    public Cfg.Indexed cfg(MethodInfo method) {
        return cpgIndex.cfg(method);
    }

    public CpgIndex cpgIndex() {
        return cpgIndex;
    }

    /** Forward summaries are a per-scan memo only; release them before the scan is returned. */
    public int forwardOriginCacheSize() {
        return origins.cacheSize();
    }

    public long forwardOriginComputeCalls() {
        return origins.computeCalls();
    }

    public long forwardOriginCacheHits() {
        return origins.cacheHits();
    }

    public long forwardOriginAnalysisRuns() {
        return origins.analysisRuns();
    }

    public void clearForwardOriginCache() {
        origins.clearCache();
    }

    /** Completeness boundaries discovered while lazy semantic indexes are built. */
    public Set<String> completenessReasons() {
        return orderedStrings(completenessReasons);
    }

    private void markIncomplete(String reason) {
        if (reason != null && !reason.isBlank()) {
            completenessReasons.add(reason);
        }
    }

    /**
     * Keep externally observable finite sets deterministic without imposing a sorted data
     * structure on the hot analysis maps.  Several callers use the returned set to seed a
     * bounded work list, so Set.copyOf is not sufficient here: its iteration order is an
     * implementation detail and turns the cap into a result-changing choice.
     */
    private static Set<String> orderedStrings(Collection<String> values) {
        if (values == null || values.isEmpty()) {
            return Set.of();
        }
        List<String> ordered = new ArrayList<>(values.size());
        for (String value : values) {
            if (value != null) {
                ordered.add(value);
            }
        }
        ordered.sort(String::compareTo);
        return Collections.unmodifiableSet(new LinkedHashSet<>(ordered));
    }

    private static Set<ValueOrigin> orderedOrigins(Collection<ValueOrigin> values) {
        if (values == null || values.isEmpty()) {
            return Set.of();
        }
        return Collections.unmodifiableSet(new LinkedHashSet<>(ValueOriginOrder.sorted(values)));
    }

    /**
     * source 规则的 bridge 是数据契约，不把某个具体框架或目标类写进引擎：
     * 只要已加载图中存在一个无条件 deserialize source 调用，就允许后续 JavaBean
     * setter 作为框架对象绑定边界参与反向污点分析。带 tainted 前置条件的 source
     * 是二次反序列化/转换桥，不能把整个依赖图提升为外部对象绑定入口。
     */
    private boolean hasDeserializeSource(Graph graph) {
        for (Node call : graph.nodesOfType(NodeType.CALL)) {
            var source = ruleEngine.matchingSource(call.strProp("owner"), call.strProp("name"),
                    call.strProp("desc"));
            if (source.isPresent() && isUnconditionalDeserializeSource(source.get())) {
                return true;
            }
        }
        return false;
    }

    private static boolean isDeserializeSource(io.just.sast.config.Rule.SourceRule source) {
        return source != null && !"serialize".equalsIgnoreCase(source.bridge());
    }

    private static boolean isUnconditionalDeserializeSource(io.just.sast.config.Rule.SourceRule source) {
        return isDeserializeSource(source) && (source.tainted() == null || source.tainted().isEmpty());
    }

    private boolean isDeserializeEntry(io.just.sast.config.Rule.MagicEntryRule entry,
                                       String owner) {
        if (entry == null || !"deserialize".equalsIgnoreCase(entry.direction())) {
            return false;
        }
        // InvocationHandler.invoke is a callback contract, not a deserialization
        // source by itself.  A serializable handler becomes attacker-controlled only
        // after an actual proxy callback edge (for example a Method collection invoke)
        // has been justified.  Treating every serializable implementation as a root
        // creates a short synthetic path to its sinks and hides the real trigger.
        return !"proxyInvoke".equals(entry.entryKind())
                && !SERIALIZED_TRIGGER_ENTRY_KINDS.contains(entry.entryKind());
    }

    /**
     * Rank typed Method-collection targets by the amount of runtime evidence available.
     * Interface declarations are intentionally ahead of ordinary concrete getters: an
     * externally assembled JDK proxy exposes Methods from its proxy interfaces, while the
     * concrete InvocationHandler implementation may not be present in the scanned artifact.
     * Sink-relevant concrete methods remain first, and the finite cap still bounds wildcard
     * expansion for dependency-heavy archives.
     */
    private int methodCollectionTargetRank(Node node, Map<String, Integer> sinkDistances) {
        String owner = node.strProp("owner");
        ClassInfo classInfo = hierarchy.classInfo(owner);
        if (sinkDistances.containsKey(methodKeyOf(owner, node.strProp("name"), node.strProp("desc")))) {
            return 0;
        }
        if (classInfo != null && classInfo.isInterface()) {
            return 1;
        }
        if (hierarchy.isSerializable(owner)) {
            return 2;
        }
        return 3;
    }

    /**
     * Build a finite Method collection target family for every invoke site.  The old model
     * used one global getter family for all sites, which was both imprecise and unable to
     * represent the common {@code Class.getDeclaredMethods()[i]} shape.  A concrete Class
     * metadata producer gives us a JVM-level owner constraint; an opaque iterator/list keeps
     * the older bounded getter fallback.
     */
    private void buildMethodCollectionTargets(Graph graph, Map<String, Integer> sinkDistances) {
        methodCollectionTargetsBySite.clear();
        preciseMethodCollectionSites.clear();
        Set<Node> globalTargets = new LinkedHashSet<>();
        List<Node> sites = new ArrayList<>(methodCollectionInvokeSites);
        sites.sort(java.util.Comparator.comparing((Node node) -> methodKeyOf(
                        node.methodOwner(), node.methodName(), node.methodDescriptor()))
                .thenComparingInt(node -> node.prop("offset") instanceof Integer offset
                        ? offset : Integer.MAX_VALUE)
                .thenComparingLong(Node::id));
        List<Node> fallbackTargets = null;
        Map<String, List<MethodInfo>> classTargetCache = new HashMap<>();
        for (Node site : sites) {
            Map<String, Boolean> classSources = methodCollectionClassSources(site);
            List<Node> targets = new ArrayList<>();
            boolean allowNonPublic = methodCollectionAllowsNonPublic(site);
            if (!classSources.isEmpty()) {
                Map<String, Node> unique = new TreeMap<>();
                for (Map.Entry<String, Boolean> source : classSources.entrySet()) {
                    String cacheKey = source.getKey() + "|" + source.getValue()
                            + "|accessible=" + allowNonPublic;
                    List<MethodInfo> classTargets = classTargetCache.computeIfAbsent(cacheKey,
                            ignored -> methodCollectionTargets(source.getKey(), source.getValue(),
                                    allowNonPublic));
                    for (MethodInfo target : classTargets) {
                        String key = methodKey(target);
                        Node node = graph.findMethodNode(target.owner(), target.name(),
                                target.descriptor());
                        if (node != null && collectionTargetRelevant(target, key, sinkDistances)) {
                            unique.putIfAbsent(key, node);
                        }
                    }
                }
                targets.addAll(unique.values());
                // A recovered Class source is not by itself an exact target proof: the class may
                // be external to the scan or none of its methods may be relevant to a sink.  Do
                // not label the bounded fallback as exact in that case.
                if (!targets.isEmpty()) {
                    preciseMethodCollectionSites.add(site.id());
                }
            }
            if (targets.isEmpty()) {
                // No concrete Class metadata was recovered.  Keep the original structural
                // fallback, but only expose public read methods and cap it per site before
                // merging into the global family.
                if (fallbackTargets == null) {
                    fallbackTargets = new ArrayList<>();
                    for (Node candidate : graph.nodesOfType(NodeType.METHOD)) {
                        MethodInfo target = methodOf(candidate.owner(), candidate.name(),
                                candidate.descriptor());
                        if (target != null && javaBeanMatches(target, "read")) {
                            fallbackTargets.add(candidate);
                        }
                    }
                    fallbackTargets = List.copyOf(fallbackTargets);
                }
                targets.addAll(fallbackTargets);
            }
            targets.sort(java.util.Comparator
                    .comparingInt((Node node) -> methodCollectionTargetRank(node, sinkDistances))
                    .thenComparingInt(node -> sinkDistances.getOrDefault(methodKeyOf(
                            node.owner(), node.name(), node.descriptor()), Integer.MAX_VALUE))
                    .thenComparing(Node::owner)
                    .thenComparing(Node::name)
                    .thenComparing(Node::descriptor));
            if (targets.size() > METHOD_COLLECTION_SITE_TARGET_CAP) {
                markIncomplete("METHOD_COLLECTION_SITE_TARGET_CAP:" +
                        METHOD_COLLECTION_SITE_TARGET_CAP);
                targets = targets.subList(0, METHOD_COLLECTION_SITE_TARGET_CAP);
            }
            List<Node> frozen = List.copyOf(targets);
            methodCollectionTargetsBySite.put(site.id(), frozen);
            globalTargets.addAll(frozen);
        }
        List<Node> ordered = new ArrayList<>(globalTargets);
        ordered.sort(java.util.Comparator
                .comparingInt((Node node) -> methodCollectionTargetRank(node, sinkDistances))
                .thenComparingInt(node -> sinkDistances.getOrDefault(methodKeyOf(
                        node.owner(), node.name(), node.descriptor()), Integer.MAX_VALUE))
                .thenComparing(Node::owner)
                .thenComparing(Node::name)
                .thenComparing(Node::descriptor));
        if (ordered.size() > METHOD_COLLECTION_TARGET_CAP) {
            markIncomplete("METHOD_COLLECTION_TARGET_CAP:" + METHOD_COLLECTION_TARGET_CAP);
            ordered = ordered.subList(0, METHOD_COLLECTION_TARGET_CAP);
        }
        methodCollectionTargetMethods = List.copyOf(ordered);
        methodCollectionSitesByTarget.clear();
        for (Node site : sites) {
            for (Node target : methodCollectionTargetsBySite.getOrDefault(site.id(), List.of())) {
                methodCollectionSitesByTarget.computeIfAbsent(methodKeyOf(target.owner(),
                                target.name(), target.descriptor()), ignored -> new ArrayList<>())
                        .add(site);
            }
        }
        for (Map.Entry<String, List<Node>> entry : methodCollectionSitesByTarget.entrySet()) {
            entry.getValue().sort(java.util.Comparator.comparing((Node node) -> methodKeyOf(
                            node.methodOwner(), node.methodName(), node.methodDescriptor()))
                    .thenComparingInt(node -> node.prop("offset") instanceof Integer offset
                            ? offset : Integer.MAX_VALUE)
                    .thenComparingLong(Node::id));
            entry.setValue(List.copyOf(entry.getValue()));
        }
    }

    private boolean collectionTargetRelevant(MethodInfo target, String key,
                                             Map<String, Integer> sinkDistances) {
        return sinkDistances.containsKey(key)
                || ruleEngine.matchingSink(target.owner(), target.name(), target.descriptor()).isPresent()
                || javaBeanMatches(target, "read");
    }

    /** Return methods from a concrete Class metadata result, including getMethods ancestors. */
    private List<MethodInfo> methodCollectionTargets(String className, boolean inherited,
                                                      boolean allowNonPublic) {
        Map<String, MethodInfo> result = new TreeMap<>();
        Deque<String> work = new ArrayDeque<>();
        Set<String> seen = new HashSet<>();
        work.add(className);
        while (!work.isEmpty()) {
            String current = work.removeFirst();
            if (!seen.add(current)) {
                continue;
            }
            ClassInfo info = hierarchy.classInfo(current);
            if (info == null) {
                continue;
            }
            for (MethodInfo method : info.methods()) {
                if ("<init>".equals(method.name()) || "<clinit>".equals(method.name())) {
                    continue;
                }
                // getDeclaredMethods may return non-public methods.  They are admitted only when
                // this exact Method value is proven to receive setAccessible(true) in the same
                // host; getMethods remains public-only by JVM contract.
                if (java.lang.reflect.Modifier.isPublic(method.access()) || allowNonPublic) {
                    result.putIfAbsent(methodKey(method), method);
                }
            }
            if (!inherited) {
                continue;
            }
            if (info.superName() != null) {
                work.addLast(info.superName());
            }
            work.addAll(info.interfaces());
        }
        return List.copyOf(result.values());
    }

    /** Whether the Method values at one collection site receive a proven access override. */
    private boolean methodCollectionAllowsNonPublic(Node site) {
        if (site == null) {
            return false;
        }
        MethodInfo host = enclosingMethod(site);
        if (host == null) {
            return false;
        }
        ForwardOrigins.Result result = origins.compute(host);
        Set<ValueOrigin> methods = argOriginAtOrdinal(site, -1, result);
        return !methods.isEmpty() && hasAccessibleOverride(host, site, methods, result);
    }

    /** Recover Class metadata owners behind one Method[] element. */
    private Map<String, Boolean> methodCollectionClassSources(Node invoke) {
        MethodInfo host = enclosingMethod(invoke);
        if (host == null) {
            return Map.of();
        }
        ForwardOrigins.Result result = origins.compute(host);
        Map<String, Boolean> sources = new TreeMap<>();
        for (ValueOrigin value : argOriginAtOrdinal(invoke, -1, result)) {
            collectMethodCollectionClasses(value, host, result, sources, new HashSet<>());
        }
        return sources;
    }

    private void collectMethodCollectionClasses(ValueOrigin value, MethodInfo host,
                                                ForwardOrigins.Result result,
                                                Map<String, Boolean> sources,
                                                Set<ValueOrigin> visiting) {
        if (value == null || !visiting.add(value)) {
            return;
        }
        try {
            if (value instanceof ValueOrigin.Insn instruction
                    && instruction.offset() >= 0
                    && instruction.offset() < host.instructions().size()) {
                InsnFact fact = host.insnAt(instruction.offset());
                ForwardOrigins.State before = result.stateBefore().get(instruction.offset());
                if (before == null || before.stack().isEmpty()) {
                    return;
                }
                if (fact.op() == Op.CHECKCAST) {
                    collectMethodCollectionClasses(before.stack()
                                    .get(before.stack().size() - 1).origins(), host, result,
                            sources, visiting);
                    return;
                }
                if (fact.op() == Op.AALOAD && before.stack().size() >= 2) {
                    // ..., arrayref, index -> arrayref is immediately below the index.
                    collectMethodCollectionClasses(before.stack()
                                    .get(before.stack().size() - 2).origins(), host, result,
                            sources, visiting);
                    return;
                }
            }
            if (!(value instanceof ValueOrigin.CallResult callResult)
                    || callResult.callNodeId() < 0) {
                return;
            }
            Node producer = callNodes.get(callResult.callNodeId());
            if (producer == null || !"java/lang/Class".equals(producer.owner())
                    || !("getMethods".equals(producer.name())
                    || "getDeclaredMethods".equals(producer.name()))) {
                return;
            }
            MethodInfo producerHost = enclosingMethod(producer);
            if (producerHost == null) {
                return;
            }
            ForwardOrigins.Result producerResult = origins.compute(producerHost);
            String className = classNameFromClassValue(argOriginAtOrdinal(producer, -1,
                    producerResult), producerHost, producerResult, new HashSet<>());
            if (className != null) {
                sources.merge(className, "getMethods".equals(producer.name()), Boolean::logicalOr);
            }
        } finally {
            visiting.remove(value);
        }
    }

    private void collectMethodCollectionClasses(Set<ValueOrigin> values, MethodInfo host,
                                                ForwardOrigins.Result result,
                                                Map<String, Boolean> sources,
                                                Set<ValueOrigin> visiting) {
        for (ValueOrigin value : ValueOriginOrder.sorted(values)) {
            collectMethodCollectionClasses(value, host, result, sources, visiting);
        }
    }

    private String classNameFromClassValue(Set<ValueOrigin> values, MethodInfo host,
                                           ForwardOrigins.Result result,
                                           Set<ValueOrigin> visiting) {
        if (values == null || values.isEmpty()) {
            return null;
        }
        String answer = null;
        for (ValueOrigin value : ValueOriginOrder.sorted(values)) {
            String candidate = classNameFromClassValue(value, host, result, visiting);
            if (candidate == null || (answer != null && !answer.equals(candidate))) {
                return null;
            }
            answer = candidate;
        }
        return answer;
    }

    private String classNameFromClassValue(ValueOrigin value, MethodInfo host,
                                           ForwardOrigins.Result result,
                                           Set<ValueOrigin> visiting) {
        if (value == null || !visiting.add(value)) {
            return null;
        }
        try {
            if (value instanceof ValueOrigin.Constant constant) {
                if (constant.value() instanceof TypeRef type) {
                    return internalClassName(type.descriptor());
                }
                if (constant.value() instanceof String text && !text.isBlank()) {
                    return text.replace('.', '/');
                }
                return null;
            }
            if (value instanceof ValueOrigin.Insn instruction
                    && instruction.offset() >= 0
                    && instruction.offset() < host.instructions().size()) {
                ForwardOrigins.State before = result.stateBefore().get(instruction.offset());
                if (before != null && !before.stack().isEmpty()
                        && host.insnAt(instruction.offset()).op() == Op.CHECKCAST) {
                    return classNameFromClassValue(before.stack()
                            .get(before.stack().size() - 1).origins(), host, result, visiting);
                }
                return null;
            }
            if (!(value instanceof ValueOrigin.CallResult callResult)
                    || callResult.callNodeId() < 0) {
                return null;
            }
            Node call = callNodes.get(callResult.callNodeId());
            if (call == null) {
                return null;
            }
            MethodInfo callHost = enclosingMethod(call);
            ForwardOrigins.Result callResultState = callHost == null ? result
                    : origins.compute(callHost);
            if ("java/lang/Class".equals(call.owner()) && "forName".equals(call.name())) {
                return classNameFromClassValue(argOriginAtOrdinal(call, 0, callResultState),
                        callHost == null ? host : callHost, callResultState, visiting);
            }
            if ("java/lang/Object".equals(call.owner()) && "getClass".equals(call.name())) {
                String descriptor = Descriptor.returnType(call.descriptor());
                return internalClassName(descriptor);
            }
            return null;
        } finally {
            visiting.remove(value);
        }
    }

    /**
     * Determine whether a platform serialization callback reaches a standard object-graph
     * trigger through a small JDK helper chain.  This is deliberately structural: it does not
     * execute the archive, does not inspect benchmark names, and does not follow arbitrary
     * application methods.  The bounded search breaks the circularity between admitting a
     * JDK container callback and discovering the serialized field/trigger path that eventually
     * reaches a configured sink.
     */
    private boolean jdkCallbackMayReachTrigger(Graph graph, Node callback) {
        if (graph == null || callback == null) {
            return false;
        }
        String callbackKey = methodKeyOf(callback.strProp("owner"), callback.strProp("name"),
                callback.strProp("desc"));
        Deque<String> work = new ArrayDeque<>();
        Deque<Integer> depths = new ArrayDeque<>();
        Set<String> visited = new HashSet<>();
        work.add(callbackKey);
        depths.add(0);
        int inspected = 0;
        while (!work.isEmpty()) {
            if (inspected++ >= JDK_CALLBACK_TRIGGER_SEARCH_CAP) {
                markIncomplete("JDK_CALLBACK_TRIGGER_SEARCH_CAP:" + JDK_CALLBACK_TRIGGER_SEARCH_CAP);
                return false;
            }
            String methodKey = work.removeFirst();
            int depth = depths.removeFirst();
            if (!visited.add(methodKey) || depth > 8) {
                continue;
            }
            for (Node call : graph.callsOfMethod(methodKey)) {
                if (serializationTriggerCall(call)) {
                    return true;
                }
                if (depth >= 8) {
                    continue;
                }
                for (Edge edge : call.out()) {
                    if (edge.type() != EdgeType.INVOKES && edge.type() != EdgeType.DISPATCHES) {
                        continue;
                    }
                    if (!isJdk(edge.to().owner())) {
                        continue;
                    }
                    work.add(methodKeyOf(edge.to().owner(), edge.to().name(), edge.to().descriptor()));
                    depths.add(depth + 1);
                }
            }
        }
        return false;
    }

    /** A declared call whose receiver is a runtime-controlled object-graph trigger. */
    private static boolean serializationTriggerCall(Node call) {
        if (call == null) {
            return false;
        }
        String owner = call.strProp("owner");
        String name = call.strProp("name");
        if ("java/lang/Object".equals(owner)) {
            return Set.of("hashCode", "equals", "toString", "compareTo", "compare")
                    .contains(name);
        }
        if ("java/lang/Comparable".equals(owner)) {
            return "compareTo".equals(name);
        }
        return "java/util/Comparator".equals(owner) && "compare".equals(name);
    }

    /** 框架包前缀：source 规则声明的框架入口类取前 3 段包名（与框架桥接 KS 的前缀口径一致）。 */
    private Set<String> deriveFrameworkPackages() {
        Set<String> packages = new HashSet<>();
        for (io.just.sast.config.Rule.SourceRule source : ruleEngine.rules().sources()) {
            io.just.sast.config.Match owner = source.call().owner();
            if (owner == null || owner.isRegex()) {
                continue; // 正则 owner 不参与包前缀派生（保守：正则目标不定界）
            }
            String[] segments = owner.pattern().split("/");
            int take = Math.min(3, segments.length);
            StringBuilder pkg = new StringBuilder();
            for (int i = 0; i < take; i++) {
                if (i > 0) {
                    pkg.append('/');
                }
                pkg.append(segments[i]);
            }
            packages.add(pkg.toString());
        }
        return packages;
    }

    /** 应用接口无条件传递展开的每构建预算。 */
    private static final int IFACE_EXPANSION_BUDGET = 0;

    /** 位点宿主是否在框架包内（source 规则派生前缀）。 */
    private boolean inFrameworkPackage(String hostOwner) {
        for (String prefix : frameworkPackages) {
            if (hostOwner.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    /** 反射跳索引规模（诊断）。 */
    public int reflectiveSiteCount() {
        return reflectiveClassesBySite.size();
    }

    /**
     * 反射跳索引：Method.invoke 调用点若其宿主方法内存在 `C.class.getMethod/getDeclaredMethod(...)`
     * （C 为 LDC 类常量、出现在 getMethod 调用点前的小窗口内），则该 invoke 位点按 FLASH 反射跳边语义
     * 视为 C 的 public 方法的伪调用者：方法名常量 → 精确到 C.名字；名字不可解（污点数据）→ C 的全部
     * public 方法（类常量保证目标集合有界）。
     */
    private void indexReflectiveJumps(Graph graph) {
        Map<String, List<Node>> reflectiveCallsByHost = new TreeMap<>();
        Map<String, MethodInfo> hostsByKey = new HashMap<>();
        for (Node call : graph.nodesOfType(NodeType.CALL)) {
            if (!"java/lang/reflect/Method".equals(call.strProp("owner"))
                    || !"invoke".equals(call.strProp("name"))) {
                if (!("java/lang/reflect/Constructor".equals(call.strProp("owner"))
                        && "newInstance".equals(call.strProp("name")))) {
                    continue;
                }
            }
            reflectiveInvokeCalls.add(call);
            MethodInfo host = methodOf(call.strProp("methodOwner"), call.strProp("methodName"),
                    call.strProp("methodDesc"));
            if (host == null) {
                continue;
            }
            String hostKey = methodKeyOf(host.owner(), host.name(), host.descriptor());
            hostsByKey.putIfAbsent(hostKey, host);
            reflectiveCallsByHost.computeIfAbsent(hostKey, ignored -> new ArrayList<>(1))
                    .add(call);
        }
        // Host-level metadata is immutable for this CPG.  Compute it once per host, then keep
        // the per-site projection below for framework/proxy/collection-specific facts.
        for (Map.Entry<String, List<Node>> entry : reflectiveCallsByHost.entrySet()) {
            List<Node> calls = entry.getValue();
            calls.sort(java.util.Comparator.comparingInt((Node call) -> call.prop("offset")
                            instanceof Integer offset ? offset : Integer.MAX_VALUE)
                    .thenComparingLong(Node::id));
            MethodInfo host = hostsByKey.get(entry.getKey());
            if (host == null) {
                continue;
            }
            scanReflectiveLookup(host, calls);
            scanJavaBeanAccess(host, calls);
            for (Node call : calls) {
            // 框架包内的 Method.invoke 位点——框架反射供给调用者池
            // （包前缀源自 source 规则：框架以攻击者可控类名反射调用应用类方法的语义，
            //   只在框架真实出现在 classpath 时成立）
            if (inFrameworkPackage(host.owner())
                    && "java/lang/reflect/Method".equals(call.owner())
                    && "invoke".equals(call.name())) {
                frameworkMethodInvokeSites.add(call);
            }
            if (proxyReflectiveInvokeSite(call)) {
                proxyMethodInvokeSites.add(call);
            }
            if (methodCollectionReflectiveInvokeSite(call)) {
                methodCollectionInvokeSites.add(call);
            }
            }
        }
        if (!reflectiveClassesBySite.isEmpty()) {
            io.just.sast.util.JustLogger.info("反射跳索引：{} 个 invoke 位点", reflectiveClassesBySite.size());
        }
        JustLogger.debug("框架反射供给索引：{} 个 Method.invoke 位点，包前缀 {}",
                frameworkMethodInvokeSites.size(), frameworkPackages);
    }

    /**
     * Index the handler half of a JDK proxy whose proxy object is supplied by
     * serialized state.  A normal call graph cannot see Proxy.newProxyInstance
     * in that case, but the handler contract is still precise enough to admit
     * only serializable InvocationHandler implementations.
     */
    private void indexSerializedProxyHandlers(Graph graph) {
        List<Node> candidates = graph.nodesOfType(NodeType.METHOD).stream()
                .filter(node -> !isJdk(node.strProp("owner")))
                .filter(node -> "invoke".equals(node.strProp("name")))
                .filter(node -> SERIALIZED_PROXY_HANDLER_DESCRIPTOR.equals(node.strProp("desc")))
                .filter(node -> isSerializedProxyHandler(
                        methodOf(node.strProp("owner"), node.strProp("name"), node.strProp("desc"))))
                .sorted(java.util.Comparator.comparing(Node::owner)
                        .thenComparing(Node::name)
                        .thenComparing(Node::descriptor))
                .toList();
        if (candidates.size() > MAX_SERIALIZED_PROXY_HANDLERS) {
            markIncomplete("SERIALIZED_PROXY_HANDLER_CAP:" + MAX_SERIALIZED_PROXY_HANDLERS);
            candidates = candidates.subList(0, MAX_SERIALIZED_PROXY_HANDLERS);
        }
        serializedProxyHandlerMethods.addAll(candidates);
        JustLogger.debug("外部序列化 JDK Proxy handler：{} 个方法", serializedProxyHandlerMethods.size());
    }

    /**
     * Index Java-side interface calls which can be the dispatch point of an externally
     * assembled serialized proxy.  We deliberately require a resolved interface declaration
     * and an application-side host method; this avoids treating every JDK implementation call
     * as a proxy callback while still retaining proxies implementing platform interfaces when
     * the call site lives in scanned application/dependency bytecode.
     */
    private void indexSerializedProxyInterfaceCalls(Graph graph) {
        List<Node> candidates = graph.nodesOfType(NodeType.CALL).stream()
                .filter(call -> "INTERFACE".equals(call.invokeKind()))
                .filter(call -> {
                    ClassInfo owner = hierarchy.classInfo(call.strProp("owner"));
                    return owner != null && owner.isInterface();
                })
                .filter(call -> !isJdk(call.strProp("methodOwner")))
                .filter(this::isExternallySuppliedProxyReceiver)
                .sorted(java.util.Comparator.comparing((Node call) -> methodKeyOf(
                                call.methodOwner(), call.methodName(), call.methodDescriptor()))
                        .thenComparingInt(call -> call.prop("offset") instanceof Integer offset
                                ? offset : Integer.MAX_VALUE)
                        .thenComparingLong(Node::id))
                .toList();
        if (candidates.size() > SERIALIZED_PROXY_INTERFACE_SITE_CAP) {
            markIncomplete("SERIALIZED_PROXY_INTERFACE_SITE_CAP:" +
                    SERIALIZED_PROXY_INTERFACE_SITE_CAP);
            candidates = candidates.subList(0, SERIALIZED_PROXY_INTERFACE_SITE_CAP);
        }
        serializedProxyInterfaceCallSites.addAll(candidates);
        JustLogger.debug("外部序列化 Proxy 接口调用位点：{} 个", serializedProxyInterfaceCallSites.size());
    }

    /**
     * Keep local Proxy.newProxyInstance calls in the ordinary proxy model.  An interface call
     * whose receiver is a proxy factory result must not also enter the external serialized
     * proxy index: doing so lets an unrelated serializable handler satisfy that local call.
     * The receiver origin is normally a CHECKCAST of the factory result, so the small recursive
     * proof follows only CHECKCAST state and exact Proxy.newProxyInstance call results.
     * Unknown receiver facts remain eligible for the external index and are marked by the
     * downstream completeness machinery rather than being silently dropped.
     */
    private boolean isExternallySuppliedProxyReceiver(Node call) {
        MethodInfo host = enclosingMethod(call);
        if (host == null) {
            return true;
        }
        boolean hasProxyFactory = host.instructions().stream()
                .anyMatch(insn -> insn.op() != Op.INVOKEDYNAMIC && insn.op().isInvoke()
                        && insn.methodRef() != null
                        && "java/lang/reflect/Proxy".equals(insn.methodRef().owner())
                        && "newProxyInstance".equals(insn.methodRef().name()));
        if (!hasProxyFactory) {
            return true;
        }
        ForwardOrigins.Result result = origins.compute(host);
        Set<ValueOrigin> receivers = argOriginAtOrdinal(call, -1, result);
        if (receivers.isEmpty()) {
            return true;
        }
        boolean factoryDerived = false;
        boolean nonFactoryDerived = false;
        for (ValueOrigin receiver : receivers) {
            if (derivedFromProxyFactory(receiver, host, result, new HashSet<>())) {
                factoryDerived = true;
            } else {
                nonFactoryDerived = true;
            }
        }
        return nonFactoryDerived || !factoryDerived;
    }

    private boolean derivedFromProxyFactory(ValueOrigin origin, MethodInfo host,
                                            ForwardOrigins.Result result, Set<Integer> visiting) {
        if (origin instanceof ValueOrigin.CallResult callResult) {
            Node factory = callNodes.get(callResult.callNodeId());
            return factory != null
                    && "java/lang/reflect/Proxy".equals(factory.owner())
                    && "newProxyInstance".equals(factory.name());
        }
        if (!(origin instanceof ValueOrigin.Insn insn) || !visiting.add(insn.offset())) {
            return false;
        }
        try {
            InsnFact fact = host.insnAt(insn.offset());
            if (fact == null || fact.op() != Op.CHECKCAST) {
                return false;
            }
            ForwardOrigins.State before = result.stateBefore().get(insn.offset());
            if (before == null || before.stack().isEmpty()) {
                return false;
            }
            Set<ValueOrigin> input = before.stack().get(before.stack().size() - 1).origins();
            return !input.isEmpty() && input.stream()
                    .allMatch(value -> derivedFromProxyFactory(value, host, result, visiting));
        } finally {
            visiting.remove(insn.offset());
        }
    }

    /**
     * Index the Java-visible part of a JNI callback without reading or loading native code.
     * The descriptor restriction is intentional: it is a sound compatibility filter for the
     * common {@code CallVoidMethod(obj, mid)} shape and keeps an opaque native boundary bounded.
     */
    private void indexNativeCallbacks(Graph graph) {
        Map<Long, List<Node>> targetsBySite = new HashMap<>();
        List<Node> callbackCandidates = graph.nodesOfType(NodeType.METHOD).stream()
                .filter(candidate -> !isJdk(candidate.owner()))
                .filter(candidate -> "()V".equals(candidate.descriptor()))
                .filter(candidate -> !candidate.name().startsWith("<"))
                .filter(candidate -> {
                    MethodInfo target = methodOf(candidate.owner(), candidate.name(), candidate.descriptor());
                    return target != null && !target.isStatic()
                            && !java.lang.reflect.Modifier.isNative(target.access())
                            && !java.lang.reflect.Modifier.isAbstract(target.access())
                            && (java.lang.reflect.Modifier.isPublic(target.access())
                            || java.lang.reflect.Modifier.isProtected(target.access()));
                })
                .sorted(java.util.Comparator.comparing(Node::owner)
                        .thenComparing(Node::name)
                        .thenComparing(Node::descriptor))
                .toList();
        Map<String, List<Node>> candidatesByOwner = new HashMap<>();
        for (Node candidate : callbackCandidates) {
            candidatesByOwner.computeIfAbsent(candidate.owner(), ignored -> new ArrayList<>())
                    .add(candidate);
        }
        for (Node call : graph.nodesOfType(NodeType.CALL)) {
            if (isJdk(call.owner()) || "STATIC".equals(call.invokeKind())
                    || "DYNAMIC".equals(call.invokeKind())) {
                continue;
            }
            MethodInfo nativeMethod = methodOf(call.owner(), call.name(), call.descriptor());
            if (nativeMethod == null || !java.lang.reflect.Modifier.isNative(nativeMethod.access())) {
                continue;
            }
            List<Node> targets = new ArrayList<>();
            List<Node> candidatePool = nativeCallbackCandidates(call, callbackCandidates,
                    candidatesByOwner);
            for (Node candidate : candidatePool) {
                MethodInfo target = methodOf(candidate.owner(), candidate.name(), candidate.descriptor());
                if (target != null && nativeCallbackCompatible(call, target)) {
                    targets.add(candidate);
                    nativeCallbackSitesByTarget.computeIfAbsent(methodKey(target), ignored -> new ArrayList<>(1))
                            .add(call);
                }
            }
            if (!targets.isEmpty()) {
                targets.sort(java.util.Comparator.comparing(n -> methodKeyOf(n.owner(), n.name(), n.descriptor())));
                targetsBySite.put(call.id(), List.copyOf(targets));
            }
        }
        for (Map.Entry<Long, List<Node>> entry : targetsBySite.entrySet()) {
            nativeCallbackTargetsBySite.put(entry.getKey(), entry.getValue());
        }
        for (Map.Entry<String, List<Node>> entry : nativeCallbackSitesByTarget.entrySet()) {
            entry.getValue().sort(java.util.Comparator.comparingLong(Node::id));
        }
        if (!nativeCallbackTargetsBySite.isEmpty()) {
            JustLogger.debug("JNI 同接收者回调索引：{} 个 native 位点，{} 个目标方法",
                    nativeCallbackTargetsBySite.size(), nativeCallbackSitesByTarget.size());
        }
    }

    /**
     * Resolve the candidate owner family once per native owner instead of comparing every
     * native call with every application method. If the owner itself is unavailable, retain
     * the old conservative all-candidate scan: unknown hierarchy information must not become
     * a false negative.
     */
    private List<Node> nativeCallbackCandidates(Node nativeCall, List<Node> allCandidates,
                                                 Map<String, List<Node>> candidatesByOwner) {
        if (hierarchy.classInfo(nativeCall.owner()) == null) {
            return allCandidates;
        }
        Set<String> owners = new java.util.LinkedHashSet<>();
        owners.add(nativeCall.owner());
        var subtypeResult = hierarchy.transitiveSubtypes(nativeCall.owner(), SUBTYPE_TRAVERSAL_CAP);
        if (!subtypeResult.complete()) {
            markIncomplete("NATIVE_CALLBACK_SUBTYPE_CAP:" + SUBTYPE_TRAVERSAL_CAP);
        }
        owners.addAll(subtypeResult.values());
        List<Node> result = new ArrayList<>();
        for (String owner : owners) {
            result.addAll(candidatesByOwner.getOrDefault(owner, List.of()));
        }
        result.sort(java.util.Comparator.comparing(n -> methodKeyOf(n.owner(), n.name(), n.descriptor())));
        return result;
    }

    private boolean nativeCallbackCompatible(Node nativeCall, MethodInfo target) {
        if (isJdk(nativeCall.owner()) || target.isStatic() || target.name().startsWith("<")
                || java.lang.reflect.Modifier.isNative(target.access())
                || java.lang.reflect.Modifier.isAbstract(target.access())
                || !"()V".equals(target.descriptor())
                || isJdk(target.owner())) {
            return false;
        }
        if (!java.lang.reflect.Modifier.isPublic(target.access())
                && !java.lang.reflect.Modifier.isProtected(target.access())) {
            return false;
        }
        // The receiver of an instance native call is the object supplied to JNI.  A subtype
        // override is also a legal callback target; unrelated classes are not.
        return hierarchy.isSubtypeOf(target.owner(), nativeCall.owner());
    }

    /**
     * 在同一宿主方法体内找 {@code C.class.getXxxMethod(name, ...)} 模式。
     *
     * <p>反射位点通常成批出现在框架适配方法中。旧实现对每个 {@code Method.invoke}
     * 重新跑一次宿主 origin 和整段指令扫描，既重复工作又会让同一站点的索引顺序依赖
     * 图节点遍历顺序。现在把宿主级事实只计算一次，再投影到该宿主的所有 invoke 站点。</p>
     */
    private void scanReflectiveLookup(MethodInfo host, List<Node> invokeSites) {
        if (host == null || invokeSites == null || invokeSites.isEmpty()) {
            return;
        }
        var insns = host.instructions();
        ForwardOrigins.Result originResult = origins.compute(host);
        for (int i = 0; i < insns.size(); i++) {
            var insn = insns.get(i);
            if (!insn.op().isInvoke() || insn.operands().isEmpty()
                    || !(insn.operands().get(0) instanceof io.just.sast.model.MethodRef ref)
                    || !"java/lang/Class".equals(ref.owner())
                    || !("getMethod".equals(ref.name()) || "getDeclaredMethod".equals(ref.name())
                    || "getConstructor".equals(ref.name())
                    || "getDeclaredConstructor".equals(ref.name()))) {
                continue;
            }
            // 优先使用调用前的栈来源；这能跨越局部变量和非线性 bytecode，避免把窗口内
            // 不相关的两个 LDC 错配。只有状态不可证明时才回退到旧的有限窗口，并保持保守。
            ReflectiveConstants dataflowConstants = reflectiveConstants(
                    originResult.stateBefore().get(insn.offset()), ref);
            String classConst = dataflowConstants.className();
            String nameConst = dataflowConstants.methodName();
            if (classConst == null) {
                ReflectiveConstants windowConstants = reflectiveWindowConstants(insns, i);
                classConst = windowConstants.className();
                boolean constructor = "getConstructor".equals(ref.name())
                        || "getDeclaredConstructor".equals(ref.name());
                nameConst = constructor ? null : windowConstants.methodName();
            }
            if (classConst == null) {
                continue;
            }
            for (Node invokeSite : invokeSites) {
                reflectiveInvokeByClass.computeIfAbsent(classConst, k -> new ArrayList<>(1))
                        .add(invokeSite);
                reflectiveClassesBySite.computeIfAbsent(invokeSite.id(), k -> new ArrayList<>(1))
                        .add(classConst);
                if (nameConst != null) {
                    reflectiveInvokeByMethod.putIfAbsent(classConst + "#" + nameConst, invokeSite);
                }
            }
        }
    }

    private record ReflectiveConstants(String className, String methodName) {
    }

    /** Recover Class/name arguments from the abstract stack immediately before a Class lookup. */
    private static ReflectiveConstants reflectiveConstants(ForwardOrigins.State state,
                                                           MethodRef ref) {
        if (state == null || ref == null) {
            return new ReflectiveConstants(null, null);
        }
        List<ForwardOrigins.Slot> stack = state.stack();
        boolean constructor = "getConstructor".equals(ref.name())
                || "getDeclaredConstructor".equals(ref.name());
        int minimum = constructor ? 2 : 3;
        if (stack.size() < minimum) {
            return new ReflectiveConstants(null, null);
        }
        int classIndex = constructor ? stack.size() - 2 : stack.size() - 3;
        String className = singleClassConstant(stack.get(classIndex).origins());
        String methodName = constructor ? null
                : singleStringConstant(stack.get(stack.size() - 2).origins());
        return new ReflectiveConstants(className, methodName);
    }

    /** Bounded compatibility fallback for malformed/unknown stack states. */
    private static ReflectiveConstants reflectiveWindowConstants(List<InsnFact> insns, int invokeIndex) {
        String className = null;
        String methodName = null;
        for (int w = Math.max(0, invokeIndex - 15); w < invokeIndex; w++) {
            InsnFact previous = insns.get(w);
            if (previous.op() != Op.LDC || previous.operands().isEmpty()) {
                continue;
            }
            Object constant = previous.operands().get(0);
            if (constant instanceof TypeRef type && className == null) {
                className = className(type);
            } else if (constant instanceof String value && methodName == null) {
                methodName = value;
            }
        }
        return new ReflectiveConstants(className, methodName);
    }

    private static String singleClassConstant(Set<ValueOrigin> origins) {
        String result = null;
        for (ValueOrigin origin : origins) {
            if (!(origin instanceof ValueOrigin.Constant constant)
                    || !(constant.value() instanceof TypeRef type)) {
                return null;
            }
            String value = className(type);
            if (result != null && !result.equals(value)) {
                return null;
            }
            result = value;
        }
        return result;
    }

    private static String singleStringConstant(Set<ValueOrigin> origins) {
        String result = null;
        for (ValueOrigin origin : origins) {
            if (!(origin instanceof ValueOrigin.Constant constant)
                    || !(constant.value() instanceof String value)) {
                return null;
            }
            if (result != null && !result.equals(value)) {
                return null;
            }
            result = value;
        }
        return result;
    }

    private static String className(TypeRef type) {
        String descriptor = type.descriptor();
        return descriptor.startsWith("L") && descriptor.endsWith(";")
                ? descriptor.substring(1, descriptor.length() - 1) : descriptor;
    }

    /**
     * JavaBean 反射跳（FLASH 第三支柱）：宿主方法内存在 PropertyDescriptor.getReadMethod/getWriteMethod
     * 产出的 Method 再 invoke 时，目标 = invoke 接收者声明类型的 JavaBean 前缀方法（get* 与 is* 读、set* 写）。
     * 接收者类型不可解（如 Object 字段）时枚举占位 Serializable 类的公共无参前缀方法（上限 50）。
     */
    private void scanJavaBeanAccess(MethodInfo host, List<Node> invokeSites) {
        if (host == null || invokeSites == null || invokeSites.isEmpty()) {
            return;
        }
        boolean read = false;
        boolean write = false;
        for (var insn : host.instructions()) {
            if (!insn.op().isInvoke() || insn.operands().isEmpty()
                    || !(insn.operands().get(0) instanceof io.just.sast.model.MethodRef ref)) {
                continue;
            }
            if ("java/beans/PropertyDescriptor".equals(ref.owner())) {
                if ("getReadMethod".equals(ref.name())) {
                    read = true;
                } else if ("getWriteMethod".equals(ref.name())) {
                    write = true;
                }
            }
        }
        if (!read && !write) {
            return;
        }
        if (inFrameworkPackage(host.owner())) {
            frameworkJavabeanSite = true;
        }
        // 同一宿主的所有站点共享一份不可变 origin summary。
        ForwardOrigins.Result originResult = origins.compute(host);
        if (originResult == null) {
            return;
        }
        for (Node invokeSite : invokeSites) {
            ForwardOrigins.State state = originResult.stateBefore()
                    .get(invokeSite.prop("offset"));
            if (state == null || state.stack().size() < 2) {
                continue;
            }
            var argOrigins = state.stack().get(state.stack().size() - 2).origins();
            String recvType = declaredTypeOf(argOrigins, host);
            // 同一宿主同时调用 getReadMethod 与 getWriteMethod 时，站点的方向是一个
            // 集合而不是二选一；保留两个方向，避免漏掉 setter 反向链。
            String kinds = read && write ? "read|write" : read ? "read" : "write";
            if (recvType != null && !isUniversalType(recvType)) {
                javabeanSitesByClass.computeIfAbsent(recvType, k -> new ArrayList<>(1))
                        .add(invokeSite.id());
                javabeanClassBySite.put(invokeSite.id(), recvType);
                javabeanSiteKinds.put(invokeSite.id(), kinds);
            } else {
                javabeanWildcardSites.add(invokeSite.id());
                javabeanSiteKinds.put(invokeSite.id(), kinds);
            }
        }
    }

    /** JavaBean 前缀匹配（读：get 与 is 前缀公共非静态无参非 void；写：set 前缀公共非静态单参）。 */
    private static boolean javaBeanMatches(io.just.sast.model.MethodInfo m, String kind) {
        if (!java.lang.reflect.Modifier.isPublic(m.access())
                || java.lang.reflect.Modifier.isStatic(m.access())) {
            return false;
        }
        String n = m.name();
        if (kind != null && kind.contains("read")) {
            return (n.startsWith("get") && n.length() > 3 || n.startsWith("is") && n.length() > 2)
                    && Descriptor.paramCount(m.descriptor()) == 0
                    && !m.descriptor().endsWith(")V");
        }
        return kind != null && kind.contains("write")
                && n.startsWith("set") && n.length() > 3
                && Descriptor.paramCount(m.descriptor()) == 1;
    }

    private static boolean javaBeanKindSupports(String encoded, String kind) {
        return encoded != null && kind != null && encoded.contains(kind);
    }

    /** 常量类 C 的伪调用 invoke 位点（名字不可解时指向 C 全部 public 方法）。 */
    public List<Node> reflectiveInvokeSitesOf(String className) {
        return reflectiveInvokeByClass.getOrDefault(className, List.of());
    }

    /**
     * Return the proven prefix of a reflective method name, or {@code null} when the name
     * is opaque.  A prefix is deliberately weaker than an exact name: it can exclude an
     * impossible sink such as {@code "get" + unknown}, while never inventing a target.
     */
    public String reflectiveNamePrefix(Node lookup, MethodInfo host,
                                       ForwardOrigins.Result hostResult) {
        if (lookup == null || host == null || hostResult == null) {
            return null;
        }
        Set<ValueOrigin> values = argOriginAtOrdinal(lookup, 0, hostResult);
        String exact = stringLiteral(values);
        if (exact != null) {
            return exact;
        }
        StringShape shape = stringShape(values, host, hostResult, new HashSet<>());
        return shape == null ? null : shape.prefix();
    }

    /** Whether a candidate method name remains possible under the lookup's string shape. */
    public boolean reflectiveNameMayMatch(Node lookup, MethodInfo host,
                                          ForwardOrigins.Result hostResult,
                                          String candidateName) {
        if (candidateName == null) {
            return false;
        }
        if (lookup == null || host == null || hostResult == null) {
            return true;
        }
        Set<ValueOrigin> values = argOriginAtOrdinal(lookup, 0, hostResult);
        String exact = stringLiteral(values);
        if (exact != null) {
            return exact.equals(candidateName);
        }
        StringShape shape = stringShape(values, host, hostResult, new HashSet<>());
        if (shape == null) {
            return true;
        }
        if (shape.exact() != null) {
            return shape.exact().equals(candidateName);
        }
        return shape.prefix() == null || candidateName.startsWith(shape.prefix());
    }

    /** (C, 方法名) 精确反射跳的 invoke 位点。 */
    public Node reflectiveInvokeSiteOf(String className, String methodName) {
        return reflectiveInvokeByMethod.get(className + "#" + methodName);
    }

    /** JavaBean 前缀方法（类+读写形态）的伪调用 invoke 位点（含 wildcard 位点）。 */
    public List<Node> javaBeanInvokeSitesOf(String className, String methodName) {
        List<Node> sites = new ArrayList<>();
        String kind = methodName.startsWith("get") || methodName.startsWith("is") ? "read" : "write";
        for (Long id : javabeanSitesByClass.getOrDefault(className, List.of())) {
            if (javaBeanKindSupports(javabeanSiteKinds.get(id), kind)) {
                sites.add(callNodes.get(id));
            }
        }
        // wildcard 位点可调用于意类的 getter——不限制 target 类
        for (Long id : javabeanWildcardSites) {
            if (javaBeanKindSupports(javabeanSiteKinds.get(id), kind)) {
                sites.add(callNodes.get(id));
            }
        }
        return sites;
    }

    /** JavaBean 类站点表（闭包用）。 */
    public Map<String, List<Long>> javabeanClassSites() {
        return javabeanSitesByClass;
    }

    /** JavaBean wildcard 位点（闭包用）。 */
    public List<Long> javabeanWildcardSiteIds() {
        return javabeanWildcardSites;
    }

    /** 全部反射跳 invoke 位点（含其常量类），供反射 sink 枚举。 */
    /** 框架包内的 Method.invoke 位点（反射供给调用者池）。 */
    public List<Node> frameworkMethodInvokeSites() {
        return frameworkMethodInvokeSites;
    }


    /** Cached proxy-runtime Method.invoke sites used by the reverse reflective wildcard. */
    public List<Node> proxyMethodInvokeSites() {
        return proxyMethodInvokeSites;
    }

    /** Cached reflective sites whose Method receiver is a typed collection element. */
    public List<Node> methodCollectionInvokeSites() {
        return methodCollectionInvokeSites;
    }

    /**
     * Serializable InvocationHandler methods that an externally assembled JDK
     * proxy can call.  The list is bounded and sorted when it is indexed.
     */
    public List<Node> serializedProxyHandlerMethods() {
        return serializedProxyHandlerMethods;
    }

    /**
     * Bounded interface dispatch sites for proxies whose proxy object is supplied externally.
     * The list is sorted by host method and bytecode offset during indexing.
     */
    public List<Node> serializedProxyInterfaceCallSites() {
        return serializedProxyInterfaceCallSites;
    }

    /** Target methods admitted by the typed Method-collection callback model. */
    public List<Node> methodCollectionTargetMethods() {
        return methodCollectionTargetMethods;
    }

    /**
     * Return the bounded target family for one reflective collection site.  A site backed by
     * Class metadata gets its own exact family; iterator/list sites retain the conservative
     * shared family because the collection element was populated outside the visible graph.
     */
    public List<Node> methodCollectionTargetMethodsOf(Node invoke) {
        if (invoke == null) {
            return List.of();
        }
        return methodCollectionTargetsBySite.getOrDefault(invoke.id(),
                methodCollectionTargetMethods);
    }

    /** Whether the site was tied to a concrete Class.getMethods/getDeclaredMethods result. */
    public boolean methodCollectionSiteIsPrecise(Node invoke) {
        return invoke != null && preciseMethodCollectionSites.contains(invoke.id());
    }

    /** Method-collection sites that can select one bounded target method. */
    public List<Node> methodCollectionSitesOf(MethodInfo method) {
        return method == null ? List.of()
                : methodCollectionSitesByTarget.getOrDefault(methodKey(method), List.of());
    }

    /** Native callback targets attached to one Java native call site. */
    public List<Node> nativeCallbackTargets(Node nativeCall) {
        return nativeCall == null ? List.of()
                : nativeCallbackTargetsBySite.getOrDefault(nativeCall.id(), List.of());
    }

    /** Native call sites that may invoke the requested same-receiver callback method. */
    public List<Node> nativeCallbackSitesOf(MethodInfo target) {
        return target == null ? List.of()
                : nativeCallbackSitesByTarget.getOrDefault(methodKey(target), List.of());
    }

    public boolean nativeCallbackSite(Node nativeCall, MethodInfo target) {
        if (nativeCall == null || target == null) {
            return false;
        }
        return nativeCallbackTargets(nativeCall).stream()
                .anyMatch(candidate -> methodKeyOf(candidate.owner(), candidate.name(), candidate.descriptor())
                        .equals(methodKey(target)));
    }

    /**
     * Map a Java native call's receiver/arguments to the bounded callback target contract.
     * The current index admits only {@code ()V} instance callbacks, so receiver mapping is
     * the useful case; matching argument forwarding is retained for future compatible rules.
     */
    public Set<ValueOrigin> nativeTargetArgumentAt(Node nativeCall, MethodInfo target, int slot,
                                                   ForwardOrigins.Result callerResult) {
        if (!nativeCallbackSite(nativeCall, target)) {
            return Set.of();
        }
        if (!target.isStatic() && slot == 0) {
            return argOriginAtOrdinal(nativeCall, -1, callerResult);
        }
        MethodInfo nativeMethod = methodOf(nativeCall.owner(), nativeCall.name(), nativeCall.descriptor());
        if (nativeMethod == null || target.isStatic()) {
            return Set.of();
        }
        int ordinal = Descriptor.paramOrdinal(target.descriptor(), false, slot);
        if (ordinal < 0 || ordinal >= Descriptor.paramCount(nativeMethod.descriptor())) {
            return Set.of();
        }
        return argOriginAtOrdinal(nativeCall, ordinal, callerResult);
    }

    /**
     * Whether a Method.invoke site is the ordinary InvocationHandler callback form where the
     * Method object is supplied by the proxy runtime (invoke argument slot 2).  A proxy can be
     * assembled outside the scanned artifact, so there is intentionally no requirement for a
     * local Proxy.newProxyInstance call.  The check remains narrow: it needs the standard
     * InvocationHandler entry contract and a direct method argument, not an arbitrary
     * application Method.invoke.
     */
    public boolean proxyReflectiveInvokeSite(Node invoke) {
        if (invoke == null || !"java/lang/reflect/Method".equals(invoke.owner())
                || !"invoke".equals(invoke.name())) {
            return false;
        }
        MethodInfo host = enclosingMethod(invoke);
        if (host == null || ruleEngine.matchingEntry(host.owner(), host.name(), host.descriptor())
                .filter(entry -> "proxyInvoke".equals(entry.entryKind())).isEmpty()) {
            return false;
        }
        ForwardOrigins.Result result = origins.compute(host);
        return argOriginAtOrdinal(invoke, -1, result).stream()
                .anyMatch(origin -> origin instanceof ValueOrigin.Param param && param.slot() == 2);
    }

    /**
     * A reflective proxy callback may select only methods exposed by an interface implemented
     * by the target object.  This keeps the external-proxy wildcard bounded to JVM-valid proxy
     * dispatch instead of treating Method.invoke as a call to every public method.
     */
    public boolean proxyCallable(MethodInfo target) {
        if (target == null || target.isStatic()
                || !java.lang.reflect.Modifier.isPublic(target.access())) {
            return false;
        }
        ClassInfo ownerInfo = hierarchy.classInfo(target.owner());
        if (ownerInfo != null && java.lang.reflect.Modifier.isInterface(ownerInfo.access())
                && methodOf(target.owner(), target.name(), target.descriptor()) != null) {
            return true;
        }
        for (String iface : hierarchy.transitiveInterfaces(target.owner())) {
            MethodInfo declaration = methodOf(iface, target.name(), target.descriptor());
            if (declaration != null) {
                return true;
            }
        }
        return false;
    }

    /**
     * Whether a loaded method is a concrete serialized InvocationHandler entry.
     * The runtime can invoke a public interface implementation even when the
     * proxy itself is created entirely outside the scanned artifact.
     */
    public boolean isSerializedProxyHandler(MethodInfo method) {
        if (method == null || method.isStatic()
                || !"invoke".equals(method.name())
                || !SERIALIZED_PROXY_HANDLER_DESCRIPTOR.equals(method.descriptor())
                || !java.lang.reflect.Modifier.isPublic(method.access())) {
            return false;
        }
        String owner = method.owner();
        return !isJdk(owner)
                && hierarchy.isSerializable(owner)
                && hierarchy.isSubtypeOf(owner, "java/lang/reflect/InvocationHandler");
    }

    /**
     * Recognize a framework-style method collection without naming the framework: the receiver
     * of Method.invoke is a CHECKCAST Method produced by Iterator.next/List.get.  The cast is a
     * useful JVM-level type fact even when the collection itself is populated by a helper method.
     */
    public boolean methodCollectionReflectiveInvokeSite(Node invoke) {
        if (invoke == null || !"java/lang/reflect/Method".equals(invoke.owner())
                || !"invoke".equals(invoke.name())) {
            return false;
        }
        MethodInfo host = enclosingMethod(invoke);
        if (host == null) {
            return false;
        }
        ForwardOrigins.Result result = origins.compute(host);
        for (ValueOrigin methodValue : argOriginAtOrdinal(invoke, -1, result)) {
            if (methodCollectionElement(methodValue, host, result, new HashSet<>())) {
                return true;
            }
        }
        return false;
    }

    private boolean methodCollectionElement(ValueOrigin value, MethodInfo host,
                                            ForwardOrigins.Result result,
                                            Set<ValueOrigin> visiting) {
        if (value == null || !visiting.add(value)) {
            return false;
        }
        try {
            if (value instanceof ValueOrigin.Insn instruction
                    && instruction.offset() >= 0
                    && instruction.offset() < host.instructions().size()
                    && (host.insnAt(instruction.offset()).op() == Op.CHECKCAST
                    || host.insnAt(instruction.offset()).op() == Op.AALOAD)) {
                ForwardOrigins.State before = result.stateBefore().get(instruction.offset());
                if (before == null || before.stack().isEmpty()) {
                    return false;
                }
                int sourceIndex = host.insnAt(instruction.offset()).op() == Op.AALOAD
                        ? before.stack().size() - 2 : before.stack().size() - 1;
                if (sourceIndex < 0) {
                    return false;
                }
                for (ValueOrigin candidate : ValueOriginOrder.sorted(
                        before.stack().get(sourceIndex).origins())) {
                    if (methodCollectionElement(candidate, host, result, visiting)) {
                        return true;
                    }
                }
                return false;
            }
            if (!(value instanceof ValueOrigin.CallResult callResult)
                    || callResult.callNodeId() < 0) {
                return false;
            }
            Node call = callNodes.get(callResult.callNodeId());
            if (call == null) {
                return false;
            }
            if (("java/util/Iterator".equals(call.owner()) && "next".equals(call.name()))
                    || ("java/util/List".equals(call.owner()) && "get".equals(call.name()))
                    || ("java/util/Collection".equals(call.owner()) && "toArray".equals(call.name()))) {
                return true;
            }
            // Class metadata arrays are a typed Method collection even when the compiler
            // lowers the loop to AALOAD instead of Iterator/List operations.
            if ("java/lang/Class".equals(call.owner())
                    && ("getMethods".equals(call.name())
                    || "getDeclaredMethods".equals(call.name()))
                    && call.descriptor().endsWith("[Ljava/lang/reflect/Method;")) {
                return true;
            }
            return false;
        } finally {
            visiting.remove(value);
        }
    }

    /** 是否存在可作为外部对象绑定边界的 deserialize source。 */
    public boolean frameworkDeserializeSourceAvailable() {
        return frameworkDeserializeSourceAvailable;
    }

    public Map<Long, List<String>> reflectiveSites() {
        return reflectiveClassesBySite;
    }

    public ForwardOrigins origins() {
        return origins;
    }

    /**
     * 入口下游闭包：从 magic entry 方法与 OIS 读宿主出发的下游可达方法键集合
     * （沿调用边 + 字段中介边——下游方法写入的字段，其读者可经字段流获得污点）。
     * 用途：反向剪枝（sink 宿主不在集合内可证明无链）与链剪枝（触发上下文判定）共用一份。
     */
    public Set<String> entryDownstream(Graph graph) {
        Set<String> downstream = entryDownstream;
        if (downstream != null) {
            return downstream;
        }
        Map<String, List<String>> fieldsWrittenBy = new HashMap<>();
        Map<String, List<String>> fieldReaders = new HashMap<>();
        for (Node m : graph.nodesOfType(NodeType.METHOD)) {
            MethodInfo info = methodOf(m.strProp("owner"), m.strProp("name"), m.strProp("desc"));
            if (info == null) {
                continue;
            }
            String key = methodKeyOf(m.strProp("owner"), m.strProp("name"), m.strProp("desc"));
            for (io.just.sast.model.InsnFact insn : info.instructions()) {
                if (insn.op().isFieldRead()) {
                    String fieldKey = fieldKey(insn);
                    fieldReaders.computeIfAbsent(fieldKey, k -> new ArrayList<>(1)).add(key);
                } else if (insn.op().isFieldWrite()) {
                    String fieldKey = fieldKey(insn);
                    fieldsWrittenBy.computeIfAbsent(key, k -> new ArrayList<>(1)).add(fieldKey);
                }
            }
        }
        downstream = new HashSet<>();
        Map<String, Integer> depths = new HashMap<>();
        Deque<Node> work = new ArrayDeque<>();
        Deque<Integer> workDepth = new ArrayDeque<>();
        // Framework deserialize boundaries admit a broad method set without eagerly
        // traversing every public method.  Membership is therefore not the same as
        // having expanded a method; keep both states explicit so an actual root can
        // still cross an already-admitted framework method.
        Set<String> scheduled = new HashSet<>();
        Set<String> expanded = new HashSet<>();
        List<Node> proxyTargets = new ArrayList<>();
        if (!proxyMethodInvokeSites.isEmpty()) {
            for (Node candidate : graph.nodesOfType(NodeType.METHOD)) {
                String owner = candidate.strProp("owner");
                if (isJdk(owner)) {
                    continue;
                }
                MethodInfo target = methodOf(owner, candidate.strProp("name"), candidate.strProp("desc"));
                if (proxyCallable(target)) {
                    proxyTargets.add(candidate);
                }
            }
        }
        Map<String, Integer> sinkDistances = sinkDistances(graph);
        sinkDistanceIndex = Map.copyOf(sinkDistances);
        List<Node> jdkCallbacks = new ArrayList<>();
        for (Node candidate : graph.nodesOfType(NodeType.METHOD)) {
            String owner = candidate.strProp("owner");
            if (!isJdk(owner)) {
                continue;
            }
            String key = methodKeyOf(owner, candidate.strProp("name"), candidate.strProp("desc"));
            var entry = ruleEngine.matchingEntry(owner, candidate.strProp("name"), candidate.strProp("desc"));
            if (entry.isEmpty() || !isDeserializeEntry(entry.get(), owner)
                    || !JDK_SERIALIZATION_ENTRY_KINDS.contains(entry.get().entryKind())) {
                continue;
            }
            // A JDK callback often reaches a user-controlled trigger through a small
            // platform helper (HashMap.readObject -> HashMap.hash -> Object.hashCode).
            // Requiring an already-proven ordinary sink distance here creates a circular
            // dependency: the callback cannot enter the closure until serialized-field and
            // trigger semantics have entered it.  Admit only this bounded structural bridge;
            // unrelated JDK callbacks remain excluded.
            if (!sinkDistances.containsKey(key)
                    && !jdkCallbackMayReachTrigger(graph, candidate)) {
                continue;
            }
            MethodInfo method = methodOf(owner, candidate.strProp("name"), candidate.strProp("desc"));
            if (method != null && !method.instructions().isEmpty()) {
                jdkCallbacks.add(candidate);
            }
        }
        jdkCallbacks.sort(java.util.Comparator
                .comparingInt((Node node) -> sinkDistances.getOrDefault(
                        methodKeyOf(node.strProp("owner"), node.strProp("name"), node.strProp("desc")),
                        Integer.MAX_VALUE))
                .thenComparing(Node::owner)
                .thenComparing(Node::name)
                .thenComparing(Node::descriptor));
        if (jdkCallbacks.size() > JDK_SERIALIZATION_CALLBACK_CAP) {
            markIncomplete("JDK_SERIALIZATION_CALLBACK_CAP:" + JDK_SERIALIZATION_CALLBACK_CAP);
            jdkCallbacks = jdkCallbacks.subList(0, JDK_SERIALIZATION_CALLBACK_CAP);
        }
        Set<String> callbackKeys = new LinkedHashSet<>();
        for (Node callback : jdkCallbacks) {
            String key = methodKeyOf(callback.strProp("owner"), callback.strProp("name"),
                    callback.strProp("desc"));
            callbackKeys.add(key);
            if (downstream.add(key)) {
                depths.put(key, 1);
            }
            if (scheduled.add(key)) {
                work.add(callback);
                workDepth.add(1);
            }
        }
        deserializationCallbackEntries = orderedStrings(callbackKeys);
        buildMethodCollectionTargets(graph, sinkDistances);
        // A handler can be supplied by serialized state while the JDK proxy is
        // assembled outside the artifact.  Admit that bounded callback family
        // only when a compatible Method-collection invoke site exists; the
        // handler list alone is not a global source.
        if (!serializedProxyHandlerMethods.isEmpty() && !methodCollectionInvokeSites.isEmpty()) {
            for (Node handler : serializedProxyHandlerMethods) {
                String handlerKey = methodKeyOf(handler.strProp("owner"),
                        handler.strProp("name"), handler.strProp("desc"));
                if (downstream.add(handlerKey)) {
                    depths.put(handlerKey, 1);
                }
                if (scheduled.add(handlerKey)) {
                    work.add(handler);
                    workDepth.add(1);
                }
            }
        }
        // The proxy may be assembled by a deserialized object graph, with no
        // Proxy.newProxyInstance or Method collection in the scanned artifact.  A resolved
        // application-side interface call is still a finite callback boundary; admit the
        // serializable handler family so sink analysis can apply the method-name/argument
        // constraints instead of dropping handler-hosted sinks at the reachability gate.
        if (!serializedProxyHandlerMethods.isEmpty()
                && !serializedProxyInterfaceCallSites.isEmpty()) {
            for (Node handler : serializedProxyHandlerMethods) {
                String handlerKey = methodKeyOf(handler.strProp("owner"),
                        handler.strProp("name"), handler.strProp("desc"));
                if (downstream.add(handlerKey)) {
                    depths.put(handlerKey, 1);
                }
                if (scheduled.add(handlerKey)) {
                    work.add(handler);
                    workDepth.add(1);
                }
            }
        }
        for (Node m : graph.nodesOfType(NodeType.METHOD)) {
            String key = methodKeyOf(m.strProp("owner"), m.strProp("name"), m.strProp("desc"));
            // JDK 的 readObject/hashCode 等方法是反序列化机制实现，不是一个可以
            // 脱离应用对象图独立启动污点的用户入口。ForwardEngine 已经采用同一
            // 边界；若这里仍把每个已物化的 JDK magic-entry 作为全局根，JDK
            // 内部调用会互相扩散，反向闭包在大 JDK 上先耗尽预算而不是分析应用。
            // JDK 类仍可由应用引用、调用边、对象图与规则片段进入闭包，因此这
            // 是根语义收敛，不是按样本删除某个 gadget。
            var entry = ruleEngine.matchingEntry(m.strProp("owner"), m.strProp("name"),
                    m.strProp("desc"));
            if (!isJdk(m.strProp("owner")) && entry.isPresent()
                    && isDeserializeEntry(entry.get(), m.strProp("owner"))
                    && downstream.add(key)) {
                depths.put(key, 0);
            }
            if (!isJdk(m.strProp("owner")) && entry.isPresent()
                    && isDeserializeEntry(entry.get(), m.strProp("owner"))
                    && scheduled.add(key)) {
                work.add(m);
                workDepth.add(0);
            }
        }
        for (Node call : graph.nodesOfType(NodeType.CALL)) {
            boolean seed = isOisRead(call)
                    // 无条件 source（框架反序列化入口）宿主与 OIS 宿主同级 seeding——威胁模型上
                    // 框架 parse 与 OIS readObject 都是「反序列化发生处」；框架内部的
                    // Method.invoke 位点由此进入闭包，反射供给伪调用者才能挂接应用类
                    // 的 setter/getter（fastjson @type / XStream / Hessian 的运行时类名分发）。
                    // 带输入前置条件的二次桥必须先由真实入口把 byte[]/对象送达，不能
                    // 在闭包阶段单独制造一个根。
                    || ruleEngine.matchingSource(call.strProp("owner"), call.strProp("name"),
                            call.strProp("desc")).filter(OriginSupport::isUnconditionalDeserializeSource)
                            .isPresent();
            if (seed) {
                Node host = graph.findMethodNode(call.strProp("methodOwner"),
                        call.strProp("methodName"), call.strProp("methodDesc"));
                String key = host != null ? methodKeyOf(
                        host.strProp("owner"), host.strProp("name"), host.strProp("desc")) : null;
                if (host != null && key != null && downstream.add(key)) {
                    depths.put(key, 0);
                }
                if (host != null && key != null && scheduled.add(key)) {
                    work.add(host);
                    workDepth.add(0);
                }
            }
        }
        // JavaBean wildcard 直接种子：图中存在 getReadMethod/invoke 模式时，
        // 只把能够沿普通调用/字段流到达 sink 的 getter 入闭包。旧实现把每个
        // Serializable getter 都作为根；在 fat jar 中这会把大量无关 DTO 的方法
        // 推进 forward fixed-point，既不增加可证明召回，又会把复杂度推向 O(all public
        // bean methods)。sinkDistances 已在本次闭包构建前建立，并包含有限字段反向流。
        if (!javabeanWildcardSites.isEmpty()) {
            Set<String> getterClasses = computeSerializableWithGetters(graph);
            for (String cls : orderedStrings(getterClasses)) {
                var ci = hierarchy.classInfo(cls);
                if (ci == null) {
                    continue;
                }
                for (var mi : ci.methods()) {
                    if (javaBeanMatches(mi, "read")) {
                        String mk = methodKeyOf(cls, mi.name(), mi.descriptor());
                        if (!sinkDistances.containsKey(mk)) {
                            continue;
                        }
                        if (downstream.add(mk)) {
                            depths.put(mk, 1);
                        }
                        Node mn = graph.findMethodNode(cls, mi.name(), mi.descriptor());
                        if (mn != null && scheduled.add(mk)) {
                            work.add(mn);
                            workDepth.add(1);
                        }
                    }
                }
            }
        }
        // 框架反射供给种子：Method.invoke / JavaBean 反射位点宿主于框架包内（source 规则派生前缀，
        // 框架桥接语义真实成立）时，所有应用类的 public 非静态方法入闭包——
        // 框架（fastjson @type / XStream / SnakeYAML 等）以攻击者可控类名反射调用任意 public 方法。
        // 精度门：仅限非 JDK 类（避免万级 JDK 方法涌入闭包）。
        boolean hasFrameworkInvoke = !frameworkMethodInvokeSites.isEmpty() || frameworkJavabeanSite;
        boolean hasFrameworkBoundary = hasFrameworkInvoke || frameworkDeserializeSourceAvailable;
        // 框架供给只枚举已加载目标/依赖中的 public bean 方法，不依赖 JDK 全量加载；
        // 因此 --fast 也必须保留这条低成本的入口语义，否则 Fastjson/XStream 等
        // 通过 JavaBean setter 触发的应用类 sink 会在快速扫描中整体消失。
        if (hasFrameworkBoundary) {
            int added = 0;
            for (Node m : graph.nodesOfType(NodeType.METHOD)) {
                String owner = m.strProp("owner");
                if (owner.startsWith("java/") || owner.startsWith("javax/")
                        || owner.startsWith("sun/") || owner.startsWith("jdk/")
                        || owner.startsWith("com/sun/")) {
                    continue; // 跳过 JDK 类
                }
                // 框架反序列化不要求 Serializable（fastjson 用默认构造器+反射，XStream 用 Converter）
                int access = hierarchy.methodAccess(owner, m.strProp("name"), m.strProp("desc"));
                    if (access >= 0 && java.lang.reflect.Modifier.isPublic(access)
                        && !java.lang.reflect.Modifier.isStatic(access)) {
                    // 没有明确的 Method.invoke/PropertyDescriptor 位点时，
                    // deserialize source 只建立通用 bean setter 输入边界，避免把所有公共方法
                    // 错当作可由请求对象直接调用；已有反射位点则保留原有反射语义。
                        if (!hasFrameworkInvoke) {
                            MethodInfo candidate = methodOf(owner, m.strProp("name"), m.strProp("desc"));
                            if (candidate == null || !javaBeanMatches(candidate, "write")) {
                                continue;
                            }
                        }
                    String mk = methodKeyOf(owner, m.strProp("name"), m.strProp("desc"));
                    if (!sinkDistances.containsKey(mk)) {
                        continue;
                    }
                    if (downstream.add(mk)) {
                        depths.put(mk, 1);
                        // 性能关键：不加入 work 队列——只入闭包集合（供 sink gate），不扩展下游 callee
                        added++;
                    }
                }
            }
            if (added > 0) {
                io.just.sast.util.JustLogger.info("框架反射供给：{} 个 sink-relevant 方法入闭包", added);
            }
        }
        while (!work.isEmpty()) {
            Node m = work.poll();
            int depth = workDepth.poll();
            String key = methodKeyOf(m.strProp("owner"), m.strProp("name"), m.strProp("desc"));
            if (!expanded.add(key)) {
                continue;
            }
            List<Node> calls = graph.callsOfMethod(key);
            if (!calls.isEmpty()) {
                // 反射跳边（FLASH 向后版）：invoke 位点的常量类 public 方法并入可达集
                for (Node call : calls) {
                    List<String> classes = reflectiveClassesBySite.get(call.id());
                    if (classes == null) {
                        continue;
                    }
                    for (String cls : classes) {
                        io.just.sast.model.ClassInfo ci = hierarchy.classInfo(cls);
                        if (ci == null) {
                            continue;
                        }
                        for (io.just.sast.model.MethodInfo mi : ci.methods()) {
                            if (!java.lang.reflect.Modifier.isPublic(mi.access())
                                    || java.lang.reflect.Modifier.isStatic(mi.access())) {
                                continue;
                            }
                            String mk = methodKeyOf(cls, mi.name(), mi.descriptor());
                            if (downstream.add(mk)) {
                                depths.put(mk, depth + 1);
                            }
                            Node mn = graph.findMethodNode(cls, mi.name(), mi.descriptor());
                            if (mn != null && scheduled.add(mk)) {
                                work.add(mn);
                                workDepth.add(depth + 1);
                            }
                        }
                    }
                }
                // JavaBean 反射跳（FLASH）：getReadMethod/getWriteMethod invoke 位点 →
                // 接收者类型（可解）或占位 Serializable 类的 JavaBean 前缀方法并入可达集
                for (Node call : calls) {
                    if (javabeanSiteKinds.containsKey(call.id())) {
                        String kind = javabeanSiteKinds.get(call.id());
                        java.util.Set<String> targetClasses = new LinkedHashSet<>();
                        String exactTargetClass = javabeanClassBySite.get(call.id());
                        if (exactTargetClass != null) {
                            targetClasses.add(exactTargetClass);
                        }
                        if (targetClasses.isEmpty()) {
                            // wildcard（Object 接收者）：所有有 JavaBean 前缀方法的 Serializable 类
                            // FLASH 语义：receiver 攻击者可控时，任意 Serializable 类的 getter 均可被反射调用
                            if (occupiableTypes == null) {
                                occupiableTypes = computeSerializableWithGetters(graph);
                            }
                            targetClasses.addAll(orderedStrings(occupiableTypes));
                        }
                        for (String cls2 : targetClasses) {
                            var ci2 = hierarchy.classInfo(cls2);
                            if (ci2 == null) {
                                continue;
                            }
                            for (var mi2 : ci2.methods()) {
                                if (javaBeanMatches(mi2, kind)) {
                                    String mk2 = methodKeyOf(cls2, mi2.name(), mi2.descriptor());
                                    if (downstream.add(mk2)) {
                                        depths.put(mk2, depth + 1);
                                    }
                                    Node mn2 = graph.findMethodNode(cls2, mi2.name(), mi2.descriptor());
                                    if (mn2 != null && scheduled.add(mk2)) {
                                        work.add(mn2);
                                        workDepth.add(depth + 1);
                                    }
                                }
                            }
                        }
                    }
                }
                for (Node call : calls) {
                    for (Edge edge : call.out()) {
                        Node callee = edge.to();
                        String calleeKey = methodKeyOf(callee.strProp("owner"),
                                callee.strProp("name"), callee.strProp("desc"));
                        if (downstream.add(calleeKey)) {
                            depths.put(calleeKey, depth + 1);
                        }
                        if (scheduled.add(calleeKey)) {
                            work.add(callee);
                            workDepth.add(depth + 1);
                        }
                    }
                    // 反射跳边展开：Method.invoke 位点的常量类目标方法并入闭包
                    List<String> reflClasses = reflectiveClassesBySite.get(call.id());
                    if (reflClasses != null) {
                        for (String cls : reflClasses) {
                            var ci2 = hierarchy.classInfo(cls);
                            if (ci2 == null) {
                                continue;
                            }
                            for (var mi2 : ci2.methods()) {
                                if (!java.lang.reflect.Modifier.isPublic(mi2.access())) {
                                    continue;
                                }
                                String mk2 = methodKeyOf(cls, mi2.name(), mi2.descriptor());
                                if (downstream.add(mk2)) {
                                    depths.put(mk2, depth + 1);
                                }
                                Node mn2 = graph.findMethodNode(cls, mi2.name(), mi2.descriptor());
                                if (mn2 != null && scheduled.add(mk2)) {
                                    work.add(mn2);
                                    workDepth.add(depth + 1);
                                }
                            }
                        }
                    }
                    // The proxy object may be constructed by the deserialization payload rather
                    // than in the scanned artifact.  A handler Method.invoke therefore has a
                    // bounded external-dispatch family: public methods exposed by application
                    // interfaces.  Materialize that family in the entry closure so reverse
                    // analysis can reach the target without inventing non-interface calls.
                    if (proxyReflectiveInvokeSite(call)) {
                        for (Node target : proxyTargets) {
                            String targetKey = methodKeyOf(target.strProp("owner"),
                                    target.strProp("name"), target.strProp("desc"));
                            if (downstream.add(targetKey)) {
                                depths.put(targetKey, depth + 1);
                            }
                            if (scheduled.add(targetKey)) {
                                work.add(target);
                                workDepth.add(depth + 1);
                            }
                        }
                    }
                    // Method-collection targets are activated on demand by the forward
                    // semantic engine.  Putting the whole sink-relevant getter family in
                    // this closure would make reachability scale with every public getter
                    // in a dependency graph instead of with the actual callback site.
                    // JNI callback bridge: native code is outside the Java call graph, but a
                    // bounded same-receiver callback family can still be represented without
                    // loading a library.  Keep these targets in the entry closure so the
                    // backward sink gate and the forward reachability gate agree.
                    for (Node target : nativeCallbackTargets(call)) {
                        String targetKey = methodKeyOf(target.strProp("owner"),
                                target.strProp("name"), target.strProp("desc"));
                        if (downstream.add(targetKey)) {
                            depths.put(targetKey, depth + 1);
                        }
                        if (scheduled.add(targetKey)) {
                            work.add(target);
                            workDepth.add(depth + 1);
                        }
                    }
                    // 分发展开：调用图分发边未物化全接收者集时闭包做全子类型展开。
                    // VIRTUAL：CHA 物化完整（超限时仅剩声明目标，out≤1）。
                    // INTERFACE：implementers 不穿透实现类的子类（子类覆写会漏）——应用接口
                    // 无条件传递展开（hibernate1 形态）；JDK 接口维持 out≤1 声明态
                    // （万级实现者的传递闭包经 JDK 图病毒扩散，真实语料耗时 3-14 倍）
                    String callOwner = call.strProp("owner");
                    boolean jdkIface = "INTERFACE".equals(call.strProp("invokeKind")) && isJdk(callOwner);
                    if (call.out().size() <= 1
                            || ("INTERFACE".equals(call.strProp("invokeKind")) && !jdkIface)) {
                        String callName = call.strProp("name");
                        String callDesc = call.strProp("desc");
                        if ("VIRTUAL".equals(call.strProp("invokeKind"))
                                || "INTERFACE".equals(call.strProp("invokeKind"))) {
                            String sigKey = callOwner + "#" + callName + callDesc;
                            List<Object[]> targets = ifaceDispatchCache.get(sigKey);
                            if (targets == null) {
                                targets = new ArrayList<>();
                                var ownerCi = hierarchy.classInfo(callOwner);
                                if (ownerCi != null) {
                                    var subtypeResult = hierarchy.transitiveSubtypes(callOwner,
                                            SUBTYPE_TRAVERSAL_CAP);
                                    if (!subtypeResult.complete()) {
                                        markIncomplete("ENTRY_DISPATCH_SUBTYPE_CAP:" + SUBTYPE_TRAVERSAL_CAP);
                                    }
                                    for (String impl : subtypeResult.values()) {
                                            String resolved = hierarchy.resolveMethod(impl, callName, callDesc);
                                            if (resolved != null) {
                                                targets.add(new Object[]{resolved,
                                                        graph.findMethodNode(resolved, callName, callDesc)});
                                            }
                                    }
                                }
                                ifaceDispatchCache.put(sigKey, targets);
                            }
                            for (Object[] t : targets) {
                                String resolved = (String) t[0];
                                Node mn = (Node) t[1];
                                String mk = methodKeyOf(resolved, callName, callDesc);
                                if (downstream.add(mk)) {
                                    depths.put(mk, depth + 1);
                                }
                                if (mn != null && scheduled.add(mk)) {
                                    work.add(mn);
                                    workDepth.add(depth + 1);
                                }
                            }
                        }
                    }
                }
            }
            List<String> written = fieldsWrittenBy.get(key);
            if (written != null) {
                for (String fieldKey : written) {
                    for (String reader : fieldReaders.getOrDefault(fieldKey, List.of())) {
                        if (downstream.add(reader)) {
                            depths.put(reader, depth + 1);
                        }
                        Node rn = methodNodeOf(graph, reader);
                        if (rn != null && scheduled.add(reader)) {
                            work.add(rn);
                            workDepth.add(depth + 1);
                        }
                    }
                }
            }
        }
        entryDownstream = downstream;
        entryDepths = depths;
        io.just.sast.util.JustLogger.info("入口闭包构成：{} 个方法，sink 普通反向相关 {} 个方法，" +
                "JDK 回调 {} 个，Method 集合目标 {} 个，代理接口位点 {} 个",
                downstream.size(), sinkDistances.size(), deserializationCallbackEntries.size(),
                methodCollectionTargetMethods.size(), serializedProxyInterfaceCallSites.size());
        return downstream;
    }

    /**
     * Methods that can reach a configured sink through ordinary call edges.  A
     * typed Method collection can select any compatible getter, but only a
     * getter with a sink-relevant body needs to be materialized by the forward
     * semantic bridge.  This keeps the wildcard precise for large dependency
     * graphs while retaining JDK sink targets such as TemplatesImpl getters.
     */
    private Map<String, Integer> sinkDistances(Graph graph) {
        Map<String, List<String>> callersByCallee = new HashMap<>();
        Map<String, List<String>> fieldsReadByMethod = new HashMap<>();
        Map<String, List<String>> writersByField = new HashMap<>();
        Map<String, Integer> distances = new HashMap<>();
        Deque<String> work = new ArrayDeque<>();
        for (Node methodNode : graph.nodesOfType(NodeType.METHOD)) {
            String methodKey = methodKeyOf(methodNode.strProp("owner"),
                    methodNode.strProp("name"), methodNode.strProp("desc"));
            MethodInfo method = methodOf(methodNode.strProp("owner"), methodNode.strProp("name"),
                    methodNode.strProp("desc"));
            if (method == null) {
                continue;
            }
            for (InsnFact instruction : method.instructions()) {
                if (instruction.op().isFieldRead()) {
                    fieldsReadByMethod.computeIfAbsent(methodKey, ignored -> new ArrayList<>(1))
                            .add(fieldKey(instruction));
                } else if (instruction.op().isFieldWrite()) {
                    writersByField.computeIfAbsent(fieldKey(instruction), ignored -> new ArrayList<>(1))
                            .add(methodKey);
                }
            }
        }
        for (Node call : graph.nodesOfType(NodeType.CALL)) {
            String callerKey = methodKeyOf(call.strProp("methodOwner"),
                    call.strProp("methodName"), call.strProp("methodDesc"));
            if (ruleEngine.matchingSink(call).isPresent() && !distances.containsKey(callerKey)) {
                distances.put(callerKey, 0);
                work.add(callerKey);
            }
            for (Edge edge : call.out()) {
                if (edge.type() != EdgeType.INVOKES && edge.type() != EdgeType.DISPATCHES) {
                    continue;
                }
                String calleeKey = methodKeyOf(edge.to().strProp("owner"),
                        edge.to().strProp("name"), edge.to().strProp("desc"));
                callersByCallee.computeIfAbsent(calleeKey, ignored -> new ArrayList<>())
                        .add(callerKey);
            }
        }
        while (!work.isEmpty()) {
            String callee = work.removeFirst();
            for (String caller : callersByCallee.getOrDefault(callee, List.of())) {
                if (distances.size() >= SINK_REACHABILITY_CAP) {
                    markIncomplete("SINK_REACHABILITY_CAP:" + SINK_REACHABILITY_CAP);
                    return distances;
                }
                if (!distances.containsKey(caller)) {
                    distances.put(caller, distances.get(callee) + 1);
                    work.addLast(caller);
                }
            }
            // A sink may be reached through a value stored in a field rather than through a
            // direct call edge (e.g. a framework setter populates a later getter).  Include
            // those field writers in the reverse relevance slice, then continue through their
            // callers.  This is a bounded semantic edge, not a whole-program field alias
            // analysis; exact object/field feasibility remains the responsibility of taint.
            for (String field : fieldsReadByMethod.getOrDefault(callee, List.of())) {
                for (String writer : writersByField.getOrDefault(field, List.of())) {
                    if (distances.size() >= SINK_REACHABILITY_CAP) {
                        markIncomplete("SINK_REACHABILITY_CAP:" + SINK_REACHABILITY_CAP);
                        return distances;
                    }
                    if (!distances.containsKey(writer)) {
                        distances.put(writer, distances.get(callee) + 1);
                        work.addLast(writer);
                    }
                }
            }
        }
        return distances;
    }



    private static boolean isJdk(String internalName) {
        return internalName.startsWith("java/") || internalName.startsWith("javax/")
                || internalName.startsWith("jdk/") || internalName.startsWith("sun/")
                || internalName.startsWith("com/sun/");
    }

    /** JVM 调用指令中只有 static 与 invokedynamic 没有隐含 receiver。 */
    private static boolean isStaticLike(String invokeKind) {
        return "STATIC".equals(invokeKind) || "DYNAMIC".equals(invokeKind);
    }


    /** 方法的入口 BFS 距离（未在下游闭包内返回 Integer.MAX_VALUE）。反向探索按升序使用。 */
    public int entryDepthOf(String methodKey) {
        Map<String, Integer> depths = entryDepths;
        return depths != null ? depths.getOrDefault(methodKey, Integer.MAX_VALUE) : Integer.MAX_VALUE;
    }

    /**
     * Return the bounded ordinary-call distance from a method to a configured sink.
     * {@link Integer#MAX_VALUE} means that no such path was proven in the current graph
     * snapshot.  Consumers may use this only to order a finite approximation; an absent
     * distance must not discard the candidate.
     */
    public int sinkDistanceOf(String methodKey) {
        if (methodKey == null || methodKey.isBlank()) {
            return Integer.MAX_VALUE;
        }
        return sinkDistanceIndex.getOrDefault(methodKey, Integer.MAX_VALUE);
    }

    /**
     * JDK serialization callbacks admitted by the sink-relevant, bounded callback bridge.
     * The snapshot is empty until {@link #entryDownstream(Graph)} has been built.
     */
    public Set<String> deserializationCallbackEntries() {
        return deserializationCallbackEntries;
    }

    private static Node methodNodeOf(Graph graph, String key) {
        int sep = key.indexOf('#');
        int paren = key.indexOf('(', sep);
        if (sep < 0 || paren < 0) {
            return null;
        }
        return graph.findMethodNode(key.substring(0, sep), key.substring(sep + 1, paren), key.substring(paren));
    }

    /** 调用点 id：方法键 + "@" + 指令 offset → CALL 节点 id；不存在返回 null。 */
    public Long callId(String methodKey, int offset) {
        return callIdByKey.get(methodKey + "@" + offset);
    }

    /** 调用点直接索引；供遍历热路径避免 id 装箱和二次 graph.node 查找。 */
    public Node callNode(String methodKey, int offset) {
        return graph.findCallNode(methodKey, offset);
    }

    /** 由来源值中的 call node id 反查调用点；仅保留给跨方法 ValueOrigin 消费者。 */
    public Node callNode(long id) {
        return callNodes.get(id);
    }

    public MethodInfo methodOf(String owner, String name, String desc) {
        String key = methodKeyOf(owner, name, desc);
        MethodInfo cached = methodCache.get(key);
        if (cached != null) {
            return cached;
        }
        long revision = hierarchy.revision();
        Long missingAt = missingMethodCache.get(key);
        if (missingAt != null && missingAt == revision) {
            return null;
        }
        ClassInfo cls = hierarchy.classInfo(owner);
        MethodInfo method = cls != null ? cls.method(name, desc) : null;
        if (method != null) {
            methodCache.put(key, method);
            missingMethodCache.remove(key);
        } else {
            // classInfo(owner) may have loaded a JDK class and advanced the revision; record
            // the post-lookup version so a later lazy load can invalidate this result.
            missingMethodCache.put(key, hierarchy.revision());
        }
        return method;
    }

    /** CALL 节点所在的方法。 */
    public MethodInfo enclosingMethod(Node call) {
        return methodOf(call.methodOwner(), call.methodName(), call.methodDescriptor());
    }

    /**
     * 调用点实参来源：slot 为被调方法的局部参数槽（实例方法 receiver=0，long/double 参数占 2 槽）。
     * 按参数序数定位调用点栈上的实参（receiver 深度 = paramCount，arg i 深度 = paramCount-1-i，
     * cat-2 实参与 cat-1 一样各占一个栈条目）；返回空集表示该位置无来源记录。
     */
    public Set<ValueOrigin> argOriginAt(Node callerCall, MethodInfo callerMethod, int slot) {
        return argOriginAt(callerCall, callerMethod, slot, origins.compute(callerMethod));
    }

    /** Same lookup with a caller-supplied result, used by hot forward exploration loops. */
    public Set<ValueOrigin> argOriginAt(Node callerCall, MethodInfo callerMethod, int slot,
                                        ForwardOrigins.Result originResult) {
        String desc = callerCall.descriptor();
        boolean calleeStatic = isStaticLike(callerCall.invokeKind());
        int ordinal = Descriptor.paramOrdinal(desc, calleeStatic, slot);
        return argOriginAtOrdinal(callerCall, ordinal, originResult);
    }

    /**
     * Hot-path variant when the caller already enumerates argument positions.  Ordinal -1 is
     * the receiver of an instance call; non-negative values are real arguments.  Avoiding a
     * slot-to-ordinal scan preserves the same stack mapping while removing descriptor work from
     * every forward propagation attempt.
     */
    public Set<ValueOrigin> argOriginAtOrdinal(Node callerCall, int ordinal,
                                               ForwardOrigins.Result originResult) {
        ForwardOrigins.State state = originResult.stateBefore().get(callerCall.offset());
        if (state == null) {
            return Set.of();
        }
        String desc = callerCall.descriptor();
        int paramCount = Descriptor.paramCount(desc);
        if (ordinal < -1 || ordinal >= paramCount) {
            return Set.of();
        }
        int depthFromTop = ordinal == -1 ? paramCount : paramCount - 1 - ordinal;
        if (depthFromTop < 0 || depthFromTop >= state.stack().size()) {
            return Set.of();
        }
        return state.stack().get(state.stack().size() - 1 - depthFromTop).origins();
    }

    /**
     * Map a reflective {@code Method.invoke} call back to a slot in the reflected target.
     * The Java reflection API keeps the target receiver in explicit argument 0 and packs
     * target parameters into the second argument's Object[]; treating the call descriptor as
     * the target descriptor accidentally returns Method.invoke's receiver for target slot 0.
     * Keep this mapping in the shared origin layer so forward feasibility and backward taint
     * use the same JVM-level reflection convention.
     */
    public Set<ValueOrigin> reflectiveTargetArgumentAt(Node invoke, MethodInfo target, int slot,
                                                       ForwardOrigins.Result callerResult) {
        if (invoke == null || target == null
                || !"java/lang/reflect/Method".equals(invoke.owner())
                || !"invoke".equals(invoke.name())) {
            return Set.of();
        }
        if (!target.isStatic() && slot == 0) {
            return argOriginAtOrdinal(invoke, 0, callerResult);
        }
        return reflectiveMethodArgumentAt(invoke, target, slot, callerResult);
    }

    /**
     * Return exact concrete receiver types when every origin is locally recoverable.
     * An empty set means "unknown", not "provably no receiver".  The method deliberately
     * recognizes only JVM facts that do not require whole-program points-to guessing:
     * NEW, CHECKCAST of a recoverable value, and a field whose value was assigned by a
     * dominating local write to the same receiver.  This is the precision boundary used by
     * both forward and backward engines, so the two analyses cannot disagree about a
     * virtual/interface dispatch solely because they were run in different directions.
     */
    public Set<String> exactConcreteTypes(Set<ValueOrigin> values, MethodInfo method,
                                          int beforeOffset) {
        if (values == null || values.isEmpty() || method == null) {
            return Set.of();
        }
        return exactConcreteTypes(values, method, beforeOffset,
                origins.compute(method));
    }

    /** Same local proof when the caller already owns the method's immutable summary. */
    public Set<String> exactConcreteTypes(Set<ValueOrigin> values, MethodInfo method,
                                          int beforeOffset,
                                          ForwardOrigins.Result originResult) {
        if (values == null || values.isEmpty() || method == null) {
            return Set.of();
        }
        Set<String> result = new LinkedHashSet<>();
        Set<ValueOrigin> visiting = new HashSet<>();
        for (ValueOrigin value : ValueOriginOrder.sorted(values)) {
            String type = exactConcreteType(value, method, beforeOffset, visiting, originResult);
            if (type == null) {
                return Set.of();
            }
            result.add(type);
        }
        return orderedStrings(result);
    }

    /**
     * Check whether a call site can dynamically dispatch to the requested method.  A
     * concrete local receiver gets JVM resolution equality; an unknown receiver remains
     * accepted so unresolved aliases and deserialized object fields do not create false
     * negatives.  Static calls do not have a receiver and are always accepted.
     */
    public boolean receiverMayDispatchTo(Node call, MethodInfo caller,
                                         String targetOwner, String targetName,
                                         String targetDescriptor) {
        return receiverMayDispatchTo(call, caller, targetOwner, targetName, targetDescriptor,
                origins.compute(caller));
    }

    /** Same receiver proof when the caller's immutable forward state is already available. */
    public boolean receiverMayDispatchTo(Node call, MethodInfo caller,
                                         String targetOwner, String targetName,
                                         String targetDescriptor,
                                         ForwardOrigins.Result callerResult) {
        if (call == null || caller == null || targetOwner == null || targetName == null
                || "STATIC".equals(call.invokeKind()) || "SPECIAL".equals(call.invokeKind())
                || "DYNAMIC".equals(call.invokeKind())) {
            return true;
        }
        ReceiverDispatchSummary summary = receiverSummaries.get(call.id());
        // Receiver facts are derived from the caller's immutable origin result, not from
        // hierarchy resolution.  The hierarchy may lazily load a JDK class while the same
        // scan is running; invalidating this summary on every such load caused the expensive
        // field/receiver proof to repeat without changing the fact.  The result identity is
        // the actual fact version and still invalidates correctly between forward phases.
        if (summary == null || summary.originResult() != callerResult) {
            summary = receiverDispatchSummary(call, caller, callerResult);
        }
        Set<String> concrete = summary.exactTypes();
        if (concrete.isEmpty()) {
            Set<String> possible = summary.possibleTypes();
            if (!possible.isEmpty()) {
                for (String type : possible) {
                    String resolved = hierarchy.resolveMethod(type, targetName, targetDescriptor);
                    // A known NEW/factory type whose class model is unavailable is still an
                    // external boundary. Preserve the conservative answer in that case.
                    if (resolved == null || targetOwner.equals(resolved)) {
                        return true;
                    }
                }
                return false;
            }
            // A field which is reinitialized on every reachable write with a platform
            // allocation/factory result cannot hold an application implementation at this
            // call site. This is intentionally a one-way precision gate: anything that is
            // not proven platform-bound stays on the conservative CHA path.
            return !summary.platformBound() || isJdk(targetOwner);
        }
        for (String type : concrete) {
            String resolved = hierarchy.resolveMethod(type, targetName, targetDescriptor);
            // A missing external method model is an unknown boundary, not proof that the
            // dispatch is impossible. When resolution is available, only the JVM-selected
            // declaration can receive this call.
            if (resolved == null || targetOwner.equals(resolved)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Describe the receiver fact used by the dispatch gate above.  This is deliberately a
     * projection of the same cached summary, rather than a second points-to analysis: the
     * backward engine can therefore attach an evidence label without changing which edge is
     * accepted.  The labels are ordered from narrowest to broadest and are stable report data.
     *
     * <p>An unknown receiver is not rejected by {@link #receiverMayDispatchTo}; deserialized
     * object graphs and missing dependencies must remain recall-preserving.  It is nevertheless
     * reported as UNKNOWN so a candidate cannot be promoted to high confidence merely because
     * the conservative CHA path happened to reach the sink.</p>
     */
    public String receiverPrecision(Node call, MethodInfo caller,
                                    String targetOwner, String targetName,
                                    String targetDescriptor,
                                    ForwardOrigins.Result callerResult) {
        if (call == null || caller == null || targetOwner == null || targetName == null
                || targetDescriptor == null) {
            return "UNKNOWN";
        }
        String invokeKind = call.invokeKind();
        if ("STATIC".equals(invokeKind) || "SPECIAL".equals(invokeKind)
                || "DYNAMIC".equals(invokeKind)) {
            return "CONCRETE";
        }
        MethodInfo target = methodOf(targetOwner, targetName, targetDescriptor);
        if (target != null && nativeCallbackSite(call, target)) {
            // The native side is opaque, but the explicit same-receiver callback contract is
            // bounded by the indexed target family and is stronger than ordinary CHA.
            return "POINTS_TO_BOUNDED";
        }
        ReceiverDispatchSummary summary = receiverSummary(call, caller, callerResult);
        if (!summary.exactTypes().isEmpty()) {
            return summary.exactTypes().size() == 1 ? "CONCRETE" : "SEALED_SET";
        }
        if (!summary.possibleTypes().isEmpty() || summary.platformBound()) {
            return "POINTS_TO_BOUNDED";
        }
        if (call.note("dispatchSkipped") != null) {
            return "UNKNOWN";
        }
        long dispatchEdges = call.out().stream()
                .filter(edge -> edge.type() == EdgeType.INVOKES
                        || edge.type() == EdgeType.DISPATCHES)
                .count();
        return dispatchEdges > 0 ? "CHA_BOUNDED" : "UNKNOWN";
    }

    /** Return the receiver summary from the one per-call-site cache. */
    private ReceiverDispatchSummary receiverSummary(Node call, MethodInfo caller,
                                                    ForwardOrigins.Result callerResult) {
        ReceiverDispatchSummary summary = receiverSummaries.get(call.id());
        if (summary == null || summary.originResult() != callerResult) {
            summary = receiverDispatchSummary(call, caller, callerResult);
        }
        return summary;
    }

    private ReceiverDispatchSummary receiverDispatchSummary(Node call, MethodInfo caller) {
        return receiverDispatchSummary(call, caller, origins.compute(caller));
    }

    private ReceiverDispatchSummary receiverDispatchSummary(Node call, MethodInfo caller,
                                                             ForwardOrigins.Result result) {
        if (result == null) {
            return new ReceiverDispatchSummary(null, Set.of(), Set.of(), false);
        }
        Set<ValueOrigin> receivers = argOriginAtOrdinal(call, -1, result);
        Set<String> concrete = exactConcreteTypes(receivers, caller, call.offset(), result);
        Set<String> possible = Set.of();
        boolean platformBound = false;
        if (concrete.isEmpty()) {
            possible = possibleConcreteTypes(receivers, caller, call.offset(), result);
            if (possible.isEmpty()) {
                platformBound = platformBoundReceiver(receivers, caller, call.offset(), result);
            }
        }
        ReceiverDispatchSummary summary = new ReceiverDispatchSummary(result, concrete,
                possible, platformBound);
        if (receiverSummaries.mappingCount() < RECEIVER_SUMMARY_CACHE_LIMIT) {
            receiverSummaries.putIfAbsent(call.id(), summary);
        }
        return summary;
    }

    /**
     * Collect the possible local concrete types for a field even when the writes are in
     * mutually exclusive branches. Unlike exactFieldValueType this is a may-set: every
     * reachable write must remain locally recoverable, but no write is required to dominate
     * the read. It is therefore safe for dispatch filtering and conservative for unknown
     * or aliased assignments.
     */
    private Set<String> possibleConcreteTypes(Set<ValueOrigin> receivers, MethodInfo method,
                                              int beforeOffset) {
        if (receivers == null || receivers.isEmpty() || method == null) {
            return Set.of();
        }
        return possibleConcreteTypes(receivers, method, beforeOffset,
                origins.compute(method));
    }

    private Set<String> possibleConcreteTypes(Set<ValueOrigin> receivers, MethodInfo method,
                                              int beforeOffset,
                                              ForwardOrigins.Result originResult) {
        if (receivers == null || receivers.isEmpty()) {
            return Set.of();
        }
        Set<String> result = new LinkedHashSet<>();
        for (ValueOrigin receiver : receivers) {
            if (!(receiver instanceof ValueOrigin.FieldRead field)) {
                return Set.of();
            }
            Set<String> fieldTypes = possibleFieldValueTypes(field, method, beforeOffset,
                    originResult);
            if (fieldTypes.isEmpty()) {
                return Set.of();
            }
            result.addAll(fieldTypes);
        }
        return orderedStrings(result);
    }

    private Set<String> possibleFieldValueTypes(ValueOrigin.FieldRead field, MethodInfo method,
                                                int beforeOffset) {
        return possibleFieldValueTypes(field, method, beforeOffset,
                method == null ? null : origins.compute(method));
    }

    private Set<String> possibleFieldValueTypes(ValueOrigin.FieldRead field, MethodInfo method,
                                                int beforeOffset,
                                                ForwardOrigins.Result result) {
        if (result == null) {
            return Set.of();
        }
        Set<String> types = new LinkedHashSet<>();
        boolean found = false;
        for (int writeOffset : fieldWriteOffsets(method)) {
            InsnFact write = method.insnAt(writeOffset);
            if (write.offset() >= beforeOffset || !write.op().isFieldWrite()
                    || !sameField(write, field)) {
                continue;
            }
            ForwardOrigins.State state = result.stateBefore().get(write.offset());
            if (state == null) {
                return Set.of();
            }
            if (!field.isStatic()) {
                Set<ValueOrigin> writerReceiver = fieldWriterReceiver(write, state);
                if (writerReceiver.isEmpty() || !writerReceiver.contains(field.receiver())) {
                    return Set.of();
                }
            }
            if (state.stack().isEmpty()) {
                return Set.of();
            }
            Set<String> valueTypes = concreteTypesOf(state.stack()
                    .get(state.stack().size() - 1).origins(), method, write.offset(), result);
            if (valueTypes.isEmpty()) {
                return Set.of();
            }
            found = true;
            types.addAll(valueTypes);
        }
        return found ? orderedStrings(types) : Set.of();
    }

    private Set<String> concreteTypesOf(Set<ValueOrigin> values, MethodInfo method,
                                        int beforeOffset) {
        if (values == null || values.isEmpty() || method == null) {
            return Set.of();
        }
        return concreteTypesOf(values, method, beforeOffset,
                origins.compute(method));
    }

    private Set<String> concreteTypesOf(Set<ValueOrigin> values, MethodInfo method,
                                        int beforeOffset,
                                        ForwardOrigins.Result originResult) {
        if (values == null || values.isEmpty()) {
            return Set.of();
        }
        Set<String> result = new LinkedHashSet<>();
        Set<ValueOrigin> visiting = new HashSet<>();
        for (ValueOrigin value : ValueOriginOrder.sorted(values)) {
            String type = exactConcreteType(value, method, beforeOffset, visiting, originResult);
            if (type == null) {
                return Set.of();
            }
            result.add(type);
        }
        return orderedStrings(result);
    }

    /**
     * Prove the narrow, reusable "fresh platform field" pattern without pretending to do
     * whole-program points-to analysis.  All receiver origins must be field reads, and every
     * local write to each such field before the call must be a platform allocation, a known
     * JDK collection factory, or null.  Parameter/alias/unknown writes invalidate the fact.
     */
    private boolean platformBoundReceiver(Set<ValueOrigin> receivers, MethodInfo method,
                                          int beforeOffset) {
        if (receivers == null || receivers.isEmpty() || method == null) {
            return false;
        }
        return platformBoundReceiver(receivers, method, beforeOffset,
                origins.compute(method));
    }

    private boolean platformBoundReceiver(Set<ValueOrigin> receivers, MethodInfo method,
                                          int beforeOffset,
                                          ForwardOrigins.Result originResult) {
        if (receivers == null || receivers.isEmpty()) {
            return false;
        }
        boolean found = false;
        for (ValueOrigin receiver : receivers) {
            if (!(receiver instanceof ValueOrigin.FieldRead field)) {
                return false;
            }
            if (!fieldValuePlatformBound(field, method, beforeOffset, originResult)) {
                return false;
            }
            found = true;
        }
        return found;
    }

    private boolean fieldValuePlatformBound(ValueOrigin.FieldRead field, MethodInfo method,
                                            int beforeOffset) {
        return fieldValuePlatformBound(field, method, beforeOffset,
                method == null ? null : origins.compute(method));
    }

    private boolean fieldValuePlatformBound(ValueOrigin.FieldRead field, MethodInfo method,
                                            int beforeOffset,
                                            ForwardOrigins.Result result) {
        if (result == null) {
            return false;
        }
        boolean found = false;
        for (int writeOffset : fieldWriteOffsets(method)) {
            InsnFact write = method.insnAt(writeOffset);
            if (write.offset() >= beforeOffset || !write.op().isFieldWrite()
                    || !sameField(write, field)) {
                continue;
            }
            ForwardOrigins.State state = result.stateBefore().get(write.offset());
            if (state == null || state.stack().isEmpty()) {
                return false;
            }
            if (!field.isStatic()) {
                Set<ValueOrigin> writerReceiver = fieldWriterReceiver(write, state);
                if (writerReceiver.isEmpty() || !writerReceiver.contains(field.receiver())) {
                    return false;
                }
            }
            if (!platformProduced(state.stack().get(state.stack().size() - 1).origins(), method)) {
                return false;
            }
            found = true;
        }
        return found;
    }

    private boolean platformProduced(Set<ValueOrigin> values, MethodInfo method) {
        if (values == null || values.isEmpty()) {
            return false;
        }
        for (ValueOrigin value : values) {
            if (value instanceof ValueOrigin.Constant constant && constant.value() == null) {
                continue;
            }
            if (value instanceof ValueOrigin.Insn instruction
                    && instruction.offset() >= 0
                    && instruction.offset() < method.instructions().size()) {
                InsnFact insn = method.insnAt(instruction.offset());
                if (insn.op() == Op.NEW && insn.typeRef() != null
                        && isJdk(internalClassName(insn.typeRef().descriptor()))) {
                    continue;
                }
            }
            if (value instanceof ValueOrigin.CallResult callResult) {
                Node call = callNodes.get(callResult.callNodeId());
                if (call != null && knownPlatformFactory(call.owner(), call.name())) {
                    continue;
                }
            }
            return false;
        }
        return true;
    }

    /** JDK methods whose returned object is a platform-owned wrapper/value by contract. */
    private static boolean knownPlatformFactory(String owner, String name) {
        return knownPlatformFactoryType(owner, name) != null;
    }

    private static String knownPlatformFactoryType(String owner, String name) {
        if (owner == null || name == null) {
            return null;
        }
        if ("java/util/Collections".equals(owner)) {
            if ("emptyMap".equals(name) || name.startsWith("singletonMap")
                    || name.startsWith("unmodifiableMap") || name.startsWith("synchronizedMap")
                    || name.startsWith("checkedMap")) {
                return "java/util/AbstractMap";
            }
            if ("emptySet".equals(name) || name.startsWith("singletonSet")
                    || name.startsWith("unmodifiableSet") || name.startsWith("synchronizedSet")
                    || name.startsWith("checkedSet") || "newSetFromMap".equals(name)) {
                return "java/util/AbstractSet";
            }
            if ("emptyList".equals(name) || name.startsWith("singletonList")
                    || name.startsWith("unmodifiableList") || name.startsWith("synchronizedList")
                    || name.startsWith("checkedList")) {
                return "java/util/AbstractList";
            }
            return null;
        }
        if ("java/util/Map".equals(owner) || "java/util/List".equals(owner)
                || "java/util/Set".equals(owner)) {
            return "of".equals(name) || "ofEntries".equals(name) || "copyOf".equals(name)
                    ? owner : null;
        }
        return "java/util/Optional".equals(owner)
                && ("empty".equals(name) || "of".equals(name) || "ofNullable".equals(name))
                ? owner : null;
    }

    private String exactConcreteType(ValueOrigin value, MethodInfo method, int beforeOffset,
                                     Set<ValueOrigin> visiting,
                                     ForwardOrigins.Result originResult) {
        if (value == null || !visiting.add(value)) {
            return null;
        }
        try {
            if (value instanceof ValueOrigin.Insn instruction) {
                if (instruction.offset() < 0 || instruction.offset() >= method.instructions().size()) {
                    return null;
                }
                InsnFact fact = method.insnAt(instruction.offset());
                if (fact.op() == Op.NEW && fact.typeRef() != null) {
                    return internalClassName(fact.typeRef().descriptor());
                }
                if (fact.op() == Op.CHECKCAST) {
                    ForwardOrigins.State state = originResult == null ? null
                            : originResult.stateBefore().get(instruction.offset());
                    if (state == null || state.stack().isEmpty()) {
                        return null;
                    }
                    Set<String> nested = exactConcreteTypes(state.stack()
                            .get(state.stack().size() - 1).origins(), method,
                            instruction.offset(), originResult);
                    return nested.size() == 1 ? nested.iterator().next() : null;
                }
                return null;
            }
            if (value instanceof ValueOrigin.Constant constant) {
                Object literal = constant.value();
                if (literal instanceof String) {
                    return "java/lang/String";
                }
                if (literal instanceof Integer || literal instanceof Short
                        || literal instanceof Byte || literal instanceof Boolean
                        || literal instanceof Character) {
                    return "java/lang/Integer";
                }
                return null;
            }
            if (value instanceof ValueOrigin.FieldRead field) {
                return exactFieldValueType(field, method, beforeOffset, originResult);
            }
            if (value instanceof ValueOrigin.CallResult callResult
                    && callResult.callNodeId() >= 0) {
                Node call = callNodes.get(callResult.callNodeId());
                if (call != null && "<init>".equals(call.name())) {
                    return call.owner();
                }
                if (call != null) {
                    String factoryType = knownPlatformFactoryType(call.owner(), call.name());
                    if (factoryType != null) {
                        return factoryType;
                    }
                }
                if (originResult == null) {
                    return null;
                }
                Set<ValueOrigin> elements = originResult.arrayElements().get(value);
                if (elements != null && !elements.isEmpty()) {
                    Set<String> elementTypes = concreteTypesOf(elements, method, beforeOffset,
                            originResult);
                    return elementTypes.size() == 1 ? elementTypes.iterator().next() : null;
                }
            }
            return null;
        } finally {
            visiting.remove(value);
        }
    }

    /**
     * Resolve a field's concrete value only for the safe local pattern:
     * every reachable write to the same receiver before the read dominates the read,
     * and every written value has one recoverable concrete allocation type.  A branch,
     * alias, parameter write, or unknown value deliberately invalidates the fact.
     */
    private String exactFieldValueType(ValueOrigin.FieldRead field, MethodInfo method,
                                       int beforeOffset) {
        return exactFieldValueType(field, method, beforeOffset,
                method == null ? null : origins.compute(method));
    }

    private String exactFieldValueType(ValueOrigin.FieldRead field, MethodInfo method,
                                       int beforeOffset,
                                       ForwardOrigins.Result result) {
        DominatorIndex dominators = dominatorIndex(method);
        if (dominators == null || result == null) {
            return null;
        }
        Set<String> types = new LinkedHashSet<>();
        boolean found = false;
        for (int writeOffset : fieldWriteOffsets(method)) {
            InsnFact write = method.insnAt(writeOffset);
            if (write.offset() >= beforeOffset || !write.op().isFieldWrite()
                    || !sameField(write, field)) {
                continue;
            }
            if (!dominators.reachable()[write.offset()]
                    || !dominates(dominators, write.offset(), beforeOffset)) {
                return null;
            }
            ForwardOrigins.State state = result.stateBefore().get(write.offset());
            if (state == null || state.stack().isEmpty()) {
                return null;
            }
            if (!field.isStatic()) {
                Set<ValueOrigin> writerReceiver = fieldWriterReceiver(write, state);
                if (writerReceiver.isEmpty() || !writerReceiver.contains(field.receiver())) {
                    return null;
                }
            }
            Set<ValueOrigin> values = state.stack().get(state.stack().size() - 1).origins();
            Set<String> writeTypes = exactConcreteTypes(values, method, write.offset(), result);
            if (writeTypes.isEmpty()) {
                return null;
            }
            found = true;
            types.addAll(writeTypes);
        }
        return found && types.size() == 1 ? types.iterator().next() : null;
    }

    /**
     * Return field-write offsets in bytecode order. CpgIndex is the authoritative compact
     * method slice when available; the fallback keeps Blackboard/unit-test construction
     * compatible with pre-index callers. The returned array is never mutated by callers.
     */
    private int[] fieldWriteOffsets(MethodInfo method) {
        if (method == null) {
            return new int[0];
        }
        IdentityHashMap<MethodInfo, int[]> local = localFieldWriteOffsets.get();
        int[] localResult = local.get(method);
        if (localResult != null) {
            return localResult;
        }
        String key = methodKey(method);
        int[] result = fieldWriteOffsetsByMethod.computeIfAbsent(key, ignored -> {
            CpgIndex.MethodSlice slice = cpgIndex.slice(key);
            if (slice != null) {
                return slice.fieldWriteOffsets();
            }
            int[] offsets = new int[8];
            int size = 0;
            for (InsnFact insn : method.instructions()) {
                if (!insn.op().isFieldWrite()) {
                    continue;
                }
                if (size == offsets.length) {
                    offsets = Arrays.copyOf(offsets, offsets.length << 1);
                }
                offsets[size++] = insn.offset();
            }
            return Arrays.copyOf(offsets, size);
        });
        if (local.size() < LOCAL_FIELD_WRITE_CACHE_LIMIT) {
            local.put(method, result);
        }
        return result;
    }

    private Set<ValueOrigin> fieldWriterReceiver(InsnFact write, ForwardOrigins.State state) {
        if (write.op() == Op.PUTSTATIC || state.stack().size() < 2) {
            return Set.of();
        }
        return state.stack().get(state.stack().size() - 2).origins();
    }

    private DominatorIndex dominatorIndex(MethodInfo method) {
        String key = methodKeyOf(method.owner(), method.name(), method.descriptor());
        if (method.instructions().size() > DOMINATOR_METHOD_LIMIT) {
            return null;
        }
        return fieldDominators.computeIfAbsent(key, ignored -> buildDominators(method));
    }

    private DominatorIndex buildDominators(MethodInfo method) {
        return buildDominators(method, true);
    }

    private DominatorIndex buildDominators(MethodInfo method, boolean includeExceptions) {
        int size = method.instructions().size();
        Cfg.Indexed cfg = cfg(method);
        boolean[] reachable = new boolean[size];
        Deque<Integer> queue = new ArrayDeque<>();
        if (size > 0) {
            reachable[0] = true;
            queue.add(0);
        }
        while (!queue.isEmpty()) {
            int current = queue.removeFirst();
            for (int edgeIndex = cfg.edgeStart(current); edgeIndex < cfg.edgeEnd(current); edgeIndex++) {
                CfgLabel edgeLabel = cfg.labelAt(edgeIndex);
                if (!includeExceptions && edgeLabel == CfgLabel.EXCEPTION) {
                    continue;
                }
                int target = cfg.targetAt(edgeIndex);
                if (target < 0 || target >= size) {
                    continue;
                }
                if (!reachable[target]) {
                    reachable[target] = true;
                    queue.addLast(target);
                }
            }
        }

        // Dominator transfer only needs the reverse CFG.  The old representation allocated
        // one List<Integer> per instruction and boxed every predecessor before the fixed-point
        // loop even though the forward CFG is already a primitive CSR index.  Rebuild the
        // reachable reverse edges directly into a primitive CSR array: this keeps the transfer
        // function identical while removing the per-method object/boxing peak on large jars.
        int[] predecessorCounts = new int[size];
        for (int current = 0; current < size; current++) {
            if (!reachable[current]) {
                continue;
            }
            for (int edgeIndex = cfg.edgeStart(current); edgeIndex < cfg.edgeEnd(current); edgeIndex++) {
                if (!includeExceptions && cfg.labelAt(edgeIndex) == CfgLabel.EXCEPTION) {
                    continue;
                }
                int target = cfg.targetAt(edgeIndex);
                if (target >= 0 && target < size) {
                    predecessorCounts[target]++;
                }
            }
        }
        int[] predecessorOffsets = new int[size + 1];
        for (int i = 0; i < size; i++) {
            predecessorOffsets[i + 1] = predecessorOffsets[i] + predecessorCounts[i];
        }
        int[] predecessors = new int[predecessorOffsets[size]];
        int[] predecessorCursor = predecessorOffsets.clone();
        for (int current = 0; current < size; current++) {
            if (!reachable[current]) {
                continue;
            }
            for (int edgeIndex = cfg.edgeStart(current); edgeIndex < cfg.edgeEnd(current); edgeIndex++) {
                if (!includeExceptions && cfg.labelAt(edgeIndex) == CfgLabel.EXCEPTION) {
                    continue;
                }
                int target = cfg.targetAt(edgeIndex);
                if (target >= 0 && target < size) {
                    predecessors[predecessorCursor[target]++] = current;
                }
            }
        }
        BitSet all = new BitSet(size);
        all.set(0, size);
        BitSet[] dominators = new BitSet[size];
        for (int i = 0; i < size; i++) {
            dominators[i] = new BitSet(size);
            if (i == 0) {
                dominators[i].set(0);
            } else if (reachable[i]) {
                dominators[i].or(all);
            }
        }
        boolean changed;
        do {
            changed = false;
            for (int i = 1; i < size; i++) {
                if (!reachable[i]) {
                    continue;
                }
                BitSet next = null;
                for (int predecessorIndex = predecessorOffsets[i];
                     predecessorIndex < predecessorOffsets[i + 1]; predecessorIndex++) {
                    int predecessor = predecessors[predecessorIndex];
                    if (!reachable[predecessor]) {
                        continue;
                    }
                    if (next == null) {
                        next = (BitSet) dominators[predecessor].clone();
                    } else {
                        next.and(dominators[predecessor]);
                    }
                }
                if (next == null) {
                    next = new BitSet(size);
                }
                next.set(i);
                if (!next.equals(dominators[i])) {
                    dominators[i] = next;
                    changed = true;
                }
            }
        } while (changed);
        return new DominatorIndex(dominators, reachable);
    }

    private static boolean dominates(DominatorIndex index, int writer, int read) {
        return writer >= 0 && read >= 0 && read < index.dominators().length
                && index.reachable()[writer] && index.reachable()[read]
                && index.dominators()[read].get(writer);
    }

    /**
     * catch 可达性守卫（可判定才剪；GadgetHunter Guard 约束静态子集 + Gleipner FP 陷阱语义）：
     * a) CCE handler：守卫区唯一调用是 Class.cast，cast 目标类常量为实参声明类型的父类——必成功；
     * b) 受检反射查找异常：守卫区唯一调用是 forName/getDeclaredField/getField/getMethod/getDeclaredMethod
     *    且名字常量、目标可解析——必成功。反向与前向引擎在 sink 判定前共用。
     */
    public boolean catchProvablyUnreachable(MethodInfo method, int sinkOffset) {
        for (io.just.sast.model.TryCatchFact tc : method.tryCatch()) {
            boolean cce = "java/lang/ClassCastException".equals(tc.type());
            boolean reflectiveChecked = "java/lang/ClassNotFoundException".equals(tc.type())
                    || "java/lang/NoSuchFieldException".equals(tc.type())
                    || "java/lang/NoSuchMethodException".equals(tc.type())
                    || "java/lang/IllegalAccessException".equals(tc.type())
                    || "java/lang/InstantiationException".equals(tc.type());
            boolean runtimeDeterministic = isDeterministicRuntime(tc.type());
            if (!cce && !reflectiveChecked && !runtimeDeterministic) {
                continue;
            }
            // A try/catch table can contain adjacent handlers, and javac commonly emits
            // a short GOTO from one handler into the shared epilogue.  A fixed bytecode
            // window (the old handler + 8 heuristic) therefore attributed a sink in the
            // next handler to the first handler and could prove the wrong exception
            // unreachable.  Resolve the actual handler region from control-flow
            // terminators and the next distinct handler instead.
            if (!sinkInHandlerRegion(method, tc, sinkOffset)) {
                continue;
            }
            io.just.sast.model.InsnFact soleInvoke = null;
            int invokeCount = 0;
            for (int i = tc.start(); i < tc.end() && i < method.instructions().size(); i++) {
                io.just.sast.model.InsnFact insn = method.instructions().get(i);
                if (insn.op().isInvoke()) {
                    invokeCount++;
                    soleInvoke = insn;
                }
            }
            if (runtimeDeterministic) {
                if (!runtimeExceptionCanReach(method, tc)) {
                    return true;
                }
                continue;
            }
            if (invokeCount < 1) {
                continue;
            }
            if (reflectiveChecked) {
                // 按异常类型枚举守卫区内的"投掷者"调用；全部投掷者可判定必成功 → handler 不可达
                boolean sawThrower = false;
                boolean allSucceed = true;
                for (int i = tc.start(); i < tc.end() && i < method.instructions().size(); i++) {
                    io.just.sast.model.InsnFact insn = method.instructions().get(i);
                    if (!insn.op().isInvoke() || insn.operands().isEmpty()
                            || !(insn.operands().get(0) instanceof io.just.sast.model.MethodRef mref)
                            || !isThrowerOf(tc.type(), mref)) {
                        continue;
                    }
                    sawThrower = true;
                    if (!reflectiveLookupAlwaysSucceeds(method, tc, insn, mref)) {
                        allSucceed = false;
                        break;
                    }
                }
                if (sawThrower && allSucceed) {
                    return true;
                }
                continue;
            }
            if (!cce || invokeCount != 1
                    || !(soleInvoke.operands().get(0) instanceof io.just.sast.model.MethodRef ref)
                    || !"java/lang/Class".equals(ref.owner()) || !"cast".equals(ref.name())) {
                continue;
            }
            String castTarget = null;
            for (int w = Math.max(0, tc.start() - 8); w < soleInvoke.offset(); w++) {
                io.just.sast.model.InsnFact prev = method.instructions().get(w);
                if (prev.op() == io.just.sast.model.Op.LDC && !prev.operands().isEmpty()
                        && prev.operands().get(0) instanceof io.just.sast.model.TypeRef t) {
                    castTarget = t.descriptor().startsWith("L") && t.descriptor().endsWith(";")
                            ? t.descriptor().substring(1, t.descriptor().length() - 1)
                            : t.descriptor();
                }
            }
            if (castTarget == null) {
                continue;
            }
            ForwardOrigins.Result result = origins.compute(method);
            ForwardOrigins.State state = result.stateBefore().get(soleInvoke.offset());
            if (state == null || state.stack().size() < 2) {
                continue;
            }
            String argType = declaredTypeOf(state.stack().get(state.stack().size() - 1).origins(), method); // cast 实参在栈顶
            if (argType != null && hierarchy.isSubtypeOf(argType, castTarget)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Prove that a sink has no normal CFG path from the method entry using only exact local
     * facts.  The ordinary taint engines intentionally merge both sides of branches; that is
     * the right recall default, but it loses useful semantics for reflective guards and
     * constant booleans.  This second, monotone pass removes an edge only when a JVM-level
     * fact makes that edge impossible: a known conditional result, a guaranteed failed
     * reflective lookup, or an incompatible exact CHECKCAST.  Unknown values and unresolved
     * metadata keep both paths.
     */
    public boolean sinkPathProvablyUnreachable(MethodInfo method, int sinkOffset) {
        if (method == null || sinkOffset < 0 || sinkOffset >= method.instructions().size()) {
            return false;
        }
        if (!hasPathProofFeature(method)) {
            // With no exact branch/cast/reflection rule, a non-null forward state is already
            // the authoritative CFG reachability fact. Returning false is conservative for
            // malformed states and avoids a full reverse walk for ordinary call sites.
            return false;
        }
        return sinkPathProvablyUnreachable(method, sinkOffset, origins.compute(method));
    }

    /** Same exact path proof when the caller already owns the method's forward result. */
    public boolean sinkPathProvablyUnreachable(MethodInfo method, int sinkOffset,
                                               ForwardOrigins.Result result) {
        if (method == null || sinkOffset < 0 || sinkOffset >= method.instructions().size()
                || !hasPathProofFeature(method)) {
            return false;
        }
        CfgProofKey proofKey = new CfgProofKey(methodKey(method), sinkOffset);
        Boolean cached = sinkPathCache.get(proofKey);
        if (cached != null) {
            return cached;
        }
        ConstantProofContext previous = constantProof.get();
        constantProof.set(new ConstantProofContext());
        try {
            Cfg.Indexed cfg = cfg(method);
            if (result == null) {
                return false;
            }
            int size = method.instructions().size();
            boolean[] canReachSink = new boolean[size];
            canReachSink[sinkOffset] = true;
            boolean changed;
            do {
                changed = false;
                for (int source = size - 1; source >= 0; source--) {
                    if (canReachSink[source]) {
                        continue;
                    }
                    for (int edgeIndex = cfg.edgeStart(source); edgeIndex < cfg.edgeEnd(source); edgeIndex++) {
                        int target = cfg.targetAt(edgeIndex);
                        CfgLabel label = cfg.labelAt(edgeIndex);
                        if (target < 0 || target >= size
                                || !feasibleCfgEdge(method, result, source, label)) {
                            continue;
                        }
                        if (canReachSink[target]) {
                            canReachSink[source] = true;
                            changed = true;
                            break;
                        }
                    }
                }
            } while (changed);
            boolean unreachable = !canReachSink[0];
            sinkPathCache.putIfAbsent(proofKey, unreachable);
            return unreachable;
        } finally {
            if (previous == null) {
                constantProof.remove();
            } else {
                constantProof.set(previous);
            }
        }
    }

    private boolean hasPathProofFeature(MethodInfo method) {
        String key = methodKey(method);
        return pathProofFeatureCache.computeIfAbsent(key, ignored -> {
            for (InsnFact insn : method.instructions()) {
                if (insn.op().isCondJump() || insn.op() == Op.CHECKCAST) {
                    return true;
                }
                if (!insn.op().isInvoke() || insn.operands().isEmpty()
                        || !(insn.operands().get(0) instanceof MethodRef ref)) {
                    continue;
                }
                if ("java/lang/reflect/Method".equals(ref.owner())
                        && "invoke".equals(ref.name())) {
                    return true;
                }
                if ("java/lang/Class".equals(ref.owner())
                        && (ref.name().startsWith("get") || "cast".equals(ref.name()))) {
                    return true;
                }
            }
            return false;
        });
    }

    /** Whether the optional exact-constant refinement had to fail open on a budget. */
    public boolean constantProofBudgetExceeded() {
        return constantProofBudgetExceeded.get();
    }

    private boolean feasibleCfgEdge(MethodInfo method, ForwardOrigins.Result result,
                                    int source, CfgLabel label) {
        InsnFact insn = method.insnAt(source);
        if (insn.op().isCondJump()) {
            Boolean branch = knownBranchResult(method, result, insn);
            if (branch == null) {
                return true;
            }
            if (label == CfgLabel.JUMP) {
                return branch;
            }
            if (label == CfgLabel.FALSE) {
                return !branch;
            }
        }
        if (insn.op() == Op.CHECKCAST && label != CfgLabel.EXCEPTION
                && castAlwaysFails(method, result, insn)) {
            return false;
        }
        if (insn.op().isInvoke() && label != CfgLabel.EXCEPTION
                && reflectiveLookupAlwaysFails(method, result, insn)) {
            return false;
        }
        if (insn.op().isInvoke() && label != CfgLabel.EXCEPTION
                && reflectiveInvocationAlwaysFails(method, result, insn)) {
            return false;
        }
        return true;
    }

    /** A normal edge is impossible when a reflective lookup has an exact missing target. */
    private boolean reflectiveLookupAlwaysFails(MethodInfo method, ForwardOrigins.Result result,
                                                InsnFact insn) {
        if (!insn.op().isInvoke() || insn.operands().isEmpty()
                || !(insn.operands().get(0) instanceof MethodRef ref)
                || !"java/lang/Class".equals(ref.owner())) {
            return false;
        }
        if ("getMethod".equals(ref.name()) || "getDeclaredMethod".equals(ref.name())
                || "getConstructor".equals(ref.name()) || "getDeclaredConstructor".equals(ref.name())) {
            Node call = graph.findCallNode(methodKey(method), insn.offset());
            if (call == null) {
                return false;
            }
            Set<ValueOrigin> classes = argOriginAtOrdinal(call, -1, result);
            String className = classLiteralName(classes);
            Set<ValueOrigin> names = argOriginAtOrdinal(call, 0, result);
            String name = stringLiteral(names);
            String descriptor = reflectiveParameterDescriptor(method, insn, ref);
            int parameterCount = descriptor == null
                    ? reflectiveParameterCount(method, result, call, ref) : -1;
            if (className == null || (name == null && parameterCount < 0)) {
                return false;
            }
            boolean inherited = "getMethod".equals(ref.name());
            boolean publicOnly = "getMethod".equals(ref.name())
                    || "getConstructor".equals(ref.name());
            String lookupName = ref.name().contains("Constructor") ? "<init>" : name;
            if (descriptor != null) {
                return !reflectiveMethodExists(className, lookupName, descriptor,
                        inherited, publicOnly);
            }
            if (parameterCount < 0) {
                return false;
            }
            if ("<init>".equals(lookupName)) {
                return !reflectiveMethodExistsByArity(className, lookupName, parameterCount,
                        inherited, publicOnly);
            }
            StringShape shape = stringShape(argOriginAtOrdinal(call, 0, result), method,
                    result, new HashSet<>());
            if (name != null) {
                return !reflectiveMethodExistsByArity(className, name, parameterCount,
                        inherited, publicOnly);
            }
            return shape != null && shape.prefix() != null
                    && !reflectiveMethodNameStartsWith(className, shape.prefix(), parameterCount,
                    inherited, publicOnly);
        }
        if ("getField".equals(ref.name()) || "getDeclaredField".equals(ref.name())) {
            Node call = graph.findCallNode(methodKey(method), insn.offset());
            if (call == null) {
                return false;
            }
            String className = classLiteralName(argOriginAtOrdinal(call, -1, result));
            String fieldName = stringLiteral(argOriginAtOrdinal(call, 0, result));
            if (className == null || fieldName == null) {
                return false;
            }
            ClassInfo target = hierarchy.classInfo(className);
            if (target == null) {
                return false;
            }
            if ("getDeclaredField".equals(ref.name())) {
                return target.field(fieldName) == null;
            }
            return publicField(className, fieldName) == null;
        }
        return false;
    }

    /** A Method.invoke normal edge is impossible when its exact target cannot be applied. */
    private boolean reflectiveInvocationAlwaysFails(MethodInfo host,
                                                    ForwardOrigins.Result result,
                                                    InsnFact insn) {
        if (!insn.op().isInvoke() || insn.operands().isEmpty()
                || !(insn.operands().get(0) instanceof MethodRef ref)
                || !"java/lang/reflect/Method".equals(ref.owner())
                || !"invoke".equals(ref.name())) {
            return false;
        }
        Node invoke = graph.findCallNode(methodKey(host), insn.offset());
        if (invoke == null) {
            return false;
        }
        Set<ValueOrigin> methodValues = argOriginAtOrdinal(invoke, -1, result);
        if (methodValues.size() != 1
                || !(methodValues.iterator().next() instanceof ValueOrigin.CallResult lookupResult)) {
            return false;
        }
        Node lookup = callNodes.get(lookupResult.callNodeId());
        MethodInfo target = reflectiveLookupTarget(lookup, host, result);
        if (target == null) {
            return false;
        }
        if (!target.isStatic()) {
            Set<ValueOrigin> receiver = argOriginAtOrdinal(invoke, 0, result);
            if (receiver.size() == 1 && isNullConstant(receiver.iterator().next())) {
                return true;
            }
        }
        return !java.lang.reflect.Modifier.isPublic(target.access())
                && !hasAccessibleOverride(host, invoke, methodValues, result);
    }

    /**
     * Check the two runtime preconditions that are locally decidable for Method.invoke:
     * instance methods need a non-null compatible receiver, and a non-public declared method
     * needs a preceding setAccessible(true) on the same Method object.  Unknown receiver or
     * metadata remains accepted so reflective application code is not under-reported.
     */
    public boolean reflectiveInvokeMayReach(MethodInfo target, Node invoke) {
        MethodInfo host = enclosingMethod(invoke);
        return reflectiveInvokeMayReach(target, invoke,
                host == null ? null : origins.compute(host));
    }

    /** Same reflective precondition check when the host summary is already available. */
    public boolean reflectiveInvokeMayReach(MethodInfo target, Node invoke,
                                            ForwardOrigins.Result result) {
        if (target == null || invoke == null || !"java/lang/reflect/Method".equals(invoke.owner())
                || !"invoke".equals(invoke.name())) {
            return true;
        }
        MethodInfo host = enclosingMethod(invoke);
        if (host == null) {
            return true;
        }
        if (result == null) {
            return true;
        }
        if (!target.isStatic()) {
            Set<ValueOrigin> receivers = argOriginAtOrdinal(invoke, 0, result);
            if (receivers.size() == 1 && isNullConstant(receivers.iterator().next())) {
                return false;
            }
        }
        if (java.lang.reflect.Modifier.isPublic(target.access())) {
            return true;
        }
        Set<ValueOrigin> methodValues = argOriginAtOrdinal(invoke, -1, result);
        for (ValueOrigin methodValue : methodValues) {
            if (!(methodValue instanceof ValueOrigin.CallResult lookupResult)) {
                continue;
            }
            Node lookup = callNodes.get(lookupResult.callNodeId());
            if (lookup != null && "getDeclaredMethod".equals(lookup.name())
                    && hasAccessibleOverride(host, invoke, Set.of(methodValue), result)) {
                return true;
            }
        }
        return false;
    }

    private String stringLiteral(Set<ValueOrigin> values) {
        if (values == null || values.size() != 1
                || !(values.iterator().next() instanceof ValueOrigin.Constant constant)
                || !(constant.value() instanceof String value)) {
            return null;
        }
        return value;
    }

    /**
     * A deliberately small string abstract value for reflective names.  Exact constants are
     * preferred; when the suffix is attacker-controlled we still retain a proven prefix such
     * as {@code "get"}.  This is enough to reject a lookup only when the target class has no
     * matching method at all, while an unknown prefix remains fully conservative.
     */
    private record StringShape(String exact, String prefix) {
        private static StringShape exact(String value) {
            return new StringShape(value, value);
        }

        private static StringShape unknown() {
            return new StringShape(null, "");
        }
    }

    private StringShape stringShape(Set<ValueOrigin> values, MethodInfo method,
                                    ForwardOrigins.Result result,
                                    Set<ValueOrigin> visiting) {
        if (values == null || values.size() != 1) {
            return null;
        }
        return stringShape(values.iterator().next(), method, result, visiting);
    }

    private StringShape stringShape(ValueOrigin value, MethodInfo method,
                                    ForwardOrigins.Result result,
                                    Set<ValueOrigin> visiting) {
        if (value == null || method == null || !visiting.add(value)) {
            return null;
        }
        try {
            if (value instanceof ValueOrigin.Constant constant
                    && constant.value() instanceof String text) {
                return StringShape.exact(text);
            }
            if (value instanceof ValueOrigin.Insn instruction
                    && instruction.offset() >= 0
                    && instruction.offset() < method.instructions().size()) {
                InsnFact insn = method.insnAt(instruction.offset());
                if (insn.op() == Op.NEW && insn.typeRef() != null) {
                    String type = internalClassName(insn.typeRef().descriptor());
                    if ("java/lang/StringBuilder".equals(type)
                            || "java/lang/StringBuffer".equals(type)) {
                        return StringShape.exact("");
                    }
                }
                return null;
            }
            if (!(value instanceof ValueOrigin.CallResult callResult)
                    || callResult.callNodeId() < 0) {
                return null;
            }
            Node call = callNodes.get(callResult.callNodeId());
            if (call == null) {
                return null;
            }
            ForwardOrigins.Result callState = origins.compute(method);
            String owner = call.owner();
            if (isStringBuilderType(owner) && "toString".equals(call.name())) {
                return stringShape(argOriginAtOrdinal(call, -1, callState), method,
                        callState, visiting);
            }
            if (isStringBuilderType(owner) && call.name().startsWith("append")) {
                StringShape receiver = stringShape(argOriginAtOrdinal(call, -1, callState),
                        method, callState, visiting);
                StringShape argument = stringShape(argOriginAtOrdinal(call, 0, callState),
                        method, callState, visiting);
                if (receiver == null) {
                    return null;
                }
                if (argument == null) {
                    return new StringShape(null, receiver.exact() != null
                            ? receiver.exact() : receiver.prefix());
                }
                return appendShape(receiver, argument);
            }
            if ("java/lang/String".equals(owner) && "concat".equals(call.name())) {
                StringShape receiver = stringShape(argOriginAtOrdinal(call, -1, callState),
                        method, callState, visiting);
                StringShape argument = stringShape(argOriginAtOrdinal(call, 0, callState),
                        method, callState, visiting);
                return receiver == null || argument == null ? null : appendShape(receiver, argument);
            }
            return null;
        } finally {
            visiting.remove(value);
        }
    }

    private static boolean isStringBuilderType(String owner) {
        return "java/lang/StringBuilder".equals(owner)
                || "java/lang/StringBuffer".equals(owner)
                || "java/lang/AbstractStringBuilder".equals(owner);
    }

    private static StringShape appendShape(StringShape left, StringShape right) {
        if (left.exact() != null && right.exact() != null) {
            return StringShape.exact(left.exact() + right.exact());
        }
        String leftPrefix = left.exact() != null ? left.exact() : left.prefix();
        String rightPrefix = right.exact() != null ? right.exact() : right.prefix();
        return new StringShape(null, leftPrefix + rightPrefix);
    }

    private String classLiteralName(Set<ValueOrigin> values) {
        if (values == null || values.size() != 1
                || !(values.iterator().next() instanceof ValueOrigin.Constant constant)
                || !(constant.value() instanceof io.just.sast.model.TypeRef type)) {
            return null;
        }
        return internalClassName(type.descriptor());
    }

    private int reflectiveParameterCount(MethodInfo method, ForwardOrigins.Result result,
                                         Node call, MethodRef ref) {
        int ordinal;
        if ("getMethod".equals(ref.name()) || "getDeclaredMethod".equals(ref.name())) {
            ordinal = 1;
        } else if ("getConstructor".equals(ref.name()) || "getDeclaredConstructor".equals(ref.name())) {
            ordinal = 0;
        } else {
            return -1;
        }
        Integer length = null;
        for (ValueOrigin array : argOriginAtOrdinal(call, ordinal, result)) {
            Integer candidate = arrayLength(array, method, result);
            if (candidate == null || (length != null && !length.equals(candidate))) {
                return -1;
            }
            length = candidate;
        }
        return length == null ? -1 : length;
    }

    private boolean reflectiveMethodExistsByArity(String owner, String name, int parameterCount,
                                                   boolean includeInherited, boolean publicOnly) {
        return reflectiveMethodMatches(owner, name, parameterCount, null,
                includeInherited, publicOnly);
    }

    private boolean reflectiveMethodNameStartsWith(String owner, String prefix, int parameterCount,
                                                   boolean includeInherited, boolean publicOnly) {
        return reflectiveMethodMatches(owner, null, parameterCount, prefix,
                includeInherited, publicOnly);
    }

    private boolean reflectiveMethodMatches(String owner, String exactName, int parameterCount,
                                            String namePrefix, boolean includeInherited,
                                            boolean publicOnly) {
        if (owner == null || parameterCount < 0) {
            return false;
        }
        Deque<String> work = new ArrayDeque<>();
        Set<String> seen = new HashSet<>();
        work.add(owner);
        while (!work.isEmpty()) {
            String current = work.removeFirst();
            if (!seen.add(current)) {
                continue;
            }
            ClassInfo cls = hierarchy.classInfo(current);
            if (cls == null) {
                continue;
            }
            for (MethodInfo candidate : cls.methods()) {
                boolean nameMatches = exactName != null
                        ? exactName.equals(candidate.name())
                        : candidate.name().startsWith(namePrefix);
                if (nameMatches && Descriptor.paramCount(candidate.descriptor()) == parameterCount
                        && (!publicOnly || java.lang.reflect.Modifier.isPublic(candidate.access()))) {
                    return true;
                }
            }
            if (!includeInherited) {
                continue;
            }
            if (cls.superName() != null) {
                work.addLast(cls.superName());
            }
            work.addAll(cls.interfaces());
        }
        return false;
    }

    private io.just.sast.model.FieldInfo publicField(String owner, String name) {
        Deque<String> work = new ArrayDeque<>();
        Set<String> seen = new HashSet<>();
        work.add(owner);
        while (!work.isEmpty()) {
            String current = work.removeFirst();
            if (!seen.add(current)) {
                continue;
            }
            ClassInfo cls = hierarchy.classInfo(current);
            if (cls == null) {
                continue;
            }
            io.just.sast.model.FieldInfo field = cls.field(name);
            if (field != null && java.lang.reflect.Modifier.isPublic(field.access())) {
                return field;
            }
            if (cls.superName() != null) {
                work.addLast(cls.superName());
            }
            work.addAll(cls.interfaces());
        }
        return null;
    }

    private boolean castAlwaysFails(MethodInfo method, ForwardOrigins.Result result,
                                    InsnFact insn) {
        if (insn.typeRef() == null) {
            return false;
        }
        ForwardOrigins.State state = result.stateBefore().get(insn.offset());
        if (state == null || state.stack().isEmpty()) {
            return false;
        }
        String target = internalClassName(insn.typeRef().descriptor());
        if (target == null) {
            return false;
        }
        Set<String> types = concreteTypesOf(state.stack().get(state.stack().size() - 1).origins(),
                method, insn.offset());
        if (types.isEmpty()) {
            return false;
        }
        for (String type : types) {
            if (type == null || hierarchy.isSubtypeOf(type, target)) {
                return false;
            }
        }
        return true;
    }

    private Boolean knownBranchResult(MethodInfo method, ForwardOrigins.Result result,
                                      InsnFact branch) {
        ForwardOrigins.State state = result.stateBefore().get(branch.offset());
        if (state == null || state.stack().isEmpty()) {
            return null;
        }
        if (branch.op() == Op.IFNULL || branch.op() == Op.IFNONNULL) {
            Boolean knownNull = knownNullness(
                    state.stack().get(state.stack().size() - 1).origins(), method, result,
                    new HashSet<>());
            if (knownNull == null) {
                return null;
            }
            return branch.op() == Op.IFNULL ? knownNull : !knownNull;
        }
        if (branch.op() == Op.IF_ACMPEQ || branch.op() == Op.IF_ACMPNE) {
            if (state.stack().size() < 2) {
                return null;
            }
            Set<ValueOrigin> left = state.stack().get(state.stack().size() - 2).origins();
            Set<ValueOrigin> right = state.stack().get(state.stack().size() - 1).origins();
            if (left.size() != 1 || right.size() != 1 || !left.equals(right)) {
                return null;
            }
            return branch.op() == Op.IF_ACMPEQ;
        }
        Integer left;
        Integer right = null;
        if (branch.op() == Op.IF_ICMPEQ || branch.op() == Op.IF_ICMPNE
                || branch.op() == Op.IF_ICMPLT || branch.op() == Op.IF_ICMPGE
                || branch.op() == Op.IF_ICMPGT || branch.op() == Op.IF_ICMPLE) {
            if (state.stack().size() < 2) {
                return null;
            }
            left = knownInteger(state.stack().get(state.stack().size() - 2).origins(), method,
                    result, new HashSet<>(), new HashSet<>());
            right = knownInteger(state.stack().get(state.stack().size() - 1).origins(), method,
                    result, new HashSet<>(), new HashSet<>());
            if (left == null || right == null) {
                return null;
            }
        } else {
            left = knownInteger(state.stack().get(state.stack().size() - 1).origins(), method,
                    result, new HashSet<>(), new HashSet<>());
            if (left == null) {
                return null;
            }
        }
        return switch (branch.op()) {
            case IFEQ -> left == 0;
            case IFNE -> left != 0;
            case IFLT -> left < 0;
            case IFGE -> left >= 0;
            case IFGT -> left > 0;
            case IFLE -> left <= 0;
            case IF_ICMPEQ -> left.equals(right);
            case IF_ICMPNE -> !left.equals(right);
            case IF_ICMPLT -> left < right;
            case IF_ICMPGE -> left >= right;
            case IF_ICMPGT -> left > right;
            case IF_ICMPLE -> left <= right;
            default -> null;
        };
    }

    private Integer knownInteger(Set<ValueOrigin> values, MethodInfo method,
                                 ForwardOrigins.Result result, Set<ValueOrigin> visiting,
                                 Set<String> methods) {
        if (values == null || values.isEmpty()) {
            return null;
        }
        Integer resultValue = null;
        for (ValueOrigin value : values) {
            Integer candidate = knownInteger(value, method, result, visiting, methods);
            if (candidate == null || (resultValue != null && !resultValue.equals(candidate))) {
                return null;
            }
            resultValue = candidate;
        }
        return resultValue;
    }

    private Integer knownInteger(ValueOrigin value, MethodInfo method,
                                 ForwardOrigins.Result result, Set<ValueOrigin> visiting,
                                 Set<String> methods) {
        if (value == null) {
            return null;
        }
        ConstantProofContext context = constantProof.get();
        ConstantFactKey factKey = context == null ? null
                : new ConstantFactKey(method == null ? "<null>" : methodKey(method), value);
        if (context != null) {
            if (context.facts.containsKey(factKey)) {
                return context.facts.get(factKey);
            }
            if (!context.consume()) {
                constantProofBudgetExceeded.set(true);
                return null;
            }
            if (!context.active.add(factKey)) {
                return null;
            }
        }
        if (!visiting.add(value)) {
            if (context != null) {
                context.active.remove(factKey);
            }
            return null;
        }
        Integer answer = null;
        try {
            answer = knownIntegerUncached(value, method, result, visiting, methods);
            return answer;
        } finally {
            visiting.remove(value);
            if (context != null) {
                context.active.remove(factKey);
                context.facts.put(factKey, answer);
            }
        }
    }

    private Integer knownIntegerUncached(ValueOrigin value, MethodInfo method,
                                         ForwardOrigins.Result result, Set<ValueOrigin> visiting,
                                         Set<String> methods) {
        if (value instanceof ValueOrigin.Constant constant) {
            return literalInteger(constant);
        }
        if (value instanceof ValueOrigin.FieldRead field && field.isStatic()) {
            return staticFieldInteger(field);
        }
        if (value instanceof ValueOrigin.FieldRead field) {
            return instanceFieldInteger(field, method, result, visiting, methods);
        }
        if (value instanceof ValueOrigin.Param param) {
            return constantParameterValue(method, param.slot(), methods);
        }
        if (value instanceof ValueOrigin.Insn instruction
                && instruction.offset() >= 0
                && instruction.offset() < method.instructions().size()) {
            InsnFact insn = method.insnAt(instruction.offset());
            ForwardOrigins.State before = result.stateBefore().get(instruction.offset());
            if (before == null) {
                return null;
            }
            if (insn.op() == Op.ARRAYLENGTH && !before.stack().isEmpty()) {
                return arrayLengthOf(before.stack().get(before.stack().size() - 1).origins(),
                        method, result);
            }
            if (insn.op() == Op.CHECKCAST && !before.stack().isEmpty()) {
                // CHECKCAST changes the verifier type, not the runtime value.  Preserve
                // exact scalar facts through a successful cast (notably
                // Method.invoke -> Boolean -> booleanValue); incompatible casts are
                // handled independently by castAlwaysFails().
                return knownInteger(before.stack().get(before.stack().size() - 1).origins(),
                        method, result, visiting, methods);
            }
            Integer unary = knownUnaryInteger(insn.op(), before, method, result,
                    visiting, methods);
            if (unary != null) {
                return unary;
            }
            Integer binary = knownBinaryInteger(insn.op(), before, method, result,
                    visiting, methods);
            if (binary != null) {
                return binary;
            }
            return null;
        }
        if (value instanceof ValueOrigin.CallResult callResult
                && callResult.callNodeId() >= 0) {
            Node call = callNodes.get(callResult.callNodeId());
            if (call == null) {
                return null;
            }
            ForwardOrigins.Result callResultState = origins.compute(method);
            if ("booleanValue".equals(call.name()) && "java/lang/Boolean".equals(call.owner())) {
                Set<ValueOrigin> receiver = argOriginAtOrdinal(call, -1, callResultState);
                return knownInteger(receiver, method, callResultState, visiting, methods);
            }
            if (isIntegerWrapperFactory(call.owner(), call.name())) {
                Set<ValueOrigin> argument = argOriginAtOrdinal(call, 0, callResultState);
                return knownInteger(argument, method, callResultState, visiting, methods);
            }
            if (isIntegerWrapperValue(call.owner(), call.name())) {
                Set<ValueOrigin> receiver = argOriginAtOrdinal(call, -1, callResultState);
                return knownInteger(receiver, method, callResultState, visiting, methods);
            }
            if ("isAccessible".equals(call.name())
                    && "java/lang/reflect/AccessibleObject".equals(call.owner())) {
                Set<ValueOrigin> receiver = argOriginAtOrdinal(call, -1, callResultState);
                return hasAccessibleOverride(method, call, receiver, callResultState) ? 1 : 0;
            }
            if ("isProxyClass".equals(call.name())
                    && "java/lang/reflect/Proxy".equals(call.owner())) {
                Set<ValueOrigin> classValues = argOriginAtOrdinal(call, 0, callResultState);
                return proxyClassValue(classValues, method, callResultState) ? 1 : 0;
            }
            if ("java/lang/reflect/Method".equals(call.owner())
                    && "invoke".equals(call.name())) {
                Integer reflected = reflectiveInvokeInteger(call, method, callResultState,
                        methods);
                if (reflected != null) {
                    return reflected;
                }
            }
            MethodInfo callee = methodOf(call.owner(), call.name(), call.descriptor());
            if (callee == null) {
                return null;
            }
            return constantReturnValue(callee, methods);
        }
        return null;
    }

    private static boolean isIntegerWrapperFactory(String owner, String name) {
        return "valueOf".equals(name) && ("java/lang/Boolean".equals(owner)
                || "java/lang/Byte".equals(owner) || "java/lang/Short".equals(owner)
                || "java/lang/Character".equals(owner) || "java/lang/Integer".equals(owner)
                || "java/lang/Long".equals(owner));
    }

    private static boolean isIntegerWrapperValue(String owner, String name) {
        return ("intValue".equals(name) || "byteValue".equals(name)
                || "shortValue".equals(name) || "charValue".equals(name)
                || "longValue".equals(name))
                && ("java/lang/Byte".equals(owner) || "java/lang/Short".equals(owner)
                || "java/lang/Character".equals(owner) || "java/lang/Integer".equals(owner)
                || "java/lang/Long".equals(owner));
    }

    private boolean hasAccessibleOverride(MethodInfo host, Node query,
                                           Set<ValueOrigin> receiver,
                                           ForwardOrigins.Result result) {
        for (Node candidate : graph.callsOfMethod(methodKey(host))) {
            if (candidate.offset() >= query.offset()
                    || !"setAccessible".equals(candidate.name())
                    || !"java/lang/reflect/AccessibleObject".equals(candidate.owner())) {
                continue;
            }
            Set<ValueOrigin> candidateReceiver = argOriginAtOrdinal(candidate, -1, result);
            if (candidateReceiver.stream().noneMatch(receiver::contains)) {
                continue;
            }
            Integer enabled = knownInteger(argOriginAtOrdinal(candidate, 0, result), host, result,
                    new HashSet<>(), new HashSet<>());
            if (enabled != null && enabled != 0) {
                return true;
            }
        }
        return false;
    }

    private boolean proxyClassValue(Set<ValueOrigin> values, MethodInfo method,
                                    ForwardOrigins.Result result) {
        if (values == null || values.size() != 1
                || !(values.iterator().next() instanceof ValueOrigin.CallResult classResult)) {
            return false;
        }
        Node classCall = callNodes.get(classResult.callNodeId());
        if (classCall == null || !"getClass".equals(classCall.name())) {
            return false;
        }
        Set<ValueOrigin> receivers = argOriginAtOrdinal(classCall, -1, result);
        for (ValueOrigin receiver : receivers) {
            if (receiver instanceof ValueOrigin.CallResult objectResult) {
                Node allocation = callNodes.get(objectResult.callNodeId());
                if (allocation != null && "java/lang/reflect/Proxy".equals(allocation.owner())
                        && "newProxyInstance".equals(allocation.name())) {
                    return true;
                }
            }
        }
        return false;
    }

    private Integer knownUnaryInteger(Op op, ForwardOrigins.State before, MethodInfo method,
                                      ForwardOrigins.Result result, Set<ValueOrigin> visiting,
                                      Set<String> methods) {
        if (before.stack().isEmpty()) {
            return null;
        }
        Integer value = knownInteger(before.stack().get(before.stack().size() - 1).origins(),
                method, result, visiting, methods);
        if (value == null) {
            return null;
        }
        return op == Op.INEG ? -value : null;
    }

    private Integer knownBinaryInteger(Op op, ForwardOrigins.State before, MethodInfo method,
                                       ForwardOrigins.Result result, Set<ValueOrigin> visiting,
                                       Set<String> methods) {
        if (before.stack().size() < 2) {
            return null;
        }
        Integer right = knownInteger(before.stack().get(before.stack().size() - 1).origins(),
                method, result, visiting, methods);
        Integer left = knownInteger(before.stack().get(before.stack().size() - 2).origins(),
                method, result, visiting, methods);
        if (left == null || right == null) {
            return null;
        }
        return switch (op) {
            case IADD -> left + right;
            case ISUB -> left - right;
            case IMUL -> left * right;
            case IDIV -> right == 0 ? null : left / right;
            case IREM -> right == 0 ? null : left % right;
            default -> null;
        };
    }

    private Integer arrayLengthOf(Set<ValueOrigin> values, MethodInfo method,
                                  ForwardOrigins.Result result) {
        if (values == null || values.isEmpty()) {
            return null;
        }
        Integer length = null;
        for (ValueOrigin value : values) {
            Integer candidate = arrayLength(value, method, result);
            if (candidate == null || (length != null && !length.equals(candidate))) {
                return null;
            }
            length = candidate;
        }
        return length;
    }

    private Boolean knownNullness(ValueOrigin value, MethodInfo method,
                                  ForwardOrigins.Result result, Set<ValueOrigin> visiting) {
        if (value instanceof ValueOrigin.Constant constant) {
            return constant.value() == null || "ACONST_NULL".equals(constant.value());
        }
        if (value instanceof ValueOrigin.Insn instruction
                && instruction.offset() >= 0 && instruction.offset() < method.instructions().size()) {
            Op op = method.insnAt(instruction.offset()).op();
            if (op == Op.NEW || op == Op.NEWARRAY || op == Op.ANEWARRAY
                    || op == Op.MULTIANEWARRAY) {
                return false;
            }
        }
        if (value instanceof ValueOrigin.CallResult callResult
                && callResult.callNodeId() >= 0) {
            Node call = callNodes.get(callResult.callNodeId());
            return call != null && "<init>".equals(call.name()) ? false : null;
        }
        return null;
    }

    /** Prove nullness only when every abstract origin agrees on the same answer. */
    private Boolean knownNullness(Set<ValueOrigin> values, MethodInfo method,
                                  ForwardOrigins.Result result, Set<ValueOrigin> visiting) {
        if (values == null || values.isEmpty()) {
            return null;
        }
        Boolean answer = null;
        for (ValueOrigin value : ValueOriginOrder.sorted(values)) {
            Boolean candidate = knownNullness(value, method, result, visiting);
            if (candidate == null || (answer != null && !answer.equals(candidate))) {
                return null;
            }
            answer = candidate;
        }
        return answer;
    }

    private Integer constantParameterValue(MethodInfo method, int slot, Set<String> methods) {
        if (method == null || slot <= 0 || !methods.add(methodKey(method))) {
            return null;
        }
        try {
            Node methodNode = graph.findMethodNodeKey(methodKey(method));
            if (methodNode == null) {
                return null;
            }
            Integer value = null;
            int seen = 0;
            for (Edge edge : methodNode.in()) {
                if (edge.type() != EdgeType.INVOKES && edge.type() != EdgeType.DISPATCHES) {
                    continue;
                }
                Node call = edge.from();
                MethodInfo caller = enclosingMethod(call);
                if (caller == null) {
                    continue;
                }
                ForwardOrigins.Result callerResult = origins.compute(caller);
                Set<ValueOrigin> values = argOriginAt(call, caller, slot, callerResult);
                Integer candidate = knownInteger(values, caller, callerResult,
                        new HashSet<>(), methods);
                if (candidate == null) {
                    return null;
                }
                if (value != null && !value.equals(candidate)) {
                    return null;
                }
                value = candidate;
                seen++;
            }
            // Reflection is deliberately not materialized as a blanket call-graph edge. If
            // the Method object has one exact Class.getMethod/getDeclaredMethod origin, the
            // Object[] element at the target parameter ordinal is nevertheless a normal JVM
            // value and can participate in the same constant proof as a direct invoke. The
            // compact index contains only reflective calls; scanning all CALL nodes here made
            // a large jar pay the full call-site count once per recursive parameter proof.
            for (Node invoke : reflectiveInvokeCalls) {
                boolean methodInvoke = "java/lang/reflect/Method".equals(invoke.owner())
                        && "invoke".equals(invoke.name());
                boolean constructorInvoke = "java/lang/reflect/Constructor".equals(invoke.owner())
                        && "newInstance".equals(invoke.name());
                if (!methodInvoke && !constructorInvoke) {
                    continue;
                }
                MethodInfo caller = enclosingMethod(invoke);
                if (caller == null) {
                    continue;
                }
                ForwardOrigins.Result callerResult = origins.compute(caller);
                MethodInfo reflected;
                if (methodInvoke) {
                    Set<ValueOrigin> methodValues = argOriginAtOrdinal(invoke, -1, callerResult);
                    if (methodValues.size() != 1
                            || !(methodValues.iterator().next() instanceof ValueOrigin.CallResult lookupResult)) {
                        continue;
                    }
                    reflected = reflectiveLookupTarget(callNodes.get(lookupResult.callNodeId()),
                            caller, callerResult);
                } else {
                    reflected = reflectiveConstructorTarget(invoke, caller, callerResult);
                }
                if (reflected == null || !methodKey(reflected).equals(methodKey(method))) {
                    continue;
                }
                Set<ValueOrigin> values = methodInvoke
                        ? reflectiveMethodArgumentAt(invoke, reflected, slot, callerResult)
                        : reflectiveConstructorArgumentAt(invoke, reflected, slot, callerResult);
                Integer candidate = knownInteger(values, caller, callerResult,
                        new HashSet<>(), methods);
                if (candidate == null) {
                    return null;
                }
                if (value != null && !value.equals(candidate)) {
                    return null;
                }
                value = candidate;
                seen++;
            }
            return seen == 0 ? null : value;
        } finally {
            methods.remove(methodKey(method));
        }
    }

    private Set<ValueOrigin> reflectiveMethodArgumentAt(Node invoke, MethodInfo target, int slot,
                                                        ForwardOrigins.Result callerResult) {
        int ordinal = Descriptor.paramOrdinal(target.descriptor(), target.isStatic(), slot);
        if (ordinal < 0) {
            return Set.of();
        }
        Set<ValueOrigin> arrays = argOriginAtOrdinal(invoke, 1, callerResult);
        Set<ValueOrigin> values = new LinkedHashSet<>();
        boolean sawArray = false;
        for (ValueOrigin array : ValueOriginOrder.sorted(arrays)) {
            sawArray = true;
            Map<Integer, Set<ValueOrigin>> indexed = callerResult.indexedArrayElements().get(array);
            if (indexed == null || !indexed.containsKey(ordinal)) {
                return Set.of(new ValueOrigin.Unknown());
            }
            values.addAll(ValueOriginOrder.sorted(indexed.get(ordinal)));
        }
        return sawArray && !values.isEmpty() ? orderedOrigins(values)
                : Set.of(new ValueOrigin.Unknown());
    }

    private Set<ValueOrigin> reflectiveConstructorArgumentAt(Node invoke, MethodInfo target,
                                                             int slot,
                                                             ForwardOrigins.Result callerResult) {
        int ordinal = Descriptor.paramOrdinal(target.descriptor(), target.isStatic(), slot);
        if (ordinal < 0) {
            return Set.of();
        }
        return arrayElementAt(argOriginAtOrdinal(invoke, 0, callerResult), ordinal,
                callerResult);
    }

    private Set<ValueOrigin> arrayElementAt(Set<ValueOrigin> arrays, int ordinal,
                                             ForwardOrigins.Result result) {
        Set<ValueOrigin> values = new LinkedHashSet<>();
        boolean sawArray = false;
        for (ValueOrigin array : ValueOriginOrder.sorted(arrays)) {
            sawArray = true;
            Map<Integer, Set<ValueOrigin>> indexed = result.indexedArrayElements().get(array);
            if (indexed == null || !indexed.containsKey(ordinal)) {
                return Set.of(new ValueOrigin.Unknown());
            }
            values.addAll(ValueOriginOrder.sorted(indexed.get(ordinal)));
        }
        return sawArray && !values.isEmpty() ? orderedOrigins(values)
                : Set.of(new ValueOrigin.Unknown());
    }

    /** Resolve an exact Constructor.newInstance target from its preceding Class.get* lookup. */
    private MethodInfo reflectiveConstructorTarget(Node newInstance, MethodInfo host,
                                                   ForwardOrigins.Result hostResult) {
        if (newInstance == null || !"java/lang/reflect/Constructor".equals(newInstance.owner())
                || !"newInstance".equals(newInstance.name())) {
            return null;
        }
        Set<ValueOrigin> constructors = argOriginAtOrdinal(newInstance, -1, hostResult);
        if (constructors.size() != 1
                || !(constructors.iterator().next() instanceof ValueOrigin.CallResult lookupResult)) {
            return null;
        }
        Node lookup = callNodes.get(lookupResult.callNodeId());
        if (lookup == null || (!"getConstructor".equals(lookup.name())
                && !"getDeclaredConstructor".equals(lookup.name()))) {
            return null;
        }
        MethodInfo lookupHost = enclosingMethod(lookup);
        if (lookupHost == null) {
            return null;
        }
        ForwardOrigins.Result lookupResultState = origins.compute(lookupHost);
        String className = classLiteralName(argOriginAtOrdinal(lookup, -1, lookupResultState));
        if (className == null) {
            return null;
        }
        InsnFact lookupInsn = lookupHost.insnAt(lookup.offset());
        String descriptor = reflectiveParameterDescriptor(lookupHost, lookupInsn,
                new MethodRef(lookup.owner(), lookup.name(), lookup.descriptor()));
        if (descriptor == null) {
            return null;
        }
        ClassInfo target = hierarchy.classInfo(className);
        return target == null ? null : target.method("<init>", descriptor);
    }

    /** Exact instance-field value supplied by an exact reflective constructor or NEW call. */
    private Integer instanceFieldInteger(ValueOrigin.FieldRead field, MethodInfo host,
                                          ForwardOrigins.Result hostResult,
                                          Set<ValueOrigin> visiting, Set<String> methods) {
        MethodInfo constructor = null;
        Node allocation = callProducer(field.receiver(), host, hostResult);
        if (allocation != null) {
            constructor = reflectiveConstructorTarget(allocation, host, hostResult);
        }
        if (constructor == null) {
            return null;
        }
        ForwardOrigins.Result constructorResult = origins.compute(constructor);
        Integer value = null;
        int writes = 0;
        for (InsnFact write : constructor.instructions()) {
            if (write.op() != Op.PUTFIELD || !sameField(write, field)) {
                continue;
            }
            ForwardOrigins.State state = constructorResult.stateBefore().get(write.offset());
            if (state == null || state.stack().isEmpty()) {
                return null;
            }
            Integer candidate = knownInteger(state.stack().get(state.stack().size() - 1).origins(),
                    constructor, constructorResult, visiting, methods);
            if (candidate == null || (value != null && !value.equals(candidate))) {
                return null;
            }
            value = candidate;
            writes++;
        }
        return writes == 1 ? value : null;
    }

    /**
     * Resolve a call result through a CHECKCAST without erasing its identity.  The forward
     * origin transfer keeps casts as instruction origins so that incompatible casts can be
     * distinguished during feasibility checks; exact reflective-field reasoning still needs
     * to recover the producer behind a successful cast.
     */
    private Node callProducer(ValueOrigin value, MethodInfo method,
                              ForwardOrigins.Result result) {
        if (value instanceof ValueOrigin.CallResult callResult
                && callResult.callNodeId() >= 0) {
            return callNodes.get(callResult.callNodeId());
        }
        if (!(value instanceof ValueOrigin.Insn instruction)
                || instruction.offset() < 0
                || instruction.offset() >= method.instructions().size()
                || method.insnAt(instruction.offset()).op() != Op.CHECKCAST) {
            return null;
        }
        ForwardOrigins.State before = result.stateBefore().get(instruction.offset());
        if (before == null || before.stack().isEmpty()) {
            return null;
        }
        Set<ValueOrigin> producers = before.stack().get(before.stack().size() - 1).origins();
        Node resolved = null;
        for (ValueOrigin producer : producers) {
            Node candidate = callProducer(producer, method, result);
            if (candidate == null || (resolved != null && resolved != candidate)) {
                return null;
            }
            resolved = candidate;
        }
        return resolved;
    }

    private Integer constantReturnValue(MethodInfo method, Set<String> methods) {
        if (method == null || !methods.add(methodKey(method))) {
            return null;
        }
        try {
            ForwardOrigins.Result result = origins.compute(method);
            Integer value = null;
            int returns = 0;
            for (InsnFact insn : method.instructions()) {
                if (insn.op() != Op.IRETURN && insn.op() != Op.LRETURN
                        && insn.op() != Op.FRETURN && insn.op() != Op.DRETURN) {
                    continue;
                }
                ForwardOrigins.State state = result.stateBefore().get(insn.offset());
                if (state == null || state.stack().isEmpty()) {
                    return null;
                }
                Integer candidate = knownInteger(state.stack().get(state.stack().size() - 1).origins(),
                        method, result, new HashSet<>(), methods);
                if (candidate == null || (value != null && !value.equals(candidate))) {
                    return null;
                }
                value = candidate;
                returns++;
            }
            return returns == 0 ? null : value;
        } finally {
            methods.remove(methodKey(method));
        }
    }

    /** Evaluate a Method.invoke result only when its Method object has an exact lookup fact. */
    private Integer reflectiveInvokeInteger(Node invoke, MethodInfo host,
                                            ForwardOrigins.Result hostResult,
                                            Set<String> methods) {
        Set<ValueOrigin> methodValues = argOriginAtOrdinal(invoke, -1, hostResult);
        if (methodValues == null || methodValues.isEmpty()) {
            return null;
        }
        Integer result = null;
        for (ValueOrigin value : methodValues) {
            if (!(value instanceof ValueOrigin.CallResult lookupResult)
                    || lookupResult.callNodeId() < 0) {
                return null;
            }
            Node lookup = callNodes.get(lookupResult.callNodeId());
            List<MethodInfo> targets = reflectiveLookupTargets(lookup, host, hostResult);
            if (targets.isEmpty()) {
                return null;
            }
            for (MethodInfo target : targets) {
                Integer candidate = constantReturnValue(target, methods);
                if (candidate == null || (result != null && !result.equals(candidate))) {
                    return null;
                }
                result = candidate;
            }
        }
        return result;
    }

    /**
     * Resolve the bounded target family of a reflective lookup for constant-return proofs.
     * Exact names use the JVM lookup semantics; an unknown name is narrowed by the small
     * string-shape analysis (for example {@code "is" + property}).  Returning a family
     * instead of choosing one target is important: a branch may be removed only when every
     * still-valid reflective target has the same known result.
     */
    private List<MethodInfo> reflectiveLookupTargets(Node lookup, MethodInfo host,
                                                       ForwardOrigins.Result hostResult) {
        if (lookup == null || host == null || hostResult == null
                || !"java/lang/Class".equals(lookup.owner())
                || (!"getMethod".equals(lookup.name())
                && !"getDeclaredMethod".equals(lookup.name()))) {
            return List.of();
        }
        String className = classLiteralName(argOriginAtOrdinal(lookup, -1, hostResult));
        if (className == null) {
            return List.of();
        }
        Set<ValueOrigin> nameOrigins = argOriginAtOrdinal(lookup, 0, hostResult);
        String exactName = stringLiteral(nameOrigins);
        StringShape shape = exactName == null
                ? stringShape(nameOrigins, host, hostResult, new HashSet<>()) : null;
        String descriptor = reflectiveParameterDescriptor(host,
                host.insnAt((Integer) lookup.prop("offset")),
                new MethodRef(lookup.owner(), lookup.name(), lookup.descriptor()));

        Map<String, MethodInfo> targets = new TreeMap<>();
        Deque<String> work = new ArrayDeque<>();
        Set<String> seen = new HashSet<>();
        work.add(className);
        boolean inherited = "getMethod".equals(lookup.name());
        while (!work.isEmpty()) {
            String current = work.removeFirst();
            if (!seen.add(current)) {
                continue;
            }
            ClassInfo cls = hierarchy.classInfo(current);
            if (cls == null) {
                continue;
            }
            for (MethodInfo candidate : cls.methods()) {
                if (!reflectiveNameMatches(candidate.name(), exactName, shape)
                        || (descriptor != null && !sameParameters(candidate.descriptor(), descriptor))) {
                    continue;
                }
                if (inherited && !java.lang.reflect.Modifier.isPublic(candidate.access())) {
                    continue;
                }
                targets.putIfAbsent(methodKey(candidate), candidate);
                if (targets.size() >= 32) {
                    break;
                }
            }
            if (targets.size() >= 32 || !inherited) {
                continue;
            }
            if (cls.superName() != null) {
                work.addLast(cls.superName());
            }
            work.addAll(cls.interfaces());
        }
        return List.copyOf(targets.values());
    }

    private static boolean reflectiveNameMatches(String name, String exactName,
                                                  StringShape shape) {
        if (exactName != null) {
            return exactName.equals(name);
        }
        if (shape == null) {
            return false;
        }
        if (shape.exact() != null) {
            return shape.exact().equals(name);
        }
        return shape.prefix() != null && name.startsWith(shape.prefix());
    }

    private MethodInfo reflectiveLookupTarget(Node lookup, MethodInfo host,
                                              ForwardOrigins.Result hostResult) {
        if (lookup == null || !"java/lang/Class".equals(lookup.owner())
                || (!"getMethod".equals(lookup.name())
                && !"getDeclaredMethod".equals(lookup.name()))) {
            return null;
        }
        Set<ValueOrigin> classValues = argOriginAtOrdinal(lookup, -1, hostResult);
        String className = classLiteralName(classValues);
        String name = stringLiteral(argOriginAtOrdinal(lookup, 0, hostResult));
        if (className == null || name == null) {
            return null;
        }
        Node lookupNode = graph.findCallNode(methodKey(host), (Integer) lookup.prop("offset"));
        if (lookupNode == null) {
            return null;
        }
        String descriptor = reflectiveParameterDescriptor(host,
                host.insnAt((Integer) lookup.prop("offset")),
                new MethodRef(lookup.owner(), lookup.name(), lookup.descriptor()));
        if (descriptor == null) {
            return null;
        }
        if ("getDeclaredMethod".equals(lookup.name())) {
            ClassInfo cls = hierarchy.classInfo(className);
            return cls == null ? null : cls.method(name, descriptor);
        }
        String owner = hierarchy.resolveMethod(className, name, descriptor);
        return owner == null ? null : methodOf(owner, name, descriptor);
    }

    /** A6: 确定性运行时异常——值依赖但可判定的子集。 */
    private static boolean isDeterministicRuntime(String type) {
        return "java/lang/ArithmeticException".equals(type)
                || "java/lang/ArrayStoreException".equals(type)
                || "java/util/EmptyStackException".equals(type)
                || "java/lang/IndexOutOfBoundsException".equals(type)
                || "java/lang/NegativeArraySizeException".equals(type)
                || "java/lang/NullPointerException".equals(type)
                || "java/util/NoSuchElementException".equals(type);
    }

    /**
     * Determine whether a runtime-exception handler still has a feasible throw site.
     *
     * <p>The old guard treated every invocation inside a handler's protected interval as a
     * possible thrower. That preserved recall, but it made guarded operations such as
     * {@code if (iterator.hasNext()) iterator.next()} and {@code if (!stack.empty())
     * stack.pop()} indistinguishable from their unsafe counterparts. This pass is deliberately
     * a small, monotone proof layer: it only removes a handler when every relevant operation
     * is either proven safe from bytecode/origin facts or protected by its immediately
     * dominating boolean guard. Unknown calls, aliases, and values keep the chain.
     */
    private boolean runtimeExceptionCanReach(MethodInfo method, TryCatchFact tc) {
        ForwardOrigins.Result result = origins.compute(method);
        int start = Math.max(0, tc.start());
        int end = Math.min(method.instructions().size(), tc.end());
        for (int offset = start; offset < end; offset++) {
            InsnFact insn = method.instructions().get(offset);
            if (!potentialRuntimeThrower(tc.type(), insn)) {
                continue;
            }
            if (runtimeInstructionMayThrow(method, result, tc.type(), offset)) {
                return true;
            }
        }
        // No instruction in the protected interval can produce this exception. The handler
        // is then unreachable even when the surrounding method contains other calls.
        return false;
    }

    private static boolean potentialRuntimeThrower(String type, InsnFact insn) {
        Op op = insn.op();
        return switch (type) {
            case "java/lang/ArithmeticException" -> op == Op.IDIV || op == Op.LDIV
                    || op == Op.IREM || op == Op.LREM;
            case "java/lang/ArrayStoreException" -> op == Op.AASTORE
                    || isReflectiveArraySet(insn);
            case "java/util/EmptyStackException", "java/util/NoSuchElementException" ->
                    op.isInvoke() || op == Op.ATHROW;
            case "java/lang/IndexOutOfBoundsException" -> isArrayAccess(op)
                    || op.isInvoke();
            case "java/lang/NegativeArraySizeException" -> op == Op.NEWARRAY
                    || op == Op.ANEWARRAY || op == Op.MULTIANEWARRAY;
            case "java/lang/NullPointerException" -> op.isInvoke()
                    || op == Op.GETFIELD || op == Op.PUTFIELD
                    || isArrayAccess(op) || op == Op.ARRAYLENGTH
                    || op == Op.MONITORENTER || op == Op.MONITOREXIT || op == Op.ATHROW;
            default -> false;
        };
    }

    private static boolean isReflectiveArraySet(InsnFact insn) {
        if (!insn.op().isInvoke() || insn.operands().isEmpty()
                || !(insn.operands().get(0) instanceof MethodRef ref)) {
            return false;
        }
        return "java/lang/reflect/Array".equals(ref.owner()) && "set".equals(ref.name());
    }

    private static boolean isArrayAccess(Op op) {
        return op == Op.IALOAD || op == Op.LALOAD || op == Op.FALOAD || op == Op.DALOAD
                || op == Op.AALOAD || op == Op.BALOAD || op == Op.CALOAD || op == Op.SALOAD
                || op == Op.IASTORE || op == Op.LASTORE || op == Op.FASTORE || op == Op.DASTORE
                || op == Op.AASTORE || op == Op.BASTORE || op == Op.CASTORE || op == Op.SASTORE;
    }

    private boolean runtimeInstructionMayThrow(MethodInfo method, ForwardOrigins.Result result,
                                               String type, int offset) {
        InsnFact insn = method.instructions().get(offset);
        ForwardOrigins.State state = result.stateBefore().get(offset);
        if (state == null) {
            return true;
        }
        return switch (type) {
            case "java/lang/ArithmeticException" -> {
                Set<ValueOrigin> divisor = state.stack().isEmpty() ? Set.of()
                        : state.stack().get(state.stack().size() - 1).origins();
                yield !definitelyNonZero(divisor, method);
            }
            case "java/lang/ArrayStoreException" -> insn.op() == Op.AASTORE
                    ? arrayStoreMayThrow(method, result, state) : true;
            case "java/util/EmptyStackException" -> collectionCallMayThrow(
                    method, result, offset, "java/util/Stack", "pop", "peek");
            case "java/util/NoSuchElementException" -> collectionCallMayThrow(
                    method, result, offset, "java/util/Iterator", "next", "previous");
            case "java/lang/IndexOutOfBoundsException" -> isArrayAccess(insn.op())
                    ? arrayAccessMayThrow(method, result, state, insn.op()) : true;
            case "java/lang/NegativeArraySizeException" -> arrayAllocationMayThrow(
                    method, result, state, insn.op(), offset);
            case "java/lang/NullPointerException" -> nullReceiverMayThrow(
                    method, result, state, insn);
            default -> true;
        };
    }

    private boolean definitelyNonZero(Set<ValueOrigin> origins, MethodInfo method) {
        Integer value = uniqueInteger(origins, method);
        return value != null && value != 0;
    }

    private Integer uniqueInteger(Set<ValueOrigin> origins, MethodInfo method) {
        if (origins == null || origins.isEmpty()) {
            return null;
        }
        Integer value = null;
        for (ValueOrigin origin : origins) {
            Integer candidate = literalInteger(origin);
            if (candidate == null && origin instanceof ValueOrigin.FieldRead field
                    && field.isStatic()) {
                candidate = staticFieldInteger(field);
            }
            if (candidate == null || (value != null && !value.equals(candidate))) {
                return null;
            }
            value = candidate;
        }
        return value;
    }

    private static Integer literalInteger(ValueOrigin origin) {
        if (!(origin instanceof ValueOrigin.Constant constant)) {
            return null;
        }
        Object value = constant.value();
        if (value instanceof Number number) {
            return number.intValue();
        }
        if (value instanceof String opcode) {
            return switch (opcode) {
                case "ICONST_M1" -> -1;
                case "ICONST_0" -> 0;
                case "ICONST_1" -> 1;
                case "ICONST_2" -> 2;
                case "ICONST_3" -> 3;
                case "ICONST_4" -> 4;
                case "ICONST_5" -> 5;
                default -> null;
            };
        }
        return null;
    }

    private boolean arrayStoreMayThrow(MethodInfo method, ForwardOrigins.Result result,
                                       ForwardOrigins.State state) {
        if (state.stack().size() < 3) {
            return true;
        }
        Set<ValueOrigin> arrays = state.stack().get(state.stack().size() - 3).origins();
        Set<ValueOrigin> values = state.stack().get(state.stack().size() - 1).origins();
        if (arrays.isEmpty() || values.isEmpty()) {
            return true;
        }
        for (ValueOrigin array : arrays) {
            String component = arrayComponentType(array, method);
            if (component == null || !valueFitsArray(values, component, method)) {
                return true;
            }
        }
        return false;
    }

    private boolean valueFitsArray(Set<ValueOrigin> values, String component, MethodInfo method) {
        for (ValueOrigin value : values) {
            if (isNullConstant(value)) {
                continue;
            }
            String type = declaredTypeOf(Set.of(value), method);
            if (type == null || !hierarchy.isSubtypeOf(type, component)) {
                return false;
            }
        }
        return true;
    }

    private String arrayComponentType(ValueOrigin origin, MethodInfo method) {
        if (origin instanceof ValueOrigin.Insn allocation
                && allocation.offset() >= 0 && allocation.offset() < method.instructions().size()) {
            InsnFact insn = method.insnAt(allocation.offset());
            if (insn.op() == Op.ANEWARRAY && insn.typeRef() != null) {
                return internalClassName(insn.typeRef().descriptor());
            }
        }
        if (origin instanceof ValueOrigin.FieldRead field) {
            String descriptor = fieldDescriptor(field);
            if (descriptor != null && descriptor.startsWith("[L") && descriptor.endsWith(";")) {
                return descriptor.substring(2, descriptor.length() - 1);
            }
        }
        return null;
    }

    private boolean collectionCallMayThrow(MethodInfo method, ForwardOrigins.Result result,
                                           int offset, String owner, String primary,
                                           String secondary) {
        InsnFact insn = method.instructions().get(offset);
        if (!insn.op().isInvoke() || insn.operands().isEmpty()
                || !(insn.operands().get(0) instanceof MethodRef ref)) {
            return true;
        }
        if (owner.equals(ref.owner())) {
            if (!primary.equals(ref.name()) && !secondary.equals(ref.name())) {
                return false;
            }
            return !isGuardedCollectionCall(method, result, offset, ref, primary, secondary);
        }
        if (isPlatformOwner(ref.owner())) {
            // A platform call with no matching thrower semantics cannot manufacture this
            // collection-specific exception. Application calls remain conservative below.
            return false;
        }
        return true;
    }

    private boolean isGuardedCollectionCall(MethodInfo method, ForwardOrigins.Result result,
                                            int throwerOffset, MethodRef thrower,
                                            String primary, String secondary) {
        for (int branchOffset = Math.max(1, throwerOffset - 4);
             branchOffset < throwerOffset; branchOffset++) {
            InsnFact branch = method.instructions().get(branchOffset);
            if (branch.op() != Op.IFNE && branch.op() != Op.IFEQ
                    || branchOffset + 1 >= throwerOffset) {
                continue;
            }
            InsnFact predicate = method.instructions().get(branchOffset - 1);
            if (!predicate.op().isInvoke() || predicate.operands().isEmpty()
                    || !(predicate.operands().get(0) instanceof MethodRef guard)) {
                continue;
            }
            boolean isEmptyGuard = "java/util/Stack".equals(guard.owner())
                    && "empty".equals(guard.name()) && "pop".equals(primary);
            boolean isIteratorGuard = "java/util/Iterator".equals(guard.owner())
                    && "hasNext".equals(guard.name()) && "next".equals(primary);
            if (!isEmptyGuard && !isIteratorGuard) {
                continue;
            }
            if (!sameReceiver(method, result, predicate, throwerOffset)) {
                continue;
            }
            // IFNE skips pop when empty()==true; IFEQ skips next when hasNext()==false.
            boolean expectedOpcode = isEmptyGuard ? branch.op() == Op.IFNE
                    : branch.op() == Op.IFEQ;
            if (expectedOpcode && branch.jumpTarget() > throwerOffset
                    && straightLineGuardPath(method, branchOffset, throwerOffset)) {
                return true;
            }
        }
        return false;
    }

    /**
     * The bytecode normally reloads the receiver (and possibly arguments) between the
     * conditional branch and the guarded invocation.  Require that this short path is the
     * branch's unique normal fall-through, with no nested control transfer or alternate edge.
     */
    private boolean straightLineGuardPath(MethodInfo method, int branchOffset,
                                          int throwerOffset) {
        int previous = branchOffset;
        for (int current = branchOffset + 1; current <= throwerOffset; current++) {
            if (current < throwerOffset && (method.instructions().get(current).op().isCondJump()
                    || method.instructions().get(current).op().isUncondJump()
                    || method.instructions().get(current).op().isSwitch()
                    || method.instructions().get(current).op().isReturn()
                    || method.instructions().get(current).op() == Op.ATHROW)) {
                return false;
            }
            if (!hasOnlyNormalPredecessor(method, current, previous)) {
                return false;
            }
            previous = current;
        }
        return true;
    }

    private boolean sameReceiver(MethodInfo method, ForwardOrigins.Result result,
                                 InsnFact guard, int throwerOffset) {
        ForwardOrigins.State guardState = result.stateBefore().get(guard.offset());
        ForwardOrigins.State throwerState = result.stateBefore().get(throwerOffset);
        Set<ValueOrigin> guardReceiver = receiverOrigins(guard, guardState);
        Set<ValueOrigin> throwerReceiver = receiverOrigins(method.insnAt(throwerOffset), throwerState);
        if (guardReceiver.isEmpty() || throwerReceiver.isEmpty()) {
            return false;
        }
        for (ValueOrigin origin : guardReceiver) {
            if (throwerReceiver.contains(origin)) {
                return true;
            }
        }
        return false;
    }

    private boolean hasOnlyNormalPredecessor(MethodInfo method, int target, int expected) {
        Cfg.Indexed cfg = cfg(method);
        for (int source = 0; source < method.instructions().size(); source++) {
            for (int edgeIndex = cfg.edgeStart(source); edgeIndex < cfg.edgeEnd(source); edgeIndex++) {
                if (cfg.targetAt(edgeIndex) == target && cfg.labelAt(edgeIndex) != CfgLabel.EXCEPTION
                        && source != expected) {
                    return false;
                }
            }
        }
        return true;
    }

    private Set<ValueOrigin> receiverOrigins(InsnFact insn, ForwardOrigins.State state) {
        if (state == null || state.stack().isEmpty()) {
            return Set.of();
        }
        int depth;
        if (insn.op() == Op.GETFIELD || insn.op() == Op.ARRAYLENGTH
                || insn.op() == Op.MONITORENTER || insn.op() == Op.MONITOREXIT) {
            depth = state.stack().size() - 1;
        } else if (insn.op() == Op.PUTFIELD) {
            depth = state.stack().size() - 2;
        } else if (insn.op().isInvoke()
                && insn.op() != Op.INVOKESTATIC && insn.op() != Op.INVOKEDYNAMIC) {
            depth = state.stack().size() - 1 - Descriptor.paramCount(insn.methodRef().descriptor());
        } else {
            return Set.of();
        }
        return depth >= 0 && depth < state.stack().size()
                ? state.stack().get(depth).origins() : Set.of();
    }

    private boolean arrayAccessMayThrow(MethodInfo method, ForwardOrigins.Result result,
                                        ForwardOrigins.State state, Op op) {
        int indexDepth = (op == Op.IASTORE || op == Op.LASTORE || op == Op.FASTORE
                || op == Op.DASTORE || op == Op.AASTORE || op == Op.BASTORE
                || op == Op.CASTORE || op == Op.SASTORE) ? 2 : 1;
        int arrayDepth = indexDepth + 1;
        if (state.stack().size() < arrayDepth) {
            return true;
        }
        Integer index = uniqueInteger(state.stack().get(state.stack().size() - indexDepth).origins(), method);
        if (index == null) {
            return true;
        }
        Set<ValueOrigin> arrays = state.stack().get(state.stack().size() - arrayDepth).origins();
        if (arrays.isEmpty()) {
            return true;
        }
        for (ValueOrigin array : arrays) {
            Integer length = arrayLength(array, method, result);
            if (length == null || index < 0 || index >= length) {
                return true;
            }
        }
        return false;
    }

    private boolean arrayAllocationMayThrow(MethodInfo method, ForwardOrigins.Result result,
                                            ForwardOrigins.State state, Op op,
                                            int allocationOffset) {
        if (state.stack().isEmpty()) {
            return true;
        }
        Integer size = uniqueInteger(state.stack().get(state.stack().size() - 1).origins(), method);
        if (size != null) {
            return size < 0;
        }
        if (op == Op.NEWARRAY || op == Op.ANEWARRAY) {
            Set<ValueOrigin> sizes = state.stack().get(state.stack().size() - 1).origins();
            for (ValueOrigin origin : sizes) {
                if (origin instanceof ValueOrigin.FieldRead field && !field.isStatic()
                        && definitelyNonNegativeField(method, result, field, allocationOffset)) {
                    continue;
                }
                return true;
            }
            return false;
        }
        return true;
    }

    private static boolean isPlatformOwner(String owner) {
        return owner != null && (owner.startsWith("java/") || owner.startsWith("javax/"));
    }

    private boolean definitelyNonNegativeField(MethodInfo method, ForwardOrigins.Result result,
                                               ValueOrigin.FieldRead field, int allocationOffset) {
        if (fieldDescriptor(field) == null) {
            return false;
        }
        for (int branchOffset = 0; branchOffset < allocationOffset; branchOffset++) {
            InsnFact branch = method.instructions().get(branchOffset);
            if (branch.op() != Op.IFGE || branch.operands().isEmpty()) {
                continue;
            }
            ForwardOrigins.State state = result.stateBefore().get(branchOffset);
            if (state == null || state.stack().isEmpty()
                    || !containsField(state.stack().get(state.stack().size() - 1).origins(), field)) {
                continue;
            }
            int target = branch.jumpTarget();
            if (target <= branchOffset || target > allocationOffset) {
                continue;
            }
            boolean normalized = false;
            for (int i = branchOffset + 1; i < target && i < method.instructions().size(); i++) {
                InsnFact candidate = method.instructions().get(i);
                if (candidate.op() == Op.PUTFIELD && sameField(candidate, field)
                        && multipliedByMinusOne(method, i, field)) {
                    normalized = true;
                    break;
                }
            }
            if (!normalized || hasFieldWrite(method, target, allocationOffset, field)) {
                continue;
            }
            return true;
        }
        return false;
    }

    private static boolean multipliedByMinusOne(MethodInfo method, int putOffset,
                                                 ValueOrigin.FieldRead field) {
        for (int i = Math.max(0, putOffset - 5); i < putOffset; i++) {
            InsnFact insn = method.instructions().get(i);
            if (insn.op() != Op.IMUL) {
                continue;
            }
            boolean sawMinusOne = false;
            boolean sawField = false;
            for (int j = i - 1; j >= Math.max(0, i - 5); j--) {
                InsnFact prior = method.instructions().get(j);
                if (prior.op() == Op.GETFIELD && sameField(prior, field)) {
                    sawField = true;
                }
                if (isMinusOne(prior)) {
                    sawMinusOne = true;
                }
            }
            if (sawMinusOne && sawField) {
                return true;
            }
        }
        return false;
    }

    private static boolean isMinusOne(InsnFact insn) {
        if (insn.op() == Op.ICONST_M1) {
            return true;
        }
        return (insn.op() == Op.BIPUSH || insn.op() == Op.SIPUSH)
                && !insn.operands().isEmpty() && insn.operands().get(0) instanceof Number n
                && n.intValue() == -1;
    }

    private static boolean hasFieldWrite(MethodInfo method, int start, int end,
                                         ValueOrigin.FieldRead field) {
        for (int i = Math.max(0, start); i < Math.min(end, method.instructions().size()); i++) {
            InsnFact insn = method.instructions().get(i);
            if (insn.op().isFieldWrite() && sameField(insn, field)) {
                return true;
            }
        }
        return false;
    }

    private static boolean containsField(Set<ValueOrigin> origins, ValueOrigin.FieldRead target) {
        for (ValueOrigin origin : origins) {
            if (origin instanceof ValueOrigin.FieldRead field && sameField(field, target)) {
                return true;
            }
        }
        return false;
    }

    private static boolean sameField(InsnFact insn, ValueOrigin.FieldRead field) {
        if (insn == null || insn.fieldRef() == null || field == null
                || !insn.fieldRef().owner().equals(field.owner())
                || !insn.fieldRef().name().equals(field.field())) {
            return false;
        }
        boolean staticField = insn.op() == Op.GETSTATIC || insn.op() == Op.PUTSTATIC;
        if (staticField != field.isStatic()) {
            return false;
        }
        return field.descriptor() == null || field.descriptor().isBlank()
                || insn.fieldRef().descriptor() == null
                || field.descriptor().equals(insn.fieldRef().descriptor());
    }

    private static boolean sameField(ValueOrigin.FieldRead left, ValueOrigin.FieldRead right) {
        return left.owner().equals(right.owner()) && left.field().equals(right.field())
                && left.isStatic() == right.isStatic()
                && (left.descriptor() == null || left.descriptor().isBlank()
                || right.descriptor() == null || right.descriptor().isBlank()
                || left.descriptor().equals(right.descriptor()));
    }

    private boolean nullReceiverMayThrow(MethodInfo method, ForwardOrigins.Result result,
                                         ForwardOrigins.State state, InsnFact insn) {
        if (insn.op() == Op.ATHROW) {
            return true;
        }
        Set<ValueOrigin> receivers = receiverOrigins(insn, state);
        if (receivers.isEmpty()) {
            return true;
        }
        for (ValueOrigin receiver : receivers) {
            if (!definitelyNonNull(receiver, method, result)) {
                return true;
            }
        }
        return false;
    }

    private boolean definitelyNonNull(ValueOrigin origin, MethodInfo method,
                                      ForwardOrigins.Result result) {
        if (isNullConstant(origin)) {
            return false;
        }
        if (origin instanceof ValueOrigin.Constant) {
            return true;
        }
        if (origin instanceof ValueOrigin.Insn allocation
                && allocation.offset() >= 0 && allocation.offset() < method.instructions().size()) {
            Op op = method.insnAt(allocation.offset()).op();
            return op == Op.NEW || op == Op.NEWARRAY || op == Op.ANEWARRAY
                    || op == Op.MULTIANEWARRAY;
        }
        if (origin instanceof ValueOrigin.CallResult call && call.callNodeId() >= 0) {
            Node node = callNodes.get(call.callNodeId());
            return node != null && "<init>".equals(node.strProp("name"));
        }
        if (origin instanceof ValueOrigin.FieldRead field && field.isStatic()) {
            return staticFieldDefinitelyNonNull(field);
        }
        return false;
    }

    private static boolean isNullConstant(ValueOrigin origin) {
        return origin instanceof ValueOrigin.Constant constant
                && (constant.value() == null || "ACONST_NULL".equals(constant.value()));
    }

    private Integer arrayLength(ValueOrigin origin, MethodInfo method, ForwardOrigins.Result result) {
        if (origin instanceof ValueOrigin.Insn allocation
                && allocation.offset() >= 0 && allocation.offset() < method.instructions().size()) {
            InsnFact insn = method.insnAt(allocation.offset());
            if (insn.op() == Op.NEWARRAY || insn.op() == Op.ANEWARRAY) {
                ForwardOrigins.State state = result.stateBefore().get(allocation.offset());
                return state == null || state.stack().isEmpty() ? null
                        : uniqueInteger(state.stack().get(state.stack().size() - 1).origins(), method);
            }
        }
        if (origin instanceof ValueOrigin.FieldRead field && field.isStatic()) {
            ClassInfo owner = hierarchy.classInfo(field.owner());
            MethodInfo clinit = owner == null ? null : owner.method("<clinit>", "()V");
            if (clinit == null) {
                return null;
            }
            ForwardOrigins.Result clinitResult = origins.compute(clinit);
            Set<ValueOrigin> writes = staticFieldWriteOrigins(field);
            Integer length = null;
            for (ValueOrigin value : writes) {
                Integer candidate = arrayLength(value, clinit, clinitResult);
                if (candidate == null || (length != null && !length.equals(candidate))) {
                    return null;
                }
                length = candidate;
            }
            return length;
        }
        if (origin instanceof ValueOrigin.CallResult callResult
                && callResult.callNodeId() >= 0) {
            Node call = callNodes.get(callResult.callNodeId());
            if (call != null && "java/lang/Class".equals(call.owner())) {
                String className = classLiteralName(argOriginAtOrdinal(call, -1, result));
                if (className != null) {
                    return reflectiveArrayLength(className, call.name());
                }
            }
        }
        return null;
    }

    /** Exact sizes for Class metadata arrays when the class model contains the target. */
    private Integer reflectiveArrayLength(String className, String methodName) {
        ClassInfo target = hierarchy.classInfo(className);
        if (target == null) {
            return null;
        }
        return switch (methodName) {
            case "getInterfaces" -> target.interfaces().size();
            case "getDeclaredFields" -> target.fields().size();
            case "getDeclaredMethods" -> (int) target.methods().stream()
                    .filter(m -> !"<init>".equals(m.name()) && !"<clinit>".equals(m.name()))
                    .count();
            case "getDeclaredConstructors" -> (int) target.methods().stream()
                    .filter(m -> "<init>".equals(m.name())).count();
            case "getConstructors" -> (int) target.methods().stream()
                    .filter(m -> "<init>".equals(m.name())
                            && java.lang.reflect.Modifier.isPublic(m.access())).count();
            case "getFields" -> publicFieldCount(className);
            case "getMethods" -> publicMethodCount(className);
            case "getClasses", "getDeclaredClasses" -> nestedClassCount(className);
            default -> null;
        };
    }

    private int nestedClassCount(String className) {
        int count = 0;
        String prefix = className + "$";
        Set<String> owners = new HashSet<>();
        for (Node node : graph.nodesOfType(NodeType.METHOD)) {
            String owner = node.strProp("owner");
            if (owner != null && owner.startsWith(prefix)) {
                owners.add(owner);
            }
        }
        for (String owner : owners) {
            ClassInfo nested = hierarchy.classInfo(owner);
            if (nested != null && java.lang.reflect.Modifier.isPublic(nested.access())) {
                count++;
            }
        }
        return count;
    }

    private int publicFieldCount(String className) {
        Set<String> signatures = new HashSet<>();
        Deque<String> work = new ArrayDeque<>();
        Set<String> seen = new HashSet<>();
        work.add(className);
        while (!work.isEmpty()) {
            String current = work.removeFirst();
            if (!seen.add(current)) {
                continue;
            }
            ClassInfo cls = hierarchy.classInfo(current);
            if (cls == null) {
                continue;
            }
            for (io.just.sast.model.FieldInfo field : cls.fields()) {
                if (java.lang.reflect.Modifier.isPublic(field.access())) {
                    signatures.add(field.name());
                }
            }
            if (cls.superName() != null) {
                work.addLast(cls.superName());
            }
            work.addAll(cls.interfaces());
        }
        return signatures.size();
    }

    private int publicMethodCount(String className) {
        Set<String> signatures = new HashSet<>();
        Deque<String> work = new ArrayDeque<>();
        Set<String> seen = new HashSet<>();
        work.add(className);
        while (!work.isEmpty()) {
            String current = work.removeFirst();
            if (!seen.add(current)) {
                continue;
            }
            ClassInfo cls = hierarchy.classInfo(current);
            if (cls == null) {
                continue;
            }
            for (MethodInfo method : cls.methods()) {
                if (java.lang.reflect.Modifier.isPublic(method.access())
                        && !"<init>".equals(method.name()) && !"<clinit>".equals(method.name())) {
                    signatures.add(method.name() + method.descriptor());
                }
            }
            if (cls.superName() != null) {
                work.addLast(cls.superName());
            }
            work.addAll(cls.interfaces());
        }
        return signatures.size();
    }

    private String fieldDescriptor(ValueOrigin.FieldRead field) {
        if (field.descriptor() != null && !field.descriptor().isBlank()) {
            return field.descriptor();
        }
        String declaring = hierarchy.resolveField(field.owner(), field.field());
        ClassInfo cls = hierarchy.classInfo(declaring == null ? field.owner() : declaring);
        io.just.sast.model.FieldInfo info = cls == null ? null : cls.field(field.field());
        return info == null ? null : info.descriptor();
    }

    private Integer staticFieldInteger(ValueOrigin.FieldRead field) {
        Integer terminal = terminalStaticFieldInteger(field);
        if (terminal != null) {
            return terminal;
        }
        Integer value = null;
        Set<ValueOrigin> writes = staticFieldWriteOrigins(field);
        for (ValueOrigin origin : writes) {
            Integer candidate = literalInteger(origin);
            if (candidate == null || (value != null && !value.equals(candidate))) {
                return null;
            }
            value = candidate;
        }
        if (writes.isEmpty()) {
            String declaring = hierarchy.resolveField(field.owner(), field.field());
            ClassInfo cls = hierarchy.classInfo(declaring == null ? field.owner() : declaring);
            io.just.sast.model.FieldInfo info = cls == null ? null : cls.field(field.field());
            if (info != null && info.constantValue() instanceof Number number) {
                return number.intValue();
            }
            if (info != null && info.constantValue() instanceof Boolean bool) {
                return bool ? 1 : 0;
            }
        }
        return value;
    }

    /**
     * Prefer a write that dominates every normal class-initializer exit.  Constant fields are
     * often assigned more than once (default value, then the real initializer); unioning all
     * writes would incorrectly turn the final value into "unknown".  A branch-specific final
     * write does not dominate all exits and therefore still falls back conservatively.
     */
    private Integer terminalStaticFieldInteger(ValueOrigin.FieldRead field) {
        ClassInfo owner = hierarchy.classInfo(field.owner());
        MethodInfo clinit = owner == null ? null : owner.method("<clinit>", "()V");
        if (clinit == null || clinit.instructions().size() > DOMINATOR_METHOD_LIMIT) {
            return null;
        }
        // Class initializers often have an exception table covering constants and
        // PUTSTATIC instructions. Those operations cannot throw the caught exception, so
        // exceptional CFG edges for them must not obscure a normal final write.
        DominatorIndex dominators = buildDominators(clinit, false);
        ForwardOrigins.Result result = origins.compute(clinit);
        List<Integer> exits = new ArrayList<>();
        for (InsnFact insn : clinit.instructions()) {
            if (insn.op().isReturn() && insn.op() != Op.ATHROW) {
                exits.add(insn.offset());
            }
        }
        if (exits.isEmpty()) {
            return null;
        }
        InsnFact selected = null;
        for (InsnFact write : clinit.instructions()) {
            if (write.op() != Op.PUTSTATIC || !sameField(write, field)) {
                continue;
            }
            boolean dominatesAll = true;
            for (Integer exit : exits) {
                if (!dominates(dominators, write.offset(), exit)) {
                    dominatesAll = false;
                    break;
                }
            }
            if (dominatesAll && (selected == null || write.offset() > selected.offset())) {
                selected = write;
            }
        }
        if (selected == null) {
            return null;
        }
        ForwardOrigins.State state = result.stateBefore().get(selected.offset());
        if (state == null || state.stack().isEmpty()) {
            return null;
        }
        return uniqueInteger(state.stack().get(state.stack().size() - 1).origins(), clinit);
    }

    private boolean staticFieldDefinitelyNonNull(ValueOrigin.FieldRead field) {
        Set<ValueOrigin> writes = staticFieldWriteOrigins(field);
        if (writes.isEmpty()) {
            return false;
        }
        for (ValueOrigin write : writes) {
            if (isNullConstant(write)) {
                return false;
            }
            if (write instanceof ValueOrigin.Insn allocation) {
                ClassInfo owner = hierarchy.classInfo(field.owner());
                MethodInfo clinit = owner == null ? null : owner.method("<clinit>", "()V");
                if (clinit == null || allocation.offset() < 0
                        || allocation.offset() >= clinit.instructions().size()) {
                    return false;
                }
                Op op = clinit.insnAt(allocation.offset()).op();
                if (op != Op.NEW && op != Op.NEWARRAY && op != Op.ANEWARRAY
                        && op != Op.MULTIANEWARRAY) {
                    return false;
                }
            } else if (!(write instanceof ValueOrigin.Constant)) {
                return false;
            }
        }
        return true;
    }

    private Set<ValueOrigin> staticFieldWriteOrigins(ValueOrigin.FieldRead field) {
        ClassInfo owner = hierarchy.classInfo(field.owner());
        MethodInfo clinit = owner == null ? null : owner.method("<clinit>", "()V");
        if (clinit == null) {
            return Set.of();
        }
        ForwardOrigins.Result result = origins.compute(clinit);
        Set<ValueOrigin> values = new HashSet<>();
        for (InsnFact insn : clinit.instructions()) {
            if (insn.op() != Op.PUTSTATIC || !sameField(insn, field)) {
                continue;
            }
            ForwardOrigins.State state = result.stateBefore().get(insn.offset());
            if (state == null || state.stack().isEmpty()) {
                return Set.of();
            }
            values.addAll(state.stack().get(state.stack().size() - 1).origins());
        }
        return orderedOrigins(values);
    }

    private static String internalClassName(String descriptor) {
        if (descriptor == null) {
            return null;
        }
        if (descriptor.startsWith("L") && descriptor.endsWith(";")) {
            return descriptor.substring(1, descriptor.length() - 1);
        }
        // ASM TypeInsnNode/ANEWARRAY carries an internal name, while LDC and
        // MultiANewArray use descriptors.  Accept both representations at the
        // model boundary; rejecting the raw internal name loses array-store proofs.
        if (descriptor.indexOf('/') >= 0 && !descriptor.startsWith("[")) {
            return descriptor;
        }
        return null;
    }

    /** 该调用是否可能抛出 caughtType（受检反射族）。 */
    private static boolean isThrowerOf(String caughtType, io.just.sast.model.MethodRef ref) {
        return switch (caughtType) {
            case "java/lang/ClassNotFoundException" ->
                    "java/lang/Class".equals(ref.owner()) && "forName".equals(ref.name());
            case "java/lang/NoSuchFieldException" ->
                    "java/lang/Class".equals(ref.owner())
                            && ("getDeclaredField".equals(ref.name()) || "getField".equals(ref.name()));
            case "java/lang/NoSuchMethodException" ->
                    "java/lang/Class".equals(ref.owner())
                            && ("getMethod".equals(ref.name()) || "getDeclaredMethod".equals(ref.name())
                                || "getConstructor".equals(ref.name())
                                || "getDeclaredConstructor".equals(ref.name()));
            case "java/lang/IllegalAccessException" ->
                    ("java/lang/reflect/Field".equals(ref.owner())
                            && ("set".equals(ref.name()) || "get".equals(ref.name())))
                    || ("java/lang/reflect/Method".equals(ref.owner()) && "invoke".equals(ref.name()));
            case "java/lang/InstantiationException" ->
                    ("java/lang/Class".equals(ref.owner()) && "newInstance".equals(ref.name()))
                    || ("java/lang/reflect/Constructor".equals(ref.owner())
                            && "newInstance".equals(ref.name()));
            default -> false;
        };
    }

    /** 受检反射查找必成功判定：常量类 + 常量名字且目标可解析。 */
    private boolean reflectiveLookupAlwaysSucceeds(MethodInfo method, io.just.sast.model.TryCatchFact tc,
                                                   io.just.sast.model.InsnFact insn,
                                                   io.just.sast.model.MethodRef ref) {
        String classConst = null;
        String nameConst = null;
        for (int w = Math.max(0, tc.start() - 8); w < insn.offset(); w++) {
            io.just.sast.model.InsnFact prev = method.instructions().get(w);
            if (prev.op() == io.just.sast.model.Op.LDC && !prev.operands().isEmpty()) {
                Object cst = prev.operands().get(0);
                if (cst instanceof io.just.sast.model.TypeRef t && classConst == null) {
                    classConst = t.descriptor().startsWith("L") && t.descriptor().endsWith(";")
                            ? t.descriptor().substring(1, t.descriptor().length() - 1)
                            : t.descriptor();
                } else if (cst instanceof String n && nameConst == null) {
                    nameConst = n;
                }
            }
        }
        String lookupName = nameConst != null ? nameConst : ""; // 无常量名无法证明必成功（空名不解析）
        var target = classConst != null ? hierarchy.classInfo(classConst) : null;
        boolean noSetAccessible = true;
        for (int i = tc.start(); i < tc.end() && i < method.instructions().size(); i++) {
            var fact = method.instructions().get(i);
            if (fact.op().isInvoke() && !fact.operands().isEmpty()
                    && fact.operands().get(0) instanceof io.just.sast.model.MethodRef mr
                    && mr.name().equals("setAccessible")) {
                noSetAccessible = false;
            }
        }
        return switch (tc.type()) {
            case "java/lang/ClassNotFoundException" ->
                    "forName".equals(ref.name()) && hierarchy.classInfo(lookupName.replace('.', '/')) != null;
            case "java/lang/NoSuchFieldException" -> target != null && target.field(lookupName) != null;
            case "java/lang/NoSuchMethodException" -> {
                // Class.getMethod/getDeclaredMethod resolve by name *and parameter
                // types*.  A name-only proof incorrectly removed the catch for
                // getMethod("doMethod", String.class) when only doMethod(int) existed.
                String parameterDescriptor = reflectiveParameterDescriptor(method, insn, ref);
                yield target != null && parameterDescriptor != null
                        && reflectiveMethodExists(classConst, lookupName, parameterDescriptor,
                        "getMethod".equals(ref.name()), "getMethod".equals(ref.name()));
            }
            case "java/lang/IllegalAccessException" -> {
                if (target == null || !noSetAccessible || target.isInterface()
                        || !java.lang.reflect.Modifier.isPublic(target.access())) {
                    yield false;
                }
                if ("java/lang/reflect/Field".equals(ref.owner())) {
                    var f = target.field(lookupName);
                    yield f != null && java.lang.reflect.Modifier.isPublic(f.access());
                }
                yield target.methods().stream().anyMatch(m -> m.name().equals(lookupName));
            }
            case "java/lang/InstantiationException" ->
                    target != null && !target.isInterface()
                            && !java.lang.reflect.Modifier.isAbstract(target.access());
            default -> false;
        };
    }

    /** Whether a sink offset belongs to this precise exception handler block. */
    private static boolean sinkInHandlerRegion(MethodInfo method,
                                               io.just.sast.model.TryCatchFact target,
                                               int sinkOffset) {
        int handler = target.handler();
        if (sinkOffset < handler || handler < 0 || handler >= method.instructions().size()) {
            return false;
        }
        int end = method.instructions().size();
        for (io.just.sast.model.TryCatchFact other : method.tryCatch()) {
            if (other.handler() > handler && other.handler() < end) {
                end = other.handler();
            }
        }
        for (int offset = handler; offset < end; offset++) {
            Op op = method.instructions().get(offset).op();
            if (offset > handler && (op == Op.GOTO || op.isReturn() || op == Op.ATHROW)) {
                end = offset;
                break;
            }
        }
        return sinkOffset < end;
    }

    /** Exact Class[] argument descriptor for a Class reflective lookup. */
    private String reflectiveParameterDescriptor(MethodInfo method,
                                                 io.just.sast.model.InsnFact insn,
                                                 io.just.sast.model.MethodRef ref) {
        if (!"java/lang/Class".equals(ref.owner())) {
            return null;
        }
        int ordinal;
        if ("getMethod".equals(ref.name()) || "getDeclaredMethod".equals(ref.name())) {
            ordinal = 1;
        } else if ("getConstructor".equals(ref.name()) || "getDeclaredConstructor".equals(ref.name())) {
            ordinal = 0;
        } else {
            return null;
        }
        Node call = graph.findCallNode(methodKey(method), insn.offset());
        if (call == null) {
            return null;
        }
        ForwardOrigins.Result result = origins.compute(method);
        Set<ValueOrigin> arrays = argOriginAtOrdinal(call, ordinal, result);
        for (ValueOrigin array : arrays) {
            Map<Integer, Set<ValueOrigin>> indexed = result.indexedArrayElements().get(array);
            if (indexed != null && !indexed.isEmpty()) {
                int max = indexed.keySet().stream().mapToInt(Integer::intValue).max().orElse(-1);
                StringBuilder descriptor = new StringBuilder("(");
                for (int index = 0; index <= max; index++) {
                    Set<ValueOrigin> values = indexed.get(index);
                    if (values == null || values.size() != 1) {
                        descriptor = null;
                        break;
                    }
                    String type = classDescriptor(values.iterator().next());
                    if (type == null) {
                        descriptor = null;
                        break;
                    }
                    descriptor.append(type);
                }
                if (descriptor != null) {
                    return descriptor.append(")V").toString();
                }
            }
            // new Class<?>[0] has no AASTORE entry.  Recover the zero-length
            // signature from the allocation's exact pre-state without guessing
            // non-zero lengths.
            if (array instanceof ValueOrigin.Insn allocation) {
                io.just.sast.model.InsnFact allocationInsn = method.insnAt(allocation.offset());
                if (allocationInsn.op() == Op.ANEWARRAY || allocationInsn.op() == Op.NEWARRAY) {
                    ForwardOrigins.State state = result.stateBefore().get(allocation.offset());
                    Integer length = state == null || state.stack().isEmpty() ? null
                            : constantInt(state.stack().get(state.stack().size() - 1).origins());
                    if (length != null && length == 0) {
                        return "()V";
                    }
                }
            }
        }
        return null;
    }

    /** Resolve a Method by parameter types, optionally including inherited public methods. */
    private boolean reflectiveMethodExists(String owner, String name, String parameterDescriptor,
                                           boolean includeInherited, boolean publicOnly) {
        if (owner == null || name == null || parameterDescriptor == null) {
            return false;
        }
        Deque<String> work = new ArrayDeque<>();
        Set<String> seen = new HashSet<>();
        work.add(owner);
        while (!work.isEmpty()) {
            String current = work.removeFirst();
            if (!seen.add(current)) {
                continue;
            }
            ClassInfo cls = hierarchy.classInfo(current);
            if (cls == null) {
                continue;
            }
            for (MethodInfo candidate : cls.methods()) {
                if (candidate.name().equals(name)
                        && parameterPrefix(candidate.descriptor()).equals(parameterPrefix(parameterDescriptor))
                        && (!publicOnly || java.lang.reflect.Modifier.isPublic(candidate.access()))) {
                    return true;
                }
            }
            if (!includeInherited) {
                break;
            }
            if (cls.superName() != null) {
                work.addLast(cls.superName());
            }
            work.addAll(hierarchy.transitiveInterfaces(current));
        }
        return false;
    }

    private static String parameterPrefix(String descriptor) {
        int close = descriptor == null ? -1 : descriptor.indexOf(')');
        return close < 0 ? "" : descriptor.substring(0, close + 1);
    }

    private static boolean sameParameters(String left, String right) {
        return parameterPrefix(left).equals(parameterPrefix(right));
    }

    private static String classDescriptor(ValueOrigin origin) {
        if (origin instanceof ValueOrigin.Constant constant
                && constant.value() instanceof io.just.sast.model.TypeRef type) {
            return type.descriptor();
        }
        if (origin instanceof ValueOrigin.FieldRead field && field.isStatic()
                && "TYPE".equals(field.field())) {
            return switch (field.owner()) {
                case "java/lang/Boolean" -> "Z";
                case "java/lang/Byte" -> "B";
                case "java/lang/Character" -> "C";
                case "java/lang/Short" -> "S";
                case "java/lang/Integer" -> "I";
                case "java/lang/Long" -> "J";
                case "java/lang/Float" -> "F";
                case "java/lang/Double" -> "D";
                case "java/lang/Void" -> "V";
                default -> null;
            };
        }
        return null;
    }

    private static Integer constantInt(Set<ValueOrigin> origins) {
        for (ValueOrigin origin : origins) {
            if (!(origin instanceof ValueOrigin.Constant constant)) {
                continue;
            }
            Object value = constant.value();
            if (value instanceof Number number) {
                return number.intValue();
            }
            if (value instanceof String opcode) {
                return switch (opcode) {
                    case "ICONST_M1" -> -1;
                    case "ICONST_0" -> 0;
                    case "ICONST_1" -> 1;
                    case "ICONST_2" -> 2;
                    case "ICONST_3" -> 3;
                    case "ICONST_4" -> 4;
                    case "ICONST_5" -> 5;
                    default -> null;
                };
            }
        }
        return null;
    }

    /** 值来源集合的声明类型（一致时返回，分歧返回 null）。 */
    private String declaredTypeOf(Set<ValueOrigin> origins, MethodInfo in) {
        String type = null;
        for (ValueOrigin origin : origins) {
            String t = null;
            if (origin instanceof ValueOrigin.FieldRead f && !f.isStatic()) {
                String declaring = hierarchy.resolveField(f.owner(), f.field());
                io.just.sast.model.ClassInfo cls = declaring != null
                        ? hierarchy.classInfo(declaring) : hierarchy.classInfo(f.owner());
                io.just.sast.model.FieldInfo field = cls != null ? cls.field(f.field()) : null;
                if (field != null && field.descriptor().startsWith("L")) {
                    t = field.descriptor().substring(1, field.descriptor().length() - 1);
                }
            } else if (origin instanceof ValueOrigin.Insn i) {
                var op = in.insnAt(i.offset());
                if (op.op() == io.just.sast.model.Op.NEW && !op.operands().isEmpty()
                        && op.typeRef().descriptor().startsWith("L") && op.typeRef().descriptor().endsWith(";")) {
                    t = op.typeRef().descriptor().substring(1, op.typeRef().descriptor().length() - 1);
                } else if (op.op() == io.just.sast.model.Op.NEW && !op.operands().isEmpty()) {
                    t = op.typeRef().descriptor();
                }
            } else if (origin instanceof ValueOrigin.CallResult cr && cr.callNodeId() >= 0) {
                Node callNode = callNodes.get(cr.callNodeId());
                if (callNode != null && "<init>".equals(callNode.strProp("name"))) {
                    t = callNode.strProp("owner"); // new X() 构造器结果 = X
                }
            } else if (origin instanceof ValueOrigin.Param p) {
                t = Descriptor.paramType(in.descriptor(),
                        Descriptor.paramOrdinal(in.descriptor(), in.isStatic(), p.slot()));
                if (t != null && t.startsWith("L") && t.endsWith(";")) {
                    t = t.substring(1, t.length() - 1);
                } else {
                    t = null;
                }
            }
            if (t == null) {
                return null;
            }
            if (type == null) {
                type = t;
            } else if (!type.equals(t)) {
                return null;
            }
        }
        return type;
    }

    private static final Set<String> UNIVERSAL_TYPES = Set.of(
            "java/lang/Object", "java/io/Serializable", "java/lang/Cloneable", "java/lang/Comparable",
            "java/io/Externalizable", "java/util/Collection", "java/util/Map", "java/util/List",
            "java/util/Set");

    /** 所有有 JavaBean 前缀方法（get 前缀或 is 前缀 公共非静态无参非 void）的 Serializable 类。 */
    private static boolean isUniversalType(String t) {
        return "java/lang/Object".equals(t) || "java/io/Serializable".equals(t)
                || "java/io/Externalizable".equals(t) || "java/lang/Cloneable".equals(t)
                || "java/lang/Comparable".equals(t);
    }

    private Set<String> computeSerializableWithGetters(Graph graph) {
        Set<String> result = new LinkedHashSet<>();
        Set<String> owners = new LinkedHashSet<>();
        for (Node m : graph.nodesOfType(NodeType.METHOD)) {
            owners.add(m.strProp("owner"));
        }
        for (String owner : orderedStrings(owners)) {
            if (!hierarchy.isSerializable(owner)) {
                continue;
            }
            var ci = hierarchy.classInfo(owner);
            if (ci == null) {
                continue;
            }
            for (var mi : ci.methods()) {
                String n = mi.name();
                if (java.lang.reflect.Modifier.isPublic(mi.access())
                        && !java.lang.reflect.Modifier.isStatic(mi.access())
                        && ((n.startsWith("get") && n.length() > 3) || (n.startsWith("is") && n.length() > 2))
                        && Descriptor.paramCount(mi.descriptor()) == 0
                        && !mi.descriptor().endsWith(")V")) {
                    result.add(owner);
                    break;
                }
            }
        }
        return orderedStrings(result);
    }

    private Set<String> computeOccupiable(Graph graph) {
        Set<String> types = new LinkedHashSet<>();
        Set<String> owners = new LinkedHashSet<>();
        for (Node m : graph.nodesOfType(NodeType.METHOD)) {
            owners.add(m.strProp("owner"));
        }
        for (String owner : orderedStrings(owners)) {
            var ci = hierarchy.classInfo(owner);
            if (ci == null || !hierarchy.isSerializable(owner)) {
                continue;
            }
            for (var f : ci.fields()) {
                if (java.lang.reflect.Modifier.isTransient(f.access())
                        || java.lang.reflect.Modifier.isStatic(f.access())) {
                    continue;
                }
                String d = f.descriptor();
                if (d.startsWith("L") && d.endsWith(";")) {
                    types.add(d.substring(1, d.length() - 1));
                } else if (d.startsWith("[L") && d.endsWith(";")) {
                    types.add(d.substring(2, d.length() - 1));
                }
            }
        }
        types.removeAll(UNIVERSAL_TYPES);
        return orderedStrings(types);
    }

    /** ObjectInputStream 读调用（反序列化数据源，无条件可控）。 */
    public static boolean isOisRead(Node call) {
        String owner = call.owner();
        String name = call.name();
        return "java/io/ObjectInputStream".equals(owner)
                && (name.equals("readObject") || name.equals("readUnshared") || name.equals("readFields"));
    }

    /** 指令按值消耗的栈条目数（cat-2 值亦为单条目，条目数 = 值数）。 */
    public static int consumedCount(Op op) {
        return switch (op) {
            case NEW -> 0;
            case INEG, LNEG, FNEG, DNEG, I2L, I2F, I2D, L2I, L2F, L2D,
                    F2I, F2L, F2D, D2I, D2L, D2F, I2B, I2C, I2S,
                    ARRAYLENGTH, CHECKCAST, INSTANCEOF -> 1;
            case IALOAD, LALOAD, FALOAD, DALOAD, AALOAD, BALOAD, CALOAD, SALOAD,
                    IADD, LADD, FADD, DADD, ISUB, LSUB, FSUB, DSUB,
                    IMUL, LMUL, FMUL, DMUL, IDIV, LDIV, FDIV, DDIV,
                    IREM, LREM, FREM, DREM, ISHL, LSHL, ISHR, LSHR, IUSHR, LUSHR,
                    IAND, LAND, IOR, LOR, IXOR, LXOR, LCMP, FCMPL, FCMPG, DCMPL, DCMPG -> 2;
            default -> 0;
        };
    }

    public static String methodKey(MethodInfo method) {
        return method.owner() + "#" + method.name() + method.descriptor();
    }

    /** CALL 节点所在方法的键。 */
    public static String methodKey(Node call) {
        return methodKeyOf(call.methodOwner(), call.methodName(), call.methodDescriptor());
    }

    public static String methodKeyOf(String owner, String name, String desc) {
        return owner + "#" + name + desc;
    }

    private static String fieldKey(InsnFact insn) {
        FieldRef ref = insn.fieldRef();
        boolean isStatic = insn.op() == Op.GETSTATIC || insn.op() == Op.PUTSTATIC;
        return ref.owner() + "#" + ref.name() + "#" + ref.descriptor() + "#" + isStatic;
    }
}
