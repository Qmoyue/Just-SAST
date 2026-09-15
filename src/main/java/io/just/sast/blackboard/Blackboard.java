package io.just.sast.blackboard;

import io.just.sast.analysis.hierarchy.ClassHierarchy;
import io.just.sast.analysis.entry.ApplicationEntryIndex;
import io.just.sast.analysis.taint.OriginSupport;
import io.just.sast.config.Rule;
import io.just.sast.config.RuleEngine;
import io.just.sast.config.RuleSet;
import io.just.sast.config.RuleSchemaV2;
import io.just.sast.cpg.build.FieldWriterIndex;
import io.just.sast.cpg.build.CpgIndex;
import io.just.sast.cpg.graph.Graph;
import io.just.sast.util.ChainMaterializer;

import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

/**
 * 黑板 = CPG 图 + 链产物 + 校准记录 + 链注释 + 事件队列。
 * 知识源通过本对象读写共享状态，互不直接调用。
 * 共享支撑（originSupport/ruleEngine）随黑板分发一次构建，全知识源复用。
 * 分析阶段允许知识源并行；跨阶段集合通过同步写入和 immutable snapshot 对外暴露。
 */
public final class Blackboard {

    /** Immutable counters for the typed solver-to-product admission boundary. */
    public record SolverAdmissionMetrics(long input, long applicationChains,
                                         long bridgeContinuations, long dependencySuffixes,
                                         long kernelOnly, long rejected,
                                         Map<String, Long> rejectedReasons) {
        public SolverAdmissionMetrics {
            input = Math.max(0L, input);
            applicationChains = Math.max(0L, applicationChains);
            bridgeContinuations = Math.max(0L, bridgeContinuations);
            dependencySuffixes = Math.max(0L, dependencySuffixes);
            kernelOnly = Math.max(0L, kernelOnly);
            rejected = Math.max(0L, rejected);
            Map<String, Long> sorted = new java.util.TreeMap<>();
            if (rejectedReasons != null) {
                rejectedReasons.forEach((reason, count) -> {
                    if (reason != null && !reason.isBlank() && count != null && count > 0L) {
                        sorted.put(reason, count);
                    }
                });
            }
            rejectedReasons = java.util.Collections.unmodifiableMap(sorted);
        }
    }

    /**
     * Typed result of one solver-candidate admission.  The chain is exposed only when the
     * candidate was accepted into one of the owned stores; rejected or duplicate candidates
     * never leak a materialized product back to the producer.
     */
    public record SolverAdmissionResult(boolean accepted, Chain chain) {
        public SolverAdmissionResult {
            if (accepted != (chain != null)) {
                throw new IllegalArgumentException("accepted admission must carry exactly one chain");
            }
        }
    }

    /**
     * Endpoint-only dependency suffix retained until a composition consumer requests its path.
     * The candidate is immutable; the supplier is memoized so a later report/compatibility
     * snapshot cannot rebuild the same suffix more than once.
     */
    public record DeferredDependencySuffix(ApplicationEntryIndex.ProducerCandidate candidate,
                                           Supplier<Chain> materializer) {
        public DeferredDependencySuffix {
            candidate = java.util.Objects.requireNonNull(candidate, "candidate");
            materializer = ChainMaterializer.memoize(
                    java.util.Objects.requireNonNull(materializer, "materializer"));
        }
    }

    /**
     * Typed composition inputs exposed by their owning stores.  Known application scopes can
     * consume the application and dependency/bridge frontiers independently instead of first
     * constructing one global union and filtering it in the composer.  {@link #all()} keeps the
     * historical compatibility view for kernel/legacy consumers and preserves key ordering and
     * first-store precedence.
     */
    public record CompositionInputs(List<Chain> applicationChains,
                                    List<Chain> bridgeContinuations,
                                    List<Chain> dependencySuffixes,
                                    List<DeferredDependencySuffix> deferredDependencySuffixes,
                                    Map<String, List<DeferredDependencySuffix>> deferredByEntryKind,
                                    Map<String, List<DeferredDependencySuffix>> deferredByTerminal) {
        /** Compatibility constructor for consumers that only expose materialized stores. */
        public CompositionInputs(List<Chain> applicationChains,
                                 List<Chain> bridgeContinuations,
                                 List<Chain> dependencySuffixes) {
            this(applicationChains, bridgeContinuations, dependencySuffixes, List.of(),
                    Map.of(), Map.of());
        }

        /** Compatibility constructor retaining the lazy deferred endpoint list. */
        public CompositionInputs(List<Chain> applicationChains,
                                 List<Chain> bridgeContinuations,
                                 List<Chain> dependencySuffixes,
                                 List<DeferredDependencySuffix> deferredDependencySuffixes) {
            this(applicationChains, bridgeContinuations, dependencySuffixes,
                    deferredDependencySuffixes, Map.of(), Map.of());
        }

        public CompositionInputs {
            applicationChains = immutableChains(applicationChains);
            bridgeContinuations = immutableChains(bridgeContinuations);
            dependencySuffixes = immutableChains(dependencySuffixes);
            if (deferredDependencySuffixes == null || deferredDependencySuffixes.isEmpty()) {
                deferredDependencySuffixes = List.of();
            } else {
                deferredDependencySuffixes = List.copyOf(deferredDependencySuffixes.stream()
                        .filter(java.util.Objects::nonNull).toList());
            }
            deferredByEntryKind = immutableDeferredIndex(deferredDependencySuffixes,
                    deferred -> deferred.candidate().entryKind());
            deferredByTerminal = immutableDeferredIndex(deferredDependencySuffixes,
                    deferred -> deferredTerminalKey(deferred.candidate()));
        }

        private static List<Chain> immutableChains(List<Chain> chains) {
            if (chains == null || chains.isEmpty()) {
                return List.of();
            }
            return List.copyOf(chains.stream().filter(java.util.Objects::nonNull).toList());
        }

        private static Map<String, List<DeferredDependencySuffix>> immutableDeferredIndex(
                List<DeferredDependencySuffix> deferred,
                java.util.function.Function<DeferredDependencySuffix, String> keyFunction) {
            Map<String, List<DeferredDependencySuffix>> grouped = new java.util.TreeMap<>();
            if (deferred != null && keyFunction != null) {
                for (DeferredDependencySuffix candidate : deferred) {
                    if (candidate == null) {
                        continue;
                    }
                    String key = keyFunction.apply(candidate);
                    if (key == null || key.isBlank()) {
                        continue;
                    }
                    grouped.computeIfAbsent(key, ignored -> new ArrayList<>()).add(candidate);
                }
            }
            Map<String, List<DeferredDependencySuffix>> immutable = new java.util.TreeMap<>();
            grouped.forEach((key, values) -> immutable.put(key, List.copyOf(values)));
            return java.util.Collections.unmodifiableMap(immutable);
        }

        private static String deferredTerminalKey(ApplicationEntryIndex.ProducerCandidate candidate) {
            if (candidate == null) {
                return "";
            }
            return deferredTerminalKey(candidate.terminalOwner(), candidate.terminalName(),
                    candidate.terminalDescriptor());
        }

        private static String deferredTerminalKey(String owner, String name, String descriptor) {
            String normalizedOwner = owner == null ? "" : owner;
            String normalizedName = name == null ? "" : name;
            String normalizedDescriptor = descriptor == null ? "" : descriptor;
            if (normalizedOwner.isBlank() || normalizedName.isBlank()) {
                return "";
            }
            return normalizedOwner + "\u0000" + normalizedName + "\u0000"
                    + normalizedDescriptor;
        }

        /** O(1) typed lookup for deferred suffixes by callback/mechanism entry kind. */
        public List<DeferredDependencySuffix> deferredDependencySuffixesForEntryKind(
                String entryKind) {
            if (entryKind == null || entryKind.isBlank()) {
                return List.of();
            }
            return deferredByEntryKind.getOrDefault(entryKind, List.of());
        }

        /** O(1) typed lookup for deferred suffixes by exact terminal identity. */
        public List<DeferredDependencySuffix> deferredDependencySuffixesForTerminal(
                String owner, String name, String descriptor) {
            String key = deferredTerminalKey(owner, name, descriptor);
            return key.isBlank() ? List.of() : deferredByTerminal.getOrDefault(key, List.of());
        }

        /**
         * Explicit compatibility union that may materialize deferred suffix payloads.
         *
         * <p>This name is intentionally verbose: demand-driven application composition must
         * use the typed owner/index accessors above and must never call a broad union merely to
         * filter it later.  The projection remains available only for kernel/legacy consumers
         * whose contract explicitly requests a materialized compatibility view.</p>
         */
        public List<Chain> compatibilityAll() {
            Map<String, Chain> unique = new java.util.TreeMap<>();
            applicationChains.forEach(chain -> unique.putIfAbsent(chain.key(), chain));
            bridgeContinuations.forEach(chain -> unique.putIfAbsent(chain.key(), chain));
            dependencySuffixes.forEach(chain -> unique.putIfAbsent(chain.key(), chain));
            deferredDependencySuffixes.forEach(deferred -> {
                addDeferredChain(unique, deferred);
            });
            return List.copyOf(unique.values());
        }

        /** Explicit compatibility continuation projection; may materialize deferred suffixes. */
        public List<Chain> compatibilityContinuationChains() {
            Map<String, Chain> unique = new java.util.TreeMap<>();
            bridgeContinuations.forEach(chain -> unique.putIfAbsent(chain.key(), chain));
            dependencySuffixes.forEach(chain -> unique.putIfAbsent(chain.key(), chain));
            deferredDependencySuffixes.forEach(deferred -> {
                addDeferredChain(unique, deferred);
            });
            return List.copyOf(unique.values());
        }

        /**
         * @deprecated use {@link #compatibilityAll()} so a deferred materialization boundary is
         * explicit at each call site.
         */
        @Deprecated
        public List<Chain> all() {
            return compatibilityAll();
        }

        /**
         * @deprecated use {@link #compatibilityContinuationChains()} so a deferred
         * materialization boundary is explicit at each call site.
         */
        @Deprecated
        public List<Chain> continuationChains() {
            return compatibilityContinuationChains();
        }

        /** A compatibility projection cannot turn a producer failure into a scan failure. */
        private static void addDeferredChain(Map<String, Chain> unique,
                                             DeferredDependencySuffix deferred) {
            if (deferred == null) {
                return;
            }
            try {
                Chain chain = deferred.materializer().get();
                if (chain != null && deferred.candidate().matches(chain)) {
                    unique.putIfAbsent(chain.key(), chain);
                }
            } catch (RuntimeException ignored) {
                // The typed admission owner records materialization failures at its boundary;
                // legacy union readers remain fail-closed and simply omit the unavailable path.
            }
        }
    }

    /** 扫描输入（管线编排期注入；知识源经黑板读取，无全局属性通道）。 */
    public record ScanInputs(Path target, List<Path> deps, boolean fast,
                             Path jdkHome, int targetMajorVersion,
                             io.just.sast.run.InputBudget.Tracker inputTracker,
                             Set<String> applicationClassNames,
                             boolean applicationScopeKnown) {
        public ScanInputs {
            // Compatibility callers do not have a pipeline-owned tracker.  Give them an
            // explicit bounded capability rather than allowing an optional consumer to create
            // an unbounded/default tracker behind the blackboard.  The production pipeline
            // passes its caller-owned tracker here, so priority/index reads charge the same
            // aggregate input budget as the scan-boundary identity work.
            inputTracker = inputTracker == null
                    ? io.just.sast.run.InputBudget.defaults().tracker() : inputTracker;
            applicationClassNames = applicationClassNames == null
                    ? Set.of() : java.util.Collections.unmodifiableSet(
                            new java.util.TreeSet<>(applicationClassNames.stream()
                                    .filter(java.util.Objects::nonNull)
                                    .filter(value -> !value.isBlank())
                                    .map(String::trim).toList()));
        }

        public ScanInputs(Path target, List<Path> deps, boolean fast) {
            this(target, deps, fast, null, 0, null, Set.of(), false);
        }

        public ScanInputs(Path target, List<Path> deps, boolean fast,
                          Path jdkHome, int targetMajorVersion) {
            this(target, deps, fast, jdkHome, targetMajorVersion, null, Set.of(), false);
        }

        public static ScanInputs fastDefault(Path target) {
            return new ScanInputs(target, List.of(), true);
        }
    }

    private final Graph graph;
    private final ClassHierarchy hierarchy;
    private final FieldWriterIndex fieldWriters;
    private final CpgIndex cpgIndex;
    private final RuleSet rules;
    private final int maxDepth;
    private final ScanInputs scanInputs;
    /** 共享分析支撑：调用点索引 + 方法解析缓存 + origin 分析缓存 + 入口下游闭包。 */
    private final OriginSupport originSupport;
    /** Immutable P3.1 execution-entry/site/terminal index used for demand-driven admission. */
    private final ApplicationEntryIndex applicationEntryIndex;
    /** 共享规则匹配引擎（随 RuleSet 一次构建，缓存随黑板生命周期）。 */
    private final RuleEngine ruleEngine;

    /** Single owner for chain identity, merge, calibration and note state. */
    private final ChainStore chainStore = new ChainStore();
    /** Solver-only bridge participants are composition inputs, not default findings. */
    private final ChainStore bridgeChainStore = new ChainStore();
    /** Dependency/JDK terminal suffixes are expanded only when an application front requests them. */
    private final ChainStore dependencySuffixStore = new ChainStore();
    /** Endpoint-only dependency suffixes waiting for a typed composition demand. */
    private final List<DeferredDependencySuffix> deferredDependencySuffixes = new ArrayList<>();
    /** Unknown application scope is an explicit kernel result, never a default finding. */
    private final ChainStore kernelChainStore = new ChainStore();
    /**
     * Application-owned callback candidates rejected from the default product but retained for
     * calibration-only audit (for example an equals sink with no proven deserialize trigger).
     * This store is deliberately excluded from composition and downstream projections.
     */
    private final ChainStore calibrationCandidateStore = new ChainStore();
    private long solverAdmissionInput;
    private long solverApplicationChains;
    private long solverBridgeContinuations;
    private long solverDependencySuffixes;
    private long solverKernelOnly;
    private long solverRejected;
    private final Map<String, Long> solverRejectedReasons = new java.util.TreeMap<>();
    /** sink 裁决（backward-taint 并行分析写）：CALL 节点 id → 裁决，报告层产出 sinks.csv。 */
    private final Map<Long, SinkOutcome> sinkOutcomes = new java.util.concurrent.ConcurrentHashMap<>();
    /** 链校准（CALIBRATION 写）：链 key → 拒绝理由；报告层过滤被拒绝的链。 */
    /** 链级注释和校准由 chainStore 持有，避免 Blackboard 维护平行 key map。 */
    /** Versioned, typed extension facts; each snapshot is immutable and isolated by class. */
    private final Map<Class<?>, List<BlackboardFact>> facts = new java.util.HashMap<>();
    /** Publication log preserves cross-type ordering for consumers that need deterministic replay. */
    private final List<BlackboardFact> factLog = new ArrayList<>();
    private long factRevision;
    /** Typed run-product registry; chain products are append-only contributions. */
    private final Map<RunProduct, Set<String>> productProducers = new EnumMap<>(RunProduct.class);
    /** 扫描完整性边界：分析器触顶/跳过的稳定原因码，供统计与报告层消费。 */
    private final Set<String> completenessReasons = ConcurrentHashMap.newKeySet();
    /** Controller phase timings are immutable snapshots at the report boundary. */
    private final Map<String, Long> phaseTimings = new ConcurrentHashMap<>();
    private final Deque<Event> queue = new ArrayDeque<>();

    public Blackboard(Graph graph, ClassHierarchy hierarchy, FieldWriterIndex fieldWriters,
                      RuleSet rules, int maxDepth, ScanInputs scanInputs) {
        this(graph, hierarchy, fieldWriters, CpgIndex.empty(), rules, maxDepth, scanInputs);
    }

    public Blackboard(Graph graph, ClassHierarchy hierarchy, FieldWriterIndex fieldWriters,
                      CpgIndex cpgIndex, RuleSet rules, int maxDepth, ScanInputs scanInputs) {
        this.graph = graph;
        this.hierarchy = hierarchy;
        this.fieldWriters = fieldWriters;
        this.cpgIndex = cpgIndex == null ? CpgIndex.empty() : cpgIndex;
        this.rules = rules == null ? RuleSet.EMPTY : rules;
        this.maxDepth = maxDepth;
        this.scanInputs = scanInputs == null
                ? ScanInputs.fastDefault(Path.of(".")) : scanInputs;
        this.ruleEngine = new RuleEngine(this.rules, hierarchy);
        this.applicationEntryIndex = ApplicationEntryIndex.build(graph, ruleEngine,
                this.scanInputs.applicationClassNames(), this.scanInputs.applicationScopeKnown());
        this.originSupport = new OriginSupport(graph, hierarchy, ruleEngine, this.scanInputs.fast(),
                this.cpgIndex, this.scanInputs.applicationClassNames(),
                this.scanInputs.applicationScopeKnown(),
                this.applicationEntryIndex.applicationEntryMethods());
    }

    public Graph graph() {
        return graph;
    }

    public ClassHierarchy hierarchy() {
        return hierarchy;
    }

    public FieldWriterIndex fieldWriters() {
        return fieldWriters;
    }

    public CpgIndex cpgIndex() {
        return cpgIndex;
    }

    public RuleSet rules() {
        return rules;
    }

    public RuleEngine ruleEngine() {
        return ruleEngine;
    }

    public int maxDepth() {
        return maxDepth;
    }

    public ScanInputs scanInputs() {
        return scanInputs;
    }

    public OriginSupport originSupport() {
        return originSupport;
    }

    public ApplicationEntryIndex applicationEntryIndex() {
        return applicationEntryIndex;
    }

    // ---- 链产物 ----

    /** 记录链；按 key 去重（backward 的 per-sink 并行可能并发调用，方法级同步）。返回是否为新链。 */
    public synchronized boolean addChain(Chain chain) {
        ChainStore.AddResult result = chainStore.add(chain);
        if (result.publishFoundEvent()) {
            publish(Event.of(EventType.CHAIN_FOUND, -1, chain));
        }
        return result.accepted();
    }

    /**
     * Publish a solver candidate through a lazy materialization boundary.  Admission consumes
     * only the immutable endpoint descriptor; the supplier is invoked only for an admitted
     * destination (or for an explicitly retained calibration candidate).  A supplier result
     * must match the descriptor, otherwise the candidate is rejected closed and no store sees
     * it.
     */
    public synchronized boolean addSolverCandidate(
            ApplicationEntryIndex.ProducerCandidate candidate,
            Supplier<Chain> materializer) {
        if (candidate != null && materializer != null
                && applicationEntryIndex.applicationScopeKnown()) {
            ApplicationEntryIndex.ProducerAdmissionDecision decision =
                    applicationEntryIndex.producerAdmission(candidate);
            if (decision.materializationPolicy()
                    == ApplicationEntryIndex.MaterializationPolicy.DEFERRED_SUFFIX) {
                // Keep the endpoint in the solver-owned deferred frontier.  The path supplier
                // is not invoked until composition asks for a suffix that can actually be
                // attached to an application front; direct admitSolverCandidate callers retain
                // the historical eager/result-returning contract.
                solverAdmissionInput++;
                deferredDependencySuffixes.add(
                        new DeferredDependencySuffix(candidate, materializer));
                return true;
            }
        }
        return admitSolverCandidate(candidate, materializer).accepted();
    }

    /**
     * Admit the explicitly retained unknown-scope composition compatibility path.  This is
     * deliberately separate from {@link #admitSolverCandidate}: unknown application scope
     * routes solver output to the kernel store, while the legacy composer contract keeps its
     * bounded, already-typed product in the default composition store for kernel/compatibility
     * callers.  It is not a solver admission and therefore does not alter solver metrics.
     */
    public synchronized SolverAdmissionResult admitCompatibilityCandidate(
            ApplicationEntryIndex.ProducerCandidate candidate,
            Supplier<Chain> materializer) {
        if (candidate == null || materializer == null
                || applicationEntryIndex.applicationScopeKnown()) {
            return new SolverAdmissionResult(false, null);
        }
        try {
            Chain chain = materializer.get();
            if (chain == null || !candidate.matches(chain)) {
                return new SolverAdmissionResult(false, null);
            }
            boolean accepted = addChain(chain);
            return new SolverAdmissionResult(accepted, accepted ? chain : null);
        } catch (RuntimeException ignored) {
            return new SolverAdmissionResult(false, null);
        }
    }

    /**
     * Admit a lazy solver candidate and return the accepted product to the producer.  Keeping
     * the result at the same owner as the routing decision avoids producer-side holders and
     * follow-up scans of the chain stores merely to recover the product that was just admitted.
     */
    public synchronized SolverAdmissionResult admitSolverCandidate(
            ApplicationEntryIndex.ProducerCandidate candidate,
            Supplier<Chain> materializer) {
        if (candidate == null) {
            return new SolverAdmissionResult(false, null);
        }
        ApplicationEntryIndex.ProducerAdmissionDecision decision =
                applicationEntryIndex.producerAdmission(candidate);
        solverAdmissionInput++;
        return switch (decision.materializationPolicy()) {
            case EAGER_APPLICATION -> {
                Chain chain = materializeCandidate(candidate, materializer);
                if (chain == null) {
                    yield new SolverAdmissionResult(false, null);
                }
                boolean accepted = addChain(chain);
                if (accepted) solverApplicationChains++;
                yield new SolverAdmissionResult(accepted, accepted ? chain : null);
            }
            case EAGER_BRIDGE -> {
                Chain chain = materializeCandidate(candidate, materializer);
                if (chain == null) {
                    yield new SolverAdmissionResult(false, null);
                }
                boolean accepted = bridgeChainStore.add(chain).accepted();
                if (accepted) solverBridgeContinuations++;
                yield new SolverAdmissionResult(accepted, accepted ? chain : null);
            }
            case DEFERRED_SUFFIX -> {
                // This direct API is the bounded compatibility boundary: unlike
                // addSolverCandidate, it historically returns a materialized suffix to callers.
                // The producer policy still identifies the endpoint as deferred for the normal
                // solver path; only this explicit compatibility call flushes it now.
                Chain chain = materializeCandidate(candidate, materializer);
                if (chain == null) {
                    yield new SolverAdmissionResult(false, null);
                }
                boolean accepted = dependencySuffixStore.add(chain).accepted();
                if (accepted) solverDependencySuffixes++;
                yield new SolverAdmissionResult(accepted, accepted ? chain : null);
            }
            case EAGER_KERNEL -> {
                Chain chain = materializeCandidate(candidate, materializer);
                if (chain == null) {
                    yield new SolverAdmissionResult(false, null);
                }
                boolean accepted = kernelChainStore.add(chain).accepted();
                if (accepted) solverKernelOnly++;
                yield new SolverAdmissionResult(accepted, accepted ? chain : null);
            }
            case REJECTED -> {
                if (isCalibrationCandidate(candidate)) {
                    Chain chain = materializeCandidate(candidate, materializer);
                    if (chain != null) {
                        calibrationCandidateStore.add(chain);
                    }
                }
                solverRejected++;
                solverRejectedReasons.merge(decision.reasonCode(), 1L, Long::sum);
                yield new SolverAdmissionResult(false, null);
            }
        };
    }

    private Chain materializeCandidate(ApplicationEntryIndex.ProducerCandidate candidate,
                                       Supplier<Chain> materializer) {
        if (materializer == null) {
            recordMaterializationFailure("MATERIALIZATION_MISSING");
            return null;
        }
        try {
            Chain chain = materializer.get();
            if (!candidate.matches(chain)) {
                recordMaterializationFailure("MATERIALIZED_CANDIDATE_MISMATCH");
                return null;
            }
            return chain;
        } catch (RuntimeException failure) {
            recordMaterializationFailure("MATERIALIZATION_FAILED");
            return null;
        }
    }

    private void recordMaterializationFailure(String reason) {
        solverRejected++;
        solverRejectedReasons.merge(reason, 1L, Long::sum);
    }

    /**
     * Materialize one deferred dependency suffix only after the caller supplies the exact
     * immutable admission decision it used for the demand filter.  Recomputing and comparing
     * the decision here prevents a stale or untyped consumer from flushing an endpoint merely
     * because it knows the deferred wrapper.
     */
    public synchronized SolverAdmissionResult materializeDeferredDependencySuffix(
            DeferredDependencySuffix deferred,
            ApplicationEntryIndex.ProducerAdmissionDecision decision) {
        if (deferred == null || decision == null
                || applicationEntryIndex == null
                || decision.materializationPolicy()
                != ApplicationEntryIndex.MaterializationPolicy.DEFERRED_SUFFIX) {
            recordMaterializationFailure("DEFERRED_DEMAND_DECISION_REQUIRED");
            return new SolverAdmissionResult(false, null);
        }
        ApplicationEntryIndex.ProducerAdmissionDecision current =
                applicationEntryIndex.producerAdmission(deferred.candidate());
        if (!current.equals(decision)) {
            recordMaterializationFailure("DEFERRED_DEMAND_DECISION_MISMATCH");
            return new SolverAdmissionResult(false, null);
        }
        return materializeDeferredDependencySuffixInternal(deferred);
    }

    /**
     * Legacy untyped entry point retained only as a fail-closed source-compatibility seam.
     * Production consumers must pass the typed demand decision above; compatibility snapshots
     * use the private internal helper so they remain an explicitly labelled projection.
     */
    @Deprecated
    public synchronized SolverAdmissionResult materializeDeferredDependencySuffix(
            DeferredDependencySuffix deferred) {
        if (deferred != null) {
            recordMaterializationFailure("DEFERRED_DEMAND_DECISION_REQUIRED");
        }
        return new SolverAdmissionResult(false, null);
    }

    private SolverAdmissionResult materializeDeferredDependencySuffixInternal(
            DeferredDependencySuffix deferred) {
        if (deferred == null || !deferredDependencySuffixes.remove(deferred)) {
            return new SolverAdmissionResult(false, null);
        }
        Chain chain = materializeCandidate(deferred.candidate(), deferred.materializer());
        if (chain == null) {
            return new SolverAdmissionResult(false, null);
        }
        boolean accepted = dependencySuffixStore.add(chain).accepted();
        if (accepted) {
            solverDependencySuffixes++;
        }
        return new SolverAdmissionResult(accepted, accepted ? chain : null);
    }

    /** Flush the compatibility/report view without exposing deferred suppliers to consumers. */
    private void materializeDeferredDependencySuffixes() {
        if (deferredDependencySuffixes.isEmpty()) {
            return;
        }
        for (DeferredDependencySuffix deferred : List.copyOf(deferredDependencySuffixes)) {
            // This method is the explicit compatibility/report projection.  It intentionally
            // bypasses the production demand API but still routes through the single internal
            // materialization owner so no supplier is duplicated or lost.
            materializeDeferredDependencySuffixInternal(deferred);
        }
    }

    /**
     * Explicit compatibility/report snapshot of the three composition owners.  This method
     * flushes deferred suffix suppliers by design; demand-driven application composition must
     * use {@link #compositionInputsLazy()} and typed index lookups instead.
     */
    public synchronized CompositionInputs compatibilityCompositionInputs() {
        materializeDeferredDependencySuffixes();
        return new CompositionInputs(chainStore.snapshot(), bridgeChainStore.snapshot(),
                dependencySuffixStore.snapshot());
    }

    /**
     * @deprecated use {@link #compatibilityCompositionInputs()} when a materialized
     * compatibility/report projection is explicitly intended.
     */
    @Deprecated
    public synchronized CompositionInputs compositionInputs() {
        return compatibilityCompositionInputs();
    }

    /**
     * Demand-driven composition snapshot.  Unlike the compatibility/report view, this keeps
     * dependency suffix endpoints deferred so the composer can inspect typed metadata before
     * requesting a path payload.
     */
    public synchronized CompositionInputs compositionInputsLazy() {
        return new CompositionInputs(chainStore.snapshot(), bridgeChainStore.snapshot(),
                dependencySuffixStore.snapshot(), List.copyOf(deferredDependencySuffixes));
    }

    public List<Chain> bridgeChains() {
        return bridgeChainStore.snapshot();
    }

    /** Explicit compatibility projection of all admitted dependency suffix payloads. */
    public synchronized List<Chain> compatibilityDependencySuffixChains() {
        materializeDeferredDependencySuffixes();
        return dependencySuffixStore.snapshot();
    }

    /**
     * @deprecated use {@link #compatibilityDependencySuffixChains()} so deferred materialization
     * is explicit at the call site.
     */
    @Deprecated
    public synchronized List<Chain> dependencySuffixChains() {
        return compatibilityDependencySuffixChains();
    }

    public List<Chain> kernelOnlyChains() {
        return kernelChainStore.snapshot();
    }

    /** Candidates retained solely so CALIBRATION can explain a rejected callback path. */
    public List<Chain> calibrationCandidates() {
        return calibrationCandidateStore.snapshot();
    }

    /** Default product plus component-kernel and calibration candidates for the report boundary. */
    public synchronized List<Chain> reportChains() {
        Map<String, Chain> unique = new java.util.TreeMap<>();
        chainStore.snapshot().forEach(chain -> unique.putIfAbsent(chain.key(), chain));
        if (applicationEntryIndex == null || !applicationEntryIndex.applicationScopeKnown()) {
            kernelChainStore.snapshot().forEach(chain -> unique.putIfAbsent(chain.key(), chain));
        }
        calibrationCandidateStore.snapshot().forEach(chain -> unique.putIfAbsent(chain.key(), chain));
        return List.copyOf(unique.values());
    }

    public synchronized SolverAdmissionMetrics solverAdmissionMetrics() {
        return new SolverAdmissionMetrics(solverAdmissionInput, solverApplicationChains,
                solverBridgeContinuations, solverDependencySuffixes, solverKernelOnly,
                solverRejected, solverRejectedReasons);
    }

    private boolean hasTypedBridgeRule(Chain chain) {
        if (chain == null) {
            return false;
        }
        Rule.SinkRule sink = ruleEngine.matchingSink(chain.sinkClass(), chain.sinkMethod(),
                chain.sinkDescriptor()).orElse(null);
        return sink != null && !RuleSchemaV2.isTerminalSink(sink)
                && !RuleSchemaV2.bridgesFor(sink).isEmpty();
    }

    public List<Chain> chains() {
        return chainStore.snapshot();
    }

    /**
     * Freeze the insertion-order race from parallel analysis before a later phase consumes
     * chains.  Analysis workers may discover equivalent paths in different orders, while
     * composition/calibration have finite caps and therefore need one stable input order.
     */
    void sortChainsForPhase() {
        chainStore.sortForPhase();
        bridgeChainStore.sortForPhase();
        dependencySuffixStore.sortForPhase();
        kernelChainStore.sortForPhase();
        calibrationCandidateStore.sortForPhase();
    }

    // ---- sink 裁决 ----

    public void recordOutcome(long callNodeId, SinkOutcome outcome) {
        if (outcome != null) {
            sinkOutcomes.put(callNodeId, outcome);
        }
    }

    public Map<Long, SinkOutcome> sinkOutcomes() {
        return java.util.Collections.unmodifiableMap(new java.util.TreeMap<>(sinkOutcomes));
    }

    // ---- 校准与注释 ----

    public void calibrateChain(String chainKey, String reason) {
        chainStore.calibrate(chainKey, reason);
        calibrationCandidateStore.calibrate(chainKey, reason);
        kernelChainStore.calibrate(chainKey, reason);
    }

    public String calibrationOf(String chainKey) {
        String reason = chainStore.calibrationOf(chainKey);
        if (reason != null) {
            return reason;
        }
        reason = calibrationCandidateStore.calibrationOf(chainKey);
        return reason != null ? reason : kernelChainStore.calibrationOf(chainKey);
    }

    public synchronized Map<String, String> chainCalibrations() {
        Map<String, String> result = new java.util.TreeMap<>(calibrationCandidateStore.calibrations());
        chainStore.calibrations().forEach(result::putIfAbsent);
        kernelChainStore.calibrations().forEach(result::putIfAbsent);
        return java.util.Collections.unmodifiableMap(result);
    }

    public synchronized int calibrationCount() {
        return chainCalibrations().size();
    }

    /** 记录一次可能导致结果欠完备的分析边界；同一原因只保留一次。 */
    public void markIncomplete(String reason) {
        if (reason != null && !reason.isBlank()) {
            completenessReasons.add(reason);
        }
    }

    public Set<String> completenessReasons() {
        if (originSupport == null || originSupport.completenessReasons().isEmpty()) {
            return sortedSet(completenessReasons);
        }
        Set<String> result = new HashSet<>(completenessReasons);
        result.addAll(originSupport.completenessReasons());
        return sortedSet(result);
    }

    /** Record a non-negative controller phase duration without exposing mutable state. */
    public void recordPhaseMs(String phase, long durationMs) {
        if (phase != null && !phase.isBlank()) {
            phaseTimings.put(phase, Math.max(0L, durationMs));
        }
    }

    public Map<String, Long> phaseMs() {
        return java.util.Collections.unmodifiableMap(new java.util.TreeMap<>(phaseTimings));
    }

    /** 链级注释（gadget 模式标注等），附着到具体链 key。 */
    public void chainNote(String chainKey, String note) {
        chainStore.note(chainKey, note);
        calibrationCandidateStore.note(chainKey, note);
        kernelChainStore.note(chainKey, note);
    }

    public List<String> chainNotesOf(String chainKey) {
        List<String> notes = chainStore.notesOf(chainKey);
        if (!notes.isEmpty()) {
            return notes;
        }
        notes = calibrationCandidateStore.notesOf(chainKey);
        return notes.isEmpty() ? kernelChainStore.notesOf(chainKey) : notes;
    }

    private boolean isCalibrationCandidate(ApplicationEntryIndex.ProducerCandidate candidate) {
        if (candidate == null || !applicationEntryIndex.isApplicationOwner(candidate.entryOwner())) {
            return false;
        }
        String kind = candidate.entryKind();
        return switch (kind == null ? "" : kind) {
            case "hashCode", "equals", "compareTo", "compare", "toString" -> true;
            default -> false;
        };
    }

    private static Set<String> sortedSet(Set<String> values) {
        java.util.TreeSet<String> sorted = new java.util.TreeSet<>();
        if (values != null) {
            values.stream().filter(value -> value != null && !value.isBlank()).forEach(sorted::add);
        }
        return java.util.Collections.unmodifiableSet(sorted);
    }

    // ---- typed immutable extension facts ----

    /**
     * Publish an immutable record fact.  A plugin may publish its own record type without
     * coupling to another knowledge source; readers request a typed immutable snapshot.
     */
    public synchronized void publishFact(BlackboardFact fact) {
        if (fact == null) {
            return;
        }
        if (!fact.getClass().isRecord()) {
            throw new IllegalArgumentException("blackboard facts must be immutable records: "
                    + fact.getClass().getName());
        }
        publishFactLocked(fact);
    }

    /** Return all facts assignable to the requested type in publication order. */
    public synchronized <T extends BlackboardFact> List<T> facts(Class<T> type) {
        if (type == null) {
            return List.of();
        }
        List<T> result = new ArrayList<>();
        for (BlackboardFact value : factLog) {
            if (type.isInstance(value)) {
                result.add(type.cast(value));
            }
        }
        return List.copyOf(result);
    }

    /** Monotonic publication revision for downstream memoization keys. */
    public synchronized long factRevision() {
        return factRevision;
    }

    // ---- typed run products ----

    /**
     * Publish one product contribution.  The method is the only mutable product registry
     * boundary; callers cannot replace a singleton product or mutate the returned snapshots.
     */
    public synchronized void publishProduct(RunProduct product, String producerId, Phase phase) {
        RunProductPublication publication = new RunProductPublication(product, producerId, phase);
        Set<String> producers = productProducers.computeIfAbsent(product,
                ignored -> new java.util.TreeSet<>());
        if (producers.contains(publication.producerId())) {
            return; // one receipt per producer keeps repeated event delivery idempotent
        }
        if (!product.appendOnly() && !producers.isEmpty()
                && !producers.contains(publication.producerId())) {
            throw new IllegalStateException("duplicate singleton product producer: "
                    + product.name());
        }
        producers.add(publication.producerId());
        publishFactLocked(publication);
    }

    /** Whether a product is available in this run, including initial products. */
    public synchronized boolean hasProduct(RunProduct product) {
        return product != null && (product.initiallyAvailable()
                || !productProducers.getOrDefault(product, Set.of()).isEmpty());
    }

    /** Stable set of all products available at the current phase barrier. */
    public synchronized Set<RunProduct> availableProducts() {
        EnumSet<RunProduct> result = EnumSet.noneOf(RunProduct.class);
        for (RunProduct product : RunProduct.values()) {
            if (hasProduct(product)) result.add(product);
        }
        return java.util.Collections.unmodifiableSet(result);
    }

    /** Product-to-producer snapshot for reports and phase diagnostics. */
    public synchronized Map<RunProduct, Set<String>> productProducers() {
        Map<RunProduct, Set<String>> result = new EnumMap<>(RunProduct.class);
        productProducers.forEach((product, producers) ->
                result.put(product, java.util.Collections.unmodifiableSet(new java.util.TreeSet<>(producers))));
        return java.util.Collections.unmodifiableMap(result);
    }

    private void publishFactLocked(BlackboardFact fact) {
        facts.computeIfAbsent(fact.getClass(), ignored -> new ArrayList<>(1)).add(fact);
        factLog.add(fact);
        factRevision++;
    }

    // ---- 事件 ----

    public synchronized void publish(Event event) {
        queue.addLast(event);
    }

    synchronized Event poll() {
        return queue.pollFirst();
    }

    synchronized boolean hasEvents() {
        return !queue.isEmpty();
    }

    synchronized void clearEvents() {
        queue.clear();
    }
}
