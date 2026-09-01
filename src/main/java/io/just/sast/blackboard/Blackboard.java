package io.just.sast.blackboard;

import io.just.sast.analysis.hierarchy.ClassHierarchy;
import io.just.sast.analysis.taint.OriginSupport;
import io.just.sast.config.RuleEngine;
import io.just.sast.config.RuleSet;
import io.just.sast.cpg.build.FieldWriterIndex;
import io.just.sast.cpg.build.CpgIndex;
import io.just.sast.cpg.graph.Graph;

import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 黑板 = CPG 图 + 链产物 + 校准记录 + 链注释 + 事件队列。
 * 知识源通过本对象读写共享状态，互不直接调用。
 * 共享支撑（originSupport/ruleEngine）随黑板分发一次构建，全知识源复用。
 * 分析阶段允许知识源并行；跨阶段集合通过同步写入和 immutable snapshot 对外暴露。
 */
public final class Blackboard {

    /** 扫描输入（管线编排期注入；知识源经黑板读取，无全局属性通道）。 */
    public record ScanInputs(Path target, List<Path> deps, boolean fast, boolean verify,
                             int verifyBudget, Path jdkHome, int targetMajorVersion,
                             boolean safeExec, boolean safeReal,
                             boolean requireStrictIsolation) {
        public ScanInputs(Path target, List<Path> deps, boolean fast, boolean verify,
                          int verifyBudget) {
            this(target, deps, fast, verify, verifyBudget, null, 0, false, false, false);
        }

        public ScanInputs(Path target, List<Path> deps, boolean fast, boolean verify,
                          int verifyBudget, Path jdkHome) {
            this(target, deps, fast, verify, verifyBudget, jdkHome, 0, false, false, false);
        }

        public ScanInputs(Path target, List<Path> deps, boolean fast, boolean verify,
                          int verifyBudget, Path jdkHome, int targetMajorVersion) {
            this(target, deps, fast, verify, verifyBudget, jdkHome, targetMajorVersion,
                    false, false, false);
        }

        public ScanInputs(Path target, List<Path> deps, boolean fast, boolean verify,
                          int verifyBudget, Path jdkHome, int targetMajorVersion,
                          boolean safeExec) {
            this(target, deps, fast, verify, verifyBudget, jdkHome, targetMajorVersion,
                    safeExec, false, false);
        }

        /** Compatibility constructor retained for callers before SAFE_REAL was added. */
        public ScanInputs(Path target, List<Path> deps, boolean fast, boolean verify,
                          int verifyBudget, Path jdkHome, int targetMajorVersion,
                          boolean safeExec, boolean requireStrictIsolation) {
            this(target, deps, fast, verify, verifyBudget, jdkHome, targetMajorVersion,
                    safeExec, false, requireStrictIsolation);
        }

        public static ScanInputs fastDefault(Path target) {
            return new ScanInputs(target, List.of(), true, true, 20, null, 0,
                    false, false, false);
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
    /** 共享规则匹配引擎（随 RuleSet 一次构建，缓存随黑板生命周期）。 */
    private final RuleEngine ruleEngine;

    /** Single owner for chain identity, merge, calibration and note state. */
    private final ChainStore chainStore = new ChainStore();
    /** sink 裁决（backward-taint 并行分析写）：CALL 节点 id → 裁决，报告层产出 sinks.csv。 */
    private final Map<Long, SinkOutcome> sinkOutcomes = new java.util.concurrent.ConcurrentHashMap<>();
    /** 链校准（CALIBRATION 写）：链 key → 拒绝理由；报告层过滤被拒绝的链。 */
    /** 链级注释和校准由 chainStore 持有，避免 Blackboard 维护平行 key map。 */
    /** Versioned, typed extension facts; each snapshot is immutable and isolated by class. */
    private final Map<Class<?>, List<BlackboardFact>> facts = new java.util.HashMap<>();
    /** Publication log preserves cross-type ordering for consumers that need deterministic replay. */
    private final List<BlackboardFact> factLog = new ArrayList<>();
    private long factRevision;
    /** 扫描完整性边界：分析器触顶/跳过的稳定原因码，供统计与报告层消费。 */
    private final Set<String> completenessReasons = ConcurrentHashMap.newKeySet();
    /** Controller phase timings are immutable snapshots at the report boundary. */
    private final Map<String, Long> phaseTimings = new ConcurrentHashMap<>();
    /** 动态验证能力的实际状态；不把“请求了验证”冒充成“子 JVM 已安全启动”。 */
    private volatile String verificationStatus = "NOT_RUN";
    /** 动态验证正式产物；报告层不得从 stderr 重新推断验证结果。 */
    private volatile VerificationSummary verificationSummary = VerificationSummary.empty("NOT_RUN", 0);
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
        this.originSupport = new OriginSupport(graph, hierarchy, ruleEngine, this.scanInputs.fast(),
                this.cpgIndex);
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

    // ---- 链产物 ----

    /** 记录链；按 key 去重（backward 的 per-sink 并行可能并发调用，方法级同步）。返回是否为新链。 */
    public synchronized boolean addChain(Chain chain) {
        ChainStore.AddResult result = chainStore.add(chain);
        if (result.publishFoundEvent()) {
            publish(Event.of(EventType.CHAIN_FOUND, -1, chain));
        }
        return result.accepted();
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
    }

    public String calibrationOf(String chainKey) {
        return chainStore.calibrationOf(chainKey);
    }

    public Map<String, String> chainCalibrations() {
        return chainStore.calibrations();
    }

    public int calibrationCount() {
        return chainStore.calibrationCount();
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

    public void setVerificationStatus(String status) {
        verificationStatus = status == null || status.isBlank() ? "UNKNOWN" : status;
    }

    public String verificationStatus() {
        return verificationStatus;
    }

    public void setVerificationSummary(VerificationSummary summary) {
        verificationSummary = summary == null
                ? VerificationSummary.empty(verificationStatus, scanInputs.verifyBudget()) : summary;
        verificationStatus = verificationSummary.capability();
    }

    public VerificationSummary verificationSummary() {
        return verificationSummary;
    }

    /** 链级注释（gadget 模式标注等），附着到具体链 key。 */
    public void chainNote(String chainKey, String note) {
        chainStore.note(chainKey, note);
    }

    public List<String> chainNotesOf(String chainKey) {
        return chainStore.notesOf(chainKey);
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
        facts.computeIfAbsent(fact.getClass(), ignored -> new ArrayList<>(1)).add(fact);
        factLog.add(fact);
        factRevision++;
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
