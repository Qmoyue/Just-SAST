package io.just.sast.blackboard;

import io.just.sast.analysis.hierarchy.ClassHierarchy;
import io.just.sast.analysis.taint.OriginSupport;
import io.just.sast.config.RuleEngine;
import io.just.sast.config.RuleSet;
import io.just.sast.cpg.build.FieldWriterIndex;
import io.just.sast.cpg.graph.Graph;

import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 黑板 = CPG 图 + 链产物 + 校准记录 + 链注释 + 事件队列。
 * 知识源通过本对象读写共享状态，互不直接调用。
 * 共享支撑（originSupport/ruleEngine）随黑板分发一次构建，全知识源复用。
 * 单线程契约：控制器串行调度，本类不加锁。
 */
public final class Blackboard {

    /** 扫描输入（管线编排期注入；知识源经黑板读取，无全局属性通道）。 */
    public record ScanInputs(Path target, List<Path> deps, boolean fast, boolean verify) {
        public static ScanInputs fastDefault(Path target) {
            return new ScanInputs(target, List.of(), true, true);
        }
    }

    private final Graph graph;
    private final ClassHierarchy hierarchy;
    private final FieldWriterIndex fieldWriters;
    private final RuleSet rules;
    private final int maxDepth;
    private final ScanInputs scanInputs;
    /** 共享分析支撑：调用点索引 + 方法解析缓存 + origin 分析缓存 + 入口下游闭包。 */
    private final OriginSupport originSupport;
    /** 共享规则匹配引擎（随 RuleSet 一次构建，缓存随黑板生命周期）。 */
    private final RuleEngine ruleEngine;

    private final List<Chain> chains = new ArrayList<>();
    private final Set<String> chainKeys = new HashSet<>();
    /** sink 裁决（backward-taint 并行分析写）：CALL 节点 id → 裁决，报告层产出 sinks.csv。 */
    private final Map<Long, SinkOutcome> sinkOutcomes = new java.util.concurrent.ConcurrentHashMap<>();
    /** 链校准（CALIBRATION 写）：链 key → 拒绝理由；报告层过滤被拒绝的链。 */
    private final Map<String, String> chainCalibrations = new HashMap<>();
    /** 链级注释（按链 key 归属，如 gadget 模式标注），报告层输出。 */
    private final Map<String, List<String>> chainNotes = new HashMap<>();
    private final Deque<Event> queue = new ArrayDeque<>();

    public Blackboard(Graph graph, ClassHierarchy hierarchy, FieldWriterIndex fieldWriters,
                      RuleSet rules, int maxDepth, ScanInputs scanInputs) {
        this.graph = graph;
        this.hierarchy = hierarchy;
        this.fieldWriters = fieldWriters;
        this.rules = rules;
        this.maxDepth = maxDepth;
        this.scanInputs = scanInputs;
        this.ruleEngine = new RuleEngine(rules, hierarchy);
        this.originSupport = new OriginSupport(graph, hierarchy, ruleEngine, scanInputs.fast());
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
        if (chainKeys.add(chain.key())) {
            chains.add(chain);
            publish(Event.of(EventType.CHAIN_FOUND, -1, chain));
            return true;
        }
        return false;
    }

    public List<Chain> chains() {
        return chains;
    }

    // ---- sink 裁决 ----

    public void recordOutcome(long callNodeId, SinkOutcome outcome) {
        sinkOutcomes.put(callNodeId, outcome);
    }

    public Map<Long, SinkOutcome> sinkOutcomes() {
        return sinkOutcomes;
    }

    // ---- 校准与注释 ----

    public void calibrateChain(String chainKey, String reason) {
        chainCalibrations.put(chainKey, reason);
    }

    public String calibrationOf(String chainKey) {
        return chainCalibrations.get(chainKey);
    }

    public Map<String, String> chainCalibrations() {
        return chainCalibrations;
    }

    public int calibrationCount() {
        return chainCalibrations.size();
    }

    /** 链级注释（gadget 模式标注等），附着到具体链 key。 */
    public void chainNote(String chainKey, String note) {
        chainNotes.computeIfAbsent(chainKey, k -> new ArrayList<>(1)).add(note);
    }

    public List<String> chainNotesOf(String chainKey) {
        List<String> list = chainNotes.get(chainKey);
        return list != null ? list : List.of();
    }

    // ---- 事件 ----

    public synchronized void publish(Event event) {
        queue.addLast(event);
    }

    Event poll() {
        return queue.pollFirst();
    }

    boolean hasEvents() {
        return !queue.isEmpty();
    }

    void clearEvents() {
        queue.clear();
    }
}
