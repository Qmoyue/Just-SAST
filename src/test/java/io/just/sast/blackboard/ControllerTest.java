package io.just.sast.blackboard;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

/** 调度器契约：阶段边界、priority 同阶段排序、异常隔离。 */
class ControllerTest {

    /** 记录调用序的探针知识源。 */
    private static final class Probe implements KnowledgeSource {
        final String id;
        final Phase phase;
        final int priority;
        final List<String> log;
        final Runnable body;

        Probe(String id, Phase phase, int priority, List<String> log, Runnable body) {
            this.id = id;
            this.phase = phase;
            this.priority = priority;
            this.log = log;
            this.body = body;
        }

        @Override public String id() { return id; }
        @Override public Set<EventType> interests() { return Set.of(EventType.SCAN_START, EventType.SCAN_ANALYZED, EventType.SCAN_COMPLETE); }
        @Override public Phase phase() { return phase; }
        @Override public int priority() { return priority; }
        @Override public void init(Blackboard blackboard) { }
        @Override public void onEvent(Blackboard blackboard, Event event) {
            body.run();
            log.add(id + ":" + phase + ":" + event.type());
        }
    }

    @Test
    void phasesRunInOrderAndPrioritySortsWithinPhase() {
        List<String> log = new ArrayList<>();
        // 注册顺序故意与 priority 相反：CALIBRATION 内 pruner(200) 必须先于 validator(100)? 不——小者先
        List<KnowledgeSource> sources = List.of(
                new Probe("pruner", Phase.CALIBRATION, 200, log, () -> { }),
                new Probe("validator", Phase.CALIBRATION, 100, log, () -> { }),
                new Probe("composer", Phase.COMPOSITION, 200, log, () -> { }),
                new Probe("object-graph", Phase.COMPOSITION, 100, log, () -> { }),
                new Probe("backward", Phase.ANALYSIS, 100, log, () -> { }));
        new Controller(new Blackboard(new io.just.sast.cpg.graph.Graph(),
                new io.just.sast.analysis.hierarchy.ClassHierarchy(java.util.Map.of(), null),
                new io.just.sast.cpg.build.FieldWriterIndex(), io.just.sast.config.RuleSet.EMPTY, 20, Blackboard.ScanInputs.fastDefault(Path.of("."))), sources).run();
        // 阶段边界与 priority 排序：完整顺序应为
        // backward(A) → object-graph(C,100) → composer(C,200) → validator(L,100) → pruner(L,200)
        assertEquals(List.of("backward:ANALYSIS", "object-graph:COMPOSITION", "composer:COMPOSITION",
                "validator:CALIBRATION", "pruner:CALIBRATION"),
                log.stream().map(e -> e.substring(0, e.lastIndexOf(':'))).toList());
    }

    @Test
    void ksFailureIsIsolatedIncludingError() {
        List<String> log = new ArrayList<>();
        List<KnowledgeSource> sources = List.of(
                new Probe("boom", Phase.ANALYSIS, 100, log, () -> { throw new OutOfMemoryError("simulated"); }),
                new Probe("after", Phase.ANALYSIS, 200, log, () -> { }));
        new Controller(new Blackboard(new io.just.sast.cpg.graph.Graph(),
                new io.just.sast.analysis.hierarchy.ClassHierarchy(java.util.Map.of(), null),
                new io.just.sast.cpg.build.FieldWriterIndex(), io.just.sast.config.RuleSet.EMPTY, 20, Blackboard.ScanInputs.fastDefault(Path.of("."))), sources).run();
        assertEquals(1, log.stream().filter(e -> e.startsWith("after:")).count(),
                "Error 级异常隔离，同阶段后续知识源照常执行");
    }

    @Test
    void chainFoundEventsDeliverToLaterPhaseSubscribers() {
        // ANALYSIS 期产出 CHAIN_FOUND（addChain），CALIBRATION 订阅者收到——事件机制跨阶段真实可用
        java.util.List<String> received = new ArrayList<>();
        final Blackboard[] holder = new Blackboard[1];
        KnowledgeSource producer = new KnowledgeSource() {
            @Override public String id() { return "producer"; }
            @Override public java.util.Set<EventType> interests() { return java.util.Set.of(EventType.SCAN_START); }
            @Override public Phase phase() { return Phase.ANALYSIS; }
            @Override public void init(Blackboard bb) { holder[0] = bb; }
            @Override public void onEvent(Blackboard bb, Event event) {
                bb.addChain(new io.just.sast.blackboard.Chain("T", "C", "HIGH", "a/A", "m", "readObject",
                        "s/S", "x", java.util.List.of(), 0));
            }
        };
        KnowledgeSource consumer = new Probe("consumer", Phase.CALIBRATION, 100, new ArrayList<>(), () -> { });
        // consumer 订阅 CHAIN_FOUND：通过自定义 interests 的 Probe 不可行——直接匿名类
        KnowledgeSource chainConsumer = new KnowledgeSource() {
            @Override public String id() { return "chain-consumer"; }
            @Override public java.util.Set<EventType> interests() { return java.util.Set.of(EventType.CHAIN_FOUND); }
            @Override public Phase phase() { return Phase.CALIBRATION; }
            @Override public void init(Blackboard bb) { }
            @Override public void onEvent(Blackboard bb, Event event) {
                if (event.type() == EventType.CHAIN_FOUND) {
                    received.add("chain");
                }
            }
        };
        new Controller(new Blackboard(new io.just.sast.cpg.graph.Graph(),
                new io.just.sast.analysis.hierarchy.ClassHierarchy(java.util.Map.of(), null),
                new io.just.sast.cpg.build.FieldWriterIndex(), io.just.sast.config.RuleSet.EMPTY, 20,
                Blackboard.ScanInputs.fastDefault(java.nio.file.Path.of("."))),
                java.util.List.of(producer, chainConsumer)).run();
        assertFalse(received.isEmpty(), "CALIBRATION 订阅者应收到 ANALYSIS 期的 CHAIN_FOUND");
    }
}

