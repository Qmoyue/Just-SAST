package io.just.sast.blackboard;

import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Contract tests for explicit phase/product dependencies and fail-closed startup validation. */
class PhaseGraphContractTest {

    @Test
    void productDependenciesResolveIndependentOfRegistrationOrder() {
        List<KnowledgeSource> sources = List.of(
                source("calibration", Phase.CALIBRATION, 100,
                        Set.of(RunProduct.COMPOSED_CHAINS), Set.of(RunProduct.CALIBRATED_CHAINS)),
                source("composition", Phase.COMPOSITION, 100,
                        Set.of(RunProduct.ANALYSIS_CHAINS), Set.of(RunProduct.COMPOSED_CHAINS)),
                source("analysis", Phase.ANALYSIS, 100,
                        Set.of(RunProduct.PROGRAM_MODEL), Set.of(RunProduct.ANALYSIS_CHAINS)));

        PhaseGraph graph = PhaseGraph.from(sources);
        PhaseGraph.Validation validation = graph.validate();

        assertTrue(validation.valid(), validation.errors().toString());
        assertEquals(List.of("analysis", "composition", "calibration"),
                graph.nodes().stream().map(PhaseGraph.Node::sourceId).toList());
        assertEquals(graph.digest(), PhaseGraph.from(List.of(sources.get(2), sources.get(1),
                sources.get(0))).digest());
    }

    @Test
    void missingProductIsRejectedBeforeAnySourceInitializes() {
        AtomicBoolean initialized = new AtomicBoolean();
        KnowledgeSource broken = source("broken", Phase.COMPOSITION, 100,
                Set.of(RunProduct.ANALYSIS_CHAINS), Set.of(RunProduct.COMPOSED_CHAINS),
                initialized);
        Blackboard bb = empty();

        new Controller(bb, List.of(broken)).run();

        assertFalse(initialized.get());
        assertTrue(bb.completenessReasons().stream()
                .anyMatch(reason -> reason.startsWith("PHASE_GRAPH_INVALID:")),
                bb.completenessReasons().toString());
    }

    @Test
    void samePhasePriorityCannotSatisfyADeclaredDependency() {
        PhaseGraph graph = PhaseGraph.from(List.of(
                source("consumer", Phase.COMPOSITION, 100,
                        Set.of(RunProduct.ANALYSIS_CHAINS), Set.of(RunProduct.COMPOSED_CHAINS)),
                source("producer", Phase.COMPOSITION, 100,
                        Set.of(RunProduct.PROGRAM_MODEL), Set.of(RunProduct.ANALYSIS_CHAINS))));

        PhaseGraph.Validation validation = graph.validate();

        assertFalse(validation.valid());
        assertTrue(validation.errors().stream()
                .anyMatch(error -> error.contains("PRODUCT_ORDER_UNDECLARED")),
                validation.errors().toString());
    }

    @Test
    void equalPriorityRemainsInvalidEvenWhenProducerSortsFirstById() {
        PhaseGraph graph = PhaseGraph.from(List.of(
                source("a-producer", Phase.COMPOSITION, 100,
                        Set.of(RunProduct.PROGRAM_MODEL), Set.of(RunProduct.ANALYSIS_CHAINS)),
                source("z-consumer", Phase.COMPOSITION, 100,
                        Set.of(RunProduct.ANALYSIS_CHAINS), Set.of(RunProduct.COMPOSED_CHAINS))));

        PhaseGraph.Validation validation = graph.validate();

        assertFalse(validation.valid());
        assertTrue(validation.errors().stream()
                .anyMatch(error -> error.contains("PRODUCT_ORDER_UNDECLARED")),
                validation.errors().toString());
    }

    @Test
    void analysisCannotDeclareAConcurrentSamePhaseProductDependency() {
        PhaseGraph graph = PhaseGraph.from(List.of(
                source("producer", Phase.ANALYSIS, 100,
                        Set.of(RunProduct.PROGRAM_MODEL), Set.of(RunProduct.ANALYSIS_CHAINS)),
                source("consumer", Phase.ANALYSIS, 200,
                        Set.of(RunProduct.ANALYSIS_CHAINS), Set.of(RunProduct.COMPOSED_CHAINS))));

        PhaseGraph.Validation validation = graph.validate();

        assertFalse(validation.valid());
        assertTrue(validation.errors().stream()
                .anyMatch(error -> error.contains("PARALLEL_PRODUCT_DEPENDENCY")),
                validation.errors().toString());
    }

    @Test
    void builtInKnowledgeSourcesHaveAValidTypedGraph() {
        PhaseGraph graph = PhaseGraph.from(io.just.sast.cli.KnowledgeSources.discover());
        PhaseGraph.Validation validation = graph.validate();
        assertTrue(validation.valid(), validation.errors().toString());
    }

    @Test
    void failedSamePhaseProducerCannotDispatchAConsumerWithoutItsProduct() {
        AtomicBoolean consumerRan = new AtomicBoolean();
        KnowledgeSource producer = source("producer", Phase.COMPOSITION, 100,
                Set.of(RunProduct.PROGRAM_MODEL), Set.of(RunProduct.ANALYSIS_CHAINS),
                new AtomicBoolean(), event -> {
                    throw new IllegalStateException("producer failure");
                });
        KnowledgeSource consumer = source("consumer", Phase.COMPOSITION, 200,
                Set.of(RunProduct.ANALYSIS_CHAINS), Set.of(RunProduct.COMPOSED_CHAINS),
                new AtomicBoolean(), event -> consumerRan.set(true));
        Blackboard bb = empty();

        new Controller(bb, List.of(producer, consumer)).run();

        assertFalse(consumerRan.get(), "consumer must be fail-closed when producer failed");
        assertTrue(bb.completenessReasons().stream().anyMatch(reason ->
                reason.startsWith("PRODUCT_UNAVAILABLE:consumer:ANALYSIS_CHAINS")),
                bb.completenessReasons().toString());
    }

    private static KnowledgeSource source(String id, Phase phase, int priority,
                                          Set<RunProduct> requires, Set<RunProduct> provides) {
        return source(id, phase, priority, requires, provides, new AtomicBoolean());
    }

    private static KnowledgeSource source(String id, Phase phase, int priority,
                                          Set<RunProduct> requires, Set<RunProduct> provides,
                                          AtomicBoolean initialized) {
        return source(id, phase, priority, requires, provides, initialized, event -> { });
    }

    private static KnowledgeSource source(String id, Phase phase, int priority,
                                          Set<RunProduct> requires, Set<RunProduct> provides,
                                          AtomicBoolean initialized, Consumer<Event> handler) {
        return new KnowledgeSource() {
            @Override public String id() { return id; }
            @Override public Set<EventType> interests() {
                return switch (phase) {
                    case ANALYSIS -> Set.of(EventType.SCAN_START);
                    case COMPOSITION -> Set.of(EventType.SCAN_ANALYZED);
                    case CALIBRATION -> Set.of(EventType.SCAN_COMPLETE);
                };
            }
            @Override public Phase phase() { return phase; }
            @Override public int priority() { return priority; }
            @Override public Set<RunProduct> requiresProducts() { return requires; }
            @Override public Set<RunProduct> providesProducts() { return provides; }
            @Override public void init(Blackboard blackboard) { initialized.set(true); }
            @Override public void onEvent(Blackboard blackboard, Event event) { handler.accept(event); }
        };
    }

    private static Blackboard empty() {
        return new Blackboard(new io.just.sast.cpg.graph.Graph(),
                new io.just.sast.analysis.hierarchy.ClassHierarchy(Map.of(), null),
                new io.just.sast.cpg.build.FieldWriterIndex(), io.just.sast.config.RuleSet.EMPTY,
                20, Blackboard.ScanInputs.fastDefault(Path.of(".")));
    }
}
