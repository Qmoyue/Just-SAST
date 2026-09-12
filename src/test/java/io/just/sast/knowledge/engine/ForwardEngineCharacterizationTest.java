package io.just.sast.knowledge.engine;

import io.just.sast.analysis.hierarchy.ClassHierarchy;
import io.just.sast.blackboard.Blackboard;
import io.just.sast.config.RuleSet;
import io.just.sast.cpg.build.FieldWriterIndex;
import io.just.sast.cpg.graph.Graph;
import io.just.sast.model.InsnFact;
import io.just.sast.model.MethodInfo;
import io.just.sast.model.TryCatchFact;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Modifier;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * P2.1 characterization seam for the forward owner.  These tests intentionally exercise only
 * stable inputs/outputs and record the current no-op/empty behavior before any owner split.
 */
class ForwardEngineCharacterizationTest {

    @Test
    void emptyProgramRunIsAStableNoOp() {
        Blackboard blackboard = emptyBlackboard();
        ForwardEngine engine = new ForwardEngine(blackboard);

        assertDoesNotThrow(() -> engine.run(ForwardEngine.Options.coarse()));
        assertEquals(List.of(), blackboard.chains());
        assertEquals(Set.of(), blackboard.completenessReasons());
        assertEquals(0, blackboard.graph().nodeCount());
        assertEquals(0, blackboard.graph().edgeCount());
    }

    @Test
    void proxyMetadataRejectsEmptyOrMalformedRequestsWithoutExpandingTheWorld() {
        MethodInfo empty = new MethodInfo("app/Handler", "invoke", "()V",
                Modifier.PUBLIC, List.<InsnFact>of(), List.<TryCatchFact>of(), false);

        assertEquals(Set.of(), ForwardEngine.proxyMethodReturnOffsets(empty, "invoke"));
        assertEquals(Set.of(), ForwardEngine.proxyMethodReturnOffsets(empty, null));
        assertEquals(Set.of(), ForwardEngine.proxyMethodFeasibleOffsets(empty, List.of("invoke")));
        assertEquals(Set.of(), ForwardEngine.proxyMethodFeasibleOffsets(empty,
                Arrays.asList("", null)));
        assertTrue(ForwardEngine.proxyMethodReturnOffsets(null, "invoke").isEmpty());
    }

    private static Blackboard emptyBlackboard() {
        Graph graph = new Graph();
        graph.freeze();
        ClassHierarchy hierarchy = new ClassHierarchy(Map.of(), name -> null);
        return new Blackboard(graph, hierarchy, new FieldWriterIndex(), RuleSet.EMPTY, 8,
                new Blackboard.ScanInputs(Path.of("characterization.jar"), List.of(), true,
                        false, 20));
    }
}
