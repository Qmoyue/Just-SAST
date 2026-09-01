package io.just.sast.knowledge.engine;

import io.just.sast.analysis.hierarchy.ClassHierarchy;
import io.just.sast.blackboard.Blackboard;
import io.just.sast.config.RuleSet;
import io.just.sast.cpg.build.FieldWriterIndex;
import io.just.sast.cpg.graph.Graph;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertTrue;

class ForwardEngineCancellationTest {

    @Test
    void interruptedRunStopsBeforeStartingASecondTraversal() {
        Blackboard blackboard = new Blackboard(new Graph(),
                new ClassHierarchy(java.util.Map.of(), null),
                new FieldWriterIndex(), RuleSet.EMPTY, 20,
                Blackboard.ScanInputs.fastDefault(Path.of(".")));
        Thread.currentThread().interrupt();
        try {
            ForwardEngine engine = new ForwardEngine(blackboard);
            engine.run(ForwardEngine.Options.coarse());
            assertTrue(blackboard.completenessReasons().contains("FORWARD_INTERRUPTED"));
        } finally {
            Thread.interrupted();
        }
    }
}
