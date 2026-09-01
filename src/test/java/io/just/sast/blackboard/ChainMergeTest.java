package io.just.sast.blackboard;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ChainMergeTest {

    @Test
    void hopReasonAndPlanEvidenceDoNotCreateASecondSemanticPath() {
        Chain first = new Chain("R", "CAT", "HIGH", "app/Entry", "readObject", "readObject",
                "java/lang/Runtime", "exec", List.of(new ChainHop(
                "app/Entry", "readObject", "java/lang/Runtime", "exec", HopKind.DIRECT_CALL,
                null, "cha", "()V", null)), 0);
        Chain second = new Chain("R", "CAT", "HIGH", "app/Entry", "readObject", "readObject",
                "java/lang/Runtime", "exec", List.of(new ChainHop(
                "app/Entry", "readObject", "java/lang/Runtime", "exec", HopKind.DIRECT_CALL,
                null, "points-to", "()V", null)), 0);

        assertEquals(ChainMerge.semanticKey(first), ChainMerge.semanticKey(second));
        assertTrue(ChainMerge.reasons(second).contains("points-to"));
    }

    @Test
    void blackboardKeepsThePreferredPathAndCarriesReasonEvidence() {
        Blackboard bb = new Blackboard(new io.just.sast.cpg.graph.Graph(),
                new io.just.sast.analysis.hierarchy.ClassHierarchy(java.util.Map.of(), null),
                new io.just.sast.cpg.build.FieldWriterIndex(), io.just.sast.config.RuleSet.EMPTY,
                20, Blackboard.ScanInputs.fastDefault(java.nio.file.Path.of(".")));
        Chain weak = new Chain("R", "CAT", "HIGH", "app/Entry", "readObject", "readObject",
                "java/lang/Runtime", "exec", List.of(new ChainHop(
                "app/Entry", "readObject", "java/lang/Runtime", "exec", HopKind.DIRECT_CALL,
                null, "weak", "()V", null)), 1);
        Chain strong = new Chain("R", "CAT", "HIGH", "app/Entry", "readObject", "readObject",
                "java/lang/Runtime", "exec", List.of(new ChainHop(
                "app/Entry", "readObject", "java/lang/Runtime", "exec", HopKind.DIRECT_CALL,
                null, "strong", "()V", null)), 0);

        assertTrue(bb.addChain(weak));
        assertTrue(bb.addChain(strong));
        assertEquals(1, bb.chains().size());
        assertEquals(strong.key(), bb.chains().get(0).key());
        assertTrue(bb.chainNotesOf(strong.key()).stream()
                .anyMatch(note -> note.contains("weak")));
    }
}
