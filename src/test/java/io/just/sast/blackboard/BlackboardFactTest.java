package io.just.sast.blackboard;

import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BlackboardFactTest {

    private record Note(String value) implements BlackboardFact {
    }

    private record Marker(String value) implements BlackboardFact {
    }

    private static final class MutableFact implements BlackboardFact {
        private final String value = "mutable";
    }

    private static Blackboard empty() {
        return new Blackboard(new io.just.sast.cpg.graph.Graph(),
                new io.just.sast.analysis.hierarchy.ClassHierarchy(Map.of(), null),
                new io.just.sast.cpg.build.FieldWriterIndex(), io.just.sast.config.RuleSet.EMPTY,
                20, Blackboard.ScanInputs.fastDefault(Path.of(".")));
    }

    @Test
    void factsAreTypedVersionedAndSnapshotted() {
        Blackboard bb = empty();
        bb.publishFact(new Note("one"));
        bb.publishFact(new Marker("middle"));
        bb.publishFact(new Note("two"));

        List<Note> notes = bb.facts(Note.class);
        assertEquals(List.of(new Note("one"), new Note("two")), notes);
        assertEquals(List.of(new Note("one"), new Marker("middle"), new Note("two")),
                bb.facts(BlackboardFact.class));
        assertEquals(3, bb.factRevision());
        assertThrows(UnsupportedOperationException.class, () -> notes.clear());
    }

    @Test
    void mutablePluginFactsAreRejected() {
        Blackboard bb = empty();
        IllegalArgumentException failure = assertThrows(IllegalArgumentException.class,
                () -> bb.publishFact(new MutableFact()));
        assertTrue(failure.getMessage().contains("immutable records"));
    }

    @Test
    void runProductsAreTypedAppendOnlyAndSingletonSafe() {
        Blackboard bb = empty();
        assertTrue(bb.hasProduct(RunProduct.PROGRAM_MODEL));
        assertEquals(Set.of(RunProduct.PROGRAM_MODEL), bb.availableProducts());

        bb.publishProduct(RunProduct.ANALYSIS_CHAINS, "backward-taint", Phase.ANALYSIS);
        bb.publishProduct(RunProduct.ANALYSIS_CHAINS, "forward-taint", Phase.ANALYSIS);
        assertTrue(bb.hasProduct(RunProduct.ANALYSIS_CHAINS));
        assertEquals(Set.of("backward-taint", "forward-taint"),
                bb.productProducers().get(RunProduct.ANALYSIS_CHAINS));
        assertEquals(2, bb.facts(RunProductPublication.class).size());
        assertThrows(UnsupportedOperationException.class,
                () -> bb.productProducers().get(RunProduct.ANALYSIS_CHAINS).clear());

        bb.publishProduct(RunProduct.VERIFICATION_RESULTS, "verify", Phase.CALIBRATION);
        assertThrows(IllegalStateException.class,
                () -> bb.publishProduct(RunProduct.VERIFICATION_RESULTS, "other", Phase.CALIBRATION));
    }

    @Test
    void legacyVerificationStatusIsOnlyAProjectionOfTheSummaryOwner() {
        Blackboard bb = empty();
        bb.setVerificationStatus("UNTESTABLE");
        assertEquals("UNTESTABLE", bb.verificationStatus());
        assertEquals("UNTESTABLE", bb.verificationSummary().capability());

        VerificationSummary detailed = VerificationSummary.empty("READY", 3);
        bb.setVerificationSummary(detailed);
        bb.setVerificationStatus("TIMEOUT");
        assertEquals("TIMEOUT", bb.verificationSummary().capability());
        assertEquals(detailed.results(), bb.verificationSummary().results());
        assertEquals(3, bb.verificationSummary().budget());
    }
}
