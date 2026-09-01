package io.just.sast.blackboard;

import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;

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
}
