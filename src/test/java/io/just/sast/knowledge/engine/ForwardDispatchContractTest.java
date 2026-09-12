package io.just.sast.knowledge.engine;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** Stable contract for revision-aware forward dispatch products. */
class ForwardDispatchContractTest {

    @Test
    void snapshotsDefensivelyFreezeResolverOutputs() {
        List<String> raw = new ArrayList<>(List.of("impl/B", "impl/A"));
        ForwardDispatch.Candidates candidates = new ForwardDispatch.Candidates(7, raw, true);
        raw.clear();

        assertEquals(List.of("impl/B", "impl/A"), candidates.raw());
        assertEquals(new ForwardDispatch.Key("app/Api", "run", "()V"),
                new ForwardDispatch.Key("app/Api", "run", "()V"));
        assertEquals("", new ForwardDispatch.Key(null, null, null).owner());

        List<ForwardDispatch.Target> targets = new ArrayList<>();
        targets.add(new ForwardDispatch.Target("impl/A", "impl/A"));
        ForwardDispatch.ResolvedCandidates resolved =
                new ForwardDispatch.ResolvedCandidates(7, targets, false);
        targets.clear();
        assertEquals(1, resolved.targets().size());
    }

    @Test
    void negativeRevisionsAreRejected() {
        assertThrows(IllegalArgumentException.class,
                () -> new ForwardDispatch.Candidates(-1, List.of(), false));
        assertThrows(IllegalArgumentException.class,
                () -> new ForwardDispatch.ResolvedCandidates(-1, List.of(), false));
    }
}
