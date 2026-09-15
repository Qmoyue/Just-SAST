package io.just.sast.chain;

import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.HopKind;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Static confidence contract: score is evidence ordering, never a reachability proof. */
class ConfidenceScorerTest {

    private static ChainHop call(String from, String to) {
        return new ChainHop(from, "m", to, "n", HopKind.DIRECT_CALL, null, "call", "()V", null);
    }

    private static ChainHop virtual(String from, String to) {
        return new ChainHop(from, "m", to, "n", HopKind.VIRTUAL_DISPATCH, null, "call", "()V", null);
    }

    private static ChainHop field(String from, String to, String name) {
        return new ChainHop(from, "m", to, "n", HopKind.FIELD_FLOW, name, "field-read", "", null);
    }

    private static ChainHop entry(String owner, String kind) {
        return new ChainHop(owner, "e", owner, "e", HopKind.ENTRY, null, kind, "", null);
    }

    private static Chain chain(List<ChainHop> hops, String entryKind, String severity, int unresolved) {
        return new Chain("R", "CODE_EXEC", severity, "app/A", "readObject", entryKind,
                "java/lang/Runtime", "exec", hops, unresolved);
    }

    @Test
    void scoreFollowsDocumentedFormula() {
        Chain c = chain(List.of(call("x", "y"), field("a", "b", "f"),
                        entry("app/A", "readObject")), "readObject", "HIGH", 0);
        assertEquals(5, ConfidenceScorer.evidenceScore(c, null));
        assertEquals("FEASIBLE", ConfidenceScorer.score(c, null));

        Chain t = chain(List.of(call("x", "y"), field("a", "b", "f"),
                        entry("app/A", "toString")), "toString", "HIGH", 0);
        assertEquals(4, ConfidenceScorer.evidenceScore(t, null));
        assertEquals("FEASIBLE", ConfidenceScorer.score(t, null));
    }

    @Test
    void virtualDispatchScoresZeroButIsCounted() {
        Chain c = chain(List.of(virtual("x", "y"), virtual("y", "z"),
                        entry("app/A", "readObject")), "readObject", "HIGH", 0);
        assertEquals(3, ConfidenceScorer.evidenceScore(c, null));
        assertTrue(ConfidenceScorer.evidenceDecomposition(c, null).contains("virtual=2+0"));
    }

    @Test
    void unresolvedIsPenalizedAndDecomposed() {
        Chain c = chain(List.of(call("x", "y"), entry("app/A", "readObject")),
                "readObject", "HIGH", 2);
        assertEquals(0, ConfidenceScorer.evidenceScore(c, null));
        assertTrue(ConfidenceScorer.evidenceDecomposition(c, null).contains("unresolved:2-4"));
    }

    @Test
    void patternBonusAndDecomposition() {
        Chain c = chain(List.of(call("x", "y"), entry("app/A", "readObject")),
                "readObject", "HIGH", 0);
        List<String> notes = List.of("pattern:CC6", "pattern:Rome");
        assertEquals(1 + 2 + 1 + 2 * ConfidenceScorer.PATTERN_BONUS,
                ConfidenceScorer.evidenceScore(c, notes));
        String decomposition = ConfidenceScorer.evidenceDecomposition(c, notes);
        assertTrue(decomposition.contains("pattern:CC6+2"));
        assertTrue(decomposition.contains("pattern:Rome+2"));
    }

    @Test
    void entryWeightsAndFrameworkInputFollowContract() {
        Chain replace = chain(List.of(entry("app/A", "writeReplace")),
                "writeReplace", "LOW", 0);
        assertEquals(2, ConfidenceScorer.evidenceScore(replace, null));

        Chain bean = chain(List.of(new ChainHop("app/Bean", "setCommand", "app/Bean",
                        "setCommand", HopKind.ENTRY, null, "framework-bean-input",
                        "(Ljava/lang/String;)V", null)), "deserialize", "HIGH", 0);
        assertEquals(4, ConfidenceScorer.evidenceScore(bean, null));
        assertTrue(ConfidenceScorer.evidenceDecomposition(bean, null)
                .contains("source-boundary:framework-bean-input+2"));
    }

    @Test
    void degradationIsVisibleWithoutChangingStaticEvidencePrecedence() {
        Chain c = chain(List.of(call("x", "y"), entry("app/A", "readObject")),
                "readObject", "HIGH", 0);
        assertEquals("DEGRADED(partial-construct)", ConfidenceScorer.score(c,
                List.of("degrade:partial-construct", "static:constructible")));
        assertTrue(ConfidenceScorer.evidenceScore(c,
                List.of("degrade:partial-construct", "static:constructible")) >= 4);
    }

    @Test
    void staticTransitionNeverTurnsUnknownOrDegradedEvidenceIntoSat() {
        Chain unresolved = chain(List.of(call("x", "y"), entry("app/A", "readObject")),
                "readObject", "HIGH", 4);
        ConfidenceScorer.ConfidenceTransition transition = ConfidenceScorer.transition(unresolved,
                List.of("static:constructible"));
        assertEquals("NOT_FEASIBLE", transition.bucket());
        assertEquals("STATIC_INFEASIBLE", transition.reasonCode());
        assertFalse(transition.staticFeasible());

        Chain degraded = chain(List.of(call("x", "y"), entry("app/A", "readObject")),
                "readObject", "HIGH", 0);
        assertEquals("DEGRADED(partial-path)", ConfidenceScorer.score(degraded,
                List.of("degrade:partial-path")));
        assertTrue(ConfidenceScorer.transition(degraded, List.of("degrade:partial-path"))
                .staticFeasible());
    }

    @Test
    void rankFeaturesAreDeterministic() {
        Chain c = chain(List.of(call("x", "y"), entry("app/A", "readObject")),
                "readObject", "HIGH", 0);
        ConfidenceScorer.RankFeatures features = ConfidenceScorer.rankFeatures(c,
                List.of("degrade:partial-construct"));
        assertEquals(4, features.staticScore());
        assertEquals(features.staticScore(), features.totalScore());
        assertEquals(1, features.staticRank());
        assertTrue(features.staticFeasible());
        assertEquals(1, features.degradationCount());
        assertEquals(List.of("STATIC_DEGRADATION_PRESENT"), features.reasons());
    }
}
