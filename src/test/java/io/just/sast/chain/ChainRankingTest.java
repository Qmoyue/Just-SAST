package io.just.sast.chain;

import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.HopKind;
import io.just.sast.blackboard.VerificationSummary;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Arrays;

import io.just.sast.blackboard.ObjectGraphPlan;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;

class ChainRankingTest {

    @Test
    void terminalSinkPrecedesCapabilityWithSameStaticShape() {
        Chain terminal = chain("terminal", "TERMINAL");
        Chain capability = chain("capability", "CAPABILITY");

        assertTrue(ChainRanking.compare(terminal, capability, Map.of(), Map.of(), Set.of()) < 0);
    }

    @Test
    void exactDynamicBoundaryPrecedesUnselectedCandidateAndExplainsWhy() {
        Chain confirmed = chain("confirmed", "TERMINAL");
        Chain unselected = chain("unselected", "TERMINAL");
        VerificationSummary.ChainResult result = new VerificationSummary.ChainResult(
                1, confirmed.key(), "SINK_BLOCKED", "canary", "FEASIBLE", 10, 1, 1,
                "SINK_BOUNDARY_REACHED", "TEST", "17", "sha256:test", false, true, "CLEAN");

        assertTrue(ChainRanking.compare(confirmed, unselected, Map.of(),
                Map.of(confirmed.key(), result), Set.of()) < 0);
        String explanation = ChainRanking.evidence(confirmed, Map.of(),
                Map.of(confirmed.key(), result), Set.of()).explanation();
        assertTrue(explanation.contains("dynamic=SINK_BLOCKED"));
        assertTrue(explanation.contains("sink_role=TERMINAL"));
    }

    @Test
    void safeEffectNoteKeepsItsOwnDynamicMeaning() {
        Chain chain = chain("safe", "TERMINAL");
        String explanation = ChainRanking.evidence(chain,
                Map.of(chain.key(), List.of("verify:safe-effect-observed")), Map.of(), Set.of())
                .explanation();

        assertTrue(explanation.contains("dynamic=SAFE_EFFECT_OBSERVED"));
    }

    @Test
    void compatibilityAndSegmentNotesUseSharedDynamicTiers() {
        Chain legacy = chain("legacy", "TERMINAL");
        Chain segment = chain("segment", "TERMINAL");
        Chain plain = chain("plain", "TERMINAL");

        assertTrue(ChainRanking.compare(legacy, plain,
                Map.of(legacy.key(), List.of("verify:confirmed")), Map.of(), Set.of()) < 0);
        assertTrue(ChainRanking.compare(segment, plain,
                Map.of(segment.key(), List.of("verify:segment-confirmed")), Map.of(), Set.of()) < 0);
        assertTrue(ChainRanking.compare(legacy, segment,
                Map.of(legacy.key(), List.of("verify:confirmed"),
                        segment.key(), List.of("verify:segment-confirmed")), Map.of(), Set.of()) < 0);
    }

    @Test
    void malformedDeclaredPlanDoesNotReceiveConstructibleRank() {
        ObjectGraphPlan partial = new ObjectGraphPlan(
                List.of(new ObjectGraphPlan.Node("entry", "app/Entry",
                        ObjectGraphPlan.NodeKind.ALLOCATE,
                        List.of(ObjectGraphPlan.Value.ref("missing")))), List.of());
        Chain chain = new Chain("RULE-partial", "COMMAND_EXEC", "HIGH", "app/Entry",
                "readObject", "readObject", "java/lang/Runtime", "exec", List.of(), 0,
                "(Ljava/lang/String;)Ljava/lang/Process;", "TERMINAL", partial);

        ChainRanking.Evidence evidence = ChainRanking.evidence(chain, Map.of(), Map.of(), Set.of());

        assertEquals(2, evidence.constructionRank());
        assertTrue(evidence.explanation().contains("construction=PLAN_PARTIAL"));
    }

    @Test
    void nullCompatibilityNotesRemainAWeakButSortableCandidate() {
        Chain candidate = chain("null-note", "TERMINAL");

        ChainRanking.Evidence evidence = ChainRanking.evidence(candidate,
                Map.of(candidate.key(), Arrays.asList(null, "degrade:partial-construct")),
                Map.of(), Set.of());

        assertEquals(2, evidence.constructionRank());
        assertTrue(evidence.explanation().contains("construction=PARTIAL")
                || evidence.explanation().contains("construction=PLAN_PARTIAL"));
    }

    @Test
    void nullNoteListIsTreatedAsNoEvidence() {
        Chain candidate = chain("null-list", "TERMINAL");

        ChainRanking.Evidence evidence = ChainRanking.evidence(candidate,
                java.util.Collections.singletonMap(candidate.key(), null), Map.of(), Set.of());

        assertEquals(3, evidence.constructionRank());
        assertTrue(evidence.explanation().contains("construction=UNKNOWN"));
    }

    private static Chain chain(String name, String role) {
        List<ChainHop> hops = List.of(new ChainHop(
                "app/Entry", "readObject", "java/lang/Runtime", "exec", HopKind.DIRECT_CALL,
                null, "test", "(Ljava/lang/String;)Ljava/lang/Process;", 0));
        return new Chain("RULE-" + name, "COMMAND_EXEC", "HIGH", "app/Entry", "readObject",
                "readObject", "java/lang/Runtime", "exec", hops, 0,
                "(Ljava/lang/String;)Ljava/lang/Process;", role);
    }
}
