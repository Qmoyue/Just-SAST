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
    void typedNestedDeserializationEvidencePrecedesGenericDeclaredConstruction() {
        ObjectGraphPlan genericPlan = new ObjectGraphPlan(
                List.of(new ObjectGraphPlan.Node("entry", "app/Entry",
                        ObjectGraphPlan.NodeKind.ALLOCATE, List.of())), List.of());
        Chain generic = new Chain("RULE-generic", "COMMAND_EXEC", "HIGH", "app/Entry",
                "readObject", "deserialize", "java/lang/Runtime", "exec", List.of(
                new ChainHop("app/Entry", "readObject", "java/lang/Runtime", "exec",
                        HopKind.DIRECT_CALL, null, "call", "()V", null)), 0,
                "()V", "TERMINAL", genericPlan);
        Chain typed = new Chain("RULE-typed", "CODE_EXEC", "HIGH", "app/Entry",
                "deserialize", "deserialize", "app/Terminal", "run", List.of(
                new ChainHop("app/Entry", "deserialize", "java/lang/reflect/Method", "invoke",
                        HopKind.DIRECT_CALL, null, "call", "()V", null),
                new ChainHop("java/security/SignedObject", "getObject", "java/io/ObjectInputStream", "<init>",
                        HopKind.DIRECT_CALL, null, "fragment-activation-invoke", "()V", null),
                new ChainHop("java/io/ObjectInputStream", "<init>", "java/io/ObjectInput", "readObject",
                        HopKind.DIRECT_CALL, null, "fragment-activation-invoke", "()Ljava/lang/Object;", null),
                new ChainHop("java/io/ObjectInput", "readObject", "app/Callback", "hashCode",
                        HopKind.DIRECT_CALL, null, "bridge-deser", "()V", null),
                new ChainHop("app/Callback", "hashCode", "app/Terminal", "run",
                        HopKind.DIRECT_CALL, null, "fragment-activation-deserialize", "()V", null)), 0,
                "()V", "TERMINAL");

        assertTrue(ChainRanking.compare(typed, generic, Map.of(), Map.of(), Set.of()) < 0);
        ChainRanking.Evidence evidence = ChainRanking.evidence(typed, Map.of(), Map.of(), Set.of());
        assertEquals(0, evidence.semanticRank());
        assertTrue(evidence.explanation().contains("semantic=TYPED_NESTED_DESERIALIZATION"));
    }

    @Test
    void precisionIncompleteCandidateCannotOutrankACompletePeer() {
        Chain complete = chain("complete", "TERMINAL");
        Chain incomplete = new Chain("RULE-incomplete", "COMMAND_EXEC", "HIGH", "app/Entry",
                "readObject", "readObject", "java/lang/Runtime", "exec", List.of(
                new ChainHop("app/Entry", "readObject", "java/lang/Runtime", "exec",
                        HopKind.VIRTUAL_DISPATCH, null, "serialized-proxy-interface", "()V", null)), 0,
                "()V", "TERMINAL");

        assertTrue(ChainRanking.compare(complete, incomplete, Map.of(), Map.of(), Set.of()) < 0);
        assertTrue(ChainRanking.evidence(incomplete, Map.of(), Map.of(), Set.of()).incompleteness()
                > ChainRanking.evidence(complete, Map.of(), Map.of(), Set.of()).incompleteness());
    }

    @Test
    void partialNestedDeserializationCannotOutrankCompleteOrdinaryChain() {
        Chain complete = chain("complete-ordinary", "TERMINAL");
        Chain partialNested = new Chain("RULE-partial-nested", "CODE_EXEC", "HIGH", "app/Entry",
                "deserialize", "deserialize", "app/Terminal", "run", List.of(
                new ChainHop("app/Entry", "deserialize", "java/security/SignedObject", "getObject",
                        HopKind.DIRECT_CALL, null, "fragment-activation-invoke", "()V", null),
                new ChainHop("java/security/SignedObject", "getObject", "app/Terminal", "run",
                        HopKind.DIRECT_CALL, null, "bridge-deser", "()V", null)), 1,
                "()V", "TERMINAL");

        assertTrue(ChainRanking.compare(complete, partialNested, Map.of(), Map.of(), Set.of()) < 0);
        assertEquals(1, ChainRanking.evidence(partialNested, Map.of(), Map.of(), Set.of())
                .semanticRank());
    }

    @Test
    void shortestCompleteChainWinsOverLongerDecorativeSuffix() {
        Chain shortChain = new Chain("RULE-short", "CODE_EXEC", "HIGH", "app/Entry",
                "handle", "source", "terminal/Target", "run", List.of(
                new ChainHop("app/Entry", "handle", "terminal/Target", "run",
                        HopKind.DIRECT_CALL, null, "bridge", "()V", null)), 0,
                "()V", "TERMINAL");
        Chain longChain = new Chain("RULE-long", "CODE_EXEC", "HIGH", "app/Entry",
                "handle", "source", "terminal/Target", "run", List.of(
                new ChainHop("dep/A", "a", "dep/B", "b", HopKind.DIRECT_CALL,
                        null, "decorative", "()V", null),
                new ChainHop("dep/B", "b", "dep/C", "c", HopKind.DIRECT_CALL,
                        null, "decorative", "()V", null),
                new ChainHop("app/Entry", "handle", "terminal/Target", "run",
                        HopKind.DIRECT_CALL, null, "bridge", "()V", null)), 0,
                "()V", "TERMINAL");

        assertTrue(ChainRanking.compare(shortChain, longChain, Map.of(), Map.of(), Set.of()) < 0);
    }

    @Test
    void declaredCompactTerminalPrecedesLongerConnectedSuffix() {
        ObjectGraphPlan compactPlan = new ObjectGraphPlan(
                List.of(new ObjectGraphPlan.Node("entry", "lib/Target",
                        ObjectGraphPlan.NodeKind.ALLOCATE, List.of())), List.of());
        Chain compact = new Chain("RULE-compact", "CODE_EXEC", "HIGH", "lib/Target",
                "activate", "reflectiveTarget", "lib/Target", "activate", List.of(
                new ChainHop("lib/Target", "activate", "lib/Target", "activate",
                        HopKind.ENTRY, null, "fragment-activation-invoke", "()V", null)), 0,
                "()V", "TERMINAL", compactPlan);

        ObjectGraphPlan connectedPlan = new ObjectGraphPlan(
                List.of(new ObjectGraphPlan.Node("entry", "app/Entry",
                        ObjectGraphPlan.NodeKind.ALLOCATE, List.of())), List.of());
        Chain connected = new Chain("RULE-connected", "CODE_EXEC", "HIGH", "app/Entry",
                "handle", "reflectiveTarget", "lib/Target", "activate", List.of(
                new ChainHop("app/Entry", "handle", "dep/Mid", "go",
                        HopKind.DIRECT_CALL, null, "bridge", "()V", null),
                new ChainHop("dep/Mid", "go", "lib/Target", "activate",
                        HopKind.DIRECT_CALL, null, "bridge", "()V", null),
                new ChainHop("app/Entry", "handle", "app/Entry", "handle",
                        HopKind.ENTRY, null, "reflectiveTarget", "()V", null)), 0,
                "()V", "TERMINAL", connectedPlan);

        assertEquals(0, ChainRanking.evidence(compact, Map.of(), Map.of(), Set.of())
                .compactTerminalRank());
        assertTrue(ChainRanking.compare(compact, connected, Map.of(), Map.of(), Set.of()) < 0);
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
