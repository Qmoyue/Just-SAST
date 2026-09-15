package io.just.sast.chain;

import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.HopKind;
import io.just.sast.blackboard.ObjectGraphPlan;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ChainRankingTest {

    @Test
    void terminalSinkPrecedesCapabilityWithSameStaticShape() {
        Chain terminal = chain("terminal", "TERMINAL");
        Chain capability = chain("capability", "CAPABILITY");

        assertTrue(ChainRanking.compare(terminal, capability, Map.of(), Set.of()) < 0);
    }

    @Test
    void staticConstructionEvidencePrecedesAnUnannotatedCandidateAndExplainsWhy() {
        Chain constructed = chain("constructed", "TERMINAL");
        Chain plain = chain("plain", "TERMINAL");

        assertTrue(ChainRanking.compare(constructed, plain,
                Map.of(constructed.key(), List.of("static:constructible")), Set.of()) < 0);
        String explanation = ChainRanking.evidence(constructed,
                Map.of(constructed.key(), List.of("static:constructible")), Set.of()).explanation();
        assertTrue(explanation.contains("construction=CONSTRUCTIBLE"));
        assertTrue(explanation.contains("sink_role=TERMINAL"));
    }

    @Test
    void constructionAndDegradationNotesUseSharedStaticTiers() {
        Chain constructed = chain("constructed", "TERMINAL");
        Chain degraded = chain("degraded", "TERMINAL");
        Chain plain = chain("plain", "TERMINAL");

        assertTrue(ChainRanking.compare(constructed, plain,
                Map.of(constructed.key(), List.of("static:constructible")), Set.of()) < 0);
        assertTrue(ChainRanking.compare(degraded, plain,
                Map.of(degraded.key(), List.of("degrade:partial-construct")), Set.of()) > 0);
        assertTrue(ChainRanking.compare(constructed, degraded,
                Map.of(constructed.key(), List.of("static:constructible"),
                        degraded.key(), List.of("degrade:partial-construct")), Set.of()) < 0);
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

        assertTrue(ChainRanking.compare(typed, generic, Map.of(), Set.of()) < 0);
        ChainRanking.Evidence evidence = ChainRanking.evidence(typed, Map.of(), Set.of());
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

        assertTrue(ChainRanking.compare(complete, incomplete, Map.of(), Set.of()) < 0);
        assertTrue(ChainRanking.evidence(incomplete, Map.of(), Set.of()).incompleteness()
                > ChainRanking.evidence(complete, Map.of(), Set.of()).incompleteness());
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

        assertTrue(ChainRanking.compare(complete, partialNested, Map.of(), Set.of()) < 0);
        assertEquals(1, ChainRanking.evidence(partialNested, Map.of(), Set.of()).semanticRank());
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

        assertTrue(ChainRanking.compare(shortChain, longChain, Map.of(), Set.of()) < 0);
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

        assertEquals(0, ChainRanking.evidence(compact, Map.of(), Set.of()).compactTerminalRank());
        assertTrue(ChainRanking.compare(compact, connected, Map.of(), Set.of()) < 0);
    }

    @Test
    void malformedPlansAndNullNotesRemainExplicitAndSortable() {
        ObjectGraphPlan partial = new ObjectGraphPlan(
                List.of(new ObjectGraphPlan.Node("entry", "app/Entry",
                        ObjectGraphPlan.NodeKind.ALLOCATE,
                        List.of(ObjectGraphPlan.Value.ref("missing")))), List.of());
        Chain candidate = new Chain("RULE-partial", "COMMAND_EXEC", "HIGH", "app/Entry",
                "readObject", "readObject", "java/lang/Runtime", "exec", List.of(), 0,
                "(Ljava/lang/String;)Ljava/lang/Process;", "TERMINAL", partial);

        ChainRanking.Evidence evidence = ChainRanking.evidence(candidate, Map.of(), Set.of());
        assertEquals(2, evidence.constructionRank());
        assertTrue(evidence.explanation().contains("construction=PLAN_PARTIAL"));

        Chain nullCandidate = chain("null-list", "TERMINAL");
        ChainRanking.Evidence nullEvidence = ChainRanking.evidence(nullCandidate,
                java.util.Collections.singletonMap(nullCandidate.key(), null), Set.of());
        assertEquals(3, nullEvidence.constructionRank());
        assertTrue(nullEvidence.explanation().contains("construction=UNKNOWN"));
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
