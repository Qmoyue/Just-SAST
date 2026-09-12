package io.just.sast.blackboard;

import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Contract tests for immutable evidence nodes, joins, bridges, IDs and graph determinism. */
class EvidenceGraphContractTest {

    private static EvidenceAtom entry() {
        return EvidenceAtom.of(EvidenceAtom.Kind.APPLICATION_ENTRY, "artifact-a", "app/Api",
                "handle", "APPLICATION_ENTRY", Map.of("protocol", "http"));
    }

    private static EvidenceAtom site() {
        return EvidenceAtom.of(EvidenceAtom.Kind.DESERIALIZATION_SITE, "artifact-a", "app/Api",
                "read", "DESERIALIZATION_SITE", Map.of("format", "java-serialization"));
    }

    @Test
    void canonicalIdsIgnoreMapInsertionOrderAndUseTypedPrefixes() {
        Map<String, String> first = new LinkedHashMap<>();
        first.put("z", "2");
        first.put("a", "1");
        Map<String, String> second = new LinkedHashMap<>();
        second.put("a", "1");
        second.put("z", "2");
        EvidenceAtom left = EvidenceAtom.of(EvidenceAtom.Kind.CALL_EDGE, "artifact", "a", "m",
                "CALL_EDGE", first);
        EvidenceAtom right = EvidenceAtom.of(EvidenceAtom.Kind.CALL_EDGE, "artifact", "a", "m",
                "CALL_EDGE", second);
        assertEquals(left.id(), right.id());
        assertTrue(left.id().startsWith("atom-"));
        assertTrue(GadgetSegmentId.fromCanonical("lib", "1").value().startsWith("segment-"));
        assertTrue(ApplicationChainId.fromCanonical("entry", "terminal").value()
                .startsWith("appchain-"));
        assertTrue(FindingId.fromCanonical("chain").value().startsWith("finding-"));
        assertTrue(CandidateId.fromCanonical("path").value().startsWith("candidate-"));
        assertTrue(AttemptId.fromCanonical("attempt").value().startsWith("attempt-"));
    }

    @Test
    void idsUseTheFullDigestAndDoNotCollideForDistinctCanonicalInputs() {
        java.util.Set<String> ids = new java.util.HashSet<>();
        for (int index = 0; index < 2048; index++) {
            ids.add(CandidateId.fromCanonical("schema-v1", "candidate-" + index).value());
        }
        assertEquals(2048, ids.size());
        assertTrue(ids.iterator().next().matches("candidate-[0-9a-f]{64}"));
        assertNotEquals(GadgetSegmentId.fromCanonical("lib", "callback", "sink-a"),
                GadgetSegmentId.fromCanonical("lib", "callback", "sink-b"));
        assertNotEquals(ApplicationChainId.fromCanonical("app-a", "entry", "terminal"),
                ApplicationChainId.fromCanonical("app-b", "entry", "terminal"));
    }

    @Test
    void joinAndBridgeRetainEntryToDependencyComposition() {
        EvidenceAtom entry = entry();
        EvidenceAtom site = site();
        EvidenceAtom reply = EvidenceAtom.of(EvidenceAtom.Kind.PROTOCOL_BRIDGE, "artifact-b",
                "java/rmi/Connection", "readObject", "RMI_REPLY", Map.of());
        BridgeEvidence bridge = BridgeEvidence.of(BridgeEvidence.Kind.JNDI_RMI, site.id(), reply.id(),
                "jndi-rmi", BridgeEvidence.Status.PROVED);
        EntryChainJoinEvidence join = EntryChainJoinEvidence.of(
                ApplicationChainId.fromCanonical(entry.id(), site.id()), entry.id(), site.id(),
                GadgetSegmentId.fromCanonical("commons", "callback"),
                EntryChainJoinEvidence.ValueFlow.PROTOCOL_REPLY,
                EntryChainJoinEvidence.ObjectIdentity.SERIALIZED_ROUND_TRIP,
                EntryChainJoinEvidence.CallbackSemantics.PROTOCOL_REENTRY,
                EntryChainJoinEvidence.RuntimeTypeProof.BOUNDED,
                EntryChainJoinEvidence.ArtifactCompatibility.CROSS_ARTIFACT_VERIFIED,
                EntryChainJoinEvidence.FilterDominance.NOT_PRESENT,
                EntryChainJoinEvidence.ConstructionConstraint.SAT,
                List.of(bridge.id()));
        EvidenceGraph graph = EvidenceGraph.empty().withNode(entry).withNode(site).withNode(reply)
                .withNode(bridge).withNode(join)
                .withEdge(EvidenceEdge.of(entry.id(), site.id(), EvidenceEdge.Kind.SUPPORTS,
                        "ENTRY_TO_SITE"))
                .withEdge(EvidenceEdge.of(site.id(), bridge.id(), EvidenceEdge.Kind.BRIDGES,
                        "JNDI_TO_RMI"))
                .withEdge(EvidenceEdge.of(bridge.id(), join.id(), EvidenceEdge.Kind.JOINS,
                        "DEPENDENCY_JOIN"));
        assertEquals(5, graph.nodes().size());
        assertEquals(3, graph.edges().size());
        assertThrows(UnsupportedOperationException.class, () -> graph.nodes().clear());
        assertThrows(UnsupportedOperationException.class, () -> graph.edges().clear());
        assertEquals(graph.canonicalDigest(),
                new EvidenceGraph(List.of(join, bridge, reply, site, entry),
                        List.of(graph.edges().get(2), graph.edges().get(0), graph.edges().get(1)))
                        .canonicalDigest());
        assertTrue(graph.toCanonicalJson().contains("evidence-graph-v1"));
    }

    @Test
    void graphRejectsDuplicateAndDanglingRelationships() {
        EvidenceAtom entry = entry();
        assertThrows(IllegalArgumentException.class,
                () -> new EvidenceGraph(List.of(entry, entry), List.of()));
        EvidenceEdge dangling = EvidenceEdge.of(entry.id(), "atom-"
                + "0".repeat(64), EvidenceEdge.Kind.SUPPORTS, "MISSING");
        assertThrows(IllegalArgumentException.class,
                () -> new EvidenceGraph(List.of(entry), List.of(dangling)));
        assertThrows(IllegalArgumentException.class,
                () -> new EvidenceEdge(entry.id(), entry.id(), "", EvidenceEdge.Kind.SUPPORTS,
                        "SELF"));
    }

    @Test
    void graphRejectsAJoinWithMissingOrWrongTypedReferences() {
        EvidenceAtom entry = entry();
        EvidenceAtom site = site();
        EntryChainJoinEvidence missingBridge = EntryChainJoinEvidence.of(
                ApplicationChainId.fromCanonical("missing-bridge"), entry.id(), site.id(),
                GadgetSegmentId.fromCanonical("lib", "missing-bridge"),
                EntryChainJoinEvidence.ValueFlow.DIRECT_VALUE,
                EntryChainJoinEvidence.ObjectIdentity.SAME_OBJECT,
                EntryChainJoinEvidence.CallbackSemantics.DIRECT,
                EntryChainJoinEvidence.RuntimeTypeProof.EXACT,
                EntryChainJoinEvidence.ArtifactCompatibility.SAME_ARTIFACT,
                EntryChainJoinEvidence.FilterDominance.NOT_PRESENT,
                EntryChainJoinEvidence.ConstructionConstraint.SAT,
                List.of(BridgeEvidence.of(BridgeEvidence.Kind.JNDI_RMI, site.id(), entry.id(),
                        "jndi-rmi", BridgeEvidence.Status.PROVED).id()));
        assertThrows(IllegalArgumentException.class,
                () -> new EvidenceGraph(List.of(entry, site, missingBridge), List.of()));

        EvidenceAtom notEntry = EvidenceAtom.of(EvidenceAtom.Kind.CALL_EDGE, "artifact-a", "app/Api",
                "handle", "CALL_EDGE", Map.of());
        EntryChainJoinEvidence wrongEntry = EntryChainJoinEvidence.of(
                ApplicationChainId.fromCanonical("wrong-entry"), notEntry.id(), site.id(),
                GadgetSegmentId.fromCanonical("lib", "wrong-entry"),
                EntryChainJoinEvidence.ValueFlow.DIRECT_VALUE,
                EntryChainJoinEvidence.ObjectIdentity.SAME_OBJECT,
                EntryChainJoinEvidence.CallbackSemantics.DIRECT,
                EntryChainJoinEvidence.RuntimeTypeProof.EXACT,
                EntryChainJoinEvidence.ArtifactCompatibility.SAME_ARTIFACT,
                EntryChainJoinEvidence.FilterDominance.NOT_PRESENT,
                EntryChainJoinEvidence.ConstructionConstraint.SAT,
                List.of());
        assertThrows(IllegalArgumentException.class,
                () -> new EvidenceGraph(List.of(notEntry, site, wrongEntry), List.of()));
    }

    @Test
    void nodesAndAttributesAreImmutableAndMalformedIdsFailClosed() {
        EvidenceAtom atom = entry();
        assertThrows(UnsupportedOperationException.class,
                () -> atom.attributes().put("new", "value"));
        assertThrows(IllegalArgumentException.class,
                () -> new GadgetSegmentId("segment-not-a-digest"));
        assertThrows(IllegalArgumentException.class,
                () -> EvidenceAtom.of(EvidenceAtom.Kind.CALL_EDGE, "artifact", "owner", "member",
                        "", Map.of()));
        assertFalse(EvidenceGraph.empty().toCanonicalJson().contains("null"));
    }
}
