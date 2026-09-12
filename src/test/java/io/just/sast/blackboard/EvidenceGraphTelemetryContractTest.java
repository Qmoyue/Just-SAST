package io.just.sast.blackboard;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Contract tests for bounded graph-size/serialization/CPU telemetry. */
class EvidenceGraphTelemetryContractTest {

    private static EvidenceGraph fixture() {
        EvidenceAtom entry = EvidenceAtom.of(EvidenceAtom.Kind.APPLICATION_ENTRY, "artifact-a",
                "app/Api", "handle", "APPLICATION_ENTRY", Map.of("protocol", "http"));
        EvidenceAtom site = EvidenceAtom.of(EvidenceAtom.Kind.DESERIALIZATION_SITE, "artifact-a",
                "app/Api", "read", "DESERIALIZATION_SITE",
                Map.of("format", "java-serialization"));
        EvidenceAtom reply = EvidenceAtom.of(EvidenceAtom.Kind.PROTOCOL_BRIDGE, "artifact-b",
                "java/rmi/Connection", "readObject", "RMI_REPLY", Map.of());
        BridgeEvidence bridge = BridgeEvidence.of(BridgeEvidence.Kind.JNDI_RMI, site.id(),
                reply.id(), "jndi-rmi", BridgeEvidence.Status.PROVED);
        EntryChainJoinEvidence join = EntryChainJoinEvidence.of(
                ApplicationChainId.fromCanonical(entry.id(), site.id()), entry.id(), site.id(),
                GadgetSegmentId.fromCanonical("commons", "callback"),
                EntryChainJoinEvidence.ValueFlow.PROTOCOL_REPLY,
                EntryChainJoinEvidence.ObjectIdentity.SERIALIZED_ROUND_TRIP,
                EntryChainJoinEvidence.CallbackSemantics.PROTOCOL_REENTRY,
                EntryChainJoinEvidence.RuntimeTypeProof.BOUNDED,
                EntryChainJoinEvidence.ArtifactCompatibility.CROSS_ARTIFACT_VERIFIED,
                EntryChainJoinEvidence.FilterDominance.NOT_PRESENT,
                EntryChainJoinEvidence.ConstructionConstraint.SAT, List.of(bridge.id()));
        return EvidenceGraph.empty().withNode(entry).withNode(site).withNode(reply)
                .withNode(bridge).withNode(join)
                .withEdge(EvidenceEdge.of(entry.id(), site.id(), EvidenceEdge.Kind.SUPPORTS,
                        "ENTRY_TO_SITE"))
                .withEdge(EvidenceEdge.of(site.id(), bridge.id(), EvidenceEdge.Kind.BRIDGES,
                        "JNDI_TO_RMI"))
                .withEdge(EvidenceEdge.of(bridge.id(), join.id(), EvidenceEdge.Kind.JOINS,
                        "DEPENDENCY_JOIN"));
    }

    @Test
    void measuredGraphIncludesEveryNodeAndEdgeWithoutClaimingRss() {
        EvidenceGraphTelemetry.Measurement measurement =
                EvidenceGraphTelemetry.measure(fixture());

        assertEquals(EvidenceGraphTelemetry.SCHEMA, measurement.schema());
        assertEquals(5, measurement.nodeCount());
        assertEquals(3, measurement.edgeCount());
        assertEquals(5, measurement.nodes().size());
        assertEquals(3, measurement.edges().size());
        assertTrue(measurement.serializedBytes() > 0L);
        assertTrue(measurement.retainedBytesEstimate() > 0L);
        measurement.nodes().forEach(node -> {
            assertTrue(node.serializedBytes() > 0L);
            assertTrue(node.canonicalBytes() > 0L);
            assertTrue(node.retainedBytesEstimate() > 0L);
        });
        measurement.edges().forEach(edge -> {
            assertTrue(edge.serializedBytes() > 0L);
            assertTrue(edge.canonicalBytes() > 0L);
            assertTrue(edge.retainedBytesEstimate() > 0L);
        });
        assertEquals(-1L, measurement.rssBytes());
        assertEquals(EvidenceGraphTelemetry.RSS_STATUS, measurement.rssStatus());
        assertEquals(EvidenceGraphTelemetry.RETAINED_SIZE_STATUS,
                measurement.retainedSizeStatus());
        assertEquals(measurement.serializedBytes(),
                measurement.toCanonicalJson().contains("\"nodes\"")
                        ? EvidenceGraphTelemetry.measure(fixture()).serializedBytes()
                        : -1L);
    }

    @Test
    void staticMeasurementIsDeterministicAndSupplierMeasuresConstruction() {
        EvidenceGraphTelemetry.Measurement first =
                EvidenceGraphTelemetry.measure(fixture());
        EvidenceGraphTelemetry.Measurement second =
                EvidenceGraphTelemetry.measure(fixture());
        assertEquals(first.graphDigest(), second.graphDigest());
        assertEquals(first.serializedBytes(), second.serializedBytes());
        assertEquals(first.retainedBytesEstimate(), second.retainedBytesEstimate());
        assertEquals(first.toCanonicalJson(), second.toCanonicalJson());

        EvidenceGraphTelemetry.Measurement constructed =
                EvidenceGraphTelemetry.measure(EvidenceGraphTelemetryContractTest::fixture);
        assertTrue(constructed.constructionWallNanos() >= 0L);
        assertTrue(constructed.constructionCpuNanos() >= -1L);
        assertTrue(constructed.constructionCpuStatus().equals("OBSERVED")
                || constructed.constructionCpuStatus().equals("NOT_SUPPORTED"));
        assertEquals(first.graphDigest(), constructed.graphDigest());
        assertNotEquals(-2L, constructed.constructionWallNanos());
    }

    @Test
    void overheadComparisonIsFailClosedAndHonorsOnePointTenLimit() {
        EvidenceGraphTelemetry.NodeMeasurement node =
                new EvidenceGraphTelemetry.NodeMeasurement("atom-"
                        + "0".repeat(64), EvidenceNode.NodeKind.ATOM, 10L, 8L, 100L);
        EvidenceGraphTelemetry.Measurement baseline = synthetic(100L, 100L, 1000L, 100L, node);
        EvidenceGraphTelemetry.Measurement within = synthetic(109L, 108L, 1090L, 108L, node);
        EvidenceGraphTelemetry.Measurement over = synthetic(111L, 108L, 1090L, 108L, node);

        EvidenceGraphTelemetry.OverheadComparison pass =
                EvidenceGraphTelemetry.compare(baseline, within, 1.10d);
        assertTrue(pass.withinLimit());
        assertFalse(pass.rssComparable());
        assertEquals("PASS", pass.status());

        EvidenceGraphTelemetry.OverheadComparison fail =
                EvidenceGraphTelemetry.compare(baseline, over, 1.10d);
        assertFalse(fail.withinLimit());
        assertEquals("OVER_LIMIT", fail.status());

        EvidenceGraphTelemetry.Measurement unmeasured =
                EvidenceGraphTelemetry.measure(fixture());
        EvidenceGraphTelemetry.OverheadComparison unknown =
                EvidenceGraphTelemetry.compare(unmeasured, unmeasured, 1.10d);
        assertEquals("NOT_COMPARABLE", unknown.status());
        assertFalse(unknown.withinLimit());
    }

    private static EvidenceGraphTelemetry.Measurement synthetic(long wall, long cpu, long retained,
                                                                 long serialized,
                                                                 EvidenceGraphTelemetry.NodeMeasurement node) {
        return new EvidenceGraphTelemetry.Measurement(
                EvidenceGraphTelemetry.SCHEMA, "a".repeat(64), 1, 0, serialized, retained,
                wall, cpu, "OBSERVED", EvidenceGraphTelemetry.RETAINED_SIZE_STATUS, -1L,
                EvidenceGraphTelemetry.RSS_STATUS, List.of(node), List.of());
    }
}
