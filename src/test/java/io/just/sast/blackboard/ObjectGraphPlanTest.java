package io.just.sast.blackboard;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ObjectGraphPlanTest {

    @Test
    void wireFormIsDeterministicAndLengthPrefixed() {
        ObjectGraphPlan plan = new ObjectGraphPlan(
                List.of(new ObjectGraphPlan.Node("entry", "a/Entry",
                        ObjectGraphPlan.NodeKind.ALLOCATE, List.of()),
                        new ObjectGraphPlan.Node("proxy", "a/Api",
                                ObjectGraphPlan.NodeKind.PROXY,
                                List.of(ObjectGraphPlan.Value.ref("handler")))),
                List.of(new ObjectGraphPlan.FieldAssignment("entry", "value",
                        List.of(new ObjectGraphPlan.Value(ObjectGraphPlan.ValueKind.STRING,
                                "a|b:payload")))));

        String encoded = plan.encodedForProbe();
        assertTrue(encoded.startsWith("v1;N2;"));
        assertTrue(encoded.contains("11:a|b:payload"));
        assertEquals(encoded, plan.fingerprint());
        assertEquals(encoded, new ObjectGraphPlan(plan.nodes(), plan.fields()).encodedForProbe());
    }

    @Test
    void duplicateNodesAndOversizedValuesAreRejected() {
        assertThrows(IllegalArgumentException.class, () -> new ObjectGraphPlan(
                List.of(new ObjectGraphPlan.Node("same", "a/A", null, List.of()),
                        new ObjectGraphPlan.Node("same", "a/B", null, List.of())), List.of()));
        assertThrows(IllegalArgumentException.class, () -> new ObjectGraphPlan.Value(
                ObjectGraphPlan.ValueKind.STRING, "x".repeat(513)));
    }

    @Test
    void shapeSummarySeparatesDeclaredReferencesFromRuntimeConstruction() {
        ObjectGraphPlan plan = new ObjectGraphPlan(
                List.of(new ObjectGraphPlan.Node("entry", "a/Entry",
                        ObjectGraphPlan.NodeKind.ALLOCATE,
                        List.of(ObjectGraphPlan.Value.ref("missing")))),
                List.of(new ObjectGraphPlan.FieldAssignment("entry", "value",
                        List.of(ObjectGraphPlan.Value.ref("entry")))));

        ObjectGraphPlan.ShapeSummary summary = plan.shapeSummary();
        assertEquals("SHAPE_PARTIAL", summary.status());
        assertEquals(2, summary.referenceCount());
        assertEquals(1, summary.resolvedReferenceCount());
        assertEquals(1, summary.fieldOwnersResolved());
        assertTrue(summary.reasons().contains("MISSING_REFERENCE:missing"));
    }
}
