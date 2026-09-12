package io.just.sast.verify;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Object-plan parser contract: bounded counts, length prefixes and closed value/node kinds. */
class ProbeObjectPlanContractTest {

    @Test
    void parsesBoundedPlanAndFreezesCollections() {
        String encoded = "v1;N1;2:aa16:java/lang/Object8:ALLOCATE0;F0;";
        ProbeObjectPlan plan = ProbeObjectPlan.parse(encoded);
        assertFalse(plan.isEmpty());
        assertEquals(1, plan.nodes.size());
        assertEquals("aa", plan.nodes.get(0).id);
        assertEquals(ProbeObjectPlan.NodeKind.ALLOCATE, plan.nodes.get(0).kind);
        assertTrue(plan.nodes.get(0).arguments.isEmpty());
        assertThrowsUnsupported(plan);
    }

    @Test
    void malformedOrOverBudgetPlanIsRejectedWithoutPartialObjects() {
        assertNull(ProbeObjectPlan.parse("v1;N65;F0;"));
        assertNull(ProbeObjectPlan.parse("v1;N1;1:a15:java/lang/Object8:ALLOCATE0;F0;"));
        assertNull(ProbeObjectPlan.parse("v1;N1;1:a16:java/lang/Object7:UNKNOWN0;F0;"));
        assertTrue(ProbeObjectPlan.parse("").isEmpty());
    }

    private static void assertThrowsUnsupported(ProbeObjectPlan plan) {
        try {
            plan.nodes.add(null);
            throw new AssertionError("plan nodes must be immutable");
        } catch (UnsupportedOperationException expected) {
            // expected
        }
    }
}
