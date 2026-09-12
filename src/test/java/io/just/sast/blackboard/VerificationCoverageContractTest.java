package io.just.sast.blackboard;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class VerificationCoverageContractTest {

    @Test
    void boundedSelectionCannotMasqueradeAsFullCoverage() {
        String group = FindingId.fromCanonical("group-a").value();
        String deferredGroup = FindingId.fromCanonical("group-b").value();
        VerificationCoverage coverage = new VerificationCoverage(
                VerificationCoverage.SCHEMA_VERSION,
                VerificationCoverage.Status.PARTIAL_DYNAMIC_BUDGET,
                2, 1, 1, 0, 1, 1,
                Map.of(group, List.of("chain-a"), deferredGroup, List.of("chain-b")),
                Map.of(group, List.of("plan-a")),
                Map.of(group, List.of("APPLICATION_PREFIX", "TERMINAL_GATE")),
                Map.of(group, List.of("APPLICATION_PREFIX")),
                Set.of(group), Set.of(),
                Map.of(deferredGroup, "BUDGET_CAP"),
                "UNKNOWN").withComputedDigest();

        assertEquals(500, coverage.coveragePermille());
        assertEquals(0, coverage.planReusePermille());
        assertFalse(coverage.complete());
        assertTrue(coverage.toCanonicalJson().contains("PARTIAL_DYNAMIC_BUDGET"));
        assertNotEquals("UNKNOWN", coverage.digest());
    }

    @Test
    void computedDigestChangesWhenPlanMappingChanges() {
        String group = FindingId.fromCanonical("group").value();
        VerificationCoverage first = new VerificationCoverage(
                VerificationCoverage.SCHEMA_VERSION, VerificationCoverage.Status.COMPLETE,
                1, 1, 0, 1, 1, 1,
                Map.of(group, List.of("chain")), Map.of(group, List.of("plan-a")),
                Map.of(group, List.of("TERMINAL_GATE")), Map.of(group, List.of("TERMINAL_GATE")),
                Set.of(), Set.of(group), Map.of(), "UNKNOWN").withComputedDigest();
        VerificationCoverage second = new VerificationCoverage(
                VerificationCoverage.SCHEMA_VERSION, VerificationCoverage.Status.COMPLETE,
                1, 1, 0, 1, 1, 1,
                Map.of(group, List.of("chain")), Map.of(group, List.of("plan-b")),
                Map.of(group, List.of("TERMINAL_GATE")), Map.of(group, List.of("TERMINAL_GATE")),
                Set.of(), Set.of(group), Map.of(), "UNKNOWN").withComputedDigest();

        assertNotEquals(first.digest(), second.digest());
    }
}
