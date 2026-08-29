package io.just.sast.blackboard;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class VerificationSummaryTest {

    @Test
    void snapshotNormalizesCountsAndOrdersResults() {
        VerificationSummary summary = new VerificationSummary(
                "JVM_SANDBOX", 20, 3, 1, 2,
                Map.of("PARTIAL", 1, "CONFIRMED", 1),
                Map.of("z-reason", 1, "a-reason", 2),
                List.of(
                        new VerificationSummary.ChainResult(2, "z", "PARTIAL",
                                "z-detail", "DEGRADED", 4, 1, 8),
                        new VerificationSummary.ChainResult(1, "a", "CONFIRMED",
                                "SINK_REACHED", "HIGH", 9, 1, 3)));

        assertEquals(List.of("a", "z"), summary.results().stream()
                .map(VerificationSummary.ChainResult::chainKey).toList());
        assertEquals(2, summary.statusCounts().get("CONFIRMED")
                + summary.statusCounts().get("PARTIAL"));
        assertThrows(UnsupportedOperationException.class,
                () -> summary.results().add(summary.results().get(0)));
    }
}
