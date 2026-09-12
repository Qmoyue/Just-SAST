package io.just.sast.report;

import io.just.sast.blackboard.VerificationSummary;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Characterizes the metric contract: zero is observed, -1 is unknown, and status is closed. */
class ScanStatisticsMetricContractTest {

    @Test
    void preservesUnknownSeparatelyFromObservedZeroAndSortsNamespaces() {
        ScanStatistics stats = new ScanStatistics(
                1, 1, 0, 0, 0, 0, 1, 1, 1, "COMPLETE", List.of(),
                Map.of(), Map.of("observed_zero", 0L, "unknown_value", -1L),
                "DISABLED", VerificationSummary.empty("DISABLED", 0), "UNKNOWN", "hash",
                Map.of("observed_zero", "observed", "unknown_value", "unknown",
                        "bad", "future-state"),
                Map.of("kernel", Map.of("kernel_only_results", -1L),
                        "application", Map.of("entries", 0L)),
                Map.of("kernel", "not_requested", "application", "candidate_only"));

        assertEquals(0L, stats.metric("observed_zero", -1L));
        assertEquals(-1L, stats.metric("unknown_value", 0L));
        assertEquals("OBSERVED", stats.metricStatus("observed_zero"));
        assertEquals("UNKNOWN", stats.metricStatus("unknown_value"));
        assertEquals("UNKNOWN", stats.metricStatus("bad"));
        assertEquals("CANDIDATE_ONLY", stats.metricNamespaceStatus("application"));
        assertEquals(-1L, stats.metricNamespace("kernel").get("kernel_only_results"));
        assertTrue(stats.metricNamespaces().keySet().stream().toList()
                .equals(List.of("application", "kernel")));
    }
}
