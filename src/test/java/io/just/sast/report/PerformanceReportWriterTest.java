package io.just.sast.report;

import io.just.sast.perf.PerformanceHarness;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PerformanceReportWriterTest {

    @Test
    void writesPathFreeStableGateAndSamples() {
        PerformanceHarness.Report report = PerformanceHarness.report(1, List.of(
                new PerformanceHarness.Sample(1, 10, 7, 3, 4, 5, -1, 2, "COMPLETE"),
                new PerformanceHarness.Sample(2, 11, 8, 3, 4, 6, -1, 2, "COMPLETE")),
                new PerformanceHarness.Limits(Long.MAX_VALUE, Long.MAX_VALUE,
                        Long.MAX_VALUE, Long.MAX_VALUE, Long.MAX_VALUE, Long.MAX_VALUE));

        String json = PerformanceReportWriter.json(report, "hot");

        assertTrue(json.contains("\"mode\":\"hot\""));
        assertTrue(json.contains("\"p50_limit_ms\":null"));
        assertTrue(json.contains("\"sample_count\":2"));
        assertTrue(json.contains("\"completeness\":\"COMPLETE\""));
        assertTrue(json.contains("\"result_digest_stable\":true"));
        assertTrue(json.contains("\"phase_ms\":{}"));
        assertTrue(json.contains("\"resource_metrics\":{}"));
        assertTrue(json.contains("\"phase_gates\":{}"));
        assertFalse(json.contains("C:\\"), "性能产物不得写入本机绝对路径");
    }
}
