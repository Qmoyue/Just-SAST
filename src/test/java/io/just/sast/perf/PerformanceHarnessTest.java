package io.just.sast.perf;

import io.just.sast.report.ScanStatistics;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PerformanceHarnessTest {

    @Test
    void warmupsAreExcludedAndPhaseFamiliesAreMeasured() throws Exception {
        AtomicInteger calls = new AtomicInteger();
        PerformanceHarness.Limits limits = new PerformanceHarness.Limits(
                10_000L, 10_000L, 10_000L, 10_000L, 10_000L, 10_000L);

        PerformanceHarness.Report report = PerformanceHarness.run(() -> {
            calls.incrementAndGet();
            return statistics(2, "COMPLETE", 7L, 3L);
        }, 1, 3, limits);

        assertEquals(4, calls.get());
        assertEquals(1, report.warmups());
        assertEquals(3, report.samples().size());
        assertEquals(3, report.wall().samples());
        assertEquals(7L, report.samples().get(0).staticMs());
        assertEquals(3L, report.samples().get(0).filterMs());
        assertEquals(7L, report.samples().get(0).phaseMs().get("frontend"));
        assertEquals(3, report.phaseGates().get("filter").samples());
        assertEquals(3L, report.phaseGates().get("filter").p50Ms());
        assertEquals(3L, report.phaseGates().get("filter").p95Ms());
        assertTrue(report.chainCountStable());
        assertTrue(report.completenessStable());
        assertTrue(report.resultDigestStable());
        assertTrue(report.passed());
    }

    @Test
    void replayReportRejectsNondeterministicResultsAndExposesRssIfPresent() {
        PerformanceHarness.Limits limits = new PerformanceHarness.Limits(
                100L, 100L, 100L, 100L, 100L, 100L);
        PerformanceHarness.Report report = PerformanceHarness.report(0, List.of(
                new PerformanceHarness.Sample(1, 10L, 6L, 4L, 10L, 12L, 21L,
                        2, "COMPLETE"),
                new PerformanceHarness.Sample(2, 11L, 7L, 4L, 11L, 13L, 23L,
                        3, "PARTIAL")), limits);

        assertFalse(report.passed());
        assertFalse(report.chainCountStable());
        assertFalse(report.completenessStable());
        assertTrue(report.resultDigestStable(), "旧版调用方未提供摘要时不应被误判为不稳定");
        assertEquals(23L, report.peakRssMb());
        assertEquals(13L, report.peakHeapMb());
    }

    @Test
    void canonicalDigestDifferenceFailsTheDeterminismGate() {
        PerformanceHarness.Report report = PerformanceHarness.report(0, List.of(
                new PerformanceHarness.Sample(1, 10L, 6L, 0L, 1L, 2L, -1L,
                        2, "COMPLETE", "aaaaaaaa"),
                new PerformanceHarness.Sample(2, 10L, 6L, 0L, 1L, 2L, -1L,
                        2, "COMPLETE", "bbbbbbbb")),
                new PerformanceHarness.Limits(100L, 100L, 100L, 100L, 100L, 100L));

        assertFalse(report.resultDigestStable());
        assertFalse(report.passed());
    }

    @Test
    void filterPhaseDrivesFilterGate() {
        PerformanceHarness.Limits limits = new PerformanceHarness.Limits(
                100L, 100L, 100L, 100L, 10L, 20L);
        PerformanceHarness.Report report = PerformanceHarness.report(0, List.of(
                new PerformanceHarness.Sample(1, 10L, 6L, 4L, 1L, 2L, -1L,
                        1, "COMPLETE", "same", Map.of(), Map.of()),
                new PerformanceHarness.Sample(2, 10L, 6L, 8L, 1L, 2L, -1L,
                        1, "COMPLETE", "same", Map.of(), Map.of())), limits);

        assertEquals(4L, report.filterPhase().p50Ms());
        assertEquals(8L, report.filterPhase().p95Ms());
        assertTrue(report.passed());
    }

    private static ScanStatistics statistics(int chains, String completeness,
                                             long staticMs, long filterMs) {
        return new ScanStatistics(1, 1, 0, 1, 1, chains,
                staticMs + filterMs, 4L, 5L, completeness, List.of(),
                Map.of("frontend", staticMs, "filter", filterMs),
                Map.of("rss_peak_mb", 8L), "COMPLETE", null, "COMPLETE");
    }
}
