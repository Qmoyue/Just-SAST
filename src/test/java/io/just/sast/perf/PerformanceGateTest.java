package io.just.sast.perf;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PerformanceGateTest {

    @Test
    void percentilesUseNearestRankAndDoNotMutateSamples() {
        List<Long> samples = List.of(40L, 10L, 30L, 20L, 50L);

        assertEquals(30L, Percentiles.p50(samples));
        assertEquals(50L, Percentiles.p95(samples));
        assertEquals(List.of(40L, 10L, 30L, 20L, 50L), samples);
    }

    @Test
    void gateRequiresBothP50AndP95() {
        PerformanceGate.Result pass = PerformanceGate.evaluate(List.of(10L, 20L, 30L, 40L),
                30L, 40L);
        PerformanceGate.Result fail = PerformanceGate.evaluate(List.of(10L, 20L, 30L, 90L),
                30L, 40L);

        assertTrue(pass.passed());
        assertFalse(fail.passed());
        assertEquals(4, fail.samples());
    }
}
