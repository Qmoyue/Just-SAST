package io.just.sast.knowledge.engine;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Contract for the immutable forward telemetry boundary consumed by report metadata. */
class ForwardRunMetricsContractTest {

    @Test
    void snapshotConversionPublishesCountersAndStructuralEstimate() {
        ForwardStateStore store = new ForwardStateStore();
        store.configureBudget(10, 3, 2);
        store.worklist().offer("pkg/Owner#run()V");
        store.recordStep();
        store.recordMethodPass();
        store.recordRound();
        store.recordPrimaryFact();
        store.recordAlternativeFact();

        ForwardRunMetrics metrics = ForwardRunMetrics.from(store.snapshot(),
                ForwardRunMetrics.Pass.REFINED, false);

        assertEquals(ForwardRunMetrics.Pass.REFINED, metrics.pass());
        assertEquals(2L, metrics.factCount());
        assertEquals(1L, metrics.rounds());
        assertEquals(1L, metrics.acceptedWorkItems());
        assertEquals(1, metrics.peakPendingWorkItems());
        assertTrue(metrics.estimatedStateBytes() > 0L);
        Map<String, Long> values = metrics.asMetrics();
        assertEquals(2L, values.get("forward_fact_count"));
        assertEquals(metrics.estimatedStateBytes(), values.get("forward_state_bytes_estimate"));
    }

    @Test
    void malformedTelemetryIsRejectedAndMetricMapIsImmutable() {
        assertThrows(IllegalArgumentException.class, () -> new ForwardRunMetrics(
                ForwardRunMetrics.Pass.UNKNOWN, false, 0, 1, 1,
                0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0));

        ForwardStateStore store = new ForwardStateStore();
        ForwardRunMetrics metrics = ForwardRunMetrics.from(store.snapshot(),
                ForwardRunMetrics.Pass.UNKNOWN, false);
        Map<String, Long> values = metrics.asMetrics();
        assertThrows(UnsupportedOperationException.class,
                () -> values.put("forward_steps", 99L));
    }
}
