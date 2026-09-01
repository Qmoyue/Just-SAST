package io.just.sast.perf;

import java.util.List;

/**
 * A host-local performance gate.  Absolute thresholds belong to a fixed runner; this type only
 * evaluates the samples and never compares unrelated machines or silently drops outliers.
 */
public final class PerformanceGate {

    public record Result(int samples, long p50Ms, long p95Ms,
                         long p50LimitMs, long p95LimitMs, boolean passed) {
        public Result {
            samples = Math.max(0, samples);
            p50Ms = Math.max(0L, p50Ms);
            p95Ms = Math.max(0L, p95Ms);
            p50LimitMs = Math.max(0L, p50LimitMs);
            p95LimitMs = Math.max(0L, p95LimitMs);
        }
    }

    private PerformanceGate() {
    }

    public static Result evaluate(List<Long> samples, long p50LimitMs, long p95LimitMs) {
        if (samples == null || samples.isEmpty()) {
            return new Result(0, 0L, 0L, p50LimitMs, p95LimitMs, false);
        }
        long p50 = Percentiles.p50(samples);
        long p95 = Percentiles.p95(samples);
        boolean passed = p50 <= Math.max(0L, p50LimitMs)
                && p95 <= Math.max(0L, p95LimitMs);
        return new Result(samples.size(), p50, p95, p50LimitMs, p95LimitMs, passed);
    }
}
