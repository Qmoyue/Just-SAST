package io.just.sast.perf;

import java.util.ArrayList;
import java.util.List;

/** Small deterministic percentile helper for the fixed-runner performance contract. */
public final class Percentiles {

    private Percentiles() {
    }

    /**
     * Return the nearest-rank percentile from non-negative millisecond samples.
     * Empty input is represented by {@code 0}; callers must keep sample count in their report.
     */
    public static long nearestRank(List<Long> samples, double percentile) {
        if (samples == null || samples.isEmpty()) {
            return 0L;
        }
        if (Double.isNaN(percentile) || percentile < 0.0 || percentile > 1.0) {
            throw new IllegalArgumentException("percentile must be between 0 and 1");
        }
        List<Long> ordered = new ArrayList<>(samples.size());
        for (Long sample : samples) {
            if (sample == null || sample < 0L) {
                throw new IllegalArgumentException("samples must be non-negative");
            }
            ordered.add(sample);
        }
        ordered.sort(Long::compareTo);
        int rank = (int) Math.ceil(percentile * ordered.size());
        int index = Math.max(0, Math.min(ordered.size() - 1, rank - 1));
        return ordered.get(index);
    }

    public static long p50(List<Long> samples) {
        return nearestRank(samples, 0.50);
    }

    public static long p95(List<Long> samples) {
        return nearestRank(samples, 0.95);
    }
}
