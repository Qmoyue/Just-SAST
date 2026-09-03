package io.just.sast.perf;

import io.just.sast.report.ScanStatistics;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.Callable;

/**
 * Fixed-runner measurement contract for scan performance.
 *
 * <p>The harness is deliberately opt-in.  The normal scanner executes one scan and does not
 * pay for warmups or repeated measurements.  A caller supplies the same immutable input/config
 * for every invocation, while this class records the external wall clock and the phase data
 * already published by the scan.  Warmups are discarded, cold/hot runs are therefore explicit
 * in the caller's setup, and no sample is removed as an outlier.</p>
 */
public final class PerformanceHarness {

    /** Non-negative host-local limits; absolute values belong to one fixed runner. */
    public record Limits(long wallP50Ms, long wallP95Ms,
                         long staticP50Ms, long staticP95Ms,
                         long dynamicP50Ms, long dynamicP95Ms) {
        public Limits {
            wallP50Ms = Math.max(0L, wallP50Ms);
            wallP95Ms = Math.max(0L, wallP95Ms);
            staticP50Ms = Math.max(0L, staticP50Ms);
            staticP95Ms = Math.max(0L, staticP95Ms);
            dynamicP50Ms = Math.max(0L, dynamicP50Ms);
            dynamicP95Ms = Math.max(0L, dynamicP95Ms);
        }
    }

    /** One measured invocation; values are normalized so a malformed producer cannot poison a report. */
    public record Sample(int iteration, long wallMs, long staticMs, long dynamicMs,
                         long heapUsedMb, long heapPeakMb, long rssPeakMb,
                         int chainsFound, String completeness, String resultDigest,
                         Map<String, Long> phaseMs, Map<String, Long> resourceMetrics,
                         List<Long> verificationCandidateMs) {
        /** Compatibility constructor for callers that do not provide canonical output bytes. */
        public Sample(int iteration, long wallMs, long staticMs, long dynamicMs,
                      long heapUsedMb, long heapPeakMb, long rssPeakMb,
                      int chainsFound, String completeness) {
            this(iteration, wallMs, staticMs, dynamicMs, heapUsedMb, heapPeakMb, rssPeakMb,
                    chainsFound, completeness, "UNKNOWN", Map.of(), Map.of(), List.of());
        }

        /** Compatibility constructor for callers that already provide a result digest. */
        public Sample(int iteration, long wallMs, long staticMs, long dynamicMs,
                      long heapUsedMb, long heapPeakMb, long rssPeakMb,
                      int chainsFound, String completeness, String resultDigest) {
            this(iteration, wallMs, staticMs, dynamicMs, heapUsedMb, heapPeakMb, rssPeakMb,
                    chainsFound, completeness, resultDigest, Map.of(), Map.of(), List.of());
        }

        /** Compatibility constructor for callers that already provide phase telemetry. */
        public Sample(int iteration, long wallMs, long staticMs, long dynamicMs,
                      long heapUsedMb, long heapPeakMb, long rssPeakMb,
                      int chainsFound, String completeness, String resultDigest,
                      Map<String, Long> phaseMs) {
            this(iteration, wallMs, staticMs, dynamicMs, heapUsedMb, heapPeakMb, rssPeakMb,
                    chainsFound, completeness, resultDigest, phaseMs, Map.of(), List.of());
        }

        public Sample {
            iteration = Math.max(1, iteration);
            wallMs = Math.max(0L, wallMs);
            staticMs = Math.max(0L, staticMs);
            dynamicMs = Math.max(0L, dynamicMs);
            heapUsedMb = Math.max(0L, heapUsedMb);
            heapPeakMb = Math.max(heapUsedMb, heapPeakMb);
            rssPeakMb = rssPeakMb < 0L ? -1L : rssPeakMb;
            chainsFound = Math.max(0, chainsFound);
            completeness = completeness == null || completeness.isBlank()
                    ? "UNKNOWN" : completeness;
            resultDigest = resultDigest == null || resultDigest.isBlank()
                    ? "UNKNOWN" : resultDigest;
            Map<String, Long> normalizedPhases = new TreeMap<>();
            if (phaseMs != null) {
                phaseMs.forEach((key, value) -> {
                    if (key != null && !key.isBlank()) {
                        normalizedPhases.put(key, Math.max(0L, value == null ? 0L : value));
                    }
                });
            }
            phaseMs = Collections.unmodifiableMap(normalizedPhases);
            Map<String, Long> normalizedResources = new TreeMap<>();
            if (resourceMetrics != null) {
                resourceMetrics.forEach((key, value) -> {
                    if (key != null && !key.isBlank() && value != null) {
                        normalizedResources.put(key, value);
                    }
                });
            }
            resourceMetrics = Collections.unmodifiableMap(normalizedResources);
            List<Long> normalizedVerification = new ArrayList<>();
            if (verificationCandidateMs != null) {
                for (Long duration : verificationCandidateMs) {
                    if (duration != null) {
                        normalizedVerification.add(Math.max(0L, duration));
                    }
                }
            }
            verificationCandidateMs = List.copyOf(normalizedVerification);
        }
    }

    /** Aggregated output suitable for a CI gate or a local JSON adapter. */
    public record Report(int warmups, List<Sample> samples,
                         PerformanceGate.Result wall,
                         PerformanceGate.Result staticPhase,
                         PerformanceGate.Result dynamicPhase,
                         long peakHeapMb, long peakRssMb,
                         boolean chainCountStable, boolean completenessStable,
                         Map<String, PerformanceGate.Result> phaseGates) {
        /** Compatibility constructor for consumers written before per-phase percentiles. */
        public Report(int warmups, List<Sample> samples,
                      PerformanceGate.Result wall,
                      PerformanceGate.Result staticPhase,
                      PerformanceGate.Result dynamicPhase,
                      long peakHeapMb, long peakRssMb,
                      boolean chainCountStable, boolean completenessStable) {
            this(warmups, samples, wall, staticPhase, dynamicPhase, peakHeapMb, peakRssMb,
                    chainCountStable, completenessStable, Map.of());
        }

        public Report {
            warmups = Math.max(0, warmups);
            samples = samples == null ? List.of() : List.copyOf(samples);
            peakHeapMb = Math.max(0L, peakHeapMb);
            peakRssMb = peakRssMb < 0L ? -1L : peakRssMb;
            Map<String, PerformanceGate.Result> sorted = new TreeMap<>();
            if (phaseGates != null) {
                phaseGates.forEach((name, gate) -> {
                    if (name != null && !name.isBlank() && gate != null) {
                        sorted.put(name, gate);
                    }
                });
            }
            phaseGates = Collections.unmodifiableMap(sorted);
        }

        public boolean passed() {
            return wall != null && staticPhase != null && dynamicPhase != null
                    && wall.passed() && staticPhase.passed() && dynamicPhase.passed()
                    && chainCountStable && completenessStable && resultDigestStable()
                    && !samples.isEmpty();
        }

        /** Canonical findings are optional for the library API, but mandatory once supplied. */
        public boolean resultDigestStable() {
            String expected = null;
            boolean observed = false;
            for (Sample sample : samples) {
                String digest = sample.resultDigest();
                if (digest == null || digest.isBlank() || "UNKNOWN".equals(digest)) {
                    if (observed) {
                        return false;
                    }
                    continue;
                }
                if (expected == null) {
                    expected = digest;
                    observed = true;
                } else if (!expected.equals(digest)) {
                    return false;
                }
            }
            return true;
        }
    }

    private PerformanceHarness() {
    }

    /** Run warmups and measured invocations against one caller-owned fixed configuration. */
    public static Report run(Callable<ScanStatistics> scan, int warmups,
                             int samples, Limits limits) throws Exception {
        Objects.requireNonNull(scan, "scan");
        Objects.requireNonNull(limits, "limits");
        int normalizedWarmups = Math.max(0, warmups);
        int normalizedSamples = Math.max(0, samples);
        for (int i = 0; i < normalizedWarmups; i++) {
            scan.call();
        }
        List<Sample> measured = new ArrayList<>(normalizedSamples);
        for (int i = 0; i < normalizedSamples; i++) {
            long started = System.nanoTime();
            ScanStatistics statistics = Objects.requireNonNull(scan.call(), "scan result");
            long wallMs = elapsedMs(started);
            measured.add(sample(i + 1, wallMs, statistics));
        }
        return report(normalizedWarmups, measured, limits);
    }

    /** Assemble a report from already measured samples for external runners and replay tests. */
    public static Report report(int warmups, List<Sample> samples, Limits limits) {
        Objects.requireNonNull(limits, "limits");
        List<Sample> stable = samples == null ? List.of() : List.copyOf(samples);
        List<Long> wall = values(stable, Dimension.WALL);
        List<Long> staticPhase = values(stable, Dimension.STATIC);
        List<Long> dynamicCandidates = verificationCandidateValues(stable);
        List<Long> dynamic = dynamicCandidates.isEmpty()
                ? values(stable, Dimension.DYNAMIC) : dynamicCandidates;
        PerformanceGate.Result wallGate = PerformanceGate.evaluate(wall,
                limits.wallP50Ms(), limits.wallP95Ms());
        PerformanceGate.Result staticGate = PerformanceGate.evaluate(staticPhase,
                limits.staticP50Ms(), limits.staticP95Ms());
        PerformanceGate.Result dynamicGate = PerformanceGate.evaluate(dynamic,
                limits.dynamicP50Ms(), limits.dynamicP95Ms());
        return new Report(Math.max(0, warmups), stable, wallGate, staticGate, dynamicGate,
                maxHeap(stable), maxRss(stable), stableInt(stable, true), stableCompleteness(stable),
                phaseGates(stable, dynamicCandidates));
    }

    /**
     * Compute percentiles for every phase that was actually published by at least one sample.
     * Missing telemetry is not converted to zero: a phase with no observation has no gate result,
     * while a phase observed in only part of a run retains its smaller explicit sample count.
     */
    private static Map<String, PerformanceGate.Result> phaseGates(List<Sample> samples,
                                                                   List<Long> candidates) {
        TreeSet<String> names = new TreeSet<>();
        for (Sample sample : samples) {
            names.addAll(sample.phaseMs().keySet());
        }
        Map<String, PerformanceGate.Result> result = new TreeMap<>();
        for (String name : names) {
            List<Long> values = new ArrayList<>();
            for (Sample sample : samples) {
                Long value = sample.phaseMs().get(name);
                if (value != null) {
                    values.add(Math.max(0L, value));
                }
            }
            result.put(name, PerformanceGate.evaluate(values, Long.MAX_VALUE, Long.MAX_VALUE));
        }
        if (candidates != null && !candidates.isEmpty()) {
            result.put("verify.candidate", PerformanceGate.evaluate(candidates,
                    Long.MAX_VALUE, Long.MAX_VALUE));
        }
        return result;
    }

    private static Sample sample(int iteration, long wallMs, ScanStatistics statistics) {
        return sample(iteration, wallMs, statistics, "UNKNOWN");
    }

    /** Build a sample while allowing an external runner to attach canonical output identity. */
    public static Sample sample(int iteration, long wallMs, ScanStatistics statistics,
                                String resultDigest) {
        return sample(iteration, wallMs, statistics, resultDigest, statistics.phaseMs(),
                resourceMetrics(statistics));
    }

    /** Build a sample with the phase telemetry published by the scan pipeline. */
    public static Sample sample(int iteration, long wallMs, ScanStatistics statistics,
                                String resultDigest, Map<String, Long> phaseMs) {
        return sample(iteration, wallMs, statistics, resultDigest, phaseMs,
                resourceMetrics(statistics));
    }

    /** Build a sample with phase and runner resource telemetry. */
    public static Sample sample(int iteration, long wallMs, ScanStatistics statistics,
                                String resultDigest, Map<String, Long> phaseMs,
                                Map<String, Long> resourceMetrics) {
        return sample(iteration, wallMs, statistics, resultDigest, phaseMs, resourceMetrics,
                verificationCandidateMs(statistics));
    }

    /** Build a sample with phase, runner and per-candidate verification telemetry. */
    public static Sample sample(int iteration, long wallMs, ScanStatistics statistics,
                                String resultDigest, Map<String, Long> phaseMs,
                                Map<String, Long> resourceMetrics,
                                List<Long> verificationCandidateMs) {
        Objects.requireNonNull(statistics, "statistics");
        long staticMs = statistics.phaseMs("static", -1L);
        if (staticMs < 0L) {
            staticMs = staticPhaseMs(statistics);
        }
        long dynamicMs = statistics.phaseMs("verify", 0L);
        long rssPeak = statistics.metric("parent_rss_mb",
                statistics.metric("rss_peak_mb", -1L));
        return new Sample(iteration, wallMs, staticMs, dynamicMs,
                statistics.heapUsedMb(), statistics.heapPeakMb(), rssPeak,
                statistics.chainsFound(), statistics.completeness(), resultDigest, phaseMs,
                resourceMetrics, verificationCandidateMs);
    }

    private static List<Long> verificationCandidateMs(ScanStatistics statistics) {
        if (statistics == null || statistics.dynamicVerification() == null) {
            return List.of();
        }
        List<Long> result = new ArrayList<>();
        statistics.dynamicVerification().results().forEach(item -> {
            if (item != null) {
                result.add(Math.max(0L, item.durationMs()));
            }
        });
        return List.copyOf(result);
    }

    private static List<Long> verificationCandidateValues(List<Sample> samples) {
        List<Long> values = new ArrayList<>();
        for (Sample sample : samples) {
            values.addAll(sample.verificationCandidateMs());
        }
        return values;
    }

    private static Map<String, Long> resourceMetrics(ScanStatistics statistics) {
        Map<String, Long> result = new TreeMap<>();
        statistics.metrics().forEach((name, value) -> {
            if (name != null && (name.startsWith("parent_") || name.startsWith("child_")
                    || name.startsWith("scratch_") || name.startsWith("uncollected_")
                    || name.startsWith("cleanup_") || "rss_peak_mb".equals(name))) {
                result.put(name, value);
            }
        });
        return result;
    }

    private static long staticPhaseMs(ScanStatistics statistics) {
        long total = 0L;
        boolean found = false;
        for (var entry : statistics.phaseMs().entrySet()) {
            String key = entry.getKey();
            if (key == null || key.equals("verify") || key.startsWith("verify.")
                    || key.equals("report") || key.startsWith("report.")) {
                continue;
            }
            total = saturatedAdd(total, Math.max(0L, entry.getValue() == null
                    ? 0L : entry.getValue()));
            found = true;
        }
        return found ? total : statistics.elapsedMs();
    }

    private enum Dimension { WALL, STATIC, DYNAMIC }

    private static List<Long> values(List<Sample> samples, Dimension dimension) {
        List<Long> values = new ArrayList<>(samples.size());
        for (Sample sample : samples) {
            values.add(switch (dimension) {
                case WALL -> sample.wallMs();
                case STATIC -> sample.staticMs();
                case DYNAMIC -> sample.dynamicMs();
            });
        }
        return values;
    }

    private static long maxHeap(List<Sample> samples) {
        long max = 0L;
        for (Sample sample : samples) {
            max = Math.max(max, sample.heapPeakMb());
        }
        return max;
    }

    private static long maxRss(List<Sample> samples) {
        long max = -1L;
        for (Sample sample : samples) {
            if (sample.rssPeakMb() >= 0L) {
                max = Math.max(max, sample.rssPeakMb());
            }
        }
        return max;
    }

    private static boolean stableInt(List<Sample> samples, boolean chains) {
        if (samples.isEmpty()) {
            return false;
        }
        int expected = chains ? samples.get(0).chainsFound() : 0;
        for (Sample sample : samples) {
            if (chains && sample.chainsFound() != expected) {
                return false;
            }
        }
        return true;
    }

    private static boolean stableCompleteness(List<Sample> samples) {
        if (samples.isEmpty()) {
            return false;
        }
        String expected = samples.get(0).completeness();
        return samples.stream().allMatch(sample -> expected.equals(sample.completeness()));
    }

    private static long elapsedMs(long started) {
        long nanos = Math.max(0L, System.nanoTime() - started);
        return nanos / 1_000_000L;
    }

    private static long saturatedAdd(long left, long right) {
        return Long.MAX_VALUE - left < right ? Long.MAX_VALUE : left + right;
    }
}
