package io.just.sast.report;

import io.just.sast.blackboard.VerificationSummary;
import io.just.sast.run.RunOutcome;

import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/** 扫描统计。 */
public record ScanStatistics(
        int filesScanned, int classesLoaded, int diagnostics,
        int sinksMarked, int magicEntries, int chainsFound,
        long elapsedMs, long heapUsedMb, long heapPeakMb,
        String completeness, List<String> completenessReasons,
        Map<String, Long> phaseMs, Map<String, Long> metrics, String verification,
        VerificationSummary dynamicVerification, String chainProofCompleteness,
        String artifactHash, Map<String, String> metricStatus,
        Map<String, Map<String, Long>> metricNamespaces,
        Map<String, String> metricNamespaceStatus) {

    /** Closed availability states for telemetry.  UNKNOWN is intentionally distinct from 0. */
    public enum MetricStatus {
        OBSERVED, CANDIDATE_ONLY, UNKNOWN, NOT_APPLICABLE, NOT_REQUESTED
    }

    public ScanStatistics {
        completeness = completeness == null ? "UNKNOWN" : completeness;
        heapUsedMb = Math.max(0L, heapUsedMb);
        heapPeakMb = Math.max(heapUsedMb, heapPeakMb);
        completenessReasons = completenessReasons == null ? List.of() : completenessReasons.stream()
                .filter(reason -> reason != null && !reason.isBlank())
                .distinct().sorted().toList();
        phaseMs = sortedMap(phaseMs);
        metrics = sortedMap(metrics);
        verification = verification == null ? "UNKNOWN" : verification;
        dynamicVerification = dynamicVerification == null
                ? VerificationSummary.empty(verification, 0) : dynamicVerification;
        chainProofCompleteness = chainProofCompleteness == null
                ? "UNKNOWN" : chainProofCompleteness;
        artifactHash = artifactHash == null || artifactHash.isBlank()
                ? "UNKNOWN" : artifactHash;
        metricStatus = sortedStatusMap(metricStatus);
        metricNamespaces = sortedNamespaceMap(metricNamespaces);
        metricNamespaceStatus = sortedStatusMap(metricNamespaceStatus);
    }

    /** 兼容旧扩展点和测试构造。 */
    public ScanStatistics(int filesScanned, int classesLoaded, int diagnostics,
                          int sinksMarked, int magicEntries, int chainsFound,
                          long elapsedMs, long heapUsedMb) {
        this(filesScanned, classesLoaded, diagnostics, sinksMarked, magicEntries, chainsFound,
                elapsedMs, heapUsedMb, heapUsedMb, "UNKNOWN", List.of(), Map.of(), Map.of(),
                "UNKNOWN", VerificationSummary.empty("UNKNOWN", 0), "UNKNOWN", "UNKNOWN",
                Map.of(), Map.of(), Map.of());
    }

    /** Compatibility constructor retained for callers that do not sample heap peak usage. */
    public ScanStatistics(int filesScanned, int classesLoaded, int diagnostics,
                          int sinksMarked, int magicEntries, int chainsFound,
                          long elapsedMs, long heapUsedMb,
                          String completeness, List<String> completenessReasons,
                          Map<String, Long> phaseMs, String verification,
                          VerificationSummary dynamicVerification) {
        this(filesScanned, classesLoaded, diagnostics, sinksMarked, magicEntries, chainsFound,
                elapsedMs, heapUsedMb, heapUsedMb, completeness, completenessReasons, phaseMs,
                Map.of(), verification, dynamicVerification, "UNKNOWN", "UNKNOWN",
                Map.of(), Map.of(), Map.of());
    }

    /** Compatibility constructor retained for callers that already provide proof completeness. */
    public ScanStatistics(int filesScanned, int classesLoaded, int diagnostics,
                          int sinksMarked, int magicEntries, int chainsFound,
                          long elapsedMs, long heapUsedMb, long heapPeakMb,
                          String completeness, List<String> completenessReasons,
                          Map<String, Long> phaseMs, Map<String, Long> metrics,
                          String verification, VerificationSummary dynamicVerification,
                          String chainProofCompleteness) {
        this(filesScanned, classesLoaded, diagnostics, sinksMarked, magicEntries, chainsFound,
                elapsedMs, heapUsedMb, heapPeakMb, completeness, completenessReasons, phaseMs,
                metrics, verification, dynamicVerification, chainProofCompleteness, "UNKNOWN");
    }

    /** Full compatibility constructor before metric availability/namespaces were added. */
    public ScanStatistics(int filesScanned, int classesLoaded, int diagnostics,
                          int sinksMarked, int magicEntries, int chainsFound,
                          long elapsedMs, long heapUsedMb, long heapPeakMb,
                          String completeness, List<String> completenessReasons,
                          Map<String, Long> phaseMs, Map<String, Long> metrics,
                          String verification, VerificationSummary dynamicVerification,
                          String chainProofCompleteness, String artifactHash) {
        this(filesScanned, classesLoaded, diagnostics, sinksMarked, magicEntries, chainsFound,
                elapsedMs, heapUsedMb, heapPeakMb, completeness, completenessReasons, phaseMs,
                metrics, verification, dynamicVerification, chainProofCompleteness, artifactHash,
                Map.of(), Map.of(), Map.of());
    }

    public static ScanStatistics empty() {
        return new ScanStatistics(0, 0, 0, 0, 0, 0, 0, 0,
                0, "UNKNOWN", List.of(), Map.of(), Map.of(), "UNKNOWN",
                VerificationSummary.empty("UNKNOWN", 0), "UNKNOWN", "UNKNOWN",
                Map.of(), Map.of(), Map.of());
    }

    /** Read an optional numeric metric without exposing a mutable map to callers. */
    public long metric(String name, long fallback) {
        if (name == null) {
            return fallback;
        }
        Long value = metrics.get(name);
        return value == null ? fallback : value;
    }

    /** Availability is a separate axis from the numeric value; missing telemetry is not zero. */
    public String metricStatus(String name) {
        if (name == null) {
            return MetricStatus.UNKNOWN.name();
        }
        return metricStatus.getOrDefault(name, MetricStatus.UNKNOWN.name());
    }

    public Map<String, Long> metricNamespace(String name) {
        if (name == null) {
            return Map.of();
        }
        return metricNamespaces.getOrDefault(name, Map.of());
    }

    public String metricNamespaceStatus(String name) {
        if (name == null) {
            return MetricStatus.UNKNOWN.name();
        }
        return metricNamespaceStatus.getOrDefault(name, MetricStatus.UNKNOWN.name());
    }

    /** Sum a stable phase family; missing phase detail falls back to the total scan time. */
    public long phaseMs(String prefix, long fallback) {
        if (prefix == null || prefix.isBlank()) {
            return fallback;
        }
        long total = 0L;
        boolean found = false;
        for (Map.Entry<String, Long> phase : phaseMs.entrySet()) {
            if (phase.getKey() != null && (phase.getKey().equals(prefix)
                    || phase.getKey().startsWith(prefix + "."))) {
                total = saturatedAdd(total, Math.max(0L, phase.getValue() == null
                        ? 0L : phase.getValue()));
                found = true;
            }
        }
        return found ? total : fallback;
    }

    /** Canonical run classification shared by cache, CLI and report consumers. */
    public RunOutcome runOutcome() {
        return RunOutcome.forScan(completeness, chainProofCompleteness,
                dynamicVerification == null ? List.of() : dynamicVerification.statusCounts().keySet());
    }

    private static long saturatedAdd(long left, long right) {
        if (Long.MAX_VALUE - left < right) {
            return Long.MAX_VALUE;
        }
        return left + right;
    }

    private static Map<String, Long> sortedMap(Map<String, Long> values) {
        if (values == null || values.isEmpty()) {
            return Map.of();
        }
        Map<String, Long> sorted = new TreeMap<>();
        values.forEach((key, value) -> {
            if (key != null && !key.isBlank() && value != null) {
                sorted.put(key, value);
            }
        });
        return sorted.isEmpty() ? Map.of()
                : java.util.Collections.unmodifiableMap(sorted);
    }

    private static Map<String, String> sortedStatusMap(Map<String, String> values) {
        if (values == null || values.isEmpty()) {
            return Map.of();
        }
        Map<String, String> sorted = new TreeMap<>();
        values.forEach((key, value) -> {
            if (key == null || key.isBlank() || value == null || value.isBlank()) {
                return;
            }
            String normalized = value.trim().toUpperCase(java.util.Locale.ROOT);
            try {
                MetricStatus.valueOf(normalized);
                sorted.put(key, normalized);
            } catch (IllegalArgumentException ignored) {
                // Unknown producer states are made explicit instead of leaking an open enum.
                sorted.put(key, MetricStatus.UNKNOWN.name());
            }
        });
        return sorted.isEmpty() ? Map.of()
                : java.util.Collections.unmodifiableMap(sorted);
    }

    private static Map<String, Map<String, Long>> sortedNamespaceMap(
            Map<String, Map<String, Long>> values) {
        if (values == null || values.isEmpty()) {
            return Map.of();
        }
        Map<String, Map<String, Long>> sorted = new TreeMap<>();
        values.forEach((namespace, metrics) -> {
            if (namespace == null || namespace.isBlank()) {
                return;
            }
            sorted.put(namespace, sortedMap(metrics));
        });
        return sorted.isEmpty() ? Map.of()
                : java.util.Collections.unmodifiableMap(sorted);
    }
}
