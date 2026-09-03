package io.just.sast.report;

import io.just.sast.blackboard.VerificationSummary;

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
        String artifactHash) {

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
    }

    /** 兼容旧扩展点和测试构造。 */
    public ScanStatistics(int filesScanned, int classesLoaded, int diagnostics,
                          int sinksMarked, int magicEntries, int chainsFound,
                          long elapsedMs, long heapUsedMb) {
        this(filesScanned, classesLoaded, diagnostics, sinksMarked, magicEntries, chainsFound,
                elapsedMs, heapUsedMb, heapUsedMb, "UNKNOWN", List.of(), Map.of(), Map.of(),
                "UNKNOWN", VerificationSummary.empty("UNKNOWN", 0), "UNKNOWN", "UNKNOWN");
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
                Map.of(), verification, dynamicVerification, "UNKNOWN", "UNKNOWN");
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

    public static ScanStatistics empty() {
        return new ScanStatistics(0, 0, 0, 0, 0, 0, 0, 0,
                0, "UNKNOWN", List.of(), Map.of(), Map.of(), "UNKNOWN",
                VerificationSummary.empty("UNKNOWN", 0), "UNKNOWN", "UNKNOWN");
    }

    /** Read an optional numeric metric without exposing a mutable map to callers. */
    public long metric(String name, long fallback) {
        if (name == null) {
            return fallback;
        }
        Long value = metrics.get(name);
        return value == null ? fallback : value;
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
}
