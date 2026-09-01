package io.just.sast.report;

import io.just.sast.blackboard.VerificationSummary;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

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
        completenessReasons = completenessReasons == null ? List.of() : List.copyOf(completenessReasons);
        phaseMs = phaseMs == null ? Map.of()
                : java.util.Collections.unmodifiableMap(new LinkedHashMap<>(phaseMs));
        metrics = metrics == null ? Map.of()
                : java.util.Collections.unmodifiableMap(new LinkedHashMap<>(metrics));
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
}
