package io.just.sast.report;

import io.just.sast.blackboard.VerificationSummary;

import java.util.List;
import java.util.Map;

/** 扫描统计。 */
public record ScanStatistics(
        int filesScanned, int classesLoaded, int diagnostics,
        int sinksMarked, int magicEntries, int chainsFound,
        long elapsedMs, long heapUsedMb,
        String completeness, List<String> completenessReasons,
        Map<String, Long> phaseMs, String verification,
        VerificationSummary dynamicVerification) {

    public ScanStatistics {
        completeness = completeness == null ? "UNKNOWN" : completeness;
        completenessReasons = completenessReasons == null ? List.of() : List.copyOf(completenessReasons);
        phaseMs = phaseMs == null ? Map.of() : Map.copyOf(phaseMs);
        verification = verification == null ? "UNKNOWN" : verification;
        dynamicVerification = dynamicVerification == null
                ? VerificationSummary.empty(verification, 0) : dynamicVerification;
    }

    /** 兼容旧扩展点和测试构造。 */
    public ScanStatistics(int filesScanned, int classesLoaded, int diagnostics,
                          int sinksMarked, int magicEntries, int chainsFound,
                          long elapsedMs, long heapUsedMb) {
        this(filesScanned, classesLoaded, diagnostics, sinksMarked, magicEntries, chainsFound,
                elapsedMs, heapUsedMb, "UNKNOWN", List.of(), Map.of(), "UNKNOWN",
                VerificationSummary.empty("UNKNOWN", 0));
    }

    public static ScanStatistics empty() {
        return new ScanStatistics(0, 0, 0, 0, 0, 0, 0, 0,
                "UNKNOWN", List.of(), Map.of(), "UNKNOWN",
                VerificationSummary.empty("UNKNOWN", 0));
    }
}
