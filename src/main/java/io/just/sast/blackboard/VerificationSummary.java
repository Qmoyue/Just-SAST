package io.just.sast.blackboard;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * 动态验证的持久化快照。它是扫描结果的一部分，而不是 stderr 日志的派生物：
 * 状态、能力边界、失败原因和有限预算内的置信度顺序都必须可复现。
 */
public record VerificationSummary(
        String capability,
        int budget,
        int constructible,
        int rejected,
        int selected,
        Map<String, Integer> statusCounts,
        Map<String, Integer> detailCounts,
        List<ChainResult> results,
        String backend,
        String jdk,
        String policyDigest,
        boolean sinkDistorted,
        boolean sandboxReady,
        String cleanup,
        String artifactHash) {

    public record ChainResult(
            int rank,
            String chainKey,
            String status,
            String detail,
            String confidence,
            int confidenceScore,
            int attempt,
            long durationMs,
            String evidence,
            String backend,
            String jdk,
            String policyDigest,
            boolean sinkDistorted,
            boolean sandboxReady,
            String cleanup) {

        public ChainResult(int rank, String chainKey, String status, String detail,
                           String confidence, int confidenceScore, int attempt,
                           long durationMs) {
            this(rank, chainKey, status, detail, confidence, confidenceScore, attempt,
                    durationMs, null);
        }

        public ChainResult(int rank, String chainKey, String status, String detail,
                           String confidence, int confidenceScore, int attempt,
                           long durationMs, String evidence) {
            this(rank, chainKey, status, detail, confidence, confidenceScore, attempt,
                    durationMs, evidence, "UNKNOWN", "UNKNOWN", "UNKNOWN", false,
                    false, "UNKNOWN");
        }

        public ChainResult {
            chainKey = chainKey == null ? "" : chainKey;
            status = status == null ? "UNKNOWN" : status;
            detail = detail == null ? "" : detail;
            confidence = confidence == null ? "UNKNOWN" : confidence;
            attempt = Math.max(1, attempt);
            durationMs = Math.max(0L, durationMs);
            evidence = evidence == null || evidence.isBlank() ? "UNKNOWN" : evidence;
            backend = normalize(backend);
            jdk = normalize(jdk);
            policyDigest = normalize(policyDigest);
            cleanup = normalize(cleanup);
        }

        private static String normalize(String value) {
            return value == null || value.isBlank() ? "UNKNOWN" : value;
        }
    }

    /** Compatibility constructor for report consumers written before runtime metadata. */
    public VerificationSummary(String capability, int budget, int constructible, int rejected,
                               int selected, Map<String, Integer> statusCounts,
                               Map<String, Integer> detailCounts, List<ChainResult> results) {
        this(capability, budget, constructible, rejected, selected, statusCounts, detailCounts,
                results, "UNKNOWN", "UNKNOWN", "UNKNOWN", false, false, "UNKNOWN", "UNKNOWN");
    }

    /** Compatibility constructor retained for callers that already provide runtime metadata. */
    public VerificationSummary(String capability, int budget, int constructible, int rejected,
                               int selected, Map<String, Integer> statusCounts,
                               Map<String, Integer> detailCounts, List<ChainResult> results,
                               String backend, String jdk, String policyDigest,
                               boolean sinkDistorted, boolean sandboxReady, String cleanup) {
        this(capability, budget, constructible, rejected, selected, statusCounts, detailCounts,
                results, backend, jdk, policyDigest, sinkDistorted, sandboxReady, cleanup,
                "UNKNOWN");
    }

    public VerificationSummary {
        capability = capability == null || capability.isBlank() ? "UNKNOWN" : capability;
        budget = Math.max(0, budget);
        constructible = Math.max(0, constructible);
        rejected = Math.max(0, rejected);
        selected = Math.max(0, selected);
        backend = normalize(backend);
        jdk = normalize(jdk);
        policyDigest = normalize(policyDigest);
        cleanup = normalize(cleanup);
        artifactHash = normalize(artifactHash);
        statusCounts = immutableCounts(statusCounts);
        detailCounts = immutableCounts(detailCounts);
        List<ChainResult> ordered = new ArrayList<>(results == null ? List.of() : results);
        ordered.sort(Comparator.comparingInt(ChainResult::rank)
                .thenComparing(ChainResult::chainKey));
        results = List.copyOf(ordered);
    }

    public static VerificationSummary empty(String capability, int budget) {
        return new VerificationSummary(capability, budget, 0, 0, 0,
                Map.of(), Map.of(), List.of(), "UNKNOWN", "UNKNOWN", "UNKNOWN",
                false, false, "UNKNOWN", "UNKNOWN");
    }

    private static String normalize(String value) {
        return value == null || value.isBlank() ? "UNKNOWN" : value;
    }

    private static Map<String, Integer> immutableCounts(Map<String, Integer> source) {
        Map<String, Integer> sorted = new TreeMap<>();
        if (source != null) {
            source.forEach((key, value) -> {
                if (key != null && !key.isBlank() && value != null && value > 0) {
                    sorted.put(key, value);
                }
            });
        }
        return Map.copyOf(sorted);
    }
}
