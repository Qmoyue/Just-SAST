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
        String artifactHash,
        String isolationLevel,
        List<String> isolationCapabilities,
        String attestationVersion) {

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
            String cleanup, String requestedMode, String effectiveMode,
            String fallback, String verificationScope, String sinkRisk,
            boolean terminalExecuted, String stopReason, String lastConfirmedStage) {

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

        /** Compatibility constructor retained for report consumers before scope metadata. */
        public ChainResult(int rank, String chainKey, String status, String detail,
                           String confidence, int confidenceScore, int attempt,
                           long durationMs, String evidence, String backend, String jdk,
                           String policyDigest, boolean sinkDistorted, boolean sandboxReady,
                           String cleanup) {
            this(rank, chainKey, status, detail, confidence, confidenceScore, attempt,
                    durationMs, evidence, backend, jdk, policyDigest, sinkDistorted,
                    sandboxReady, cleanup,
                    field(detail, "requested_mode", "UNKNOWN"),
                    field(detail, "effective_mode", "UNKNOWN"),
                    field(detail, "fallback", "none"), defaultScope(status), "UNKNOWN",
                    defaultTerminalExecuted(status), defaultStopReason(status, detail),
                    defaultLastStage(status));
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
            requestedMode = normalize(requestedMode);
            effectiveMode = normalize(effectiveMode);
            fallback = normalize(fallback);
            verificationScope = normalize(verificationScope);
            sinkRisk = normalize(sinkRisk);
            stopReason = normalize(stopReason);
            lastConfirmedStage = normalize(lastConfirmedStage);
        }

        private static String normalize(String value) {
            return value == null || value.isBlank() ? "UNKNOWN" : value;
        }

        private static String field(String detail, String name, String fallback) {
            if (detail == null) return fallback;
            String marker = name + "=";
            int start = detail.indexOf(marker);
            if (start < 0) return fallback;
            start += marker.length();
            int end = detail.indexOf(';', start);
            String value = end < 0 ? detail.substring(start) : detail.substring(start, end);
            return value.isBlank() ? fallback : value;
        }

        private static String defaultScope(String status) {
            return switch (status == null ? "" : status) {
                case "SINK_BLOCKED" -> "BOUNDARY_ONLY";
                case "PRE_SINK_CONFIRMED" -> "PREFIX_ONLY";
                case "SINK_EXECUTED_SAFE", "JNI_EXECUTED_SAFE" -> "TERMINAL_EXECUTED_SAFE";
                default -> "NONE";
            };
        }

        private static boolean defaultTerminalExecuted(String status) {
            return "SINK_EXECUTED_SAFE".equals(status) || "JNI_EXECUTED_SAFE".equals(status);
        }

        private static String defaultStopReason(String status, String detail) {
            if ("SINK_BLOCKED".equals(status)) return "SINK_BOUNDARY_CANARY";
            if ("PRE_SINK_CONFIRMED".equals(status)) return "HIGH_RISK_SINK";
            if ("SINK_EXECUTED_SAFE".equals(status)
                    || "JNI_EXECUTED_SAFE".equals(status)) return "SAFE_TERMINAL_RETURNED";
            if ("SAFE_EFFECT_OBSERVED".equals(status)) return "ADAPTER_EFFECT_ONLY";
            if ("TIMEOUT".equals(status)) return "PROCESS_TIMEOUT";
            if ("UNTESTABLE".equals(status) && detail != null
                    && detail.startsWith("SANDBOX_UNAVAILABLE")) return "SANDBOX_UNAVAILABLE";
            return "NONE";
        }

        private static String defaultLastStage(String status) {
            return switch (status == null ? "" : status) {
                case "SINK_BLOCKED" -> "SINK_BOUNDARY";
                case "PRE_SINK_CONFIRMED" -> "PRE_SINK";
                case "SINK_EXECUTED_SAFE", "JNI_EXECUTED_SAFE" -> "SINK_RETURNED";
                case "SAFE_EFFECT_OBSERVED" -> "ADAPTER_EFFECT";
                case "CONCRETE_REACHED" -> "CONCRETE_TRIGGER";
                case "EXECUTED" -> "ENTRY_RETURNED";
                default -> "NONE";
            };
        }
    }

    /** Compatibility constructor for report consumers written before runtime metadata. */
    public VerificationSummary(String capability, int budget, int constructible, int rejected,
                               int selected, Map<String, Integer> statusCounts,
                               Map<String, Integer> detailCounts, List<ChainResult> results) {
        this(capability, budget, constructible, rejected, selected, statusCounts, detailCounts,
                results, "UNKNOWN", "UNKNOWN", "UNKNOWN", false, false, "UNKNOWN", "UNKNOWN",
                "UNKNOWN", List.of(), "UNKNOWN");
    }

    /** Compatibility constructor retained for callers that already provide runtime metadata. */
    public VerificationSummary(String capability, int budget, int constructible, int rejected,
                               int selected, Map<String, Integer> statusCounts,
                               Map<String, Integer> detailCounts, List<ChainResult> results,
                               String backend, String jdk, String policyDigest,
                               boolean sinkDistorted, boolean sandboxReady, String cleanup) {
        this(capability, budget, constructible, rejected, selected, statusCounts, detailCounts,
                results, backend, jdk, policyDigest, sinkDistorted, sandboxReady, cleanup,
                "UNKNOWN", "UNKNOWN", List.of(), "UNKNOWN");
    }

    /** Compatibility constructor retained for callers that provide isolation metadata. */
    public VerificationSummary(String capability, int budget, int constructible, int rejected,
                               int selected, Map<String, Integer> statusCounts,
                               Map<String, Integer> detailCounts, List<ChainResult> results,
                               String backend, String jdk, String policyDigest,
                               boolean sinkDistorted, boolean sandboxReady, String cleanup,
                               String artifactHash, String isolationLevel,
                               List<String> isolationCapabilities) {
        this(capability, budget, constructible, rejected, selected, statusCounts, detailCounts,
                results, backend, jdk, policyDigest, sinkDistorted, sandboxReady, cleanup,
                artifactHash, isolationLevel, isolationCapabilities, "UNKNOWN");
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
        isolationLevel = normalize(isolationLevel);
        attestationVersion = normalize(attestationVersion);
        java.util.TreeSet<String> capabilities = new java.util.TreeSet<>();
        if (isolationCapabilities != null) {
            for (String isolationCapability : isolationCapabilities) {
                if (isolationCapability != null && !isolationCapability.isBlank()) {
                    capabilities.add(isolationCapability);
                }
            }
        }
        isolationCapabilities = List.copyOf(capabilities);
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
                false, false, "UNKNOWN", "UNKNOWN", "UNKNOWN", List.of(), "UNKNOWN");
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
        return java.util.Collections.unmodifiableMap(sorted);
    }
}
