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

    /** Stable machine-readable disclosure of the dynamic verification trust boundary. */
    public record SafetyDisclosure(
            String schemaVersion,
            String verificationMode,
            boolean targetCodeExecutionPossible,
            String targetCodeExecuted,
            boolean resourceContainmentOnly,
            boolean filesystemIsolation,
            boolean networkIsolation,
            boolean tokenIsolation,
            boolean dangerousSinkExecuted,
            boolean recommendedForUntrustedArtifacts,
            String targetTrust,
            String isolationBackend,
            String isolationStatus,
            boolean failClosedOnIsolationFailure,
            List<String> capabilityGaps) {

        public SafetyDisclosure {
            schemaVersion = normalize(schemaVersion);
            verificationMode = normalize(verificationMode);
            targetCodeExecuted = normalize(targetCodeExecuted);
            targetTrust = normalize(targetTrust);
            isolationBackend = normalize(isolationBackend);
            isolationStatus = normalize(isolationStatus);
            List<String> gaps = new ArrayList<>();
            if (capabilityGaps != null) {
                capabilityGaps.stream().filter(value -> value != null && !value.isBlank())
                        .map(String::trim).distinct().sorted().forEach(gaps::add);
            }
            capabilityGaps = List.copyOf(gaps);
        }

        private static String normalize(String value) {
            return value == null || value.isBlank() ? "UNKNOWN" : value;
        }
    }

    /**
     * Derive the disclosure from the immutable verification snapshot.  This is deliberately the
     * only owner of the trust/risk interpretation used by reports and run metadata.
     */
    public SafetyDisclosure safetyDisclosure() {
        boolean staticOnly = "DISABLED".equalsIgnoreCase(capability)
                || "STATIC_ONLY".equalsIgnoreCase(capability);
        boolean possible = !staticOnly;
        boolean selectedPlans = selected > 0 || !results.isEmpty();
        boolean observedTarget = results.stream().anyMatch(VerificationSummary::targetCodeObserved);
        boolean onlyIsolationBlock = selectedPlans && !results.isEmpty()
                && results.stream().allMatch(VerificationSummary::isolationBlockedResult);
        String executed;
        if (!possible || !selectedPlans) {
            executed = "NO";
        } else if (observedTarget) {
            executed = "YES";
        } else if (onlyIsolationBlock) {
            executed = "NO";
        } else {
            // A selected plan with no authenticated target observation is intentionally unknown;
            // timeout/crash/partial results must not be reinterpreted as a negative fact.
            executed = "UNKNOWN";
        }
        boolean dangerous = results.stream().anyMatch(result -> result.terminalExecuted()
                && !result.sinkDistorted());
        String backend = normalizeIsolationBackend(backend());
        String isolationStatus = staticOnly ? "NOT_REQUESTED"
                : sandboxReady ? "READY" : "UNAVAILABLE";
        List<String> gaps = List.of(
                "filesystem_isolation=false",
                "network_isolation=false",
                "token_isolation=false",
                "syscall_filtering=false",
                "attacker_payload_execution=false");
        return new SafetyDisclosure(
                "JUST-VERIFY-DISCLOSURE-V1",
                staticOnly ? "STATIC_ONLY" : "AUTO",
                possible,
                executed,
                true,
                false,
                false,
                false,
                dangerous,
                staticOnly,
                staticOnly ? "STATIC_ONLY_UNTRUSTED_ARTIFACT_PATH"
                        : "TRUSTED_LOCAL_TARGET_REQUIRED",
                backend,
                isolationStatus,
                true,
                gaps);
    }

    private static boolean targetCodeObserved(ChainResult result) {
        if (result == null) {
            return false;
        }
        return switch (result.outcomeStatus()) {
            case SINK_BLOCKED, PRE_SINK_CONFIRMED, SINK_EXECUTED_SAFE,
                    JNI_EXECUTED_SAFE, SAFE_EFFECT_OBSERVED, CONCRETE_REACHED,
                    EXECUTED -> true;
            default -> false;
        };
    }

    private static boolean isolationBlockedResult(ChainResult result) {
        if (result == null) {
            return false;
        }
        return result.outcomeStatus() == VerificationOutcome.Status.UNTESTABLE
                && !result.sandboxReady()
                && (result.detail().startsWith("SANDBOX_UNAVAILABLE")
                || result.detail().startsWith("ISOLATION_UNAVAILABLE"));
    }

    private static String normalizeIsolationBackend(String value) {
        if (value == null || value.isBlank()) {
            return "UNKNOWN";
        }
        String normalized = value.trim().toUpperCase(java.util.Locale.ROOT);
        if (normalized.startsWith("WINDOWS_JOB_OBJECT")) {
            return "WINDOWS_JOB_OBJECT";
        }
        return normalized;
    }

    /**
     * One persisted verification result.  Attempt semantics live in one typed outcome; the raw
     * status is retained solely to round-trip legacy report wire values.  The accessors below
     * project the old detail/evidence/scope shape without storing a second copy per chain.
     */
    public record ChainResult(
            int rank,
            String chainKey,
            String status,
            String confidence,
            int confidenceScore,
            int attempt,
            long durationMs,
            VerificationOutcome outcome,
            String backend,
            String jdk,
            String policyDigest,
            boolean sinkDistorted,
            boolean sandboxReady,
            String cleanup) {

        public ChainResult(int rank, String chainKey, String status, String detail,
                           String confidence, int confidenceScore, int attempt,
                           long durationMs) {
            this(rank, chainKey, status, confidence, confidenceScore, attempt, durationMs,
                    VerificationDetailAdapter.fromLegacy(status, detail, null), "UNKNOWN",
                    "UNKNOWN", "UNKNOWN", false, false, "UNKNOWN");
        }

        public ChainResult(int rank, String chainKey, String status, String detail,
                           String confidence, int confidenceScore, int attempt,
                           long durationMs, String evidence) {
            this(rank, chainKey, status, confidence, confidenceScore, attempt, durationMs,
                    VerificationDetailAdapter.fromLegacy(status, detail, evidence), "UNKNOWN",
                    "UNKNOWN", "UNKNOWN", false, false, "UNKNOWN");
        }

        /** Compatibility constructor retained for report consumers before scope metadata. */
        public ChainResult(int rank, String chainKey, String status, String detail,
                           String confidence, int confidenceScore, int attempt,
                           long durationMs, String evidence, String backend, String jdk,
                           String policyDigest, boolean sinkDistorted, boolean sandboxReady,
                           String cleanup) {
            this(rank, chainKey, status, confidence, confidenceScore, attempt, durationMs,
                    VerificationDetailAdapter.fromLegacy(status, detail, evidence), backend, jdk,
                    policyDigest, sinkDistorted, sandboxReady, cleanup);
        }

        /** Compatibility constructor retaining the complete pre-typed wire shape. */
        public ChainResult(int rank, String chainKey, String status, String detail,
                           String confidence, int confidenceScore, int attempt,
                           long durationMs, String evidence, String backend, String jdk,
                           String policyDigest, boolean sinkDistorted, boolean sandboxReady,
                           String cleanup, String requestedMode, String effectiveMode,
                           String fallback, String verificationScope, String sinkRisk,
                           boolean terminalExecuted, String stopReason, String lastConfirmedStage) {
            this(rank, chainKey, status, confidence, confidenceScore, attempt, durationMs,
                    VerificationOutcome.fromLegacyFields(status, detail, evidence, requestedMode,
                            effectiveMode, fallback, verificationScope, sinkRisk, terminalExecuted,
                            stopReason, lastConfirmedStage), backend, jdk, policyDigest,
                    sinkDistorted, sandboxReady, cleanup);
        }

        private ChainResult(int rank, String chainKey, String status, String detail,
                            String confidence, int confidenceScore, int attempt,
                            long durationMs, String evidence, VerificationOutcome outcome) {
            this(rank, chainKey, status, confidence, confidenceScore, attempt, durationMs,
                    outcome == null ? VerificationDetailAdapter.fromLegacy(status, detail, evidence)
                            : outcome,
                    "UNKNOWN", "UNKNOWN", "UNKNOWN", false, false, "UNKNOWN");
        }

        private ChainResult(int rank, String chainKey, String status, String detail,
                            String confidence, int confidenceScore, int attempt,
                            long durationMs, String evidence, String backend, String jdk,
                            String policyDigest, boolean sinkDistorted, boolean sandboxReady,
                            String cleanup, VerificationOutcome outcome) {
            this(rank, chainKey, status, confidence, confidenceScore, attempt, durationMs,
                    outcome == null ? VerificationDetailAdapter.fromLegacy(status, detail, evidence)
                            : outcome,
                    backend, jdk, policyDigest, sinkDistorted, sandboxReady, cleanup);
        }

        public ChainResult {
            chainKey = chainKey == null ? "" : chainKey;
            status = status == null ? "UNKNOWN" : status;
            confidence = confidence == null ? "UNKNOWN" : confidence;
            attempt = Math.max(1, attempt);
            durationMs = Math.max(0L, durationMs);
            outcome = outcome == null
                    ? VerificationDetailAdapter.fromLegacy(status, "", null) : outcome;
            backend = normalize(backend);
            jdk = normalize(jdk);
            policyDigest = normalize(policyDigest);
            cleanup = normalize(cleanup);
        }

        private static String normalize(String value) {
            return value == null || value.isBlank() ? "UNKNOWN" : value;
        }

        /** Legacy detail projection; semantic consumers should use {@link #outcome()}. */
        public String detail() {
            return outcome.detail();
        }

        /** Legacy evidence projection; semantic consumers should use {@link #outcome()}. */
        public String evidence() {
            return outcome.evidence();
        }

        public String requestedMode() {
            return outcome.requestedMode();
        }

        public String effectiveMode() {
            return outcome.effectiveMode();
        }

        public String fallback() {
            return outcome.fallback();
        }

        public String verificationScope() {
            return outcome.scope().name();
        }

        public String sinkRisk() {
            return outcome.sinkRisk();
        }

        public boolean terminalExecuted() {
            return outcome.terminalExecuted();
        }

        public String stopReason() {
            return outcome.stopReason().name();
        }

        public String lastConfirmedStage() {
            return outcome.lastConfirmedStage().name();
        }

        /** Canonical closed status for policy code; {@link #status()} is wire compatibility. */
        public VerificationOutcome.Status outcomeStatus() {
            return outcome.status();
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

    /**
     * Return a snapshot with a new run capability while preserving all attempt evidence.
     * Legacy status setters use this projection so the summary remains the sole owner of the
     * verification capability instead of maintaining a second mutable string.
     */
    public VerificationSummary withCapability(String value) {
        return new VerificationSummary(value, budget, constructible, rejected, selected,
                statusCounts, detailCounts, results, backend, jdk, policyDigest, sinkDistorted,
                sandboxReady, cleanup, artifactHash, isolationLevel, isolationCapabilities,
                attestationVersion);
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
