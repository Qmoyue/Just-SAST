package io.just.sast.blackboard;

import java.util.Locale;
import java.util.Objects;

/**
 * Typed observation of one bounded verification attempt.  Wire strings remain only at the
 * legacy boundary; solver and report migrations can consume these closed values directly.
 */
public record VerificationOutcome(
        Status status,
        String detail,
        String evidence,
        String requestedMode,
        String effectiveMode,
        String fallback,
        Scope scope,
        String sinkRisk,
        boolean terminalExecuted,
        StopReason stopReason,
        Stage lastConfirmedStage) implements BlackboardFact {

    public enum Status {
        SINK_BLOCKED,
        PRE_SINK_CONFIRMED,
        SINK_EXECUTED_SAFE,
        JNI_EXECUTED_SAFE,
        SAFE_EFFECT_OBSERVED,
        CONCRETE_REACHED,
        EXECUTED,
        PARTIAL,
        FAILED,
        TIMEOUT,
        UNTESTABLE,
        UNKNOWN;

        public static Status fromWire(String value) {
            if (value == null || value.isBlank()) {
                return UNKNOWN;
            }
            String normalized = value.trim().toUpperCase(Locale.ROOT);
            // Pre-schema SAFE_SINK_EXECUTED was the inert adapter-effect label.  Preserve its
            // historical meaning at this one boundary without treating it as a real terminal.
            if ("SAFE_SINK_EXECUTED".equals(normalized)) {
                return SAFE_EFFECT_OBSERVED;
            }
            try {
                return valueOf(normalized);
            } catch (IllegalArgumentException ignored) {
                return UNKNOWN;
            }
        }
    }

    public enum Scope {
        NONE,
        PREFIX_ONLY,
        BOUNDARY_ONLY,
        TERMINAL_EXECUTED_SAFE;

        public static Scope fromWire(String value) {
            if (value == null || value.isBlank()) {
                return NONE;
            }
            try {
                return valueOf(value.trim().toUpperCase(Locale.ROOT));
            } catch (IllegalArgumentException ignored) {
                return NONE;
            }
        }
    }

    public enum StopReason {
        NONE,
        SINK_BOUNDARY_CANARY,
        HIGH_RISK_SINK,
        SAFE_TERMINAL_RETURNED,
        ADAPTER_EFFECT_ONLY,
        PROCESS_TIMEOUT,
        SANDBOX_UNAVAILABLE,
        UNTESTABLE;

        public static StopReason fromWire(String value) {
            if (value == null || value.isBlank()) {
                return NONE;
            }
            try {
                return valueOf(value.trim().toUpperCase(Locale.ROOT));
            } catch (IllegalArgumentException ignored) {
                return NONE;
            }
        }
    }

    public enum Stage {
        NONE,
        SINK_BOUNDARY,
        PRE_SINK,
        SINK_RETURNED,
        ADAPTER_EFFECT,
        CONCRETE_TRIGGER,
        ENTRY_RETURNED;

        public static Stage fromWire(String value) {
            if (value == null || value.isBlank()) {
                return NONE;
            }
            try {
                return valueOf(value.trim().toUpperCase(Locale.ROOT));
            } catch (IllegalArgumentException ignored) {
                return NONE;
            }
        }
    }

    public VerificationOutcome {
        status = Objects.requireNonNull(status, "status");
        detail = detail == null ? "" : detail;
        evidence = normalize(evidence);
        requestedMode = normalize(requestedMode);
        effectiveMode = normalize(effectiveMode);
        fallback = normalize(fallback);
        scope = Objects.requireNonNull(scope, "scope");
        sinkRisk = normalize(sinkRisk);
        stopReason = Objects.requireNonNull(stopReason, "stopReason");
        lastConfirmedStage = Objects.requireNonNull(lastConfirmedStage, "lastConfirmedStage");
    }

    /** Convert an old status/detail pair at exactly one compatibility boundary. */
    public static VerificationOutcome fromLegacy(String status, String detail, String evidence) {
        return VerificationDetailAdapter.fromLegacy(status, detail, evidence);
    }

    /**
     * Build one typed outcome from the complete legacy wire shape.  This is the single adapter
     * owner for callers that already carry explicit scope/stop/stage fields; free-form detail is
     * used only to fill an absent evidence value and is never reinterpreted as policy.
     */
    public static VerificationOutcome fromLegacyFields(String status, String detail,
                                                        String evidence, String requestedMode,
                                                        String effectiveMode, String fallback,
                                                        String verificationScope,
                                                        String sinkRisk,
                                                        boolean terminalExecuted,
                                                        String stopReason,
                                                        String lastConfirmedStage) {
        VerificationOutcome legacy = fromLegacy(status, detail, evidence);
        String resolvedEvidence = evidence == null || evidence.isBlank()
                ? legacy.evidence() : evidence;
        return new VerificationOutcome(
                Status.fromWire(status),
                detail == null ? "" : detail,
                resolvedEvidence,
                normalize(requestedMode),
                normalize(effectiveMode),
                normalize(fallback),
                Scope.fromWire(verificationScope),
                normalize(sinkRisk),
                terminalExecuted,
                StopReason.fromWire(stopReason),
                Stage.fromWire(lastConfirmedStage));
    }

    private static String normalize(String value) {
        return value == null || value.isBlank() ? "UNKNOWN" : value.trim();
    }
}
