package io.just.sast.blackboard;

import java.util.Locale;
import java.util.List;

/**
 * Sole compatibility owner for the pre-schema semicolon detail protocol.  New producers should
 * construct {@link VerificationOutcome} directly; no renderer or verifier may infer a status
 * from detail text outside this class.
 */
public final class VerificationDetailAdapter {
    private VerificationDetailAdapter() {
    }

    public static VerificationOutcome fromLegacy(String status, String detail, String evidence) {
        String rawDetail = detail == null ? "" : detail;
        VerificationOutcome.Status code = VerificationOutcome.Status.fromWire(status);
        return new VerificationOutcome(
                code,
                rawDetail,
                hasText(evidence) ? evidence : defaultEvidence(code, rawDetail),
                field(rawDetail, "requested_mode", "UNKNOWN"),
                field(rawDetail, "effective_mode", "UNKNOWN"),
                field(rawDetail, "fallback", "none"),
                defaultScope(code),
                field(rawDetail, "sink_risk", "UNKNOWN"),
                defaultTerminalExecuted(code),
                defaultStopReason(code, rawDetail),
                defaultLastStage(code));
    }

    /**
     * Parse the legacy chain-note status protocol at the same compatibility boundary as the
     * semicolon detail adapter.  New producers must publish {@link VerificationOutcome}; this
     * helper exists only while old blackboard notes are still present in v1 fixtures.
     */
    public static String statusFromLegacyNotes(List<String> notes) {
        if (notes == null || notes.isEmpty()) {
            return "";
        }
        if (notes.contains("verify:sink-blocked") || notes.contains("verify:confirmed")) {
            return VerificationOutcome.Status.SINK_BLOCKED.name();
        }
        if (notes.contains("verify:pre-sink-confirmed")
                || notes.contains("verify:prefix-confirmed")) {
            return VerificationOutcome.Status.PRE_SINK_CONFIRMED.name();
        }
        if (notes.contains("verify:jni-executed-safe")) {
            return VerificationOutcome.Status.JNI_EXECUTED_SAFE.name();
        }
        if (notes.contains("verify:sink-executed-safe")) {
            return VerificationOutcome.Status.SINK_EXECUTED_SAFE.name();
        }
        if (notes.contains("verify:segment-confirmed")
                || notes.contains("verify:concrete-reached")) {
            return VerificationOutcome.Status.CONCRETE_REACHED.name();
        }
        if (notes.contains("verify:safe-effect-observed")) {
            return VerificationOutcome.Status.SAFE_EFFECT_OBSERVED.name();
        }
        if (notes.contains("verify:executed")) {
            return VerificationOutcome.Status.EXECUTED.name();
        }
        return notes.stream().anyMatch(note -> note != null
                && note.startsWith("degrade:partial-path"))
                ? VerificationOutcome.Status.PARTIAL.name() : "";
    }

    private static String defaultEvidence(VerificationOutcome.Status status, String detail) {
        return switch (status) {
            case SINK_BLOCKED -> "SINK_CANARY_BOUNDARY";
            case PRE_SINK_CONFIRMED -> "PREFIX_CHAIN_CONFIRMED";
            case SINK_EXECUTED_SAFE -> "REAL_SINK_BODY_SAFE_ARGUMENTS";
            case JNI_EXECUTED_SAFE -> "JNI_LOAD_CALLBACK_SAFE_FIXTURE";
            case SAFE_EFFECT_OBSERVED -> "SAFE_EFFECT_OBSERVED";
            case CONCRETE_REACHED -> "CONCRETE_TRIGGER";
            case EXECUTED -> "ENTRY_RETURNED";
            case PARTIAL -> "PARTIAL_PATH";
            case TIMEOUT -> "PROCESS_TIMEOUT";
            case UNTESTABLE -> detail.startsWith("SANDBOX_UNAVAILABLE")
                    ? "SANDBOX_UNAVAILABLE"
                    : detail.startsWith("PROCESS_OOM")
                    ? "PROCESS_OOM"
                    : detail.startsWith("PROBE_OUTPUT_LIMIT")
                    ? "PROBE_OUTPUT_LIMIT"
                    : detail.startsWith("CANARY_ARTIFACT_MISSING")
                    ? "VERIFIER_ARTIFACT_MISSING" : "VERIFIER_CAPABILITY_LIMIT";
            case FAILED -> "NO_TRIGGER";
            case UNKNOWN -> "UNKNOWN";
        };
    }

    private static VerificationOutcome.Scope defaultScope(VerificationOutcome.Status status) {
        return switch (status) {
            case SINK_BLOCKED -> VerificationOutcome.Scope.BOUNDARY_ONLY;
            case PRE_SINK_CONFIRMED -> VerificationOutcome.Scope.PREFIX_ONLY;
            case SINK_EXECUTED_SAFE, JNI_EXECUTED_SAFE ->
                    VerificationOutcome.Scope.TERMINAL_EXECUTED_SAFE;
            default -> VerificationOutcome.Scope.NONE;
        };
    }

    private static boolean defaultTerminalExecuted(VerificationOutcome.Status status) {
        return status == VerificationOutcome.Status.SINK_EXECUTED_SAFE
                || status == VerificationOutcome.Status.JNI_EXECUTED_SAFE;
    }

    private static VerificationOutcome.StopReason defaultStopReason(
            VerificationOutcome.Status status, String detail) {
        return switch (status) {
            case SINK_BLOCKED -> VerificationOutcome.StopReason.SINK_BOUNDARY_CANARY;
            case PRE_SINK_CONFIRMED -> VerificationOutcome.StopReason.HIGH_RISK_SINK;
            case SINK_EXECUTED_SAFE, JNI_EXECUTED_SAFE ->
                    VerificationOutcome.StopReason.SAFE_TERMINAL_RETURNED;
            case SAFE_EFFECT_OBSERVED -> VerificationOutcome.StopReason.ADAPTER_EFFECT_ONLY;
            case TIMEOUT -> VerificationOutcome.StopReason.PROCESS_TIMEOUT;
            case UNTESTABLE -> detail.startsWith("SANDBOX_UNAVAILABLE")
                    ? VerificationOutcome.StopReason.SANDBOX_UNAVAILABLE
                    : VerificationOutcome.StopReason.UNTESTABLE;
            default -> VerificationOutcome.StopReason.NONE;
        };
    }

    private static VerificationOutcome.Stage defaultLastStage(VerificationOutcome.Status status) {
        return switch (status) {
            case SINK_BLOCKED -> VerificationOutcome.Stage.SINK_BOUNDARY;
            case PRE_SINK_CONFIRMED -> VerificationOutcome.Stage.PRE_SINK;
            case SINK_EXECUTED_SAFE, JNI_EXECUTED_SAFE -> VerificationOutcome.Stage.SINK_RETURNED;
            case SAFE_EFFECT_OBSERVED -> VerificationOutcome.Stage.ADAPTER_EFFECT;
            case CONCRETE_REACHED -> VerificationOutcome.Stage.CONCRETE_TRIGGER;
            case EXECUTED -> VerificationOutcome.Stage.ENTRY_RETURNED;
            default -> VerificationOutcome.Stage.NONE;
        };
    }

    private static String field(String detail, String name, String fallback) {
        if (detail == null || detail.isEmpty()) {
            return fallback;
        }
        String marker = name + "=";
        String[] fields = detail.split(";", -1);
        for (String item : fields) {
            if (!item.startsWith(marker)) {
                continue;
            }
            String value = item.substring(marker.length());
            return value.isBlank() ? fallback : value;
        }
        return fallback;
    }

    private static boolean hasText(String value) {
        return value != null && !value.isBlank();
    }
}
