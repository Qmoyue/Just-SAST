package io.just.sast.report;

import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ConstructionSummary;
import io.just.sast.blackboard.VerificationOutcome;
import io.just.sast.blackboard.VerificationSummary;

import java.util.List;

/** Shared serialization of construction and dynamic evidence dimensions. */
final class ReportEvidence {

    private ReportEvidence() {
    }

    static ConstructionSummary construction(Chain chain, List<String> notes,
                                             VerificationSummary.ChainResult verification) {
        return ConstructionSummary.summarize(chain, notes, verification);
    }

    static String constructionJson(Chain chain, List<String> notes,
                                   VerificationSummary.ChainResult verification) {
        ConstructionSummary summary = construction(chain, notes, verification);
        return constructionJson(summary);
    }

    static String constructionJson(ConstructionSummary summary) {
        StringBuilder json = new StringBuilder("{\"overall\":\"")
                .append(escape(summary.overallStatus()))
                .append("\",\"type\":\"").append(escape(summary.typeStatus()))
                .append("\",\"fields\":\"").append(escape(summary.fieldStatus()))
                .append("\",\"trigger\":\"").append(escape(summary.triggerStatus()))
                .append("\",\"sink_control\":\"").append(escape(summary.sinkControlStatus()))
                .append("\",\"reasons\":[");
        for (int i = 0; i < summary.reasons().size(); i++) {
            if (i > 0) {
                json.append(',');
            }
            json.append('\"').append(escape(summary.reasons().get(i))).append('\"');
        }
        return json.append("]}").toString();
    }

    static String constructionReasons(Chain chain, List<String> notes,
                                      VerificationSummary.ChainResult verification) {
        return String.join("|", construction(chain, notes, verification).reasons());
    }

    /**
     * Map the closed verifier state to one mutually-exclusive report bucket.  Reporters must
     * not derive this from free-form detail text: a high-risk prefix is not a terminal call and
     * a boundary canary is not a prefix confirmation.
     */
    static String verificationGroup(VerificationSummary.ChainResult result) {
        if (result == null) {
            return "not_selected";
        }
        VerificationOutcome outcome = result.outcome();
        if (outcome.scope() == VerificationOutcome.Scope.TERMINAL_EXECUTED_SAFE
                && result.terminalExecuted()
                && (outcome.status() == VerificationOutcome.Status.SINK_EXECUTED_SAFE
                || outcome.status() == VerificationOutcome.Status.JNI_EXECUTED_SAFE)) {
            return "real_safe_terminal";
        }
        if (outcome.scope() == VerificationOutcome.Scope.PREFIX_ONLY
                && !result.terminalExecuted()
                && outcome.status() == VerificationOutcome.Status.PRE_SINK_CONFIRMED) {
            return "prefix_confirmed_high_risk";
        }
        if (outcome.scope() == VerificationOutcome.Scope.BOUNDARY_ONLY
                && !result.terminalExecuted()
                && outcome.status() == VerificationOutcome.Status.SINK_BLOCKED) {
            return "boundary_only";
        }
        return "unverified";
    }

    static String sinkRisk(Chain chain) {
        return chain == null || chain.sinkRisk() == null
                ? "UNKNOWN" : chain.sinkRisk().name();
    }

    private static String escape(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder result = new StringBuilder(value.length() + 8);
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            switch (ch) {
                case '"' -> result.append("\\\"");
                case '\\' -> result.append("\\\\");
                case '\n' -> result.append("\\n");
                case '\r' -> result.append("\\r");
                case '\t' -> result.append("\\t");
                default -> {
                    if (ch < 0x20) {
                        result.append(String.format("\\u%04x", (int) ch));
                    } else {
                        result.append(ch);
                    }
                }
            }
        }
        return result.toString();
    }
}
