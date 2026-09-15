package io.just.sast.report;

import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ConstructionSummary;

import java.util.List;

/** Shared serialization of static construction and terminal evidence dimensions. */
final class ReportEvidence {

    private ReportEvidence() {
    }

    static ConstructionSummary construction(Chain chain, List<String> notes) {
        return ConstructionSummary.summarize(chain, notes);
    }

    static String constructionJson(Chain chain, List<String> notes) {
        return constructionJson(construction(chain, notes));
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

    static String constructionReasons(Chain chain, List<String> notes) {
        return String.join("|", construction(chain, notes).reasons());
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
