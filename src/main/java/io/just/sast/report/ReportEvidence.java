package io.just.sast.report;

import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ConstructionSummary;
import io.just.sast.analysis.taint.FilterAnalysis;

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

    /** One canonical JSON projection for bounded-filter evidence shared by all report views. */
    static String filterEvidenceJson(List<FilterAnalysis.Evidence> evidence) {
        StringBuilder json = new StringBuilder("[");
        List<FilterAnalysis.Evidence> values = evidence == null ? List.of() : evidence;
        for (int i = 0; i < values.size(); i++) {
            if (i > 0) {
                json.append(',');
            }
            FilterAnalysis.Evidence item = values.get(i);
            json.append("{\"kind\":\"").append(escape(item.kind().name()))
                    .append("\",\"location\":\"").append(escape(item.location()))
                    .append("\",\"status\":\"").append(escape(item.status().name()))
                    .append("\",\"reason_code\":\"").append(escape(item.reasonCode()))
                    .append("\",\"domain_digest\":\"").append(escape(item.domainDigest()))
                    .append("\",\"semantic_digest\":\"").append(escape(item.semanticDigest()))
                    .append("\",\"budget\":").append(item.budget())
                    .append(",\"evaluated\":").append(item.evaluated())
                    .append(",\"retained\":").append(item.retained())
                    .append(",\"rejected\":").append(item.rejected())
                    .append(",\"expanded\":").append(item.expanded())
                    .append(",\"filter_cost_nanos\":").append(item.filterCostNanos())
                    .append('}');
        }
        return json.append(']').toString();
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
