package io.just.sast.blackboard;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/** Static construction and terminal-control evidence for one chain. */
public record ConstructionSummary(String typeStatus, String fieldStatus,
                                  String triggerStatus, String sinkControlStatus,
                                  String overallStatus, List<String> reasons) {

    public ConstructionSummary {
        typeStatus = normalize(typeStatus);
        fieldStatus = normalize(fieldStatus);
        triggerStatus = normalize(triggerStatus);
        sinkControlStatus = normalize(sinkControlStatus);
        overallStatus = normalize(overallStatus);
        reasons = stableReasons(reasons);
    }

    public static ConstructionSummary summarize(Chain chain, List<String> notes) {
        if (chain == null) {
            return new ConstructionSummary("UNKNOWN", "UNKNOWN", "UNKNOWN", "UNKNOWN",
                    "NOT_EVALUATED", List.of("NULL_CHAIN"));
        }
        List<String> stableNotes = notes == null ? List.of() : notes;
        ObjectGraphPlan plan = chain.constructionPlan();
        ObjectGraphPlan.ShapeSummary shape = plan == null ? null : plan.shapeSummary();
        boolean shapeValid = shape != null && shape.valid();

        String type;
        if (plan == null) {
            type = "NOT_DECLARED";
        } else if (!shapeValid) {
            type = "PARTIAL";
        } else {
            type = "DECLARED_SHAPE";
        }

        String fields;
        if (plan == null) {
            fields = "NOT_DECLARED";
        } else if (!shapeValid || shape.fieldOwnersUnresolved() > 0) {
            fields = "PARTIAL";
        } else if (shape.fieldCount() == 0) {
            fields = "NO_FIELD_ASSIGNMENTS";
        } else {
            fields = "DECLARED_ASSIGNMENTS";
        }

        String trigger = !chain.hops().isEmpty() && chain.entryClass() != null
                && !chain.entryClass().isBlank() ? "STATIC_PATH_ONLY" : "NOT_PROVEN";

        String sinkControl;
        if (!chain.terminalSink()) {
            sinkControl = "CAPABILITY_ONLY";
        } else if (chain.sinkDescriptor() == null || chain.sinkDescriptor().isBlank()
                || chain.unresolvedHops() > 0) {
            sinkControl = "STATIC_UNCERTAIN";
        } else if (!chain.hops().isEmpty()) {
            sinkControl = "STATIC_ARGUMENT_FLOW";
        } else {
            sinkControl = "STATIC_UNCERTAIN";
        }

        Set<String> reasons = new LinkedHashSet<>();
        if (shape != null) {
            reasons.addAll(shape.reasons());
        } else {
            reasons.add("PLAN_NOT_DECLARED");
        }
        if (!chain.terminalSink()) {
            reasons.add("CAPABILITY_SINK");
        }
        if (chain.unresolvedHops() > 0) {
            reasons.add("UNRESOLVED_HOPS:" + chain.unresolvedHops());
        }
        if (chain.sinkDescriptor() == null || chain.sinkDescriptor().isBlank()) {
            reasons.add("SINK_DESCRIPTOR_MISSING");
        }
        stableNotes.stream().filter(note -> note != null
                        && (note.startsWith("degrade:") || note.contains("CAP")
                        || note.contains("UNKNOWN")))
                .forEach(reasons::add);

        boolean degraded = reasons.stream().anyMatch(reason -> reason.startsWith("degrade:")
                || reason.startsWith("UNRESOLVED_HOPS")
                || reason.startsWith("MISSING_"));
        String overall;
        if ("PARTIAL".equals(type) || "PARTIAL".equals(fields) || degraded) {
            overall = "PARTIAL";
        } else if (plan != null) {
            overall = "DECLARED";
        } else {
            overall = "NOT_EVALUATED";
        }
        return new ConstructionSummary(type, fields, trigger, sinkControl, overall,
                new ArrayList<>(reasons));
    }

    private static List<String> stableReasons(List<String> reasons) {
        if (reasons == null || reasons.isEmpty()) {
            return List.of();
        }
        ArrayList<String> sorted = new ArrayList<>();
        for (String reason : reasons) {
            if (reason != null && !reason.isBlank()) {
                sorted.add(reason);
            }
        }
        sorted.sort(String::compareTo);
        return List.copyOf(new LinkedHashSet<>(sorted));
    }

    private static String normalize(String value) {
        return value == null || value.isBlank() ? "UNKNOWN" : value;
    }
}
