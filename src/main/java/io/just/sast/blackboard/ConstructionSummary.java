package io.just.sast.blackboard;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Separate evidence dimensions for the safe, declarative object-graph plan.
 *
 * <p>A valid plan proves only that the bounded description is internally coherent.  It does
 * not prove that an application class can be instantiated or that a serialized payload is
 * exploitable.  Dynamic states describe the authenticated child boundary and keep
 * safe-adapter distortion visible.</p>
 */
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

    public static ConstructionSummary summarize(Chain chain, List<String> notes,
                                                 VerificationSummary.ChainResult verification) {
        if (chain == null) {
            return new ConstructionSummary("UNKNOWN", "UNKNOWN", "UNKNOWN", "UNKNOWN",
                    "NOT_EVALUATED", List.of("NULL_CHAIN"));
        }
        List<String> stableNotes = notes == null ? List.of() : notes;
        ObjectGraphPlan plan = chain.constructionPlan();
        ObjectGraphPlan.ShapeSummary shape = plan == null ? null : plan.shapeSummary();
        boolean shapeValid = shape != null && shape.valid();
        boolean safeShapeVerified = stableNotes.stream()
                .anyMatch("verify:constructible"::equals);

        String type;
        if (plan == null) {
            type = "NOT_DECLARED";
        } else if (!shapeValid) {
            type = "PARTIAL";
        } else if (safeShapeVerified) {
            type = "SAFE_SHAPE_VERIFIED";
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

        String dynamic = verification == null ? "" : verification.status();
        String trigger;
        if ("SINK_BLOCKED".equals(dynamic)) {
            trigger = "DYNAMIC_CANARY_BOUNDARY";
        } else if ("SINK_EXECUTED_SAFE".equals(dynamic)) {
            trigger = "DYNAMIC_REAL_SINK_SAFE_ARGUMENTS";
        } else if ("JNI_EXECUTED_SAFE".equals(dynamic)) {
            trigger = "DYNAMIC_JNI_SAFE_FIXTURE";
        } else if ("SAFE_EFFECT_OBSERVED".equals(dynamic)) {
            trigger = "DYNAMIC_SAFE_ADAPTER_BOUNDARY";
        } else if ("CONCRETE_REACHED".equals(dynamic)) {
            trigger = "DYNAMIC_TRIGGER_REACHED";
        } else if ("EXECUTED".equals(dynamic)) {
            trigger = "DYNAMIC_ENTRY_RETURNED";
        } else if ("PARTIAL".equals(dynamic)) {
            trigger = "PARTIAL";
        } else if (!chain.hops().isEmpty() && chain.entryClass() != null
                && !chain.entryClass().isBlank()) {
            trigger = "STATIC_PATH_ONLY";
        } else {
            trigger = "NOT_PROVEN";
        }

        String sinkControl;
        if (!chain.terminalSink()) {
            sinkControl = "CAPABILITY_ONLY";
        } else if ("SINK_BLOCKED".equals(dynamic)) {
            sinkControl = "DYNAMIC_CANARY_REACHED";
        } else if ("SINK_EXECUTED_SAFE".equals(dynamic)
                || "JNI_EXECUTED_SAFE".equals(dynamic)) {
            sinkControl = "DYNAMIC_TARGET_SAFE_ARGUMENTS";
        } else if ("SAFE_EFFECT_OBSERVED".equals(dynamic)) {
            sinkControl = "DYNAMIC_ADAPTER_ONLY";
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
        if (verification == null) {
            reasons.add("DYNAMIC_NOT_SELECTED");
        } else if (verification.sinkDistorted()) {
            reasons.add("SINK_DISTORTED:" + verification.status());
        }

        boolean degraded = reasons.stream().anyMatch(reason -> reason.startsWith("degrade:")
                || reason.startsWith("UNRESOLVED_HOPS")
                || reason.startsWith("MISSING_"));
        String overall;
        if ("PARTIAL".equals(type) || "PARTIAL".equals(fields) || degraded) {
            overall = "PARTIAL";
        } else if ("SAFE_SHAPE_VERIFIED".equals(type)) {
            overall = "SAFE_SHAPE_VERIFIED";
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
