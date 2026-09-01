package io.just.sast.report;

import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.ConstructionSummary;
import io.just.sast.blackboard.HopKind;
import io.just.sast.blackboard.ObjectGraphPlan;
import io.just.sast.blackboard.VerificationSummary;
import io.just.sast.chain.ChainRanking;
import io.just.sast.chain.ChainPrecision;
import io.just.sast.chain.ConfidenceScorer;
import io.just.sast.verify.FieldDependencyPlan;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Writes a safe, deterministic construction plan for the highest-value chains.
 *
 * The artifact is deliberately a plan rather than executable serialization bytes: it exposes
 * object/field/trigger constraints and verification evidence without creating command, native,
 * network, or remote-class-loading payloads.
 */
public final class PayloadPlanWriter {

    private static final int MAX_PLANS = 64;

    private record PlanView(Chain chain, FieldDependencyPlan fields, List<String> notes,
                            VerificationSummary.ChainResult verification,
                            String construction, boolean highConfidence,
                            ConstructionSummary constructionSummary) {
    }

    public void write(Path outDir, List<Chain> chains, Map<String, String> calibrations,
                      Map<String, List<String>> notes, VerificationSummary verification)
            throws IOException {
        write(ReportLayout.flat(outDir), chains, calibrations, notes, verification);
    }

    public void write(ReportLayout layout, List<Chain> chains, Map<String, String> calibrations,
                      Map<String, List<String>> notes, VerificationSummary verification)
            throws IOException {
        Files.createDirectories(layout.meta());
        Files.createDirectories(layout.verification());
        Map<String, VerificationSummary.ChainResult> verified = new HashMap<>();
        if (verification != null) {
            for (VerificationSummary.ChainResult result : verification.results()) {
                verified.put(result.chainKey(), result);
            }
        }

        List<Chain> ordered = new ArrayList<>();
        for (Chain chain : chains == null ? List.<Chain>of() : chains) {
            if (calibrations == null || !calibrations.containsKey(chain.key())) {
                ordered.add(chain);
            }
        }
        ordered.sort(ChainRanking.comparator(notes, verified, Set.of()));
        if (ordered.size() > MAX_PLANS) {
            ordered = new ArrayList<>(ordered.subList(0, MAX_PLANS));
        }

        List<PlanView> views = new ArrayList<>(ordered.size());
        for (Chain chain : ordered) {
            List<String> chainNotes = notes == null
                    ? List.of() : notes.getOrDefault(chain.key(), List.of());
            FieldDependencyPlan fields = FieldDependencyPlan.from(chain, chain.entryKind());
            String construction = constructionStatus(chain, chainNotes);
            views.add(new PlanView(chain, fields, List.copyOf(chainNotes),
                    verified.get(chain.key()), construction,
                    ChainPrecision.isHighConfidence(chain, chainNotes, verified.get(chain.key())),
                    ConstructionSummary.summarize(chain, chainNotes, verified.get(chain.key()))));
        }

        StringBuilder json = new StringBuilder("{\n")
                .append("  \"schema_version\":1,\n")
                .append("  \"mode\":\"INERT_OBJECT_GRAPH_PLAN\",\n")
                .append("  \"safety\":\"NO_EXECUTABLE_PAYLOAD\",\n")
                .append("  \"selection_limit\":").append(MAX_PLANS).append(",\n")
                .append("  \"plans\":[\n");
        for (int i = 0; i < views.size(); i++) {
            if (i > 0) {
                json.append(",\n");
            }
            PlanView view = views.get(i);
            appendPlan(json, view.chain(), view.fields(), view.notes(), view.verification(),
                    view.construction(), view.highConfidence(), view.constructionSummary());
        }
        json.append("\n  ]\n}\n");
        AtomicFiles.writeUtf8(layout.meta().resolve("payload-plan.json"), json.toString());
        AtomicFiles.writeUtf8(layout.verification().resolve("payload.json"), readableJson(views));
        AtomicFiles.writeUtf8(layout.verification().resolve("payload.md"), readableMarkdown(views));
    }

    private static void appendPlan(StringBuilder json, Chain chain, FieldDependencyPlan fields,
                                   List<String> notes,
                                   VerificationSummary.ChainResult verification,
                                   String construction,
                                   boolean highConfidence,
                                   ConstructionSummary constructionSummary) {
        json.append("    {")
                .append("\"chain_key\":\"").append(esc(chain.key())).append("\"")
                .append(",\"rule_id\":\"").append(esc(chain.ruleId())).append("\"")
                .append(",\"entry\":{\"class\":\"").append(esc(chain.entryClass()))
                .append("\",\"method\":\"").append(esc(chain.entryMethod()))
                .append("\",\"kind\":\"").append(esc(chain.entryKind())).append("\"")
                .append(",\"trigger\":\"").append(esc(chain.entryKind())).append("\"}")
                .append(",\"sink\":{\"class\":\"").append(esc(chain.sinkClass()))
                .append("\",\"method\":\"").append(esc(chain.sinkMethod()))
                .append("\",\"descriptor\":\"").append(esc(chain.sinkDescriptor()))
                .append("\",\"role\":\"").append(esc(chain.sinkRole()))
                .append("\",\"capability\":\"").append(esc(capabilityOf(chain))).append("\"}")
                .append(",\"ranking_evidence\":\"")
                .append(esc(ChainRanking.evidence(chain, Map.of(chain.key(), notes),
                        verification == null ? Map.of() : Map.of(chain.key(), verification), Set.of())
                        .explanation())).append("\"")
                .append(",\"high_confidence\":").append(highConfidence)
                .append(",\"construction\":{\"status\":\"").append(construction)
                .append("\",\"strategy\":\"INERT_REFLECTIVE_OBJECT_GRAPH\"")
                .append(",\"encoded_fields\":\"").append(esc(fields.encodedFields())).append("\"")
                .append(",\"object_graph_plan\":\"")
                .append(esc(chain.constructionPlan() == null
                        ? "" : chain.constructionPlan().encodedForProbe())).append("\"")
                .append(",\"shape_summary\":");
        appendShapeSummary(json, chain);
        json.append(",\"construction_summary\":");
        appendConstructionSummary(json, constructionSummary);
        json.append('}')
                .append(",\"field_dependencies\":[");
        for (int i = 0; i < fields.fields().size(); i++) {
            if (i > 0) {
                json.append(',');
            }
            FieldDependencyPlan.FieldLink field = fields.fields().get(i);
            json.append("{\"from_owner\":\"").append(esc(field.fromOwner()))
                    .append("\",\"field\":\"").append(esc(field.field()))
                    .append("\",\"to_owner\":\"").append(esc(field.toOwner()))
                    .append("\",\"strategy\":\"IN_MEMORY_REFERENCE\"}");
        }
        json.append("],\"display_path\":\"").append(esc(displayPath(chain, verification)))
                .append("\",\"constraints\":[\"TYPE_COMPATIBLE_FIELDS\",\"BOUNDED_DEPTH\",")
                .append("\"SINK_CANARY_ONLY\"]");
        if (verification == null) {
            json.append(",\"verification\":{\"status\":\"NOT_SELECTED\"}");
        } else {
            json.append(",\"verification\":{\"rank\":").append(verification.rank())
                    .append(",\"status\":\"").append(esc(verification.status()))
                    .append("\",\"detail\":\"").append(esc(verification.detail()))
                    .append("\",\"confidence\":\"").append(esc(verification.confidence()))
                    .append("\",\"confidence_score\":").append(verification.confidenceScore())
                    .append(",\"attempt\":").append(verification.attempt())
                    .append(",\"duration_ms\":").append(verification.durationMs()).append('}');
        }
        json.append(",\"limitations\":[\"NO_COMMAND_EXECUTION\",\"NO_NATIVE_LIBRARY_LOAD\",")
                .append("\"NO_REMOTE_REQUEST\",\"NO_AUTOMATIC_SERIALIZED_BYTES\"]}");
    }

    private static String constructionStatus(Chain chain, List<String> notes) {
        if (chain.constructionPlan() != null
                && !chain.constructionPlan().shapeSummary().valid()) {
            return "PARTIAL";
        }
        return notes.stream().anyMatch("verify:constructible"::equals)
                ? "CONSTRUCTIBLE"
                : chain.constructionPlan() != null && !chain.constructionPlan().isEmpty()
                ? "PLAN_DECLARED"
                : notes.stream().anyMatch("degrade:partial-construct"::equals)
                ? "PARTIAL" : "NOT_EVALUATED";
    }

    private static void appendShapeSummary(StringBuilder json, Chain chain) {
        ObjectGraphPlan.ShapeSummary summary = chain.constructionPlan() == null
                ? new ObjectGraphPlan.ShapeSummary(0, 0, 0, 0, 0, 0, false,
                List.of("PLAN_NOT_DECLARED"))
                : chain.constructionPlan().shapeSummary();
        json.append("{\"status\":\"").append(esc(summary.status())).append("\"")
                .append(",\"nodes\":").append(summary.nodeCount())
                .append(",\"fields\":").append(summary.fieldCount())
                .append(",\"references\":").append(summary.referenceCount())
                .append(",\"resolved_references\":").append(summary.resolvedReferenceCount())
                .append(",\"field_owners_resolved\":").append(summary.fieldOwnersResolved())
                .append(",\"field_owners_unresolved\":").append(summary.fieldOwnersUnresolved())
                .append(",\"reasons\":[");
        for (int i = 0; i < summary.reasons().size(); i++) {
            if (i > 0) {
                json.append(',');
            }
            json.append('"').append(esc(summary.reasons().get(i))).append('"');
        }
        json.append("]}");
    }

    private static void appendConstructionSummary(StringBuilder json,
                                                  ConstructionSummary summary) {
        if (summary == null) {
            json.append("{\"overall\":\"UNKNOWN\",\"reasons\":[\"SUMMARY_MISSING\"]}");
            return;
        }
        json.append("{\"overall\":\"").append(esc(summary.overallStatus()))
                .append("\",\"type\":\"").append(esc(summary.typeStatus()))
                .append("\",\"fields\":\"").append(esc(summary.fieldStatus()))
                .append("\",\"trigger\":\"").append(esc(summary.triggerStatus()))
                .append("\",\"sink_control\":\"")
                .append(esc(summary.sinkControlStatus())).append("\",\"reasons\":[");
        for (int i = 0; i < summary.reasons().size(); i++) {
            if (i > 0) {
                json.append(',');
            }
            json.append('"').append(esc(summary.reasons().get(i))).append('"');
        }
        json.append("]}");
    }

    private static String readableJson(List<PlanView> views) {
        StringBuilder json = new StringBuilder("{\n")
                .append("  \"schema_version\":1,\n")
                .append("  \"safety\":\"NO_EXECUTABLE_PAYLOAD\",\n")
                .append("  \"description\":\"Human/agent-readable chain view; final sink body is never executed\",\n")
                .append("  \"plans\":[\n");
        for (int i = 0; i < views.size(); i++) {
            if (i > 0) {
                json.append(",\n");
            }
            appendReadablePlan(json, views.get(i), "    ");
        }
        return json.append("\n  ]\n}\n").toString();
    }

    private static void appendReadablePlan(StringBuilder json, PlanView view, String indent) {
        Chain chain = view.chain();
        VerificationSummary.ChainResult verification = view.verification();
        json.append(indent).append("{\n")
                .append(indent).append("  \"chain_key\":\"").append(esc(chain.key())).append("\",\n")
                .append(indent).append("  \"title\":\"")
                .append(esc(displayTitle(chain))).append("\",\n")
                .append(indent).append("  \"rule_id\":\"").append(esc(chain.ruleId())).append("\",\n")
                .append(indent).append("  \"confidence\":\"")
                .append(esc(ConfidenceScorer.score(chain, view.notes()))).append("\",\n")
                .append(indent).append("  \"high_confidence\":")
                .append(view.highConfidence()).append(",\n")
                .append(indent).append("  \"display_path\":\"")
                .append(esc(displayPath(chain, verification))).append("\",\n")
                .append(indent).append("  \"entry\":{\"class\":\"")
                .append(esc(chain.entryClass())).append("\",\"method\":\"")
                .append(esc(chain.entryMethod())).append("\",\"kind\":\"")
                .append(esc(chain.entryKind())).append("\"},\n")
                .append(indent).append("  \"sink_boundary\":{\"class\":\"")
                .append(esc(chain.sinkClass())).append("\",\"method\":\"")
                .append(esc(chain.sinkMethod())).append("\",\"role\":\"")
                .append(esc(chain.sinkRole())).append("\",\"status\":\"")
                .append(esc(verification == null ? "NOT_SELECTED" : verification.status()))
                .append("\",\"execution\":\"").append(executionLabel())
                .append("\",\"observed_boundary\":\"")
                .append(observedBoundary(verification)).append("\"},\n")
                .append(indent).append("  \"construction\":{\"status\":\"")
                .append(esc(view.construction()))
                .append("\",\"strategy\":\"INERT_REFLECTIVE_OBJECT_GRAPH\",\"object_graph_plan\":\"")
                .append(esc(chain.constructionPlan() == null
                        ? "" : chain.constructionPlan().encodedForProbe()))
                .append("\",\"shape_summary\":");
        appendShapeSummary(json, chain);
        json.append(",\"construction_summary\":");
        appendConstructionSummary(json, view.constructionSummary());
        json.append("},\n")
                .append(indent).append("  \"steps\":");
        appendStringArray(json, stepLabels(chain), indent + "  ");
        json.append(",\n")
                .append(indent).append("  \"field_dependencies\":[\n");
        for (int i = 0; i < view.fields().fields().size(); i++) {
            if (i > 0) {
                json.append(",\n");
            }
            FieldDependencyPlan.FieldLink field = view.fields().fields().get(i);
            json.append(indent).append("    {\"from_owner\":\"")
                    .append(esc(field.fromOwner())).append("\",\"field\":\"")
                    .append(esc(field.field())).append("\",\"to_owner\":\"")
                    .append(esc(field.toOwner())).append("\"}");
        }
        json.append("\n").append(indent).append("  ],\n")
                .append(indent).append("  \"verification\":");
        appendVerification(json, verification);
        json.append("\n").append(indent).append('}');
    }

    private static void appendVerification(StringBuilder json,
                                           VerificationSummary.ChainResult verification) {
        if (verification == null) {
            json.append("{\"status\":\"NOT_SELECTED\",\"evidence\":\"NONE\"}");
            return;
        }
        json.append("{\"status\":\"").append(esc(verification.status()))
                .append("\",\"evidence\":\"").append(esc(verification.evidence()))
                .append("\",\"detail\":\"").append(esc(verification.detail()))
                .append("\",\"attempt\":").append(verification.attempt())
                .append(",\"duration_ms\":").append(verification.durationMs()).append('}');
    }

    private static void appendStringArray(StringBuilder json, List<String> values, String indent) {
        json.append("[\n");
        for (int i = 0; i < values.size(); i++) {
            if (i > 0) {
                json.append(",\n");
            }
            json.append(indent).append('"').append(esc(values.get(i))).append('"');
        }
        json.append("\n").append(indent, 0, Math.max(0, indent.length() - 2)).append(']');
    }

    private static String readableMarkdown(List<PlanView> views) {
        StringBuilder markdown = new StringBuilder("# Just payload review\n\n")
                .append("> This is a safe, human-readable construction and verification view. "
                        + "It never emits executable serialization bytes.\n\n");
        if (views.isEmpty()) {
            return markdown.append("No eligible chain plans.\n").toString();
        }
        for (int i = 0; i < views.size(); i++) {
            PlanView view = views.get(i);
            Chain chain = view.chain();
            VerificationSummary.ChainResult verification = view.verification();
            markdown.append("## ").append(i + 1).append(". ")
                    .append(displayTitle(chain)).append("\n\n")
                    .append("- Rule: `").append(escMarkdown(chain.ruleId())).append("`\n")
                    .append("- Confidence: `").append(escMarkdown(
                             ConfidenceScorer.score(chain, view.notes()))).append("`\n")
                    .append("- High confidence: `").append(view.highConfidence()).append("`\n")
                    .append("- Verification: `").append(escMarkdown(
                            verification == null ? "NOT_SELECTED" : verification.status()))
                    .append("` (`").append(escMarkdown(verification == null ? "NONE"
                            : verification.evidence())).append("`)\n\n")
                    .append("### Chain\n\n")
                    .append("`").append(escMarkdown(displayPath(chain, verification))).append("`\n\n")
                    .append("### Steps\n\n");
            List<String> steps = stepLabels(chain);
            for (int step = 0; step < steps.size(); step++) {
                markdown.append(step + 1).append(". ")
                        .append(escMarkdown(steps.get(step))).append("\n");
            }
            markdown.append('\n')
                    .append("### Field dependencies\n\n");
            if (view.fields().fields().isEmpty()) {
                markdown.append("None recorded.\n\n");
            } else {
                for (FieldDependencyPlan.FieldLink field : view.fields().fields()) {
                    markdown.append("- `").append(escMarkdown(field.fromOwner())).append(".")
                            .append(escMarkdown(field.field())).append("` → `")
                            .append(escMarkdown(field.toOwner())).append("`\n");
                }
                markdown.append('\n');
            }
            markdown.append("### Safety boundary\n\n")
                    .append(safetyText(chain, verification));
        }
        return markdown.toString();
    }

    private static String displayTitle(Chain chain) {
        return chain.entryClass().replace('/', '.') + "." + chain.entryMethod()
                + " → " + chain.sinkClass().replace('/', '.') + "." + chain.sinkMethod();
    }

    private static String displayPath(Chain chain, VerificationSummary.ChainResult verification) {
        String path = CsvReporter.pathSummary(chain);
        if (path == null || path.isBlank()) {
            path = chain.entryClass() + "." + chain.entryMethod() + " → "
                    + chain.sinkClass() + "." + chain.sinkMethod();
        }
        String normalized = path.replace('/', '.');
        String sink = chain.sinkClass().replace('/', '.') + "." + chain.sinkMethod();
        if (!normalized.endsWith(sink)) {
            normalized = normalized + " -> " + sink;
        }
        return normalized + " [" + boundaryLabel(verification) + "]";
    }

    private static String boundaryLabel(VerificationSummary.ChainResult verification) {
        if (verification == null) {
            return "SINK BOUNDARY NOT EXECUTED BY THIS PLAN";
        }
        return switch (verification.status()) {
            case "SINK_BLOCKED" -> "SINK BLOCKED BEFORE BODY";
            case "SAFE_EFFECT_OBSERVED" -> "SAFE EFFECT OBSERVED; REAL SINK NOT ENTERED";
            case "CONCRETE_REACHED" -> "CONCRETE TRIGGER; SINK NOT PROVEN";
            case "EXECUTED" -> "ENTRY RETURNED; SINK NOT PROVEN";
            default -> "SINK BOUNDARY NOT PROVEN";
        };
    }

    private static String executionLabel() {
        return "NOT_EXECUTED_BY_INERT_PLAN";
    }

    private static String observedBoundary(VerificationSummary.ChainResult verification) {
        if (verification == null) {
            return "NOT_SELECTED";
        }
        return switch (verification.status()) {
            case "SINK_BLOCKED" -> "SINK_BLOCKED_BEFORE_BODY";
            case "SAFE_EFFECT_OBSERVED" -> "SAFE_EFFECT_OBSERVED_WITH_DISTORTION";
            case "CONCRETE_REACHED" -> "CONCRETE_TRIGGER_WITHOUT_EXACT_CANARY";
            case "EXECUTED" -> "ENTRY_RETURNED_WITHOUT_SINK_PROOF";
            default -> "NOT_PROVEN";
        };
    }

    private static List<String> stepLabels(Chain chain) {
        List<String> labels = new ArrayList<>();
        List<ChainHop> hops = new ArrayList<>(chain.hops());
        java.util.Collections.reverse(hops);
        for (ChainHop hop : hops) {
            String from = dotted(hop.fromOwner(), hop.fromName());
            String to = dotted(hop.toOwner(), hop.toName());
            String label;
            if (hop.kind() == HopKind.ENTRY) {
                label = "ENTRY " + chain.entryKind() + ": " + dotted(chain.entryClass(), chain.entryMethod());
            } else if (hop.kind() == HopKind.FIELD_FLOW) {
                label = "FIELD " + from + "." + nullToDash(hop.field()) + " -> " + to;
            } else {
                label = hop.kind() + " " + from + " -> " + to;
                if (hop.reason() != null && !hop.reason().isBlank()) {
                    label += " (" + hop.reason() + ")";
                }
            }
            labels.add(label);
        }
        labels.add("SINK BOUNDARY " + dotted(chain.sinkClass(), chain.sinkMethod()));
        return List.copyOf(labels);
    }

    private static String dotted(String owner, String method) {
        return (owner == null ? "?" : owner.replace('/', '.')) + "." + nullToDash(method);
    }

    private static String nullToDash(String value) {
        return value == null || value.isBlank() ? "?" : value;
    }

    private static String safetyText(Chain chain, VerificationSummary.ChainResult verification) {
        String sink = escMarkdown(dotted(chain.sinkClass(), chain.sinkMethod()));
        if (verification != null && "SINK_BLOCKED".equals(verification.status())) {
            return "`SINK_CANARY_ONLY`: the real prefix reached the canary and stopped before `"
                    + sink + "` executed. No command, network, native load, or serialized attack bytes are emitted.\n\n";
        }
        if (verification != null && "SAFE_EFFECT_OBSERVED".equals(verification.status())) {
            return "`SAFE_EFFECT_OBSERVED`: a fixed inert/mock effect was observed under the declared policy; the real sink `"
                    + sink + "` was not entered. This result is intentionally distorted and does not prove RCE, network access, native loading, or exploitability.\n\n";
        }
        return "`SINK_CANARY_ONLY`: this artifact is an inert plan. The final sink `" + sink
                + "` is not proven reachable by the recorded verification status. No command, network, native load, or serialized attack bytes are emitted.\n\n";
    }

    private static String escMarkdown(String value) {
        return value == null ? "" : value.replace("`", "'")
                .replace("\r", " ").replace("\n", " ");
    }

    private static String capabilityOf(Chain chain) {
        String owner = chain.sinkClass();
        String method = chain.sinkMethod();
        if ((owner != null && (owner.contains("/rmi/") || owner.startsWith("sun/rmi/")))
                || (method != null && (method.contains("load") || method.contains("exec")))) {
            return "DANGEROUS_CAPABILITY_BOUNDARY";
        }
        return "IN_PROCESS_CANARY";
    }

    private static String esc(String value) {
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
