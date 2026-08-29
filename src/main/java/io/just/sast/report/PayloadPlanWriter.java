package io.just.sast.report;

import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.VerificationSummary;
import io.just.sast.chain.ConfidenceScorer;
import io.just.sast.verify.FieldDependencyPlan;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Writes a safe, deterministic construction plan for the highest-value chains.
 *
 * The artifact is deliberately a plan rather than executable serialization bytes: it exposes
 * object/field/trigger constraints and verification evidence without creating command, native,
 * network, or remote-class-loading payloads.
 */
public final class PayloadPlanWriter {

    private static final int MAX_PLANS = 64;

    public void write(Path outDir, List<Chain> chains, Map<String, String> calibrations,
                      Map<String, List<String>> notes, VerificationSummary verification)
            throws IOException {
        Files.createDirectories(outDir);
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
        ordered.sort(Comparator.comparingInt((Chain chain) ->
                        -ConfidenceScorer.evidenceScore(chain,
                                notes == null ? List.of() : notes.getOrDefault(chain.key(), List.of())))
                .thenComparing(Chain::key));
        if (ordered.size() > MAX_PLANS) {
            ordered = new ArrayList<>(ordered.subList(0, MAX_PLANS));
        }

        StringBuilder json = new StringBuilder("{\n")
                .append("  \"schema_version\":1,\n")
                .append("  \"mode\":\"INERT_OBJECT_GRAPH_PLAN\",\n")
                .append("  \"safety\":\"NO_EXECUTABLE_PAYLOAD\",\n")
                .append("  \"selection_limit\":").append(MAX_PLANS).append(",\n")
                .append("  \"plans\":[\n");
        for (int i = 0; i < ordered.size(); i++) {
            if (i > 0) {
                json.append(",\n");
            }
            Chain chain = ordered.get(i);
            List<String> chainNotes = notes == null
                    ? List.of() : notes.getOrDefault(chain.key(), List.of());
            FieldDependencyPlan fields = FieldDependencyPlan.from(chain, chain.entryKind());
            appendPlan(json, chain, fields, chainNotes, verified.get(chain.key()));
        }
        json.append("\n  ]\n}\n");
        Files.write(outDir.resolve("payload-plan.json"),
                json.toString().getBytes(StandardCharsets.UTF_8));
    }

    private static void appendPlan(StringBuilder json, Chain chain, FieldDependencyPlan fields,
                                   List<String> notes,
                                   VerificationSummary.ChainResult verification) {
        String construction = notes.stream().anyMatch("verify:constructible"::equals)
                ? "CONSTRUCTIBLE"
                : notes.stream().anyMatch("degrade:partial-construct"::equals)
                ? "PARTIAL" : "NOT_EVALUATED";
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
                .append("\",\"capability\":\"").append(esc(capabilityOf(chain))).append("\"}")
                .append(",\"construction\":{\"status\":\"").append(construction)
                .append("\",\"strategy\":\"INERT_REFLECTIVE_OBJECT_GRAPH\"")
                .append(",\"encoded_fields\":\"").append(esc(fields.encodedFields())).append("\"}")
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
        json.append("],\"constraints\":[\"TYPE_COMPATIBLE_FIELDS\",\"BOUNDED_DEPTH\",")
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
