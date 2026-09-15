package io.just.sast.analysis.entry;

import io.just.sast.blackboard.BlackboardFact;
import io.just.sast.blackboard.EntryChainJoinEvidence;
import io.just.sast.blackboard.EvidenceGraph;
import io.just.sast.blackboard.FindingState;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

/**
 * Immutable report-boundary product for application-entry to dependency-chain joins.
 *
 * <p>The product is deliberately separate from the legacy {@code Chain} store.  A chain can
 * still be useful kernel evidence while lacking an application join; this record makes that
 * distinction explicit without allowing a renderer to infer it from notes.</p>
 */
public record ApplicationChainEvidence(
        String schemaVersion,
        String artifactDigest,
        String applicationIndexDigest,
        boolean applicationScopeKnown,
        EvidenceGraph graph,
        Map<String, EntryChainJoinEvidence> joins,
        Map<String, FindingState> states,
        Map<String, String> decisions,
        Map<String, ApplicationEntryIndex.CandidateAdmissionStatus> admissionDecisions,
        List<String> reasons) implements BlackboardFact {

    public static final String SCHEMA_VERSION = "JUST-APPLICATION-CHAIN-EVIDENCE-V1";

    public ApplicationChainEvidence {
        if (!SCHEMA_VERSION.equals(schemaVersion)) {
            throw new IllegalArgumentException("unsupported application-chain evidence schema: "
                    + schemaVersion);
        }
        artifactDigest = normalizeDigest(artifactDigest);
        applicationIndexDigest = normalizeDigest(applicationIndexDigest);
        graph = Objects.requireNonNull(graph, "graph");
        joins = immutableMap(joins);
        states = immutableMap(states);
        decisions = immutableMap(decisions);
        admissionDecisions = immutableEnumMap(admissionDecisions);
        List<String> sortedReasons = new ArrayList<>();
        if (reasons != null) {
            reasons.stream().filter(value -> value != null && !value.isBlank())
                    .map(String::trim).distinct().sorted().forEach(sortedReasons::add);
        }
        reasons = List.copyOf(sortedReasons);
        joins.forEach((key, value) -> {
            if (!Objects.equals(key, value.applicationChainId().value())) {
                throw new IllegalArgumentException("join key does not match application chain id");
            }
        });
        states.keySet().forEach(key -> {
            if (key == null || key.isBlank()) {
                throw new IllegalArgumentException("state key must not be blank");
            }
        });
        admissionDecisions.keySet().forEach(key -> {
            if (key == null || key.isBlank()) {
                throw new IllegalArgumentException("admission decision key must not be blank");
            }
        });
    }

    /** Compatibility constructor for callers that do not yet carry pre-materialization data. */
    public ApplicationChainEvidence(String schemaVersion, String artifactDigest,
                                    String applicationIndexDigest,
                                    boolean applicationScopeKnown, EvidenceGraph graph,
                                    Map<String, EntryChainJoinEvidence> joins,
                                    Map<String, FindingState> states,
                                    Map<String, String> decisions, List<String> reasons) {
        this(schemaVersion, artifactDigest, applicationIndexDigest, applicationScopeKnown, graph,
                joins, states, decisions, Map.of(), reasons);
    }

    public static ApplicationChainEvidence empty(boolean scopeKnown, List<String> reasons) {
        List<String> normalized = new ArrayList<>();
        if (!scopeKnown) {
            normalized.add("APPLICATION_SCOPE_UNKNOWN");
        }
        if (reasons != null) {
            normalized.addAll(reasons);
        }
        return new ApplicationChainEvidence(SCHEMA_VERSION, "UNKNOWN", "UNKNOWN", scopeKnown,
                EvidenceGraph.empty(),
                Map.of(), Map.of(), Map.of(), Map.of(), normalized);
    }

    public int joinCount() {
        return joins.size();
    }

    public int applicationStateCount() {
        return states.size();
    }

    /** Number of raw chains that reached the entry∩terminal admission point. */
    public long candidateJoinCount() {
        return decisions.values().stream()
                .filter(value -> !"APPLICATION_ENTRY_NOT_IN_CHAIN".equals(value)
                        && !"ENTRY_NOT_IN_TERMINAL_INTERSECTION".equals(value))
                .count();
    }

    /** Number of raw chains carrying an application execution entry, including incomplete ones. */
    public long anchoredCandidateCount() {
        return decisions.values().stream()
                .filter(value -> !"APPLICATION_ENTRY_NOT_IN_CHAIN".equals(value))
                .count();
    }

    /** Number of raw chains that passed the typed pre-materialization admission boundary. */
    public long admissionCandidateCount() {
        return admissionDecisions.values().stream()
                .filter(ApplicationEntryIndex.CandidateAdmissionStatus.ADMITTED::equals)
                .count();
    }

    /** Number of raw chains rejected before evidence-node/join construction. */
    public long admissionRejectedCount() {
        return admissionDecisions.values().stream()
                .filter(status -> status != ApplicationEntryIndex.CandidateAdmissionStatus.ADMITTED)
                .count();
    }

    public java.util.Set<String> admissionCandidateKeys() {
        return admissionDecisions.entrySet().stream()
                .filter(entry -> entry.getValue()
                        == ApplicationEntryIndex.CandidateAdmissionStatus.ADMITTED)
                .map(Map.Entry::getKey)
                .collect(java.util.stream.Collectors.toUnmodifiableSet());
    }

    /** Chain keys admitted by the joiner; unlike the evidence map keys these are legacy
     * chain identities consumed by scheduling/report compatibility adapters. */
    public java.util.Set<String> joinedChainKeys() {
        return decisions.entrySet().stream()
                .filter(entry -> "JOINED".equals(entry.getValue()))
                .map(Map.Entry::getKey)
                .collect(java.util.stream.Collectors.toUnmodifiableSet());
    }

    public String semanticDigest() {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            update(digest, schemaVersion);
            update(digest, artifactDigest);
            update(digest, applicationIndexDigest);
            update(digest, Boolean.toString(applicationScopeKnown));
            update(digest, graph.canonicalDigest());
            joins.forEach((key, value) -> {
                update(digest, "join=" + key);
                update(digest, value.canonical());
            });
            states.forEach((key, value) -> update(digest, "state=" + key + "|" + value));
            decisions.forEach((key, value) -> update(digest, "decision=" + key + "|" + value));
            admissionDecisions.forEach((key, value) ->
                    update(digest, "admission=" + key + "|" + value.name()));
            reasons.forEach(value -> update(digest, "reason=" + value));
            StringBuilder result = new StringBuilder(64);
            for (byte value : digest.digest()) {
                result.append(String.format(java.util.Locale.ROOT, "%02x", value & 0xff));
            }
            return result.toString();
        } catch (NoSuchAlgorithmException impossible) {
            throw new AssertionError(impossible);
        }
    }

    public String toCanonicalJson() {
        StringBuilder json = new StringBuilder(1024)
                .append("{\"schema_version\":\"").append(escape(schemaVersion))
                .append("\",\"artifact_digest\":\"").append(escape(artifactDigest))
                .append("\",\"application_index_digest\":\"")
                .append(escape(applicationIndexDigest))
                .append("\",\"application_scope_known\":").append(applicationScopeKnown)
                .append(",\"graph_digest\":\"").append(graph.canonicalDigest())
                .append("\",\"graph\":").append(graph.toCanonicalJson())
                .append(",\"join_count\":").append(joins.size())
                .append(",\"state_count\":").append(states.size())
                .append(",\"joins\":[");
        int index = 0;
        for (EntryChainJoinEvidence join : joins.values()) {
            if (index++ > 0) json.append(',');
            json.append(join.toCanonicalJson());
        }
        json.append("],\"states\":{");
        index = 0;
        for (Map.Entry<String, FindingState> entry : states.entrySet()) {
            if (index++ > 0) json.append(',');
            FindingState state = entry.getValue();
            json.append('"').append(escape(entry.getKey())).append("\":{")
                    .append("\"entry_status\":\"").append(state.entryStatus())
                    .append("\",\"chain_progress\":\"").append(state.chainProgress())
                    .append("\",\"feasibility\":\"").append(state.feasibility())
                    .append("\",\"completeness\":\"").append(state.completeness())
                    .append("\",\"risk\":\"").append(state.risk())
                    .append("\",\"eligibility\":\"").append(state.eligibility())
                    .append("\"}");
        }
        json.append("},\"decisions\":{");
        index = 0;
        for (Map.Entry<String, String> entry : decisions.entrySet()) {
            if (index++ > 0) json.append(',');
            json.append('"').append(escape(entry.getKey())).append("\":\"")
                    .append(escape(entry.getValue())).append('"');
        }
        json.append("},\"admission_decisions\":{");
        index = 0;
        for (Map.Entry<String, ApplicationEntryIndex.CandidateAdmissionStatus> entry
                : admissionDecisions.entrySet()) {
            if (index++ > 0) json.append(',');
            json.append('"').append(escape(entry.getKey())).append("\":\"")
                    .append(entry.getValue().name()).append('"');
        }
        json.append("},\"reasons\":[");
        for (index = 0; index < reasons.size(); index++) {
            if (index > 0) json.append(',');
            json.append('"').append(escape(reasons.get(index))).append('"');
        }
        return json.append("]}").toString();
    }

    /** Attach the scan-boundary artifact identity after the join has been published. */
    public ApplicationChainEvidence withArtifactDigest(String digest) {
        return new ApplicationChainEvidence(schemaVersion, digest, applicationIndexDigest,
                applicationScopeKnown, graph, joins, states, decisions, admissionDecisions,
                reasons);
    }

    private static <T> Map<String, T> immutableMap(Map<String, T> input) {
        if (input == null || input.isEmpty()) {
            return Map.of();
        }
        TreeMap<String, T> sorted = new TreeMap<>();
        input.forEach((key, value) -> {
            if (key != null && !key.isBlank() && value != null) {
                sorted.put(key, value);
            }
        });
        return Collections.unmodifiableMap(sorted);
    }

    private static Map<String, ApplicationEntryIndex.CandidateAdmissionStatus> immutableEnumMap(
            Map<String, ApplicationEntryIndex.CandidateAdmissionStatus> input) {
        if (input == null || input.isEmpty()) {
            return Map.of();
        }
        TreeMap<String, ApplicationEntryIndex.CandidateAdmissionStatus> sorted = new TreeMap<>();
        input.forEach((key, value) -> {
            if (key != null && !key.isBlank() && value != null) {
                sorted.put(key, value);
            }
        });
        return Collections.unmodifiableMap(sorted);
    }

    private static void update(MessageDigest digest, String value) {
        digest.update((value == null ? "" : value).getBytes(StandardCharsets.UTF_8));
        digest.update((byte) 0);
    }

    private static String normalizeDigest(String value) {
        if (value == null || value.isBlank()) {
            return "UNKNOWN";
        }
        String normalized = value.trim();
        if (!"UNKNOWN".equals(normalized)
                && !normalized.matches("[0-9A-Fa-f]{64}")) {
            throw new IllegalArgumentException("digest must be SHA-256 or UNKNOWN: " + value);
        }
        return normalized.toUpperCase(java.util.Locale.ROOT);
    }

    private static String escape(String value) {
        if (value == null) return "";
        StringBuilder out = new StringBuilder(value.length() + 8);
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            switch (ch) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (ch < 0x20) {
                        out.append(String.format(java.util.Locale.ROOT, "\\u%04x", (int) ch));
                    } else {
                        out.append(ch);
                    }
                }
            }
        }
        return out.toString();
    }
}
