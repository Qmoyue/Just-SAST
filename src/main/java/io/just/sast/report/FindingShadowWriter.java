package io.just.sast.report;

import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.FindingId;
import io.just.sast.blackboard.FindingState;
import io.just.sast.blackboard.SinkRisk;
import io.just.sast.blackboard.VerificationSummary;
import io.just.sast.chain.ChainIds;
import io.just.sast.chain.ConfidenceScorer;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * Additive v1/v2 finding shadow used while the typed state becomes the report source of truth.
 *
 * <p>The legacy fields are a compact projection of the existing chain/report contract.  The
 * typed fields are deliberately conservative: application ownership, external control, a
 * dependency join and constraints are only promoted when an explicit typed marker is present.
 * A legacy terminal-looking chain therefore cannot silently become an eligible application
 * finding during the shadow period.  The document is metadata/evidence only; default
 * findings.json, SARIF, CSV, HTML and Markdown continue to use their existing reader.</p>
 */
public final class FindingShadowWriter {

    public static final String SCHEMA_VERSION = "JUST-FINDING-D003-V1";
    public static final String RULES_SCHEMA_VERSION = "JUST-RULES-D002-V2";
    public static final String RULES_SEMANTICS_VERSION = "1";
    public static final String PROJECTION = "LEGACY_CHAIN_ADAPTER_V1";

    /** Closed categories make a shadow diff machine-actionable without parsing prose. */
    public enum Difference {
        NO_DIFFERENCE,
        LEGACY_CALIBRATED_HIDDEN,
        V2_ENTRY_UNPROVEN,
        V2_EXTERNAL_CONTROL_UNPROVEN,
        V2_DEPENDENCY_JOIN_UNPROVEN,
        V2_IMPACT_UNPROVEN,
        V2_CONSTRAINT_UNKNOWN,
        V2_COMPLETENESS_UNKNOWN,
        LEGACY_TERMINAL_WITHOUT_TYPED_IMPACT,
        LEGACY_FEASIBLE_WITHOUT_TYPED_ELIGIBILITY,
        V2_DYNAMIC_UNKNOWN_OR_FAILED,
        V2_DUPLICATE_FINDING_ID,
        V2_PROJECTION_ONLY
    }

    public record Legacy(String chainId, String confidence, int rank, String sinkRole,
                         String sinkRisk, String entryKind, int chainLength, int unresolvedHops,
                         String verificationStatus, boolean exported, String calibration) {
        public Legacy {
            chainId = normalize(chainId, "UNKNOWN");
            confidence = normalize(confidence, "UNKNOWN");
            rank = Math.max(0, rank);
            sinkRole = normalize(sinkRole, "UNKNOWN");
            sinkRisk = normalize(sinkRisk, "UNKNOWN");
            entryKind = normalize(entryKind, "UNKNOWN");
            chainLength = Math.max(0, chainLength);
            unresolvedHops = Math.max(0, unresolvedHops);
            verificationStatus = normalize(verificationStatus, "NOT_SELECTED");
            calibration = calibration == null ? "" : calibration;
        }
    }

    public record Typed(FindingState state, String eligibility, List<String> violations,
                        String projection, String confidenceBucket, String confidenceReason,
                        int staticRank, int totalScore) {
        public Typed {
            state = Objects.requireNonNull(state, "state");
            eligibility = normalize(eligibility, state.eligibility().name());
            List<String> copy = new ArrayList<>(violations == null ? List.of() : violations);
            copy.removeIf(value -> value == null || value.isBlank());
            copy.sort(String::compareTo);
            violations = List.copyOf(copy);
            projection = normalize(projection, PROJECTION);
            confidenceBucket = normalize(confidenceBucket, "UNKNOWN");
            confidenceReason = normalize(confidenceReason, "UNKNOWN");
            staticRank = Math.max(0, staticRank);
            totalScore = Math.max(0, totalScore);
        }
    }

    public record FindingRecord(String id, int legacyCount, Legacy legacy, Typed typed,
                                List<String> differences) {
        public FindingRecord {
            if (id == null || !id.startsWith("finding-")) {
                throw new IllegalArgumentException("finding shadow id is invalid: " + id);
            }
            legacyCount = Math.max(1, legacyCount);
            legacy = Objects.requireNonNull(legacy, "legacy");
            typed = Objects.requireNonNull(typed, "typed");
            List<String> sorted = new ArrayList<>(differences == null ? List.of() : differences);
            sorted.removeIf(value -> value == null || value.isBlank());
            sorted.sort(String::compareTo);
            sorted.forEach(value -> {
                try {
                    Difference.valueOf(value);
                } catch (IllegalArgumentException ex) {
                    throw new IllegalArgumentException("unknown finding shadow difference: "
                            + value, ex);
                }
            });
            differences = List.copyOf(sorted.isEmpty()
                    ? List.of(Difference.NO_DIFFERENCE.name()) : sorted);
        }

        public String toCanonicalJson() {
            StringBuilder json = new StringBuilder("{\"id\":\"")
                    .append(esc(id)).append("\",\"legacy_count\":")
                    .append(legacyCount).append(",\"legacy\":");
            appendLegacy(json, legacy);
            json.append(",\"typed\":");
            appendTyped(json, typed);
            json.append(",\"differences\":[");
            for (int i = 0; i < differences.size(); i++) {
                if (i > 0) json.append(',');
                json.append('\"').append(esc(differences.get(i))).append('\"');
            }
            return json.append("]}").toString();
        }
    }

    public record Document(String schemaVersion, String rulesSchemaVersion,
                           String rulesSemanticsVersion, String projection,
                           List<FindingRecord> findings, Map<String, Integer> differenceCounts) {
        public Document {
            if (!SCHEMA_VERSION.equals(schemaVersion)) {
                throw new IllegalArgumentException("unsupported finding shadow schema: "
                        + schemaVersion);
            }
            rulesSchemaVersion = normalize(rulesSchemaVersion, RULES_SCHEMA_VERSION);
            rulesSemanticsVersion = normalize(rulesSemanticsVersion, RULES_SEMANTICS_VERSION);
            projection = normalize(projection, PROJECTION);
            List<FindingRecord> sorted = new ArrayList<>(findings == null ? List.of() : findings);
            sorted.sort(Comparator.comparing(FindingRecord::id));
            Set<String> ids = new TreeSet<>();
            for (FindingRecord finding : sorted) {
                if (!ids.add(finding.id())) {
                    throw new IllegalArgumentException("duplicate finding shadow id: "
                            + finding.id());
                }
            }
            findings = List.copyOf(sorted);
            Map<String, Integer> counts = new TreeMap<>();
            if (differenceCounts != null) {
                differenceCounts.forEach((key, value) -> {
                    if (key != null && !key.isBlank() && value != null && value > 0) {
                        try {
                            Difference.valueOf(key);
                        } catch (IllegalArgumentException ex) {
                            throw new IllegalArgumentException(
                                    "unknown finding shadow difference count: " + key, ex);
                        }
                        counts.put(key, value);
                    }
                });
            }
            if (counts.isEmpty()) {
                for (FindingRecord finding : findings) {
                    for (String difference : finding.differences()) {
                        counts.merge(difference, 1, Integer::sum);
                    }
                }
            }
            differenceCounts = Map.copyOf(counts);
        }

        public String toCanonicalJson() {
            StringBuilder json = new StringBuilder("{\"schema_version\":\"")
                    .append(esc(schemaVersion)).append("\",\"rules_schema_version\":\"")
                    .append(esc(rulesSchemaVersion)).append("\",\"rules_semantics_version\":\"")
                    .append(esc(rulesSemanticsVersion)).append("\",\"projection\":\"")
                    .append(esc(projection)).append("\",\"findings\":[");
            for (int i = 0; i < findings.size(); i++) {
                if (i > 0) json.append(',');
                json.append(findings.get(i).toCanonicalJson());
            }
            json.append("],\"difference_counts\":{");
            List<Map.Entry<String, Integer>> counts = new ArrayList<>(differenceCounts.entrySet());
            counts.sort(Map.Entry.comparingByKey());
            for (int i = 0; i < counts.size(); i++) {
                if (i > 0) json.append(',');
                Map.Entry<String, Integer> entry = counts.get(i);
                json.append('\"').append(esc(entry.getKey())).append("\":")
                        .append(entry.getValue());
            }
            return json.append("}}").toString();
        }

        public String digest() {
            return ChainIds.sha256(toCanonicalJson());
        }
    }

    public Document build(List<Chain> chains, Map<String, String> calibrations,
                          Map<String, List<String>> notes, VerificationSummary verification) {
        return build(chains, calibrations, notes, verification, Map.of());
    }

    /**
     * Build a shadow with an optional typed-state map keyed by the legacy chain key.  The
     * pipeline currently passes no map because the EvidenceGraph producer is scheduled for
     * P3.1; consequently absent state is conservatively unknown rather than inferred from
     * free-form notes.
     */
    public Document build(List<Chain> chains, Map<String, String> calibrations,
                          Map<String, List<String>> notes, VerificationSummary verification,
                          Map<String, FindingState> typedStates) {
        List<Chain> input = chains == null ? List.of() : chains;
        Map<String, String> hidden = calibrations == null ? Map.of() : calibrations;
        Map<String, List<String>> stableNotes = notes == null ? Map.of() : notes;
        FindingOutputReader.Snapshot snapshot = new FindingOutputReader().read(
                input, hidden, stableNotes, verification, typedStates);
        return build(snapshot);
    }

    /** Build a shadow directly from the report-boundary snapshot without re-reading legacy data. */
    public Document build(FindingOutputReader.Snapshot snapshot) {
        Objects.requireNonNull(snapshot, "finding output snapshot");
        Map<String, FindingRecord> records = new LinkedHashMap<>();
        for (FindingOutputReader.Finding view : snapshot.findings()) {
            Chain chain = view.chain();
            List<String> chainNotes = view.notes();
            VerificationSummary.ChainResult result = view.verification();
            String id = FindingId.fromCanonical(chain.ruleId(), chain.key()).value();
            boolean exported = view.exported();
            String calibration = view.calibration();
            Legacy legacy = legacy(chain, view, chainNotes, result, exported, calibration);
            FindingState state = view.state();
            ConfidenceScorer.ConfidenceTransition transition = view.confidence();
            Typed typed = new Typed(state, state.eligibility().name(),
                    state.defaultFindingViolations(), PROJECTION, transition.bucket(),
                    transition.reasonCode(), transition.features().staticRank(),
                    transition.features().totalScore());
            List<String> differences = differences(chain, legacy, typed);
            FindingRecord next = new FindingRecord(id, 1, legacy, typed, differences);
            FindingRecord previous = records.putIfAbsent(id, next);
            if (previous != null) {
                int count = previous.legacyCount() + 1;
                // Keep one canonical record and make the duplicate visible rather than letting
                // report ordering decide which legacy chain silently wins.
                List<String> merged = new ArrayList<>(previous.differences());
                merged.add(Difference.V2_DUPLICATE_FINDING_ID.name());
                records.put(id, new FindingRecord(id, count, previous.legacy(), previous.typed(),
                        merged));
            }
        }
        List<FindingRecord> findings = new ArrayList<>(records.values());
        findings.sort(Comparator.comparing(FindingRecord::id));
        Map<String, Integer> counts = new TreeMap<>();
        for (FindingRecord finding : findings) {
            for (String difference : finding.differences()) {
                counts.merge(difference, 1, Integer::sum);
            }
        }
        return new Document(SCHEMA_VERSION, RULES_SCHEMA_VERSION, RULES_SEMANTICS_VERSION,
                PROJECTION, findings, counts);
    }

    public Path write(ReportLayout layout, List<Chain> chains, Map<String, String> calibrations,
                      Map<String, List<String>> notes, VerificationSummary verification)
            throws IOException {
        return write(layout, chains, calibrations, notes, verification, Map.of());
    }

    public Path write(ReportLayout layout, List<Chain> chains, Map<String, String> calibrations,
                      Map<String, List<String>> notes, VerificationSummary verification,
                      Map<String, FindingState> typedStates) throws IOException {
        if (layout == null) {
            throw new IOException("report layout is null");
        }
        Document document = build(chains, calibrations, notes, verification, typedStates);
        Path path = layout.meta().resolve("finding-v2-shadow.json");
        AtomicFiles.writeUtf8(path, document.toCanonicalJson() + "\n");
        return path;
    }

    /** Write the shadow projection from the already-frozen canonical snapshot. */
    public Path write(ReportLayout layout, FindingOutputReader.Snapshot snapshot)
            throws IOException {
        if (layout == null) {
            throw new IOException("report layout is null");
        }
        Document document = build(snapshot);
        Path path = layout.meta().resolve("finding-v2-shadow.json");
        AtomicFiles.writeUtf8(path, document.toCanonicalJson() + "\n");
        return path;
    }

    private static Legacy legacy(Chain chain, FindingOutputReader.Finding view,
                                 List<String> notes, VerificationSummary.ChainResult result,
                                 boolean exported, String calibration) {
        String status = view == null ? (result == null ? ConfidenceScorer.statusFromNotes(notes)
                : result.status()) : view.verificationStatus(false);
        if (status == null || status.isBlank()) status = "NOT_SELECTED";
        String confidence = view == null ? ConfidenceScorer.score(chain, notes)
                : view.confidence().bucket();
        int rank = view == null ? ConfidenceScorer.rank(chain, notes)
                : view.confidence().features().staticRank();
        return new Legacy(ChainIds.id(chain.key()), confidence, rank, chain.sinkRole(), chain.sinkRisk().name(),
                chain.entryKind(), chain.hops().size(), chain.unresolvedHops(), status,
                exported, calibration);
    }

    private static List<String> differences(Chain chain, Legacy legacy, Typed typed) {
        List<String> differences = new ArrayList<>();
        FindingState state = typed.state();
        if (!legacy.exported()) {
            differences.add(Difference.LEGACY_CALIBRATED_HIDDEN.name());
        }
        if (state.entryStatus() == FindingState.EntryStatus.NO_APPLICATION_ENTRY) {
            differences.add(Difference.V2_ENTRY_UNPROVEN.name());
        } else if (state.entryStatus() != FindingState.EntryStatus.EXTERNAL_ENTRY) {
            differences.add(Difference.V2_EXTERNAL_CONTROL_UNPROVEN.name());
        }
        if (!state.dependencyJoined()) {
            differences.add(Difference.V2_DEPENDENCY_JOIN_UNPROVEN.name());
        }
        if (!state.impactComplete()) {
            differences.add(Difference.V2_IMPACT_UNPROVEN.name());
        }
        if (state.feasibility() == FindingState.Feasibility.UNKNOWN) {
            differences.add(Difference.V2_CONSTRAINT_UNKNOWN.name());
        }
        if (state.completeness() == FindingState.Completeness.UNKNOWN) {
            differences.add(Difference.V2_COMPLETENESS_UNKNOWN.name());
        }
        if (legacy.sinkRole().equalsIgnoreCase("TERMINAL") && !state.impactComplete()) {
            differences.add(Difference.LEGACY_TERMINAL_WITHOUT_TYPED_IMPACT.name());
        }
        if (legacy.confidence().startsWith("FEASIBLE")
                && !state.defaultFindingEligible()) {
            differences.add(Difference.LEGACY_FEASIBLE_WITHOUT_TYPED_ELIGIBILITY.name());
        }
        if (state.verification() == FindingState.Verification.UNKNOWN
                || state.verification() == FindingState.Verification.FAILED
                || state.verification() == FindingState.Verification.UNSUPPORTED) {
            differences.add(Difference.V2_DYNAMIC_UNKNOWN_OR_FAILED.name());
        }
        // All typed values in this phase are adapter projections.  Keeping this code explicit
        // prevents a future consumer from treating a shadow state as proof of an application
        // join before the EvidenceGraph writer is migrated in P1.7/P3.1.
        differences.add(Difference.V2_PROJECTION_ONLY.name());
        differences.sort(String::compareTo);
        return List.copyOf(differences);
    }


    private static void appendLegacy(StringBuilder json, Legacy legacy) {
        json.append("{\"chain_id\":\"").append(esc(legacy.chainId()))
                .append("\",\"confidence\":\"").append(esc(legacy.confidence()))
                .append("\",\"rank\":").append(legacy.rank())
                .append(",\"sink_role\":\"").append(esc(legacy.sinkRole()))
                .append("\",\"sink_risk\":\"").append(esc(legacy.sinkRisk()))
                .append("\",\"entry_kind\":\"").append(esc(legacy.entryKind()))
                .append("\",\"chain_length\":").append(legacy.chainLength())
                .append(",\"unresolved_hops\":").append(legacy.unresolvedHops())
                .append(",\"verification_status\":\"").append(esc(legacy.verificationStatus()))
                .append("\",\"exported\":").append(legacy.exported())
                .append(",\"calibration\":\"").append(esc(legacy.calibration())).append('}');
    }

    private static void appendTyped(StringBuilder json, Typed typed) {
        FindingState state = typed.state();
        json.append("{\"entry_status\":\"").append(state.entryStatus())
                .append("\",\"chain_progress\":\"").append(state.chainProgress())
                .append("\",\"feasibility\":\"").append(state.feasibility())
                .append("\",\"completeness\":\"").append(state.completeness())
                .append("\",\"verification\":\"").append(state.verification())
                .append("\",\"risk\":\"").append(state.risk())
                .append("\",\"eligibility\":\"").append(esc(typed.eligibility()))
                .append("\",\"violations\":");
        appendStrings(json, typed.violations());
        json.append(",\"projection\":\"").append(esc(typed.projection()))
                .append("\",\"confidence_bucket\":\"").append(esc(typed.confidenceBucket()))
                .append("\",\"confidence_reason\":\"").append(esc(typed.confidenceReason()))
                .append("\",\"static_rank\":").append(typed.staticRank())
                .append(",\"total_score\":").append(typed.totalScore()).append('}');
    }

    private static void appendStrings(StringBuilder json, List<String> values) {
        json.append('[');
        for (int i = 0; i < values.size(); i++) {
            if (i > 0) json.append(',');
            json.append('\"').append(esc(values.get(i))).append('\"');
        }
        json.append(']');
    }

    private static String normalize(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value.trim();
    }

    private static String esc(String value) {
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
                    if (ch < 0x20) out.append(String.format(Locale.ROOT, "\\u%04x", (int) ch));
                    else out.append(ch);
                }
            }
        }
        return out.toString();
    }
}
