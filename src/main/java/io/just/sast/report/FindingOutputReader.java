package io.just.sast.report;

import io.just.sast.analysis.entry.ApplicationChainEvidence;
import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ConstructionSummary;
import io.just.sast.blackboard.FindingId;
import io.just.sast.blackboard.FindingState;
import io.just.sast.blackboard.VerificationSummary;
import io.just.sast.chain.ChainPrecision;
import io.just.sast.chain.ChainIds;
import io.just.sast.chain.ChainRanking;
import io.just.sast.chain.ConfidenceScorer;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;

/**
 * Canonical report reader for the typed finding contract.
 *
 * <p>This class is intentionally a reader, not an analyzer.  It freezes the immutable inputs at
 * the report boundary and computes the shared evidence tuple once.  Renderers may keep their
 * legacy wire fields during migration, but they must consume this snapshot instead of parsing
 * notes or recomputing a format-specific ranking.  A missing producer-side {@link FindingState}
 * is represented conservatively; no application entry, dependency join, terminal impact or
 * external control is invented from a chain name or free-form note.</p>
 */
public final class FindingOutputReader {

    public static final String SCHEMA_VERSION = "JUST-FINDING-OUTPUT-D004-V1";

    /** One immutable finding projection shared by all report formats. */
    public record Finding(
            String id,
            Chain chain,
            List<String> notes,
            VerificationSummary.ChainResult verification,
            FindingState state,
            ConfidenceScorer.ConfidenceTransition confidence,
            ChainRanking.Evidence ranking,
            ChainPrecision.Assessment precision,
            boolean highConfidence,
            ConstructionSummary construction,
            boolean exported,
            String calibration) {

        public Finding {
            id = Objects.requireNonNull(id, "id");
            chain = Objects.requireNonNull(chain, "chain");
            notes = stableNotes(notes);
            state = Objects.requireNonNull(state, "state");
            confidence = Objects.requireNonNull(confidence, "confidence");
            ranking = Objects.requireNonNull(ranking, "ranking");
            precision = Objects.requireNonNull(precision, "precision");
            construction = Objects.requireNonNull(construction, "construction");
            calibration = calibration == null ? "" : calibration;
        }

        public String verificationStatus(boolean structuredVerification) {
            return legacyVerificationStatus(verification, notes, structuredVerification);
        }

        public String verificationEvidence() {
            return verification == null ? "" : normalize(verification.evidence(), "UNKNOWN");
        }

        public String verificationGroup() {
            return ReportEvidence.verificationGroup(verification);
        }

        public List<String> typedViolations() {
            return state.defaultFindingViolations();
        }

        private static List<String> stableNotes(List<String> input) {
            if (input == null || input.isEmpty()) {
                return List.of();
            }
            List<String> copy = new ArrayList<>();
            input.stream().filter(Objects::nonNull).forEach(copy::add);
            return List.copyOf(copy);
        }

        private static String normalize(String value, String fallback) {
            return value == null || value.isBlank() ? fallback : value;
        }
    }

    /** Frozen report view.  All maps and lists are immutable and deterministically ordered. */
    public record Snapshot(
            String schemaVersion,
            List<Finding> findings,
            Map<String, Finding> byChainKey,
            Map<String, VerificationSummary.ChainResult> verificationByKey,
            boolean structuredVerification,
            Map<String, ApplicationTrace> applicationTraces) {

        /** Compatibility constructor for callers that do not have application evidence. */
        public Snapshot(String schemaVersion, List<Finding> findings,
                        Map<String, Finding> byChainKey,
                        Map<String, VerificationSummary.ChainResult> verificationByKey,
                        boolean structuredVerification) {
            this(schemaVersion, findings, byChainKey, verificationByKey, structuredVerification,
                    Map.of());
        }

        public Snapshot {
            if (!SCHEMA_VERSION.equals(schemaVersion)) {
                throw new IllegalArgumentException("unsupported finding output schema: "
                        + schemaVersion);
            }
            List<Finding> ordered = new ArrayList<>(findings == null ? List.of() : findings);
            ordered.sort(Comparator.comparing(Finding::id).thenComparing(f -> f.chain().key()));
            findings = List.copyOf(ordered);
            Map<String, Finding> stableFindings = new TreeMap<>();
            for (Finding finding : findings) {
                stableFindings.putIfAbsent(finding.chain().key(), finding);
            }
            byChainKey = Map.copyOf(stableFindings);
            Map<String, VerificationSummary.ChainResult> stableResults = new TreeMap<>();
            if (verificationByKey != null) {
                verificationByKey.forEach((key, value) -> {
                    if (key != null && value != null) {
                        stableResults.putIfAbsent(key, value);
                    }
                });
            }
            verificationByKey = Map.copyOf(stableResults);
            Map<String, ApplicationTrace> stableTraces = new TreeMap<>();
            if (applicationTraces != null) {
                applicationTraces.forEach((key, value) -> {
                    if (key != null && !key.isBlank() && value != null) {
                        stableTraces.putIfAbsent(key, value);
                    }
                });
            }
            applicationTraces = Map.copyOf(stableTraces);
        }

        public Finding require(String chainKey) {
            Finding finding = byChainKey.get(chainKey);
            if (finding == null) {
                throw new IllegalArgumentException("unknown finding chain key: " + chainKey);
            }
            return finding;
        }

        public List<Finding> exported() {
            return findings.stream().filter(Finding::exported).toList();
        }

        /** Typed application-entry projection for a raw chain key, if one was joined. */
        public ApplicationTrace applicationTrace(String chainKey) {
            return applicationTraces.get(chainKey);
        }

        /** Canonical machine contract used by migration goldens and cache/debug consumers. */
        public String toCanonicalJson() {
            StringBuilder json = new StringBuilder("{\"schema_version\":\"")
                    .append(escape(schemaVersion)).append("\",\"structured_verification\":")
                    .append(structuredVerification).append(",\"findings\":[");
            for (int i = 0; i < findings.size(); i++) {
                if (i > 0) json.append(',');
                Finding finding = findings.get(i);
                Chain chain = finding.chain();
                FindingState state = finding.state();
                json.append("{\"id\":\"").append(escape(finding.id()))
                        .append("\",\"chain_key\":\"").append(escape(chain.key()))
                        .append("\",\"rule_id\":\"").append(escape(chain.ruleId()))
                        .append("\",\"entry_class\":\"").append(escape(chain.entryClass()))
                        .append("\",\"entry_method\":\"").append(escape(chain.entryMethod()))
                        .append("\",\"entry_kind\":\"").append(escape(chain.entryKind()))
                        .append("\",\"sink_class\":\"").append(escape(chain.sinkClass()))
                        .append("\",\"sink_method\":\"").append(escape(chain.sinkMethod()))
                        .append("\",\"sink_role\":\"").append(escape(chain.sinkRole()))
                        .append("\",\"sink_risk\":\"").append(chain.sinkRisk())
                        .append("\",\"entry_status\":\"").append(state.entryStatus())
                        .append("\",\"chain_progress\":\"").append(state.chainProgress())
                        .append("\",\"feasibility\":\"").append(state.feasibility())
                        .append("\",\"completeness\":\"").append(state.completeness())
                        .append("\",\"verification\":\"").append(state.verification())
                        .append("\",\"risk\":\"").append(state.risk())
                        .append("\",\"eligibility\":\"")
                        .append(escape(state.eligibility().name())).append("\",\"violations\":");
                appendStrings(json, state.defaultFindingViolations());
                json.append(",\"confidence\":\"")
                        .append(escape(finding.confidence().bucket()))
                        .append("\",\"confidence_reason\":\"")
                        .append(escape(finding.confidence().reasonCode()))
                        .append("\",\"static_rank\":")
                        .append(finding.confidence().features().staticRank())
                        .append(",\"total_score\":")
                        .append(finding.confidence().features().totalScore())
                        .append(",\"verification_status\":\"")
                        .append(escape(finding.verificationStatus(structuredVerification)))
                        .append("\",\"verification_group\":\"")
                        .append(escape(finding.verificationGroup()))
                        .append("\",\"exported\":").append(finding.exported())
                        .append(",\"calibration\":\"").append(escape(finding.calibration()))
                        .append("\",\"application_trace\":");
                ApplicationTrace trace = applicationTraces.get(chain.key());
                json.append(trace == null ? "null" : trace.toCanonicalJson()).append('}');
            }
            return json.append("]}").toString();
        }

        public String digest() {
            return ChainIds.sha256(toCanonicalJson());
        }
    }

    public Snapshot read(List<Chain> chains, Map<String, String> calibrations,
                         Map<String, List<String>> notes, VerificationSummary verification) {
        return read(chains, calibrations, notes, verification, Map.of());
    }

    /**
     * Read a single immutable snapshot.  The optional map is the only producer-side route for
     * proving typed state during the migration; absent keys deliberately stay conservative.
     */
    public Snapshot read(List<Chain> chains, Map<String, String> calibrations,
                         Map<String, List<String>> notes, VerificationSummary verification,
                         Map<String, FindingState> typedStates) {
        return read(chains, calibrations, notes, verification, typedStates, false);
    }

    /**
     * Read a report snapshot with an explicit default-export policy.
     *
     * <p>The legacy overloads intentionally keep their compatibility projection for
     * standalone renderer callers that do not provide producer-side typed state.  The scan
     * pipeline must pass {@code enforceDefaultExportPolicy=true}: in that product path a
     * finding is exported only when the immutable state satisfies the complete application
     * entry/join/terminal contract.  Rejected candidates remain in this canonical snapshot so
     * the audit evidence and calibration writers can explain why they were not user findings.</p>
     */
    public Snapshot read(List<Chain> chains, Map<String, String> calibrations,
                         Map<String, List<String>> notes, VerificationSummary verification,
                         Map<String, FindingState> typedStates,
                         boolean enforceDefaultExportPolicy) {
        return read(chains, calibrations, notes, verification, typedStates,
                enforceDefaultExportPolicy, null);
    }

    /**
     * Read a snapshot with the producer-owned application evidence carried to every renderer.
     * This additive overload leaves compatibility callers unable to infer an application root
     * from a legacy chain or free-form note.
     */
    public Snapshot read(List<Chain> chains, Map<String, String> calibrations,
                         Map<String, List<String>> notes, VerificationSummary verification,
                         Map<String, FindingState> typedStates,
                         boolean enforceDefaultExportPolicy,
                         ApplicationChainEvidence applicationEvidence) {
        List<Chain> input = chains == null ? List.of() : chains;
        Map<String, String> hidden = calibrations == null ? Map.of() : calibrations;
        Map<String, List<String>> stableNotes = stableNotesMap(notes);
        Map<String, FindingState> states = typedStates == null ? Map.of() : typedStates;
        Map<String, VerificationSummary.ChainResult> results = verificationByKey(verification);
        Map<String, Finding> byKey = new LinkedHashMap<>();
        List<Finding> allFindings = new ArrayList<>();
        for (Chain chain : input) {
            if (chain == null) {
                continue;
            }
            List<String> chainNotes = stableNotes.getOrDefault(chain.key(), List.of());
            VerificationSummary.ChainResult result = results.get(chain.key());
            FindingState state = states.get(chain.key());
            if (state == null) {
                state = conservativeState(chain, result);
            }
            ConfidenceScorer.ConfidenceTransition confidence =
                    ConfidenceScorer.transition(chain, chainNotes);
            ChainRanking.Evidence ranking = ChainRanking.evidence(chain, stableNotes, results,
                    Set.of());
            ChainPrecision.Assessment precision = ChainPrecision.assess(chain, chainNotes, result);
            ConstructionSummary construction = ReportEvidence.construction(chain, chainNotes,
                    result);
            Finding candidate = new Finding(
                    FindingId.fromCanonical(chain.ruleId(), chain.key()).value(), chain,
                    chainNotes, result, state, confidence, ranking, precision,
                    ChainPrecision.isHighConfidence(chain, chainNotes, result), construction,
                    (!enforceDefaultExportPolicy || state.defaultFindingEligible())
                            && !hidden.containsKey(chain.key()),
                    hidden.getOrDefault(chain.key(), ""));
            allFindings.add(candidate);
            // A duplicate key is retained as one canonical reader row.  Format-specific
            // renderers may still expose variants through chains.csv/edges.csv, but must not
            // let iteration order select a different semantic projection.
            byKey.putIfAbsent(chain.key(), candidate);
        }
        return new Snapshot(SCHEMA_VERSION, allFindings, byKey, results,
                verification != null, ApplicationTrace.fromEvidence(applicationEvidence));
    }

    public static FindingState conservativeState(Chain chain,
                                                 VerificationSummary.ChainResult result) {
        Objects.requireNonNull(chain, "chain");
        FindingState.EntryStatus entry = FindingState.EntryStatus.NO_APPLICATION_ENTRY;
        FindingState.ChainProgress progress = FindingState.ChainProgress.ENTRY_IDENTIFIED;
        FindingState.Feasibility feasibility = FindingState.Feasibility.UNKNOWN;
        FindingState.Completeness completeness = chain.unresolvedHops() > 0
                ? FindingState.Completeness.PARTIAL : FindingState.Completeness.UNKNOWN;
        FindingState.Verification verification = verification(result);
        FindingState.Risk risk = switch (chain.sinkRisk()) {
            case SAFE_CALLABLE -> FindingState.Risk.LOW;
            case CONTROLLED_EFFECT -> FindingState.Risk.MEDIUM;
            case HIGH_RISK_TERMINAL -> FindingState.Risk.HIGH;
        };
        return new FindingState(entry, progress, feasibility, completeness, verification, risk);
    }

    public static Map<String, VerificationSummary.ChainResult> verificationByKey(
            VerificationSummary verification) {
        if (verification == null || verification.results().isEmpty()) {
            return Map.of();
        }
        Map<String, VerificationSummary.ChainResult> result = new TreeMap<>();
        for (VerificationSummary.ChainResult item : verification.results()) {
            if (item != null) {
                result.putIfAbsent(item.chainKey(), item);
            }
        }
        return Map.copyOf(result);
    }

    /**
     * Compatibility projection for report formats that still expose the v1 verification label.
     * The parser is deliberately kept here, next to the canonical finding reader, so format
     * writers cannot disagree about note precedence while the analyzer migrates to typed
     * verification outcomes.  A typed result always wins; notes are consulted only when the
     * caller explicitly has no structured result.
     */
    public static String legacyVerificationStatus(VerificationSummary.ChainResult result,
                                                  List<String> notes,
                                                  boolean structuredVerification) {
        if (result != null) {
            return normalizeStatus(result.status(), "UNKNOWN");
        }
        if (structuredVerification) {
            return "NOT_SELECTED";
        }
        String status = ConfidenceScorer.statusFromNotes(notes);
        return status.isBlank() ? "NOT_SELECTED" : status;
    }

    /** Compatibility confidence label used by SARIF/v1 consumers during the migration. */
    public static String legacyConfidence(Chain chain, List<String> notes,
                                          VerificationSummary.ChainResult result,
                                          boolean structuredVerification) {
        if (result != null) {
            return legacyVerificationStatus(result, notes, structuredVerification);
        }
        if (structuredVerification) {
            return "NOT_SELECTED";
        }
        List<String> stable = notes == null ? List.of() : notes;
        if (stable.contains("verify:confirmed") && !stable.contains("verify:sink-blocked")) {
            return "CONFIRMED";
        }
        String status = ConfidenceScorer.statusFromNotes(stable);
        return status.isBlank() ? ConfidenceScorer.score(chain, stable) : status;
    }

    private static String normalizeStatus(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value;
    }

    private static Map<String, List<String>> stableNotesMap(Map<String, List<String>> notes) {
        if (notes == null || notes.isEmpty()) {
            return Map.of();
        }
        Map<String, List<String>> stable = new TreeMap<>();
        notes.forEach((key, value) -> {
            if (key != null) {
                stable.put(key, value == null ? List.of() : List.copyOf(value.stream()
                        .filter(Objects::nonNull).toList()));
            }
        });
        return Map.copyOf(stable);
    }

    private static FindingState.Verification verification(VerificationSummary.ChainResult result) {
        if (result == null) {
            return FindingState.Verification.NOT_ATTEMPTED;
        }
        return switch (result.outcomeStatus()) {
            case SINK_BLOCKED -> FindingState.Verification.DYNAMIC_BOUNDARY_CONFIRMED;
            case PRE_SINK_CONFIRMED, CONCRETE_REACHED, EXECUTED ->
                    FindingState.Verification.DYNAMIC_SEGMENT_CONFIRMED;
            case SINK_EXECUTED_SAFE, JNI_EXECUTED_SAFE ->
                    FindingState.Verification.SAFE_TERMINAL_CONFIRMED;
            case SAFE_EFFECT_OBSERVED -> FindingState.Verification.DYNAMIC_SEGMENT_CONFIRMED;
            case PARTIAL, FAILED, TIMEOUT -> FindingState.Verification.FAILED;
            case UNTESTABLE -> FindingState.Verification.UNSUPPORTED;
            case UNKNOWN -> FindingState.Verification.UNKNOWN;
        };
    }

    private static void appendStrings(StringBuilder json, List<String> values) {
        json.append('[');
        for (int i = 0; i < values.size(); i++) {
            if (i > 0) json.append(',');
            json.append('\"').append(escape(values.get(i))).append('\"');
        }
        json.append(']');
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
                    if (ch < 0x20) out.append(String.format(java.util.Locale.ROOT,
                            "\\u%04x", (int) ch));
                    else out.append(ch);
                }
            }
        }
        return out.toString();
    }
}
