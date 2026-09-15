package io.just.sast.report;

import io.just.sast.analysis.entry.ApplicationChainEvidence;
import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ConstructionSummary;
import io.just.sast.blackboard.FindingId;
import io.just.sast.blackboard.FindingState;
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

/** Canonical report reader for the typed static finding contract. */
public final class FindingOutputReader {

    public static final String SCHEMA_VERSION = "JUST-FINDING-OUTPUT-D004-V1";

    /** One immutable finding projection shared by all report formats. */
    public record Finding(
            String id,
            Chain chain,
            List<String> notes,
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
    }

    /** Frozen report view. All maps and lists are immutable and deterministically ordered. */
    public record Snapshot(
            String schemaVersion,
            List<Finding> findings,
            Map<String, Finding> byChainKey,
            Map<String, ApplicationTrace> applicationTraces) {

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

        public ApplicationTrace applicationTrace(String chainKey) {
            return applicationTraces.get(chainKey);
        }

        /** Canonical machine contract used by report, cache and audit consumers. */
        public String toCanonicalJson() {
            StringBuilder json = new StringBuilder("{\"schema_version\":\"")
                    .append(escape(schemaVersion)).append("\",\"findings\":[");
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
                        .append("\",\"entry_descriptor\":\"")
                        .append(escape(ChainIdentity.entryDescriptor(chain)))
                        .append("\",\"entry_kind\":\"").append(escape(chain.entryKind()))
                        .append("\",\"sink_class\":\"").append(escape(chain.sinkClass()))
                        .append("\",\"sink_method\":\"").append(escape(chain.sinkMethod()))
                        .append("\",\"sink_role\":\"").append(escape(chain.sinkRole()))
                        .append("\",\"sink_risk\":\"").append(chain.sinkRisk())
                        .append("\",\"entry_status\":\"").append(state.entryStatus())
                        .append("\",\"chain_progress\":\"").append(state.chainProgress())
                        .append("\",\"feasibility\":\"").append(state.feasibility())
                        .append("\",\"completeness\":\"").append(state.completeness())
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
                        .append(",\"exported\":").append(finding.exported())
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
                         Map<String, List<String>> notes) {
        return read(chains, calibrations, notes, Map.of(), false, null);
    }

    public Snapshot read(List<Chain> chains, Map<String, String> calibrations,
                         Map<String, List<String>> notes,
                         Map<String, FindingState> typedStates) {
        return read(chains, calibrations, notes, typedStates, false, null);
    }

    /** Read a snapshot with an explicit default-export policy. */
    public Snapshot read(List<Chain> chains, Map<String, String> calibrations,
                         Map<String, List<String>> notes,
                         Map<String, FindingState> typedStates,
                         boolean enforceDefaultExportPolicy) {
        return read(chains, calibrations, notes, typedStates,
                enforceDefaultExportPolicy, null);
    }

    /** Read a snapshot with producer-owned application evidence carried to every renderer. */
    public Snapshot read(List<Chain> chains, Map<String, String> calibrations,
                         Map<String, List<String>> notes,
                         Map<String, FindingState> typedStates,
                         boolean enforceDefaultExportPolicy,
                         ApplicationChainEvidence applicationEvidence) {
        List<Chain> input = chains == null ? List.of() : chains;
        Map<String, String> hidden = calibrations == null ? Map.of() : calibrations;
        Map<String, List<String>> stableNotes = stableNotesMap(notes);
        Map<String, FindingState> states = typedStates == null ? Map.of() : typedStates;
        Map<String, Finding> byKey = new LinkedHashMap<>();
        List<Finding> allFindings = new ArrayList<>();
        for (Chain chain : input) {
            if (chain == null) {
                continue;
            }
            List<String> chainNotes = stableNotes.getOrDefault(chain.key(), List.of());
            FindingState state = states.get(chain.key());
            if (state == null) {
                state = conservativeState(chain);
            }
            ConfidenceScorer.ConfidenceTransition confidence =
                    ConfidenceScorer.transition(chain, chainNotes);
            ChainRanking.Evidence ranking = ChainRanking.evidence(chain, stableNotes, Set.of());
            ChainPrecision.Assessment precision = ChainPrecision.assess(chain, chainNotes);
            ConstructionSummary construction = ReportEvidence.construction(chain, chainNotes);
            Finding candidate = new Finding(
                    FindingId.fromCanonical(chain.ruleId(), chain.key()).value(), chain,
                    chainNotes, state, confidence, ranking, precision,
                    ChainPrecision.isHighConfidence(chain, chainNotes), construction,
                    (!enforceDefaultExportPolicy || state.defaultFindingEligible())
                            && !hidden.containsKey(chain.key()),
                    hidden.getOrDefault(chain.key(), ""));
            allFindings.add(candidate);
            byKey.putIfAbsent(chain.key(), candidate);
        }
        return new Snapshot(SCHEMA_VERSION, allFindings, byKey,
                ApplicationTrace.fromEvidence(applicationEvidence));
    }

    public static FindingState conservativeState(Chain chain) {
        Objects.requireNonNull(chain, "chain");
        FindingState.EntryStatus entry = FindingState.EntryStatus.NO_APPLICATION_ENTRY;
        FindingState.ChainProgress progress = FindingState.ChainProgress.ENTRY_IDENTIFIED;
        FindingState.Feasibility feasibility = FindingState.Feasibility.UNKNOWN;
        FindingState.Completeness completeness = chain.unresolvedHops() > 0
                ? FindingState.Completeness.PARTIAL : FindingState.Completeness.UNKNOWN;
        FindingState.Risk risk = switch (chain.sinkRisk()) {
            case SAFE_CALLABLE -> FindingState.Risk.LOW;
            case CONTROLLED_EFFECT -> FindingState.Risk.MEDIUM;
            case HIGH_RISK_TERMINAL -> FindingState.Risk.HIGH;
        };
        return new FindingState(entry, progress, feasibility, completeness, risk);
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

    private static void appendStrings(StringBuilder json, List<String> values) {
        json.append('[');
        for (int i = 0; i < values.size(); i++) {
            if (i > 0) json.append(',');
            json.append('"').append(escape(values.get(i))).append('"');
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
