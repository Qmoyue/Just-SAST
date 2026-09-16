package io.just.sast.report;

import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.FindingState;
import io.just.sast.chain.ChainPrecision;
import io.just.sast.chain.ChainRanking;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.Objects;

/**
 * Writes the small, stable reading surface for a scan.
 *
 * <p>The canonical {@link FindingOutputReader.Snapshot} is the only source for both files.
 * This pair contains no executable material and no format-specific re-ranking.</p>
 */
public final class ConciseReportWriter {

    public static final String SCHEMA_VERSION = "JUST-REPORT-V1";
    public static final int MARKDOWN_DISPLAY_LIMIT = 10;

    public void write(ReportLayout layout, String mode,
                      FindingOutputReader.Snapshot snapshot,
                      ScanStatistics statistics) throws IOException {
        Objects.requireNonNull(layout, "layout");
        Objects.requireNonNull(snapshot, "snapshot");
        Objects.requireNonNull(statistics, "statistics");
        String normalizedMode = normalizeMode(mode);
        List<FindingOutputReader.Finding> findings = ordered(snapshot.findings());
        AtomicFiles.writeUtf8(layout.root().resolve("report.json"),
                json(normalizedMode, snapshot, statistics, findings) + "\n");
        AtomicFiles.writeUtf8(layout.root().resolve("report.md"),
                markdown(normalizedMode, snapshot, statistics, findings));
    }

    private static List<FindingOutputReader.Finding> ordered(
            List<FindingOutputReader.Finding> findings) {
        List<FindingOutputReader.Finding> ordered = new ArrayList<>(
                findings == null ? List.of() : findings);
        ordered.sort((left, right) -> {
            int result = Boolean.compare(right.exported(), left.exported());
            if (result != 0) {
                return result;
            }
            result = ChainRanking.compareEvidence(left.ranking(), left.chain().key(),
                    right.ranking(), right.chain().key());
            return result != 0 ? result : left.id().compareTo(right.id());
        });
        return List.copyOf(ordered);
    }

    private static String json(String mode, FindingOutputReader.Snapshot snapshot,
                               ScanStatistics stats,
                               List<FindingOutputReader.Finding> findings) {
        StringBuilder out = new StringBuilder(4096);
        out.append("{\"schema_version\":").append(quote(SCHEMA_VERSION))
                .append(",\"mode\":").append(quote(mode))
                .append(",\"static_analysis\":{\"target_code_executed\":false")
                .append(",\"filter_evidence\":\"meta/scan-metadata.json\"}")
                .append(",\"artifact_sha256\":").append(quote(stats.artifactHash()))
                .append(",\"run\":{")
                .append("\"status\":").append(quote(stats.runOutcome().status().name()))
                .append(",\"completeness\":").append(quote(stats.completeness()))
                .append(",\"chain_proof_completeness\":")
                .append(quote(stats.chainProofCompleteness()))
                .append(",\"reason_codes\":");
        appendStrings(out, stats.runOutcome().reasonCodes());
        out.append("}")
                .append(",\"summary\":{\"candidates\":").append(findings.size())
                .append(",\"exported\":").append(findings.stream()
                        .filter(FindingOutputReader.Finding::exported).count())
                .append(",\"files_scanned\":").append(stats.filesScanned())
                .append(",\"classes_loaded\":").append(stats.classesLoaded())
                .append(",\"elapsed_ms\":").append(stats.elapsedMs()).append('}')
                .append(",\"presentation\":");
        appendPresentation(out, stats, findings);
        out.append(",\"filter_evidence\":");
        out.append(ReportEvidence.filterEvidenceJson(stats.filterEvidence()));
        out.append(",\"result_explanation\":");
        appendResultExplanation(out, stats, findings);
        out.append(",\"chains\":[");
        for (int i = 0; i < findings.size(); i++) {
            if (i > 0) out.append(',');
            appendFinding(out, snapshot, findings.get(i));
        }
        return out.append("]}").toString();
    }

    private static void appendFinding(StringBuilder out, FindingOutputReader.Snapshot snapshot,
                                      FindingOutputReader.Finding finding) {
        Chain chain = finding.chain();
        FindingState state = finding.state();
        out.append('{')
                .append("\"id\":").append(quote(finding.id()))
                .append(",\"chain_key\":").append(quote(chain.key()))
                .append(",\"exported\":").append(finding.exported())
                .append(",\"rule_id\":").append(quote(chain.ruleId()))
                .append(",\"category\":").append(quote(chain.category()))
                .append(",\"severity\":").append(quote(chain.severity()))
                .append(",\"entry\":{\"class\":").append(quote(chain.entryClass()))
                .append(",\"method\":").append(quote(chain.entryMethod()))
                .append(",\"descriptor\":").append(quote(ChainIdentity.entryDescriptor(chain)))
                .append(",\"kind\":").append(quote(chain.entryKind())).append('}')
                .append(",\"sink\":{\"class\":").append(quote(chain.sinkClass()))
                .append(",\"method\":").append(quote(chain.sinkMethod()))
                .append(",\"descriptor\":").append(quote(ChainIdentity.sinkDescriptor(chain)))
                .append(",\"role\":").append(quote(chain.sinkRole()))
                .append(",\"risk\":").append(quote(chain.sinkRisk().name())).append('}')
                .append(",\"state\":{\"entry_status\":")
                .append(quote(state.entryStatus().name()))
                .append(",\"chain_progress\":").append(quote(state.chainProgress().name()))
                .append(",\"feasibility\":").append(quote(state.feasibility().name()))
                .append(",\"completeness\":").append(quote(state.completeness().name()))
                .append(",\"risk\":").append(quote(state.risk().name()))
                .append(",\"eligibility\":").append(quote(state.eligibility().name()))
                .append(",\"violations\":");
        appendStrings(out, state.defaultFindingViolations());
        out.append('}')
                .append(",\"constraints\":{\"feasibility\":")
                .append(quote(state.feasibility().name()))
                .append(",\"completeness\":").append(quote(state.completeness().name()))
                .append(",\"violations\":");
        appendStrings(out, state.defaultFindingViolations());
        out.append(",\"unresolved_hops\":").append(chain.unresolvedHops()).append('}')
                .append(",\"ranking\":{\"static_score\":")
                .append(finding.ranking().staticScore())
                .append(",\"precision_rank\":").append(finding.ranking().precisionRank())
                .append(",\"explanation\":").append(quote(finding.ranking().explanation()))
                .append('}')
                .append(",\"confidence\":{\"bucket\":")
                .append(quote(finding.confidence().bucket()))
                .append(",\"reason\":").append(quote(finding.confidence().reasonCode()))
                .append(",\"static_rank\":")
                .append(finding.confidence().features().staticRank())
                .append(",\"total_score\":")
                .append(finding.confidence().features().totalScore()).append('}')
                .append(",\"precision\":")
                .append(ChainPrecision.toJson(finding.precision(), ConciseReportWriter::escape,
                        finding.highConfidence()))
                .append(",\"construction\":")
                .append(ReportEvidence.constructionJson(finding.construction()))
                .append(",\"notes\":");
        appendStrings(out, finding.notes());
        List<ChainHop> hops = orderedHops(chain);
        out.append(",\"object_relations\":[");
        boolean firstRelation = true;
        for (ChainHop hop : hops) {
            if (hop.field() == null || hop.field().isBlank()) {
                continue;
            }
            if (!firstRelation) {
                out.append(',');
            }
            firstRelation = false;
            out.append("{\"from\":").append(quote(member(hop.fromOwner(), hop.fromName())))
                    .append(",\"to\":").append(quote(member(hop.toOwner(), hop.toName())))
                    .append(",\"kind\":").append(quote(hop.kind() == null
                            ? "UNKNOWN" : hop.kind().name()))
                    .append(",\"field\":").append(quote(hop.field()))
                    .append(",\"field_owner\":").append(nullableQuote(hop.fieldOwner()))
                    .append('}');
        }
        out.append(']');
        out.append(",\"hops\":[");
        for (int i = 0; i < hops.size(); i++) {
            if (i > 0) out.append(',');
            ChainHop hop = hops.get(i);
            out.append("{\"hop_index\":").append(i + 1)
                    .append(",\"from\":").append(quote(member(hop.fromOwner(), hop.fromName())))
                    .append(",\"from_descriptor\":")
                    .append(nullableQuote(hopFromDescriptor(hops, i)))
                    .append(",\"to\":").append(quote(member(hop.toOwner(), hop.toName())))
                    .append(",\"kind\":").append(quote(hop.kind() == null
                            ? "UNKNOWN" : hop.kind().name()))
                    .append(",\"field\":").append(quote(hop.field()))
                    .append(",\"reason\":").append(quote(hop.reason()))
                    .append(",\"descriptor\":").append(quote(hop.desc()))
                    .append(",\"arg_ordinal\":").append(hop.argOrdinal() == null
                            ? "null" : hop.argOrdinal())
                    .append(",\"field_owner\":").append(nullableQuote(hop.fieldOwner()))
                    .append(",\"location\":")
                    .append(ReportEvidence.hopLocationJson(hop.provenance()))
                    .append('}');
        }
        out.append(']');
        ApplicationTrace trace = snapshot.applicationTrace(chain.key());
        if (trace != null) {
            out.append(",\"application_trace\":").append(trace.toCanonicalJson());
        } else {
            out.append(",\"application_trace\":null");
        }
        out.append('}');
    }

    private static String markdown(String mode, FindingOutputReader.Snapshot snapshot,
                                   ScanStatistics stats,
                                   List<FindingOutputReader.Finding> findings) {
        StringBuilder out = new StringBuilder(4096)
                .append("# Just report\n\n")
                .append("This report is static-only and contains no generated attack bytes.\n\n")
                .append("## Run\n\n")
                .append("- Mode: `").append(md(mode)).append("`\n")
                .append("- Status: `").append(md(stats.runOutcome().status().name())).append("`\n")
                .append("- Completeness: `").append(md(stats.completeness())).append("`\n")
                .append("- Chain proof: `").append(md(stats.chainProofCompleteness())).append("`\n")
                .append("- Artifact SHA-256: `").append(md(stats.artifactHash())).append("`\n")
                .append("- Target code executed: `NO`\n")
                .append("- Candidates: ").append(findings.size())
                .append("; exported: ").append(findings.stream()
                        .filter(FindingOutputReader.Finding::exported).count()).append('\n')
                .append("- Display limit: `").append(MARKDOWN_DISPLAY_LIMIT)
                .append("` detailed; detailed: ").append(Math.min(MARKDOWN_DISPLAY_LIMIT,
                        findings.size()))
                .append("; compact: ").append(Math.max(0, findings.size()
                        - MARKDOWN_DISPLAY_LIMIT))
                .append("; JSON candidates: ").append(findings.size())
                .append("; JSON truncation: `NO`\n")
                .append("- Search budget: `").append(md(searchBudgetSummary(stats)))
                .append("` (independent of display limit)\n")
                .append("- Filter evidence: `").append(stats.filterEvidence().size())
                .append("` rows; full status, proof scope, digests, counts and cost are in "
                        + "report.json and meta/scan-metadata.json\n")
                .append("- Result: ").append(md(resultMessage(findings))).append('\n')
                .append("- Reason codes: `").append(md(String.join(",", resultReasonCodes(stats,
                        findings)))).append("`\n\n");
        if (findings.isEmpty()) {
            out.append("No static chain candidate was produced. Check completeness and reason codes; ")
                    .append("an empty result is not proof that the artifact is safe.\n");
            return out.toString();
        }
        if (findings.stream().noneMatch(FindingOutputReader.Finding::exported)) {
            out.append("Candidates were retained as audit evidence, but none met the selected "
                    + "mode's export contract.\n\n");
        }
        out.append("## Chains\n\n");
        int number = 1;
        int detailedCount = Math.min(MARKDOWN_DISPLAY_LIMIT, findings.size());
        for (int index = 0; index < detailedCount; index++) {
            FindingOutputReader.Finding finding = findings.get(index);
            Chain chain = finding.chain();
            out.append("### ").append(number++).append(". ")
                    .append(finding.exported() ? "EXPORTED" : "CANDIDATE")
                    .append(" — `").append(md(chain.ruleId())).append("`\n\n")
                    .append("- Finding ID: `").append(md(finding.id())).append("`\n")
                    .append('`').append(md(member(chain.entryClass(), chain.entryMethod())))
                    .append("` → `").append(md(member(chain.sinkClass(), chain.sinkMethod())))
                    .append("`\n\n")
                    .append("- State: `").append(md(finding.state().eligibility().name()))
                    .append("`; feasibility `").append(md(finding.state().feasibility().name()))
                    .append("`; completeness `").append(md(finding.state().completeness().name()))
                    .append("`\n")
                    .append("- Rank: ").append(finding.ranking().staticScore())
                    .append("; ").append(md(finding.ranking().explanation())).append("\n");
            ApplicationTrace trace = snapshot.applicationTrace(chain.key());
            if (trace != null) {
                out.append("- Application path: `").append(md(trace.entryDisplay()))
                        .append("` → site `").append(md(trace.siteDisplay())).append("`\n");
                if (trace.joinEvidence() != null) {
                    out.append("- Join evidence: `")
                            .append(md(trace.joinEvidence().display())).append("`\n");
                }
            }
            if (!finding.notes().isEmpty()) {
                out.append("- Notes: ").append(finding.notes().stream().map(ConciseReportWriter::md)
                        .reduce((left, right) -> left + "; " + right).orElse("")).append("\n");
            }
            List<ChainHop> orderedHops = orderedHops(chain);
            if (!orderedHops.isEmpty()) {
                out.append("- Hops:\n");
                for (int hopIndex = 0; hopIndex < orderedHops.size(); hopIndex++) {
                    ChainHop hop = orderedHops.get(hopIndex);
                    out.append("  - `").append(md(member(hop.fromOwner(), hop.fromName())))
                            .append("` — ").append(md(hop.kind() == null
                                    ? "UNKNOWN" : hop.kind().name()))
                            .append(" → `").append(md(member(hop.toOwner(), hop.toName())))
                            .append('`');
                    if (hop.field() != null && !hop.field().isBlank()) {
                        out.append("; field `").append(md(hop.field())).append('`');
                        if (hop.fieldOwner() != null && !hop.fieldOwner().isBlank()) {
                            out.append(" declared by `").append(md(hop.fieldOwner())).append('`');
                        }
                    }
                    if (hop.argOrdinal() != null) {
                        out.append("; arg ").append(hop.argOrdinal());
                    }
                    String fromDescriptor = hopFromDescriptor(orderedHops, hopIndex);
                    if (fromDescriptor != null && !fromDescriptor.isBlank()) {
                        out.append("; from descriptor `").append(md(fromDescriptor)).append('`');
                    }
                    if (hop.desc() != null && !hop.desc().isBlank()) {
                        out.append("; descriptor `").append(md(hop.desc())).append('`');
                    }
                    if (hop.reason() != null && !hop.reason().isBlank()) {
                        out.append("; ").append(md(hop.reason()));
                    }
                    out.append("; location `")
                            .append(md(ReportEvidence.hopLocationSummary(hop.provenance())))
                            .append('`');
                    out.append('\n');
                }
            }
            out.append('\n');
        }
        if (findings.size() > detailedCount) {
            out.append("## Remaining candidate summaries\n\n")
                    .append("The JSON report retains every candidate and variant; these rows are "
                            + "compact display only.\n\n")
                    .append("| # | Finding ID | Rule | Entry | Sink | Eligibility |\n")
                    .append("|---:|---|---|---|---|---|\n");
            for (int index = detailedCount; index < findings.size(); index++) {
                FindingOutputReader.Finding finding = findings.get(index);
                Chain chain = finding.chain();
                out.append('|').append(number++).append('|').append(md(finding.id())).append('|')
                        .append(md(chain.ruleId())).append('|')
                        .append(md(member(chain.entryClass(), chain.entryMethod()))).append('|')
                        .append(md(member(chain.sinkClass(), chain.sinkMethod()))).append('|')
                        .append(md(finding.state().eligibility().name())).append('|').append('\n');
            }
            out.append('\n');
        }
        return out.toString();
    }

    private static void appendPresentation(StringBuilder out, ScanStatistics stats,
                                           List<FindingOutputReader.Finding> findings) {
        int count = findings.size();
        out.append("{\"display_limit\":").append(MARKDOWN_DISPLAY_LIMIT)
                .append(",\"detailed_count\":").append(Math.min(MARKDOWN_DISPLAY_LIMIT, count))
                .append(",\"compact_count\":").append(Math.max(0, count - MARKDOWN_DISPLAY_LIMIT))
                .append(",\"json_candidate_count\":").append(count)
                .append(",\"json_truncated\":false")
                .append(",\"search_budget\":");
        appendSearchBudget(out, stats);
        out.append('}');
    }

    private static void appendSearchBudget(StringBuilder out, ScanStatistics stats) {
        long stepLimit = stats.metric("forward_step_limit", -1L);
        long methodPassLimit = stats.metric("forward_method_pass_limit", -1L);
        long roundLimit = stats.metric("forward_round_limit", -1L);
        boolean bounded = stepLimit >= 0L || methodPassLimit >= 0L || roundLimit >= 0L;
        out.append("{\"source\":\"meta/scan-metadata.json\",\"status\":")
                .append(quote(bounded ? "BOUNDED" : "UNKNOWN"))
                .append(",\"step_limit\":");
        appendNullableLong(out, stepLimit);
        out.append(",\"method_pass_limit\":");
        appendNullableLong(out, methodPassLimit);
        out.append(",\"round_limit\":");
        appendNullableLong(out, roundLimit);
        out.append('}');
    }

    private static String searchBudgetSummary(ScanStatistics stats) {
        long stepLimit = stats.metric("forward_step_limit", -1L);
        long methodPassLimit = stats.metric("forward_method_pass_limit", -1L);
        long roundLimit = stats.metric("forward_round_limit", -1L);
        if (stepLimit < 0L && methodPassLimit < 0L && roundLimit < 0L) {
            return "UNKNOWN; see meta/scan-metadata.json";
        }
        return "step_limit=" + nullableMetric(stepLimit)
                + ",method_pass_limit=" + nullableMetric(methodPassLimit)
                + ",round_limit=" + nullableMetric(roundLimit);
    }

    private static String nullableMetric(long value) {
        return value < 0L ? "UNKNOWN" : Long.toString(value);
    }

    private static void appendNullableLong(StringBuilder out, long value) {
        if (value < 0L) {
            out.append("null");
        } else {
            out.append(value);
        }
    }

    private static void appendResultExplanation(StringBuilder out, ScanStatistics stats,
                                                List<FindingOutputReader.Finding> findings) {
        long exported = findings.stream().filter(FindingOutputReader.Finding::exported).count();
        out.append("{\"kind\":").append(quote(resultKind(findings, exported)))
                .append(",\"message\":").append(quote(resultMessage(findings)))
                .append(",\"candidate_count\":").append(findings.size())
                .append(",\"exported_count\":").append(exported)
                .append(",\"reason_codes\":");
        appendStrings(out, resultReasonCodes(stats, findings));
        out.append('}');
    }

    private static String resultKind(List<FindingOutputReader.Finding> findings, long exported) {
        if (findings.isEmpty()) {
            return "EMPTY";
        }
        return exported == 0 ? "AUDIT_CANDIDATES_ONLY" : "EXPORTED_CANDIDATES";
    }

    private static String resultMessage(List<FindingOutputReader.Finding> findings) {
        if (findings.isEmpty()) {
            return "No static chain candidate was produced; this does not prove that the artifact is safe.";
        }
        if (findings.stream().noneMatch(FindingOutputReader.Finding::exported)) {
            return "Candidates are available as audit evidence, but none met the selected mode's export contract.";
        }
        return "Static chain candidates are available for review.";
    }

    private static List<String> resultReasonCodes(ScanStatistics stats,
                                                  List<FindingOutputReader.Finding> findings) {
        Set<String> reasons = new TreeSet<>();
        if (stats != null) {
            reasons.addAll(stats.runOutcome().reasonCodes());
            reasons.addAll(stats.completenessReasons());
        }
        if (findings.isEmpty()) {
            reasons.add("NO_CANDIDATES");
        } else if (findings.stream().noneMatch(FindingOutputReader.Finding::exported)) {
            reasons.add("NO_EXPORTED_CANDIDATES");
        }
        return List.copyOf(reasons);
    }

    /** Chains are built by reverse sink search; reports present the readable entry-to-sink path. */
    private static List<ChainHop> orderedHops(Chain chain) {
        List<ChainHop> hops = chain == null || chain.hops() == null
                ? new ArrayList<>() : new ArrayList<>(chain.hops());
        java.util.Collections.reverse(hops);
        return hops;
    }

    private static String normalizeMode(String mode) {
        if (mode == null || mode.isBlank()) {
            return "component";
        }
        String normalized = mode.trim().toLowerCase(java.util.Locale.ROOT);
        if (!normalized.equals("component") && !normalized.equals("application")) {
            throw new IllegalArgumentException("unsupported report mode: " + mode);
        }
        return normalized;
    }

    private static String member(String owner, String name) {
        String left = owner == null || owner.isBlank() ? "?" : owner;
        String right = name == null || name.isBlank() ? "?" : name;
        return left + "#" + right;
    }

    /** Derive a source descriptor only when the adjacent typed hop proves the same method. */
    private static String hopFromDescriptor(List<ChainHop> hops, int index) {
        ChainHop hop = hops.get(index);
        if (hop.fromOwner() != null && hop.fromName() != null
                && hop.fromOwner().equals(hop.toOwner()) && hop.fromName().equals(hop.toName())
                && hop.desc() != null && !hop.desc().isBlank()) {
            return hop.desc();
        }
        if (index > 0) {
            ChainHop previous = hops.get(index - 1);
            if (hop.fromOwner() != null && hop.fromName() != null
                    && hop.fromOwner().equals(previous.toOwner())
                    && hop.fromName().equals(previous.toName())
                    && previous.desc() != null && !previous.desc().isBlank()) {
                return previous.desc();
            }
        }
        return null;
    }

    private static void appendStrings(StringBuilder out, List<String> values) {
        out.append('[');
        if (values != null) {
            for (int i = 0; i < values.size(); i++) {
                if (i > 0) out.append(',');
                out.append(quote(values.get(i)));
            }
        }
        out.append(']');
    }

    private static String quote(String value) {
        return "\"" + escape(value) + "\"";
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

    private static String nullableQuote(String value) {
        return value == null || value.isBlank() ? "null" : quote(value);
    }

    private static String md(String value) {
        return value == null ? "" : value.replace("`", "'")
                .replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("|", "\\|").replace("\r", " ").replace("\n", " ");
    }
}
