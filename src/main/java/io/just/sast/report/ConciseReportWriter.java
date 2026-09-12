package io.just.sast.report;

import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.FindingState;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;

/**
 * Writes the small, stable reading surface for a scan.
 *
 * <p>The canonical {@link FindingOutputReader.Snapshot} is the only source for both files.
 * Older renderer files remain available during migration, but this pair is deliberately free
 * of payload bytes, verifier output and format-specific re-ranking.</p>
 */
public final class ConciseReportWriter {

    public static final String SCHEMA_VERSION = "JUST-REPORT-V1";

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
        ordered.sort(Comparator.comparing(FindingOutputReader.Finding::exported).reversed()
                .thenComparing((FindingOutputReader.Finding finding) ->
                        finding.ranking().staticScore(), Comparator.reverseOrder())
                .thenComparing(FindingOutputReader.Finding::id));
        return List.copyOf(ordered);
    }

    private static String json(String mode, FindingOutputReader.Snapshot snapshot,
                               ScanStatistics stats,
                               List<FindingOutputReader.Finding> findings) {
        StringBuilder out = new StringBuilder(4096);
        out.append("{\"schema_version\":").append(quote(SCHEMA_VERSION))
                .append(",\"mode\":").append(quote(mode))
                .append(",\"static_safety\":{\"verification_mode\":\"STATIC_ONLY\"")
                .append(",\"target_code_execution_possible\":false")
                .append(",\"target_code_executed\":\"NO\"")
                .append(",\"dynamic_filtering\":\"ANALYSIS_ONLY\"}")
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
                .append(",\"chains\":[");
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
                .append(",\"exported\":").append(finding.exported())
                .append(",\"rule_id\":").append(quote(chain.ruleId()))
                .append(",\"category\":").append(quote(chain.category()))
                .append(",\"severity\":").append(quote(chain.severity()))
                .append(",\"entry\":{\"class\":").append(quote(chain.entryClass()))
                .append(",\"method\":").append(quote(chain.entryMethod()))
                .append(",\"kind\":").append(quote(chain.entryKind())).append('}')
                .append(",\"sink\":{\"class\":").append(quote(chain.sinkClass()))
                .append(",\"method\":").append(quote(chain.sinkMethod()))
                .append(",\"descriptor\":").append(quote(chain.sinkDescriptor()))
                .append(",\"role\":").append(quote(chain.sinkRole()))
                .append(",\"risk\":").append(quote(chain.sinkRisk().name())).append('}')
                .append(",\"state\":{\"entry_status\":")
                .append(quote(state.entryStatus().name()))
                .append(",\"chain_progress\":").append(quote(state.chainProgress().name()))
                .append(",\"feasibility\":").append(quote(state.feasibility().name()))
                .append(",\"completeness\":").append(quote(state.completeness().name()))
                .append(",\"verification\":").append(quote(state.verification().name()))
                .append(",\"risk\":").append(quote(state.risk().name()))
                .append(",\"eligibility\":").append(quote(state.eligibility().name()))
                .append(",\"violations\":");
        appendStrings(out, state.defaultFindingViolations());
        out.append('}')
                .append(",\"ranking\":{\"static_score\":")
                .append(finding.ranking().staticScore())
                .append(",\"precision_rank\":").append(finding.ranking().precisionRank())
                .append(",\"explanation\":").append(quote(finding.ranking().explanation()))
                .append('}')
                .append(",\"construction\":")
                .append(ReportEvidence.constructionJson(finding.construction()))
                .append(",\"notes\":");
        appendStrings(out, finding.notes());
        out.append(",\"hops\":[");
        for (int i = 0; i < chain.hops().size(); i++) {
            if (i > 0) out.append(',');
            ChainHop hop = chain.hops().get(i);
            out.append("{\"from\":").append(quote(member(hop.fromOwner(), hop.fromName())))
                    .append(",\"to\":").append(quote(member(hop.toOwner(), hop.toName())))
                    .append(",\"kind\":").append(quote(hop.kind() == null
                            ? "UNKNOWN" : hop.kind().name()))
                    .append(",\"field\":").append(quote(hop.field()))
                    .append(",\"reason\":").append(quote(hop.reason()))
                    .append(",\"descriptor\":").append(quote(hop.desc()))
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
                        .filter(FindingOutputReader.Finding::exported).count()).append("\n\n");
        if (findings.isEmpty()) {
            out.append("No chain candidates were produced. Check completeness and reason codes; ")
                    .append("an empty result is not proof that the artifact is safe.\n");
            return out.toString();
        }
        out.append("## Chains\n\n");
        int number = 1;
        for (FindingOutputReader.Finding finding : findings) {
            Chain chain = finding.chain();
            out.append("### ").append(number++).append(". ")
                    .append(finding.exported() ? "EXPORTED" : "CANDIDATE")
                    .append(" — `").append(md(chain.ruleId())).append("`\n\n")
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
            }
            if (!finding.notes().isEmpty()) {
                out.append("- Notes: ").append(finding.notes().stream().map(ConciseReportWriter::md)
                        .reduce((left, right) -> left + "; " + right).orElse("")).append("\n");
            }
            if (!chain.hops().isEmpty()) {
                out.append("- Hops:\n");
                for (ChainHop hop : chain.hops()) {
                    out.append("  - `").append(md(member(hop.fromOwner(), hop.fromName())))
                            .append("` — ").append(md(hop.kind() == null
                                    ? "UNKNOWN" : hop.kind().name()))
                            .append(" → `").append(md(member(hop.toOwner(), hop.toName())))
                            .append('`');
                    if (hop.field() != null && !hop.field().isBlank()) {
                        out.append("; field `").append(md(hop.field())).append('`');
                    }
                    if (hop.reason() != null && !hop.reason().isBlank()) {
                        out.append("; ").append(md(hop.reason()));
                    }
                    out.append('\n');
                }
            }
            out.append('\n');
        }
        return out.toString();
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
        if (value == null) return "\"\"";
        StringBuilder out = new StringBuilder(value.length() + 8).append('"');
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
        return out.append('"').toString();
    }

    private static String md(String value) {
        return value == null ? "" : value.replace("`", "'")
                .replace("\r", " ").replace("\n", " ");
    }
}
