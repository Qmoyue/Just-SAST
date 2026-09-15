package io.just.sast.report;

import io.just.sast.blackboard.Chain;
import io.just.sast.analysis.taint.FilterAnalysis;
import io.just.sast.chain.ChainPrecision;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

/** Optional detailed JSON/HTML/Markdown views backed by one static finding snapshot. */
public final class MultiFormatReporter {

    public void write(Path outDir, List<Chain> chains,
                      Map<String, String> calibrations, Map<String, List<String>> notes)
            throws IOException {
        write(ReportLayout.flat(outDir), chains, calibrations, notes);
    }

    public void write(ReportLayout layout, List<Chain> chains,
                      Map<String, String> calibrations, Map<String, List<String>> notes)
            throws IOException {
        write(layout, new FindingOutputReader().read(chains, calibrations, notes));
    }

    /** Render all optional detailed views from the immutable canonical snapshot. */
    public void write(ReportLayout layout, FindingOutputReader.Snapshot snapshot)
            throws IOException {
        if (layout == null) {
            throw new IOException("report layout is null");
        }
        if (snapshot == null) {
            throw new IOException("finding output snapshot is null");
        }
        Files.createDirectories(layout.findings());
        List<FindingOutputReader.Finding> findings = new ArrayList<>(snapshot.findings());
        findings.sort((left, right) -> {
            int comparison = ChainRankingSupport.compare(left, right);
            return comparison != 0 ? comparison : left.id().compareTo(right.id());
        });
        writeJson(layout.findings().resolve("findings.json"), findings, snapshot);
        writeHtml(layout.findings().resolve("findings.html"), findings, snapshot);
        writeMarkdown(layout.findings().resolve("findings.md"), findings, snapshot);
    }

    /** Write static scan metadata, including bounded-filter telemetry. */
    public void writeMetadata(Path outDir, ScanStatistics stats) throws IOException {
        writeMetadata(ReportLayout.flat(outDir), stats);
    }

    public void writeMetadata(ReportLayout layout, ScanStatistics stats) throws IOException {
        if (layout == null || stats == null) {
            throw new IOException("scan metadata inputs are missing");
        }
        Files.createDirectories(layout.meta());
        StringBuilder sb = new StringBuilder("{\n")
                .append("  \"schema_version\":1,\n")
                .append("  \"run_outcome\":").append(stats.runOutcome().toCanonicalJson())
                .append(",\n  \"files_scanned\":").append(stats.filesScanned())
                .append(",\"classes_loaded\":").append(stats.classesLoaded())
                .append(",\"diagnostics\":").append(stats.diagnostics())
                .append(",\"sinks_marked\":").append(stats.sinksMarked())
                .append(",\"magic_entries\":").append(stats.magicEntries())
                .append(",\"chains_found\":").append(stats.chainsFound())
                .append(",\"elapsed_ms\":").append(stats.elapsedMs())
                .append(",\"heap_used_mb\":").append(stats.heapUsedMb())
                .append(",\"heap_peak_mb\":").append(stats.heapPeakMb())
                .append(",\"completeness\":").append(quote(stats.completeness()))
                .append(",\"chain_proof_completeness\":")
                .append(quote(stats.chainProofCompleteness()))
                .append(",\"artifact_sha256\":").append(quote(stats.artifactHash()))
                .append(",\"completeness_reasons\":");
        appendStrings(sb, stats.completenessReasons());
        sb.append(",\"phase_ms\":");
        appendLongMap(sb, stats.phaseMs());
        sb.append(",\"metrics\":");
        appendLongMap(sb, stats.metrics());
        sb.append(",\"metric_status\":");
        appendStringMap(sb, stats.metricStatus());
        sb.append(",\"metric_namespaces\":");
        appendNestedLongMap(sb, stats.metricNamespaces());
        sb.append(",\"metric_namespace_status\":");
        appendStringMap(sb, stats.metricNamespaceStatus());
        sb.append(",\"filter_evidence\":");
        appendFilterEvidenceJson(sb, stats.filterEvidence());
        sb.append("\n}\n");
        AtomicFiles.writeUtf8(layout.meta().resolve("scan-metadata.json"), sb.toString());
        AtomicFiles.writeUtf8(layout.meta().resolve("run.json"),
                "{\"schema_version\":1,\"kind\":\"just-run\",\"run_outcome\":"
                        + stats.runOutcome().toCanonicalJson() + "}\n");
    }

    private static void writeJson(Path path, List<FindingOutputReader.Finding> findings,
                                  FindingOutputReader.Snapshot snapshot) throws IOException {
        StringBuilder out = new StringBuilder("[\n");
        for (int i = 0; i < findings.size(); i++) {
            if (i > 0) out.append(",\n");
            FindingOutputReader.Finding finding = findings.get(i);
            Chain chain = finding.chain();
            out.append("  {\"id\":").append(quote(finding.id()))
                    .append(",\"rule_id\":").append(quote(chain.ruleId()))
                    .append(",\"category\":").append(quote(chain.category()))
                    .append(",\"severity\":").append(quote(chain.severity()))
                    .append(",\"confidence\":").append(quote(finding.confidence().bucket()))
                    .append(",\"entry_class\":").append(quote(chain.entryClass()))
                    .append(",\"entry_method\":").append(quote(chain.entryMethod()))
                    .append(",\"entry_kind\":").append(quote(chain.entryKind()))
                    .append(",\"sink_class\":").append(quote(chain.sinkClass()))
                    .append(",\"sink_method\":").append(quote(chain.sinkMethod()))
                    .append(",\"sink_descriptor\":").append(quote(chain.sinkDescriptor()))
                    .append(",\"sink_role\":").append(quote(chain.sinkRole()))
                    .append(",\"sink_risk\":").append(quote(chain.sinkRisk().name()))
                    .append(",\"state\":{")
                    .append("\"entry_status\":").append(quote(finding.state().entryStatus().name()))
                    .append(",\"chain_progress\":").append(quote(finding.state().chainProgress().name()))
                    .append(",\"feasibility\":").append(quote(finding.state().feasibility().name()))
                    .append(",\"completeness\":").append(quote(finding.state().completeness().name()))
                    .append(",\"risk\":").append(quote(finding.state().risk().name()))
                    .append(",\"eligibility\":").append(quote(finding.state().eligibility().name()))
                    .append(",\"violations\":");
            appendStrings(out, finding.typedViolations());
            out.append('}')
                    .append(",\"static_rank\":").append(finding.ranking().staticScore())
                    .append(",\"precision\":")
                    .append(ChainPrecision.toJson(finding.precision(), MultiFormatReporter::escape,
                            finding.highConfidence()))
                    .append(",\"construction\":")
                    .append(ReportEvidence.constructionJson(finding.construction()))
                    .append(",\"exported\":").append(finding.exported())
                    .append(",\"calibration\":").append(quote(finding.calibration()))
                    .append(",\"notes\":");
            appendStrings(out, finding.notes());
            ApplicationTrace trace = snapshot.applicationTrace(chain.key());
            out.append(",\"application_trace\":")
                    .append(trace == null ? "null" : trace.toCanonicalJson())
                    .append('}');
        }
        out.append("\n]\n");
        AtomicFiles.writeUtf8(path, out.toString());
    }

    private static void writeHtml(Path path, List<FindingOutputReader.Finding> findings,
                                  FindingOutputReader.Snapshot snapshot) throws IOException {
        StringBuilder out = new StringBuilder("<!DOCTYPE html>\n<html><head><meta charset='UTF-8'>")
                .append("<title>Just SAST Findings</title></head><body>\n")
                .append("<h1>Just SAST Findings</h1>\n")
                .append("<p>Static evidence only; no target code or attack bytes are executed.</p>\n")
                .append("<table><thead><tr><th>#</th><th>Rule</th><th>Confidence</th>")
                .append("<th>Entry</th><th>Application path</th><th>Sink</th><th>State</th>")
                .append("</tr></thead><tbody>\n");
        int index = 1;
        for (FindingOutputReader.Finding finding : findings) {
            Chain chain = finding.chain();
            ApplicationTrace trace = snapshot.applicationTrace(chain.key());
            out.append("<tr><td>").append(index++).append("</td><td>")
                    .append(escapeHtml(chain.ruleId())).append("</td><td>")
                    .append(escapeHtml(finding.confidence().bucket())).append("</td><td>")
                    .append(escapeHtml(chain.entryClass() + "#" + chain.entryMethod()))
                    .append("</td><td>")
                    .append(escapeHtml(trace == null ? "" : trace.applicationPath(chain)))
                    .append("</td><td>")
                    .append(escapeHtml(chain.sinkClass() + "#" + chain.sinkMethod()))
                    .append("</td><td>")
                    .append(escapeHtml(finding.state().eligibility().name())).append("</td></tr>\n");
        }
        out.append("</tbody></table>\n</body></html>\n");
        AtomicFiles.writeUtf8(path, out.toString());
    }

    private static void writeMarkdown(Path path, List<FindingOutputReader.Finding> findings,
                                      FindingOutputReader.Snapshot snapshot) throws IOException {
        StringBuilder out = new StringBuilder("# Just findings\n\n")
                .append("Static evidence only; no target code or attack bytes are executed.\n\n")
                .append("| # | Rule | Confidence | Entry | Application path | Sink | Eligibility |\n")
                .append("|---:|---|---|---|---|---|---|\n");
        int index = 1;
        for (FindingOutputReader.Finding finding : findings) {
            Chain chain = finding.chain();
            ApplicationTrace trace = snapshot.applicationTrace(chain.key());
            out.append('|').append(index++).append('|').append(md(chain.ruleId())).append('|')
                    .append(md(finding.confidence().bucket())).append('|')
                    .append(md(chain.entryClass() + "#" + chain.entryMethod())).append('|')
                    .append(md(trace == null ? "" : trace.applicationPath(chain))).append('|')
                    .append(md(chain.sinkClass() + "#" + chain.sinkMethod())).append('|')
                    .append(md(finding.state().eligibility().name())).append('|').append('\n');
        }
        AtomicFiles.writeUtf8(path, out.toString());
    }

    private static void appendFilterEvidenceJson(StringBuilder out,
                                                  List<FilterAnalysis.Evidence> evidence) {
        out.append('[');
        for (int i = 0; i < evidence.size(); i++) {
            if (i > 0) out.append(',');
            FilterAnalysis.Evidence item = evidence.get(i);
            out.append("{\"kind\":").append(quote(item.kind().name()))
                    .append(",\"location\":").append(quote(item.location()))
                    .append(",\"status\":").append(quote(item.status().name()))
                    .append(",\"reason_code\":").append(quote(item.reasonCode()))
                    .append(",\"domain_digest\":").append(quote(item.domainDigest()))
                    .append(",\"semantic_digest\":").append(quote(item.semanticDigest()))
                    .append(",\"budget\":").append(item.budget())
                    .append(",\"evaluated\":").append(item.evaluated())
                    .append(",\"retained\":").append(item.retained())
                    .append(",\"rejected\":").append(item.rejected())
                    .append(",\"expanded\":").append(item.expanded())
                    .append(",\"filter_cost_nanos\":").append(item.filterCostNanos())
                    .append('}');
        }
        out.append(']');
    }

    private static void appendLongMap(StringBuilder out, Map<String, Long> values) {
        out.append('{');
        int index = 0;
        for (Map.Entry<String, Long> entry : values.entrySet()) {
            if (index++ > 0) out.append(',');
            out.append(quote(entry.getKey())).append(':').append(entry.getValue());
        }
        out.append('}');
    }

    private static void appendStringMap(StringBuilder out, Map<String, String> values) {
        out.append('{');
        int index = 0;
        for (Map.Entry<String, String> entry : values.entrySet()) {
            if (index++ > 0) out.append(',');
            out.append(quote(entry.getKey())).append(':').append(quote(entry.getValue()));
        }
        out.append('}');
    }

    private static void appendNestedLongMap(StringBuilder out,
                                             Map<String, Map<String, Long>> values) {
        out.append('{');
        int index = 0;
        for (Map.Entry<String, Map<String, Long>> entry : values.entrySet()) {
            if (index++ > 0) out.append(',');
            out.append(quote(entry.getKey())).append(':');
            appendLongMap(out, entry.getValue());
        }
        out.append('}');
    }

    private static void appendStrings(StringBuilder out, List<String> values) {
        out.append('[');
        for (int i = 0; i < values.size(); i++) {
            if (i > 0) out.append(',');
            out.append(quote(values.get(i)));
        }
        out.append(']');
    }

    private static String quote(String value) {
        return '"' + escape(value) + '"';
    }

    private static String escape(String value) {
        if (value == null) return "";
        return value.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
    }

    private static String escapeHtml(String value) {
        return value == null ? "" : value.replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace("\"", "&quot;");
    }

    private static String md(String value) {
        return value == null ? "" : value.replace("|", "\\|")
                .replace("\r", " ").replace("\n", " ");
    }

    /** Keeps ranking comparison local to this renderer and avoids rebuilding a second snapshot. */
    private static final class ChainRankingSupport {
        private static int compare(FindingOutputReader.Finding left,
                                   FindingOutputReader.Finding right) {
            return io.just.sast.chain.ChainRanking.compareEvidence(left.ranking(), left.id(),
                    right.ranking(), right.id());
        }
    }
}
