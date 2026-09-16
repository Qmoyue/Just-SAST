package io.just.sast.report;

import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.FindingState;
import io.just.sast.chain.ChainPrecision;
import io.just.sast.chain.ChainRanking;
import io.just.sast.run.RunOutcome;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;

/**
 * Writes the two public report entries from one frozen finding snapshot.
 *
 * <p>JSON keeps all candidates and evidence. Markdown is a small reading surface that renders
 * the same ordered graph and points to the machine report for exact detail.</p>
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
                .append(",\"analysis\":{\"mode\":\"STATIC_ONLY\"")
                .append(",\"filter_evidence\":\"meta/scan-metadata.json\"}")
                .append(",\"artifact_sha256\":").append(quote(stats.artifactHash()))
                .append(",\"run\":{")
                .append("\"outcome\":").append(quote(publicOutcome(stats, findings)))
                .append(",\"coverage\":").append(quote(coverage(stats)))
                .append(",\"chain_proof_coverage\":")
                .append(quote(coverage(stats.chainProofCompleteness())))
                .append(",\"coverage_reasons\":");
        appendStrings(out, coverageReasons(stats));
        out.append(",\"exit_code\":").append(stats.runOutcome().exitCode())
                .append("}")
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
            if (i > 0) {
                out.append(',');
            }
            appendFinding(out, snapshot, findings.get(i));
        }
        return out.append("]}").toString();
    }

    private static String publicOutcome(ScanStatistics stats,
                                        List<FindingOutputReader.Finding> findings) {
        RunOutcome.Status status = stats.runOutcome().status();
        return switch (status) {
            case FAILED, USAGE_ERROR, UNSUPPORTED, NOT_RUN -> status.name();
            case SUCCESS, PARTIAL -> findings.isEmpty()
                    ? "NO_FINDINGS" : "FINDINGS_AVAILABLE";
        };
    }

    private static String coverage(ScanStatistics stats) {
        String completeness = coverage(stats.completeness());
        String chainProof = coverage(stats.chainProofCompleteness());
        if ("UNKNOWN".equals(completeness) || "UNKNOWN".equals(chainProof)) {
            return "UNKNOWN";
        }
        return "COMPLETE".equals(completeness) && "COMPLETE".equals(chainProof)
                ? "COMPLETE" : "BOUNDED";
    }

    private static String coverage(String value) {
        String normalized = value == null ? "UNKNOWN"
                : value.trim().toUpperCase(java.util.Locale.ROOT);
        return switch (normalized) {
            case "COMPLETE" -> "COMPLETE";
            case "UNKNOWN" -> "UNKNOWN";
            default -> "BOUNDED";
        };
    }

    private static List<String> coverageReasons(ScanStatistics stats) {
        Set<String> reasons = new TreeSet<>();
        reasons.addAll(stats.runOutcome().reasonCodes());
        reasons.addAll(stats.completenessReasons());
        if (!"COMPLETE".equals(coverage(stats)) && reasons.isEmpty()) {
            reasons.add("ANALYSIS_INCOMPLETE");
        }
        return List.copyOf(reasons);
    }

    private static void appendFinding(StringBuilder out, FindingOutputReader.Snapshot snapshot,
                                      FindingOutputReader.Finding finding) {
        Chain chain = finding.chain();
        FindingState state = finding.state();
        List<ChainHop> hops = orderedHops(chain);
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
        out.append(",\"graph\":");
        appendGraphJson(out, graph(chain, hops));
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
            if (i > 0) {
                out.append(',');
            }
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

    private static void appendGraphJson(StringBuilder out, GraphProjection graph) {
        out.append("{\"nodes\":[");
        for (int i = 0; i < graph.nodes().size(); i++) {
            if (i > 0) {
                out.append(',');
            }
            GraphNode node = graph.nodes().get(i);
            out.append("{\"id\":").append(quote(node.id()))
                    .append(",\"label\":").append(quote(node.label()))
                    .append(",\"role\":").append(quote(node.role()))
                    .append('}');
        }
        out.append("],\"edges\":[");
        for (int i = 0; i < graph.edges().size(); i++) {
            if (i > 0) {
                out.append(',');
            }
            GraphEdge edge = graph.edges().get(i);
            out.append("{\"from\":").append(quote(edge.from()))
                    .append(",\"to\":").append(quote(edge.to()))
                    .append(",\"kind\":").append(quote(edge.kind()))
                    .append(",\"reason\":").append(quote(edge.reason()))
                    .append('}');
        }
        out.append("]}");
    }

    private static void appendMarkdownGraph(StringBuilder out, GraphProjection graph) {
        out.append("~~~text\n");
        if (graph.nodes().isEmpty()) {
            out.append("[UNKNOWN] no graph nodes\n");
        } else {
            GraphNode first = graph.nodes().get(0);
            out.append('[').append(first.role()).append("] ")
                    .append(md(first.label())).append('\n');
            for (GraphEdge edge : graph.edges()) {
                GraphNode target = graph.nodes().stream()
                        .filter(node -> node.id().equals(edge.to()))
                        .findFirst()
                        .orElseThrow(() -> new IllegalStateException(
                                "graph edge target is missing: " + edge.to()));
                out.append("    │ ").append(md(graphEdgeLabel(edge))).append("\n")
                        .append("    ▼\n")
                        .append('[').append(target.role()).append("] ")
                        .append(md(target.label())).append('\n');
            }
        }
        out.append("~~~\n");
    }

    /**
     * Build a readable linear projection of one chain without changing its evidence.
     *
     * <p>The solver stores some composed chains as ordered fragments: the application/mechanism
     * prefix ends at a capability and the terminal suffix begins at that capability. Rendering
     * only the raw hop endpoints makes the graph appear disconnected. A {@code CHAIN_JOIN}
     * edge exposes that presentation join, while the exact raw hops remain available below it.
     * This is deliberately a presentation edge, not a new call-graph claim.</p>
     */
    private static GraphProjection graph(Chain chain, List<ChainHop> hops) {
        java.util.LinkedHashMap<String, String> nodeIds = new java.util.LinkedHashMap<>();
        List<String> labels = new ArrayList<>();
        List<GraphEdge> edges = new ArrayList<>();
        String current = member(chain.entryClass(), chain.entryMethod());
        ensureGraphNode(nodeIds, labels, current);
        for (ChainHop hop : hops) {
            String from = member(hop.fromOwner(), hop.fromName());
            String to = member(hop.toOwner(), hop.toName());
            String kind = hop.kind() == null ? "UNKNOWN" : hop.kind().name();
            if (from.equals(to)) {
                // Identity and field-flow self hops are useful in exact JSON evidence, but a
                // self-loop makes a human gadget graph look cyclic when no traversal occurs.
                ensureGraphNode(nodeIds, labels, from);
                continue;
            }
            if (!current.equals(from)) {
                String currentId = ensureGraphNode(nodeIds, labels, current);
                String fromId = ensureGraphNode(nodeIds, labels, from);
                edges.add(new GraphEdge(currentId, fromId, "CHAIN_JOIN",
                        "presentation join; exact endpoints remain in hops"));
            }
            String fromId = ensureGraphNode(nodeIds, labels, from);
            String toId = ensureGraphNode(nodeIds, labels, to);
            edges.add(new GraphEdge(fromId, toId, kind, graphEdgeReason(hop)));
            current = to;
        }
        String sink = member(chain.sinkClass(), chain.sinkMethod());
        if (!current.equals(sink)) {
            String currentId = ensureGraphNode(nodeIds, labels, current);
            String sinkId = ensureGraphNode(nodeIds, labels, sink);
            String kind = chain.terminalSink() ? "SINK_BOUNDARY" : "CAPABILITY_BOUNDARY";
            String reason = chain.terminalSink()
                    ? "declared sink; exact terminal evidence is in hops"
                    : "target-unresolved; no terminal is claimed";
            edges.add(new GraphEdge(currentId, sinkId, kind, reason));
        }
        List<GraphNode> nodes = new ArrayList<>();
        for (int i = 0; i < labels.size(); i++) {
            String role;
            if (i == 0) {
                role = "ENTRY";
            } else if (i == labels.size() - 1) {
                role = chain.terminalSink() ? "TERMINAL" : "BOUNDARY";
            } else {
                role = "STEP";
            }
            nodes.add(new GraphNode("n" + (i + 1), labels.get(i), role));
        }
        return new GraphProjection(nodes, edges);
    }

    private static String ensureGraphNode(java.util.Map<String, String> nodeIds,
                                          List<String> labels, String label) {
        return nodeIds.computeIfAbsent(label, ignored -> {
            String id = "n" + (nodeIds.size() + 1);
            labels.add(label);
            return id;
        });
    }

    private record GraphProjection(List<GraphNode> nodes, List<GraphEdge> edges) {
        private GraphProjection {
            nodes = List.copyOf(nodes);
            edges = List.copyOf(edges);
        }
    }

    private record GraphNode(String id, String label, String role) {
    }

    private record GraphEdge(String from, String to, String kind, String reason) {
    }

    private static String graphEdgeReason(ChainHop hop) {
        String reason = hop.reason() == null ? "" : hop.reason();
        if (hop.field() == null || hop.field().isBlank()) {
            return reason;
        }
        String field = "field=" + hop.field();
        return reason.isBlank() ? field : field + "; " + reason;
    }

    private static String graphEdgeLabel(GraphEdge edge) {
        if (edge.reason() == null || edge.reason().isBlank()) {
            return edge.kind();
        }
        return edge.kind() + " — " + edge.reason();
    }

    private static String markdown(String mode, FindingOutputReader.Snapshot snapshot,
                                   ScanStatistics stats,
                                   List<FindingOutputReader.Finding> findings) {
        long exported = findings.stream().filter(FindingOutputReader.Finding::exported).count();
        StringBuilder out = new StringBuilder(4096)
                .append("# Just report\n\n")
                .append("## Result\n\n")
                .append("- Outcome: ").append(md(publicOutcome(stats, findings))).append('\n')
                .append("- Coverage: ").append(md(coverage(stats))).append('\n')
                .append("- Mode: ").append(md(mode)).append('\n')
                .append("- Candidates: ").append(findings.size())
                .append("; exported: ").append(exported).append('\n')
                .append("- Artifact SHA-256: ").append(md(stats.artifactHash())).append('\n')
                .append("- Read next: report.json for all candidates and exact evidence\n");
        List<String> reasons = coverageReasons(stats);
        if (!"COMPLETE".equals(coverage(stats)) && !reasons.isEmpty()) {
            out.append("- Coverage notes: ").append(md(String.join(", ",
                    reasons.subList(0, Math.min(3, reasons.size())))));
            if (reasons.size() > 3) {
                out.append(" (and ").append(reasons.size() - 3).append(" more in report.json)");
            }
            out.append('\n');
        }
        out.append('\n');
        if (findings.isEmpty()) {
            out.append("No static chain candidate was produced. An empty result is not proof that "
                    + "the artifact is safe.\n")
                    .append("Reason: NO_CANDIDATES\n");
            return out.toString();
        }
        if (exported == 0) {
            out.append("Candidates were retained as audit evidence, but none met the selected "
                    + "mode export contract.\n\n");
        }
        out.append("## Chains\n\n");
        int number = 1;
        int detailedCount = Math.min(MARKDOWN_DISPLAY_LIMIT, findings.size());
        for (int index = 0; index < detailedCount; index++) {
            FindingOutputReader.Finding finding = findings.get(index);
            Chain chain = finding.chain();
            out.append("### ").append(number++).append(". ")
                    .append(finding.exported() ? "EXPORTED" : "CANDIDATE")
                    .append(" — ").append(md(chain.ruleId())).append("\n\n")
                    .append("Finding ID: ").append(md(finding.id())).append("\n\n")
                    .append("State: ").append(md(finding.state().eligibility().name()))
                    .append("; feasibility ").append(md(finding.state().feasibility().name()))
                    .append("; chain completeness ")
                    .append(md(finding.state().completeness().name())).append("\n\n");
            ApplicationTrace trace = snapshot.applicationTrace(chain.key());
            if (trace != null) {
                out.append("Application path: ").append(md(trace.entryDisplay()))
                        .append(" → site ").append(md(trace.siteDisplay())).append("\n");
                if (trace.joinEvidence() != null) {
                    out.append("Join: ").append(md(trace.joinEvidence().display())).append("\n");
                }
            } else {
                out.append("Chain: ").append(md(member(chain.entryClass(), chain.entryMethod())))
                        .append(" → ")
                        .append(md(member(chain.sinkClass(), chain.sinkMethod()))).append("\n");
            }
            out.append("Gadget graph:\n");
            List<ChainHop> orderedHops = orderedHops(chain);
            appendMarkdownGraph(out, graph(chain, orderedHops));
            if (chain.terminalSink()) {
                out.append("Terminal: ").append(md(member(chain.sinkClass(), chain.sinkMethod())))
                        .append("; exact hop evidence: report.json\n");
            } else {
                out.append("Capability boundary: ")
                        .append(md(member(chain.sinkClass(), chain.sinkMethod())))
                        .append("; target unresolved, so no terminal is claimed; exact hop evidence: report.json\n");
            }
            appendMarkdownLocations(out, orderedHops);
            if (!finding.notes().isEmpty()) {
                out.append("Notes: ").append(finding.notes().stream().map(ConciseReportWriter::md)
                        .reduce((left, right) -> left + "; " + right).orElse("")).append('\n');
            }
            out.append('\n');
        }
        if (findings.size() > detailedCount) {
            out.append("## Remaining candidate summaries\n\n")
                    .append("The JSON report retains every candidate and variant.\n\n")
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

    private static void appendMarkdownLocations(StringBuilder out, List<ChainHop> hops) {
        List<String> locations = new ArrayList<>();
        for (ChainHop hop : hops) {
            String summary = ReportEvidence.hopLocationSummary(hop.provenance());
            if (!locations.contains(summary)) {
                locations.add(summary);
            }
        }
        if (!locations.isEmpty()) {
            out.append("Location evidence: ").append(md(String.join(", ", locations)))
                    .append('\n');
        }
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

    private static void appendNullableLong(StringBuilder out, long value) {
        if (value < 0L) {
            out.append("null");
        } else {
            out.append(value);
        }
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
                if (i > 0) {
                    out.append(',');
                }
                out.append(quote(values.get(i)));
            }
        }
        out.append(']');
    }

    private static String quote(String value) {
        return "\"" + escape(value) + "\"";
    }

    private static String escape(String value) {
        if (value == null) {
            return "";
        }
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
                        out.append(String.format(java.util.Locale.ROOT,
                                "\\u%04x", (int) ch));
                    } else {
                        out.append(ch);
                    }
                }
            }
        }
        return out.toString();
    }

    private static String nullableQuote(String value) {
        return value == null || value.isBlank() ? "null" : quote(value);
    }

    private static String md(String value) {
        return value == null ? "" : value.replace("&", "&amp;")
                .replace("<", "&lt;").replace(">", "&gt;")
                .replace("|", "\\|").replace("\r", " ").replace("\n", " ");
    }
}
