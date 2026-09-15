package io.just.sast.report;

import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ConstructionSummary;
import io.just.sast.blackboard.VerificationSummary;
import io.just.sast.analysis.taint.FilterAnalysis;
import io.just.sast.chain.ChainRanking;
import io.just.sast.chain.ChainPrecision;
import io.just.sast.chain.ConfidenceScorer;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Set;

/**
 * E1-E3: 多格式报告输出——JSON（机器消费）、HTML（可视化）、Markdown（PR comment）。
 * 与 CSV/SARIF 并行，同一数据源。
 */
public final class MultiFormatReporter {

    /** Per-chain evidence memo shared by JSON/HTML/Markdown in one report pass. */
    private record ChainView(String confidence, ChainRanking.Evidence ranking,
                             ChainPrecision.Assessment precision,
                             boolean highConfidence,
                             ConstructionSummary construction,
                             ApplicationTrace applicationTrace) {
    }

    public void write(Path outDir, List<Chain> chains,
                      Map<String, String> calibrations, Map<String, List<String>> notes) throws IOException {
        write(ReportLayout.flat(outDir), chains, calibrations, notes, null);
    }

    public void write(ReportLayout layout, List<Chain> chains,
                      Map<String, String> calibrations, Map<String, List<String>> notes) throws IOException {
        write(layout, chains, calibrations, notes, null);
    }

    /**
     * Use the closed verification snapshot as the only source of dynamic terminal state.
     * Free-form chain notes are still rendered as supplementary static annotations.
     */
    public void write(ReportLayout layout, List<Chain> chains,
                      Map<String, String> calibrations, Map<String, List<String>> notes,
                      VerificationSummary verification) throws IOException {
        chains = chains == null ? List.of() : chains;
        calibrations = calibrations == null ? Map.of() : calibrations;
        notes = notes == null ? Map.of() : notes;
        write(layout, new FindingOutputReader().read(chains, calibrations, notes, verification));
    }

    /** Render a previously frozen snapshot; all formats in a pipeline can share one reader. */
    public void write(ReportLayout layout, FindingOutputReader.Snapshot snapshot)
            throws IOException {
        if (layout == null) {
            throw new IOException("report layout is null");
        }
        if (snapshot == null) {
            throw new IOException("finding output snapshot is null");
        }
        List<Chain> chains = snapshot.findings().stream()
                .map(FindingOutputReader.Finding::chain).toList();
        Map<String, String> calibrations = new java.util.TreeMap<>();
        Map<String, List<String>> notes = new java.util.TreeMap<>();
        for (FindingOutputReader.Finding finding : snapshot.findings()) {
            if (!finding.exported()) {
                calibrations.putIfAbsent(finding.chain().key(), finding.calibration());
            }
            notes.putIfAbsent(finding.chain().key(), finding.notes());
        }
        Files.createDirectories(layout.findings());
        Map<String, VerificationSummary.ChainResult> verificationByKey =
                snapshot.verificationByKey();
        boolean structuredVerification = snapshot.structuredVerification();
        List<Chain> orderedChains = new ArrayList<>(chains);
        orderedChains.sort(ChainRanking.comparator(notes, verificationByKey, Set.of()));
        Map<String, ChainView> views = buildViews(orderedChains, snapshot);
        // E1: JSON
        writeJson(layout.findings().resolve("findings.json"), orderedChains, calibrations, notes,
                verificationByKey, structuredVerification, views);
        // E2: HTML
        writeHtml(layout.findings().resolve("findings.html"), orderedChains, calibrations, notes,
                verificationByKey, structuredVerification, views);
        // E3: Markdown
        writeMarkdown(layout.findings().resolve("findings.md"), orderedChains, calibrations, notes,
                verificationByKey, structuredVerification, views);
    }

    /** 扫描元数据旁车文件：不破坏 findings.json 数组契约，同时公开完整性和性能边界。 */
    public void writeMetadata(Path outDir, ScanStatistics stats) throws IOException {
        writeMetadata(ReportLayout.flat(outDir), stats);
    }

    public void writeMetadata(ReportLayout layout, ScanStatistics stats) throws IOException {
        Files.createDirectories(layout.meta());
        Files.createDirectories(layout.verification());
        io.just.sast.run.RunOutcome runOutcome = stats == null
                ? io.just.sast.run.RunOutcome.notRun("MISSING_SCAN_STATISTICS", "")
                : stats.runOutcome();
        StringBuilder sb = new StringBuilder("{\n")
                .append("  \"schema_version\":1,")
                .append("\n")
                .append("  \"run_outcome\":").append(runOutcome.toCanonicalJson()).append(",\n")
                .append("  \"files_scanned\":").append(stats.filesScanned())
                .append(",\"classes_loaded\":").append(stats.classesLoaded())
                .append(",\"diagnostics\":").append(stats.diagnostics())
                .append(",\"sinks_marked\":").append(stats.sinksMarked())
                .append(",\"magic_entries\":").append(stats.magicEntries())
                .append(",\"chains_found\":").append(stats.chainsFound())
                .append(",\"elapsed_ms\":").append(stats.elapsedMs())
                .append(",\"heap_used_mb\":").append(stats.heapUsedMb())
                .append(",\"heap_peak_mb\":").append(stats.heapPeakMb())
                .append(",\"completeness\":\"").append(escJson(stats.completeness())).append("\"")
                .append(",\"chain_proof_completeness\":\"")
                .append(escJson(stats.chainProofCompleteness())).append("\"")
                .append(",\"artifact_sha256\":\"")
                .append(escJson(stats.artifactHash())).append("\"")
                .append(",\"verification\":\"").append(escJson(stats.verification())).append("\"")
                .append(",\"completeness_reasons\":[");
        for (int i = 0; i < stats.completenessReasons().size(); i++) {
            if (i > 0) sb.append(',');
            sb.append('"').append(escJson(stats.completenessReasons().get(i))).append('"');
        }
        sb.append("],\"phase_ms\":{");
        List<Map.Entry<String, Long>> phases = new ArrayList<>(stats.phaseMs().entrySet());
        phases.sort(Map.Entry.comparingByKey());
        for (int i = 0; i < phases.size(); i++) {
            if (i > 0) sb.append(',');
            Map.Entry<String, Long> phase = phases.get(i);
            sb.append('"').append(escJson(phase.getKey())).append("\":").append(phase.getValue());
        }
        sb.append("},\"metrics\":{");
        List<Map.Entry<String, Long>> metrics = new ArrayList<>(stats.metrics().entrySet());
        metrics.sort(Map.Entry.comparingByKey());
        for (int i = 0; i < metrics.size(); i++) {
            if (i > 0) sb.append(',');
            Map.Entry<String, Long> metric = metrics.get(i);
            sb.append('"').append(escJson(metric.getKey())).append("\":").append(metric.getValue());
        }
        sb.append("},\"metric_status\":{");
        List<Map.Entry<String, String>> metricStatus = new ArrayList<>(stats.metricStatus().entrySet());
        metricStatus.sort(Map.Entry.comparingByKey());
        for (int i = 0; i < metricStatus.size(); i++) {
            if (i > 0) sb.append(',');
            Map.Entry<String, String> metric = metricStatus.get(i);
            sb.append('"').append(escJson(metric.getKey())).append("\":\"")
                    .append(escJson(metric.getValue())).append('"');
        }
        sb.append("},\"metric_namespaces\":{");
        List<Map.Entry<String, Map<String, Long>>> namespaces =
                new ArrayList<>(stats.metricNamespaces().entrySet());
        namespaces.sort(Map.Entry.comparingByKey());
        for (int i = 0; i < namespaces.size(); i++) {
            if (i > 0) sb.append(',');
            Map.Entry<String, Map<String, Long>> namespace = namespaces.get(i);
            sb.append('"').append(escJson(namespace.getKey())).append("\":{");
            List<Map.Entry<String, Long>> values = new ArrayList<>(namespace.getValue().entrySet());
            values.sort(Map.Entry.comparingByKey());
            for (int j = 0; j < values.size(); j++) {
                if (j > 0) sb.append(',');
                Map.Entry<String, Long> value = values.get(j);
                sb.append('"').append(escJson(value.getKey())).append("\":")
                        .append(value.getValue());
            }
            sb.append('}');
        }
        sb.append("},\"metric_namespace_status\":{");
        List<Map.Entry<String, String>> namespaceStatus =
                new ArrayList<>(stats.metricNamespaceStatus().entrySet());
        namespaceStatus.sort(Map.Entry.comparingByKey());
        for (int i = 0; i < namespaceStatus.size(); i++) {
            if (i > 0) sb.append(',');
            Map.Entry<String, String> status = namespaceStatus.get(i);
            sb.append('"').append(escJson(status.getKey())).append("\":\"")
                    .append(escJson(status.getValue())).append('"');
        }
        sb.append("},\"filter_evidence\":");
        appendFilterEvidenceJson(sb, stats.filterEvidence());
        sb.append(",\"dynamic_verification\":");
        appendVerificationJson(sb, stats.dynamicVerification());
        sb.append("\n}\n");
        AtomicFiles.writeUtf8(layout.meta().resolve("scan-metadata.json"), sb.toString());
        StringBuilder dynamic = new StringBuilder();
        appendVerificationJson(dynamic, stats.dynamicVerification());
        dynamic.append('\n');
        AtomicFiles.writeUtf8(layout.verification().resolve("dynamic-verification.json"),
                dynamic.toString());
        StringBuilder run = new StringBuilder("{\n  \"schema_version\":1,\n  \"kind\":\"just-run\",\n  \"run_outcome\":")
                .append(runOutcome.toCanonicalJson()).append(',');
        appendRunDisclosure(run, stats.dynamicVerification());
        run.append("\n}\n");
        AtomicFiles.writeUtf8(layout.meta().resolve("run.json"), run.toString());
    }

    private static void appendFilterEvidenceJson(StringBuilder sb,
                                                 List<FilterAnalysis.Evidence> evidence) {
        sb.append('[');
        if (evidence != null) {
            for (int i = 0; i < evidence.size(); i++) {
                if (i > 0) {
                    sb.append(',');
                }
                FilterAnalysis.Evidence item = evidence.get(i);
                sb.append('{')
                        .append("\"kind\":\"").append(escJson(item.kind().name())).append('"')
                        .append(",\"location\":\"").append(escJson(item.location())).append('"')
                        .append(",\"status\":\"").append(escJson(item.status().name())).append('"')
                        .append(",\"reason_code\":\"").append(escJson(item.reasonCode())).append('"')
                        .append(",\"domain_digest\":\"").append(escJson(item.domainDigest())).append('"')
                        .append(",\"semantic_digest\":\"").append(escJson(item.semanticDigest())).append('"')
                        .append(",\"budget\":").append(item.budget())
                        .append(",\"evaluated\":").append(item.evaluated())
                        .append(",\"retained\":").append(item.retained())
                        .append(",\"rejected\":").append(item.rejected())
                        .append(",\"expanded\":").append(item.expanded())
                        .append(",\"filter_cost_nanos\":").append(item.filterCostNanos())
                        .append('}');
            }
        }
        sb.append(']');
    }

    private static void appendVerificationJson(StringBuilder sb, VerificationSummary summary) {
        VerificationSummary safeSummary = summary == null
                ? VerificationSummary.empty("UNKNOWN", 0) : summary;
        VerificationSummary.SafetyDisclosure disclosure = safeSummary.safetyDisclosure();
        sb.append('{')
                .append("\"schema_version\":1,")
                .append("\"capability\":\"").append(escJson(safeSummary.capability())).append("\"")
                .append(",\"verification_mode\":\"").append(escJson(disclosure.verificationMode()))
                .append("\",\"verificationMode\":\"").append(escJson(disclosure.verificationMode()))
                .append("\",\"target_code_execution_possible\":")
                .append(disclosure.targetCodeExecutionPossible())
                .append(",\"targetCodeExecutionPossible\":")
                .append(disclosure.targetCodeExecutionPossible())
                .append(",\"target_code_executed\":\"")
                .append(escJson(disclosure.targetCodeExecuted()))
                .append("\",\"targetCodeExecuted\":\"")
                .append(escJson(disclosure.targetCodeExecuted())).append('"')
                .append(",\"resource_containment_only\":")
                .append(disclosure.resourceContainmentOnly())
                .append(",\"resourceContainmentOnly\":")
                .append(disclosure.resourceContainmentOnly())
                .append(",\"filesystem_isolation\":")
                .append(disclosure.filesystemIsolation())
                .append(",\"filesystemIsolation\":")
                .append(disclosure.filesystemIsolation())
                .append(",\"network_isolation\":")
                .append(disclosure.networkIsolation())
                .append(",\"networkIsolation\":")
                .append(disclosure.networkIsolation())
                .append(",\"token_isolation\":")
                .append(disclosure.tokenIsolation())
                .append(",\"tokenIsolation\":")
                .append(disclosure.tokenIsolation())
                .append(",\"dangerous_sink_executed\":")
                .append(disclosure.dangerousSinkExecuted())
                .append(",\"dangerousSinkExecuted\":")
                .append(disclosure.dangerousSinkExecuted())
                .append(",\"recommended_for_untrusted_artifacts\":")
                .append(disclosure.recommendedForUntrustedArtifacts())
                .append(",\"recommendedForUntrustedArtifacts\":")
                .append(disclosure.recommendedForUntrustedArtifacts())
                .append(",\"target_trust\":\"").append(escJson(disclosure.targetTrust()))
                .append("\",\"isolation_backend\":\"")
                .append(escJson(disclosure.isolationBackend()))
                .append("\",\"isolationBackend\":\"")
                .append(escJson(disclosure.isolationBackend()))
                .append("\",\"isolation_status\":\"")
                .append(escJson(disclosure.isolationStatus()))
                .append("\",\"isolationStatus\":\"")
                .append(escJson(disclosure.isolationStatus()))
                .append("\",\"fail_closed_on_isolation_failure\":")
                .append(disclosure.failClosedOnIsolationFailure())
                .append(",\"failClosedOnIsolationFailure\":")
                .append(disclosure.failClosedOnIsolationFailure())
                .append(",\"capability_gaps\":");
        appendStrings(sb, disclosure.capabilityGaps());
        sb.append(",\"backend\":\"").append(escJson(safeSummary.backend())).append("\"")
                .append(",\"isolation_level\":\"").append(escJson(safeSummary.isolationLevel())).append("\"")
                .append(",\"isolation_capabilities\":");
        appendStrings(sb, safeSummary.isolationCapabilities());
        sb.append(",\"jdk\":\"").append(escJson(safeSummary.jdk())).append("\"")
                .append(",\"attestation_version\":\"")
                .append(escJson(safeSummary.attestationVersion())).append("\"")
                .append(",\"policy_digest\":\"").append(escJson(safeSummary.policyDigest())).append("\"")
                .append(",\"artifact_sha256\":\"").append(escJson(safeSummary.artifactHash())).append("\"")
                .append(",\"sink_distorted\":").append(safeSummary.sinkDistorted())
                .append(",\"resource_containment_ready\":").append(safeSummary.sandboxReady())
                .append(",\"cleanup\":\"").append(escJson(safeSummary.cleanup())).append("\"")
                .append(",\"budget\":").append(safeSummary.budget())
                .append(",\"constructible\":").append(safeSummary.constructible())
                .append(",\"rejected\":").append(safeSummary.rejected())
                .append(",\"selected\":").append(safeSummary.selected())
                .append(",\"status_counts\":");
        appendCounts(sb, safeSummary.statusCounts());
        sb.append(",\"detail_counts\":");
        appendCounts(sb, safeSummary.detailCounts());
        sb.append(",\"results\":[");
        for (int i = 0; i < safeSummary.results().size(); i++) {
            if (i > 0) {
                sb.append(',');
            }
            VerificationSummary.ChainResult result = safeSummary.results().get(i);
            sb.append('{')
                    .append("\"rank\":").append(result.rank())
                    .append(",\"chain_key\":\"").append(escJson(result.chainKey())).append("\"")
                    .append(",\"status\":\"").append(escJson(result.status())).append("\"")
                    .append(",\"detail\":\"").append(escJson(result.detail())).append("\"")
                    .append(",\"confidence\":\"").append(escJson(result.confidence())).append("\"")
                    .append(",\"confidence_score\":").append(result.confidenceScore())
                    .append(",\"attempt\":").append(result.attempt())
                    .append(",\"duration_ms\":").append(result.durationMs())
                    .append(",\"evidence\":\"").append(escJson(result.evidence())).append("\"")
                    .append(",\"backend\":\"").append(escJson(result.backend())).append("\"")
                    .append(",\"jdk\":\"").append(escJson(result.jdk())).append("\"")
                    .append(",\"policy_digest\":\"").append(escJson(result.policyDigest())).append("\"")
                    .append(",\"sink_distorted\":").append(result.sinkDistorted())
                    .append(",\"resource_containment_ready\":").append(result.sandboxReady())
                    .append(",\"requested_mode\":\"").append(escJson(result.requestedMode())).append("\"")
                    .append(",\"effective_mode\":\"").append(escJson(result.effectiveMode())).append("\"")
                    .append(",\"fallback\":\"").append(escJson(result.fallback())).append("\"")
                    .append(",\"verification_scope\":\"").append(escJson(result.verificationScope())).append("\"")
                    .append(",\"verification_group\":\"")
                    .append(ReportEvidence.verificationGroup(result)).append("\"")
                    .append(",\"sink_risk\":\"").append(escJson(result.sinkRisk())).append("\"")
                    .append(",\"terminal_executed\":").append(result.terminalExecuted())
                    .append(",\"stop_reason\":\"").append(escJson(result.stopReason())).append("\"")
                    .append(",\"last_confirmed_stage\":\"").append(escJson(result.lastConfirmedStage())).append("\"")
                    .append(",\"cleanup\":\"").append(escJson(result.cleanup())).append("\"")
                    .append('}');
        }
        sb.append("]}");
    }

    private static void appendRunDisclosure(StringBuilder sb, VerificationSummary summary) {
        VerificationSummary.SafetyDisclosure disclosure = (summary == null
                ? VerificationSummary.empty("UNKNOWN", 0) : summary).safetyDisclosure();
        sb.append("\n  \"verificationMode\":\"").append(escJson(disclosure.verificationMode()))
                .append("\",\n  \"targetCodeExecutionPossible\":")
                .append(disclosure.targetCodeExecutionPossible())
                .append(",\n  \"targetCodeExecuted\":\"")
                .append(escJson(disclosure.targetCodeExecuted())).append("\",\n  \"resourceContainmentOnly\":")
                .append(disclosure.resourceContainmentOnly())
                .append(",\n  \"filesystemIsolation\":")
                .append(disclosure.filesystemIsolation())
                .append(",\n  \"networkIsolation\":")
                .append(disclosure.networkIsolation())
                .append(",\n  \"tokenIsolation\":")
                .append(disclosure.tokenIsolation())
                .append(",\n  \"dangerousSinkExecuted\":")
                .append(disclosure.dangerousSinkExecuted())
                .append(",\n  \"recommendedForUntrustedArtifacts\":")
                .append(disclosure.recommendedForUntrustedArtifacts())
                .append(",\n  \"targetTrust\":\"").append(escJson(disclosure.targetTrust()))
                .append("\",\n  \"isolationBackend\":\"")
                .append(escJson(disclosure.isolationBackend())).append("\",\n  \"isolationStatus\":\"")
                .append(escJson(disclosure.isolationStatus())).append("\",\n  \"failClosedOnIsolationFailure\":")
                .append(disclosure.failClosedOnIsolationFailure())
                .append(",\n  \"capabilityGaps\":");
        appendStrings(sb, disclosure.capabilityGaps());
    }

    private static void appendStrings(StringBuilder sb, List<String> values) {
        sb.append('[');
        if (values != null) {
            for (int i = 0; i < values.size(); i++) {
                if (i > 0) {
                    sb.append(',');
                }
                sb.append('"').append(escJson(values.get(i))).append('"');
            }
        }
        sb.append(']');
    }

    private static void appendCounts(StringBuilder sb, Map<String, Integer> counts) {
        sb.append('{');
        List<Map.Entry<String, Integer>> entries = new ArrayList<>(counts.entrySet());
        entries.sort(Map.Entry.comparingByKey());
        for (int i = 0; i < entries.size(); i++) {
            if (i > 0) {
                sb.append(',');
            }
            Map.Entry<String, Integer> entry = entries.get(i);
            sb.append('"').append(escJson(entry.getKey())).append("\":").append(entry.getValue());
        }
        sb.append('}');
    }

    private void writeJson(Path path, List<Chain> chains,
                           Map<String, String> calibrations, Map<String, List<String>> notes,
                           Map<String, VerificationSummary.ChainResult> verification,
                           boolean structuredVerification,
                           Map<String, ChainView> views) throws IOException {
        writeAtomically(path, temp -> {
            try (BufferedWriter writer = AtomicFiles.newUtf8Writer(temp)) {
                writer.write("[\n");
                boolean first = true;
                for (Chain c : chains) {
                    if (calibrations.containsKey(c.key())) {
                        continue;
                    }
                    if (!first) {
                        writer.write(",\n");
                    }
                    first = false;
                    List<String> cn = notes.getOrDefault(c.key(), List.of());
                    VerificationSummary.ChainResult result = verification.get(c.key());
                    ChainView view = views.get(c.key());
                    String verify = verificationStatus(result, cn, structuredVerification);
                    writer.append("  {\"rule_id\":\"").append(escJson(c.ruleId()))
                            .append("\",\"category\":\"").append(escJson(c.category()))
                            .append("\",\"severity\":\"").append(escJson(c.severity()))
                            .append("\",\"confidence\":\"").append(escJson(view.confidence()))
                            .append("\",\"entry_class\":\"").append(escJson(c.entryClass().replace('/', '.')))
                            .append("\",\"entry_method\":\"").append(escJson(c.entryMethod()))
                            .append("\",\"sink_class\":\"").append(escJson(c.sinkClass().replace('/', '.')))
                            .append("\",\"sink_method\":\"").append(escJson(c.sinkMethod()))
                            .append("\",\"sink_descriptor\":\"").append(escJson(c.sinkDescriptor()))
                            .append("\",\"sink_role\":\"").append(escJson(c.sinkRole()))
                            .append("\",\"sink_risk\":\"").append(escJson(c.sinkRisk().name()))
                            .append("\",\"ranking_evidence\":\"")
                            .append(escJson(view.ranking().explanation()))
                            .append("\",\"precision\":")
                            .append(ChainPrecision.toJson(view.precision(), MultiFormatReporter::escJson,
                                    view.highConfidence()))
                            .append(",\"high_confidence\":")
                            .append(Boolean.toString(view.highConfidence()))
                            .append(",\"construction\":")
                            .append(ReportEvidence.constructionJson(view.construction()))
                            .append(",\"chain_length\":").append(Integer.toString(c.hops().size()))
                            .append(",\"unresolved_hops\":").append(Integer.toString(c.unresolvedHops()))
                            .append(",\"path\":\"").append(escJson(CsvReporter.pathSummary(c)))
                            .append("\",\"application_entry_class\":\"")
                            .append(escJson(view.applicationTrace() == null ? ""
                                    : view.applicationTrace().applicationEntryClass()))
                            .append("\",\"application_entry_method\":\"")
                            .append(escJson(view.applicationTrace() == null ? ""
                                    : view.applicationTrace().applicationEntryMethod()))
                            .append("\",\"application_site_class\":\"")
                            .append(escJson(view.applicationTrace() == null ? ""
                                    : view.applicationTrace().applicationSiteClass()))
                            .append("\",\"application_site_method\":\"")
                            .append(escJson(view.applicationTrace() == null ? ""
                                    : view.applicationTrace().applicationSiteMethod()))
                            .append("\",\"application_site_kind\":\"")
                            .append(escJson(view.applicationTrace() == null ? ""
                                    : view.applicationTrace().applicationSiteKind()))
                            .append("\",\"application_join_kind\":\"")
                            .append(escJson(view.applicationTrace() == null ? ""
                                    : view.applicationTrace().joinKind()))
                            .append("\",\"application_chain_entry_method\":\"")
                            .append(escJson(view.applicationTrace() == null ? ""
                                    : view.applicationTrace().chainEntryMethod()))
                            .append("\",\"application_entry_prefix_path\":\"")
                            .append(escJson(view.applicationTrace() == null ? ""
                                    : view.applicationTrace().entryPrefixPath()))
                            .append("\",\"application_path\":\"")
                            .append(escJson(view.applicationTrace() == null ? ""
                                    : view.applicationTrace().applicationPath(c)))
                            .append("\",\"verification_status\":\"").append(escJson(verify))
                            .append("\",\"verification_evidence\":\"")
                            .append(escJson(result == null ? "" : result.evidence()))
                            .append("\",\"verification_rank\":")
                            .append(Integer.toString(result == null ? 0 : result.rank()))
                            .append(",\"verify\":\"").append(escJson(verify)).append('"')
                            .append(",\"sink_distorted\":")
                            .append(Boolean.toString(result != null && result.sinkDistorted()))
                            .append(",\"resource_containment_ready\":")
                            .append(Boolean.toString(result != null && result.sandboxReady()))
                            .append(",\"requested_mode\":\"")
                            .append(escJson(result == null ? "UNKNOWN" : result.requestedMode()))
                            .append("\",\"effective_mode\":\"")
                            .append(escJson(result == null ? "UNKNOWN" : result.effectiveMode()))
                            .append("\",\"fallback\":\"")
                            .append(escJson(result == null ? "none" : result.fallback()))
                            .append("\",\"verification_scope\":\"")
                            .append(escJson(result == null ? "NONE" : result.verificationScope()))
                            .append("\",\"verification_group\":\"")
                            .append(ReportEvidence.verificationGroup(result))
                            .append("\",\"sink_risk_observed\":\"")
                            .append(escJson(result == null ? c.sinkRisk().name() : result.sinkRisk()))
                            .append("\",\"terminal_executed\":")
                            .append(Boolean.toString(result != null && result.terminalExecuted()))
                            .append(",\"stop_reason\":\"")
                            .append(escJson(result == null ? "NOT_SELECTED" : result.stopReason()))
                            .append("\",\"last_confirmed_stage\":\"")
                            .append(escJson(result == null ? "NONE" : result.lastConfirmedStage()))
                            .append('"')
                            .append('}');
                }
                writer.write("\n]");
            }
        });
    }

    private void writeHtml(Path path, List<Chain> chains,
                           Map<String, String> calibrations, Map<String, List<String>> notes,
                           Map<String, VerificationSummary.ChainResult> verification,
                           boolean structuredVerification,
                           Map<String, ChainView> views) throws IOException {
        writeAtomically(path, temp -> {
          try (BufferedWriter writer = AtomicFiles.newUtf8Writer(temp)) {
            writer.write("<!DOCTYPE html>\n<html><head><meta charset='UTF-8'><title>Just SAST Findings</title>\n");
            writer.write("<style>body{font-family:monospace;margin:20px;background:#1e1e1e;color:#d4d4d4}");
            writer.write("table{border-collapse:collapse;width:100%}th,td{border:1px solid #444;padding:6px 10px;text-align:left}");
            writer.write("th{background:#2d2d2d}.HIGH{color:#f44747}.FEASIBLE{color:#4ec9b0}.DEGRADED{color:#cca700}");
            writer.write(".path{font-size:11px;color:#888}</style></head><body>\n");
            writer.write("<h1>Just SAST — Gadget Chain Findings</h1>\n");
            writer.append("<p>Total: ").append(Long.toString(chains.stream()
                    .filter(c -> !calibrations.containsKey(c.key())).count())).append(" chains</p>\n");
            writer.write("<table><tr><th>#</th><th>Rule</th><th>Confidence</th><th>Verification</th><th>Group</th><th>Scope</th><th>Sink risk</th><th>Terminal executed</th><th>High confidence</th><th>Application entry</th><th>Application path</th><th>Chain entry</th><th>Sink</th><th>Sink role</th><th>Construction</th><th>Sink control</th><th>Precision</th><th>Rank evidence</th><th>Hops</th></tr>\n");
            int seq = 0;
            for (Chain c : chains) {
                if (calibrations.containsKey(c.key())) {
                    continue;
                }
                seq++;
                List<String> cn = notes.getOrDefault(c.key(), List.of());
                VerificationSummary.ChainResult result = verification.get(c.key());
                ChainView view = views.get(c.key());
                String conf = view.confidence();
                ConstructionSummary construction = view.construction();
                writer.append("<tr><td>").append(Integer.toString(seq))
                        .append("</td><td>").append(escHtml(c.ruleId()))
                        .append("</td><td class='").append(conf.contains("DEGRADED") ? "DEGRADED" : "FEASIBLE").append("'>").append(conf)
                        .append("</td><td>").append(escHtml(verificationStatus(result, cn,
                                structuredVerification)))
                        .append("</td><td>").append(escHtml(ReportEvidence.verificationGroup(result)))
                        .append("</td><td>").append(escHtml(result == null ? "NONE" : result.verificationScope()))
                        .append("</td><td>").append(escHtml(c.sinkRisk().name()))
                        .append("</td><td>").append(Boolean.toString(result != null && result.terminalExecuted()))
                        .append("</td><td>").append(Boolean.toString(view.highConfidence()))
                        .append("</td><td>").append(escHtml(view.applicationTrace() == null ? ""
                                : view.applicationTrace().entryDisplay()))
                        .append("</td><td class='path'>").append(escHtml(view.applicationTrace() == null ? ""
                                : view.applicationTrace().applicationPath(c)))
                        .append("</td><td>").append(escHtml(c.entryClass().replace('/', '.'))).append(".").append(escHtml(c.entryMethod()))
                        .append("</td><td>").append(escHtml(c.sinkClass().replace('/', '.'))).append(".").append(escHtml(c.sinkMethod()))
                        .append("</td><td>").append(escHtml(c.sinkRole()))
                        .append("</td><td>").append(escHtml(construction.overallStatus()))
                        .append("</td><td>").append(escHtml(construction.sinkControlStatus()))
                        .append("</td><td>").append(escHtml(view.precision().compact()))
                        .append("</td><td>").append(escHtml(view.ranking().explanation()))
                        .append("</td><td>").append(Integer.toString(c.hops().size())).append("</td></tr>\n");
            }
            writer.write("</table></body></html>");
          }
        });
    }

    private void writeMarkdown(Path path, List<Chain> chains,
                               Map<String, String> calibrations, Map<String, List<String>> notes,
                               Map<String, VerificationSummary.ChainResult> verification,
                               boolean structuredVerification,
                               Map<String, ChainView> views) throws IOException {
        writeAtomically(path, temp -> {
          try (BufferedWriter writer = AtomicFiles.newUtf8Writer(temp)) {
            writer.write("# Just SAST — Gadget Chain Findings\n\n");
            long count = chains.stream().filter(c -> !calibrations.containsKey(c.key())).count();
            writer.append("**Total**: ").append(Long.toString(count)).append(" chains\n\n");
            writer.write("| # | Rule | Confidence | Verification | Group | Scope | Sink risk | Terminal executed | High confidence | Application entry | Application path | Chain entry | Sink | Sink role | Construction | Sink control | Precision | Rank evidence | Hops |\n|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n");
            int seq = 0;
            for (Chain c : chains) {
                if (calibrations.containsKey(c.key())) {
                    continue;
                }
                seq++;
                List<String> cn = notes.getOrDefault(c.key(), List.of());
                VerificationSummary.ChainResult result = verification.get(c.key());
                ChainView view = views.get(c.key());
                ConstructionSummary construction = view.construction();
                writer.append("| ").append(Integer.toString(seq))
                        .append(" | `").append(escMd(c.ruleId())).append("`")
                        .append(" | ").append(escMd(view.confidence()))
                        .append(" | ").append(escMd(verificationStatus(result, cn,
                                structuredVerification)))
                        .append(" | ").append(escMd(ReportEvidence.verificationGroup(result)))
                        .append(" | ").append(escMd(result == null ? "NONE" : result.verificationScope()))
                        .append(" | ").append(escMd(c.sinkRisk().name()))
                        .append(" | ").append(Boolean.toString(result != null && result.terminalExecuted()))
                        .append(" | ").append(Boolean.toString(view.highConfidence()))
                        .append(" | `").append(escMd(view.applicationTrace() == null ? ""
                                : view.applicationTrace().entryDisplay())).append("`")
                        .append(" | `").append(escMd(view.applicationTrace() == null ? ""
                                : view.applicationTrace().applicationPath(c))).append("`")
                        .append(" | `").append(escMd(c.entryClass().replace('/', '.'))).append(".").append(escMd(c.entryMethod())).append("`")
                        .append(" | `").append(escMd(c.sinkClass().replace('/', '.'))).append(".").append(escMd(c.sinkMethod())).append("`")
                        .append(" | ").append(escMd(c.sinkRole()))
                        .append(" | ").append(escMd(construction.overallStatus()))
                        .append(" | ").append(escMd(construction.sinkControlStatus()))
                        .append(" | ").append(escMd(view.precision().compact()))
                        .append(" | ").append(escMd(view.ranking().explanation()))
                        .append(" | ").append(Integer.toString(c.hops().size())).append(" |\n");
            }
          }
        });
    }

    /** D4: 休眠链检测——Serializable 类有 sink 调用但不在入口闭包内（依赖变更可激活）。 */
    public void writeDormant(Path outDir, java.util.Set<String> entryReachable,
                             java.util.Set<String> sinkHosts) throws IOException {
        writeDormant(ReportLayout.flat(outDir), entryReachable, sinkHosts);
    }

    public void writeDormant(ReportLayout layout, java.util.Set<String> entryReachable,
                             java.util.Set<String> sinkHosts) throws IOException {
        java.util.Set<String> dormant = new java.util.TreeSet<>(sinkHosts);
        dormant.removeAll(entryReachable);
        if (dormant.isEmpty()) {
            return;
        }
        StringBuilder sb = new StringBuilder("# 休眠链（Dormant Gadgets）\n\n");
        sb.append("以下 ").append(dormant.size()).append(" 个类含 gadget 构件但当前入口不可达——\n");
        sb.append("依赖小改动（新增入口/字段引用变更）可能激活。\n\n");
        for (String d : dormant) {
            sb.append("- `").append(d.replace('/', '.')).append("`\n");
        }
        Files.createDirectories(layout.evidence());
        AtomicFiles.writeUtf8(layout.evidence().resolve("dormant.md"), sb.toString());
    }

    /** JSON 字符串转义（含控制字符；不做 HTML 实体——实体泄漏进 JSON 是历史缺陷）。 */
    private static String escJson(String s) {
        if (s == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(s.length() + 8);
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            switch (ch) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (ch < 0x20) {
                        sb.append(String.format("\\u%04x", (int) ch));
                    } else {
                        sb.append(ch);
                    }
                }
            }
        }
        return sb.toString();
    }

    /** HTML 文本转义。 */
    private static String escHtml(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    /** Markdown 表格转义（管道符破坏列结构，换行破坏行结构）。 */
    private static String escMd(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("|", "\\|").replace("\r", " ").replace("\n", " ");
    }

    private static Map<String, VerificationSummary.ChainResult> verificationByKey(
            VerificationSummary verification) {
        if (verification == null || verification.results().isEmpty()) {
            return Map.of();
        }
        Map<String, VerificationSummary.ChainResult> result = new java.util.HashMap<>();
        for (VerificationSummary.ChainResult item : verification.results()) {
            result.putIfAbsent(item.chainKey(), item);
        }
        return result;
    }

    private static Map<String, ChainView> buildViews(
            List<Chain> chains, FindingOutputReader.Snapshot snapshot) {
        Map<String, ChainView> views = new HashMap<>(Math.max(16, chains.size() * 2));
        for (Chain chain : chains) {
            if (views.containsKey(chain.key())) {
                continue;
            }
            FindingOutputReader.Finding finding = snapshot.byChainKey().get(chain.key());
            if (finding == null) {
                // Defensive only: the reader is built from the same immutable chain list.  Do
                // not let a future caller silently invent a second semantic source.
                continue;
            }
            views.put(chain.key(), new ChainView(
                    finding.confidence().bucket(), finding.ranking(), finding.precision(),
                    finding.highConfidence(), finding.construction(),
                    snapshot.applicationTrace(chain.key())));
        }
        return views;
    }

    private static String verificationStatus(VerificationSummary.ChainResult result,
                                             List<String> notes,
                                             boolean structuredVerification) {
        return FindingOutputReader.legacyVerificationStatus(result, notes,
                structuredVerification);
    }

    @FunctionalInterface
    private interface AtomicWriter {
        void write(Path temp) throws IOException;
    }

    private static void writeAtomically(Path target, AtomicWriter writer) throws IOException {
        Path temp = AtomicFiles.tempSibling(target);
        boolean committed = false;
        try {
            writer.write(temp);
            AtomicFiles.commit(temp, target);
            committed = true;
        } finally {
            if (!committed) {
                Files.deleteIfExists(temp);
            }
        }
    }
}
