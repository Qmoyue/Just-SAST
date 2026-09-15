package io.just.sast.report;

import io.just.sast.blackboard.VerificationSummary;
import io.just.sast.model.DependencyGraph;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Writes the single human entry point for a classified scan result. */
public final class ReportIndexWriter {

    public void write(ReportLayout layout, ScanStatistics stats) throws IOException {
        Files.createDirectories(layout.root());
        StringBuilder markdown = new StringBuilder("# Just scan report\n\n")
                .append("> One reading entry for this scan. Detailed artifacts are grouped by purpose.\n\n")
                .append("## Summary\n\n")
                .append("| Metric | Value |\n|---|---:|\n")
                .append("| Files scanned | ").append(stats.filesScanned()).append(" |\n")
                .append("| Classes loaded | ").append(stats.classesLoaded()).append(" |\n")
                .append("| Sinks marked | ").append(stats.sinksMarked()).append(" |\n")
                .append("| Magic entries | ").append(stats.magicEntries()).append(" |\n")
                .append("| Chains found | ").append(stats.chainsFound()).append(" |\n")
                .append("| Elapsed | ").append(stats.elapsedMs()).append(" ms |\n")
                .append("| Dependency resolution | ")
                .append(timing(stats, "dependency_resolution_ms")).append(" |\n")
                .append("| Network download wall | ")
                .append(timing(stats, "network_download_wall_ms")).append(" |\n")
                .append("| Network request duration | ")
                .append(timing(stats, "network_request_ms")).append(" |\n")
                .append("| Analysis | ").append(timing(stats, "analysis_ms")).append(" |\n")
                .append("| Bounded filter | ")
                .append(timing(stats, "filter_ms")).append(" |\n")
                .append("| Report | ").append(timing(stats, "report_ms")).append(" |\n")
                .append("| Total wall | ").append(timing(stats, "total_wall_ms")).append(" |\n")
                .append("| Dependency sources | `")
                .append(markdown(dependencySources(stats))).append("` |\n")
                .append("| Heap used | ").append(stats.heapUsedMb()).append(" MB |\n")
                .append("| Heap peak | ").append(stats.heapPeakMb()).append(" MB |\n")
                .append("| Artifact SHA-256 | `").append(markdown(stats.artifactHash())).append("` |\n")
                .append("| Completeness | `").append(markdown(stats.completeness())).append("` |\n")
                .append("| Chain proof completeness | `")
                .append(markdown(stats.chainProofCompleteness())).append("` |\n")
                .append("| Dynamic verification | `").append(markdown(stats.verification())).append("` |\n")
                .append("| Verification mode | `")
                .append(markdown(stats.dynamicVerification().safetyDisclosure().verificationMode()))
                .append("` |\n")
                .append("| Target code execution possible | `")
                .append(stats.dynamicVerification().safetyDisclosure().targetCodeExecutionPossible())
                .append("` |\n")
                .append("| Target code executed | `")
                .append(markdown(stats.dynamicVerification().safetyDisclosure().targetCodeExecuted()))
                .append("` |\n")
                .append("| Resource containment only | `")
                .append(stats.dynamicVerification().safetyDisclosure().resourceContainmentOnly())
                .append("` |\n")
                .append("| Filesystem isolation | `")
                .append(stats.dynamicVerification().safetyDisclosure().filesystemIsolation())
                .append("` |\n")
                .append("| Network isolation | `")
                .append(stats.dynamicVerification().safetyDisclosure().networkIsolation())
                .append("` |\n")
                .append("| Recommended for untrusted artifacts | `")
                .append(stats.dynamicVerification().safetyDisclosure().recommendedForUntrustedArtifacts())
                .append("` |\n")
                .append("| Isolation level | `")
                .append(markdown(stats.dynamicVerification().isolationLevel())).append("` |\n")
                .append("| Isolation capabilities | `")
                .append(markdown(String.join(",", stats.dynamicVerification().isolationCapabilities())))
                .append("` |\n")
                .append("| Isolation attestation | `")
                .append(markdown(stats.dynamicVerification().attestationVersion())).append("` |\n\n")
                .append("## Read first\n\n")
                .append("- [Findings overview](findings/findings.md) — grouped static findings.\n")
                .append("- [Payload review](verification/payload.md) — readable chain plans; inert and non-delivery.\n")
                .append("- [Dynamic verification](verification/dynamic-verification.json) — persistent status and evidence.\n")
                .append("- [Machine-readable payload view](verification/payload.json) — the same chain view for agents.\n\n")
                .append("- [Dependency inventory](evidence/dependencies.csv) — deterministic component identities; see `meta/dependencies.sbom.json` for CycloneDX.\n\n")
                .append("## Artifact map\n\n")
                .append("### findings/\n\n")
                .append("Static findings in CSV, SARIF, JSON, HTML, and Markdown forms.\n\n")
                .append("### verification/\n\n")
                .append("Dynamic results plus the bounded payload review. `SINK_BLOCKED` means the real prefix reached the canary boundary and the sink body was not entered; `SINK_EXECUTED_SAFE` means a Just-fixed-argument adapter call returned under an authenticated Job Object and is intentionally distorted; `JNI_EXECUTED_SAFE` is reserved for the Just-owned native fixture contract; `PRE_SINK_CONFIRMED` means a high-risk terminal was intentionally not entered; `CONCRETE_REACHED` means a concrete trigger ran without exact sink proof. Job Object provides process/resource containment only, not filesystem, network, token, or syscall isolation.\n\n")
                .append("> **Dynamic trust boundary:** `verify=auto` may load and initialize target code for a user-selected local/trusted artifact. Job Object is process/resource containment, not an OS access-control boundary, and is not recommended for untrusted JARs; use `--no-verify` for static-only analysis.\n\n")
                .append("### evidence/\n\n")
                .append("Per-hop edges, sink outcomes, calibrations, dormant-gadget evidence, and dependency inventory.\n\n")
                .append("### meta/\n\n")
                .append("Scan metadata, path-free scan identity, SBOM and the complete inert construction plan.\n")
                .append("The canonical typed finding snapshot is available at `meta/finding-output.json`;\n")
                .append("all renderers use its immutable reader tuple while v1 fields remain compatibility projections.\n")
                .append("The v1/v2 rule migration shadow is available at `meta/rules-v2-shadow.json`;\n")
                .append("each semantic difference is explicitly classified while legacy findings remain the default.\n")
                .append("The finding state migration shadow is available at `meta/finding-v2-shadow.json`;\n")
                .append("it places the legacy chain projection beside conservative typed six-axis state and never changes default findings.\n\n");

        appendVerificationSummary(markdown, stats.dynamicVerification());
        if (!stats.completenessReasons().isEmpty()) {
            markdown.append("## Completeness notes\n\n");
            for (String reason : stats.completenessReasons()) {
                markdown.append("- `").append(markdown(reason)).append("`\n");
            }
            markdown.append('\n');
        }
        AtomicFiles.writeUtf8(layout.root().resolve("index.md"), markdown.toString());
    }

    private static String timing(ScanStatistics stats, String metric) {
        return stats.metric(metric, -1L) + " ms (" + stats.metricStatus(metric) + ")";
    }

    private static String dependencySources(ScanStatistics stats) {
        List<String> values = new ArrayList<>();
        for (DependencyGraph.Source source : DependencyGraph.Source.values()) {
            String suffix = source.name().toLowerCase(java.util.Locale.ROOT);
            values.add(suffix + "=" + stats.metric("dependency_source_" + suffix, -1L));
        }
        return String.join(",", values);
    }

    private static void appendVerificationSummary(StringBuilder markdown,
                                                   VerificationSummary summary) {
        markdown.append("## Verification summary\n\n")
                .append("| Status | Count |\n|---|---:|\n");
        List<Map.Entry<String, Integer>> entries = new ArrayList<>(summary.statusCounts().entrySet());
        entries.sort(Map.Entry.comparingByKey());
        if (entries.isEmpty()) {
            markdown.append("| — | 0 |\n");
        } else {
            for (Map.Entry<String, Integer> entry : entries) {
                markdown.append("| `").append(markdown(entry.getKey())).append("` | ")
                        .append(entry.getValue()).append(" |\n");
            }
        }
        markdown.append('\n');
    }

    private static String markdown(String value) {
        return value == null ? "" : value.replace("`", "'")
                .replace("|", "\\|").replace("\r", " ").replace("\n", " ");
    }
}
