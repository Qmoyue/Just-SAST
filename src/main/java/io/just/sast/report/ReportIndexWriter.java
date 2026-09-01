package io.just.sast.report;

import io.just.sast.blackboard.VerificationSummary;

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
                .append("| Heap used | ").append(stats.heapUsedMb()).append(" MB |\n")
                .append("| Heap peak | ").append(stats.heapPeakMb()).append(" MB |\n")
                .append("| Artifact SHA-256 | `").append(markdown(stats.artifactHash())).append("` |\n")
                .append("| Completeness | `").append(markdown(stats.completeness())).append("` |\n")
                .append("| Chain proof completeness | `")
                .append(markdown(stats.chainProofCompleteness())).append("` |\n")
                .append("| Dynamic verification | `").append(markdown(stats.verification())).append("` |\n\n")
                .append("## Read first\n\n")
                .append("- [Findings overview](findings/findings.md) — grouped static findings.\n")
                .append("- [Payload review](verification/payload.md) — ysoserial-style readable chain plans; inert and safe.\n")
                .append("- [Dynamic verification](verification/dynamic-verification.json) — persistent status and evidence.\n")
                .append("- [Machine-readable payload view](verification/payload.json) — the same chain view for agents.\n\n")
                .append("## Artifact map\n\n")
                .append("### findings/\n\n")
                .append("Static findings in CSV, SARIF, JSON, HTML, and Markdown forms.\n\n")
                .append("### verification/\n\n")
                .append("Dynamic results plus the safe payload review. `SINK_BLOCKED` means the real prefix reached the canary boundary and the sink body was not entered; `CONCRETE_REACHED` means a concrete trigger ran without an exact canary.\n\n")
                .append("### evidence/\n\n")
                .append("Per-hop edges, sink outcomes, calibrations, and dormant-gadget evidence.\n\n")
                .append("### meta/\n\n")
                .append("Scan metadata and the complete inert construction plan.\n\n");

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
