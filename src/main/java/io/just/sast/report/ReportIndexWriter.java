package io.just.sast.report;

import io.just.sast.model.DependencyGraph;

import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

/** Writes the single human entry point for a classified static scan. */
public final class ReportIndexWriter {

    public void write(ReportLayout layout, ScanStatistics stats) throws IOException {
        Files.createDirectories(layout.root());
        StringBuilder markdown = new StringBuilder("# Just scan report\n\n")
                .append("> One reading entry for this static scan. Canonical reports and provenance are grouped by purpose.\n\n")
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
                .append("| Filter evidence rows | ").append(stats.filterEvidence().size()).append(" |\n")
                .append("| Dependency sources | `")
                .append(markdown(dependencySources(stats))).append("` |\n")
                .append("| Heap used | ").append(stats.heapUsedMb()).append(" MB |\n")
                .append("| Heap peak | ").append(stats.heapPeakMb()).append(" MB |\n")
                .append("| Artifact SHA-256 | `").append(markdown(stats.artifactHash())).append("` |\n")
                .append("| Completeness | `").append(markdown(stats.completeness())).append("` |\n")
                .append("| Chain proof completeness | `")
                .append(markdown(stats.chainProofCompleteness())).append("` |\n\n")
                .append("## Read first\n\n")
                .append("- [Concise JSON](report.json) — canonical summary and static chain evidence.\n")
                .append("- [Concise Markdown](report.md) — the same snapshot for human review.\n")
                .append("- [Finding output](meta/finding-output.json) — immutable typed finding snapshot.\n")
                .append("- [Input digest](meta/input-digest.json) — analyzed input identity.\n")
                .append("- [Dependency inventory](evidence/dependencies.csv) — deterministic component identities.\n\n")
                .append("## Artifact map\n\n")
                .append("### evidence/\n\n")
                .append("Per-hop edges, sink outcomes, application evidence, and dependency inventory.\n\n")
                .append("### meta/\n\n")
                .append("Scan metadata, path-free scan identity, input digest, and the canonical finding snapshot.\n\n")
                .append("All report views are static analysis. Unknown, incomplete, and budget-limited conditions remain visible; an empty result is not proof that the artifact is safe.\n");

        if (!stats.completenessReasons().isEmpty()) {
            markdown.append("\n## Completeness notes\n\n");
            for (String reason : stats.completenessReasons()) {
                markdown.append("- `").append(markdown(reason)).append("`\n");
            }
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

    private static String markdown(String value) {
        return value == null ? "" : value.replace("`", "'")
                .replace("|", "\\|").replace("\r", " ").replace("\n", " ");
    }
}
