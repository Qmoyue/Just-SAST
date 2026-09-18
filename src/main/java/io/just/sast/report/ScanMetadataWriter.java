package io.just.sast.report;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

/** Writes the internal static-scan metadata files owned by the report transaction. */
public final class ScanMetadataWriter {

    public void write(Path outDir, ScanStatistics stats) throws IOException {
        write(ReportLayout.flat(outDir), stats);
    }

    public void write(ReportLayout layout, ScanStatistics stats) throws IOException {
        if (layout == null || stats == null) {
            throw new IOException("scan metadata inputs are missing");
        }
        Files.createDirectories(layout.meta());
        StringBuilder out = new StringBuilder("{\n")
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
        appendStrings(out, stats.completenessReasons());
        out.append(",\"phase_ms\":");
        appendLongMap(out, stats.phaseMs());
        out.append(",\"metrics\":");
        appendLongMap(out, stats.metrics());
        out.append(",\"metric_status\":");
        appendStringMap(out, stats.metricStatus());
        out.append(",\"metric_namespaces\":");
        appendNestedLongMap(out, stats.metricNamespaces());
        out.append(",\"metric_namespace_status\":");
        appendStringMap(out, stats.metricNamespaceStatus());
        out.append(",\"filter_evidence\":");
        out.append(ReportEvidence.filterEvidenceJson(stats.filterEvidence()));
        out.append("\n}\n");
        AtomicFiles.writeUtf8(layout.meta().resolve("scan-metadata.json"), out.toString());
        AtomicFiles.writeUtf8(layout.meta().resolve("run.json"),
                "{\"schema_version\":1,\"kind\":\"just-run\",\"run_outcome\":"
                        + stats.runOutcome().toCanonicalJson() + "}\n");
    }

    private static void appendLongMap(StringBuilder out, Map<String, Long> values) {
        out.append('{');
        int index = 0;
        for (Map.Entry<String, Long> entry : values.entrySet()) {
            if (index++ > 0) {
                out.append(',');
            }
            out.append(quote(entry.getKey())).append(':').append(entry.getValue());
        }
        out.append('}');
    }

    private static void appendStringMap(StringBuilder out, Map<String, String> values) {
        out.append('{');
        int index = 0;
        for (Map.Entry<String, String> entry : values.entrySet()) {
            if (index++ > 0) {
                out.append(',');
            }
            out.append(quote(entry.getKey())).append(':').append(quote(entry.getValue()));
        }
        out.append('}');
    }

    private static void appendNestedLongMap(StringBuilder out,
                                             Map<String, Map<String, Long>> values) {
        out.append('{');
        int index = 0;
        for (Map.Entry<String, Map<String, Long>> entry : values.entrySet()) {
            if (index++ > 0) {
                out.append(',');
            }
            out.append(quote(entry.getKey())).append(':');
            appendLongMap(out, entry.getValue());
        }
        out.append('}');
    }

    private static void appendStrings(StringBuilder out, java.util.List<String> values) {
        out.append('[');
        for (int i = 0; i < values.size(); i++) {
            if (i > 0) {
                out.append(',');
            }
            out.append(quote(values.get(i)));
        }
        out.append(']');
    }

    private static String quote(String value) {
        return '"' + escape(value) + '"';
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
                        out.append(String.format(java.util.Locale.ROOT, "\\u%04x", (int) ch));
                    } else {
                        out.append(ch);
                    }
                }
            }
        }
        return out.toString();
    }
}
