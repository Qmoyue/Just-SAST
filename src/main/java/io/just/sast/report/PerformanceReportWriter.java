package io.just.sast.report;

import io.just.sast.perf.PerformanceGate;
import io.just.sast.perf.PerformanceHarness;

import java.io.IOException;
import java.nio.file.Path;

/**
 * Stable, path-free JSON projection for the opt-in performance runner.
 *
 * <p>The scan report already owns the detailed phase telemetry.  This artifact only contains
 * the repeated-run contract, so it can be compared by a fixed CI runner without leaking input
 * paths or depending on a JSON library in the hot scan path.</p>
 */
public final class PerformanceReportWriter {

    private PerformanceReportWriter() {
    }

    public static String json(PerformanceHarness.Report report, String mode) {
        if (report == null) {
            throw new IllegalArgumentException("performance report is null");
        }
        StringBuilder out = new StringBuilder(2048);
        out.append("{\n")
                .append("  \"schema_version\":1,\n")
                .append("  \"mode\":\"").append(escape(mode)).append("\",\n")
                .append("  \"warmups\":").append(report.warmups()).append(",\n")
                .append("  \"sample_count\":").append(report.samples().size()).append(",\n")
                .append("  \"gate_passed\":").append(report.passed()).append(",\n")
                .append("  \"chain_count_stable\":").append(report.chainCountStable()).append(",\n")
                .append("  \"completeness_stable\":").append(report.completenessStable()).append(",\n")
                .append("  \"result_digest_stable\":").append(report.resultDigestStable()).append(",\n")
                .append("  \"peak_heap_mb\":").append(report.peakHeapMb()).append(",\n")
                .append("  \"peak_rss_mb\":").append(report.peakRssMb()).append(",\n")
                .append("  \"wall\":");
        appendGate(out, report.wall());
        out.append(",\n  \"static\":");
        appendGate(out, report.staticPhase());
        out.append(",\n  \"dynamic\":");
        appendGate(out, report.dynamicPhase());
        out.append(",\n  \"samples\":[\n");
        for (int i = 0; i < report.samples().size(); i++) {
            if (i > 0) {
                out.append(",\n");
            }
            PerformanceHarness.Sample sample = report.samples().get(i);
            out.append("    {\"iteration\":").append(sample.iteration())
                    .append(",\"wall_ms\":").append(sample.wallMs())
                    .append(",\"static_ms\":").append(sample.staticMs())
                    .append(",\"dynamic_ms\":").append(sample.dynamicMs())
                    .append(",\"heap_used_mb\":").append(sample.heapUsedMb())
                    .append(",\"heap_peak_mb\":").append(sample.heapPeakMb())
                    .append(",\"rss_peak_mb\":").append(sample.rssPeakMb())
                    .append(",\"chains_found\":").append(sample.chainsFound())
                    .append(",\"completeness\":\"").append(escape(sample.completeness()))
                    .append("\",\"result_digest\":\"")
                    .append(escape(sample.resultDigest())).append("\"}");
        }
        out.append("\n  ]\n}\n");
        return out.toString();
    }

    public static void write(Path target, PerformanceHarness.Report report, String mode)
            throws IOException {
        if (target == null) {
            throw new IOException("performance report target is null");
        }
        AtomicFiles.writeUtf8(target, json(report, mode));
    }

    private static void appendGate(StringBuilder out, PerformanceGate.Result result) {
        if (result == null) {
            out.append("null");
            return;
        }
        out.append('{')
                .append("\"samples\":").append(result.samples())
                .append(",\"p50_ms\":").append(result.p50Ms())
                .append(",\"p95_ms\":").append(result.p95Ms())
                .append(",\"p50_limit_ms\":");
        appendLimit(out, result.p50LimitMs());
        out.append(",\"p95_limit_ms\":");
        appendLimit(out, result.p95LimitMs());
        out.append(",\"passed\":").append(result.passed()).append('}');
    }

    private static void appendLimit(StringBuilder out, long limit) {
        if (limit == Long.MAX_VALUE) {
            out.append("null");
        } else {
            out.append(limit);
        }
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
                        out.append(String.format("\\u%04x", (int) ch));
                    } else {
                        out.append(ch);
                    }
                }
            }
        }
        return out.toString();
    }
}
