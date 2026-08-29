package io.just.sast.report;

import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.VerificationSummary;
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

/**
 * E1-E3: 多格式报告输出——JSON（机器消费）、HTML（可视化）、Markdown（PR comment）。
 * 与 CSV/SARIF 并行，同一数据源。
 */
public final class MultiFormatReporter {

    public void write(Path outDir, List<Chain> chains,
                      Map<String, String> calibrations, Map<String, List<String>> notes) throws IOException {
        write(ReportLayout.flat(outDir), chains, calibrations, notes);
    }

    public void write(ReportLayout layout, List<Chain> chains,
                      Map<String, String> calibrations, Map<String, List<String>> notes) throws IOException {
        Files.createDirectories(layout.findings());
        List<Chain> orderedChains = new ArrayList<>(chains);
        orderedChains.sort(Comparator.comparing(Chain::key));
        // E1: JSON
        writeJson(layout.findings().resolve("findings.json"), orderedChains, calibrations, notes);
        // E2: HTML
        writeHtml(layout.findings().resolve("findings.html"), orderedChains, calibrations, notes);
        // E3: Markdown
        writeMarkdown(layout.findings().resolve("findings.md"), orderedChains, calibrations, notes);
    }

    /** 扫描元数据旁车文件：不破坏 findings.json 数组契约，同时公开完整性和性能边界。 */
    public void writeMetadata(Path outDir, ScanStatistics stats) throws IOException {
        writeMetadata(ReportLayout.flat(outDir), stats);
    }

    public void writeMetadata(ReportLayout layout, ScanStatistics stats) throws IOException {
        Files.createDirectories(layout.meta());
        Files.createDirectories(layout.verification());
        StringBuilder sb = new StringBuilder("{\n")
                .append("  \"schema_version\":1,")
                .append("\n")
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
        sb.append("},\"dynamic_verification\":");
        appendVerificationJson(sb, stats.dynamicVerification());
        sb.append("\n}\n");
        Files.write(layout.meta().resolve("scan-metadata.json"),
                sb.toString().getBytes(StandardCharsets.UTF_8));
        StringBuilder dynamic = new StringBuilder();
        appendVerificationJson(dynamic, stats.dynamicVerification());
        dynamic.append('\n');
        Files.write(layout.verification().resolve("dynamic-verification.json"),
                dynamic.toString().getBytes(StandardCharsets.UTF_8));
    }

    private static void appendVerificationJson(StringBuilder sb, VerificationSummary summary) {
        sb.append('{')
                .append("\"schema_version\":1,")
                .append("\"capability\":\"").append(escJson(summary.capability())).append("\"")
                .append(",\"budget\":").append(summary.budget())
                .append(",\"constructible\":").append(summary.constructible())
                .append(",\"rejected\":").append(summary.rejected())
                .append(",\"selected\":").append(summary.selected())
                .append(",\"status_counts\":");
        appendCounts(sb, summary.statusCounts());
        sb.append(",\"detail_counts\":");
        appendCounts(sb, summary.detailCounts());
        sb.append(",\"results\":[");
        for (int i = 0; i < summary.results().size(); i++) {
            if (i > 0) {
                sb.append(',');
            }
            VerificationSummary.ChainResult result = summary.results().get(i);
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
                    .append('}');
        }
        sb.append("]}");
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
                           Map<String, String> calibrations, Map<String, List<String>> notes) throws IOException {
        try (BufferedWriter writer = Files.newBufferedWriter(path, StandardCharsets.UTF_8)) {
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
                String verify = cn.stream().filter(n -> n.startsWith("verify:"))
                        .reduce((a, b) -> b).map(n -> n.substring("verify:".length())).orElse("");
                writer.append("  {\"rule_id\":\"").append(escJson(c.ruleId()))
                        .append("\",\"category\":\"").append(escJson(c.category()))
                        .append("\",\"severity\":\"").append(escJson(c.severity()))
                        .append("\",\"confidence\":\"").append(escJson(ConfidenceScorer.score(c, cn)))
                        .append("\",\"entry_class\":\"").append(escJson(c.entryClass().replace('/', '.')))
                        .append("\",\"entry_method\":\"").append(escJson(c.entryMethod()))
                        .append("\",\"sink_class\":\"").append(escJson(c.sinkClass().replace('/', '.')))
                        .append("\",\"sink_method\":\"").append(escJson(c.sinkMethod()))
                        .append("\",\"sink_descriptor\":\"").append(escJson(c.sinkDescriptor()))
                        .append("\",\"chain_length\":").append(Integer.toString(c.hops().size()))
                        .append(",\"unresolved_hops\":").append(Integer.toString(c.unresolvedHops()))
                        .append(",\"path\":\"").append(escJson(CsvReporter.pathSummary(c)))
                        .append("\",\"verify\":\"").append(escJson(verify))
                        .append("\"}");
            }
            writer.write("\n]");
        }
    }

    private void writeHtml(Path path, List<Chain> chains,
                           Map<String, String> calibrations, Map<String, List<String>> notes) throws IOException {
        try (BufferedWriter writer = Files.newBufferedWriter(path, StandardCharsets.UTF_8)) {
            writer.write("<!DOCTYPE html>\n<html><head><meta charset='UTF-8'><title>Just SAST Findings</title>\n");
            writer.write("<style>body{font-family:monospace;margin:20px;background:#1e1e1e;color:#d4d4d4}");
            writer.write("table{border-collapse:collapse;width:100%}th,td{border:1px solid #444;padding:6px 10px;text-align:left}");
            writer.write("th{background:#2d2d2d}.HIGH{color:#f44747}.FEASIBLE{color:#4ec9b0}.DEGRADED{color:#cca700}");
            writer.write(".path{font-size:11px;color:#888}</style></head><body>\n");
            writer.write("<h1>Just SAST — Gadget Chain Findings</h1>\n");
            writer.append("<p>Total: ").append(Long.toString(chains.stream()
                    .filter(c -> !calibrations.containsKey(c.key())).count())).append(" chains</p>\n");
            writer.write("<table><tr><th>#</th><th>Rule</th><th>Confidence</th><th>Entry</th><th>Sink</th><th>Hops</th></tr>\n");
            int seq = 0;
            for (Chain c : chains) {
                if (calibrations.containsKey(c.key())) {
                    continue;
                }
                seq++;
                List<String> cn = notes.getOrDefault(c.key(), List.of());
                String conf = ConfidenceScorer.score(c, cn);
                writer.append("<tr><td>").append(Integer.toString(seq))
                        .append("</td><td>").append(escHtml(c.ruleId()))
                        .append("</td><td class='").append(conf.contains("DEGRADED") ? "DEGRADED" : "FEASIBLE").append("'>").append(conf)
                        .append("</td><td>").append(escHtml(c.entryClass().replace('/', '.'))).append(".").append(escHtml(c.entryMethod()))
                        .append("</td><td>").append(escHtml(c.sinkClass().replace('/', '.'))).append(".").append(escHtml(c.sinkMethod()))
                        .append("</td><td>").append(Integer.toString(c.hops().size())).append("</td></tr>\n");
            }
            writer.write("</table></body></html>");
        }
    }

    private void writeMarkdown(Path path, List<Chain> chains,
                               Map<String, String> calibrations, Map<String, List<String>> notes) throws IOException {
        try (BufferedWriter writer = Files.newBufferedWriter(path, StandardCharsets.UTF_8)) {
            writer.write("# Just SAST — Gadget Chain Findings\n\n");
            long count = chains.stream().filter(c -> !calibrations.containsKey(c.key())).count();
            writer.append("**Total**: ").append(Long.toString(count)).append(" chains\n\n");
            writer.write("| # | Rule | Confidence | Entry | Sink | Hops |\n|---|---|---|---|---|---|\n");
            int seq = 0;
            for (Chain c : chains) {
                if (calibrations.containsKey(c.key())) {
                    continue;
                }
                seq++;
                List<String> cn = notes.getOrDefault(c.key(), List.of());
                writer.append("| ").append(Integer.toString(seq))
                        .append(" | `").append(escMd(c.ruleId())).append("`")
                        .append(" | ").append(escMd(ConfidenceScorer.score(c, cn)))
                        .append(" | `").append(escMd(c.entryClass().replace('/', '.'))).append(".").append(escMd(c.entryMethod())).append("`")
                        .append(" | `").append(escMd(c.sinkClass().replace('/', '.'))).append(".").append(escMd(c.sinkMethod())).append("`")
                        .append(" | ").append(Integer.toString(c.hops().size())).append(" |\n");
            }
        }
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
        Files.write(layout.evidence().resolve("dormant.md"),
                sb.toString().getBytes(StandardCharsets.UTF_8));
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
}
