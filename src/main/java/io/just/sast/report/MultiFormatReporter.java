package io.just.sast.report;

import io.just.sast.blackboard.Chain;
import io.just.sast.chain.ConfidenceScorer;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

/**
 * E1-E3: 多格式报告输出——JSON（机器消费）、HTML（可视化）、Markdown（PR comment）。
 * 与 CSV/SARIF 并行，同一数据源。
 */
public final class MultiFormatReporter {

    public void write(Path outDir, List<Chain> chains,
                      Map<String, String> calibrations, Map<String, List<String>> notes) throws IOException {
        // E1: JSON
        writeJson(outDir.resolve("findings.json"), chains, calibrations, notes);
        // E2: HTML
        writeHtml(outDir.resolve("findings.html"), chains, calibrations, notes);
        // E3: Markdown
        writeMarkdown(outDir.resolve("findings.md"), chains, calibrations, notes);
    }

    private void writeJson(Path path, List<Chain> chains,
                           Map<String, String> calibrations, Map<String, List<String>> notes) throws IOException {
        StringBuilder sb = new StringBuilder("[\n");
        boolean first = true;
        for (Chain c : chains) {
            if (calibrations.containsKey(c.key())) {
                continue;
            }
            if (!first) {
                sb.append(",\n");
            }
            first = false;
            List<String> cn = notes.getOrDefault(c.key(), List.of());
            String verify = cn.stream().filter(n -> n.startsWith("verify:"))
                    .reduce((a, b) -> b).map(n -> n.substring("verify:".length())).orElse("");
            sb.append("  {\"rule_id\":\"").append(escJson(c.ruleId()))
                    .append("\",\"category\":\"").append(escJson(c.category()))
                    .append("\",\"severity\":\"").append(escJson(c.severity()))
                    .append("\",\"confidence\":\"").append(escJson(ConfidenceScorer.score(c, cn)))
                    .append("\",\"entry_class\":\"").append(escJson(c.entryClass().replace('/', '.')))
                    .append("\",\"entry_method\":\"").append(escJson(c.entryMethod()))
                    .append("\",\"sink_class\":\"").append(escJson(c.sinkClass().replace('/', '.')))
                    .append("\",\"sink_method\":\"").append(escJson(c.sinkMethod()))
                    .append("\",\"chain_length\":").append(c.hops().size())
                    .append(",\"unresolved_hops\":").append(c.unresolvedHops())
                    .append(",\"path\":\"").append(escJson(CsvReporter.pathSummary(c)))
                    .append("\",\"verify\":\"").append(escJson(verify))
                    .append("\"}");
        }
        sb.append("\n]");
        Files.write(path, sb.toString().getBytes(StandardCharsets.UTF_8));
    }

    private void writeHtml(Path path, List<Chain> chains,
                           Map<String, String> calibrations, Map<String, List<String>> notes) throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append("<!DOCTYPE html>\n<html><head><meta charset='UTF-8'><title>Just SAST Findings</title>\n");
        sb.append("<style>body{font-family:monospace;margin:20px;background:#1e1e1e;color:#d4d4d4}");
        sb.append("table{border-collapse:collapse;width:100%}th,td{border:1px solid #444;padding:6px 10px;text-align:left}");
        sb.append("th{background:#2d2d2d}.HIGH{color:#f44747}.FEASIBLE{color:#4ec9b0}.DEGRADED{color:#cca700}");
        sb.append(".path{font-size:11px;color:#888}</style></head><body>\n");
        sb.append("<h1>Just SAST — Gadget Chain Findings</h1>\n");
        sb.append("<p>Total: ").append(chains.stream().filter(c -> !calibrations.containsKey(c.key())).count()).append(" chains</p>\n");
        sb.append("<table><tr><th>#</th><th>Rule</th><th>Confidence</th><th>Entry</th><th>Sink</th><th>Hops</th></tr>\n");
        int seq = 0;
        for (Chain c : chains) {
            if (calibrations.containsKey(c.key())) {
                continue;
            }
            seq++;
            List<String> cn = notes.getOrDefault(c.key(), List.of());
            String conf = ConfidenceScorer.score(c, cn);
            sb.append("<tr><td>").append(seq)
                    .append("</td><td>").append(escHtml(c.ruleId()))
                    .append("</td><td class='").append(conf.contains("DEGRADED") ? "DEGRADED" : "FEASIBLE").append("'>").append(conf)
                    .append("</td><td>").append(escHtml(c.entryClass().replace('/', '.'))).append(".").append(escHtml(c.entryMethod()))
                    .append("</td><td>").append(escHtml(c.sinkClass().replace('/', '.'))).append(".").append(escHtml(c.sinkMethod()))
                    .append("</td><td>").append(c.hops().size()).append("</td></tr>\n");
        }
        sb.append("</table></body></html>");
        Files.write(path, sb.toString().getBytes(StandardCharsets.UTF_8));
    }

    private void writeMarkdown(Path path, List<Chain> chains,
                               Map<String, String> calibrations, Map<String, List<String>> notes) throws IOException {
        StringBuilder sb = new StringBuilder("# Just SAST — Gadget Chain Findings\n\n");
        long count = chains.stream().filter(c -> !calibrations.containsKey(c.key())).count();
        sb.append("**Total**: ").append(count).append(" chains\n\n");
        sb.append("| # | Rule | Confidence | Entry | Sink | Hops |\n|---|---|---|---|---|---|\n");
        int seq = 0;
        for (Chain c : chains) {
            if (calibrations.containsKey(c.key())) {
                continue;
            }
            seq++;
            List<String> cn = notes.getOrDefault(c.key(), List.of());
            sb.append("| ").append(seq)
                    .append(" | `").append(escMd(c.ruleId())).append("`")
                    .append(" | ").append(escMd(ConfidenceScorer.score(c, cn)))
                    .append(" | `").append(escMd(c.entryClass().replace('/', '.'))).append(".").append(escMd(c.entryMethod())).append("`")
                    .append(" | `").append(escMd(c.sinkClass().replace('/', '.'))).append(".").append(escMd(c.sinkMethod())).append("`")
                    .append(" | ").append(c.hops().size()).append(" |\n");
        }
        Files.write(path, sb.toString().getBytes(StandardCharsets.UTF_8));
    }

    /** D4: 休眠链检测——Serializable 类有 sink 调用但不在入口闭包内（依赖变更可激活）。 */
    public void writeDormant(Path outDir, java.util.Set<String> entryReachable,
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
        Files.write(outDir.resolve("dormant.md"), sb.toString().getBytes(StandardCharsets.UTF_8));
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
