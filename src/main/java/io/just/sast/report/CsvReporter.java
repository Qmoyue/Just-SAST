package io.just.sast.report;

import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.HopKind;
import io.just.sast.blackboard.SinkOutcome;
import io.just.sast.chain.ChainIds;
import io.just.sast.chain.ConfidenceScorer;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

/**
 * CSV 报告（四表）：findings.csv（一条链一行，entry → sink 顺序）+ edges.csv（每跳明细）
 * + sinks.csv（每个 sink 的裁决）+ calibrations.csv（被校准拒绝的链与拒绝理由——剪枝可审计）。
 * findings 含 patterns 列（已知 gadget 模式标注）与 evidence 因子分解串（逐项可核对计分）。
 * RFC 4180，UTF-8 with BOM（Excel 中文兼容）。
 */
public final class CsvReporter {

    private io.just.sast.cpg.graph.Graph cpgGraph;

    /** 供给 region 跨越数计算的冻结图（ScanPipeline 报告期接线）。 */
    public void withGraph(io.just.sast.cpg.graph.Graph graph) {
        this.cpgGraph = graph;
    }

    private final RegionRegions regions = new RegionRegions();

    public void write(Path outDir, List<Chain> chains, Map<Long, SinkOutcome> outcomes,
                      Map<String, String> calibrations, Map<String, List<String>> chainNotes) throws IOException {
        regions.attach(cpgGraph);
        Files.createDirectories(outDir);
        List<Row> findings = new ArrayList<>();
        List<Row> edges = new ArrayList<>();
        // 按 (entry, sink, category) 折叠：代表链取最短路径，其余计入 variant_count
        Map<String, List<Chain>> groups = new java.util.LinkedHashMap<>();
        for (Chain chain : chains) {
            if (calibrations.containsKey(chain.key())) {
                continue; // 被校准拒绝的链不进 findings（进 calibrations.csv）
            }
            groups.computeIfAbsent(pairKey(chain), k -> new ArrayList<>()).add(chain);
        }
        for (List<Chain> group : groups.values()) {
            group.sort(chainOrder());
        }
        // 高可用链置顶：置信度 → 质量（无未解析） → 链长 → 变体数
        List<List<Chain>> sortedGroups = new ArrayList<>(groups.values());
        sortedGroups.sort((a, b) -> compareGroups(a, b, chainNotes));
        int seq = 0;
        for (List<Chain> group : sortedGroups) {
            Chain representative = group.get(0);
            String chainId = ChainIds.id(representative.key()) + "-" + String.format("%04d", ++seq);
            // 收集组内全部变体的注释（verify 标注可能在非 representative 变体上）
            List<String> groupNotes = new ArrayList<>();
            for (Chain variant : group) {
                groupNotes.addAll(chainNotes.getOrDefault(variant.key(), List.of()));
            }
            findings.add(findingRow(chainId, representative, group.size(),
                    Map.of(representative.key(), groupNotes)));
            edges.addAll(edgeRows(chainId, representative));
        }
        List<Row> sinks = new ArrayList<>();
        List<SinkOutcome> orderedOutcomes = new ArrayList<>(outcomes.values());
        orderedOutcomes.sort(Comparator.comparing(CsvReporter::sinkKey));
        for (SinkOutcome outcome : orderedOutcomes) {
            sinks.add(sinkRow(outcome));
        }
        List<Row> calibrationRows = new ArrayList<>();
        List<Map.Entry<String, String>> orderedCalibrations = new ArrayList<>(calibrations.entrySet());
        orderedCalibrations.sort(Map.Entry.comparingByKey());
        for (Map.Entry<String, String> e : orderedCalibrations) {
            calibrationRows.add(new Row(e.getKey(), e.getValue()));
        }
        // chains.csv：全变体链表（同 entry/sink 折叠组内的每条路径独立成行——变体路径对分析者有价值）
        List<Row> allChains = new ArrayList<>();
        for (List<Chain> group : sortedGroups) {
            for (Chain variant : group) {
                allChains.add(new Row(ChainIds.id(variant.key()), variant.ruleId(),
                        variant.entryClass(), variant.entryMethod(), entryDescriptor(variant), variant.entryKind(),
                        variant.sinkClass(), variant.sinkMethod(), sinkDescriptor(variant),
                        String.valueOf(regions.crossings(variant)), pathSummary(variant)));
            }
        }
        writeCsv(outDir.resolve("chains.csv"), CHAINS_HEADER, allChains);
        writeCsv(outDir.resolve("findings.csv"), FINDINGS_HEADER, findings);
        writeCsv(outDir.resolve("edges.csv"), EDGES_HEADER, edges);
        writeCsv(outDir.resolve("sinks.csv"), SINKS_HEADER, sinks);
        writeCsv(outDir.resolve("calibrations.csv"), CALIBRATIONS_HEADER, calibrationRows);
    }

    /** 组内任一变体有 verify:confirmed 注释。 */
    private static boolean hasConfirmedNote(List<Chain> group, Map<String, List<String>> chainNotes) {
        for (Chain c : group) {
            List<String> notes = chainNotes.get(c.key());
            if (notes != null) {
                for (String n : notes) {
                    // 子进程确认与段归因确认（完整链的内段被子进程证实）均置顶
                    if (n.startsWith("verify:confirmed") || n.equals("verify:segment-confirmed")) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private static String pairKey(Chain chain) {
        return chain.ruleId() + "|" + chain.entryClass() + "#" + chain.entryMethod()
                + "|" + entryDescriptor(chain) + "|"
                + chain.sinkClass() + "#" + chain.sinkMethod() + "|" + sinkDescriptor(chain)
                + "|" + chain.category();
    }

    /** 组排序：CONFIRMED 链置顶 → 证据分值降序 → 链长（短优先） → 变体数（多优先）。 */
    private static int compareGroups(List<Chain> g1, List<Chain> g2,
                                     Map<String, List<String>> chainNotes) {
        Chain c1 = g1.get(0);
        Chain c2 = g2.get(0);
        // CONFIRMED 优先（子进程验证为真的链排最前）
        boolean confirmed1 = hasConfirmedNote(g1, chainNotes);
        boolean confirmed2 = hasConfirmedNote(g2, chainNotes);
        if (confirmed1 != confirmed2) {
            return confirmed1 ? -1 : 1;
        }
        int cmp = Integer.compare(ConfidenceScorer.evidenceScore(c2, null),
                ConfidenceScorer.evidenceScore(c1, null));
        if (cmp != 0) {
            return cmp;
        }
        cmp = Integer.compare(c1.hops().size(), c2.hops().size());
        if (cmp != 0) {
            return cmp;
        }
        cmp = Integer.compare(g2.size(), g1.size());
        if (cmp != 0) {
            return cmp;
        }
        return pairKey(c1).compareTo(pairKey(c2));
    }

    private static Comparator<Chain> chainOrder() {
        return Comparator.comparingInt((Chain c) -> c.hops().size()).thenComparing(Chain::key);
    }

    private static String sinkKey(SinkOutcome outcome) {
        return String.join("|", nullToEmpty(outcome.ruleId()), nullToEmpty(outcome.category()),
                nullToEmpty(outcome.sinkOwner()), nullToEmpty(outcome.sinkMethod()),
                nullToEmpty(outcome.enclosingClass()), nullToEmpty(outcome.enclosingMethod()));
    }

    private static String nullToEmpty(String value) {
        return value == null ? "" : value;
    }

    private static final String FINDINGS_HEADER = "chain_id,rule_id,category,severity,confidence,confidence_score,quality,"
            + "entry_class,entry_method,entry_descriptor,entry_kind,sink_class,sink_method,sink_kind,"
            + "sink_descriptor,chain_length,unresolved_hops,variant_count,patterns,path,evidence,verify";

    private static final String EDGES_HEADER = "chain_id,step,from_class,from_method,to_class,to_method,"
            + "edge_kind,field,reason";

    private static final String SINKS_HEADER = "rule_id,category,sink_class,sink_method,"
            + "enclosing_class,enclosing_method,"
            + "verdict,chains_found,steps,unresolved,too_long";

    private static final String CALIBRATIONS_HEADER = "chain_key,reject_reason";

    private static final String CHAINS_HEADER = "variant_id,rule_id,entry_class,entry_method,entry_descriptor,entry_kind,"
            + "sink_class,sink_method,sink_descriptor,region_crossings,path";

    private Row sinkRow(SinkOutcome outcome) {
        return new Row(outcome.ruleId(), outcome.category(),
                outcome.sinkOwner(), outcome.sinkMethod(),
                outcome.enclosingClass(), outcome.enclosingMethod(),
                outcome.verdict(), String.valueOf(outcome.chainsFound()),
                String.valueOf(outcome.steps()), String.valueOf(outcome.unresolved()),
                String.valueOf(outcome.tooLong()));
    }

    private Row findingRow(String chainId, Chain chain, int variantCount, Map<String, List<String>> chainNotes) {
        List<String> notes = chainNotes.getOrDefault(chain.key(), List.of());
        String patterns = notes.stream()
                .filter(n -> n.startsWith("pattern:"))
                .map(n -> n.substring("pattern:".length()))
                .reduce((a, b) -> a + "|" + b)
                .orElse("");
        String confidence = ConfidenceScorer.score(chain, notes);
        String quality = chain.unresolvedHops() > 0 ? "PARTIAL(unresolved=" + chain.unresolvedHops() + ")" : "COMPLETE";
        String path = pathSummary(chain);
        String evidence = ConfidenceScorer.evidenceDecomposition(chain, notes);
        return new Row(chainId, chain.ruleId(), chain.category(), chain.severity(), confidence,
                String.valueOf(ConfidenceScorer.evidenceScore(chain, notes)), quality,
                chain.entryClass(), chain.entryMethod(), entryDescriptor(chain), chain.entryKind(),
                chain.sinkClass(), chain.sinkMethod(), chain.category(), sinkDescriptor(chain),
                String.valueOf(chain.hops().size()), String.valueOf(chain.unresolvedHops()),
                String.valueOf(variantCount), patterns, path, evidence, verifySummary(chain, notes));
    }

    /** 验证候选摘要（GadgetHunter Vars/Flow/Runtime 静态子集 + 动态验证结果）。 */
    private static String verifySummary(Chain chain, List<String> notes) {
        String base = verifySummary(chain);
        if (notes == null) {
            return base;
        }
        for (String note : notes) {
            if (note.startsWith("verify:")) {
                return note.substring("verify:".length()).toUpperCase() + ";" + base;
            }
        }
        return base;
    }

    private static String verifySummary(Chain chain) {
        StringBuilder fields = new StringBuilder("[");
        for (ChainHop hop : chain.hops()) {
            if (hop.kind() == HopKind.FIELD_FLOW && hop.field() != null) {
                fields.append(hop.field()).append(',');
            }
        }
        if (fields.length() > 1) {
            fields.setLength(fields.length() - 1);
        }
        fields.append(']');
        return "vars:rule=" + chain.ruleId()
                + ";flow:entry=" + chain.entryKind() + ",fields=" + fields
                + ";runtime:unresolved=" + chain.unresolvedHops();
    }

    /** 入口方法描述符（ENTRY 跳携带；未知为空）。 */
    private static String entryDescriptor(Chain chain) {
        for (ChainHop hop : chain.hops()) {
            if (hop.kind() == HopKind.ENTRY && hop.desc() != null) {
                return hop.desc();
            }
        }
        return "";
    }

    /** sink 调用描述符（不同重载不能合并；旧构造的 Chain 仍可从 hop 回退推断）。 */
    private static String sinkDescriptor(Chain chain) {
        if (chain.sinkDescriptor() != null && !chain.sinkDescriptor().isEmpty()) {
            return chain.sinkDescriptor();
        }
        for (ChainHop hop : chain.hops()) {
            if (chain.sinkClass().equals(hop.toOwner()) && chain.sinkMethod().equals(hop.toName())
                    && hop.desc() != null && !hop.desc().isEmpty()) {
                return hop.desc();
            }
        }
        return "";
    }

    /** entry → sink 的人读顺序：反转 hops，每跳 from → to（包内共享给多格式报告）。 */
    static String pathSummary(Chain chain) {
        StringBuilder sb = new StringBuilder();
        List<ChainHop> hops = new ArrayList<>(chain.hops());
        java.util.Collections.reverse(hops);
        for (int i = 0; i < hops.size(); i++) {
            ChainHop hop = hops.get(i);
            if (i == 0) {
                sb.append(hop.fromOwner()).append('.').append(hop.fromName());
            }
            if (hop.kind() != HopKind.ENTRY && hop.kind() != HopKind.FIELD_FLOW) {
                sb.append(" -> ").append(hop.toOwner()).append('.').append(hop.toName());
            } else if (hop.kind() == HopKind.FIELD_FLOW) {
                sb.append(" --[").append(hop.field()).append("]--> ")
                        .append(hop.toOwner()).append('.').append(hop.toName());
            }
        }
        return sb.toString();
    }

    private List<Row> edgeRows(String chainId, Chain chain) {
        List<Row> rows = new ArrayList<>();
        List<ChainHop> hops = new ArrayList<>(chain.hops());
        java.util.Collections.reverse(hops);
        int step = 1;
        for (ChainHop hop : hops) {
            if (hop.kind() == HopKind.ENTRY) {
                continue;
            }
            rows.add(new Row(chainId, String.valueOf(step++),
                    hop.fromOwner(), hop.fromName(), hop.toOwner(), hop.toName(),
                    edgeKind(hop.kind()), hop.field() == null ? "" : hop.field(),
                    hop.reason() == null ? "" : hop.reason()));
        }
        return rows;
    }

    private static String edgeKind(HopKind kind) {
        return switch (kind) {
            case DIRECT_CALL -> "DIRECT_CALL";
            case VIRTUAL_DISPATCH -> "VIRTUAL_DISPATCH";
            case LAMBDA -> "LAMBDA";
            case NATIVE_CALLBACK -> "NATIVE_CALLBACK";
            case FIELD_FLOW -> "FIELD_FLOW";
            case ENTRY -> "ENTRY";
        };
    }

    /** region 跨越数（惰性 RegionMap，链上相邻跳的 region 切换计数）。
     * 实例字段（历史缺陷：static map 跨扫描复用旧图，同 JVM 二扫的 region_crossings 失真）。 */
    static final class RegionRegions {
        private io.just.sast.analysis.taint.RegionMap map;

        void attach(io.just.sast.cpg.graph.Graph graph) {
            // Reporter 可在同一 JVM 中复用；每次写出都必须绑定当前图，不能沿用上次扫描的 region。
            map = graph == null ? null : new io.just.sast.analysis.taint.RegionMap(graph);
        }

        int crossings(Chain chain) {
            if (map == null) {
                return 0;
            }
            String prev = null;
            int crossings = 0;
            for (ChainHop hop : chain.hops()) {
                String from = hop.fromOwner() + "#" + hop.fromName();
                String to = hop.toOwner() + "#" + hop.toName();
                if (prev != null && !map.sameRegion(prev, from)) {
                    crossings++;
                }
                if (!map.sameRegion(from, to)) {
                    crossings++;
                }
                prev = to;
            }
            return crossings;
        }
    }

    private record Row(List<String> cells) {
        Row(String... values) {
            this(List.of(values));
        }
    }

    /** 流式写出（大语料 10 万+ 链不能整表拼 String——堆峰值会翻倍）。 */
    private static void writeCsv(Path file, String header, List<Row> rows) throws IOException {
        try (java.io.BufferedWriter w = Files.newBufferedWriter(file, StandardCharsets.UTF_8)) {
            w.write('\uFEFF');
            w.write(header);
            w.write("\r\n");
            for (Row row : rows) {
                for (int i = 0; i < row.cells().size(); i++) {
                    if (i > 0) {
                        w.write(',');
                    }
                    w.write(escape(row.cells().get(i)));
                }
                w.write("\r\n");
            }
        }
    }

    private static String escape(String value) {
        String v = value == null ? "" : value;
        boolean needQuote = v.contains(",") || v.contains("\"") || v.contains("\n") || v.contains("\r");
        if (!needQuote) {
            return v;
        }
        return '"' + v.replace("\"", "\"\"") + '"';
    }
}
