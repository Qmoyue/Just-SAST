package io.just.sast.report;

import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.HopKind;
import io.just.sast.blackboard.SinkOutcome;
import io.just.sast.chain.ChainIds;
import io.just.sast.chain.ChainPrecision;
import io.just.sast.chain.ChainRanking;
import io.just.sast.chain.ConfidenceScorer;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Optional static evidence renderer: findings.csv（一条链一行，entry → sink 顺序）
 * + edges.csv（每跳明细）+ sinks.csv（每个 sink 的裁决）
 * + calibrations.csv（静态校准拒绝的链与拒绝理由——剪枝可审计）。
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
        write(ReportLayout.flat(outDir), chains, outcomes, calibrations, chainNotes);
    }

    public void write(ReportLayout layout, List<Chain> chains, Map<Long, SinkOutcome> outcomes,
                      Map<String, String> calibrations, Map<String, List<String>> chainNotes) throws IOException {
        FindingOutputReader.Snapshot output = new FindingOutputReader().read(
                chains, calibrations, chainNotes);
        write(layout, outcomes, output, null);
    }

    /**
     * Render from a snapshot that was already frozen by the scan pipeline.  This overload keeps
     * CSV on the same reader boundary as the canonical report and avoids rebuilding all static
     * projections for each format.
     */
    public void write(ReportLayout layout, Map<Long, SinkOutcome> outcomes,
                      FindingOutputReader.Snapshot output, Map<String, Long> timings)
            throws IOException {
        if (output == null) {
            throw new IOException("finding output snapshot is null");
        }
        List<Chain> chains = output.findings().stream()
                .map(FindingOutputReader.Finding::chain).toList();
        Map<String, String> calibrations = new java.util.TreeMap<>();
        Map<String, List<String>> notes = new java.util.TreeMap<>();
        for (FindingOutputReader.Finding finding : output.findings()) {
            // An unexported typed candidate is not necessarily calibrated/rejected.  Keep the
            // calibration map keyed only by an actual non-empty reason; otherwise chains.csv
            // would mislabel every NO_APPLICATION_ENTRY/unknown-state candidate as
            // `REJECTED,` while calibrations.csv has no corresponding audit row.
            if (!finding.exported() && finding.calibration() != null
                    && !finding.calibration().isBlank()) {
                calibrations.putIfAbsent(finding.chain().key(), finding.calibration());
            }
            notes.putIfAbsent(finding.chain().key(), finding.notes());
        }
        write(layout, chains, outcomes, calibrations, notes, timings, output);
    }

    private void write(ReportLayout layout, List<Chain> chains, Map<Long, SinkOutcome> outcomes,
                       Map<String, String> calibrations, Map<String, List<String>> chainNotes,
                       Map<String, Long> timings,
                       FindingOutputReader.Snapshot output) throws IOException {
        long phaseStart = System.nanoTime();
        chains = chains == null ? List.of() : chains;
        outcomes = outcomes == null ? Map.of() : outcomes;
        calibrations = calibrations == null ? Map.of() : calibrations;
        final Map<String, List<String>> stableChainNotes = chainNotes == null ? Map.of() : chainNotes;
        if (output == null) {
            throw new IOException("finding output snapshot is null");
        }
        regions.attach(cpgGraph);
        Files.createDirectories(layout.findings());
        Files.createDirectories(layout.evidence());
        recordTiming(timings, "prepare", phaseStart);
        // 按 (entry, sink, category) 折叠：代表链取最短路径，其余计入 variant_count
        phaseStart = System.nanoTime();
        Map<String, List<Chain>> groups = new java.util.LinkedHashMap<>();
        for (Chain chain : chains) {
            if (calibrations.containsKey(chain.key())) {
                continue; // 被校准拒绝的链不进 findings（进 calibrations.csv）
            }
            FindingOutputReader.Finding canonical = output.byChainKey().get(chain.key());
            if (canonical == null || !canonical.exported()) {
                // The canonical reader deliberately keeps rejected/unanchored candidates for
                // chains.csv and calibration audit. They are not product findings: projecting
                // their application trace here would create a renderer-only orphan that cannot
                // be reconciled with an exported JOINED decision.
                continue;
            }
            // A pair (entry, sink, category) is not sufficient once the typed application
            // evidence contains multiple entry prefixes or chain paths for the same legacy
            // variant.  Folding those paths into one CSV representative would make the JSON
            // and SARIF rows impossible to trace back to this renderer.  Include a compact
            // digest of the complete typed trace plus its rendered application path so only
            // semantically identical application projections are folded.
            groups.computeIfAbsent(pairKey(chain, output), k -> new ArrayList<>()).add(chain);
        }
        for (List<Chain> group : groups.values()) {
            group.sort((left, right) -> {
                int comparison = ChainRanking.compare(left, right, stableChainNotes, Set.of());
                return comparison != 0 ? comparison : chainOrder().compare(left, right);
            });
        }
        recordTiming(timings, "group", phaseStart);
        phaseStart = System.nanoTime();
        // 高可用链置顶：置信度 → 质量（无未解析） → 链长 → 变体数
        List<List<Chain>> sortedGroups = new ArrayList<>(groups.values());
        sortedGroups.sort((a, b) -> compareGroups(a, b, stableChainNotes));
        recordTiming(timings, "sort", phaseStart);
        phaseStart = System.nanoTime();
        List<SinkOutcome> orderedOutcomes = new ArrayList<>(outcomes.values());
        orderedOutcomes.sort(Comparator.comparing(CsvReporter::sinkKey));
        List<Map.Entry<String, String>> orderedCalibrations = new ArrayList<>(calibrations.entrySet());
        orderedCalibrations.sort(Map.Entry.comparingByKey());
        Map<String, Chain> chainsByKey = new HashMap<>(Math.max(16, chains.size() * 2));
        for (Chain chain : chains) {
            chainsByKey.putIfAbsent(chain.key(), chain);
        }
        recordTiming(timings, "order", phaseStart);
        // Keep only the grouped Chain objects in memory. Rows are encoded directly into each
        // file; materializing findings + edges + every variant duplicated large strings and
        // made reporting a second memory peak after analysis had already completed.
        phaseStart = System.nanoTime();
        writeFindings(layout.findings().resolve("findings.csv"), sortedGroups, stableChainNotes,
                output);
        recordTiming(timings, "findings", phaseStart);
        phaseStart = System.nanoTime();
        writeEdges(layout.evidence().resolve("edges.csv"), sortedGroups);
        recordTiming(timings, "edges", phaseStart);
        phaseStart = System.nanoTime();
        writeChains(layout.evidence().resolve("chains.csv"), chains, calibrations, output);
        recordTiming(timings, "chains", phaseStart);
        phaseStart = System.nanoTime();
        writeSinks(layout.evidence().resolve("sinks.csv"), orderedOutcomes);
        recordTiming(timings, "sinks", phaseStart);
        phaseStart = System.nanoTime();
        writeCalibrations(layout.evidence().resolve("calibrations.csv"), chainsByKey,
                orderedCalibrations);
        recordTiming(timings, "calibrations", phaseStart);
    }

    private void writeFindings(Path file, List<List<Chain>> groups,
                               Map<String, List<String>> chainNotes,
                               FindingOutputReader.Snapshot output) throws IOException {
        writeCsv(file, FINDINGS_HEADER, writer -> {
            for (int i = 0; i < groups.size(); i++) {
                List<Chain> group = groups.get(i);
                Chain representative = group.get(0);
                List<String> groupNotes = new ArrayList<>();
                for (Chain variant : group) {
                    List<String> variantNotes = chainNotes.getOrDefault(variant.key(), List.of());
                    if (variantNotes != null) {
                        groupNotes.addAll(variantNotes);
                    }
                }
                String chainId = groupId(representative, i + 1);
                boolean groupHighConfidence = group.stream().anyMatch(variant ->
                        output.byChainKey().get(variant.key()) != null
                                ? output.byChainKey().get(variant.key()).highConfidence()
                                : ChainPrecision.isHighConfidence(variant,
                                chainNotes.getOrDefault(variant.key(), List.of())));
                writeRow(writer, findingRow(chainId, representative, group.size(),
                        Map.of(representative.key(), groupNotes), groupHighConfidence, output));
            }
        });
    }

    private void writeEdges(Path file, List<List<Chain>> groups) throws IOException {
        writeCsv(file, EDGES_HEADER, writer -> {
            for (int i = 0; i < groups.size(); i++) {
                List<Chain> group = groups.get(i);
                String chainId = groupId(group.get(0), i + 1);
                List<ChainHop> hops = group.get(0).hops();
                int step = 1;
                for (int hopIndex = hops.size() - 1; hopIndex >= 0; hopIndex--) {
                    ChainHop hop = hops.get(hopIndex);
                    if (hop.kind() == HopKind.ENTRY) {
                        continue;
                    }
                    writeRow(writer, new Row(chainId, String.valueOf(step++),
                            hop.fromOwner(), hop.fromName(), hop.toOwner(), hop.toName(),
                            edgeKind(hop.kind()), hop.field() == null ? "" : hop.field(),
                            hop.reason() == null ? "" : hop.reason()));
                }
            }
        });
    }

    private void writeChains(Path file, List<Chain> chains,
                             Map<String, String> calibrations,
                             FindingOutputReader.Snapshot output) throws IOException {
        writeCsv(file, CHAINS_HEADER, writer -> {
            for (Chain variant : chains) {
                String rejectReason = calibrations.get(variant.key());
                ApplicationTrace trace = output.applicationTrace(variant.key());
                writeRow(writer, new Row(ChainIds.id(variant.key()), variant.ruleId(),
                        variant.entryClass(), variant.entryMethod(), entryDescriptor(variant), variant.entryKind(),
                        variant.sinkClass(), variant.sinkMethod(), sinkDescriptor(variant),
                        variant.sinkRole(), variant.sinkRisk().name(),
                        rejectReason == null ? String.valueOf(regions.crossings(variant)) : "",
                        pathSummary(variant),
                        rejectReason == null ? "ACCEPTED" : "REJECTED",
                        rejectReason == null ? "" : rejectReason,
                        trace == null ? "" : trace.applicationEntryClass(),
                        trace == null ? "" : trace.applicationEntryMethod(),
                        trace == null ? "" : trace.applicationSiteClass(),
                        trace == null ? "" : trace.applicationSiteMethod(),
                        trace == null ? "" : trace.applicationSiteKind(),
                        trace == null ? "" : trace.joinKind(),
                        trace == null ? "" : trace.chainEntryMethod(),
                        trace == null ? "" : trace.entryPrefixPath(),
                        trace == null ? "" : trace.applicationPath(variant)));
            }
        });
    }

    private static void writeSinks(Path file, List<SinkOutcome> outcomes) throws IOException {
        writeCsv(file, SINKS_HEADER, writer -> {
            for (SinkOutcome outcome : outcomes) {
                writeRow(writer, new Row(outcome.ruleId(), outcome.category(),
                        outcome.sinkOwner(), outcome.sinkMethod(), outcome.enclosingClass(),
                        outcome.enclosingMethod(), outcome.verdict(),
                        String.valueOf(outcome.chainsFound()), String.valueOf(outcome.steps()),
                        String.valueOf(outcome.unresolved()), String.valueOf(outcome.tooLong())));
            }
        });
    }

    private static void writeCalibrations(Path file, Map<String, Chain> chainsByKey,
                                          List<Map.Entry<String, String>> calibrations)
            throws IOException {
        writeCsv(file, CALIBRATIONS_HEADER, writer -> {
            for (Map.Entry<String, String> calibration : calibrations) {
                String key = calibration.getKey();
                Chain chain = chainsByKey.get(key);
                writeRow(writer, new Row(
                        ChainIds.id(key),
                        chain == null ? "" : chain.ruleId(),
                        chain == null ? "" : chain.category(),
                        chain == null ? "" : chain.entryClass(),
                        chain == null ? "" : chain.entryMethod(),
                        chain == null ? "" : entryDescriptor(chain),
                        chain == null ? "" : chain.sinkClass(),
                        chain == null ? "" : chain.sinkMethod(),
                        chain == null ? "" : sinkDescriptor(chain),
                        chain == null ? "" : chain.sinkRole(),
                        chain == null ? "" : chain.sinkRisk().name(),
                        chain == null ? "" : String.valueOf(chain.hops().size()),
                        chain == null ? "" : String.valueOf(chain.unresolvedHops()),
                        ChainIds.sha256(key), calibration.getValue()));
            }
        });
    }

    private static String groupId(Chain chain, int sequence) {
        String sequenceText = Integer.toString(Math.max(0, sequence));
        String chainId = ChainIds.id(chain.key());
        StringBuilder result = new StringBuilder(chainId.length() + 5)
                .append(chainId).append('-');
        for (int i = sequenceText.length(); i < 4; i++) {
            result.append('0');
        }
        return result.append(sequenceText).toString();
    }

    private static String pairKey(Chain chain, FindingOutputReader.Snapshot output) {
        String base = chain.ruleId() + "|" + chain.entryClass() + "#" + chain.entryMethod()
                + "|" + entryDescriptor(chain) + "|"
                + chain.sinkClass() + "#" + chain.sinkMethod() + "|" + sinkDescriptor(chain)
                + "|" + chain.category() + "|" + chain.sinkRole() + "|" + chain.sinkRisk().name();
        ApplicationTrace trace = output == null ? null : output.applicationTrace(chain.key());
        if (trace == null) {
            return base + "|application-trace=NONE";
        }
        String material = String.join("\u001f",
                trace.applicationEntryClass(), trace.applicationEntryMethod(),
                trace.applicationSiteClass(), trace.applicationSiteMethod(),
                trace.applicationSiteKind(), trace.joinKind(), trace.chainEntryMethod(),
                trace.entryPrefixPath(), trace.dependencyOwner(), trace.terminalOwner(),
                trace.terminalMethod(), trace.applicationPath(chain));
        return base + "|application-trace=" + ChainIds.sha256(material);
    }

    /** 组排序：SINK_BLOCKED 链置顶 → 证据分值降序 → 链长（短优先） → 变体数（多优先）。 */
    private static int compareGroups(List<Chain> g1, List<Chain> g2,
                                     Map<String, List<String>> chainNotes) {
        Chain c1 = g1.get(0);
        Chain c2 = g2.get(0);
        int cmp = ChainRanking.compare(c1, c2, chainNotes, Set.of());
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
        return c1.key().compareTo(c2.key());
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
            + "sink_descriptor,sink_role,chain_length,unresolved_hops,variant_count,patterns,path,evidence,rank_evidence,static_evidence,"
            + "construction_status,construction_type,construction_fields,construction_trigger,construction_sink_control,"
            + "construction_reasons,precision,high_confidence,sink_risk,application_entry_class,application_entry_method,"
            + "application_site_class,application_site_method,application_site_kind,application_join_kind,"
            + "application_chain_entry_method,application_entry_prefix_path,application_path";

    private static final String EDGES_HEADER = "chain_id,step,from_class,from_method,to_class,to_method,"
            + "edge_kind,field,reason";

    private static final String SINKS_HEADER = "rule_id,category,sink_class,sink_method,"
            + "enclosing_class,enclosing_method,"
            + "verdict,chains_found,steps,unresolved,too_long";

    /** Compact rejection table; full paths live once in chains.csv keyed by variant_id. */
    private static final String CALIBRATIONS_HEADER = "variant_id,rule_id,category,entry_class,entry_method,"
            + "entry_descriptor,sink_class,sink_method,sink_descriptor,sink_role,sink_risk,chain_length,unresolved_hops,"
            + "path_digest,reject_reason";

    private static final String CHAINS_HEADER = "variant_id,rule_id,entry_class,entry_method,entry_descriptor,entry_kind,"
            + "sink_class,sink_method,sink_descriptor,sink_role,sink_risk,region_crossings,path,calibration_status,"
            + "calibration_reason,application_entry_class,application_entry_method,application_site_class,"
            + "application_site_method,application_site_kind,application_join_kind,application_chain_entry_method,"
            + "application_entry_prefix_path,application_path";

    private Row findingRow(String chainId, Chain chain, int variantCount,
                           Map<String, List<String>> chainNotes,
                           boolean highConfidence,
                           FindingOutputReader.Snapshot output) {
        List<String> notes = chainNotes.getOrDefault(chain.key(), List.of());
        if (notes == null) {
            notes = List.of();
        }
        String patterns = notes.stream()
                .filter(n -> n != null && n.startsWith("pattern:"))
                .map(n -> n.substring("pattern:".length()))
                .reduce((a, b) -> a + "|" + b)
                .orElse("");
        FindingOutputReader.Finding view = output == null ? null : output.byChainKey().get(chain.key());
        String confidence = view == null ? ConfidenceScorer.score(chain, notes)
                : view.confidence().bucket();
        ChainPrecision.Assessment precisionAssessment = view == null
                ? ChainPrecision.assess(chain, notes) : view.precision();
        String quality = "COMPLETE".equals(precisionAssessment.completeness())
                ? "COMPLETE" : "PARTIAL";
        String path = pathSummary(chain);
        String evidence = ConfidenceScorer.evidenceDecomposition(chain, notes);
        String precision = precisionAssessment.compact();
        io.just.sast.blackboard.ConstructionSummary construction = view == null
                ? ReportEvidence.construction(chain, notes) : view.construction();
        int evidenceScore = view == null ? ConfidenceScorer.evidenceScore(chain, notes)
                : view.confidence().features().totalScore();
        String rankingEvidence = view == null
                ? ChainRanking.evidence(chain, chainNotes, Set.of())
                .explanation()
                : view.ranking().explanation();
        ApplicationTrace trace = output == null ? null : output.applicationTrace(chain.key());
        return new Row(chainId, chain.ruleId(), chain.category(), chain.severity(), confidence,
                String.valueOf(evidenceScore), quality,
                chain.entryClass(), chain.entryMethod(), entryDescriptor(chain), chain.entryKind(),
                chain.sinkClass(), chain.sinkMethod(), sinkInvocationKind(chain), sinkDescriptor(chain),
                chain.sinkRole(),
                String.valueOf(chain.hops().size()), String.valueOf(chain.unresolvedHops()),
                String.valueOf(variantCount), patterns, path, evidence,
                rankingEvidence,
                staticEvidenceSummary(chain),
                construction.overallStatus(), construction.typeStatus(), construction.fieldStatus(),
                construction.triggerStatus(), construction.sinkControlStatus(),
                String.join("|", construction.reasons()),
                precision, Boolean.toString(highConfidence),
                chain.sinkRisk().name(),
                trace == null ? "" : trace.applicationEntryClass(),
                trace == null ? "" : trace.applicationEntryMethod(),
                trace == null ? "" : trace.applicationSiteClass(),
                trace == null ? "" : trace.applicationSiteMethod(),
                trace == null ? "" : trace.applicationSiteKind(),
                trace == null ? "" : trace.joinKind(),
                trace == null ? "" : trace.chainEntryMethod(),
                trace == null ? "" : trace.entryPrefixPath(),
                trace == null ? "" : trace.applicationPath(chain));
    }

    /** Compact static evidence summary used only by the optional CSV view. */
    private static String staticEvidenceSummary(Chain chain) {
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
        return "rule=" + chain.ruleId()
                + ";entry=" + chain.entryKind() + ",fields=" + fields
                + ";unresolved_hops=" + chain.unresolvedHops();
    }

    private static String sinkInvocationKind(Chain chain) {
        if (chain == null) {
            return "UNKNOWN";
        }
        for (ChainHop hop : chain.hops()) {
            if (chain.sinkClass().equals(hop.toOwner())
                    && chain.sinkMethod().equals(hop.toName())) {
                return hop.kind().name();
            }
        }
        return "UNKNOWN";
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
        List<ChainHop> hops = chain.hops();
        boolean first = true;
        for (int hopIndex = hops.size() - 1; hopIndex >= 0; hopIndex--) {
            ChainHop hop = hops.get(hopIndex);
            if (first) {
                sb.append(hop.fromOwner()).append('.').append(hop.fromName());
                first = false;
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
    private static java.io.BufferedWriter openCsv(Path file, String header) throws IOException {
        java.io.BufferedWriter writer = AtomicFiles.newUtf8Writer(file);
        writer.write('\uFEFF');
        writer.write(header);
        writer.write("\r\n");
        return writer;
    }

    @FunctionalInterface
    private interface CsvBody {
        void write(java.io.BufferedWriter writer) throws IOException;
    }

    private static void writeCsv(Path file, String header, CsvBody body) throws IOException {
        Path temp = AtomicFiles.tempSibling(file);
        boolean committed = false;
        try {
            // Close the writer before REPLACE_EXISTING. Keeping a Windows handle open across
            // the move made the findings file wait on AV/file-lock handling even when its body
            // was tiny.
            try (java.io.BufferedWriter writer = openCsv(temp, header)) {
                body.write(writer);
                writer.flush();
            }
            AtomicFiles.commit(temp, file);
            committed = true;
        } finally {
            if (!committed) {
                Files.deleteIfExists(temp);
            }
        }
    }

    private static void writeRow(java.io.BufferedWriter writer, Row row) throws IOException {
        for (int i = 0; i < row.cells().size(); i++) {
            if (i > 0) {
                writer.write(',');
            }
            writer.write(escape(row.cells().get(i)));
        }
        writer.write("\r\n");
    }

    private static String escape(String value) {
        String v = value == null ? "" : value;
        boolean needQuote = v.contains(",") || v.contains("\"") || v.contains("\n") || v.contains("\r");
        if (!needQuote) {
            return v;
        }
        return '"' + v.replace("\"", "\"\"") + '"';
    }

    private static void recordTiming(Map<String, Long> timings, String phase, long startedNanos) {
        if (timings != null && phase != null) {
            timings.put(phase, Math.max(0L,
                    java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(System.nanoTime()
                            - startedNanos)));
        }
    }
}
