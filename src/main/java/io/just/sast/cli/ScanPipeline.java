package io.just.sast.cli;

import io.just.sast.analysis.callgraph.CallGraphBuilder;
import io.just.sast.analysis.hierarchy.ClassHierarchy;
import io.just.sast.blackboard.Blackboard;
import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.Controller;
import io.just.sast.config.RuleSet;
import io.just.sast.config.Rule;
import io.just.sast.config.YamlRuleLoader;
import io.just.sast.cpg.build.BuiltCpg;
import io.just.sast.cpg.build.CpgBuilder;
import io.just.sast.cpg.graph.Node;
import io.just.sast.cpg.graph.NodeType;
import io.just.sast.frontend.asm.BytecodeFrontend;
import io.just.sast.frontend.asm.ClassBytes;
import io.just.sast.frontend.asm.JrtClassSource;
import io.just.sast.frontend.asm.JdkClassSelector;
import io.just.sast.frontend.asm.TargetJdkSource;
import io.just.sast.model.JdkClassSource;
import io.just.sast.model.LoadResult;
import io.just.sast.report.ConsoleSummary;
import io.just.sast.report.CsvReporter;
import io.just.sast.report.ReportIndexWriter;
import io.just.sast.report.ReportLayout;
import io.just.sast.report.ScanStatistics;
import io.just.sast.util.ArchiveLimits;
import io.just.sast.util.ArtifactFingerprint;
import io.just.sast.util.JustLogger;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

/** 扫描管线编排：frontend → 层次 → CPG/调用图（构建后冻结）→ 黑板（串行三阶段）→ CSV。 */
public final class ScanPipeline {

    /** 反向回溯递归深度上限（内部固定，不暴露参数）。覆盖 ~8 层链（再深需按链一致性做精度门，见 development.md）。 */
    private static final int MAX_DEPTH = 64;

    private ScanPipeline() {}

    public static final class UsageException extends Exception {
        public UsageException(String message) {
            super(message);
        }
    }

    /** 扫描结果。 */
    public record ScanResult(int exitCode, List<Chain> chains, ScanStatistics stats) {}

    public static ScanResult run(Path target, List<Path> deps, Path output, Path rules,
        boolean stats, boolean fast, Path jdkHome, boolean verify,
                                 int verifyBudget) throws Exception {
        return run(target, deps, output, rules, stats, fast, jdkHome, verify,
                verifyBudget, false, verify, false, null, null);
    }

    public static ScanResult run(Path target, List<Path> deps, Path output, Path rules,
        boolean stats, boolean fast, Path jdkHome, boolean verify,
                                 int verifyBudget, boolean safeExec) throws Exception {
        return run(target, deps, output, rules, stats, fast, jdkHome, verify,
                verifyBudget, safeExec, verify && !safeExec, false, null, null);
    }

    public static ScanResult run(Path target, List<Path> deps, Path output, Path rules,
        boolean stats, boolean fast, Path jdkHome, boolean verify,
                                 int verifyBudget, boolean safeExec,
                                 boolean requireOsIsolation) throws Exception {
        return run(target, deps, output, rules, stats, fast, jdkHome, verify,
                verifyBudget, safeExec, verify && !safeExec, requireOsIsolation, null, null);
    }

    public static ScanResult run(Path target, List<Path> deps, Path output, Path rules,
        boolean stats, boolean fast, Path jdkHome, boolean verify,
                                 int verifyBudget, boolean safeExec,
                                 boolean requireOsIsolation, Path baseline,
                                 Path suppressions) throws Exception {
        return run(target, deps, output, rules, stats, fast, jdkHome, verify, verifyBudget,
                safeExec, verify && !safeExec, requireOsIsolation, baseline, suppressions);
    }

    /** Full pipeline entry point with an explicit adapter-owned SAFE_REAL mode. */
    public static ScanResult run(Path target, List<Path> deps, Path output, Path rules,
        boolean stats, boolean fast, Path jdkHome, boolean verify,
                                 int verifyBudget, boolean safeExec, boolean safeReal,
                                 boolean requireOsIsolation, Path baseline,
                                 Path suppressions) throws Exception {
        long start = System.nanoTime();
        long parentCpuStarted = processCpuTimeMs();
        Map<String, Long> phaseMs = new java.util.LinkedHashMap<>();
        resetHeapPeaks();

        validatePath(target, "扫描目标", true);
        if (deps != null) {
            for (Path dep : deps) {
                validatePath(dep, "依赖", true);
            }
        }
        if (rules != null) {
            validatePath(rules, "规则", false);
        }
        if (output == null) {
            throw new UsageException("输出目录不能为空");
        }
        if (Files.exists(output) && ArchiveLimits.isLinkOrReparsePoint(output)) {
            throw new UsageException("输出路径不能是符号链接或 reparse point: "
                    + output.toAbsolutePath());
        }
        if (Files.exists(output) && !Files.isDirectory(output)) {
            throw new UsageException("输出路径不是目录: " + output.toAbsolutePath());
        }
        if (baseline != null) {
            validatePath(baseline, "baseline", true);
            if (output.toAbsolutePath().normalize().equals(baseline.toAbsolutePath().normalize())) {
                throw new UsageException("baseline 不能与当前输出目录相同");
            }
        }
        if (suppressions != null) {
            validatePath(suppressions, "suppression 文件", false);
        }
        if (verifyBudget < 0) {
            throw new UsageException("--verify-budget 不能为负数");
        }
        if (safeExec && !verify) {
            throw new UsageException("--safe-exec 需要启用动态验证（不能与 --no-verify 同时使用）");
        }
        if (safeReal && !verify) {
            throw new UsageException("--safe-real-sink 需要启用动态验证（不能与 --no-verify 同时使用）");
        }
        if (safeExec && safeReal) {
            throw new UsageException("--safe-exec 与 --safe-real-sink 不能同时使用");
        }
        if (requireOsIsolation && !verify) {
            throw new UsageException("--require-os-isolation 需要启用动态验证（不能与 --no-verify 同时使用）");
        }

        if (verify) {
            io.just.sast.verify.OsIsolation.prewarmJobObject();
        }

        // Hash immutable inputs once at the scan boundary. Besides making report identity
        // available to the cache layer before frontend parsing, reusing these values avoids a
        // second full read of a large target/dependency archive during report generation.
        List<Path> scanDeps = deps == null ? List.of() : List.copyOf(deps);
        String targetArtifactHash = artifactHash(target);
        List<String> dependencyHashes = io.just.sast.report.ScanCache.dependencyHashes(scanDeps);
        String dependencyIdentity = io.just.sast.report.ScanCache
                .dependencyIdentityFromHashes(dependencyHashes);

        // 规则
        RuleSet ruleSet;
        try {
            ruleSet = loadRules(rules);
        } catch (IOException e) {
            throw new UsageException("规则加载失败: " + e.getMessage());
        }

        // 输入目标
        List<Path> targets = new ArrayList<>();
        targets.add(target);
        if (deps != null) {
            targets.addAll(deps);
        }

        // 构建期：JDK 类来源（--jdk-home 指定目标版本——Java 9+ 真挂载目标镜像，否则用运行时 jrt）
        long frontendStart = System.nanoTime();
        JdkClassSource jdkSource;
        if (jdkHome != null) {
            TargetJdkSource targetJdk;
            try {
                targetJdk = new TargetJdkSource(jdkHome);
            } catch (IOException e) {
                throw new UsageException("--jdk-home 加载失败: " + e.getMessage());
            }
            jdkSource = targetJdk;
            JustLogger.info("使用目标 JDK：{}（--jdk-home={}）", targetJdk.description(), jdkHome);
        } else {
            JrtClassSource jrt = JrtClassSource.runtime();
            jdkSource = jrt;
        }
        try {
        BytecodeFrontend frontend = new BytecodeFrontend();
        // 先解析 target/deps；完整模式随后只把应用引用、规则类型和 magic-entry 方法
        // 所需的 JDK 类体放进 CPG，避免对同一批应用字节重复读取/解析。
        // 把原始 ClassBytes 限制在独立 helper 的生命周期内。完整扫描需要的只是
        // ClassInfo；否则 JDK 切片规划期间 input 仍会把整批 fat-jar byte[] 挂住。
        int targetFeature = jdkFeature(jdkSource);
        LoadResult applicationLoad = loadApplication(frontend, targets, targetFeature);
        LoadResult load;
        if (fast) {
            load = applicationLoad;
        } else {
            load = loadWithJdkSlice(frontend, applicationLoad, jdkSource, ruleSet);
        }
        JustLogger.info("解析完成：{} 个类（{} 个文件），诊断 {} 条",
                load.classCount(), load.filesScanned(), load.diagnosticCount());
        if (load.targetMajorVersion() > 0) {
            String targetJdk = jdkVersionOf(load.targetMajorVersion());
            String runtimeJdk = System.getProperty("java.version", "?");
            JustLogger.info("目标 JDK：{}（major={}），运行时 JDK：{}", targetJdk, load.targetMajorVersion(), runtimeJdk);
            if (jdkHome == null && load.targetMajorVersion() < 61 && !runtimeJdk.startsWith("1.8")) {
                JustLogger.warn("目标编译版本低于运行时 JDK——建议用 --jdk-home 指定目标版本（当前用运行时库，假阳风险）");
            }
        }
        phaseMs.put("frontend", elapsedMs(frontendStart));

        long cpgStart = System.nanoTime();
        ClassHierarchy hierarchy = new ClassHierarchy(load.classes(), jdkSource);
        BuiltCpg cpg = new CpgBuilder().build(load);
        int callEdges = new CallGraphBuilder(hierarchy).build(cpg.graph());
        cpg.graph().freeze();
        JustLogger.info("CPG 构建完成：节点 {}，边 {}，调用边 {}，字段写入 {} 组",
                cpg.graph().nodeCount(), cpg.graph().edgeCount(), callEdges,
                cpg.fieldWriters().fieldCount());
        phaseMs.put("cpg", elapsedMs(cpgStart));

        // 分析期（黑板串行三阶段：ANALYSIS → COMPOSITION → CALIBRATION）
        long analysisStart = System.nanoTime();
        Blackboard blackboard = new Blackboard(cpg.graph(), hierarchy, cpg.fieldWriters(), cpg.index(), ruleSet, MAX_DEPTH,
                new Blackboard.ScanInputs(target.toAbsolutePath().normalize(), scanDeps, fast, verify,
                        verifyBudget, jdkHome, load.targetMajorVersion(), safeExec, safeReal,
                        requireOsIsolation));
        new Controller(blackboard, KnowledgeSources.discover()).run();
        for (Map.Entry<String, Long> timing : blackboard.phaseMs().entrySet()) {
            phaseMs.put(timing.getKey(), timing.getValue());
        }
        phaseMs.put("analysis", elapsedMs(analysisStart));
        // Publish a non-overlapping static phase for the performance harness.  The aggregate
        // analysis timer includes calibration, while the verifier publishes its own child
        // process duration; subtracting that one explicit interval avoids charging dynamic
        // process startup to static p50/p95 and keeps the default scan on a single pass.
        long preReportMs = elapsedMs(start);
        long dynamicMs = phaseMs.getOrDefault("verify", 0L);
        phaseMs.put("static", Math.max(0L, preReportMs - dynamicMs));

        // 报告期
        long reportStart = System.nanoTime();
        ReportLayout reportLayout = ReportLayout.create(output);
        // Freeze the blackboard views once at the report boundary.  Each reporter previously
        // requested fresh defensive copies of chains/calibrations/outcomes and rebuilt the
        // chain-note map independently.  On a large closure that turned reporting into a
        // repeated synchronization/copy pass without changing any emitted byte.
        List<Chain> reportChains = blackboard.chains();
        Map<Long, io.just.sast.blackboard.SinkOutcome> reportOutcomes = blackboard.sinkOutcomes();
        Map<String, String> reportCalibrations = blackboard.chainCalibrations();
        Map<String, List<String>> reportNotes = blackboardNotes(blackboard);
        io.just.sast.blackboard.VerificationSummary reportVerification =
                blackboard.verificationSummary();
        CsvReporter reporter = new CsvReporter();
        io.just.sast.report.MultiFormatReporter multiFormatReporter = new io.just.sast.report.MultiFormatReporter();
        reporter.withGraph(cpg.graph());
        long csvReportStart = System.nanoTime();
        Map<String, Long> csvTimings = new java.util.LinkedHashMap<>();
        reporter.write(reportLayout, reportChains, reportOutcomes, reportCalibrations,
                reportNotes, reportVerification, csvTimings);
        phaseMs.put("report.csv", elapsedMs(csvReportStart));
        for (Map.Entry<String, Long> timing : csvTimings.entrySet()) {
            phaseMs.put("report.csv." + timing.getKey(), timing.getValue());
        }
        // C1: SARIF 2.1.0 + E1-E3: JSON/HTML/Markdown 多格式输出
        long sarifReportStart = System.nanoTime();
        new io.just.sast.report.SarifReporter().withHierarchy(hierarchy).withRules(ruleSet).write(
                reportLayout, reportChains, reportCalibrations, reportNotes, reportVerification);
        phaseMs.put("report.sarif", elapsedMs(sarifReportStart));
        long multiFormatReportStart = System.nanoTime();
        multiFormatReporter.write(reportLayout, reportChains, reportCalibrations, reportNotes,
                reportVerification);
        phaseMs.put("report.multi_format", elapsedMs(multiFormatReportStart));
        long payloadReportStart = System.nanoTime();
        new io.just.sast.report.PayloadPlanWriter().write(reportLayout, reportChains,
                reportCalibrations, reportNotes, reportVerification);
        phaseMs.put("report.payload", elapsedMs(payloadReportStart));
        long inventoryStart = System.nanoTime();
        String dependencyInventoryHash = new io.just.sast.report.DependencyInventoryWriter().write(reportLayout, target,
                scanDeps, targetArtifactHash, load.targetMajorVersion(), dependencyHashes);
        phaseMs.put("report.inventory", elapsedMs(inventoryStart));
        new io.just.sast.report.ScanIdentityWriter().write(reportLayout, targetArtifactHash,
                dependencyIdentity, dependencyInventoryHash, rules, jdkHome,
                load.targetMajorVersion(), fast, verify, verifyBudget, safeExec,
                safeReal, requireOsIsolation);
        new io.just.sast.report.BaselineSuppressionWriter().write(reportLayout, baseline,
                suppressions, reportChains, reportCalibrations);
        JustLogger.info("扫描报告已输出到 {}", output.toAbsolutePath());

        // sink/entry 统计从图直接产出（与引擎同一 RuleEngine 实例，access 过滤口径一致）
        int sinkCount = 0;
        for (Node call : cpg.graph().nodesOfType(NodeType.CALL)) {
            if (blackboard.ruleEngine().matchingSink(call).isPresent()) {
                sinkCount++;
            }
        }
        int entryCount = 0;
        for (Node method : cpg.graph().nodesOfType(NodeType.METHOD)) {
            if (blackboard.ruleEngine().matchingEntry(method.strProp("owner"),
                    method.strProp("name"), method.strProp("desc")).isPresent()) {
                entryCount++;
            }
        }
        phaseMs.put("report", elapsedMs(reportStart));
        Map<Long, io.just.sast.blackboard.SinkOutcome> outcomes = reportOutcomes;
        List<String> completenessReasons = completenessReasons(load, cpg.graph(), outcomes,
                blackboard.completenessReasons(), fast, jdkHome, targetFeature);
        ScanStatistics scanStats = new ScanStatistics(
                load.filesScanned(), load.classCount(), load.diagnosticCount(),
                sinkCount, entryCount, reportChains.size(),
                elapsedMs(start),
                (Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()) / 1024 / 1024,
                heapPeakMb(),
                completenessReasons.isEmpty() ? "COMPLETE" : "PARTIAL",
                completenessReasons, phaseMs, scanMetrics(cpg, blackboard, reportChains, reportNotes,
                        reportVerification, parentCpuStarted),
                verify ? blackboard.verificationStatus() : "DISABLED",
                verify ? reportVerification
                        : io.just.sast.blackboard.VerificationSummary.empty("DISABLED", verifyBudget),
                chainProofCompleteness(reportChains, outcomes, completenessReasons),
                targetArtifactHash);
        multiFormatReporter.writeMetadata(reportLayout, scanStats);
        new ReportIndexWriter().write(reportLayout, scanStats);
        if (stats) {
            ConsoleSummary.print(scanStats, outcomes);
        }
        // Reports no longer need CFGs. Clear the per-scan cache before returning so callers
        // retaining ScanResult do not accidentally retain every materialized method graph.
        blackboard.originSupport().clearForwardOriginCache();
        cpg.index().clearCfgCache();
        return new ScanResult(ExitCode.OK.code(), blackboard.chains(), scanStats);
        } finally {
            // External --jdk-home JRT images own a FileSystem and URLClassLoader.  Close them
            // on both normal and exceptional exits; runtime() deliberately implements a no-op.
            jdkSource.close();
        }
    }

    private static void resetHeapPeaks() {
        try {
            for (java.lang.management.MemoryPoolMXBean pool
                    : java.lang.management.ManagementFactory.getMemoryPoolMXBeans()) {
                if (pool.getType() == java.lang.management.MemoryType.HEAP) {
                    pool.resetPeakUsage();
                }
            }
        } catch (RuntimeException ignored) {
            // Peak telemetry is diagnostic only; scan semantics must not depend on MXBeans.
        }
    }

    /** JVM heap-pool peak, not OS RSS; used as a comparable in-process telemetry signal. */
    private static long heapPeakMb() {
        long bytes = 0L;
        try {
            for (java.lang.management.MemoryPoolMXBean pool
                    : java.lang.management.ManagementFactory.getMemoryPoolMXBeans()) {
                if (pool.getType() != java.lang.management.MemoryType.HEAP) {
                    continue;
                }
                java.lang.management.MemoryUsage usage = pool.getPeakUsage();
                if (usage != null && usage.getUsed() > 0L) {
                    bytes += usage.getUsed();
                }
            }
        } catch (RuntimeException ignored) {
            return (Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory())
                    / 1024 / 1024;
        }
        return bytes / 1024 / 1024;
    }

    private static LoadResult loadApplication(BytecodeFrontend frontend, List<Path> targets,
                                              int targetFeature) {
        return frontend.loadStreaming(targets, targetFeature);
    }

    private static int jdkFeature(JdkClassSource source) {
        if (source instanceof TargetJdkSource target) {
            return target.feature();
        }
        if (source instanceof JrtClassSource runtime) {
            return runtime.feature();
        }
        return 0;
    }

    /**
     * Keep only the demand-driven JDK closure alive during frontend construction. The selected
     * bytes are the only external input that the next parse phase needs; this avoids reading an
     * entire JDK image merely to decide that most of it is irrelevant to the target.
     */
    private static LoadResult loadWithJdkSlice(BytecodeFrontend frontend, LoadResult application,
                                                JdkClassSource jdkSource, RuleSet rules)
            throws IOException {
        JdkClassSelector.Selection selection;
        if (jdkSource instanceof TargetJdkSource targetJdk) {
            selection = JdkClassSelector.selectDemandDriven(targetJdk::loadBytes, -1,
                    application.classes(), jdkTypeSeeds(rules), jdkEntrySeeds(rules));
        } else if (jdkSource instanceof JrtClassSource jrt) {
            selection = JdkClassSelector.selectDemandDriven(jrt::loadBytes, -1,
                    application.classes(), jdkTypeSeeds(rules), jdkEntrySeeds(rules));
        } else {
            // The current pipeline only creates TargetJdkSource/JrtClassSource. Keep the
            // legacy path for third-party JdkClassSource implementations without widening the
            // model interface or changing their extension contract.
            List<ClassBytes> availableJdk = List.of();
            selection = JdkClassSelector.selectDetailed(availableJdk,
                    application.classes(), jdkTypeSeeds(rules), jdkEntrySeeds(rules));
        }
        String available = selection.availableClasses() < 0 ? "按需未知" : String.valueOf(selection.availableClasses());
        JustLogger.info("JDK 类切片：候选 {}，header {} 个，初始种子 {} 个，隐式 entry 新增 {} 个，闭包物化 {} 个",
                available, selection.headerClasses(), selection.initialSeeds(),
                selection.implicitEntrySeeds(), selection.closureClasses());
        return frontend.load(application, selection.classes());
    }

    /** 将“没有发现”与“分析曾触顶/跳过内容”区分开，原因使用稳定类别而不泄漏路径。 */
    private static List<String> completenessReasons(LoadResult load, io.just.sast.cpg.graph.Graph graph,
                                                     Map<Long, io.just.sast.blackboard.SinkOutcome> outcomes,
                                                     java.util.Set<String> analysisReasons,
                                                     boolean fast, Path jdkHome, int targetFeature) {
        LinkedHashSet<String> reasons = new LinkedHashSet<>(load.completenessReasons());
        reasons.addAll(analysisReasons);
        if (fast) {
            reasons.add("FAST_MODE");
        }
        if (jdkHome != null && targetFeature <= 0) {
            // Multi-release selection and verifier runtime choice cannot be called target
            // accurate when an external image exposes no readable feature metadata.
            reasons.add("JDK_FEATURE_UNKNOWN");
        }
        if (load.diagnosticCount() > 0) {
            reasons.add("PARSE_DIAGNOSTICS");
        }
        String runtime = System.getProperty("java.version", "");
        if (jdkHome == null && load.targetMajorVersion() > 0 && load.targetMajorVersion() < 61
                && !runtime.startsWith("1.8")) {
            reasons.add("JDK_APPROXIMATION");
        }
        for (Node call : graph.nodesOfType(NodeType.CALL)) {
            if (call.note("dispatchSkipped") != null) {
                reasons.add("DISPATCH_CAP");
                break;
            }
        }
        for (io.just.sast.blackboard.SinkOutcome outcome : outcomes.values()) {
            if ("TRUNCATED".equals(outcome.verdict()) || "TOO_LONG".equals(outcome.verdict())
                    || "UNRESOLVED".equals(outcome.verdict()) || "NO_STATE".equals(outcome.verdict())) {
                reasons.add("ANALYSIS_BOUND");
                break;
            }
        }
        return List.copyOf(reasons);
    }

    private static String chainProofCompleteness(List<Chain> chains,
                                                 Map<Long, io.just.sast.blackboard.SinkOutcome> outcomes,
                                                 List<String> completenessReasons) {
        if (chains == null || chains.isEmpty()) {
            return "NO_SURVIVING_CHAIN";
        }
        boolean partialChain = chains.stream().anyMatch(chain -> chain.unresolvedHops() > 0);
        boolean partialSink = outcomes != null && outcomes.values().stream().anyMatch(outcome ->
                "TRUNCATED".equals(outcome.verdict()) || "TOO_LONG".equals(outcome.verdict())
                        || "UNRESOLVED".equals(outcome.verdict()) || "NO_STATE".equals(outcome.verdict()));
        // A surviving chain is not a complete proof when any upstream semantic phase was
        // bounded or aborted.  Previously this field only inspected the surviving chain
        // objects, which could incorrectly report COMPLETE after a global timeout (notably
        // on dependency-heavy jars where the controller cancels a knowledge source).
        boolean boundedOrAborted = completenessReasons != null && completenessReasons.stream()
                .filter(java.util.Objects::nonNull)
                .anyMatch(ScanPipeline::invalidatesChainProof);
        return partialChain || partialSink || boundedOrAborted ? "PARTIAL" : "COMPLETE";
    }

    private static boolean invalidatesChainProof(String reason) {
        return "ANALYSIS_BOUND".equals(reason)
                || "CONTROLLER_ABORTED".equals(reason)
                || reason.startsWith("SOURCE_FAILED:")
                || reason.startsWith("BACKWARD_")
                || reason.startsWith("FORWARD_")
                || reason.startsWith("DISPATCH_")
                || reason.startsWith("COMPOSITION_");
    }

    private static Map<String, Long> scanMetrics(BuiltCpg cpg, Blackboard blackboard,
                                                 List<Chain> chains,
                                                 Map<String, List<String>> chainNotes,
                                                 io.just.sast.blackboard.VerificationSummary verification,
                                                 long parentCpuStarted) {
        Map<String, Long> metrics = new java.util.LinkedHashMap<>();
        metrics.put("graph_nodes", (long) cpg.graph().nodeCount());
        metrics.put("graph_edges", (long) cpg.graph().edgeCount());
        metrics.put("cpg_methods", (long) cpg.index().methodCount());
        metrics.put("cpg_cfg_builds", cpg.index().cfgBuilds());
        metrics.put("cpg_cfg_cache_hits", cpg.index().cfgCacheHits());
        metrics.put("cpg_cfg_cache_size", (long) cpg.index().cfgCacheSize());
        metrics.put("blackboard_chains", (long) (chains == null ? 0 : chains.size()));
        metrics.put("blackboard_calibrations", (long) blackboard.calibrationCount());
        metrics.put("forward_origin_cache_size",
                (long) blackboard.originSupport().forwardOriginCacheSize());
        metrics.put("forward_origin_compute_calls",
                blackboard.originSupport().forwardOriginComputeCalls());
        metrics.put("forward_origin_cache_hits",
                blackboard.originSupport().forwardOriginCacheHits());
        metrics.put("forward_origin_analysis_runs",
                blackboard.originSupport().forwardOriginAnalysisRuns());
        verification = verification == null ? blackboard.verificationSummary() : verification;
        metrics.put("verification_constructible", (long) verification.constructible());
        metrics.put("verification_rejected", (long) verification.rejected());
        metrics.put("verification_construction_deferred", (chains == null ? List.<Chain>of() : chains).stream()
                .map(chain -> chainNotes == null ? List.<String>of()
                        : chainNotes.getOrDefault(chain.key(), List.of()))
                .filter(notes -> notes.contains("verify:construction-deferred"))
                .count());
        metrics.put("verification_selected", (long) verification.selected());
        metrics.put("verification_results", (long) verification.results().size());
        metrics.put("verification_attempts", verification.results().stream()
                .mapToLong(io.just.sast.blackboard.VerificationSummary.ChainResult::attempt).sum());
        metrics.put("verification_timeouts", (long) verification.statusCounts()
                .getOrDefault("TIMEOUT", 0));
        metrics.put("verification_untestable", (long) verification.statusCounts()
                .getOrDefault("UNTESTABLE", 0));
        metrics.putAll(blackboard.verificationResourceMetrics());
        metrics.put("parent_rss_mb", io.just.sast.verify.OsIsolation.currentProcessRssMb());
        long parentCpuNow = processCpuTimeMs();
        metrics.put("parent_cpu_ms", parentCpuStarted >= 0L && parentCpuNow >= parentCpuStarted
                ? parentCpuNow - parentCpuStarted : -1L);
        metrics.put("parent_thread_peak", parentThreadPeak());
        metrics.put("parent_processes_current", currentProcessCount());
        return metrics;
    }

    private static long processCpuTimeMs() {
        try {
            java.lang.management.OperatingSystemMXBean bean =
                    java.lang.management.ManagementFactory.getOperatingSystemMXBean();
            if (bean instanceof com.sun.management.OperatingSystemMXBean sun) {
                long nanos = sun.getProcessCpuTime();
                return nanos < 0L ? -1L : nanos / 1_000_000L;
            }
        } catch (RuntimeException ignored) {
            // Resource telemetry must not affect scan semantics.
        }
        return -1L;
    }

    private static long parentThreadPeak() {
        try {
            return Math.max(0L, java.lang.management.ManagementFactory.getThreadMXBean()
                    .getPeakThreadCount());
        } catch (RuntimeException ignored) {
            return -1L;
        }
    }

    private static long currentProcessCount() {
        try {
            return 1L + java.lang.ProcessHandle.current().descendants().count();
        } catch (RuntimeException ignored) {
            return -1L;
        }
    }

    private static void validatePath(Path path, String label, boolean allowDirectory)
            throws UsageException {
        if (path == null) {
            throw new UsageException(label + "不能为空");
        }
        if (!Files.exists(path)) {
            throw new UsageException(label + "不存在: " + path.toAbsolutePath());
        }
        if (ArchiveLimits.isLinkOrReparsePoint(path)) {
            throw new UsageException(label + "不能是符号链接或 reparse point: "
                    + path.toAbsolutePath());
        }
        if (!Files.isRegularFile(path) && !(allowDirectory && Files.isDirectory(path))) {
            throw new UsageException(label + "不是普通文件或目录: " + path.toAbsolutePath());
        }
    }

    /** 链级注释视图（有注释的链 key → 注释列表快照，报告层消费）。 */
    private static Map<String, List<String>> blackboardNotes(Blackboard blackboard) {
        Map<String, List<String>> notes = new java.util.TreeMap<>();
        for (Chain chain : blackboard.chains()) {
            List<String> list = blackboard.chainNotesOf(chain.key());
            if (!list.isEmpty()) {
                notes.put(chain.key(), list);
            }
        }
        return notes;
    }

    /** class 文件 major version → JDK 版本描述。 */
    private static String jdkVersionOf(int major) {
        return switch (major) {
            case 45 -> "1.0/1.1";
            case 46 -> "1.2";
            case 47 -> "1.3";
            case 48 -> "1.4";
            case 49 -> "1.5";
            case 50 -> "1.6";
            case 51 -> "1.7";
            case 52 -> "1.8";
            case 53 -> "9";
            case 54 -> "10";
            case 55 -> "11";
            case 56 -> "12";
            case 57 -> "13";
            case 58 -> "14";
            case 59 -> "15";
            case 60 -> "16";
            case 61 -> "17";
            case 62 -> "18";
            case 63 -> "19";
            case 64 -> "20";
            case 65 -> "21";
            case 66 -> "22";
            case 67 -> "23";
            case 68 -> "24";
            default -> "unknown(" + major + ")";
        };
    }

    private static RuleSet loadRules(Path rulesFile) throws IOException {
        YamlRuleLoader loader = new YamlRuleLoader();
        if (rulesFile != null) {
            try (InputStream in = Files.newInputStream(rulesFile)) {
                RuleSet custom = loader.load(in);
                // Container summaries are part of the scanner's JVM value-flow contract,
                // not a requirement every project-specific sink file must duplicate. Keep
                // user sinks/entries/sources authoritative, while supplying missing generic
                // Map/List/Deque summaries from the bundled rule data. An identical custom
                // matcher wins by omission; a more specific custom matcher is still selected
                // by RuleEngine's normal specificity ordering.
                RuleSet bundled = loadBundledRules(loader);
                List<Rule.ModelRule> models = new ArrayList<>(custom.models());
                for (Rule.ModelRule model : bundled.models()) {
                    if (models.stream().noneMatch(existing -> existing.call().equals(model.call()))) {
                        models.add(model);
                    }
                }
                return new RuleSet(custom.sinks(), custom.magicEntries(), custom.sources(),
                        models, custom.fragments());
            }
        }
        return loadBundledRules(loader);
    }

    private static RuleSet loadBundledRules(YamlRuleLoader loader) throws IOException {
        try (InputStream in = ScanPipeline.class.getResourceAsStream("/rules/default-rules.yaml")) {
            if (in == null) {
                throw new IOException("内置规则文件不存在: /rules/default-rules.yaml");
            }
            return loader.load(in);
        }
    }

    /** Stable SHA-256 identity used by reports and the dynamic child attestation protocol. */
    private static String artifactHash(Path input) throws IOException {
        return ArtifactFingerprint.sha256(input);
    }

    /** 从规则数据提取字面量类型种子；正则 owner 仍由现有调用图/规则逻辑处理。 */
    private static java.util.Set<String> jdkTypeSeeds(RuleSet rules) {
        java.util.Set<String> seeds = new LinkedHashSet<>();
        // sink/source/model 的 JDK owner 通常已经出现在应用字节码的 MethodRef 中，
        // 且规则只需要调用点事实；把整个 Class/reflect/网络 API 作为 class body
        // 种子会把大量无关平台实现重新拉回 CPG。只有声明式 fragment 的 JDK 锚点
        // 可能没有应用直接引用，必须保留为显式种子。
        for (Rule.FragmentRule rule : rules.fragments()) {
            addTypeSeed(seeds, rule.entryClass());
            addTypeSeed(seeds, rule.sinkOwner());
            for (Rule.HopSpec hop : rule.hops()) {
                addTypeSeed(seeds, hop.cls());
            }
            if (rule.constructionPlan() != null) {
                for (var node : rule.constructionPlan().nodes()) {
                    addTypeSeed(seeds, node.type());
                    for (var value : node.arguments()) {
                        if (value.kind() == io.just.sast.blackboard.ObjectGraphPlan.ValueKind.CLASS) {
                            addTypeSeed(seeds, value.value());
                        }
                    }
                }
                for (var assignment : rule.constructionPlan().fields()) {
                    // A field owner may be a node id. Node types above are the actual class
                    // seeds; CLASS values in assignments are JDK/interface dependencies.
                    for (var value : assignment.values()) {
                        if (value.kind() == io.just.sast.blackboard.ObjectGraphPlan.ValueKind.CLASS) {
                            addTypeSeed(seeds, value.value());
                        }
                    }
                }
            }
        }
        return seeds;
    }

    private static void addTypeSeed(java.util.Set<String> seeds, String name) {
        if (name != null && !name.isEmpty() && !name.startsWith("~")) {
            seeds.add(name);
        }
    }

    private static long elapsedMs(long startedNanos) {
        long elapsed = Math.max(0L, System.nanoTime() - startedNanos);
        return elapsed / 1_000_000L;
    }

    /** 将可配置的 magic-entry Match 映射为 frontend 不依赖 Rule 类型的轻量种子。 */
    private static List<JdkClassSelector.EntrySeed> jdkEntrySeeds(RuleSet rules) {
        List<JdkClassSelector.EntrySeed> seeds = new ArrayList<>();
        for (Rule.MagicEntryRule rule : rules.magicEntries()) {
            var method = rule.method();
            var name = method.name();
            var descriptor = method.descriptor();
            seeds.add(new JdkClassSelector.EntrySeed(
                    name.pattern(), name.isRegex(),
                    descriptor == null ? null : descriptor.pattern(),
                    descriptor != null && descriptor.isRegex(),
                    method.privateOnly(), rule.implementsType(), rule.entryKind()));
        }
        return List.copyOf(seeds);
    }
}
