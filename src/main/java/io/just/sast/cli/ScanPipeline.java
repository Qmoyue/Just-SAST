package io.just.sast.cli;

import io.just.sast.analysis.callgraph.CallGraphBuilder;
import io.just.sast.analysis.entry.ApplicationChainEvidence;
import io.just.sast.analysis.entry.ApplicationChainJoiner;
import io.just.sast.analysis.entry.DemandDrivenProgramSlice;
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
import io.just.sast.knowledge.engine.ForwardRunMetrics;
import io.just.sast.model.JdkClassSource;
import io.just.sast.model.LoadResult;
import io.just.sast.model.ArtifactProvenance;
import io.just.sast.model.DependencyGraph;
import io.just.sast.model.ProgramUniverse;
import io.just.sast.report.ConsoleSummary;
import io.just.sast.report.ReportIndexWriter;
import io.just.sast.report.ReportLayout;
import io.just.sast.report.ReportTransaction;
import io.just.sast.report.ScanStatistics;
import io.just.sast.report.HopProvenanceResolver;
import io.just.sast.run.RunOutcome;
import io.just.sast.run.InputBudget;
import io.just.sast.util.ArchiveLimits;
import io.just.sast.util.ArtifactFingerprint;
import io.just.sast.util.InputDigestVerification;
import io.just.sast.util.JustLogger;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/** 扫描管线编排：frontend → 层次 → CPG/调用图（构建后冻结）→ 黑板（串行三阶段）→ report。 */
public final class ScanPipeline {

    /** 反向回溯递归深度上限（内部固定，不暴露参数）。覆盖 ~8 层链（再深需按链一致性做精度门，见 development.md）。 */
    private static final int MAX_DEPTH = 64;

    private ScanPipeline() {}

    public static final class UsageException extends Exception {
        public UsageException(String message) {
            super(message);
        }
    }

    /**
     * Typed handoff for input-preparation timing.  Dependency resolution is completed before
     * the frontend starts; keeping its timing here prevents network work from being charged to
     * analysis or reconstructed by a report writer.
     */
    public record DependencyPreparation(DependencyStatus status, int completedArtifacts,
                                        int cacheArtifacts, int remoteArtifacts,
                                        long resolutionWallMs, long networkDownloadWallMs,
                                        long networkRequestMs, long transferredBytes) {
        public enum DependencyStatus {
            NOT_PROVIDED, COMPLETE, PARTIAL, UNRESOLVED
        }

        public DependencyPreparation {
            status = Objects.requireNonNull(status, "dependency preparation status");
            if (completedArtifacts < 0 || cacheArtifacts < 0 || remoteArtifacts < 0
                    || (long) cacheArtifacts + remoteArtifacts != completedArtifacts) {
                throw new IllegalArgumentException("dependency artifact counts are invalid");
            }
            if (resolutionWallMs < 0L || networkDownloadWallMs < 0L
                    || networkRequestMs < 0L || transferredBytes < 0L) {
                throw new IllegalArgumentException("dependency timings must be non-negative");
            }
            if (status == DependencyStatus.NOT_PROVIDED && completedArtifacts != 0) {
                throw new IllegalArgumentException(
                        "missing POM cannot report completed dependency artifacts");
            }
        }

        public static DependencyPreparation notProvided() {
            return new DependencyPreparation(DependencyStatus.NOT_PROVIDED,
                    0, 0, 0, 0L, 0L, 0L, 0L);
        }
    }

    /** 扫描结果；运行状态由闭集 RunOutcome 唯一拥有。 */
    public record ScanResult(RunOutcome outcome, List<Chain> chains, ScanStatistics stats) {
        public ScanResult {
            outcome = outcome == null ? RunOutcome.notRun("MISSING_SCAN_OUTCOME", "") : outcome;
            chains = chains == null ? List.of() : List.copyOf(chains);
            if (stats == null) {
                throw new IllegalArgumentException("scan statistics are required");
            }
        }

        public int exitCode() {
            return outcome.exitCode();
        }
    }

    /** Minimal component scan entry point used by library and test callers. */
    public static ScanResult run(Path target, List<Path> deps, Path output, Path rules,
        boolean stats, boolean fast, Path jdkHome) throws Exception {
        return run(target, deps, output, rules, stats, fast, jdkHome,
                null, null, false, ModeDemandPolicy.forMode(ScanMode.COMPONENT));
    }

    /** Explicit mode entry point; all scans remain static-only. */
    public static ScanResult run(Path target, List<Path> deps, Path output, Path rules,
        boolean stats, boolean fast, Path jdkHome, ModeDemandPolicy modePolicy) throws Exception {
        return run(target, deps, output, rules, stats, fast, jdkHome,
                null, null, false, modePolicy);
    }

    /** Scan entry point with explicit report-difference and overwrite policies. */
    public static ScanResult run(Path target, List<Path> deps, Path output, Path rules,
        boolean stats, boolean fast, Path jdkHome, Path baseline, Path suppressions,
        boolean overwrite, ModeDemandPolicy modePolicy) throws Exception {
        return run(target, deps, output, rules, stats, fast, jdkHome, baseline, suppressions,
                overwrite, modePolicy, null, -1, "MAVEN_POM_NOT_PROVIDED",
                DependencyPreparation.notProvided());
    }

    /**
     * Full pipeline entry point with the explicit input-preparation handoff.  Actual direct
     * inputs remain ahead of POM-derived bytes, while the immutable environment graph carries
     * selected CACHE/REMOTE provenance into frontend ownership and report identity.
     */
    public static ScanResult run(Path target, List<Path> deps, Path output, Path rules,
        boolean stats, boolean fast, Path jdkHome, Path baseline,
                                 Path suppressions, boolean overwrite,
                                 ModeDemandPolicy modePolicy,
                                 DependencyGraph preparedDependencyGraph,
                                 int explicitDependencyCount,
                                 String dependencyEnvironmentIdentity,
                                 DependencyPreparation dependencyPreparation) throws Exception {
        if (modePolicy == null) {
            throw new IllegalArgumentException("mode/demand policy is required");
        }
        Objects.requireNonNull(dependencyPreparation, "dependency preparation is required");
        long start = System.nanoTime();
        long parentCpuStarted = processCpuTimeMs();
        Map<String, Long> phaseMs = new java.util.LinkedHashMap<>();
        resetHeapPeaks();
        GcSnapshot gcStarted = gcSnapshot();
        InputBudget inputBudget = InputBudget.defaults();

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
        if (Files.exists(output) && !overwrite) {
            throw new UsageException("输出目录已存在；run-level 报告默认不覆盖，请显式使用 --overwrite: "
                    + output.toAbsolutePath());
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
        // Hash immutable inputs once at the scan boundary. Besides making report identity
        // available to the cache layer before frontend parsing, reusing these values avoids a
        // second full read of a large target/dependency archive during report generation.
        List<Path> scanDeps = deps == null ? List.of() : List.copyOf(deps);
        int actualDependencyCount = preparedDependencyGraph == null ? scanDeps.size()
                : explicitDependencyCount;
        if (actualDependencyCount < 0 || actualDependencyCount > scanDeps.size()) {
            throw new UsageException("依赖输入准备边界无效");
        }
        List<Path> actualDependencies = scanDeps.subList(0, actualDependencyCount);
        InputBudget.Tracker inputTracker = inputBudget.tracker();
        String targetArtifactHash = artifactHash(target, inputTracker);
        List<String> dependencyHashes = io.just.sast.report.ScanCache
                .dependencyHashes(scanDeps, inputTracker);
        String dependencyIdentity = io.just.sast.report.ScanCache
                .dependencyIdentityFromHashes(dependencyHashes,
                        dependencyEnvironmentIdentity == null || dependencyEnvironmentIdentity.isBlank()
                                ? "MAVEN_POM_NOT_PROVIDED" : dependencyEnvironmentIdentity);

        // 规则
        RuleSet ruleSet;
        try {
            ruleSet = loadRules(rules, inputBudget, inputTracker);
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
                targetJdk = new TargetJdkSource(jdkHome, inputBudget, inputTracker);
            } catch (IOException e) {
                throw new UsageException("--jdk-home 加载失败: " + e.getMessage());
            }
            jdkSource = targetJdk;
            JustLogger.info("使用目标 JDK：{}（--jdk-home={}）", targetJdk.description(), jdkHome);
        } else {
            JrtClassSource jrt = JrtClassSource.runtime(inputBudget, inputTracker);
            jdkSource = jrt;
        }
        try {
        BytecodeFrontend frontend = new BytecodeFrontend(inputBudget);
        // 先解析 target/deps；完整模式随后只把应用引用、规则类型和 magic-entry 方法
        // 所需的 JDK 类体放进 CPG，避免对同一批应用字节重复读取/解析。
        // 把原始 ClassBytes 限制在独立 helper 的生命周期内。完整扫描需要的只是
        // ClassInfo；否则 JDK 切片规划期间 input 仍会把整批 fat-jar byte[] 挂住。
        int targetFeature = jdkFeature(jdkSource);
            BytecodeFrontend.ScopedLoad scopedApplication = loadApplication(frontend, targets,
                    targetFeature, inputTracker);
            LoadResult applicationLoad = scopedApplication.load();
            java.util.Set<String> demandRoots = modePolicy.demandRootClasses(
                    scopedApplication.applicationClassNames());
            java.util.Set<String> applicationClassNames = modePolicy.applicationClassNames(
                    scopedApplication.applicationClassNames());
        LoadResult load;
        if (fast) {
            load = applicationLoad;
        } else {
            load = loadWithJdkSlice(frontend, applicationLoad, jdkSource, ruleSet,
                    inputTracker);
        }
        // The frontend has already parsed every bounded input entry.  Before CPG construction,
        // retain only application-owned classes plus a generic, rule/reference-driven dependency
        // closure.  This is the graph-facing demand boundary: it reduces unrelated dependency
        // noise without pretending that an unread or malformed archive entry was absent, and it
        // never changes the application-entry/join contract or benchmark truth.
        long demandSliceStart = System.nanoTime();
        DemandDrivenProgramSlice.Result demandSlice = DemandDrivenProgramSlice.select(
                load, demandRoots, ruleSet);
        load = demandSlice.load();
        phaseMs.put("dependency_slice", elapsedMs(demandSliceStart));
        JustLogger.info("依赖需求切片：{} -> {} 个类，依赖 {} -> {}，能力类 {}，规则锚点 {}，引用轮数 {}{}",
                demandSlice.inputClasses(), demandSlice.selectedClasses(),
                demandSlice.inputDependencies(), demandSlice.selectedDependencies(),
                demandSlice.capabilityClasses(), demandSlice.ruleAnchorClasses(),
                demandSlice.referenceRounds(), demandSlice.capped() ? "（触顶，结果 PARTIAL）" : "");
        JustLogger.debug("应用范围：{} 个类；需求切片应用边界/终端门由前端模型计算，图级入口索引随后复核",
                applicationClassNames.size());
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

        // Freeze actual artifact/dependency relationships once, before CPG construction. The
        // same graph is carried by the immutable universe and later serialized by the report
        // boundary; inventory generation must not reopen paths and invent a second identity.
        long dependencyResolutionStart = System.nanoTime();
        List<ArtifactProvenance> artifactInputs = artifactProvenance(target, scanDeps,
                targetArtifactHash, dependencyHashes, jdkSource, targetFeature);
        DependencyGraph dependencyGraph = new io.just.sast.report.DependencyInventoryWriter()
                .build(target, actualDependencies, targetArtifactHash, load.targetMajorVersion(),
                        dependencyHashes.subList(0, actualDependencyCount), artifactInputs,
                        inputBudget, inputTracker);
        if (preparedDependencyGraph != null) {
            dependencyGraph = dependencyGraph.merge(preparedDependencyGraph);
        } else {
            dependencyGraph = dependencyGraph.withEnvironmentConditions(
                    List.of("MAVEN_POM_NOT_PROVIDED"));
        }
        Map<String, Integer> applicationIndexes = new java.util.LinkedHashMap<>();
        Map<String, List<Integer>> applicationDuplicates = new java.util.LinkedHashMap<>();
        java.util.Set<String> graphApplicationClassNames = new LinkedHashSet<>(load.classes().keySet());
        graphApplicationClassNames.retainAll(scopedApplication.applicationClassNames());
        for (String className : graphApplicationClassNames) {
            Integer index = scopedApplication.classArtifactIndexes().get(className);
            if (index != null) {
                applicationIndexes.put(className, index);
                List<Integer> duplicates = scopedApplication.duplicateArtifactIndexes()
                        .get(className);
                if (duplicates != null && !duplicates.isEmpty()) {
                    applicationDuplicates.put(className, duplicates);
                }
            }
        }
        dependencyGraph = dependencyGraph.bindClassOwners(applicationIndexes,
                applicationDuplicates, scopedApplication.artifactDetails(),
                graphApplicationClassNames);
        phaseMs.put("dependency_graph", elapsedMs(dependencyResolutionStart));
        // Resolver timing belongs to input preparation.  The graph assembly above is a local
        // scan phase and must remain distinguishable from network/model work done by the CLI.
        phaseMs.put("dependency_resolution", dependencyPreparation.resolutionWallMs());

        // Freeze the frontend product at the phase boundary.  Downstream owners consume only
        // the immutable model; raw ASM/class bytes never cross into CPG or knowledge code.
        Map<String, ArtifactProvenance> applicationArtifacts = new java.util.LinkedHashMap<>();
        if (!artifactInputs.isEmpty()) {
            ArtifactProvenance application = artifactInputs.get(0);
            for (String className : graphApplicationClassNames) {
                applicationArtifacts.put(className, application);
            }
        }
        ProgramUniverse universe = ProgramUniverse.of(load, applicationArtifacts,
                artifactInputs, dependencyGraph);
        Map<String, ArtifactProvenance> hopArtifacts = hopArtifactOwners(
                scopedApplication, artifactInputs);

        long cpgStart = System.nanoTime();
        ClassHierarchy hierarchy = new ClassHierarchy(universe.classes(), jdkSource);
        BuiltCpg cpg = new CpgBuilder().build(universe);
        int callEdges = new CallGraphBuilder(hierarchy).build(cpg.graph());
        cpg.graph().freeze();
        JustLogger.info("CPG 构建完成：节点 {}，边 {}，调用边 {}，字段写入 {} 组",
                cpg.graph().nodeCount(), cpg.graph().edgeCount(), callEdges,
                cpg.fieldWriters().fieldCount());
        phaseMs.put("cpg", elapsedMs(cpgStart));

        // 分析期（黑板串行三阶段：ANALYSIS → COMPOSITION → CALIBRATION）
        long analysisStart = System.nanoTime();
        Blackboard blackboard = new Blackboard(cpg.graph(), hierarchy, cpg.fieldWriters(), cpg.index(), ruleSet, MAX_DEPTH,
                new Blackboard.ScanInputs(target.toAbsolutePath().normalize(), scanDeps, fast,
                        jdkHome, load.targetMajorVersion(), inputTracker, applicationClassNames,
                        // Component mode deliberately has no application-entry scope: its
                        // mechanism products are retained in the kernel store and exported by
                        // the component report.  Application mode enables the strict
                        // entry/site/join admission boundary.
                        modePolicy.applicationScopeKnown(),
                        scopedApplication.applicationResourceFacts()));
        scopedApplication.applicationResourceFacts().completenessReasons()
                .forEach(blackboard::markIncomplete);
        new Controller(blackboard, KnowledgeSources.discover()).run();
        for (Map.Entry<String, Long> timing : blackboard.phaseMs().entrySet()) {
            phaseMs.put(timing.getKey(), timing.getValue());
        }
        phaseMs.put("analysis", elapsedMs(analysisStart));
        phaseMs.put("filter", blackboard.originSupport().finiteFilterMs());
        // The application-entry joiner owns this product. Build it once at the phase boundary
        // when the controller did not publish a newer instance; an empty application product is
        // a valid negative result and remains explicit in the evidence report.
        ApplicationChainEvidence applicationEvidence = latestApplicationChainEvidence(blackboard);
        if (applicationEvidence == null) {
            applicationEvidence = ApplicationChainJoiner.build(blackboard);
            blackboard.publishFact(applicationEvidence);
        }
        // Re-check immutable input identities after analysis.  The digest pass uses the same
        // scan-boundary tracker and therefore cannot silently obtain a second aggregate budget;
        // any changed/unavailable input becomes an explicit completeness reason while static
        // facts remain available for diagnosis.
        InputDigestVerification inputDigest = InputDigestVerification.verify(target, scanDeps,
                targetArtifactHash, dependencyHashes, inputTracker);
        if (!inputDigest.matched()) {
            inputDigest.reasons().forEach(blackboard::markIncomplete);
        }
        // The joiner publishes the application join before report identity is assembled. Enrich that
        // immutable product exactly once with the scan-boundary target digest so every exported
        // application chain can be traced back to the bytes that were analyzed.
        applicationEvidence = applicationEvidence.withArtifactDigest(targetArtifactHash);
        if (!modePolicy.requireApplicationJoin()) {
            applicationEvidence = ApplicationChainEvidence.empty(false,
                    List.of("COMPONENT_MODE_KERNEL_ONLY"));
        }
        blackboard.publishFact(applicationEvidence);
        // Publish one static phase for the performance harness. The complete pre-report
        // interval is static analysis.
        long preReportMs = elapsedMs(start);
        phaseMs.put("static", Math.max(0L, preReportMs));

        // 报告期
        long reportStart = System.nanoTime();
        try (ReportTransaction transaction = ReportTransaction.begin(output, overwrite)) {
        ReportLayout reportLayout = transaction.layout();
        // Freeze the blackboard views once at the report boundary.  Each reporter previously
        // requested fresh defensive copies of chains/calibrations/outcomes and rebuilt the
        // chain-note map independently.  On a large closure that turned reporting into a
        // repeated synchronization/copy pass without changing any emitted byte.
        // Include calibration-only callback candidates in the audit snapshot.  They never
        // enter composition and strict product export still requires the typed application
        // finding state, but retaining them here preserves an explainable
        // no-trigger/rejection row instead of silently dropping a solver observation.
        List<Chain> reportChains = HopProvenanceResolver.enrich(blackboard.reportChains(),
                cpg.graph(), hopArtifacts);
        Map<Long, io.just.sast.blackboard.SinkOutcome> reportOutcomes = blackboard.sinkOutcomes();
        Map<String, String> reportCalibrations = blackboard.chainCalibrations();
        Map<String, List<String>> reportNotes = blackboardNotes(blackboard);
        LinkedHashSet<String> completeness = new LinkedHashSet<>(completenessReasons(load, cpg.graph(),
                reportOutcomes, blackboard.completenessReasons(), fast, jdkHome, targetFeature));
        if (jdkSource instanceof TargetJdkSource targetJdk) {
            completeness.addAll(targetJdk.completenessReasons());
        } else if (jdkSource instanceof JrtClassSource runtimeJdk) {
            completeness.addAll(runtimeJdk.completenessReasons());
        }
        List<String> scanCompletenessReasons = List.copyOf(completeness);
        String scanChainProofCompleteness = chainProofCompleteness(reportChains, reportOutcomes,
                scanCompletenessReasons);
        RunOutcome scanOutcome = RunOutcome.forScan(
                scanCompletenessReasons.isEmpty() ? "COMPLETE" : "PARTIAL",
                scanChainProofCompleteness);
        io.just.sast.report.FindingOutputReader.Snapshot findingOutput =
                new io.just.sast.report.FindingOutputReader().read(
                        reportChains, reportCalibrations, reportNotes,
                        applicationEvidence.states(),
                        modePolicy.requireApplicationJoin(),
                        applicationEvidence);
        long findingOutputStart = System.nanoTime();
        new io.just.sast.report.FindingOutputWriter().write(reportLayout, findingOutput);
        phaseMs.put("report.finding_output", elapsedMs(findingOutputStart));
        long inputDigestReportStart = System.nanoTime();
        new io.just.sast.report.InputDigestWriter().write(reportLayout, inputDigest);
        phaseMs.put("report.input_digest", elapsedMs(inputDigestReportStart));
        long applicationEvidenceReportStart = System.nanoTime();
        new io.just.sast.report.ApplicationChainEvidenceWriter().write(reportLayout,
                applicationEvidence);
        phaseMs.put("report.application_chain_evidence",
                elapsedMs(applicationEvidenceReportStart));
        long inventoryStart = System.nanoTime();
        String dependencyInventoryHash = new io.just.sast.report.DependencyInventoryWriter()
                .write(reportLayout, dependencyGraph, targetArtifactHash);
        phaseMs.put("report.inventory", elapsedMs(inventoryStart));
        new io.just.sast.report.ScanIdentityWriter().write(reportLayout, targetArtifactHash,
                dependencyIdentity, dependencyInventoryHash, rules, jdkHome,
                load.targetMajorVersion(), fast, modePolicy.wireName(), inputBudget, inputTracker,
                jdkSource == null ? null : jdkSource.sourceInfo());
        new io.just.sast.report.BaselineSuppressionWriter().write(reportLayout, baseline,
                suppressions, reportChains, reportCalibrations, inputBudget);
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
        long pipelineWallMs = elapsedMs(start);
        // Dependency preparation happens before this method is entered.  Add its one measured
        // wall interval to the end-to-end total, without adding network request durations or
        // any child interval a second time.
        long totalWallMs = saturatedAdd(dependencyPreparation.resolutionWallMs(), pipelineWallMs);
        Map<Long, io.just.sast.blackboard.SinkOutcome> outcomes = reportOutcomes;
        GcSnapshot gcDelta = gcSnapshot().delta(gcStarted);
        ScanMetricCapture metricCapture = scanMetricCapture(cpg, blackboard, reportChains,
                reportNotes, parentCpuStarted, entryCount, phaseMs, gcDelta,
                applicationEvidence, dependencyGraph, dependencyPreparation, totalWallMs);
        ScanStatistics scanStats = new ScanStatistics(
                load.filesScanned(), load.classCount(), load.diagnosticCount(),
                sinkCount, entryCount, reportChains.size(),
                totalWallMs,
                (Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()) / 1024 / 1024,
                heapPeakMb(),
                scanCompletenessReasons.isEmpty() ? "COMPLETE" : "PARTIAL",
                scanCompletenessReasons, phaseMs, metricCapture.values(),
                scanChainProofCompleteness,
                targetArtifactHash, metricCapture.status(), metricCapture.namespaces(),
                metricCapture.namespaceStatus(), blackboard.originSupport().finiteFilterEvidence());
        new io.just.sast.report.MultiFormatReporter().writeMetadata(reportLayout, scanStats);
        new ReportIndexWriter().write(reportLayout, scanStats);
        new io.just.sast.report.ConciseReportWriter().write(reportLayout,
                modePolicy.wireName(),
                findingOutput, scanStats);
        transaction.commit();
        JustLogger.info("扫描报告已输出到 {}", output.toAbsolutePath());
        if (stats) {
            ConsoleSummary.print(scanStats, outcomes);
        }
        // Reports no longer need CFGs. Clear the per-scan cache before returning so callers
        // retaining ScanResult do not accidentally retain every materialized method graph.
        blackboard.originSupport().clearForwardOriginCache();
        cpg.index().clearCfgCache();
        return new ScanResult(scanStats.runOutcome(), reportChains, scanStats);
        }
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

    private static BytecodeFrontend.ScopedLoad loadApplication(BytecodeFrontend frontend,
                                                               List<Path> targets,
                                                               int targetFeature,
                                                               InputBudget.Tracker inputTracker) {
        return frontend.loadStreamingWithApplicationScope(targets, targetFeature, inputTracker);
    }

    /** Input identities are computed once at the scan boundary and carried by the universe. */
    private static List<ArtifactProvenance> artifactProvenance(Path target, List<Path> dependencies,
                                                                String targetHash,
                                                                List<String> dependencyHashes,
                                                                JdkClassSource jdkSource,
                                                                int targetFeature) {
        List<ArtifactProvenance> result = new ArrayList<>();
        result.add(new ArtifactProvenance(logicalArtifactName(target),
                ArtifactProvenance.Role.APPLICATION, targetHash,
                regularFileSize(target)));
        for (int i = 0; i < dependencies.size(); i++) {
            Path dependency = dependencies.get(i);
            String hash = i < dependencyHashes.size() ? dependencyHashes.get(i) : "UNKNOWN";
            result.add(new ArtifactProvenance(logicalArtifactName(dependency),
                    ArtifactProvenance.Role.DEPENDENCY, hash, regularFileSize(dependency)));
        }
        if (jdkSource != null) {
            result.add(ArtifactProvenance.unknown("jdk:" + Math.max(0, targetFeature),
                    ArtifactProvenance.Role.JDK));
        }
        return List.copyOf(result);
    }

    private static Map<String, ArtifactProvenance> hopArtifactOwners(
            BytecodeFrontend.ScopedLoad scopedLoad, List<ArtifactProvenance> artifacts) {
        if (scopedLoad == null || scopedLoad.classArtifactIndexes().isEmpty()
                || artifacts == null || artifacts.isEmpty()) {
            return Map.of();
        }
        Map<String, ArtifactProvenance> result = new LinkedHashMap<>();
        scopedLoad.classArtifactIndexes().forEach((className, index) -> {
            if (className == null || className.isBlank() || index == null
                    || index < 0 || index >= artifacts.size()) {
                return;
            }
            ArtifactProvenance artifact = artifacts.get(index);
            if (artifact != null) {
                result.putIfAbsent(className, artifact);
            }
        });
        return Map.copyOf(result);
    }

    private static String logicalArtifactName(Path path) {
        if (path == null || path.getFileName() == null) {
            return "<unknown>";
        }
        return path.getFileName().toString();
    }

    private static long regularFileSize(Path path) {
        try {
            return path != null && java.nio.file.Files.isRegularFile(path)
                    ? java.nio.file.Files.size(path) : -1L;
        } catch (IOException ignored) {
            return -1L;
        }
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
                                                JdkClassSource jdkSource, RuleSet rules,
                                                InputBudget.Tracker inputTracker)
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
        return frontend.load(application, selection.classes(), inputTracker);
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
            // Multi-release selection cannot be called target accurate when an external image
            // exposes no readable feature metadata.
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

    private record ScanMetricCapture(Map<String, Long> values,
                                     Map<String, String> status,
                                     Map<String, Map<String, Long>> namespaces,
                                     Map<String, String> namespaceStatus) {
    }

    /**
     * Process-local garbage-collector counters used to compare owner migrations.  MXBeans may
     * report {@code -1} on a collector that does not expose a counter; that case remains
     * UNKNOWN rather than being coerced to zero.  The counters are cumulative JVM observations,
     * so only a monotonic, fully observed delta is published for one scan.
     */
    static record GcSnapshot(long collectionCount, long collectionTimeMs, boolean observed) {
        static GcSnapshot unknown() {
            return new GcSnapshot(-1L, -1L, false);
        }

        GcSnapshot delta(GcSnapshot before) {
            if (before == null || !observed || !before.observed()
                    || collectionCount < before.collectionCount()
                    || collectionTimeMs < before.collectionTimeMs()) {
                return unknown();
            }
            return new GcSnapshot(collectionCount - before.collectionCount(),
                    collectionTimeMs - before.collectionTimeMs(), true);
        }
    }

    /** Read all available JVM collector counters without making telemetry a scan dependency. */
    static GcSnapshot gcSnapshot() {
        long count = 0L;
        long timeMs = 0L;
        boolean any = false;
        try {
            for (java.lang.management.GarbageCollectorMXBean bean
                    : java.lang.management.ManagementFactory.getGarbageCollectorMXBeans()) {
                if (bean == null) {
                    continue;
                }
                any = true;
                long beanCount = bean.getCollectionCount();
                long beanTime = bean.getCollectionTime();
                if (beanCount < 0L || beanTime < 0L) {
                    return GcSnapshot.unknown();
                }
                count = saturatedAdd(count, beanCount);
                timeMs = saturatedAdd(timeMs, beanTime);
            }
        } catch (RuntimeException ignored) {
            return GcSnapshot.unknown();
        }
        return any ? new GcSnapshot(count, timeMs, true) : GcSnapshot.unknown();
    }

    private static long saturatedAdd(long left, long right) {
        if (right > 0L && left > Long.MAX_VALUE - right) {
            return Long.MAX_VALUE;
        }
        return left + right;
    }

    /**
     * Build one deterministic telemetry snapshot at the report boundary.  Engine counters
     * are observed facts; application anchoring/join/DAG counters remain UNKNOWN until the
     * typed evidence model exists.  Keeping the axes explicit prevents a raw chain count from
     * being mistaken for an application finding or a kernel result.
     */
    private static ScanMetricCapture scanMetricCapture(BuiltCpg cpg, Blackboard blackboard,
                                                       List<Chain> chains,
                                                       Map<String, List<String>> chainNotes,
                                                       long parentCpuStarted,
                                                       int entryCandidates,
                                                       Map<String, Long> phaseMs,
                                                       GcSnapshot gcDelta,
                                                       ApplicationChainEvidence applicationEvidence,
                                                       DependencyGraph dependencyGraph,
                                                       DependencyPreparation dependencyPreparation,
                                                       long totalWallMs) {
        ForwardRunMetrics forward = latestForwardMetrics(blackboard);
        Map<String, Long> metrics = scanMetrics(cpg, blackboard, chains, chainNotes,
                parentCpuStarted, forward);
        List<Chain> observedChains = chains == null ? List.of() : chains;
        long unresolved = observedChains.stream().filter(chain -> chain.unresolvedHops() > 0).count();
        long structurallyComplete = observedChains.stream()
                .filter(chain -> chain.unresolvedHops() == 0).count();
        long terminal = observedChains.stream().filter(Chain::terminalSink).count();
        long hopTotal = observedChains.stream().mapToLong(chain -> chain.hops().size()).sum();
        long hopMax = observedChains.stream().mapToLong(chain -> chain.hops().size()).max().orElse(0L);
        long bridgeHops = observedChains.stream().flatMap(chain -> chain.hops().stream())
                .filter(hop -> hop.reason() != null && hop.reason().startsWith("bridge-"))
                .count();
        long noteCount = chainNotes == null ? 0L
                : chainNotes.values().stream().filter(java.util.Objects::nonNull)
                .mapToLong(List::size).sum();
        io.just.sast.analysis.entry.ApplicationEntryIndex entryIndex =
                blackboard.applicationEntryIndex();
        long indexedEntries = entryIndex == null ? -1L : entryIndex.applicationEntries().size();
        long indexedSites = entryIndex == null ? -1L : entryIndex.deserializeSites().size();
        long indexedTerminals = entryIndex == null ? -1L : entryIndex.terminalImpacts().size();
        long indexedForward = entryIndex == null ? -1L : entryIndex.entryForwardSlice().size();
        long indexedReverse = entryIndex == null ? -1L : entryIndex.sinkReverseSlice().size();
        long indexedIntersection = entryIndex == null ? -1L
                : entryIndex.entryTerminalIntersection().size();
        long indexedDependencies = entryIndex == null ? -1L
                : entryIndex.dependencyCandidates().size();
        long applicationSites = applicationEvidence == null ? -1L
                : applicationEvidence.joins().values().stream()
                .map(io.just.sast.blackboard.EntryChainJoinEvidence::applicationSiteAtomId)
                .distinct().count();
        long candidateJoins = applicationEvidence == null ? -1L
                : applicationEvidence.candidateJoinCount();
        long validatedJoins = applicationEvidence == null ? -1L
                : applicationEvidence.joinCount();
        long joinedDependencySegments = validatedJoins;
        long completeAnchoredChains = applicationEvidence == null ? -1L
                : applicationEvidence.states().values().stream()
                .filter(io.just.sast.blackboard.FindingState::impactComplete).count();
        long anchoredCandidates = applicationEvidence == null ? -1L
                : applicationEvidence.anchoredCandidateCount();
        long admissionInput = applicationEvidence == null ? -1L
                : applicationEvidence.admissionDecisions().size();
        long admissionCandidates = applicationEvidence == null ? -1L
                : applicationEvidence.admissionCandidateCount();
        long admissionRejected = applicationEvidence == null ? -1L
                : applicationEvidence.admissionRejectedCount();
        Blackboard.SolverAdmissionMetrics solverAdmission = blackboard == null
                ? new Blackboard.SolverAdmissionMetrics(0, 0, 0, 0, 0, 0, Map.of())
                : blackboard.solverAdmissionMetrics();
        long unresolvedBridges = applicationEvidence == null ? -1L
                : applicationEvidence.graph().nodes().stream()
                .filter(node -> node instanceof io.just.sast.blackboard.BridgeEvidence bridge
                        && bridge.status() != io.just.sast.blackboard.BridgeEvidence.Status.PROVED)
                .count();
        long evidenceDagNodes = applicationEvidence == null ? -1L
                : applicationEvidence.graph().nodes().size();
        long evidenceDagEdges = applicationEvidence == null ? -1L
                : applicationEvidence.graph().edges().size();

        // Preserve the existing flat counters for compatibility, then add namespaced aliases.
        metrics.put("chain_candidate_count", (long) observedChains.size());
        metrics.put("chain_structurally_complete_count", structurallyComplete);
        metrics.put("chain_unresolved_count", unresolved);
        metrics.put("chain_terminal_count", terminal);
        metrics.put("chain_hop_total", hopTotal);
        metrics.put("chain_hop_max", hopMax);
        metrics.put("chain_bridge_hop_count", bridgeHops);
        metrics.put("chain_note_count", noteCount);
        metrics.put("application_entry_candidates", Math.max(0L, entryCandidates));
        metrics.put("application_entry_sites_candidates", Math.max(0L, entryCandidates));
        metrics.put("entry_index_application_entries", indexedEntries);
        metrics.put("entry_index_deserialize_sites", indexedSites);
        metrics.put("entry_index_terminal_impacts", indexedTerminals);
        metrics.put("entry_index_forward_methods", indexedForward);
        metrics.put("entry_index_reverse_methods", indexedReverse);
        metrics.put("entry_index_intersection_methods", indexedIntersection);
        metrics.put("entry_index_dependency_candidates", indexedDependencies);
        metrics.put("application_sites", applicationSites);
        metrics.put("candidate_joins", candidateJoins);
        metrics.put("validated_joins", validatedJoins);
        metrics.put("joined_dependency_segments", joinedDependencySegments);
        metrics.put("complete_anchored_chains", completeAnchoredChains);
        metrics.put("anchored_candidates", anchoredCandidates);
        metrics.put("application_admission_input", admissionInput);
        metrics.put("application_admission_candidates", admissionCandidates);
        metrics.put("application_admission_rejected", admissionRejected);
        metrics.put("solver_admission_input", solverAdmission.input());
        metrics.put("solver_application_chains", solverAdmission.applicationChains());
        metrics.put("solver_bridge_continuations", solverAdmission.bridgeContinuations());
        metrics.put("solver_dependency_suffixes", solverAdmission.dependencySuffixes());
        metrics.put("solver_kernel_only", solverAdmission.kernelOnly());
        metrics.put("solver_rejected", solverAdmission.rejected());
        metrics.put("unresolved_bridges", unresolvedBridges);
        metrics.put("dag_nodes", evidenceDagNodes);
        metrics.put("dag_edges", evidenceDagEdges);
        metrics.put("gc_collection_count", gcDelta == null || !gcDelta.observed()
                ? -1L : gcDelta.collectionCount());
        metrics.put("gc_collection_time_ms", gcDelta == null || !gcDelta.observed()
                ? -1L : gcDelta.collectionTimeMs());
        metrics.put("dependency_resolution_ms", dependencyPreparation.resolutionWallMs());
        metrics.put("network_download_wall_ms", dependencyPreparation.networkDownloadWallMs());
        metrics.put("network_request_ms", dependencyPreparation.networkRequestMs());
        metrics.put("dependency_transferred_bytes", dependencyPreparation.transferredBytes());
        metrics.put("dependency_completed_artifacts",
                (long) dependencyPreparation.completedArtifacts());
        metrics.put("dependency_cache_artifacts", (long) dependencyPreparation.cacheArtifacts());
        metrics.put("dependency_remote_artifacts", (long) dependencyPreparation.remoteArtifacts());
        for (DependencyGraph.Source source : DependencyGraph.Source.values()) {
            metrics.put("dependency_source_" + source.name().toLowerCase(java.util.Locale.ROOT),
                    dependencySourceCount(dependencyGraph, source));
        }
        metrics.put("analysis_ms", phaseMs.getOrDefault("analysis", -1L));
        long filterMs = blackboard.originSupport().finiteFilterMs();
        long filterEvaluations = blackboard.originSupport().finiteFilterEvaluations();
        metrics.put("filter_ms", filterMs);
        metrics.put("filter_evaluations", filterEvaluations);
        metrics.put("filter_retained", blackboard.originSupport().finiteFilterRetained());
        metrics.put("filter_rejections", blackboard.originSupport().finiteFilterRejections());
        metrics.put("filter_expanded", blackboard.originSupport().finiteFilterExpanded());
        metrics.put("filter_unknown", blackboard.originSupport().finiteFilterUnknown());
        metrics.put("filter_budget_exceeded", blackboard.originSupport().finiteFilterBudgetExceeded());
        metrics.put("filter_cache_hits", blackboard.originSupport().finiteFilterCacheHits());
        metrics.put("filter_cache_misses", blackboard.originSupport().finiteFilterCacheMisses());
        metrics.put("filter_cache_size", (long) blackboard.originSupport().finiteFilterCacheSize());
        metrics.put("report_ms", phaseMs.getOrDefault("report", -1L));
        metrics.put("total_wall_ms", totalWallMs);
        addPassTelemetry(metrics, phaseMs, "frontend", "frontend", -1L);
        addPassTelemetry(metrics, phaseMs, "cpg", "cpg", cpg.index().cfgCacheHits());
        addPassTelemetry(metrics, phaseMs, "analysis", "analysis",
                blackboard.originSupport().forwardOriginCacheHits());
        addPassTelemetry(metrics, phaseMs, "calibration", "blackboard.calibration", -1L);
        addPassTelemetry(metrics, phaseMs, "composition", "blackboard.composition", -1L);
        addPassTelemetry(metrics, phaseMs, "report", "report", 0L);
        // A negative value is the stable numeric representation of UNKNOWN.  Its availability
        // is recorded separately below and consumers must not coerce it to zero.
        for (String name : List.of("application_sites", "candidate_joins", "validated_joins",
                "joined_dependency_segments", "complete_anchored_chains", "anchored_candidates",
                "unresolved_bridges", "avoided_states", "materialized_states", "dag_nodes",
                "dag_edges", "representative_paths", "kernel_only_results")) {
            metrics.putIfAbsent(name, -1L);
        }

        Map<String, String> status = new java.util.LinkedHashMap<>();
        metrics.keySet().forEach(name -> status.put(name, "OBSERVED"));
        if (forward == null) {
            for (String name : ForwardRunMetrics.metricNames()) {
                status.put(name, "UNKNOWN");
            }
        }
        status.put("application_entry_candidates", "CANDIDATE_ONLY");
        status.put("application_entry_sites_candidates", "CANDIDATE_ONLY");
        status.put("entry_index_application_entries", indexedEntries < 0L ? "UNKNOWN" : "OBSERVED");
        status.put("entry_index_deserialize_sites", indexedSites < 0L ? "UNKNOWN" : "OBSERVED");
        status.put("entry_index_terminal_impacts", indexedTerminals < 0L ? "UNKNOWN" : "OBSERVED");
        status.put("entry_index_forward_methods", indexedForward < 0L ? "UNKNOWN" : "OBSERVED");
        status.put("entry_index_reverse_methods", indexedReverse < 0L ? "UNKNOWN" : "OBSERVED");
        status.put("entry_index_intersection_methods", indexedIntersection < 0L ? "UNKNOWN" : "OBSERVED");
        status.put("entry_index_dependency_candidates", indexedDependencies < 0L ? "UNKNOWN" : "OBSERVED");
        String gcStatus = gcDelta == null || !gcDelta.observed() ? "UNKNOWN" : "OBSERVED";
        status.put("gc_collection_count", gcStatus);
        status.put("gc_collection_time_ms", gcStatus);
        String dependencyTimingStatus = dependencyPreparation.status()
                == DependencyPreparation.DependencyStatus.NOT_PROVIDED
                ? "NOT_APPLICABLE" : "OBSERVED";
        for (String name : List.of("dependency_resolution_ms", "network_download_wall_ms",
                "network_request_ms", "dependency_transferred_bytes",
                "dependency_completed_artifacts", "dependency_cache_artifacts",
                "dependency_remote_artifacts")) {
            status.put(name, dependencyTimingStatus);
        }
        for (DependencyGraph.Source source : DependencyGraph.Source.values()) {
            status.put("dependency_source_" + source.name().toLowerCase(java.util.Locale.ROOT),
                    "OBSERVED");
        }
        status.put("analysis_ms", phaseMs.containsKey("analysis") ? "OBSERVED" : "UNKNOWN");
        String filterStatus = filterEvaluations == 0L
                ? "NOT_APPLICABLE" : "OBSERVED";
        for (String name : List.of("filter_ms", "filter_evaluations", "filter_retained",
                "filter_rejections", "filter_expanded", "filter_unknown",
                "filter_budget_exceeded", "filter_cache_hits", "filter_cache_misses",
                "filter_cache_size")) {
            status.put(name, filterStatus);
        }
        status.put("report_ms", phaseMs.containsKey("report") ? "OBSERVED" : "UNKNOWN");
        status.put("total_wall_ms", "OBSERVED");
        for (String name : List.of("application_sites", "candidate_joins", "validated_joins",
                "joined_dependency_segments", "complete_anchored_chains", "anchored_candidates",
                "unresolved_bridges", "avoided_states", "materialized_states", "dag_nodes",
                "dag_edges", "representative_paths")) {
            // A present evidence product does not make every derived telemetry field
            // observed.  The state/materialization/path counters are intentionally not
            // implemented yet and use -1 as UNKNOWN; advertising them as OBSERVED makes
            // the run-level metrics contract reject an otherwise valid static scan.
            long value = metrics.getOrDefault(name, -1L);
            status.put(name, applicationEvidence == null || value < 0L ? "UNKNOWN" : "OBSERVED");
        }
        status.put("kernel_only_results", "NOT_REQUESTED");
        addPassTelemetryStatus(status, metrics, phaseMs, "frontend", "frontend", false);
        addPassTelemetryStatus(status, metrics, phaseMs, "cpg", "cpg", true);
        addPassTelemetryStatus(status, metrics, phaseMs, "analysis", "analysis", true);
        addPassTelemetryStatus(status, metrics, phaseMs, "calibration", "blackboard.calibration", false);
        addPassTelemetryStatus(status, metrics, phaseMs, "composition", "blackboard.composition", false);
        addPassTelemetryStatus(status, metrics, phaseMs, "report", "report", true);

        Map<String, Long> application = new java.util.LinkedHashMap<>();
        application.put("entries", indexedEntries < 0L ? (long) Math.max(0, entryCandidates)
                : indexedEntries);
        application.put("sites", indexedSites);
        application.put("entry_index_forward_methods", indexedForward);
        application.put("entry_index_reverse_methods", indexedReverse);
        application.put("entry_index_intersection_methods", indexedIntersection);
        application.put("entry_index_dependency_candidates", indexedDependencies);
        application.put("application_sites", applicationSites);
        application.put("candidate_joins", candidateJoins);
        application.put("validated_joins", validatedJoins);
        application.put("joined_dependency_segments", joinedDependencySegments);
        application.put("complete_anchored_chains", completeAnchoredChains);
        application.put("anchored_candidates", anchoredCandidates);
        application.put("admission_input", admissionInput);
        application.put("admission_candidates", admissionCandidates);
        application.put("admission_rejected", admissionRejected);
        application.put("unresolved_bridges", unresolvedBridges);
        application.put("dag_nodes", evidenceDagNodes);
        application.put("dag_edges", evidenceDagEdges);
        Map<String, Long> analysis = new java.util.LinkedHashMap<>();
        analysis.put("raw_chain_candidates", (long) observedChains.size());
        analysis.put("structurally_complete_chains", structurallyComplete);
        analysis.put("unresolved_chain_candidates", unresolved);
        analysis.put("solver_admission_input", solverAdmission.input());
        analysis.put("solver_application_chains", solverAdmission.applicationChains());
        analysis.put("solver_bridge_continuations", solverAdmission.bridgeContinuations());
        analysis.put("solver_dependency_suffixes", solverAdmission.dependencySuffixes());
        analysis.put("solver_kernel_only", solverAdmission.kernelOnly());
        analysis.put("solver_rejected", solverAdmission.rejected());
        analysis.put("materialized_states", -1L);
        analysis.put("avoided_states", -1L);
        analysis.put("dag_nodes", -1L);
        analysis.put("dag_edges", -1L);
        analysis.put("representative_paths", -1L);
        analysis.put("forward_origin_cache_bytes_estimate",
                blackboard.originSupport().forwardOriginCacheBytesEstimate());
        analysis.put("filter_ms", filterMs);
        analysis.put("filter_evaluations", filterEvaluations);
        analysis.put("filter_retained", blackboard.originSupport().finiteFilterRetained());
        analysis.put("filter_rejections", blackboard.originSupport().finiteFilterRejections());
        analysis.put("filter_expanded", blackboard.originSupport().finiteFilterExpanded());
        analysis.put("filter_unknown", blackboard.originSupport().finiteFilterUnknown());
        analysis.put("filter_budget_exceeded", blackboard.originSupport().finiteFilterBudgetExceeded());
        analysis.put("filter_cache_hits", blackboard.originSupport().finiteFilterCacheHits());
        analysis.put("filter_cache_misses", blackboard.originSupport().finiteFilterCacheMisses());
        analysis.put("filter_cache_size", (long) blackboard.originSupport().finiteFilterCacheSize());
        if (forward != null) {
            analysis.putAll(forward.asMetrics());
        } else {
            for (String name : ForwardRunMetrics.metricNames()) {
                analysis.put(name, -1L);
            }
        }
        Map<String, Long> kernel = new java.util.LinkedHashMap<>();
        kernel.put("kernel_only_results", -1L);

        Map<String, Map<String, Long>> namespaces = new java.util.LinkedHashMap<>();
        namespaces.put("analysis", analysis);
        namespaces.put("application", application);
        namespaces.put("kernel", kernel);
        Map<String, String> namespaceStatus = new java.util.LinkedHashMap<>();
        namespaceStatus.put("analysis", "OBSERVED");
        namespaceStatus.put("application", applicationEvidence == null ? "UNKNOWN" : "OBSERVED");
        namespaceStatus.put("kernel", "NOT_REQUESTED");
        return new ScanMetricCapture(metrics, status, namespaces, namespaceStatus);
    }

    private static long dependencySourceCount(DependencyGraph graph,
                                              DependencyGraph.Source source) {
        return graph.nodes().values().stream().filter(node -> node.source() == source).count();
    }

    private static ApplicationChainEvidence latestApplicationChainEvidence(Blackboard blackboard) {
        if (blackboard == null) {
            return null;
        }
        List<ApplicationChainEvidence> facts = blackboard.facts(ApplicationChainEvidence.class);
        return facts.isEmpty() ? null : facts.get(facts.size() - 1);
    }

    private static ForwardRunMetrics latestForwardMetrics(Blackboard blackboard) {
        if (blackboard == null) {
            return null;
        }
        List<ForwardRunMetrics> facts = blackboard.facts(ForwardRunMetrics.class);
        return facts.isEmpty() ? null : facts.get(facts.size() - 1);
    }

    /** Add pass timing/cache fields without pretending phase-local RSS was sampled. */
    private static void addPassTelemetry(Map<String, Long> values, Map<String, Long> phaseMs,
                                         String pass, String phase,
                                         long cacheHits) {
        long duration = phaseMs == null ? -1L : phaseMs.getOrDefault(phase, -1L);
        values.put("pass_" + pass + "_time_ms", duration);
        values.put("pass_" + pass + "_rss_peak_mb", -1L);
        values.put("pass_" + pass + "_cache_hits", cacheHits);
    }

    private static void addPassTelemetryStatus(Map<String, String> statuses,
                                               Map<String, Long> values,
                                               Map<String, Long> phaseMs, String pass,
                                               String phase, boolean cacheObserved) {
        String time = "pass_" + pass + "_time_ms";
        String rss = "pass_" + pass + "_rss_peak_mb";
        String cache = "pass_" + pass + "_cache_hits";
        statuses.put(time, phaseMs != null && phaseMs.containsKey(phase) ? "OBSERVED" : "UNKNOWN");
        statuses.put(rss, "UNKNOWN");
        statuses.put(cache, cacheObserved ? "OBSERVED" : "NOT_APPLICABLE");
        // Keep the helper defensive if a future phase spec is edited independently.
        values.putIfAbsent(time, -1L);
        values.putIfAbsent(rss, -1L);
        values.putIfAbsent(cache, -1L);
    }

    private static Map<String, Long> scanMetrics(BuiltCpg cpg, Blackboard blackboard,
                                                 List<Chain> chains,
                                                 Map<String, List<String>> chainNotes,
                                                 long parentCpuStarted,
                                                 ForwardRunMetrics forward) {
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
        metrics.put("forward_origin_cache_bytes_estimate",
                blackboard.originSupport().forwardOriginCacheBytesEstimate());
        metrics.put("forward_origin_compute_calls",
                blackboard.originSupport().forwardOriginComputeCalls());
        metrics.put("forward_origin_cache_hits",
                blackboard.originSupport().forwardOriginCacheHits());
        metrics.put("forward_origin_analysis_runs",
                blackboard.originSupport().forwardOriginAnalysisRuns());
        if (forward != null) {
            metrics.putAll(forward.asMetrics());
        } else {
            for (String name : ForwardRunMetrics.metricNames()) {
                metrics.put(name, -1L);
            }
        }
        // RSS is optional telemetry and remains UNKNOWN when the host does not expose it.
        metrics.put("parent_rss_mb", -1L);
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
        for (Chain chain : blackboard.reportChains()) {
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
        return loadRules(rulesFile, InputBudget.defaults());
    }

    private static RuleSet loadRules(Path rulesFile, InputBudget budget) throws IOException {
        return loadRules(rulesFile, budget, null);
    }

    /** Load rules under the scan-boundary tracker; compatibility callers keep the local path. */
    private static RuleSet loadRules(Path rulesFile, InputBudget budget,
                                     InputBudget.Tracker tracker) throws IOException {
        YamlRuleLoader loader = new YamlRuleLoader();
        InputBudget requested = budget == null ? InputBudget.defaults() : budget;
        InputBudget policy = tracker == null ? requested : tracker.budget();
        if (rulesFile != null) {
            ArchiveLimits.FileReadSnapshot snapshot = ArchiveLimits.snapshotRegularFile(
                    rulesFile, policy, "RULES");
            IOException failure = null;
            RuleSet custom = null;
            try (InputStream in = io.just.sast.util.IoUtil.openNoFollow(rulesFile, "RULES")) {
                custom = loader.load(in, policy, tracker);
            } catch (IOException parseFailure) {
                failure = parseFailure;
            }
            try {
                ArchiveLimits.verifyRegularFileUnchanged(snapshot, "RULES");
            } catch (IOException changed) {
                if (failure == null) {
                    failure = changed;
                } else {
                    failure.addSuppressed(changed);
                }
            }
            if (failure != null) {
                throw failure;
            }
            // Container summaries are part of the scanner's JVM value-flow contract,
            // not a requirement every project-specific sink file must duplicate. Keep
            // user sinks/entries/sources authoritative, while supplying missing generic
            // Map/List/Deque summaries from the bundled rule data. An identical custom
            // matcher wins by omission; a more specific custom matcher is still selected
            // by RuleEngine's normal specificity ordering.
            RuleSet bundled = loadBundledRules(loader, policy, tracker);
            List<Rule.ModelRule> models = new ArrayList<>(custom.models());
            for (Rule.ModelRule model : bundled.models()) {
                if (models.stream().noneMatch(existing -> existing.call().equals(model.call()))) {
                    models.add(model);
                }
            }
            List<Rule.ConditionRule> conditions = new ArrayList<>(custom.conditions());
            for (Rule.ConditionRule condition : bundled.conditions()) {
                if (conditions.stream().noneMatch(existing -> existing.id().equals(condition.id()))) {
                    conditions.add(condition);
                }
            }
            return new RuleSet(custom.sinks(), custom.magicEntries(), custom.sources(),
                    models, custom.fragments(), conditions, custom.schemaVersion());
        }
        return loadBundledRules(loader, policy, tracker);
    }

    private static RuleSet loadBundledRules(YamlRuleLoader loader) throws IOException {
        return loadBundledRules(loader, InputBudget.defaults());
    }

    private static RuleSet loadBundledRules(YamlRuleLoader loader, InputBudget budget) throws IOException {
        return loadBundledRules(loader, budget, null);
    }

    private static RuleSet loadBundledRules(YamlRuleLoader loader, InputBudget budget,
                                            InputBudget.Tracker tracker) throws IOException {
        try (InputStream in = ScanPipeline.class.getResourceAsStream("/rules/default-rules.yaml")) {
            if (in == null) {
                throw new IOException("内置规则文件不存在: /rules/default-rules.yaml");
            }
            return loader.load(in, budget == null ? InputBudget.defaults() : budget, tracker);
        }
    }

    /** Stable SHA-256 identity used by reports and cache keys. */
    private static String artifactHash(Path input) throws IOException {
        return artifactHash(input, InputBudget.defaults());
    }

    private static String artifactHash(Path input, InputBudget budget) throws IOException {
        return ArtifactFingerprint.sha256(input, budget);
    }

    private static String artifactHash(Path input, InputBudget.Tracker tracker) throws IOException {
        return ArtifactFingerprint.sha256(input, tracker);
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
