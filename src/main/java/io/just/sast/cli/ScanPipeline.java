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
import io.just.sast.util.JustLogger;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
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
        long start = System.currentTimeMillis();
        Map<String, Long> phaseMs = new java.util.LinkedHashMap<>();

        validatePath(target, "扫描目标", true);
        if (deps != null) {
            for (Path dep : deps) {
                validatePath(dep, "依赖", true);
            }
        }
        if (output == null) {
            throw new UsageException("输出目录不能为空");
        }
        if (Files.exists(output) && !Files.isDirectory(output)) {
            throw new UsageException("输出路径不是目录: " + output.toAbsolutePath());
        }
        if (verifyBudget < 0) {
            throw new UsageException("--verify-budget 不能为负数");
        }

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
        long frontendStart = System.currentTimeMillis();
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
        BytecodeFrontend frontend = new BytecodeFrontend();
        // 先解析 target/deps；完整模式随后只把应用引用、规则类型和 magic-entry 方法
        // 所需的 JDK 类体放进 CPG，避免对同一批应用字节重复读取/解析。
        // 把原始 ClassBytes 限制在独立 helper 的生命周期内。完整扫描需要的只是
        // ClassInfo；否则 JDK 切片规划期间 input 仍会把整批 fat-jar byte[] 挂住。
        LoadResult applicationLoad = loadApplication(frontend, targets);
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
        phaseMs.put("frontend", System.currentTimeMillis() - frontendStart);

        long cpgStart = System.currentTimeMillis();
        ClassHierarchy hierarchy = new ClassHierarchy(load.classes(), jdkSource);
        BuiltCpg cpg = new CpgBuilder().build(load);
        int callEdges = new CallGraphBuilder(hierarchy).build(cpg.graph());
        cpg.graph().freeze();
        JustLogger.info("CPG 构建完成：节点 {}，边 {}，调用边 {}，字段写入 {} 组",
                cpg.graph().nodeCount(), cpg.graph().edgeCount(), callEdges,
                cpg.fieldWriters().fieldCount());
        phaseMs.put("cpg", System.currentTimeMillis() - cpgStart);

        // 分析期（黑板串行三阶段：ANALYSIS → COMPOSITION → CALIBRATION）
        List<Path> scanDeps = deps != null ? deps : List.of();
        long analysisStart = System.currentTimeMillis();
        Blackboard blackboard = new Blackboard(cpg.graph(), hierarchy, cpg.fieldWriters(), cpg.index(), ruleSet, MAX_DEPTH,
                new Blackboard.ScanInputs(target.toAbsolutePath().normalize(), scanDeps, fast, verify,
                        verifyBudget, jdkHome, load.targetMajorVersion()));
        new Controller(blackboard, KnowledgeSources.discover()).run();
        phaseMs.put("analysis", System.currentTimeMillis() - analysisStart);

        // 报告期
        long reportStart = System.currentTimeMillis();
        ReportLayout reportLayout = ReportLayout.create(output);
        CsvReporter reporter = new CsvReporter();
        io.just.sast.report.MultiFormatReporter multiFormatReporter = new io.just.sast.report.MultiFormatReporter();
        reporter.withGraph(cpg.graph());
        reporter.write(reportLayout, blackboard.chains(), blackboard.sinkOutcomes(),
                blackboard.chainCalibrations(), blackboardNotes(blackboard));
        // C1: SARIF 2.1.0 + E1-E3: JSON/HTML/Markdown 多格式输出
        new io.just.sast.report.SarifReporter().withHierarchy(hierarchy).withRules(ruleSet).write(
                reportLayout, blackboard.chains(), blackboard.chainCalibrations(), blackboardNotes(blackboard));
        multiFormatReporter.write(reportLayout, blackboard.chains(),
                blackboard.chainCalibrations(), blackboardNotes(blackboard));
        new io.just.sast.report.PayloadPlanWriter().write(reportLayout, blackboard.chains(),
                blackboard.chainCalibrations(), blackboardNotes(blackboard),
                blackboard.verificationSummary());
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
        phaseMs.put("report", System.currentTimeMillis() - reportStart);
        Map<Long, io.just.sast.blackboard.SinkOutcome> outcomes = blackboard.sinkOutcomes();
        List<String> completenessReasons = completenessReasons(load, cpg.graph(), outcomes,
                blackboard.completenessReasons(), fast, jdkHome);
        ScanStatistics scanStats = new ScanStatistics(
                load.filesScanned(), load.classCount(), load.diagnosticCount(),
                sinkCount, entryCount, blackboard.chains().size(),
                System.currentTimeMillis() - start,
                (Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()) / 1024 / 1024,
                completenessReasons.isEmpty() ? "COMPLETE" : "PARTIAL",
                completenessReasons, phaseMs, verify ? blackboard.verificationStatus() : "DISABLED",
                verify ? blackboard.verificationSummary()
                        : io.just.sast.blackboard.VerificationSummary.empty("DISABLED", verifyBudget));
        multiFormatReporter.writeMetadata(reportLayout, scanStats);
        new ReportIndexWriter().write(reportLayout, scanStats);
        if (stats) {
            ConsoleSummary.print(scanStats, outcomes);
        }
        return new ScanResult(ExitCode.OK.code(), blackboard.chains(), scanStats);
    }

    private static LoadResult loadApplication(BytecodeFrontend frontend, List<Path> targets) {
        return frontend.loadStreaming(targets);
    }

    /**
     * Keep the complete JDK source list alive only during closure planning.  The selected
     * bytes are the only external input that the next parse phase needs; putting this scope
     * in a helper also gives the GC/JIT a clear lifetime boundary for large target JDKs.
     */
    private static LoadResult loadWithJdkSlice(BytecodeFrontend frontend, LoadResult application,
                                                JdkClassSource jdkSource, RuleSet rules)
            throws IOException {
        List<ClassBytes> selected;
        JdkClassSelector.Selection selection;
        {
            List<ClassBytes> availableJdk;
            if (jdkSource instanceof TargetJdkSource targetJdk) {
                availableJdk = targetJdk.listAll();
            } else {
                availableJdk = ((JrtClassSource) jdkSource).listAll(JrtClassSource.DESER_MODULES);
            }
            selection = JdkClassSelector.selectDetailed(availableJdk,
                    application.classes(), jdkTypeSeeds(rules), jdkEntrySeeds(rules));
            selected = selection.classes();
        }
        JustLogger.info("JDK 类切片：可用 {} 个，header {} 个，初始种子 {} 个，隐式 entry 新增 {} 个，闭包物化 {} 个",
                selection.availableClasses(), selection.headerClasses(), selection.initialSeeds(),
                selection.implicitEntrySeeds(), selection.closureClasses());
        return frontend.load(application, selected);
    }

    /** 将“没有发现”与“分析曾触顶/跳过内容”区分开，原因使用稳定类别而不泄漏路径。 */
    private static List<String> completenessReasons(LoadResult load, io.just.sast.cpg.graph.Graph graph,
                                                     Map<Long, io.just.sast.blackboard.SinkOutcome> outcomes,
                                                     java.util.Set<String> analysisReasons,
                                                     boolean fast, Path jdkHome) {
        LinkedHashSet<String> reasons = new LinkedHashSet<>(load.completenessReasons());
        reasons.addAll(analysisReasons);
        if (fast) {
            reasons.add("FAST_MODE");
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

    private static void validatePath(Path path, String label, boolean allowDirectory)
            throws UsageException {
        if (path == null) {
            throw new UsageException(label + "不能为空");
        }
        if (!Files.exists(path)) {
            throw new UsageException(label + "不存在: " + path.toAbsolutePath());
        }
        if (!Files.isRegularFile(path) && !(allowDirectory && Files.isDirectory(path))) {
            throw new UsageException(label + "不是普通文件或目录: " + path.toAbsolutePath());
        }
    }

    /** 链级注释视图（有注释的链 key → 注释列表快照，报告层消费）。 */
    private static Map<String, List<String>> blackboardNotes(Blackboard blackboard) {
        Map<String, List<String>> notes = new HashMap<>();
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
                return loader.load(in);
            }
        }
        try (InputStream in = ScanPipeline.class.getResourceAsStream("/rules/default-rules.yaml")) {
            return loader.load(in);
        }
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
        }
        return seeds;
    }

    private static void addTypeSeed(java.util.Set<String> seeds, String name) {
        if (name != null && !name.isEmpty() && !name.startsWith("~")) {
            seeds.add(name);
        }
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
