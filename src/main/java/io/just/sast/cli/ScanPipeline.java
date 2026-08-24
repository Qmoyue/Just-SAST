package io.just.sast.cli;

import io.just.sast.analysis.callgraph.CallGraphBuilder;
import io.just.sast.analysis.hierarchy.ClassHierarchy;
import io.just.sast.blackboard.Blackboard;
import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.Controller;
import io.just.sast.config.RuleSet;
import io.just.sast.config.YamlRuleLoader;
import io.just.sast.cpg.build.BuiltCpg;
import io.just.sast.cpg.build.CpgBuilder;
import io.just.sast.cpg.graph.Node;
import io.just.sast.cpg.graph.NodeType;
import io.just.sast.frontend.asm.BytecodeFrontend;
import io.just.sast.frontend.asm.ClassBytes;
import io.just.sast.frontend.asm.JrtClassSource;
import io.just.sast.frontend.asm.TargetJdkSource;
import io.just.sast.model.JdkClassSource;
import io.just.sast.model.LoadResult;
import io.just.sast.report.ConsoleSummary;
import io.just.sast.report.CsvReporter;
import io.just.sast.report.ScanStatistics;
import io.just.sast.util.JustLogger;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
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
                                 boolean stats, boolean fast, Path jdkHome, boolean verify) throws Exception {
        long start = System.currentTimeMillis();

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
        JdkClassSource jdkSource;
        List<ClassBytes> jdkClasses;
        if (jdkHome != null) {
            TargetJdkSource targetJdk;
            try {
                targetJdk = new TargetJdkSource(jdkHome);
            } catch (IOException e) {
                throw new UsageException("--jdk-home 加载失败: " + e.getMessage());
            }
            jdkSource = targetJdk;
            jdkClasses = fast ? List.of() : targetJdk.listAll();
            JustLogger.info("使用目标 JDK：{}（--jdk-home={}）", targetJdk.description(), jdkHome);
        } else {
            JrtClassSource jrt = JrtClassSource.runtime();
            jdkSource = jrt;
            jdkClasses = fast ? List.of() : jrt.listAll(JrtClassSource.DESER_MODULES);
        }
        BytecodeFrontend frontend = new BytecodeFrontend();
        LoadResult load = fast ? frontend.load(targets) : frontend.load(targets, jdkClasses);
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

        ClassHierarchy hierarchy = new ClassHierarchy(load.classes(), jdkSource);
        BuiltCpg cpg = new CpgBuilder().build(load);
        int callEdges = new CallGraphBuilder(hierarchy).build(cpg.graph());
        cpg.graph().freeze();
        JustLogger.info("CPG 构建完成：节点 {}，边 {}，调用边 {}，字段写入 {} 组",
                cpg.graph().nodeCount(), cpg.graph().edgeCount(), callEdges,
                cpg.fieldWriters().fieldCount());

        // 分析期（黑板串行三阶段：ANALYSIS → COMPOSITION → CALIBRATION）
        List<Path> scanDeps = deps != null ? deps : List.of();
        Blackboard blackboard = new Blackboard(cpg.graph(), hierarchy, cpg.fieldWriters(), ruleSet, MAX_DEPTH,
                new Blackboard.ScanInputs(target.toAbsolutePath().normalize(), scanDeps, fast, verify));
        new Controller(blackboard, KnowledgeSources.discover()).run();

        // 报告期
        CsvReporter reporter = new CsvReporter();
        reporter.withGraph(cpg.graph());
        reporter.write(output, blackboard.chains(), blackboard.sinkOutcomes(),
                blackboard.chainCalibrations(), blackboardNotes(blackboard));
        // C1: SARIF 2.1.0 + E1-E3: JSON/HTML/Markdown 多格式输出
        new io.just.sast.report.SarifReporter().withHierarchy(hierarchy).withRules(ruleSet).write(
                output, blackboard.chains(), blackboard.chainCalibrations(), blackboardNotes(blackboard));
        new io.just.sast.report.MultiFormatReporter().write(output, blackboard.chains(),
                blackboard.chainCalibrations(), blackboardNotes(blackboard));
        JustLogger.info("CSV + SARIF 已输出到 {}", output.toAbsolutePath());

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
        ScanStatistics scanStats = new ScanStatistics(
                load.filesScanned(), load.classCount(), load.diagnosticCount(),
                sinkCount, entryCount, blackboard.chains().size(),
                System.currentTimeMillis() - start,
                (Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()) / 1024 / 1024);
        if (stats) {
            ConsoleSummary.print(scanStats, blackboard.sinkOutcomes());
        }
        return new ScanResult(ExitCode.OK.code(), blackboard.chains(), scanStats);
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
}
