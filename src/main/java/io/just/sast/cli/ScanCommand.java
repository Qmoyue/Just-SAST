package io.just.sast.cli;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.Callable;

/** scan 子命令：深度扫描 JAR/目录（默认含 JDK 运行库全量分析），导出 gadget 链 CSV。 */
@Command(name = "scan", description = "深度扫描 JAR/class 目录，挖掘反序列化 gadget 链并导出 CSV")
public final class ScanCommand implements Callable<Integer> {

    @Option(names = "--jar", required = true, paramLabel = "<jar|dir>",
            description = "目标 JAR 或 class 目录（支持 Spring Boot fat jar）")
    Path target;

    @Option(names = "--deps", split = ",", paramLabel = "<jar|dir,...>",
            description = "附加依赖（逗号分隔）")
    List<Path> deps;

    @Option(names = "--output", paramLabel = "<dir>", defaultValue = "just-out",
            description = "CSV 输出目录（默认 just-out）")
    Path output;

    @Option(names = "--rules", paramLabel = "<file>",
            description = "自定义规则 YAML（默认内置）")
    Path rules;

    @Option(names = "--fast", description = "快速模式：不加载 JDK 运行库全量（链可能不完整）")
    boolean fast;

    @Option(names = "--jdk-home", paramLabel = "<dir>",
            description = "目标 JDK/JRE 主目录（不指定则用运行时 JDK；Java 8 读 jre/lib/rt.jar，Java 9+ 走 jrt-fs）")
    Path jdkHome;

    @Option(names = "--stats", description = "输出扫描统计")
    boolean stats;

    @Override
    public Integer call() {
        try {
            return ScanPipeline.run(target, deps, output, rules, stats, fast, jdkHome).exitCode();
        } catch (ScanPipeline.UsageException e) {
            System.err.println("[just:error] " + e.getMessage());
            return ExitCode.USAGE.code();
        } catch (Exception e) {
            System.err.println("[just:error] 扫描失败: " + e);
            e.printStackTrace();
            return ExitCode.INTERNAL.code();
        }
    }
}
