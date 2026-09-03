package io.just.sast.cli;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import io.just.sast.report.ScanCache;

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

    @Option(names = "--no-verify",
            description = "关闭子进程链级动态验证（CI/不可执行环境；默认验证会在子 JVM 中真实执行入口方法）")
    boolean noVerify;

    @Option(names = "--safe-exec",
            description = "显式使用仅 canary 的兼容 adapter；默认动态验证走 LIGHT_SAFE_CALL")
    boolean safeExec;

    @Option(names = "--safe-real-sink",
            description = "显式声明 SAFE_REAL（默认动态验证已启用）；参数按签名替换为固定安全值，不执行危险命令/RCE")
    boolean safeRealSink;

    @Option(names = "--require-os-isolation",
            description = "动态验证要求 Job Object；不可用时返回 UNTESTABLE，不启动无隔离真实终点")
    boolean requireOsIsolation;

    @Option(names = "--baseline", paramLabel = "<scan-dir>",
            description = "按语义链身份比较已有扫描目录；只标记新增/不变/消失，不删除证据")
    Path baseline;

    @Option(names = "--suppressions", paramLabel = "<file>",
            description = "读取语义链身份、sha256:<digest> 或 rule:<id> 抑制项；默认只输出标记，不删除发现")
    Path suppressions;

    @Option(names = "--cache", paramLabel = "<dir>",
            description = "显式启用完整报告增量缓存；只缓存 COMPLETE 且无失败动态终态的扫描")
    Path cache;

    @Option(names = "--verify-budget", paramLabel = "<N>", defaultValue = "20",
            description = "子进程动态验证的链数预算（默认 20；按证据分值选取，同一入口类最多 2 条）")
    int verifyBudget;


    @Override
    public Integer call() {
        try {
            // SAFE_REAL is the product default for enabled dynamic verification. Windows uses
            // the same lightweight Job Object runner whether or not the explicit requirement
            // bit is set; the bit only changes the cache/report identity and failure policy.
            boolean useSafeReal = !noVerify && (safeRealSink || !safeExec);
            boolean useOsIsolation = requireOsIsolation;
            boolean useCache = cache != null && baseline == null && suppressions == null;
            if (cache != null && !useCache) {
                System.err.println("[just:info] --cache 与 baseline/suppressions 同时使用时跳过缓存，"
                        + "避免复用未应用当前差异策略的报告");
            }
            ScanCache.Preflight preflight = null;
            if (useCache) {
                try {
                    preflight = ScanCache.preflight(target, deps, rules, jdkHome, fast,
                            !noVerify, verifyBudget, safeExec, useSafeReal,
                            useOsIsolation);
                    if (ScanCache.restore(cache, preflight.cacheKey(), output)) {
                        System.err.println("[just:info] 增量缓存命中（报告身份已校验）");
                        return ExitCode.OK.code();
                    }
                } catch (java.io.IOException | RuntimeException cacheFailure) {
                    System.err.println("[just:warn] 增量缓存不可用，继续完整扫描: "
                            + cacheFailure.getClass().getSimpleName());
                }
            }
            ScanPipeline.ScanResult result = ScanPipeline.run(target, deps, output, rules, stats,
                    fast, jdkHome, !noVerify, verifyBudget, safeExec, useSafeReal,
                    useOsIsolation,
                    baseline, suppressions);
            if (useCache && preflight != null) {
                try {
                    boolean stored = ScanCache.store(cache, preflight.cacheKey(), output,
                            result.stats());
                    ScanCache.recordEvent(output, preflight.cacheKey(), stored ? "stored" : "not-stored");
                } catch (java.io.IOException | RuntimeException cacheFailure) {
                    System.err.println("[just:warn] 增量缓存未写入: "
                            + cacheFailure.getClass().getSimpleName());
                }
            }
            return result.exitCode();
        } catch (ScanPipeline.UsageException e) {
            System.err.println("[just:error] " + e.getMessage());
            return ExitCode.USAGE.code();
        } catch (Exception e) {
            System.err.println("[just:error] 扫描失败: " + e);
            return ExitCode.INTERNAL.code();
        }
    }
}
