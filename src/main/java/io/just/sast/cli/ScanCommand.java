package io.just.sast.cli;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import io.just.sast.report.ScanCache;
import io.just.sast.run.RunOutcome;
import io.just.sast.verify.VerificationDefaults;

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

    @Option(names = "--overwrite",
            description = "显式替换既有报告目录；新报告先在唯一 staging 中完成并原子交换")
    boolean overwrite;

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
            description = "关闭动态验证，仅执行静态分析；适用于来源不明或不可信制品（targetCodeExecutionPossible=false）")
    boolean noVerify;

    @Option(names = "--safe-exec",
            hidden = true,
            description = "已弃用的兼容调试选项；不改变目标信任模型")
    boolean safeExec;

    @Option(names = "--safe-real-sink",
            hidden = true,
            description = "已弃用的兼容调试选项；固定参数调用不等于 OS 访问控制边界或真实利用")
    boolean safeRealSink;

    @Option(names = "--require-os-isolation",
            hidden = true,
            description = "已弃用的兼容选项；动态验证始终 fail-closed，不会在无 Job Object 时启动目标")
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

    @Option(names = "--verify-budget", paramLabel = "<N>",
            defaultValue = VerificationDefaults.VERIFY_BUDGET_TEXT,
            description = "子进程动态验证的规范化 finding 组预算（默认 32；按证据分值选取）")
    int verifyBudget;


    @Override
    public Integer call() {
        try {
            printVerificationDisclosure(noVerify);
            // The default enabled mode is AUTO: static analysis completes first, then the
            // bounded verifier may load trusted target code behind a Job Object resource
            // boundary. Legacy adapter flags only select compatibility probes.
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
                        return RunOutcome.success().exitCode();
                    }
                } catch (java.io.IOException | RuntimeException cacheFailure) {
                    System.err.println("[just:warn] 增量缓存不可用，继续完整扫描: "
                            + cacheFailure.getClass().getSimpleName());
                }
            }
            ScanPipeline.ScanResult result = ScanPipeline.run(target, deps, output, rules, stats,
                    fast, jdkHome, !noVerify, verifyBudget, safeExec, useSafeReal,
                    useOsIsolation,
                    baseline, suppressions, overwrite,
                    ScanPipeline.ExportPolicy.STRICT_PRODUCT);
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
            return RunOutcome.usage("USAGE_ERROR", e.getMessage()).exitCode();
        } catch (Exception e) {
            System.err.println("[just:error] 扫描失败: " + e);
            return RunOutcome.failed("SCAN_FAILURE", e.getClass().getSimpleName()).exitCode();
        }
    }

    private static void printVerificationDisclosure(boolean noVerify) {
        if (noVerify) {
            System.err.println("[just:info] verificationMode=STATIC_ONLY; "
                    + "targetCodeExecutionPossible=false; targetCodeExecuted=NO; "
                    + "recommendedForUntrustedArtifacts=true");
            return;
        }
        System.err.println("[just:warning] verificationMode=AUTO; "
                + "targetCodeExecutionPossible=true; targetCodeExecuted=UNKNOWN; "
                + "targetTrust=TRUSTED_LOCAL_TARGET_REQUIRED; "
                + "resourceContainmentOnly=true; filesystemIsolation=false; "
                + "networkIsolation=false; recommendedForUntrustedArtifacts=false; "
                + "isolationFailure=FAIL_CLOSED; use --no-verify for untrusted artifacts");
    }
}
