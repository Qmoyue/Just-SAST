package io.just.sast.cli;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import io.just.sast.dependency.MavenDependencyGraphResolver;
import io.just.sast.report.ScanCache;
import io.just.sast.run.RunOutcome;
import io.just.sast.verify.VerificationDefaults;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Path;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.concurrent.Callable;

/** scan 子命令：深度扫描 JAR/目录（默认含 JDK 运行库全量分析），导出 gadget 链 CSV。 */
@Command(name = "scan", description = "深度扫描 JAR/class 目录，挖掘反序列化 gadget 链并导出 CSV")
public final class ScanCommand implements Callable<Integer> {

    @Option(names = "--jar", required = true, paramLabel = "<jar|dir>",
            description = "目标 JAR 或 class 目录（支持 Spring Boot fat jar）")
    Path target;

    @Option(names = "--mode", defaultValue = "component", paramLabel = "<component|application>",
            description = "扫描模式：component 挖掘组件/依赖机制链（默认）；application 要求真实应用入口与连接证据")
    String mode = "component";

    @Option(names = "--deps", split = ",", paramLabel = "<jar|dir,...>",
            description = "附加依赖（逗号分隔）")
    List<Path> deps;

    @Option(names = "--pom", paramLabel = "<pom.xml>",
            description = "显式 Maven 根 POM；只解析模型并补齐准确的 compile/runtime 制品")
    Path pom;

    @Option(names = "--repository", paramLabel = "<url>",
            description = "显式扩展 Maven 仓库（可重复；仅接受 file/http/https，不读取 POM 仓库）")
    List<String> repositories;

    @Option(names = "--offline",
            description = "禁止网络请求；只使用显式输入和已存在的完整 Maven 缓存")
    boolean offline;

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
            ScanMode selectedMode = ScanMode.parse(mode);
            ModeDemandPolicy modePolicy = ModeDemandPolicy.forMode(selectedMode);
            if (safeExec || safeRealSink || requireOsIsolation) {
                throw new ScanPipeline.UsageException(
                        "真实动态验证已移除；--mode/静态扫描不接受旧 verifier 选项");
            }
            printVerificationDisclosure();
            List<Path> scanDeps = resolveDependencies();
            // The product CLI is static-only.  The library compatibility overloads still
            // retain their old verifier seams for characterization until P1.4 removes them.
            boolean useSafeReal = false;
            boolean useOsIsolation = false;
            boolean useCache = selectedMode == ScanMode.APPLICATION
                    && cache != null && baseline == null && suppressions == null;
            if (selectedMode == ScanMode.COMPONENT && cache != null) {
                System.err.println("[just:info] component 模式暂不复用旧 cache；模式身份纳入新缓存契约后启用");
            }
            if (cache != null && !useCache) {
                System.err.println("[just:info] --cache 与 baseline/suppressions 同时使用时跳过缓存，"
                        + "避免复用未应用当前差异策略的报告");
            }
            ScanCache.Preflight preflight = null;
            if (useCache) {
                try {
                    preflight = ScanCache.preflight(target, scanDeps, rules, jdkHome, fast,
                            false, verifyBudget, false, false,
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
            ScanPipeline.ScanResult result = ScanPipeline.run(target, scanDeps, output, rules, stats,
                    fast, jdkHome, false, verifyBudget, false, false,
                    useOsIsolation,
                    baseline, suppressions, overwrite,
                    modePolicy);
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

    private List<Path> resolveDependencies() throws ScanPipeline.UsageException {
        List<Path> resolved = deps == null ? new ArrayList<>() : new ArrayList<>(deps);
        boolean hasRepositories = repositories != null && !repositories.isEmpty();
        if (pom == null) {
            if (offline || hasRepositories) {
                throw new ScanPipeline.UsageException(
                        "--offline/--repository 需要同时提供显式 --pom；无 POM 时 Just 不按类名猜包");
            }
            return List.copyOf(resolved);
        }

        List<MavenDependencyGraphResolver.RepositorySpec> selectedRepositories =
                new ArrayList<>();
        selectedRepositories.add(MavenDependencyGraphResolver.RepositorySpec.central());
        if (hasRepositories) {
            for (int index = 0; index < repositories.size(); index++) {
                String value = repositories.get(index);
                if (value == null || value.isBlank()) {
                    throw new ScanPipeline.UsageException("--repository URL 不能为空");
                }
                try {
                    selectedRepositories.add(new MavenDependencyGraphResolver.RepositorySpec(
                            "repository-" + (index + 1), URI.create(value)));
                } catch (IllegalArgumentException invalid) {
                    throw new ScanPipeline.UsageException("--repository 无效: "
                            + invalid.getMessage());
                }
            }
        }
        Path localRepository = dependencyCache();
        MavenDependencyGraphResolver.Request request =
                new MavenDependencyGraphResolver.Request(pom, localRepository,
                        selectedRepositories, List.of(), offline);
        try (MavenDependencyGraphResolver resolver = new MavenDependencyGraphResolver()) {
            MavenDependencyGraphResolver.Completion completion = resolver.complete(request);
            for (MavenDependencyGraphResolver.Problem problem
                    : completion.resolution().problems()) {
                if (problem.severity() == MavenDependencyGraphResolver.Severity.WARNING) {
                    System.err.println("[just:warn] dependency " + problem.code() + " ["
                            + problem.coordinate() + "]: " + problem.detail());
                }
            }
            if (completion.status() == MavenDependencyGraphResolver.Status.UNRESOLVED) {
                String detail = completion.resolution().problems().stream()
                        .filter(problem -> problem.severity()
                                == MavenDependencyGraphResolver.Severity.ERROR)
                        .map(problem -> problem.code() + " [" + problem.coordinate() + "]: "
                                + problem.detail())
                        .collect(Collectors.joining(" | "));
                if (detail.isBlank()) {
                    detail = "no-resolved-dependency-artifacts";
                }
                throw new ScanPipeline.UsageException("Maven 依赖补齐未完成: " + detail);
            }
            resolved.addAll(completion.paths());
            System.err.println("[just:info] dependencyCompletion=" + completion.status()
                    + "; artifacts=" + completion.artifacts().size()
                    + "; networkDownloadWallMs=" + completion.networkDownloadWallMs());
            return List.copyOf(resolved);
        } catch (IOException failure) {
            throw new ScanPipeline.UsageException("Maven 依赖补齐失败: " + failure.getMessage());
        }
    }

    private Path dependencyCache() throws ScanPipeline.UsageException {
        Path root = (cache == null ? Path.of(".just-cache") : cache)
                .toAbsolutePath().normalize();
        Path localRepository = root.resolve("maven-repository").normalize();
        if (!localRepository.startsWith(root)) {
            throw new ScanPipeline.UsageException("Maven 缓存路径越界");
        }
        if (Files.exists(root, LinkOption.NOFOLLOW_LINKS)
                && (Files.isSymbolicLink(root)
                || !Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS))) {
            throw new ScanPipeline.UsageException("Maven 缓存根不是实际目录: " + root);
        }
        if (Files.exists(localRepository, LinkOption.NOFOLLOW_LINKS)
                && (Files.isSymbolicLink(localRepository)
                || !Files.isDirectory(localRepository, LinkOption.NOFOLLOW_LINKS))) {
            throw new ScanPipeline.UsageException("Maven 本地仓库不是实际目录: " + localRepository);
        }
        return localRepository;
    }

    private static void printVerificationDisclosure() {
        System.err.println("[just:info] verificationMode=STATIC_ONLY; "
                + "targetCodeExecutionPossible=false; targetCodeExecuted=NO; "
                + "dynamicFiltering=ANALYSIS_ONLY; recommendedForUntrustedArtifacts=true");
    }
}
