package io.just.sast.cli;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import io.just.sast.dependency.MavenDependencyGraphResolver;
import io.just.sast.model.DependencyGraph;
import io.just.sast.report.ScanStatistics;
import io.just.sast.report.ScanCache;
import io.just.sast.run.RunOutcome;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Path;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.concurrent.Callable;

/** scan 子命令：深度扫描 JAR/目录并输出 canonical static report。 */
@Command(name = "scan", description = "深度扫描 JAR/class 目录并输出静态链报告")
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
            description = "静态报告输出目录（默认 just-out）")
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

    @Option(names = "--baseline", paramLabel = "<scan-dir>",
            description = "按语义链身份比较已有扫描目录；只标记新增/不变/消失，不删除证据")
    Path baseline;

    @Option(names = "--suppressions", paramLabel = "<file>",
            description = "读取语义链身份、sha256:<digest> 或 rule:<id> 抑制项；默认只输出标记，不删除发现")
    Path suppressions;

    @Option(names = "--cache", paramLabel = "<dir>",
            description = "显式启用完整报告增量缓存；只缓存 COMPLETE 且无内部失败终态的扫描")
    Path cache;


    @Override
    public Integer call() {
        try {
            ScanMode selectedMode = ScanMode.parse(mode);
            if (cache != null && (baseline != null || suppressions != null)) {
                throw new ScanPipeline.UsageException(
                        "--cache 不能与 --baseline 或 --suppressions 同时使用");
            }
            ModeDemandPolicy modePolicy = ModeDemandPolicy.forMode(selectedMode);
            printStaticAnalysisDisclosure();
            PreparedDependencies prepared = resolveDependencies();
            List<Path> scanDeps = prepared.paths();
            boolean useCache = cache != null;
            ScanCache.Preflight preflight = null;
            if (useCache) {
                try {
                    preflight = ScanCache.preflight(target, scanDeps, rules, jdkHome, fast,
                            modePolicy.wireName(), prepared.environmentIdentity());
                    if (ScanCache.restore(cache, preflight.cacheKey(), output)) {
                        System.err.println("[just:info] 增量缓存命中（报告身份已校验）");
                        return RunOutcome.success().exitCode();
                    }
                } catch (java.io.IOException | RuntimeException cacheFailure) {
                    throw new CacheFailure(cacheFailure);
                }
            }
            ScanPipeline.ScanResult result = ScanPipeline.run(target, scanDeps, output, rules, stats,
                    fast, jdkHome, baseline, suppressions, overwrite,
                    modePolicy, prepared.environmentGraph(), prepared.explicitDependencyCount(),
                    prepared.environmentIdentity(), prepared.dependencyPreparation());
            printScanTiming(result.stats());
            if (useCache && preflight != null) {
                try {
                    boolean stored = ScanCache.store(cache, preflight.cacheKey(), output,
                            result.stats());
                    ScanCache.recordEvent(output, preflight.cacheKey(), stored ? "stored" : "not-stored");
                } catch (java.io.IOException | RuntimeException cacheFailure) {
                    throw new CacheFailure(cacheFailure);
                }
            }
            return result.exitCode();
        } catch (ScanPipeline.UsageException e) {
            System.err.println("[just:error] " + e.getMessage());
            return RunOutcome.usage("USAGE_ERROR", e.getMessage()).exitCode();
        } catch (CacheFailure e) {
            System.err.println("[just:error] " + e.getMessage());
            return RunOutcome.failed("CACHE_FAILURE", e.getMessage()).exitCode();
        } catch (Exception e) {
            System.err.println("[just:error] 扫描失败: " + e);
            return RunOutcome.failed("SCAN_FAILURE", e.getClass().getSimpleName()).exitCode();
        }
    }

    private static final class CacheFailure extends Exception {
        private CacheFailure(Throwable cause) {
            super("缓存操作失败: " + (cause.getMessage() == null
                    ? cause.getClass().getSimpleName() : cause.getMessage()), cause);
        }
    }

    private PreparedDependencies resolveDependencies() throws ScanPipeline.UsageException {
        List<Path> resolved = deps == null ? new ArrayList<>() : new ArrayList<>(deps);
        int explicitDependencyCount = resolved.size();
        boolean hasRepositories = repositories != null && !repositories.isEmpty();
        if (pom == null) {
            if (offline || hasRepositories) {
                throw new ScanPipeline.UsageException(
                        "--offline/--repository 需要同时提供显式 --pom；无 POM 时 Just 不按类名猜包");
            }
            return new PreparedDependencies(resolved, explicitDependencyCount, null,
                    "MAVEN_POM_NOT_PROVIDED", ScanPipeline.DependencyPreparation.notProvided());
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
                    + "; cacheArtifacts=" + completion.artifacts().stream()
                    .filter(artifact -> artifact.source() == DependencyGraph.Source.CACHE).count()
                    + "; remoteArtifacts=" + completion.artifacts().stream()
                    .filter(artifact -> artifact.source() == DependencyGraph.Source.REMOTE).count()
                    + "; resolutionWallMs=" + completion.resolutionWallMs()
                    + "; networkDownloadWallMs=" + completion.networkDownloadWallMs()
                    + "; networkRequestMs=" + completion.networkRequestMs()
                    + "; transferredBytes=" + completion.transferredBytes());
            return new PreparedDependencies(resolved, explicitDependencyCount,
                    completion.environmentGraph(explicitDependencyCount + 1),
                    completion.semanticIdentity(), dependencyPreparation(completion));
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

    private static void printStaticAnalysisDisclosure() {
        System.err.println("[just:info] analysisMode=STATIC_ONLY; "
                + "targetCodeExecution=DISABLED; boundedFiltering=ANALYSIS_ONLY; "
                + "recommendedForUntrustedArtifacts=true");
    }

    private static ScanPipeline.DependencyPreparation dependencyPreparation(
            MavenDependencyGraphResolver.Completion completion) {
        int cacheArtifacts = Math.toIntExact(completion.artifacts().stream()
                .filter(artifact -> artifact.source() == DependencyGraph.Source.CACHE).count());
        int remoteArtifacts = Math.toIntExact(completion.artifacts().stream()
                .filter(artifact -> artifact.source() == DependencyGraph.Source.REMOTE).count());
        return new ScanPipeline.DependencyPreparation(
                ScanPipeline.DependencyPreparation.DependencyStatus.valueOf(
                        completion.status().name()),
                completion.artifacts().size(), cacheArtifacts, remoteArtifacts,
                completion.resolutionWallMs(), completion.networkDownloadWallMs(),
                completion.networkRequestMs(), completion.transferredBytes());
    }

    private static void printScanTiming(ScanStatistics stats) {
        System.err.println("[just:info] scanTiming="
                + "dependencyResolutionMs=" + stats.metric("dependency_resolution_ms", -1L)
                + "; networkDownloadWallMs=" + stats.metric("network_download_wall_ms", -1L)
                + "; networkRequestMs=" + stats.metric("network_request_ms", -1L)
                + "; analysisMs=" + stats.metric("analysis_ms", -1L)
                + "; filterMs=" + stats.metric("filter_ms", -1L)
                + "; reportMs=" + stats.metric("report_ms", -1L)
                + "; totalWallMs=" + stats.metric("total_wall_ms", -1L)
                + "; timingStatus=" + stats.metricStatus("total_wall_ms")
                + "; dependencySources=" + dependencySources(stats));
    }

    private static String dependencySources(ScanStatistics stats) {
        List<String> values = new ArrayList<>();
        for (DependencyGraph.Source source : DependencyGraph.Source.values()) {
            String key = "dependency_source_"
                    + source.name().toLowerCase(java.util.Locale.ROOT);
            values.add(source.name().toLowerCase(java.util.Locale.ROOT)
                    + "=" + stats.metric(key, -1L));
        }
        return String.join(",", values);
    }

    /** Explicit handoff from input preparation to the frontend/cache pipeline. */
    private record PreparedDependencies(List<Path> paths, int explicitDependencyCount,
                                        DependencyGraph environmentGraph,
                                        String environmentIdentity,
                                        ScanPipeline.DependencyPreparation dependencyPreparation) {
        private PreparedDependencies {
            paths = paths == null ? List.of() : List.copyOf(paths);
            if (explicitDependencyCount < 0 || explicitDependencyCount > paths.size()) {
                throw new IllegalArgumentException("explicit dependency count is invalid");
            }
            environmentIdentity = environmentIdentity == null || environmentIdentity.isBlank()
                    ? "MAVEN_POM_NOT_PROVIDED" : environmentIdentity;
            dependencyPreparation = java.util.Objects.requireNonNull(dependencyPreparation,
                    "dependency preparation");
        }
    }
}
