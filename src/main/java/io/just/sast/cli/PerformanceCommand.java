package io.just.sast.cli;

import io.just.sast.perf.PerformanceHarness;
import io.just.sast.perf.PerformanceProfile;
import io.just.sast.report.PerformanceReportWriter;
import io.just.sast.report.ScanStatistics;
import io.just.sast.util.ArchiveLimits;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.Callable;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Opt-in fixed-runner performance command.  Normal scans never invoke this command and pay no
 * repeated-run cost.  {@code hot} measures repeated scans in one JVM; {@code cold} starts a
 * fresh scan process for every warmup/sample and is the useful approximation for cold-start CI.
 */
@Command(name = "perf", description = "在固定 runner 上测量扫描 p50/p95 与结果稳定性")
public final class PerformanceCommand implements Callable<Integer> {

    private static final long DISABLED_LIMIT = Long.MAX_VALUE;
    private static final Pattern NUMBER = Pattern.compile(
            "\\\"([^\\\"]+)\\\"\\s*:\\s*(-?\\d+)");
    private static final Pattern STRING = Pattern.compile(
            "\\\"([^\\\"]+)\\\"\\s*:\\s*\\\"([^\\\"]*)\\\"");

    @Option(names = "--jar", required = true, paramLabel = "<jar|dir>",
            description = "目标 JAR 或 class 目录")
    Path target;

    @Option(names = "--deps", split = ",", paramLabel = "<jar|dir,...>",
            description = "附加依赖（逗号分隔）")
    List<Path> deps;

    @Option(names = "--rules", paramLabel = "<file>", description = "自定义规则 YAML")
    Path rules;

    @Option(names = "--jdk-home", paramLabel = "<dir>", description = "目标 JDK/JRE 主目录")
    Path jdkHome;

    @Option(names = "--fast", description = "快速模式；结果完整性仍会如实记录")
    boolean fast;

    @Option(names = "--no-verify", description = "关闭动态验证，仅测静态扫描")
    boolean noVerify;

    @Option(names = "--safe-exec", description = "使用安全化 sink adapter")
    boolean safeExec;

    @Option(names = "--safe-real-sink", description = "请求 strict runner 内的 adapter-owned safe effect")
    boolean safeRealSink;

    @Option(names = "--require-os-isolation", description = "动态验证必须使用 OS_STRICT")
    boolean requireOsIsolation;

    @Option(names = "--verify-budget", defaultValue = "20", paramLabel = "<N>",
            description = "每次扫描的动态验证预算")
    int verifyBudget;

    @Option(names = "--mode", defaultValue = "hot", paramLabel = "<hot|cold>",
            description = "hot=同 JVM 重复扫描；cold=每次启动独立扫描进程")
    String mode;

    @Option(names = "--warmups", defaultValue = "1", paramLabel = "<N>",
            description = "丢弃的 warmup 次数")
    int warmups;

    @Option(names = "--runs", defaultValue = "5", paramLabel = "<N>",
            description = "保留的测量次数")
    int runs;

    @Option(names = "--work-dir", paramLabel = "<dir>",
            description = "临时报告目录的父目录；未指定时使用临时目录")
    Path workDir;

    @Option(names = "--report", paramLabel = "<file>",
            description = "写入性能 JSON；未指定时只输出到 stdout")
    Path report;

    @Option(names = "--process-timeout-ms", defaultValue = "900000", paramLabel = "<ms>",
            description = "cold 子进程单次超时")
    long processTimeoutMs;

    @Option(names = "--wall-p50-limit-ms", defaultValue = "0", paramLabel = "<ms>",
            description = "wall p50 门限；0 表示只测量不设门")
    long wallP50LimitMs;

    @Option(names = "--wall-p95-limit-ms", defaultValue = "0", paramLabel = "<ms>",
            description = "wall p95 门限；0 表示只测量不设门")
    long wallP95LimitMs;

    @Option(names = "--static-p50-limit-ms", defaultValue = "0", paramLabel = "<ms>",
            description = "静态 p50 门限；0 表示只测量不设门")
    long staticP50LimitMs;

    @Option(names = "--static-p95-limit-ms", defaultValue = "0", paramLabel = "<ms>",
            description = "静态 p95 门限；0 表示只测量不设门")
    long staticP95LimitMs;

    @Option(names = "--dynamic-p50-limit-ms", defaultValue = "0", paramLabel = "<ms>",
            description = "动态 p50 门限；0 表示只测量不设门")
    long dynamicP50LimitMs;

    @Option(names = "--dynamic-p95-limit-ms", defaultValue = "0", paramLabel = "<ms>",
            description = "动态 p95 门限；0 表示只测量不设门")
    long dynamicP95LimitMs;

    @Option(names = "--limits-file", paramLabel = "<properties>",
            description = "固定 runner 性能门限 profile（UTF-8 properties）")
    Path limitsFile;

    private PerformanceProfile.Limits profileLimits;

    @Override
    public Integer call() {
        Path createdRoot = null;
        try {
            profileLimits = limitsFile == null ? null : readProfile(limitsFile);
            validateOptions();
            boolean cold = "cold".equalsIgnoreCase(mode);
            if (!cold && !"hot".equalsIgnoreCase(mode)) {
                throw new ScanPipeline.UsageException("--mode 必须是 hot 或 cold");
            }
            Path parent = prepareParent();
            createdRoot = Files.createTempDirectory(parent, "just-perf-");
            PerformanceHarness.Report result = cold
                    ? runCold(createdRoot)
                    : runHot(createdRoot);
            String json = PerformanceReportWriter.json(result, cold ? "cold" : "hot");
            if (report != null) {
                validateReportTarget(report);
                PerformanceReportWriter.write(report, result, cold ? "cold" : "hot");
            }
            System.out.print(json);
            return result.passed() ? ExitCode.OK.code() : ExitCode.INTERNAL.code();
        } catch (ScanPipeline.UsageException e) {
            System.err.println("[just:error] " + e.getMessage());
            return ExitCode.USAGE.code();
        } catch (Exception e) {
            System.err.println("[just:error] 性能测量失败: " + e);
            return ExitCode.INTERNAL.code();
        } finally {
            if (createdRoot != null) {
                deleteTree(createdRoot);
            }
        }
    }

    private void validateOptions() throws ScanPipeline.UsageException {
        if (warmups < 0 || runs <= 0) {
            throw new ScanPipeline.UsageException("--warmups 不能为负数，--runs 必须大于 0");
        }
        if (verifyBudget < 0) {
            throw new ScanPipeline.UsageException("--verify-budget 不能为负数");
        }
        if (processTimeoutMs <= 0) {
            throw new ScanPipeline.UsageException("--process-timeout-ms 必须大于 0");
        }
        checkLimit(wallP50LimitMs, "--wall-p50-limit-ms");
        checkLimit(wallP95LimitMs, "--wall-p95-limit-ms");
        checkLimit(staticP50LimitMs, "--static-p50-limit-ms");
        checkLimit(staticP95LimitMs, "--static-p95-limit-ms");
        checkLimit(dynamicP50LimitMs, "--dynamic-p50-limit-ms");
        checkLimit(dynamicP95LimitMs, "--dynamic-p95-limit-ms");
        if (limitsFile != null && hasInlineLimit()) {
            throw new ScanPipeline.UsageException(
                    "--limits-file 不能与 --*-limit-ms 同时使用");
        }
        if (safeExec && safeRealSink) {
            throw new ScanPipeline.UsageException("--safe-exec 与 --safe-real-sink 不能同时使用");
        }
        if (safeRealSink && !requireOsIsolation) {
            throw new ScanPipeline.UsageException(
                    "--safe-real-sink 必须同时使用 --require-os-isolation");
        }
    }

    private boolean hasInlineLimit() {
        return wallP50LimitMs != 0L || wallP95LimitMs != 0L
                || staticP50LimitMs != 0L || staticP95LimitMs != 0L
                || dynamicP50LimitMs != 0L || dynamicP95LimitMs != 0L;
    }

    private static PerformanceProfile.Limits readProfile(Path file)
            throws ScanPipeline.UsageException {
        try {
            return PerformanceProfile.read(file);
        } catch (IOException | RuntimeException failure) {
            throw new ScanPipeline.UsageException(
                    "性能 profile 无效: " + failure.getMessage());
        }
    }

    private static void checkLimit(long value, String option) throws ScanPipeline.UsageException {
        if (value < 0) {
            throw new ScanPipeline.UsageException(option + " 不能为负数");
        }
    }

    private Path prepareParent() throws IOException, ScanPipeline.UsageException {
        if (workDir == null) {
            return Path.of(System.getProperty("java.io.tmpdir", "."))
                    .toAbsolutePath().normalize();
        }
        Path parent = workDir.toAbsolutePath().normalize();
        if (Files.exists(parent, LinkOption.NOFOLLOW_LINKS)
                && (ArchiveLimits.isLinkOrReparsePoint(parent)
                || !Files.isDirectory(parent, LinkOption.NOFOLLOW_LINKS))) {
            throw new ScanPipeline.UsageException("--work-dir 不是安全目录: " + parent);
        }
        Files.createDirectories(parent);
        return parent;
    }

    private PerformanceHarness.Report runHot(Path root) throws Exception {
        AtomicInteger counter = new AtomicInteger();
        for (int i = 0; i < warmups; i++) {
            scanOnce(root.resolve("warmup-" + counter.incrementAndGet()));
        }
        List<PerformanceHarness.Sample> samples = new ArrayList<>(runs);
        for (int i = 0; i < runs; i++) {
            Path output = root.resolve("run-" + counter.incrementAndGet());
            long started = System.nanoTime();
            ScanStatistics statistics = scanOnce(output);
            samples.add(PerformanceHarness.sample(i + 1, elapsedMs(started), statistics,
                    findingsDigest(output)));
        }
        return PerformanceHarness.report(warmups, samples, limits());
    }

    private ScanStatistics scanOnce(Path output) throws Exception {
        return ScanPipeline.run(target, deps, output, rules, false, fast, jdkHome,
                !noVerify, verifyBudget, safeExec, safeRealSink, requireOsIsolation,
                null, null).stats();
    }

    private PerformanceHarness.Report runCold(Path root) throws Exception {
        List<PerformanceHarness.Sample> samples = new ArrayList<>(runs);
        int iteration = 0;
        for (int i = 0; i < warmups; i++) {
            runColdOnce(root.resolve("warmup-" + (i + 1)), ++iteration);
        }
        for (int i = 0; i < runs; i++) {
            samples.add(runColdOnce(root.resolve("run-" + (i + 1)), ++iteration));
        }
        return PerformanceHarness.report(warmups, samples, limits());
    }

    private PerformanceHarness.Sample runColdOnce(Path output, int iteration)
            throws Exception {
        Files.createDirectories(output);
        List<String> command = new ArrayList<>();
        command.add(javaExecutable());
        command.add("-cp");
        command.add(System.getProperty("java.class.path", ""));
        command.add(JustMain.class.getName());
        command.add("scan");
        command.add("--jar");
        command.add(target.toAbsolutePath().normalize().toString());
        command.add("--output");
        command.add(output.toAbsolutePath().normalize().toString());
        if (deps != null && !deps.isEmpty()) {
            command.add("--deps");
            command.add(joinPaths(deps));
        }
        addPath(command, "--rules", rules);
        addPath(command, "--jdk-home", jdkHome);
        if (fast) command.add("--fast");
        if (noVerify) command.add("--no-verify");
        if (safeExec) command.add("--safe-exec");
        if (safeRealSink) command.add("--safe-real-sink");
        if (requireOsIsolation) command.add("--require-os-isolation");
        command.add("--verify-budget");
        command.add(Integer.toString(verifyBudget));

        long started = System.nanoTime();
        Process process = new ProcessBuilder(command)
                .redirectOutput(ProcessBuilder.Redirect.DISCARD)
                .redirectError(ProcessBuilder.Redirect.DISCARD)
                .start();
        boolean finished = process.waitFor(processTimeoutMs, TimeUnit.MILLISECONDS);
        if (!finished) {
            terminateProcessTree(process);
            throw new IOException("cold scan timed out after " + processTimeoutMs + " ms");
        }
        if (process.exitValue() != ExitCode.OK.code()) {
            throw new IOException("cold scan exited with code " + process.exitValue());
        }
        Path metadata = output.resolve("meta").resolve("scan-metadata.json");
        if (!Files.isRegularFile(metadata, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("cold scan did not produce scan metadata");
        }
        String json = Files.readString(metadata, StandardCharsets.UTF_8);
        long wall = elapsedMs(started);
        long staticMs = objectNumber(json, "phase_ms", "static", 0L);
        long dynamicMs = objectNumber(json, "phase_ms", "verify", 0L);
        long heapUsed = number(json, "heap_used_mb", 0L);
        long heapPeak = number(json, "heap_peak_mb", heapUsed);
        long rss = objectNumber(json, "metrics", "rss_peak_mb", -1L);
        int chains = (int) Math.max(0L, number(json, "chains_found", 0L));
        String completeness = string(json, "completeness", "UNKNOWN");
        PerformanceHarness.Sample sample = new PerformanceHarness.Sample(iteration, wall, staticMs,
                dynamicMs, heapUsed, heapPeak, rss, chains, completeness,
                findingsDigest(output));
        return sample;
    }

    private static String findingsDigest(Path output) throws IOException {
        Path findings = output.resolve("findings").resolve("findings.csv");
        if (!Files.isRegularFile(findings, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("scan did not produce canonical findings");
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            try (InputStream input = Files.newInputStream(findings)) {
                byte[] buffer = new byte[8192];
                int read;
                while ((read = input.read(buffer)) >= 0) {
                    if (read > 0) {
                        digest.update(buffer, 0, read);
                    }
                }
            }
            StringBuilder hex = new StringBuilder(64);
            for (byte value : digest.digest()) {
                hex.append(String.format(Locale.ROOT, "%02x", value));
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException impossible) {
            throw new IOException("SHA-256 unavailable", impossible);
        }
    }

    private PerformanceHarness.Limits limits() {
        if (profileLimits != null) {
            return new PerformanceHarness.Limits(
                    disabled(profileLimits.wallP50Ms()), disabled(profileLimits.wallP95Ms()),
                    disabled(profileLimits.staticP50Ms()), disabled(profileLimits.staticP95Ms()),
                    disabled(profileLimits.dynamicP50Ms()), disabled(profileLimits.dynamicP95Ms()));
        }
        return new PerformanceHarness.Limits(
                disabled(wallP50LimitMs), disabled(wallP95LimitMs),
                disabled(staticP50LimitMs), disabled(staticP95LimitMs),
                disabled(dynamicP50LimitMs), disabled(dynamicP95LimitMs));
    }

    private static long disabled(long value) {
        return value == 0L ? DISABLED_LIMIT : value;
    }

    private static String javaExecutable() {
        Path javaHome = Path.of(System.getProperty("java.home", ""));
        Path candidate = javaHome.resolve("bin").resolve(
                System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win")
                        ? "java.exe" : "java");
        return candidate.toString();
    }

    private static void addPath(List<String> command, String option, Path value) {
        if (value != null) {
            command.add(option);
            command.add(value.toAbsolutePath().normalize().toString());
        }
    }

    private static String joinPaths(List<Path> paths) {
        StringBuilder joined = new StringBuilder();
        for (Path path : paths) {
            if (joined.length() > 0) {
                joined.append(',');
            }
            joined.append(path.toAbsolutePath().normalize());
        }
        return joined.toString();
    }

    private static long number(String json, String key, long fallback) {
        Matcher matcher = NUMBER.matcher(json == null ? "" : json);
        while (matcher.find()) {
            if (key.equals(matcher.group(1))) {
                try {
                    return Long.parseLong(matcher.group(2));
                } catch (NumberFormatException ignored) {
                    return fallback;
                }
            }
        }
        return fallback;
    }

    private static long objectNumber(String json, String object, String key, long fallback) {
        String source = json == null ? "" : json;
        String marker = "\"" + object + "\"";
        int start = source.indexOf(marker);
        if (start < 0) {
            return fallback;
        }
        int bodyStart = source.indexOf('{', start + marker.length());
        int bodyEnd = bodyStart < 0 ? -1 : source.indexOf('}', bodyStart + 1);
        if (bodyStart < 0 || bodyEnd < 0) {
            return fallback;
        }
        return number(source.substring(bodyStart, bodyEnd + 1), key, fallback);
    }

    private static String string(String json, String key, String fallback) {
        Matcher matcher = STRING.matcher(json == null ? "" : json);
        while (matcher.find()) {
            if (key.equals(matcher.group(1))) {
                return matcher.group(2);
            }
        }
        return fallback;
    }

    private static long elapsedMs(long started) {
        return Math.max(0L, System.nanoTime() - started) / 1_000_000L;
    }

    private static void terminateProcessTree(Process process) {
        try {
            process.toHandle().descendants().forEach(handle -> handle.destroyForcibly());
        } catch (RuntimeException ignored) {
            // The parent process kill below is still the required fail-closed action.
        }
        process.destroyForcibly();
    }

    private static void validateReportTarget(Path target) throws ScanPipeline.UsageException {
        Path normalized = target.toAbsolutePath().normalize();
        if (Files.exists(normalized, LinkOption.NOFOLLOW_LINKS)
                && ArchiveLimits.isLinkOrReparsePoint(normalized)) {
            throw new ScanPipeline.UsageException("--report 不能覆盖符号链接或 reparse point");
        }
        Path parent = normalized.getParent();
        if (parent != null && Files.exists(parent, LinkOption.NOFOLLOW_LINKS)
                && ArchiveLimits.isLinkOrReparsePoint(parent)) {
            throw new ScanPipeline.UsageException("--report 父目录不能是符号链接或 reparse point");
        }
    }

    private static void deleteTree(Path root) {
        try {
            if (!Files.exists(root, LinkOption.NOFOLLOW_LINKS)
                    || ArchiveLimits.isLinkOrReparsePoint(root)) {
                return;
            }
            try (var stream = Files.walk(root)) {
                stream.sorted(Comparator.reverseOrder()).forEach(path -> {
                    try {
                        Files.deleteIfExists(path);
                    } catch (IOException ignored) {
                        // A failed cleanup is not converted into a successful performance gate.
                    }
                });
            }
        } catch (IOException ignored) {
            // The report/gate result remains the primary outcome; callers can retain --work-dir.
        }
    }
}
