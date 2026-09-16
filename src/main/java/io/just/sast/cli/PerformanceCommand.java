package io.just.sast.cli;

import io.just.sast.perf.PerformanceHarness;
import io.just.sast.perf.PerformanceProfile;
import io.just.sast.report.PerformanceReportWriter;
import io.just.sast.report.ScanStatistics;
import io.just.sast.run.ExitReason;
import io.just.sast.run.InputBudget;
import io.just.sast.run.RunOutcome;
import io.just.sast.util.ArchiveLimits;
import io.just.sast.util.IoUtil;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Opt-in fixed-runner performance command.  Normal scans never invoke this command and pay no
 * repeated-run cost.  {@code hot} measures repeated scans in one JVM; {@code cold} starts a
 * fresh scan process for every warmup/sample and is the useful approximation for cold-start CI.
 */
@Command(name = "perf", description = "在固定 runner 上测量扫描 p50/p95 与结果稳定性",
        mixinStandardHelpOptions = true)
public final class PerformanceCommand implements Callable<Integer> {

    /*
     * A generated report is an aggregate projection rather than one archive entry.  Keep the
     * ordinary scan budget for the total read, but allow the performance runner to consume one
     * report up to that same aggregate bound.
     */
    private static final InputBudget OUTPUT_INPUT_POLICY = performanceOutputPolicy();

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

    @Option(names = "--launcher-jar", paramLabel = "<jar>",
            description = "cold 模式使用的发布 launcher JAR；未指定时使用当前 classpath")
    Path launcherJar;

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

    @Option(names = "--filter-p50-limit-ms", defaultValue = "0", paramLabel = "<ms>",
            description = "静态有限过滤 p50 门限；0 表示只测量不设门")
    long filterP50LimitMs;

    @Option(names = "--filter-p95-limit-ms", defaultValue = "0", paramLabel = "<ms>",
            description = "静态有限过滤 p95 门限；0 表示只测量不设门")
    long filterP95LimitMs;

    @Option(names = "--limits-file", paramLabel = "<properties>",
            description = "固定 runner 性能门限 profile（UTF-8 properties）")
    Path limitsFile;

    private PerformanceProfile.Limits profileLimits;

    static InputBudget outputInputPolicyForContract() {
        return OUTPUT_INPUT_POLICY;
    }

    private static InputBudget performanceOutputPolicy() {
        InputBudget defaults = InputBudget.defaults();
        return defaults.withArchiveLimits(defaults.maxPhysicalBytes(), defaults.maxCompressedBytes(),
                defaults.maxUncompressedBytes(), defaults.maxUncompressedBytes(),
                defaults.maxArchiveEntries(), defaults.maxArchiveNesting(),
                defaults.maxClassEntries());
    }

    @Override
    public Integer call() {
        Path createdRoot = null;
        try {
            validateOptions();
            profileLimits = limitsFile == null ? null : readProfile(limitsFile);
            printStaticOnlyDisclosure();
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
            return RunOutcome.forPerformance(result.passed(), !result.samples().isEmpty()).exitCode();
        } catch (ScanPipeline.UsageException e) {
            System.err.println("[just:error] " + e.getMessage());
            return RunOutcome.usage("PERFORMANCE_USAGE", e.getMessage()).exitCode();
        } catch (Exception e) {
            System.err.println("[just:error] 性能测量失败: " + e);
            return RunOutcome.failed("PERFORMANCE_FAILURE", e.getClass().getSimpleName()).exitCode();
        } finally {
            if (createdRoot != null) {
                if (!deleteTree(createdRoot)) {
                    System.err.println("[just:warn] 性能临时目录未能安全清理，已保留供审计: "
                            + createdRoot);
                }
            }
        }
    }

    private void validateOptions() throws ScanPipeline.UsageException {
        if (warmups < 0 || runs <= 0) {
            throw new ScanPipeline.UsageException("--warmups 不能为负数，--runs 必须大于 0");
        }
        if (processTimeoutMs <= 0) {
            throw new ScanPipeline.UsageException("--process-timeout-ms 必须大于 0");
        }
        checkLimit(wallP50LimitMs, "--wall-p50-limit-ms");
        checkLimit(wallP95LimitMs, "--wall-p95-limit-ms");
        checkLimit(staticP50LimitMs, "--static-p50-limit-ms");
        checkLimit(staticP95LimitMs, "--static-p95-limit-ms");
        checkLimit(filterP50LimitMs, "--filter-p50-limit-ms");
        checkLimit(filterP95LimitMs, "--filter-p95-limit-ms");
        if (limitsFile != null && hasInlineLimit()) {
            throw new ScanPipeline.UsageException(
                    "--limits-file 不能与 --*-limit-ms 同时使用");
        }
        if (launcherJar != null) {
            Path normalized = launcherJar.toAbsolutePath().normalize();
            if (!Files.isRegularFile(normalized, LinkOption.NOFOLLOW_LINKS)
                    || ArchiveLimits.isLinkOrReparsePoint(normalized)) {
                throw new ScanPipeline.UsageException("--launcher-jar 不是普通非链接文件: "
                        + normalized);
            }
            launcherJar = normalized;
        }
    }

    private boolean hasInlineLimit() {
        return wallP50LimitMs != 0L || wallP95LimitMs != 0L
                || staticP50LimitMs != 0L || staticP95LimitMs != 0L
                || filterP50LimitMs != 0L || filterP95LimitMs != 0L;
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
                    resultDigest(output, OUTPUT_INPUT_POLICY, OUTPUT_INPUT_POLICY.tracker())));
        }
        return PerformanceHarness.report(warmups, samples, limits());
    }

    private ScanStatistics scanOnce(Path output) throws Exception {
        return ScanPipeline.run(target, deps, output, rules, false, fast, jdkHome,
                ModeDemandPolicy.forMode(ScanMode.COMPONENT)).stats();
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
        List<String> command = new ArrayList<>();
        command.add(javaExecutable());
        if (launcherJar != null) {
            command.add("-jar");
            command.add(launcherJar.toString());
        } else {
            command.add("-cp");
            command.add(System.getProperty("java.class.path", ""));
            command.add(JustMain.class.getName());
        }
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

        long started = System.nanoTime();
        Process process = new ProcessBuilder(command)
                .redirectOutput(ProcessBuilder.Redirect.DISCARD)
                .redirectError(ProcessBuilder.Redirect.DISCARD)
                .start();
        long timeToFirstUsefulMs = -1L;
        long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(processTimeoutMs);
        while (!process.waitFor(100L, TimeUnit.MILLISECONDS)) {
            if (timeToFirstUsefulMs < 0L) {
                timeToFirstUsefulMs = firstUsefulReportMs(output, started);
            }
            if (System.nanoTime() >= deadline) {
                terminateProcessTree(process);
                throw new IOException("cold scan timed out after " + processTimeoutMs + " ms");
            }
        }
        if (timeToFirstUsefulMs < 0L) {
            timeToFirstUsefulMs = firstUsefulReportMs(output, started);
        }
        if (process.exitValue() != ExitReason.OK.code()) {
            throw new IOException("cold scan exited with code " + process.exitValue());
        }
        Path metadata = output.resolve("meta").resolve("scan-metadata.json");
        if (!Files.isRegularFile(metadata, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("cold scan did not produce scan metadata");
        }
        InputBudget.Tracker outputBudget = OUTPUT_INPUT_POLICY.tracker();
        String json = readBoundedText(metadata, OUTPUT_INPUT_POLICY, outputBudget,
                "PERFORMANCE_METADATA");
        long wall = elapsedMs(started);
            Metadata metadataValues = parseMetadata(json);
            long staticMs = metadataValues.staticMs();
            long filterMs = metadataValues.filterMs();
            long heapUsed = metadataValues.heapUsedMb();
            long heapPeak = metadataValues.heapPeakMb();
            Long parentRss = objectNumber(json, "metrics", "parent_rss_mb");
            Long rssPeak = objectNumber(json, "metrics", "rss_peak_mb");
            long rss = parentRss != null ? parentRss : rssPeak == null ? -1L : rssPeak;
            int chains = metadataValues.chainsFound();
            String completeness = metadataValues.completeness();
        PerformanceHarness.Sample sample = new PerformanceHarness.Sample(iteration, wall, staticMs,
                filterMs, heapUsed, heapPeak, rss, chains, completeness,
                resultDigest(output, OUTPUT_INPUT_POLICY, outputBudget), objectNumbers(json, "phase_ms"),
                resourceNumbers(json, "metrics"), timeToFirstUsefulMs);
        return sample;
    }

    /**
     * The report writer publishes the complete canonical report with an atomic move.  Observing
     * its first non-empty regular file therefore records the first result a consumer can read,
     * without parsing target-owned bytes or executing any target code.
     */
    private static long firstUsefulReportMs(Path output, long started) throws IOException {
        Path report = output.resolve("report.json");
        try {
            BasicFileAttributes attributes = Files.readAttributes(report,
                    BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (attributes.isRegularFile() && attributes.size() > 0L) {
                return elapsedMs(started);
            }
            return -1L;
        } catch (java.nio.file.NoSuchFileException missing) {
            return -1L;
        }
    }

    /**
     * Digest the stable result projection used by the performance gate.  Metadata is excluded
     * because it contains elapsed time and host observations; the findings plus the complete
     * variant evidence are the user-visible static result and must agree across runs.
     */
    private static String resultDigest(Path output, InputBudget policy,
                                       InputBudget.Tracker tracker) throws IOException {
        Path report = output.resolve("report.json");
        return new io.just.sast.report.CanonicalReportReader()
                .read(report, policy, tracker).digest();
    }

    private static String readBoundedText(Path file, InputBudget policy,
                                          InputBudget.Tracker tracker, String label)
            throws IOException {
        ArchiveLimits.FileReadSnapshot snapshot = ArchiveLimits.snapshotRegularFile(
                file, policy, label);
        BasicFileAttributes before = snapshot.fileAttributes();
        long limit = Math.min(policy.maxEntryBytes(), tracker.remainingReadBytes());
        if (before.size() > policy.maxEntryBytes() || before.size() > limit) {
            throw new IOException(label + "_INPUT_LIMIT:" + policy.maxEntryBytes());
        }
        byte[] bytes;
        try (IoUtil.OpenedInput opened = IoUtil.openRegularFile(file, label);
             InputStream input = opened.stream()) {
            bytes = IoUtil.readAll(input, limit, tracker);
        }
        ArchiveLimits.verifyRegularFileUnchanged(snapshot, label);
        return new String(bytes, StandardCharsets.UTF_8);
    }

    /** Package-local hostile contract seam for shared metadata/result input accounting. */
    static String readBoundedTextForContract(Path file, InputBudget policy,
                                             InputBudget.Tracker tracker) throws IOException {
        return readBoundedText(file, policy, tracker, "PERFORMANCE_METADATA");
    }

    private PerformanceHarness.Limits limits() {
        if (profileLimits != null) {
            return new PerformanceHarness.Limits(
                    disabled(profileLimits.wallP50Ms()), disabled(profileLimits.wallP95Ms()),
                    disabled(profileLimits.staticP50Ms()), disabled(profileLimits.staticP95Ms()),
                    disabled(profileLimits.filterP50Ms()), disabled(profileLimits.filterP95Ms()));
        }
        return new PerformanceHarness.Limits(
                disabled(wallP50LimitMs), disabled(wallP95LimitMs),
                disabled(staticP50LimitMs), disabled(staticP95LimitMs),
                disabled(filterP50LimitMs), disabled(filterP95LimitMs));
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

    private record Metadata(long staticMs, long filterMs, long heapUsedMb, long heapPeakMb,
                            int chainsFound, String completeness) {
    }

    private static Metadata parseMetadata(String json) throws IOException {
        long staticMs = requiredObjectNumber(json, "phase_ms", "static");
        long filterMs = requiredObjectNumber(json, "phase_ms", "filter");
        long heapUsed = requiredNumber(json, "heap_used_mb");
        long heapPeak = requiredNumber(json, "heap_peak_mb");
        long chains = requiredNumber(json, "chains_found");
        String completeness = requiredString(json, "completeness");
        if (staticMs < 0L || filterMs < 0L || heapUsed < 0L || heapPeak < heapUsed
                || chains < 0L || chains > Integer.MAX_VALUE) {
            throw new IOException("PERFORMANCE_METADATA_VALUES_INVALID");
        }
        if (!Set.of("COMPLETE", "PARTIAL", "UNKNOWN").contains(completeness)) {
            throw new IOException("PERFORMANCE_METADATA_COMPLETENESS_INVALID:" + completeness);
        }
        return new Metadata(staticMs, filterMs, heapUsed, heapPeak, (int) chains, completeness);
    }

    /** Package-local hostile contract seam: required metadata cannot silently become zero. */
    static void validateMetadataForContract(String json) throws IOException {
        parseMetadata(json);
    }

    private static long requiredNumber(String json, String key) throws IOException {
        Long value = number(json, key);
        if (value == null) {
            throw new IOException("PERFORMANCE_METADATA_MISSING:" + key);
        }
        return value;
    }

    private static long requiredObjectNumber(String json, String object, String key)
            throws IOException {
        Long value = objectNumber(json, object, key);
        if (value == null) {
            throw new IOException("PERFORMANCE_METADATA_MISSING:" + object + "." + key);
        }
        return value;
    }

    private static String requiredString(String json, String key) throws IOException {
        String value = string(json, key, null);
        if (value == null || value.isBlank()) {
            throw new IOException("PERFORMANCE_METADATA_MISSING:" + key);
        }
        return value.trim().toUpperCase(Locale.ROOT);
    }

    private static Long number(String json, String key) {
        Matcher matcher = NUMBER.matcher(json == null ? "" : json);
        while (matcher.find()) {
            if (key.equals(matcher.group(1))) {
                try {
                    return Long.parseLong(matcher.group(2));
                } catch (NumberFormatException ignored) {
                    return null;
                }
            }
        }
        return null;
    }

    private static Long objectNumber(String json, String object, String key) {
        String source = json == null ? "" : json;
        String marker = "\"" + object + "\"";
        int start = source.indexOf(marker);
        if (start < 0) {
            return null;
        }
        int bodyStart = source.indexOf('{', start + marker.length());
        int bodyEnd = bodyStart < 0 ? -1 : source.indexOf('}', bodyStart + 1);
        if (bodyStart < 0 || bodyEnd < 0) {
            return null;
        }
        return number(source.substring(bodyStart, bodyEnd + 1), key);
    }

    private static Map<String, Long> objectNumbers(String json, String object) {
        String source = json == null ? "" : json;
        String marker = "\"" + object + "\"";
        int start = source.indexOf(marker);
        if (start < 0) {
            return Map.of();
        }
        int bodyStart = source.indexOf('{', start + marker.length());
        int bodyEnd = bodyStart < 0 ? -1 : source.indexOf('}', bodyStart + 1);
        if (bodyStart < 0 || bodyEnd < 0) {
            return Map.of();
        }
        Matcher matcher = NUMBER.matcher(source.substring(bodyStart, bodyEnd + 1));
        Map<String, Long> values = new LinkedHashMap<>();
        while (matcher.find()) {
            try {
                values.put(matcher.group(1), Long.parseLong(matcher.group(2)));
            } catch (NumberFormatException ignored) {
                // A malformed optional phase is omitted; the top-level scan result remains valid.
            }
        }
        return values.isEmpty() ? Map.of() : Map.copyOf(values);
    }

    private static Map<String, Long> resourceNumbers(String json, String object) {
        Map<String, Long> all = objectNumbers(json, object);
        Map<String, Long> result = new LinkedHashMap<>();
        all.forEach((name, value) -> {
            if (name.startsWith("parent_") || name.startsWith("child_")
                    || name.startsWith("scratch_") || name.startsWith("uncollected_")
                    || name.startsWith("cleanup_") || "rss_peak_mb".equals(name)) {
                result.put(name, value);
            }
        });
        return result.isEmpty() ? Map.of() : Map.copyOf(result);
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

    private static boolean deleteTree(Path root) {
        return deleteTreeBounded(root, OUTPUT_INPUT_POLICY);
    }

    /**
     * Bounded, no-follow cleanup for performance-run output.  Cleanup is deliberately fail
     * closed: if the tree exceeds the shared input policy or changes into a link/reparse point,
     * no partial deletion is attempted and the caller may retain the work directory for
     * diagnosis.  This protects the runner itself without claiming a provider-independent
     * TOCTOU guarantee.
     */
    static boolean deleteTreeBounded(Path root, InputBudget budget) {
        if (root == null) {
            return true;
        }
        Path normalized = root.toAbsolutePath().normalize();
        try {
            if (!Files.exists(normalized, LinkOption.NOFOLLOW_LINKS)) {
                return true;
            }
            if (ArchiveLimits.isLinkOrReparsePoint(normalized)) {
                return false;
            }
            InputBudget policy = budget == null ? InputBudget.defaults() : budget;
            InputBudget.Tracker tracker = policy.tracker();
            List<Path> entries = new ArrayList<>();
            try (var stream = Files.walk(normalized)) {
                var iterator = stream.iterator();
                while (iterator.hasNext()) {
                    tracker.checkTime();
                    Path path = iterator.next();
                    Path candidate = path.toAbsolutePath().normalize();
                    if (!candidate.startsWith(normalized)
                            || ArchiveLimits.isLinkOrReparsePoint(path)) {
                        return false;
                    }
                    Path relativePath = normalized.relativize(candidate);
                    if (relativePath.getNameCount() > policy.maxPathDepth()) {
                        return false;
                    }
                    String relative = relativePath.toString().replace('\\', '/');
                    if (!relative.isBlank() && !ArchiveLimits.safeEntryName(relative, policy)) {
                        return false;
                    }
                    BasicFileAttributes attributes = Files.readAttributes(path,
                            BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
                    tracker.observeFile(relative.isBlank() ? "<root>" : relative,
                            attributes.isRegularFile() ? attributes.size() : 0L);
                    entries.add(path);
                }
            }
            entries.sort(Comparator.reverseOrder());
            for (Path path : entries) {
                if (!Files.deleteIfExists(path)) {
                    return false;
                }
            }
            return true;
        } catch (IOException | RuntimeException failure) {
            return false;
        }
    }

    private static void printStaticOnlyDisclosure() {
        System.err.println("[just:info] perf analysisMode=STATIC_ONLY; "
                + "boundedFiltering=ANALYSIS_ONLY; "
                + "recommendedForUntrustedArtifacts=true");
    }
}
