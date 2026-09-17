package io.just.sast.frontend.asm;

import io.just.sast.model.ClassInfo;
import io.just.sast.model.ArchiveMemberProvenance;
import io.just.sast.model.JdkClassSource;
import io.just.sast.model.JdkSourceInfo;
import io.just.sast.run.InputBudget;
import io.just.sast.util.ArchiveLimits;
import io.just.sast.util.IoUtil;
import io.just.sast.util.JustLogger;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * 目标 JDK 类来源（--jdk-home 指定）：
 * - Java 8 及以下（有 rt.jar）：从 $jdkHome/jre/lib/ 或 $jdkHome/lib/ 读 rt.jar + 辅助 jar
 * - Java 9+（有 lib/jrt-fs.jar）：挂载目标 JDK 的 jrt-fs.jar 对其模块镜像打开文件系统——
 *   读取的是目标 JDK 的类而非运行时的（JDK 版本决定 gadget 存亡，不可用运行时顶替）
 */
public final class TargetJdkSource implements JdkClassSource {

    private final ClassFileReader reader = new ClassFileReader();
    /** 内部名 → 所在 jar 路径（Java 8 模式） */
    /** Lazy Java 8 lookups can happen from parallel hierarchy queries. */
    private final Map<String, Path> classToJar = new ConcurrentHashMap<>();
    private final List<Path> coreJars = new ArrayList<>();
    private boolean legacyIndexBuilt;
    /** Java 9+ 模式的目标镜像 */
    private final JrtClassSource jrtDelegate;
    private final String jdkDescription;
    private final int feature;
    private final JdkSourceInfo sourceInfo;
    private final InputBudget budget;
    private final InputBudget.Tracker inputTracker;
    private final Set<String> observedEntries = ConcurrentHashMap.newKeySet();
    private final Set<String> accountedClasses = ConcurrentHashMap.newKeySet();
    /**
     * Content identity for class entries observed during this source lifetime.  The digest is
     * computed over bytes already materialized under the entry budget, so it adds no second file
     * read and detects a same-name entry changing between two lazy lookups.
     */
    private final Map<String, String> classEntryDigests = new ConcurrentHashMap<>();
    private final AtomicInteger classEntries = new AtomicInteger();
    private volatile String budgetFailure;

    public TargetJdkSource(Path jdkHome) throws IOException {
        this(jdkHome, InputBudget.defaults());
    }

    /** Construct a target-JDK source with the scan's immutable input policy. */
    public TargetJdkSource(Path jdkHome, InputBudget budget) throws IOException {
        this(jdkHome, budget, null);
    }

    /**
     * Construct a target-JDK source using the scan's caller-owned aggregate input tracker.
     * Legacy and JRT modes then charge release metadata, central-directory indexing and class
     * bytes to the same accounting as application/dependency parsing.
     */
    public TargetJdkSource(Path jdkHome, InputBudget budget,
                           InputBudget.Tracker callerTracker) throws IOException {
        InputBudget requested = budget == null ? InputBudget.defaults() : budget;
        this.inputTracker = callerTracker == null ? requested.tracker() : callerTracker;
        this.budget = callerTracker == null ? requested : this.inputTracker.budget();
        if (jdkHome == null) {
            throw new IOException("--jdk-home 不能为空");
        }
        Path home = jdkHome.toAbsolutePath().normalize();
        // Jabba's `default` selector may be a junction; the toolchain path is trusted and the
        // concrete archive/JRT leaves are checked before opening them.
        if (!Files.isDirectory(home)) {
            throw new IOException("--jdk-home 不是目录: " + home);
        }
        if (ArchiveLimits.isLinkOrReparsePoint(home)) {
            try {
                Path linkTarget = Files.readSymbolicLink(home);
                home = (linkTarget.isAbsolute() ? linkTarget : home.getParent().resolve(linkTarget))
                        .toAbsolutePath().normalize();
            } catch (IOException | RuntimeException linkReadFailure) {
                try {
                    home = home.toRealPath();
                } catch (IOException | RuntimeException realPathFailure) {
                    realPathFailure.addSuppressed(linkReadFailure);
                    throw new IOException("--jdk-home 目录别名无法解析", realPathFailure);
                }
            }
            if (!Files.isDirectory(home) || ArchiveLimits.isLinkOrReparsePoint(home)) {
                throw new IOException("--jdk-home 真实目录不是安全目录: " + home);
            }
        }
        // Java 8 及以下：找 rt.jar（JDK 在 $home/jre/lib/rt.jar，JRE 在 $home/lib/rt.jar）
        Path rtJar = home.resolve("jre").resolve("lib").resolve("rt.jar");
        if (!Files.exists(rtJar)) {
            rtJar = home.resolve("lib").resolve("rt.jar");
        }
        if (Files.isRegularFile(rtJar, java.nio.file.LinkOption.NOFOLLOW_LINKS)
                && !ArchiveLimits.isLinkOrReparsePoint(rtJar)) {
            jdkDescription = detectLegacyVersion(home, this.budget, this.inputTracker)
                    + "（rt.jar 模式）";
            feature = detectFeature(home, this.budget, this.inputTracker);
            sourceInfo = new JdkSourceInfo(JdkSourceInfo.ImageKind.TARGET_RT_JAR, feature);
            coreJars.add(rtJar);
            // 辅助 jar：jce / jsse / charsets / resources（反序列化相关类可能分布在多个 jar）
            Path libDir = rtJar.getParent();
            for (String aux : List.of("jce.jar", "jsse.jar", "charsets.jar", "resources.jar")) {
                Path auxPath = libDir.resolve(aux);
                if (Files.isRegularFile(auxPath, java.nio.file.LinkOption.NOFOLLOW_LINKS)
                        && !ArchiveLimits.isLinkOrReparsePoint(auxPath)) {
                    coreJars.add(auxPath);
                }
            }
            jrtDelegate = null;
            JustLogger.info("目标 JDK 来源：{}（{} 个核心 jar：{}）",
                    jdkDescription, coreJars.size(),
                    coreJars.stream().map(p -> p.getFileName().toString())
                            .collect(java.util.stream.Collectors.joining(", ")));
            return;
        }
        // Java 9+：挂载目标 JDK 的 jrt-fs（真实现，非运行时回退）
        Path release = home.resolve("release");
        if (Files.isRegularFile(release, java.nio.file.LinkOption.NOFOLLOW_LINKS)
                && !ArchiveLimits.isLinkOrReparsePoint(release)) {
            jrtDelegate = JrtClassSource.external(home, this.budget, this.inputTracker);
            jdkDescription = readReleaseVersion(home, this.budget, this.inputTracker)
                    + "（jrt-fs 外部挂载）";
            feature = jrtDelegate.feature();
            sourceInfo = new JdkSourceInfo(JdkSourceInfo.ImageKind.TARGET_JRT, feature);
            JustLogger.info("目标 JDK 来源：{}（读取目标镜像，非运行时）", jdkDescription);
            return;
        }
        throw new IOException("--jdk-home 无法识别 JDK 结构（既无 rt.jar 也无 release 文件）: " + home);
    }

    @Override
    public ClassInfo load(String internalName) {
        ClassBytes bytes = loadBytes(internalName);
        if (bytes == null) {
            return null;
        }
        try {
            return reader.read(bytes.bytes(), budget, inputTracker);
        } catch (IOException structuralFailure) {
            budgetFailure = structuralFailure.getMessage();
            JustLogger.debug("目标 JDK 类结构预算拒绝 {}: {}", internalName,
                    structuralFailure.getMessage());
            return null;
        } catch (Exception e) {
            JustLogger.debug("目标 JDK 类加载失败 {}: {}", internalName, e.getMessage());
            return null;
        }
    }

    @Override
    public String moduleOf(String internalName) {
        return jrtDelegate == null ? null : jrtDelegate.moduleOf(internalName);
    }

    /** Stable completeness reasons from bounded JDK input reads. */
    public List<String> completenessReasons() {
        if (jrtDelegate != null) {
            return jrtDelegate.completenessReasons();
        }
        return budgetFailure == null ? List.of() : List.of(budgetFailure);
    }

    /** 按内部名读取原始 class，避免完整模式预先 materialize 整个 JDK。 */
    public ClassBytes loadBytes(String internalName) {
        if (internalName == null || !ArchiveLimits.safeEntryName(internalName + ".class", budget)) {
            return null;
        }
        if (jrtDelegate != null) {
            return jrtDelegate.loadBytes(internalName);
        }
        // Java 8 模式：从 classToJar 索引（懒构建）或遍历 jar 查找
        Path jarPath = classToJar.get(internalName);
        if (jarPath == null) {
            jarPath = findInJars(internalName);
            if (jarPath == null) {
                return null;
            }
            classToJar.putIfAbsent(internalName, jarPath);
            jarPath = classToJar.get(internalName);
        }
        try {
            ArchiveLimits.checkContainerSize(jarPath, budget);
            ArchiveLimits.FileReadSnapshot jarSnapshot = ArchiveLimits.snapshotRegularFile(
                    jarPath, budget, "JDK_CLASS");
            ClassBytes result = null;
            try (ArchiveLimits.ZipFileHandle handle = ArchiveLimits.openZipFile(
                    jarSnapshot, "JDK_CLASS")) {
                ZipFile zip = handle.zip();
                ZipEntry entry = zip.getEntry(internalName + ".class");
                if (entry != null) {
                    observeEntry(jarPath, entry);
                    accountClass(jarPath, entry);
                    try (var input = zip.getInputStream(entry)) {
                        byte[] bytes = readClassEntryBytes(jarPath, entry, input);
                        String origin = "jdk:" + jarPath.getFileName();
                        result = new ClassBytes(internalName, bytes, origin,
                                ArchiveMemberProvenance.fromBytes(origin, origin,
                                        internalName + ".class", bytes,
                                        ArchiveMemberProvenance.Role.JDK,
                                        ArchiveMemberProvenance.Kind.CLASS));
                    }
                }
            }
            return result;
        } catch (BudgetInputException failure) {
            budgetFailure = failure.getMessage();
            JustLogger.debug("目标 JDK 类预算拒绝 {}: {}", internalName, failure.getMessage());
            return null;
        } catch (IOException failure) {
            budgetFailure = failure.getMessage();
            JustLogger.debug("目标 JDK 类输入拒绝 {}: {}", internalName, failure.getMessage());
            return null;
        } catch (Exception e) {
            JustLogger.debug("目标 JDK 类加载失败 {}: {}", internalName, e.getMessage());
            return null;
        }
    }

    /** 枚举全部核心 jar 的类（替代 jrt 的 listAll，全量分析用）。 */
    public List<ClassBytes> listAll() throws IOException {
        if (jrtDelegate != null) {
            return jrtDelegate.listAll(JrtClassSource.DESER_MODULES);
        }
        List<ClassBytes> result = new ArrayList<>();
        for (Path jar : coreJars) {
            ArchiveLimits.checkContainerSize(jar, budget);
            ArchiveLimits.FileReadSnapshot jarSnapshot = ArchiveLimits.snapshotRegularFile(
                    jar, budget, "JDK_CLASS");
            try (ArchiveLimits.ZipFileHandle handle = ArchiveLimits.openZipFile(
                    jarSnapshot, "JDK_CLASS")) {
                ZipFile zip = handle.zip();
                var entries = zip.entries();
                while (entries.hasMoreElements()) {
                    ZipEntry entry = entries.nextElement();
                    String name = entry.getName();
                    if (entry.isDirectory() || !name.endsWith(".class")
                            || name.startsWith("META-INF/versions/")) {
                        observeEntry(jar, entry);
                        continue;
                    }
                    String className = name.substring(0, name.length() - 6);
                    classToJar.putIfAbsent(className, jar);
                    observeEntry(jar, entry);
                    accountClass(jar, entry);
                    try (var input = zip.getInputStream(entry)) {
                        byte[] bytes = readClassEntryBytes(jar, entry, input);
                        String origin = "jdk:" + jar.getFileName();
                        result.add(new ClassBytes(className, bytes, origin,
                                ArchiveMemberProvenance.fromBytes(origin, origin,
                                        name, bytes, ArchiveMemberProvenance.Role.JDK,
                                        ArchiveMemberProvenance.Kind.CLASS)));
                    }
                }
            }
        }
        if (jrtDelegate == null) {
            legacyIndexBuilt = true;
        }
        result.sort(java.util.Comparator.comparing(ClassBytes::className)
                .thenComparing(ClassBytes::origin));
        return result;
    }

    public String description() {
        return jdkDescription;
    }

    /** Feature represented by the selected target JDK, or zero when metadata is unavailable. */
    public int feature() {
        return feature;
    }

    @Override
    public JdkSourceInfo sourceInfo() {
        return sourceInfo;
    }

    /** Release an externally mounted JRT image; legacy rt.jar sources own no open handle. */
    @Override
    public void close() {
        if (jrtDelegate != null) {
            jrtDelegate.close();
        }
    }

    private Path findInJars(String internalName) {
        ensureLegacyIndex();
        return classToJar.get(internalName);
    }

    /**
     * Build only the Java 8 central-directory index once. The old path reopened every core
     * jar for every unresolved reference during closure planning; this is metadata-only and
     * avoids retaining any class bytes while removing that repeated disk scan.
     */
    private synchronized void ensureLegacyIndex() {
        if (legacyIndexBuilt) {
            return;
        }
        for (Path jar : coreJars) {
            ArchiveLimits.FileReadSnapshot jarSnapshot;
            try {
                ArchiveLimits.checkContainerSize(jar, budget);
                jarSnapshot = ArchiveLimits.snapshotRegularFile(jar, budget, "JDK_INDEX");
            } catch (IOException failure) {
                budgetFailure = failure.getMessage() == null
                        ? "JDK_INDEX_INPUT_REJECTED" : failure.getMessage();
                JustLogger.debug("目标 JDK 索引物理大小拒绝 {}: {}", jar, failure.getMessage());
                break;
            }
            try (ArchiveLimits.ZipFileHandle handle = ArchiveLimits.openZipFile(
                    jarSnapshot, "JDK_INDEX")) {
                ZipFile zip = handle.zip();
                var entries = zip.entries();
                while (entries.hasMoreElements()) {
                    ZipEntry entry = entries.nextElement();
                    try {
                        inputTracker.checkTime();
                        observeEntry(jar, entry);
                    } catch (IOException failure) {
                        budgetFailure = failure.getMessage();
                        JustLogger.debug("目标 JDK 索引预算拒绝 {}: {}", jar, failure.getMessage());
                        break;
                    }
                    String name = entry.getName();
                    if (!ArchiveLimits.safeEntryName(name, budget)) {
                        budgetFailure = "JDK_ARCHIVE_ENTRY_PATH_CAP:" + budget.maxPathChars();
                        JustLogger.debug("目标 JDK 索引路径拒绝 {}!{}", jar, name);
                        break;
                    }
                    if (entry.isDirectory() || !name.endsWith(".class")
                            || name.startsWith("META-INF/versions/")) {
                        continue;
                    }
                    classToJar.putIfAbsent(name.substring(0, name.length() - 6), jar);
                }
            } catch (IOException e) {
                JustLogger.debug("目标 JDK 索引构建失败 {}: {}", jar, e.getMessage());
            }
        }
        legacyIndexBuilt = true;
    }

    private void observeEntry(Path jar, ZipEntry entry) throws IOException {
        String key = jar.toAbsolutePath().normalize() + "!" + entry.getName();
        if (observedEntries.add(key)) {
            try {
                inputTracker.observe(entry);
            } catch (IOException failure) {
                throw new BudgetInputException("JDK_ARCHIVE_INPUT_BUDGET", failure);
            }
        }
    }

    private void accountClass(Path jar, ZipEntry entry) throws IOException {
        String key = jar.toAbsolutePath().normalize() + "!" + entry.getName();
        if (!accountedClasses.add(key)) {
            return;
        }
        int count = classEntries.incrementAndGet();
        if (count > budget.maxClassEntries()) {
            throw new BudgetInputException("JDK_CLASS_ENTRIES_CAP:" + budget.maxClassEntries());
        }
    }

    /**
     * Read one legacy JDK class entry under the shared byte policy and bind the returned bytes
     * to the CRC advertised by the same ZIP central-directory entry.  ZipFile does not expose
     * a portable parent-relative handle, so the surrounding ZipFileHandle still brackets the
     * container identity; this checksum closes the separate gap where a caller could otherwise
     * receive class bytes that do not match the entry metadata.
     */
    private byte[] readClassEntryBytes(Path jar, ZipEntry entry, java.io.InputStream input)
            throws IOException {
        long declaredSize = entry == null ? -1L : entry.getSize();
        long limit = Math.min(budget.maxEntryBytes(), declaredSize < 0
                ? budget.maxEntryBytes() : declaredSize);
        byte[] bytes = IoUtil.readAll(input, limit, inputTracker);
        if (declaredSize >= 0L && bytes.length != declaredSize) {
            throw new IOException("JDK_CLASS_SIZE_MISMATCH:" + entry.getName());
        }
        if (entry != null && entry.getCrc() >= 0L) {
            CRC32 crc = new CRC32();
            crc.update(bytes);
            if (crc.getValue() != entry.getCrc()) {
                throw new IOException("JDK_CLASS_CRC_MISMATCH:" + entry.getName());
            }
        }
        if (jar != null && entry != null) {
            String key = jar.toAbsolutePath().normalize() + "!" + entry.getName();
            String digest = classEntryDigest(bytes);
            String prior = classEntryDigests.putIfAbsent(key, digest);
            if (prior != null && !prior.equals(digest)) {
                classEntryDigests.remove(key, prior);
                throw new IOException("JDK_CLASS_ENTRY_CHANGED:" + entry.getName());
            }
        }
        return bytes;
    }

    private static String classEntryDigest(byte[] bytes) throws IOException {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IOException("JDK_CLASS_IDENTITY_UNAVAILABLE", impossible);
        }
    }

    private static final class BudgetInputException extends IOException {
        private BudgetInputException(String message) {
            super(message);
        }

        private BudgetInputException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /** 从 $jdkHome/release 或目录名推断版本描述。 */
    private static String detectLegacyVersion(Path home, InputBudget budget,
                                              InputBudget.Tracker tracker) {
        // 尝试读 jre/release（部分发行版有）
        for (Path release : List.of(home.resolve("release"), home.resolve("jre").resolve("release"))) {
            String version = readVersionFromRelease(release,
                    budget == null ? InputBudget.defaults() : budget, tracker);
            if (version != null) {
                return "JDK " + version;
            }
        }
        // 回退：目录名推断（如 jdk8u202 → JDK 8u202）
        String name = home.getFileName().toString().toLowerCase();
        if (name.contains("jdk7") || name.contains("jre7")) {
            return "JDK 7";
        }
        if (name.contains("jdk8") || name.contains("jre8")) {
            return "JDK 8";
        }
        return "JDK (legacy, " + name + ")";
    }

    private static String readReleaseVersion(Path home, InputBudget budget,
                                             InputBudget.Tracker tracker) {
        String version = readVersionFromRelease(home.resolve("release"), budget, tracker);
        return version != null ? "JDK " + version : "JDK 9+";
    }

    private static int detectFeature(Path home, InputBudget budget,
                                     InputBudget.Tracker tracker) {
        for (Path release : List.of(home.resolve("release"), home.resolve("jre").resolve("release"))) {
            String version = readVersionFromRelease(release, budget, tracker);
            if (version == null || version.isBlank()) {
                continue;
            }
            try {
                String normalized = version.startsWith("1.") ? version.substring(2)
                        : version.split("[.+-]", 2)[0];
                int dot = normalized.indexOf('.');
                return Integer.parseInt(dot < 0 ? normalized : normalized.substring(0, dot));
            } catch (RuntimeException ignored) {
                // Try the directory-name fallback below.
            }
        }
        String name = home.getFileName() == null ? "" : home.getFileName().toString().toLowerCase();
        java.util.regex.Matcher matcher = java.util.regex.Pattern.compile("(?:jdk|jre)[^0-9]*(\\d+)")
                .matcher(name);
        if (matcher.find()) {
            try {
                return Integer.parseInt(matcher.group(1));
            } catch (RuntimeException ignored) {
                // Unknown feature; keep the explicit zero sentinel.
            }
        }
        return 0;
    }

    private static String readVersionFromRelease(Path releaseFile, InputBudget budget,
                                                 InputBudget.Tracker tracker) {
        try {
            if (!Files.isRegularFile(releaseFile, java.nio.file.LinkOption.NOFOLLOW_LINKS)
                    || ArchiveLimits.isLinkOrReparsePoint(releaseFile)) {
                return null;
            }
            long size = Files.size(releaseFile);
            InputBudget policy = budget == null ? InputBudget.defaults() : budget;
            InputBudget.Tracker accounting = tracker == null ? policy.tracker() : tracker;
            long cap = Math.min(64L * 1024L, policy.maxEntryBytes());
            if (size > cap) {
                return null;
            }
            byte[] bytes;
            ArchiveLimits.FileReadSnapshot snapshot = ArchiveLimits.snapshotRegularFile(
                    releaseFile, policy, "JDK_RELEASE");
            try (IoUtil.OpenedInput opened = IoUtil.openRegularFile(releaseFile, "JDK_RELEASE")) {
                bytes = IoUtil.readAll(opened.stream(), cap, accounting);
            }
            ArchiveLimits.verifyRegularFileUnchanged(snapshot, "JDK_RELEASE");
            for (String line : new String(bytes, java.nio.charset.StandardCharsets.UTF_8)
                    .split("\\R")) {
                if (line.startsWith("JAVA_VERSION=")) {
                    return line.substring("JAVA_VERSION=".length()).replace("\"", "").trim();
                }
            }
        } catch (IOException ignored) {
        }
        return null;
    }
}
