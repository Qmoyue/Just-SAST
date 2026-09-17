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
import java.io.InputStream;
import java.net.URI;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.FileSystem;
import java.nio.file.FileSystemNotFoundException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.LinkOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.spi.FileSystemProvider;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

/**
 * 通过 jrtfs 读取 JDK 模块镜像类：按需懒加载 + 全量模块枚举。
 * 两种构造：runtime()（运行时自身镜像）/ external(jdkHome)（挂载目标 JDK 的 lib/jrt-fs.jar
 * 并对其 runtime image 打开文件系统——读的是目标 JDK 的类，而非运行时的）。
 * JDK 版本决定 gadget 存亡（如新 JDK 移除/加固的类），--jdk-home 场景必须读目标镜像。
 */
public final class JrtClassSource implements JdkClassSource {

    /** 与反序列化链相关的 JDK 模块（全量加载集）。 */
    public static final List<String> DESER_MODULES = List.of(
            "java.base", "java.naming", "java.rmi", "java.management", "java.scripting", "java.sql",
            // Swing's EventListenerList is used by the declared JDK gadget fragments.  It is
            // outside the default java.* core modules, but still part of the target JDK image
            // and must be discoverable without requiring an unbounded whole-image walk.
            "java.desktop",
            // TemplatesImpl and the XML transformer implementation are part of
            // the JDK XML module. They are a common deserialization sink even
            // when the application bytecode reaches them through reflection,
            // so omitting java.xml makes the default full scan incomplete.
            "java.xml");

    private final ClassFileReader reader = new ClassFileReader();
    private final FileSystem jrt;
    /** Non-null only for external images; the runtime JRT filesystem must never be closed here. */
    private final URLClassLoader ownerLoader;
    /** Class-to-module hits are shared by lazy hierarchy lookups. */
    private final Map<String, String> moduleIndex = new ConcurrentHashMap<>();
    /** Negative lookups must also be memoized; optional framework types are often repeated. */
    private final Set<String> missingClasses = ConcurrentHashMap.newKeySet();
    /** Package-to-module candidates avoid walking every configured module on the first miss. */
    private final Map<String, List<String>> packageIndex = new ConcurrentHashMap<>();
    /** One policy/tracker covers all classes read from this JDK image during a scan. */
    private final InputBudget budget;
    private final InputBudget.Tracker inputTracker;
    private final Set<String> accountedClasses = ConcurrentHashMap.newKeySet();
    private final AtomicInteger classEntries = new AtomicInteger();
    private final AtomicInteger indexedClasses = new AtomicInteger();
    private volatile String budgetFailure;
    private volatile boolean fullIndexBuilt;
    private final int feature;
    private final JdkSourceInfo sourceInfo;
    private volatile boolean closed;

    private JrtClassSource(FileSystem jrt, int feature) {
        this(jrt, feature, null, InputBudget.defaults(), null);
    }

    private JrtClassSource(FileSystem jrt, int feature, URLClassLoader ownerLoader) {
        this(jrt, feature, ownerLoader, InputBudget.defaults(), null);
    }

    private JrtClassSource(FileSystem jrt, int feature, URLClassLoader ownerLoader,
                           InputBudget budget) {
        this(jrt, feature, ownerLoader, budget, null);
    }

    private JrtClassSource(FileSystem jrt, int feature, URLClassLoader ownerLoader,
                           InputBudget budget, InputBudget.Tracker callerTracker) {
        this.jrt = jrt;
        this.feature = Math.max(0, feature);
        this.ownerLoader = ownerLoader;
        InputBudget policy = budget == null ? InputBudget.defaults() : budget;
        this.inputTracker = callerTracker == null ? policy.tracker() : callerTracker;
        // A caller-owned tracker is the aggregate authority.  Using its policy for all local
        // limits prevents a source from observing one budget while enforcing another.
        this.budget = callerTracker == null ? policy : callerTracker.budget();
        this.sourceInfo = new JdkSourceInfo(ownerLoader == null
                ? JdkSourceInfo.ImageKind.RUNTIME_JRT
                : JdkSourceInfo.ImageKind.TARGET_JRT, this.feature);
    }

    /** 运行时 JDK 自身的 jrt 文件系统（JVM 启动即存在）。 */
    public static JrtClassSource runtime() {
        return runtime(InputBudget.defaults());
    }

    /** Runtime JRT source under an explicit immutable input policy. */
    public static JrtClassSource runtime(InputBudget budget) {
        return runtime(budget, null);
    }

    /** Runtime JRT source reusing the scan's caller-owned input tracker. */
    public static JrtClassSource runtime(InputBudget budget,
                                         InputBudget.Tracker callerTracker) {
        try {
            return new JrtClassSource(FileSystems.getFileSystem(URI.create("jrt:/")),
                    Runtime.version().feature(), null, budget, callerTracker);
        } catch (FileSystemNotFoundException e) {
            throw new IllegalStateException("运行时无 jrt 文件系统（非模块化 JDK？）", e);
        }
    }

    /**
     * 外部目标 JDK：加载其 lib/jrt-fs.jar（独立 URLClassLoader，避免被运行时内置 provider 抢先），
     * 用该 provider 以 jrt:/ URI + java.home 环境参数对目标镜像打开文件系统
     * （实测 Path 变体在 jrt-fs 上未实现，URI 变体 + java.home 是可行路径）。
     */
    public static JrtClassSource external(Path jdkHome) throws IOException {
        return external(jdkHome, InputBudget.defaults());
    }

    /** Mount an external JDK image under an explicit immutable input policy. */
    public static JrtClassSource external(Path jdkHome, InputBudget budget) throws IOException {
        return external(jdkHome, budget, null);
    }

    /** Mount an external JDK image while charging its metadata and classes to a caller tracker. */
    public static JrtClassSource external(Path jdkHome, InputBudget budget,
                                          InputBudget.Tracker callerTracker) throws IOException {
        InputBudget requested = budget == null ? InputBudget.defaults() : budget;
        InputBudget.Tracker accounting = callerTracker == null
                ? requested.tracker() : callerTracker;
        InputBudget policy = callerTracker == null ? requested : accounting.budget();
        if (jdkHome == null) {
            throw new IOException("目标 JDK 目录为空");
        }
        Path normalizedHome = jdkHome.toAbsolutePath().normalize();
        // A Jabba-managed `default` home is commonly a junction/symlink. The JDK home is a
        // trusted toolchain input; validate the actual jrt-fs.jar leaf below instead of
        // rejecting that managed alias.
        if (!Files.isDirectory(normalizedHome)) {
            throw new IOException("目标 JDK 目录不是安全目录: " + normalizedHome);
        }
        Path effectiveHome = trustedHome(normalizedHome);
        Path jrtFsJar = effectiveHome.resolve("lib").resolve("jrt-fs.jar");
        if (!Files.isRegularFile(jrtFsJar, java.nio.file.LinkOption.NOFOLLOW_LINKS)
                || ArchiveLimits.isLinkOrReparsePoint(jrtFsJar)) {
            throw new IOException("目标 JDK 缺少安全的 lib/jrt-fs.jar: " + normalizedHome);
        }
        ArchiveLimits.checkContainerSize(jrtFsJar, policy);
        ArchiveLimits.FileReadSnapshot providerSnapshot = ArchiveLimits.snapshotRegularFile(
                jrtFsJar, policy, "JRT_PROVIDER");
        URLClassLoader loader = new URLClassLoader(new URL[] {jrtFsJar.toUri().toURL()},
                ClassLoader.getPlatformClassLoader());
        try {
            for (FileSystemProvider candidate : ServiceLoader.load(FileSystemProvider.class, loader)) {
                if ("jrt".equalsIgnoreCase(candidate.getScheme())) {
                    FileSystem fs = candidate.newFileSystem(URI.create("jrt:/"),
                            Map.of("java.home", effectiveHome.toString()));
                    try {
                        // jrt-fs.jar is the provider code used to mount the target image.  A
                        // replacement between the leaf check and ServiceLoader construction
                        // must not be silently accepted as target-JDK evidence.  Once the
                        // provider is mounted its in-memory classloader/FS is independent of
                        // later edits to the jar, so this bracket is intentionally limited to
                        // the construction boundary.
                        ArchiveLimits.verifyRegularFileUnchanged(providerSnapshot,
                                "JRT_PROVIDER");
                    } catch (IOException | RuntimeException failure) {
                        try {
                            fs.close();
                        } catch (IOException closeFailure) {
                            failure.addSuppressed(closeFailure);
                        }
                        throw failure;
                    }
                    return new JrtClassSource(fs, readFeature(effectiveHome, policy, accounting),
                            loader, policy, accounting);
                }
            }
        } catch (IOException | RuntimeException failure) {
            closeQuietly(loader);
            throw failure;
        }
        closeQuietly(loader);
        throw new IOException("jrt-fs.jar 中未找到 jrt FileSystemProvider: " + jrtFsJar);
    }

    /** 兜底构造：先试 external，目标不是模块化 JDK（无 jrt-fs.jar）返回 null 由调用方降级。 */
    public static JrtClassSource externalOrNull(Path jdkHome) {
        return externalOrNull(jdkHome, InputBudget.defaults());
    }

    public static JrtClassSource externalOrNull(Path jdkHome, InputBudget budget) {
        return externalOrNull(jdkHome, budget, null);
    }

    public static JrtClassSource externalOrNull(Path jdkHome, InputBudget budget,
                                                InputBudget.Tracker callerTracker) {
        try {
            return external(jdkHome, budget, callerTracker);
        } catch (IOException e) {
            JustLogger.warn("外部 JDK jrt-fs 挂载失败（{}），回退运行时镜像", e.getMessage());
            return null;
        }
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
            JustLogger.debug("JDK 类结构预算拒绝 {}: {}", internalName, structuralFailure.getMessage());
            return null;
        } catch (Exception e) {
            JustLogger.debug("JDK 类加载失败 {}: {}", internalName, e.getMessage());
            return null;
        }
    }

    /** 按内部名读取原始 class，仅供 frontend 的按需闭包规划使用。 */
    public ClassBytes loadBytes(String internalName) {
        try {
            String module = moduleOf(internalName);
            if (module == null) {
                return null;
            }
            Path classFile = jrt.getPath("modules", module, internalName + ".class");
            if (!Files.exists(classFile)) {
                return null;
            }
            return readClassFile(module, internalName, classFile);
        } catch (BudgetInputException failure) {
            budgetFailure = failure.getMessage();
            JustLogger.debug("JDK 类读取预算拒绝 {}: {}", internalName, failure.getMessage());
            return null;
        } catch (Exception e) {
            JustLogger.debug("JDK 类加载失败 {}: {}", internalName, e.getMessage());
            return null;
        }
    }

    /** Stable completeness reasons collected while optional JDK classes are requested. */
    public List<String> completenessReasons() {
        return budgetFailure == null ? List.of() : List.of(budgetFailure);
    }

    /** Feature represented by this JRT image, used for multi-release archive selection. */
    public int feature() {
        return feature;
    }

    @Override
    public JdkSourceInfo sourceInfo() {
        return sourceInfo;
    }

    /** Close only resources owned by external(Path); runtime() remains process-owned. */
    @Override
    public void close() {
        if (ownerLoader == null || closed) {
            return;
        }
        synchronized (this) {
            if (closed) {
                return;
            }
            closed = true;
            try {
                jrt.close();
            } catch (IOException | RuntimeException e) {
                JustLogger.debug("外部 JDK jrt 文件系统关闭失败: {}", e.getMessage());
            }
            closeQuietly(ownerLoader);
        }
    }

    @Override
    public String moduleOf(String internalName) {
        try {
            return moduleOfChecked(internalName);
        } catch (IOException failure) {
            JustLogger.debug("JRT 模块查询失败 {}: {}", internalName, failure.getMessage());
            return null;
        } catch (RuntimeException ignored) {
            // The JRT provider is allowed to reject a missing package or a malformed
            // descriptor with a provider-specific runtime exception.  Module lookup is
            // optional metadata; an application-owned or array name is simply not a JRT
            // class and must not flood a normal scan with one debug line per reference.
            return null;
        }
    }

    private String moduleOfChecked(String internalName) throws IOException {
        if (internalName == null || internalName.isBlank()
                || internalName.indexOf('[') >= 0
                || (internalName.startsWith("L") && internalName.endsWith(";"))
                || !ArchiveLimits.safeEntryName(internalName + ".class", budget)) {
            return null;
        }
        String cached = moduleIndex.get(internalName);
        if (cached != null) {
            return cached;
        }
        if (missingClasses.contains(internalName)) {
            return null;
        }
        Path inJavaBase = jrt.getPath("modules", "java.base", internalName + ".class");
        if (Files.exists(inJavaBase)) {
            moduleIndex.put(internalName, "java.base");
            return "java.base";
        }
        for (String module : modulesForPackage(packageName(internalName))) {
            Path classFile = jrt.getPath("modules", module, internalName + ".class");
            if (Files.exists(classFile)) {
                moduleIndex.putIfAbsent(internalName, module);
                return moduleIndex.get(internalName);
            }
        }
        // A caller-owned tracker may have exhausted while reading the package index. Do not
        // fall through to the bounded full-module walk: that would reset the effective budget
        // through a different metadata path and could turn an incomplete lookup into a false
        // result.
        if (budgetFailure != null) {
            return null;
        }
        if (!fullIndexBuilt) {
            // Unknown JDK names used to trigger a walk of every module.  Just's default
            // deserialization model has a bounded module surface; indexing only that surface
            // keeps a missing optional type from turning one lookup into a full JRT scan.
            synchronized (this) {
                if (!fullIndexBuilt) {
                    try {
                        buildFullIndex(DESER_MODULES);
                    } finally {
                        // A failed/limited index is still terminal for this source. Repeating
                        // the walk for every unresolved type would turn one bounded lookup
                        // into an unbounded retry loop and would not improve completeness.
                        fullIndexBuilt = true;
                    }
                }
            }
        }
        String result = moduleIndex.get(internalName);
        if (result == null) {
            missingClasses.add(internalName);
        }
        return result;
    }

    /**
     * JRT exposes a package index. Querying it is O(number of modules containing the package),
     * while walking every class below /modules is O(the whole image). Keep a sorted immutable
     * list so external and runtime images have identical lookup order.
     */
    private List<String> modulesForPackage(String packageName) {
        if (packageName == null || packageName.isBlank()) {
            return List.of();
        }
        List<String> cached = packageIndex.get(packageName);
        if (cached != null) {
            return cached;
        }
        try {
            Path packagePath = jrt.getPath("packages", packageName);
            if (!Files.isDirectory(packagePath)) {
                packageIndex.put(packageName, List.of());
                return List.of();
            }
            List<String> modules;
            try (Stream<Path> children = Files.list(packagePath)) {
                List<String> observed = new ArrayList<>();
                var iterator = children.iterator();
                while (iterator.hasNext()) {
                    Path modulePath = iterator.next();
                    try {
                        inputTracker.checkTime();
                        inputTracker.observeFilesystemEntry();
                    } catch (IOException budgetFailure) {
                        this.budgetFailure = "JDK_PACKAGE_INDEX_INPUT_BUDGET";
                        throw budgetFailure;
                    }
                    if (modulePath == null || isMutableProviderLink(modulePath)) {
                        this.budgetFailure = "JDK_PACKAGE_INDEX_LINK";
                        throw new IOException(this.budgetFailure);
                    }
                    Path fileName = modulePath.getFileName();
                    if (fileName == null || fileName.toString().isBlank()) {
                        this.budgetFailure = "JDK_PACKAGE_INDEX_ENTRY_INVALID";
                        throw new IOException(this.budgetFailure);
                    }
                    observed.add(fileName.toString());
                }
                modules = observed.stream().sorted().toList();
            }
            List<String> stable = List.copyOf(modules);
            packageIndex.putIfAbsent(packageName, stable);
            return packageIndex.get(packageName);
        } catch (IOException e) {
            // The package index is an optimization, not a correctness boundary.  Providers
            // for older/external images may expose /modules but not /packages; let moduleOf
            // fall back to the bounded deserialization-module index instead of turning a JDK
            // lookup into a silent load failure.
            JustLogger.debug("JRT package index unavailable {}: {}", packageName, e.getMessage());
            return List.of();
        } catch (RuntimeException ignored) {
            // Some JRT providers throw NPE/IllegalArgumentException for a package that is
            // absent from the image.  Treat that as an ordinary negative lookup; package
            // indexing is an optimization and never a semantic proof.
            packageIndex.putIfAbsent(packageName, List.of());
            return List.of();
        }
    }

    private static String packageName(String internalName) {
        int slash = internalName.lastIndexOf('/');
        // The JRT /packages index uses the module-system package spelling (dots), while
        // class names arriving from ASM use JVM internal-name slashes.
        return slash < 0 ? "" : internalName.substring(0, slash).replace('/', '.');
    }

    /** JRT entries are immutable provider objects; DOS reparse probing mislabels them on some
     * Windows providers. Filesystem-backed fallbacks still use the shared link guard. */
    private static boolean isMutableProviderLink(Path path) {
        if (path == null) {
            return true;
        }
        try {
            String scheme = path.getFileSystem().provider().getScheme();
            return !"jrt".equalsIgnoreCase(scheme)
                    && ArchiveLimits.isLinkOrReparsePoint(path);
        } catch (RuntimeException failure) {
            return true;
        }
    }

    /** Immutable identity bracketing one class-entry read from a JRT provider. */
    record ClassEntrySnapshot(Path path, BasicFileAttributes attributes) {
        ClassEntrySnapshot {
            path = path == null ? null : path.toAbsolutePath().normalize();
            if (attributes == null) {
                throw new IllegalArgumentException("class-entry attributes are required");
            }
        }

        /** Expose provider identity strength so callers do not infer content equality. */
        ArchiveLimits.IdentityStrength identityStrength() {
            return ArchiveLimits.identityStrength(path, attributes);
        }
    }

    private ClassBytes readClassFile(String module, String internalName, Path classFile)
            throws IOException {
        String key = module + "/" + internalName;
        ClassEntrySnapshot snapshot = snapshotClassEntry(classFile);
        long size = snapshot.attributes().size();
        if (size > budget.maxEntryBytes()) {
            throw new BudgetInputException("JDK_CLASS_BYTES_CAP:" + budget.maxEntryBytes());
        }
        if (accountedClasses.add(key)) {
            int count = classEntries.incrementAndGet();
            if (count > budget.maxClassEntries()) {
                throw new BudgetInputException("JDK_CLASS_ENTRIES_CAP:" + budget.maxClassEntries());
            }
            try {
                inputTracker.observeFile("jdk:/" + key + ".class", size);
            } catch (IOException failure) {
                throw new BudgetInputException("JDK_INPUT_BUDGET", failure);
            }
        }
        try (IoUtil.OpenedInput opened = openClassInput(classFile);
             InputStream input = opened.stream()) {
            byte[] bytes = IoUtil.readAll(input,
                    Math.min(size, budget.maxEntryBytes()), inputTracker);
            verifyClassEntryUnchanged(snapshot);
            String origin = "jdk:/" + module;
            return new ClassBytes(internalName, bytes, origin,
                    ArchiveMemberProvenance.fromBytes(origin, origin, internalName + ".class",
                            bytes, ArchiveMemberProvenance.Role.JDK,
                            ArchiveMemberProvenance.Kind.CLASS));
        } catch (IOException failure) {
            throw new BudgetInputException(failure.getMessage() == null
                    ? "JDK_INPUT_BUDGET" : failure.getMessage(), failure);
        }
    }

    private static ClassEntrySnapshot snapshotClassEntry(Path path) throws IOException {
        if (path == null) {
            throw new IOException("JDK_CLASS_ENTRY_NOT_REGULAR");
        }
        BasicFileAttributes attributes = readClassAttributes(path);
            if (!attributes.isRegularFile() || ArchiveLimits.isLinkOrReparsePoint(path)) {
                throw new IOException("JDK_CLASS_ENTRY_NOT_REGULAR");
            }
        return new ClassEntrySnapshot(path, attributes);
    }

    private static void verifyClassEntryUnchanged(ClassEntrySnapshot snapshot)
            throws IOException {
        if (snapshot == null || snapshot.path() == null) {
            throw new IOException("JDK_CLASS_CHANGED_DURING_READ");
        }
        BasicFileAttributes current = readClassAttributes(snapshot.path());
        BasicFileAttributes expected = snapshot.attributes();
        if (!sameClassEntryIdentity(expected, current)) {
            throw new IOException("JDK_CLASS_CHANGED_DURING_READ");
        }
    }

    /**
     * The JRT provider is immutable but does not implement the NOFOLLOW_LINKS option.  Keep
     * the strict option on providers that support it and use the provider's ordinary read only
     * for this virtual image; a JRT class entry cannot be replaced by a filesystem symlink.
     */
    private static BasicFileAttributes readClassAttributes(Path path) throws IOException {
        try {
            return Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        } catch (UnsupportedOperationException unsupported) {
            return Files.readAttributes(path, BasicFileAttributes.class);
        }
    }

    private static IoUtil.OpenedInput openClassInput(Path path) throws IOException {
        String scheme = path == null ? "" : path.getFileSystem().provider().getScheme();
        if ("jrt".equalsIgnoreCase(scheme)) {
            return IoUtil.openImmutableProviderFile(path, "JDK_CLASS");
        }
        return IoUtil.openRegularFile(path, "JDK_CLASS");
    }

    private static boolean sameClassEntryIdentity(BasicFileAttributes expected,
                                                   BasicFileAttributes current) {
        if (expected.isRegularFile() != current.isRegularFile()
                || expected.size() != current.size()
                || !expected.creationTime().equals(current.creationTime())
                || !expected.lastModifiedTime().equals(current.lastModifiedTime())) {
            return false;
        }
        if (expected.fileKey() != null || current.fileKey() != null) {
            return expected.fileKey() != null && current.fileKey() != null
                    && expected.fileKey().equals(current.fileKey());
        }
        // JRT providers commonly expose no fileKey.  A non-zero creation time is the
        // portable replacement signal; epoch sentinels on both sides are accepted for
        // immutable providers whose metadata intentionally omits identity.
        return expected.creationTime().toMillis() == 0L
                && current.creationTime().toMillis() == 0L
                || expected.creationTime().equals(current.creationTime());
    }

    /** Package-local hostile contract seam; production reads use the same snapshot logic. */
    static ClassEntrySnapshot snapshotClassEntryForContract(Path path) throws IOException {
        return snapshotClassEntry(path);
    }

    /** Package-local hostile contract seam; production reads use the same verification logic. */
    static void verifyClassEntryForContract(ClassEntrySnapshot snapshot) throws IOException {
        verifyClassEntryUnchanged(snapshot);
    }

    private static int readFeature(java.nio.file.Path jdkHome, InputBudget budget,
                                   InputBudget.Tracker tracker) {
        InputBudget policy = budget == null ? InputBudget.defaults() : budget;
        InputBudget.Tracker accounting = tracker == null ? policy.tracker() : tracker;
        try {
            java.nio.file.Path release = jdkHome.resolve("release");
            if (java.nio.file.Files.isRegularFile(release,
                    java.nio.file.LinkOption.NOFOLLOW_LINKS)
                    && !ArchiveLimits.isLinkOrReparsePoint(release)) {
                long size = Files.size(release);
                if (size > Math.min(64L * 1024L, policy.maxEntryBytes())) {
                    return 0;
                }
                byte[] bytes;
                ArchiveLimits.FileReadSnapshot snapshot = ArchiveLimits.snapshotRegularFile(
                        release, policy, "JRT_RELEASE");
                try (IoUtil.OpenedInput opened = IoUtil.openRegularFile(
                        release, "JRT_RELEASE")) {
                    bytes = IoUtil.readAll(opened.stream(),
                            Math.min(64L * 1024L, policy.maxEntryBytes()), accounting);
                }
                ArchiveLimits.verifyRegularFileUnchanged(snapshot, "JRT_RELEASE");
                for (String line : new String(bytes, java.nio.charset.StandardCharsets.UTF_8)
                        .split("\\R")) {
                    if (!line.startsWith("JAVA_VERSION=")) {
                        continue;
                    }
                    String version = line.substring("JAVA_VERSION=".length())
                            .replace("\"", "").trim();
                    String normalized = version.startsWith("1.") ? version.substring(2)
                            : version.split("[.+-]", 2)[0];
                    int dot = normalized.indexOf('.');
                    return Integer.parseInt(dot < 0 ? normalized : normalized.substring(0, dot));
                }
            }
        } catch (IOException | RuntimeException ignored) {
            // An unknown image version falls back to the scanner runtime selection.
        }
        return 0;
    }

    private void buildFullIndex(List<String> modulesToIndex) throws IOException {
        Path modules = jrt.getPath("modules");
        for (String moduleName : modulesToIndex) {
            Path module = modules.resolve(moduleName);
            if (!Files.isDirectory(module)) {
                continue;
            }
            try (Stream<Path> walk = Files.walk(module)) {
                try {
                    walk.forEach(p -> {
                        try {
                            inputTracker.checkTime();
                            accountIndexPath(module, p);
                            if (!p.toString().endsWith(".class")) {
                                return;
                            }
                            String rel = module.relativize(p).toString().replace('\\', '/');
                            if (!ArchiveLimits.safeEntryName(rel, budget)) {
                                throw new IOException("JDK_CLASS_INDEX_PATH_CAP:" + budget.maxPathChars());
                            }
                            String className = rel.substring(0, rel.length() - 6);
                            if (indexedClasses.incrementAndGet() > budget.maxClassEntries()) {
                                throw new IOException("JDK_CLASS_INDEX_CAP:" + budget.maxClassEntries());
                            }
                            moduleIndex.putIfAbsent(className, moduleName);
                        } catch (IOException failure) {
                            throw new java.io.UncheckedIOException(failure);
                        }
                    });
                } catch (java.io.UncheckedIOException failure) {
                    budgetFailure = failure.getCause().getMessage();
                    throw failure.getCause();
                }
            }
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

    private static void closeQuietly(URLClassLoader loader) {
        try {
            loader.close();
        } catch (IOException | RuntimeException e) {
            JustLogger.debug("外部 JDK jrt 类加载器关闭失败: {}", e.getMessage());
        }
    }

    /** Resolve only the trusted toolchain root; untrusted artifact paths never use this path. */
    private static Path trustedHome(Path normalizedHome) throws IOException {
        if (!ArchiveLimits.isLinkOrReparsePoint(normalizedHome)) {
            return normalizedHome;
        }
        try {
            Path linkTarget = Files.readSymbolicLink(normalizedHome);
            Path resolved = (linkTarget.isAbsolute()
                    ? linkTarget : normalizedHome.getParent().resolve(linkTarget))
                    .toAbsolutePath().normalize();
            if (!Files.isDirectory(resolved)
                    || ArchiveLimits.isLinkOrReparsePoint(resolved)) {
                throw new IOException("目标 JDK 真实目录不是安全目录");
            }
            return resolved;
        } catch (IOException | RuntimeException linkReadFailure) {
            try {
                Path resolved = normalizedHome.toRealPath();
                if (!Files.isDirectory(resolved)
                        || ArchiveLimits.isLinkOrReparsePoint(resolved)) {
                    throw new IOException("目标 JDK 真实目录不是安全目录");
                }
                return resolved;
            } catch (IOException | RuntimeException realPathFailure) {
                realPathFailure.addSuppressed(linkReadFailure);
                throw new IOException("目标 JDK 目录别名无法解析", realPathFailure);
            }
        }
    }

    /** 枚举指定模块的全部类字节（--jdk 全量分析用）。 */
    public List<ClassBytes> listAll(List<String> modules) throws IOException {
        List<ClassBytes> result = new ArrayList<>();
        Path modulesRoot = jrt.getPath("modules");
        for (String module : modules) {
            Path modulePath = modulesRoot.resolve(module);
            if (!Files.isDirectory(modulePath)) {
                continue;
            }
            List<Path> classFiles;
            try (Stream<Path> walk = Files.walk(modulePath)) {
                try {
                    classFiles = walk.peek(path -> {
                                try {
                                    inputTracker.checkTime();
                                    accountIndexPath(modulePath, path);
                                } catch (IOException failure) {
                                    throw new java.io.UncheckedIOException(failure);
                                }
                            })
                            .filter(p -> p.toString().endsWith(".class"))
                            .sorted().toList();
                } catch (java.io.UncheckedIOException failure) {
                    budgetFailure = failure.getCause() == null
                            ? "JDK_CLASS_INDEX_INPUT_BUDGET" : failure.getCause().getMessage();
                    throw failure.getCause() == null
                            ? new IOException(budgetFailure) : failure.getCause();
                }
            }
            for (Path p : classFiles) {
                    String rel = modulePath.relativize(p).toString().replace('\\', '/');
                    String className = rel.substring(0, rel.length() - 6);
                    try {
                        result.add(readClassFile(module, className, p));
                    } catch (BudgetInputException failure) {
                        budgetFailure = failure.getMessage();
                        throw failure;
                    } catch (IOException e) {
                        JustLogger.debug("JDK 类读取失败 {}: {}", className, e.getMessage());
                    }
            }
        }
        result.sort(java.util.Comparator.comparing(ClassBytes::className)
                .thenComparing(ClassBytes::origin));
        return result;
    }

    /** Charge every path visited by an explicit JRT index/list walk to the caller tracker. */
    private void accountIndexPath(Path moduleRoot, Path path) throws IOException {
        if (moduleRoot == null || path == null) {
            throw new IOException("JDK_CLASS_INDEX_INPUT_BUDGET");
        }
        String relative = moduleRoot.equals(path) ? "" : moduleRoot.relativize(path)
                .toString().replace('\\', '/');
        if (!relative.isBlank() && !ArchiveLimits.safeEntryName(relative, budget)) {
            throw new IOException("JDK_CLASS_INDEX_PATH_CAP:" + budget.maxPathChars());
        }
        try {
            inputTracker.observeFilesystemEntry();
        } catch (IOException failure) {
            throw new IOException("JDK_CLASS_INDEX_INPUT_BUDGET", failure);
        }
        if (ArchiveLimits.isLinkOrReparsePoint(path)) {
            throw new IOException("JDK_CLASS_INDEX_LINK");
        }
    }
}
