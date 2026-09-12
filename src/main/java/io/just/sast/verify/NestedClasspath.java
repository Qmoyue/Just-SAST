package io.just.sast.verify;

import io.just.sast.util.ArchiveLimits;
import io.just.sast.util.IoUtil;
import io.just.sast.run.InputBudget;

import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.LinkOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.jar.Manifest;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * 把普通 JAR、目录和常见 fat JAR/WAR 统一表示为 classpath。
 *
 * <p>嵌套条目只展开到临时目录，单条/总大小有界，路径经过归一化校验；实例关闭时
 * 删除所有展开产物。该组件不包含题目或框架名称，构造器和动态探针共享同一边界。</p>
 */
public final class NestedClasspath implements AutoCloseable {

    private final List<Path> entries;
    private final List<Path> artifacts;

    private NestedClasspath(List<Path> entries, List<Path> artifacts) {
        this.entries = List.copyOf(entries);
        this.artifacts = new ArrayList<>(artifacts);
    }

    /** 打开输入 classpath，并在展开失败时清理已创建的中间文件。 */
    public static NestedClasspath open(List<Path> inputs) throws IOException {
        return open(inputs, InputBudget.defaults());
    }

    /** Open a classpath with one explicit budget shared by every direct and nested input. */
    public static NestedClasspath open(List<Path> inputs, InputBudget budget) throws IOException {
        return open(inputs, budget, runtimeFeature(), null);
    }

    /**
     * Open a classpath under the feature version of the child JVM that will consume it.
     * Multi-release classes extracted from fat archives are projected to their logical path
     * using this feature; the parent scanner's runtime version is never used implicitly when
     * the caller has a target-JDK selection.
     */
    public static NestedClasspath open(List<Path> inputs, InputBudget budget,
                                       int targetFeature) throws IOException {
        return open(inputs, budget, targetFeature, null);
    }

    /** Open using the runtime feature while retaining a caller-owned aggregate tracker. */
    public static NestedClasspath open(List<Path> inputs, InputBudget budget,
                                       InputBudget.Tracker callerTracker) throws IOException {
        return open(inputs, budget, runtimeFeature(), callerTracker);
    }

    /**
     * Open a classpath while retaining the caller-owned aggregate tracker.  The tracker is
     * intentionally part of the API rather than an implementation detail: verifier payload
     * construction must not reset the scan-wide archive/byte/time budget when it expands the
     * same application and dependency inputs a second time.
     */
    public static NestedClasspath open(List<Path> inputs, InputBudget budget,
                                       int targetFeature, InputBudget.Tracker callerTracker)
            throws IOException {
        List<Path> entries = new ArrayList<>();
        List<Path> artifacts = new ArrayList<>();
        InputBudget requested = budget == null ? InputBudget.defaults() : budget;
        InputBudget.Tracker sharedBudget = callerTracker == null
                ? requested.tracker() : callerTracker;
        // The mutable tracker is authoritative for all dimensions after it is supplied.  This
        // keeps a legacy caller that passes a tracker made from a derived policy deterministic,
        // instead of pairing counters from one policy with limits from another.
        InputBudget policy = sharedBudget.budget();
        int feature = targetFeature > 0 ? targetFeature : runtimeFeature();
        Set<Path> uniqueInputs = new LinkedHashSet<>();
        if (inputs != null) {
            for (Path input : inputs) {
                if (input != null) {
                    uniqueInputs.add(input.toAbsolutePath().normalize());
                }
            }
        }
        try {
            for (Path input : uniqueInputs) {
                // Validate the direct classpath root before adding it to the URL list.
                // Files.isRegularFile follows links, so checking only inside expand()
                // misses a symlinked directory (which is never expanded but is still
                // later handed to URLClassLoader).
                ArchiveLimits.checkPathAncestors(input, policy);
                if (ArchiveLimits.isLinkOrReparsePoint(input)) {
                    throw new IOException("unsafe classpath input link or reparse point: " + input);
                }
                entries.add(input);
                entries.addAll(expand(input, artifacts, sharedBudget, policy, 0, feature));
            }
            return new NestedClasspath(entries, artifacts);
        } catch (IOException | RuntimeException e) {
            deleteAll(artifacts);
            throw e;
        }
    }

    /** 文件系统 classpath 条目（原始输入 + 展开的 classes 目录/嵌套 JAR）。 */
    public List<Path> entries() {
        return entries;
    }

    /** URLClassLoader 所需的 classpath URL。 */
    public List<URL> urls() throws IOException {
        List<URL> urls = new ArrayList<>(entries.size());
        for (Path entry : entries) {
            urls.add(entry.toUri().toURL());
        }
        return List.copyOf(urls);
    }

    @Override
    public void close() {
        List<Path> toDelete;
        synchronized (artifacts) {
            toDelete = new ArrayList<>(artifacts);
            artifacts.clear();
        }
        deleteAll(toDelete);
    }

    private static List<Path> expand(Path input, List<Path> artifacts,
                                     InputBudget.Tracker budget, InputBudget policy) throws IOException {
        return expand(input, artifacts, budget, policy, 0, runtimeFeature());
    }

    /** Expand one archive and recursively inspect extracted fat-archive libraries. */
    private static List<Path> expand(Path input, List<Path> artifacts,
                                     InputBudget.Tracker budget, InputBudget policy,
                                     int depth, int targetFeature) throws IOException {
        if (!Files.isRegularFile(input, LinkOption.NOFOLLOW_LINKS)) {
            return List.of();
        }
        if (ArchiveLimits.isLinkOrReparsePoint(input)) {
            throw new IOException("unsafe classpath input link or reparse point: " + input);
        }
        ArchiveLimits.checkContainerSize(input, policy);
        ArchiveLimits.FileReadSnapshot snapshot = ArchiveLimits.snapshotRegularFile(
                input, policy, "NESTED_ARCHIVE");
        boolean hasClasses = false;
        boolean hasLib = false;
        List<ZipEntry> orderedEntries = new ArrayList<>();
        Set<String> seenNames = new LinkedHashSet<>();
        try (ArchiveLimits.ZipFileHandle handle = ArchiveLimits.openZipFile(snapshot,
                "NESTED_ARCHIVE")) {
            ZipFile zip = handle.zip();
            Enumeration<? extends ZipEntry> elements = zip.entries();
            while (elements.hasMoreElements()) {
                ZipEntry entry = elements.nextElement();
                String name = entry.getName();
                if (!ArchiveLimits.safeEntryName(name, policy)) {
                    throw new IOException("unsafe archive entry: " + name);
                }
                if (!seenNames.add(name)) {
                    throw new IOException("duplicate archive entry: " + name);
                }
                budget.observe(entry);
                orderedEntries.add(entry);
                if (!entry.isDirectory() && isNestedClass(name)) {
                    hasClasses = true;
                } else if (!entry.isDirectory() && isNestedLibrary(name)) {
                    hasLib = true;
                }
            }
            orderedEntries.sort(Comparator.comparing(ZipEntry::getName));
            if (!hasClasses && !hasLib) {
                return List.of();
            }
            ArchiveSelection selection = ArchiveSelection.read(zip, orderedEntries, targetFeature,
                    budget, policy);

            Path root = Files.createTempDirectory("just-verify-cp-");
            artifacts.add(root);
            Path classes = root.resolve("classes");
            Path lib = root.resolve("lib");
            Files.createDirectories(classes);
            Files.createDirectories(lib);
            Set<String> seenOutputs = new LinkedHashSet<>();
            try {
                for (ZipEntry entry : orderedEntries) {
                    String name = entry.getName();
                    boolean classEntry = isNestedClass(name) && !entry.isDirectory();
                    boolean libraryEntry = isNestedLibrary(name);
                    if (!classEntry && !libraryEntry) {
                        continue;
                    }
                    String defaultRelative = nestedRelative(name);
                    if (!selection.include(name, classEntry, defaultRelative)) {
                        continue;
                    }
                    String relative = classEntry
                            ? selection.logicalPath(name, defaultRelative)
                            : defaultRelative;
                    if (!ArchiveLimits.safeEntryName(relative, policy)) {
                        throw new IOException("unsafe nested entry: " + name);
                    }
                    String outputKey = (classEntry ? "classes/" : "lib/") + relative;
                    if (!seenOutputs.add(outputKey)) {
                        throw new IOException("duplicate normalized nested entry: " + name);
                    }
                    Path base = classEntry ? classes : lib;
                    Path output = base.resolve(relative).normalize();
                    if (!output.startsWith(base)) {
                        throw new IOException("unsafe nested entry: " + name);
                    }
                    createOutputParent(base, output.getParent());
                    OutputParentSnapshot parentSnapshot = snapshotOutputParent(base,
                            output.getParent());
                    if (!safeOutputParent(base, output.getParent())
                            || Files.exists(output, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
                        throw new IOException("unsafe nested output path: " + output);
                    }
                    verifyOutputParent(parentSnapshot);
                    try (var inputStream = zip.getInputStream(entry)) {
                        copyBounded(inputStream, output, budget);
                    }
                    // Re-check the complete parent chain after the write.  A concurrent
                    // checkout/build must not be able to replace an output directory with a
                    // link and make the next classpath URL escape the owned temporary root.
                    verifyOutputParent(parentSnapshot);
                    if (!safeOutputParent(base, output.getParent())
                            || !Files.isRegularFile(output, LinkOption.NOFOLLOW_LINKS)
                            || ArchiveLimits.isLinkOrReparsePoint(output)) {
                        throw new IOException("unsafe nested output path changed: " + output);
                    }
                }
            } catch (IOException | RuntimeException e) {
                deleteQuietly(root);
                artifacts.remove(root);
                throw e;
            }

            List<Path> result = new ArrayList<>();
            if (hasClasses) {
                result.add(classes);
            }
            if (hasLib) {
                try (var stream = Files.list(lib)) {
                    List<Path> libraries = stream.filter(Files::isRegularFile)
                            .filter(path -> path.getFileName().toString().endsWith(".jar"))
                            .sorted(Comparator.comparing(Path::toString))
                            .toList();
                    result.addAll(libraries);
                    if (depth < policy.maxArchiveNesting()) {
                        for (Path library : libraries) {
                            try {
                                result.addAll(expand(library, artifacts, budget, policy,
                                        depth + 1, targetFeature));
                            } catch (IOException nestedFailure) {
                                // Ordinary dependency jars are often not fat archives (and
                                // fixtures may intentionally be opaque).  They remain on the
                                // classpath as-is; only bounded/input-integrity failures abort
                                // the verifier setup.
                                if (!"ARCHIVE_CORRUPT".equals(nestedFailure.getMessage())) {
                                    throw nestedFailure;
                                }
                            }
                        }
                    } else if (!libraries.isEmpty()) {
                        throw new IOException("NESTING_CAP:" + policy.maxArchiveNesting());
                    }
                }
            }
            return List.copyOf(result);
        } catch (java.util.zip.ZipException notAnArchive) {
            // A verifier classpath is an input boundary, not an optional best-effort
            // directory walk.  Returning an empty expansion here used to make a corrupt
            // fat archive look like a successful setup and hid the reason from the dynamic
            // result.  Keep the parent artifact visible, but fail closed with a stable code.
            throw new IOException("ARCHIVE_CORRUPT", notAnArchive);
        }
    }

    private static boolean isNestedClass(String name) {
        return name.startsWith("BOOT-INF/classes/") || name.startsWith("WEB-INF/classes/");
    }

    private static boolean isNestedLibrary(String name) {
        return (name.startsWith("BOOT-INF/lib/") || name.startsWith("WEB-INF/lib/"))
                && name.endsWith(".jar") && !name.endsWith("/");
    }

    private static boolean sameFileKey(BasicFileAttributes before,
                                       BasicFileAttributes after) {
        if (before == null || after == null) {
            return false;
        }
        if (before.fileKey() != null || after.fileKey() != null) {
            return before.fileKey() != null && after.fileKey() != null
                    && before.fileKey().equals(after.fileKey());
        }
        return before.creationTime().equals(after.creationTime());
    }

    private static String nestedRelative(String name) throws IOException {
        String prefix = name.startsWith("BOOT-INF/") ? "BOOT-INF/" : "WEB-INF/";
        String relative = name.substring(prefix.length()).replace('\\', '/');
        int slash = relative.indexOf('/');
        if (slash < 0 || slash == relative.length() - 1) {
            throw new IOException("invalid nested entry: " + name);
        }
        return relative.substring(slash + 1);
    }

    /** Bounded multi-release view used when fat-archive classes are materialized. */
    private static final class ArchiveSelection {
        private final Map<String, VersionedPath> selectedByPhysical;
        private final Set<String> overriddenLogical;

        private ArchiveSelection(Map<String, VersionedPath> selectedByPhysical,
                                 Set<String> overriddenLogical) {
            this.selectedByPhysical = Map.copyOf(selectedByPhysical);
            this.overriddenLogical = Set.copyOf(overriddenLogical);
        }

        private static ArchiveSelection read(ZipFile zip, List<ZipEntry> entries,
                                             int targetFeature, InputBudget.Tracker tracker,
                                             InputBudget policy) throws IOException {
            boolean multiRelease = false;
            for (ZipEntry entry : entries) {
                if (!"META-INF/MANIFEST.MF".equalsIgnoreCase(entry.getName())) {
                    continue;
                }
                try (var input = zip.getInputStream(entry)) {
                    byte[] bytes = IoUtil.readAll(input,
                            Math.min(64L * 1024L, policy.maxEntryBytes()), tracker);
                    multiRelease = "true".equalsIgnoreCase(new Manifest(
                            new java.io.ByteArrayInputStream(bytes)).getMainAttributes()
                            .getValue("Multi-Release"));
                } catch (IOException | RuntimeException malformed) {
                    if (isBudgetFailure(malformed)) {
                        throw new IOException("ARCHIVE_MANIFEST_BUDGET", malformed);
                    }
                    // A malformed manifest is treated as a base-only archive.  This mirrors
                    // the static reader and avoids allowing an untrusted versioned class to
                    // shadow the base view merely because metadata is malformed.
                    multiRelease = false;
                }
                break;
            }
            if (!multiRelease || targetFeature < 9) {
                return new ArchiveSelection(Map.of(), Set.of());
            }
            Map<String, VersionedPath> bestByLogical = new HashMap<>();
            for (ZipEntry entry : entries) {
                VersionedPath candidate = VersionedPath.parse(entry.getName());
                if (candidate == null || candidate.version() > targetFeature) {
                    continue;
                }
                VersionedPath previous = bestByLogical.get(candidate.logicalPath());
                if (previous == null || candidate.version() > previous.version()
                        || (candidate.version() == previous.version()
                        && candidate.physicalPath().compareTo(previous.physicalPath()) < 0)) {
                    bestByLogical.put(candidate.logicalPath(), candidate);
                }
            }
            Map<String, VersionedPath> byPhysical = new HashMap<>();
            for (VersionedPath selected : bestByLogical.values()) {
                byPhysical.put(selected.physicalPath(), selected);
            }
            return new ArchiveSelection(byPhysical, bestByLogical.keySet());
        }

        private boolean include(String physicalPath, boolean classEntry, String logicalPath) {
            if (!classEntry) {
                return true;
            }
            VersionedPath versioned = VersionedPath.parse(physicalPath);
            if (versioned != null) {
                return selectedByPhysical.containsKey(physicalPath);
            }
            return !overriddenLogical.contains(logicalPath)
                    && !physicalPath.startsWith("BOOT-INF/classes/META-INF/versions/")
                    && !physicalPath.startsWith("WEB-INF/classes/META-INF/versions/");
        }

        private String logicalPath(String physicalPath, String fallback) {
            VersionedPath selected = selectedByPhysical.get(physicalPath);
            return selected == null ? fallback : selected.logicalPath();
        }

        private static boolean isBudgetFailure(Throwable failure) {
            String message = failure == null || failure.getMessage() == null
                    ? "" : failure.getMessage();
            return message.contains("上限") || message.contains("limit")
                    || message.contains("exceed") || message.startsWith("INPUT_");
        }
    }

    private record VersionedPath(String physicalPath, String logicalPath, int version) {
        private static VersionedPath parse(String physicalPath) {
            if (physicalPath == null) {
                return null;
            }
            String prefix;
            if (physicalPath.startsWith("BOOT-INF/classes/")) {
                prefix = "BOOT-INF/classes/";
            } else if (physicalPath.startsWith("WEB-INF/classes/")) {
                prefix = "WEB-INF/classes/";
            } else {
                return null;
            }
            String relative = physicalPath.substring(prefix.length());
            String marker = "META-INF/versions/";
            if (!relative.startsWith(marker)) {
                return null;
            }
            int versionStart = marker.length();
            int slash = relative.indexOf('/', versionStart);
            if (slash <= versionStart || slash == relative.length() - 1) {
                return null;
            }
            int version;
            try {
                version = Integer.parseInt(relative.substring(versionStart, slash));
            } catch (NumberFormatException invalid) {
                return null;
            }
            if (version < 9) {
                return null;
            }
            String logical = relative.substring(slash + 1);
            return new VersionedPath(physicalPath, logical, version);
        }
    }

    private static long copyBounded(java.io.InputStream input, Path output,
                                    InputBudget.Tracker budget) throws IOException {
        long total = 0L;
        long limit = Math.min(budget.budget().maxEntryBytes(),
                budget.remainingReadBytes());
        byte[] buffer = new byte[8192];
        int emptyReads = 0;
        try (var out = Files.newOutputStream(output, StandardOpenOption.CREATE_NEW,
                StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS)) {
            for (int read; ; ) {
                budget.checkTime();
                read = budget.readBounded(input, buffer, 0, buffer.length, limit - total,
                        "nested entry exceeds limit: " + limit);
                if (read == -1) {
                    break;
                }
                if (read == 0) {
                    // InputStream permits a zero-byte result for a non-empty request. A
                    // custom nested stream must not turn a bounded extraction into an
                    // infinite loop; make one-byte progress and retain the same limit check.
                    if (++emptyReads > 1024) {
                        throw new IOException("INPUT_STREAM_NO_PROGRESS");
                    }
                    int one = budget.readByteBounded(input, limit - total,
                            "nested entry exceeds limit: " + limit);
                    if (one == -1) {
                        break;
                    }
                    buffer[0] = (byte) one;
                    read = 1;
                } else {
                    emptyReads = 0;
                }
                if (read > limit - total) {
                    throw new IOException("nested entry exceeds limit: " + limit);
                }
                out.write(buffer, 0, read);
                total += read;
            }
        }
        return total;
    }

    private static boolean safeOutputParent(Path base, Path parent) {
        if (base == null || parent == null || !parent.startsWith(base)
                || ArchiveLimits.isLinkOrReparsePoint(base)) {
            return false;
        }
        Path current = base;
        Path relative = base.relativize(parent);
        for (Path component : relative) {
            current = current.resolve(component);
            if (!Files.isDirectory(current, LinkOption.NOFOLLOW_LINKS)
                    || ArchiveLimits.isLinkOrReparsePoint(current)) {
                return false;
            }
        }
        return true;
    }

    /** Snapshot of the complete extraction-parent chain, including the owned base directory. */
    record OutputParentSnapshot(Path base, List<OutputParentComponent> components) {
        OutputParentSnapshot {
            components = List.copyOf(components);
        }
    }

    private record OutputParentComponent(Path path, BasicFileAttributes attributes) {
    }

    private static OutputParentSnapshot snapshotOutputParent(Path base, Path parent)
            throws IOException {
        if (base == null || parent == null) {
            throw new IOException("unsafe nested output parent: " + parent);
        }
        Path normalizedBase = base.toAbsolutePath().normalize();
        Path normalizedParent = parent.toAbsolutePath().normalize();
        if (!normalizedParent.startsWith(normalizedBase)
                || !safeOutputParent(normalizedBase, normalizedParent)) {
            throw new IOException("unsafe nested output parent: " + normalizedParent);
        }
        List<OutputParentComponent> components = new ArrayList<>();
        Path current = normalizedBase;
        components.add(new OutputParentComponent(current, readOutputParentIdentity(current)));
        for (Path component : normalizedBase.relativize(normalizedParent)) {
            current = current.resolve(component);
            components.add(new OutputParentComponent(current, readOutputParentIdentity(current)));
        }
        return new OutputParentSnapshot(normalizedBase, components);
    }

    private static void verifyOutputParent(OutputParentSnapshot snapshot) throws IOException {
        if (snapshot == null || snapshot.components().isEmpty()) {
            throw new IOException("output parent changed during extraction");
        }
        try {
            for (OutputParentComponent expected : snapshot.components()) {
                BasicFileAttributes current = readOutputParentIdentity(expected.path());
                if (!sameOutputParentIdentity(expected.attributes(), current)) {
                    throw new IOException("output parent changed during extraction: "
                            + expected.path());
                }
            }
            Path parent = snapshot.components().get(snapshot.components().size() - 1).path();
            if (!safeOutputParent(snapshot.base(), parent)) {
                throw new IOException("output parent changed during extraction: " + parent);
            }
        } catch (IOException failure) {
            if (failure.getMessage() != null
                    && failure.getMessage().startsWith("output parent changed during extraction")) {
                throw failure;
            }
            throw new IOException("output parent changed during extraction", failure);
        }
    }

    private static BasicFileAttributes readOutputParentIdentity(Path path) throws IOException {
        BasicFileAttributes attributes = Files.readAttributes(path, BasicFileAttributes.class,
                LinkOption.NOFOLLOW_LINKS);
        if (!attributes.isDirectory() || ArchiveLimits.isLinkOrReparsePoint(path)) {
            throw new IOException("unsafe nested output parent: " + path);
        }
        return attributes;
    }

    private static boolean sameOutputParentIdentity(BasicFileAttributes expected,
                                                     BasicFileAttributes current) {
        return expected.isDirectory() == current.isDirectory()
                && expected.creationTime().equals(current.creationTime())
                && sameFileKey(expected, current);
    }

    /**
     * Create an extraction parent one component at a time without ever following a
     * symlink/reparse point.  {@link Files#createDirectories(Path)} is convenient but
     * permits a concurrent replacement between the existence check and the mkdir call;
     * the verifier must fail closed at this input boundary instead of writing outside its
     * owned temporary tree.
     */
    private static void createOutputParent(Path base, Path parent) throws IOException {
        if (base == null || parent == null || !parent.startsWith(base)
                || ArchiveLimits.isLinkOrReparsePoint(base)) {
            throw new IOException("unsafe nested output parent: " + parent);
        }
        Path current = base;
        if (!Files.isDirectory(current, LinkOption.NOFOLLOW_LINKS)
                || ArchiveLimits.isLinkOrReparsePoint(current)) {
            throw new IOException("unsafe nested output parent: " + current);
        }
        for (Path component : base.relativize(parent)) {
            current = current.resolve(component);
            if (Files.exists(current, LinkOption.NOFOLLOW_LINKS)) {
                if (!Files.isDirectory(current, LinkOption.NOFOLLOW_LINKS)
                        || ArchiveLimits.isLinkOrReparsePoint(current)) {
                    throw new IOException("unsafe nested output parent: " + current);
                }
            } else {
                try {
                    Files.createDirectory(current);
                } catch (java.nio.file.FileAlreadyExistsException raced) {
                    // A concurrent creator is acceptable only when it created an ordinary
                    // directory; links/reparse points and non-directories remain fatal.
                    if (!Files.isDirectory(current, LinkOption.NOFOLLOW_LINKS)
                            || ArchiveLimits.isLinkOrReparsePoint(current)) {
                        throw new IOException("unsafe nested output parent: " + current,
                                raced);
                    }
                }
            }
            if (!safeOutputParent(base, current)) {
                throw new IOException("unsafe nested output parent changed: " + current);
            }
        }
    }

    /** Package-local hostile contract seam; production extraction always calls the private guard. */
    static void createOutputParentForContract(Path base, Path parent) throws IOException {
        createOutputParent(base, parent);
    }

    /** Package-local hostile contract seam; production extraction always verifies snapshots. */
    static OutputParentSnapshot snapshotOutputParentForContract(Path base, Path parent)
            throws IOException {
        return snapshotOutputParent(base, parent);
    }

    /** Package-local hostile contract seam; production extraction always verifies snapshots. */
    static void verifyOutputParentForContract(OutputParentSnapshot snapshot) throws IOException {
        verifyOutputParent(snapshot);
    }

    private static void deleteAll(List<Path> paths) {
        for (Path path : paths) {
            deleteQuietly(path);
        }
    }

    private static void deleteQuietly(Path path) {
        for (int attempt = 0; attempt < 4; attempt++) {
            if (path == null || !Files.exists(path, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
                return;
            }
            if (Files.isDirectory(path, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
                try (var walk = Files.walk(path)) {
                    walk.sorted(Comparator.reverseOrder())
                            .forEach(NestedClasspath::deleteFileQuietly);
                } catch (IOException ignored) {
                }
            } else {
                deleteFileQuietly(path);
            }
            if (!Files.exists(path, java.nio.file.LinkOption.NOFOLLOW_LINKS)
                    || !isWindows() || attempt == 3) {
                return;
            }
            try {
                Thread.sleep(25L);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                return;
            }
        }
    }

    private static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase(java.util.Locale.ROOT)
                .contains("win");
    }

    private static int runtimeFeature() {
        try {
            return Runtime.version().feature();
        } catch (RuntimeException unsupported) {
            return 8;
        }
    }

    private static void deleteFileQuietly(Path path) {
        try {
            Files.deleteIfExists(path);
        } catch (IOException ignored) {
        }
    }
}
