package io.just.sast.verify;

import io.just.sast.util.ArchiveLimits;

import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
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
        List<Path> entries = new ArrayList<>();
        List<Path> artifacts = new ArrayList<>();
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
                entries.add(input);
                entries.addAll(expand(input, artifacts));
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

    private static List<Path> expand(Path input, List<Path> artifacts) throws IOException {
        if (!Files.isRegularFile(input)) {
            return List.of();
        }
        if (ArchiveLimits.isLinkOrReparsePoint(input)) {
            throw new IOException("unsafe classpath input link or reparse point: " + input);
        }
        ArchiveLimits.checkContainerSize(input);
        boolean hasClasses = false;
        boolean hasLib = false;
        List<ZipEntry> orderedEntries = new ArrayList<>();
        ArchiveLimits.Tracker budget = new ArchiveLimits.Tracker();
        Set<String> seenNames = new LinkedHashSet<>();
        try (ZipFile zip = new ZipFile(input.toFile())) {
            Enumeration<? extends ZipEntry> elements = zip.entries();
            while (elements.hasMoreElements()) {
                ZipEntry entry = elements.nextElement();
                String name = entry.getName();
                if (!ArchiveLimits.safeEntryName(name)) {
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
                    String relative = nestedRelative(name);
                    if (!ArchiveLimits.safeEntryName(relative)) {
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
                    Files.createDirectories(output.getParent());
                    try (var inputStream = zip.getInputStream(entry)) {
                        copyBounded(inputStream, output, budget);
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
                    result.addAll(stream.filter(Files::isRegularFile)
                            .filter(path -> path.getFileName().toString().endsWith(".jar"))
                            .sorted(Comparator.comparing(Path::toString))
                            .toList());
                }
            }
            return List.copyOf(result);
        } catch (java.util.zip.ZipException notAnArchive) {
            return List.of();
        }
    }

    private static boolean isNestedClass(String name) {
        return name.startsWith("BOOT-INF/classes/") || name.startsWith("WEB-INF/classes/");
    }

    private static boolean isNestedLibrary(String name) {
        return (name.startsWith("BOOT-INF/lib/") || name.startsWith("WEB-INF/lib/"))
                && name.endsWith(".jar") && !name.endsWith("/");
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

    private static long copyBounded(java.io.InputStream input, Path output,
                                    ArchiveLimits.Tracker budget) throws IOException {
        long total = 0L;
        long limit = Math.min(ArchiveLimits.MAX_ENTRY_UNCOMPRESSED_BYTES,
                budget.remainingReadBytes());
        byte[] buffer = new byte[8192];
        try (var out = Files.newOutputStream(output)) {
            for (int read; ; ) {
                read = input.read(buffer);
                if (read == -1) {
                    break;
                }
                if (read == 0) {
                    // InputStream permits a zero-byte result for a non-empty request. A
                    // custom nested stream must not turn a bounded extraction into an
                    // infinite loop; make one-byte progress and retain the same limit check.
                    int one = input.read();
                    if (one == -1) {
                        break;
                    }
                    buffer[0] = (byte) one;
                    read = 1;
                }
                if (read > limit - total) {
                    throw new IOException("nested entry exceeds limit: " + limit);
                }
                out.write(buffer, 0, read);
                total += read;
            }
        }
        budget.recordRead(total);
        return total;
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

    private static void deleteFileQuietly(Path path) {
        try {
            Files.deleteIfExists(path);
        } catch (IOException ignored) {
        }
    }
}
