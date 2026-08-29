package io.just.sast.frontend.asm;

import io.just.sast.util.IoUtil;
import io.just.sast.util.JustLogger;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;

/**
 * 读取 JAR / class 目录 / 单个 class 文件。
 * 支持 Spring Boot fat jar：BOOT-INF/classes 下的类 + BOOT-INF/lib 下的嵌套 jar 递归解析。
 */
public final class JarReader {

    @FunctionalInterface
    public interface ClassConsumer {
        void accept(ClassBytes bytes) throws IOException;
    }

    /** 类文件读取结果；类列表与“是否因边界跳过内容”分开，避免把上限误当成解析成功。 */
    public record ReadResult(List<ClassBytes> classes, List<String> completenessReasons) {
        public ReadResult {
            classes = classes == null ? List.of() : List.copyOf(classes);
            completenessReasons = completenessReasons == null ? List.of() : List.copyOf(completenessReasons);
        }
    }

    /** 流式读取结果：只保留计数和完整性原因，不持有任何 class byte[]。 */
    public record StreamResult(int classesEmitted, List<String> completenessReasons) {
        public StreamResult {
            completenessReasons = completenessReasons == null ? List.of()
                    : List.copyOf(completenessReasons);
        }
    }

    /** 嵌套 jar 递归深度上限，防 zip 炸弹。 */
    private static final int MAX_NESTING = 4;
    /** 单次扫描的 class 条目上限。 */
    private static final int MAX_CLASSES = 100_000;

    private static final String[] CLASS_PREFIXES = {"BOOT-INF/classes/", "WEB-INF/classes/"};
    private static final String[] LIB_PREFIXES = {"BOOT-INF/lib/", "WEB-INF/lib/"};
    private static final String SKIPPED_MULTIRELEASE = "META-INF/versions/";

    public List<ClassBytes> read(Path target) throws IOException {
        return readDetailed(target).classes();
    }

    public ReadResult readDetailed(Path target) throws IOException {
        List<ClassBytes> out = new ArrayList<>();
        StreamResult result = streamDetailed(target, out::add);
        return new ReadResult(out, result.completenessReasons());
    }

    /**
     * 按输入顺序逐个发出 class。回调返回后，读取器不再持有该条目的 byte[]；这让前端
     * 可以用固定大小批次解析大型 fat jar，而不是把整个工件的原始字节挂到 CPG 构建前。
     */
    public StreamResult streamDetailed(Path target, ClassConsumer consumer) throws IOException {
        if (target == null || consumer == null) {
            throw new IllegalArgumentException("target and consumer are required");
        }
        if (!Files.exists(target)) {
            throw new IOException("目标不存在: " + target);
        }
        ReaderState state = new ReaderState(consumer);
        if (Files.isDirectory(target)) {
            readDirectory(target, target.getFileName().toString(), state);
        } else {
            String name = target.getFileName().toString();
            if (name.endsWith(".jar") || name.endsWith(".zip") || name.endsWith(".war")) {
                readJarFile(target, name, 0, state);
            } else if (name.endsWith(".class")) {
                state.emit(new ClassBytes(classNameFromPath(name), Files.readAllBytes(target), name));
            } else {
                throw new IOException("不支持的输入: " + target + "（仅支持 .jar/.zip/.class/目录）");
            }
        }
        return new StreamResult(state.emitted, List.copyOf(state.reasons));
    }

    private void readDirectory(Path dir, String origin, ReaderState state) throws IOException {
        try (Stream<Path> stream = Files.walk(dir)) {
            var classes = stream.filter(Files::isRegularFile)
                    .filter(p -> p.getFileName().toString().endsWith(".class")).iterator();
            while (classes.hasNext()) {
                if (state.atCapacity()) {
                    state.markCap("目录 " + dir);
                    return;
                }
                Path p = classes.next();
                try {
                    String rel = dir.relativize(p).toString().replace('\\', '/');
                    state.emit(new ClassBytes(classNameFromPath(rel), Files.readAllBytes(p), origin));
                } catch (IOException e) {
                    JustLogger.warn("读取失败 {}: {}", p, e.getMessage());
                    state.reasons.add("READ_ERROR");
                }
            }
        }
    }

    private void readJarFile(Path jar, String origin, int depth, ReaderState state) throws IOException {
        try (ZipFile zip = new ZipFile(jar.toFile())) {
            var entries = zip.entries();
            while (entries.hasMoreElements()) {
                if (state.atCapacity()) {
                    state.markCap("解析 " + jar);
                    return;
                }
                ZipEntry entry = entries.nextElement();
                String path = entry.getName();
                if (path.startsWith(SKIPPED_MULTIRELEASE)) {
                    state.reasons.add("MULTI_RELEASE_SKIPPED");
                    continue; // multi-release 变体暂不解析
                }
                if (entry.isDirectory()) {
                    continue;
                }
                if (path.endsWith(".class")) {
                    byte[] bytes;
                    try (var input = zip.getInputStream(entry)) {
                        bytes = IoUtil.readAll(input);
                    }
                    state.emit(new ClassBytes(stripClassPrefix(path), bytes, origin + "!" + path));
                } else if (isNestedLib(path)) {
                    if (depth >= MAX_NESTING) {
                        state.reasons.add("NESTING_CAP:" + MAX_NESTING);
                        continue;
                    }
                    try (var input = zip.getInputStream(entry)) {
                        readNestedJar(input, origin + "!" + path, depth + 1, state);
                    }
                }
            }
        }
    }

    /** 嵌套 jar 内继续递归；直接消费当前 zip entry，不再复制整个嵌套 jar。 */
    private void readNestedJar(InputStream input, String origin, int depth,
                               ReaderState state) throws IOException {
        // Closing a child ZipInputStream must not close its parent's current entry. The
        // wrapper is also what lets the top-level ZipFile close the entry deterministically.
        try (ZipInputStream zip = new ZipInputStream(new NonClosingInputStream(input))) {
            ZipEntry entry;
            while ((entry = zip.getNextEntry()) != null) {
                if (state.atCapacity()) {
                    state.markCap("解析嵌套 jar " + origin);
                    return;
                }
                String path = entry.getName();
                if (path.startsWith(SKIPPED_MULTIRELEASE)) {
                    state.reasons.add("MULTI_RELEASE_SKIPPED");
                    continue;
                }
                if (entry.isDirectory()) {
                    continue;
                }
                if (path.endsWith(".class")) {
                    state.emit(new ClassBytes(stripClassPrefix(path), IoUtil.readAll(zip), origin + "!" + path));
                } else if (path.endsWith(".jar")) {
                    if (depth >= MAX_NESTING) {
                        state.reasons.add("NESTING_CAP:" + MAX_NESTING);
                        continue;
                    }
                    readNestedJar(zip, origin + "!" + path, depth + 1, state);
                }
            }
        }
    }

    private static final class ReaderState {
        private final ClassConsumer consumer;
        private final Set<String> reasons = new LinkedHashSet<>();
        private int emitted;

        private ReaderState(ClassConsumer consumer) {
            this.consumer = consumer;
        }

        private boolean atCapacity() {
            return emitted >= MAX_CLASSES;
        }

        private void markCap(String where) {
            JustLogger.warn("class 条目超过上限 {}，停止{}", MAX_CLASSES, where);
            reasons.add("CLASS_CAP:" + MAX_CLASSES);
        }

        private void emit(ClassBytes bytes) throws IOException {
            if (atCapacity()) {
                markCap(bytes.origin());
                return;
            }
            consumer.accept(bytes);
            emitted++;
        }
    }

    /** 让递归 ZipInputStream 结束时不关闭父容器。 */
    private static final class NonClosingInputStream extends FilterInputStream {
        private NonClosingInputStream(InputStream input) {
            super(input);
        }

        @Override
        public void close() {
            // Parent ZipFile/ZipInputStream owns the underlying stream.
        }
    }

    private static boolean isNestedLib(String path) {
        for (String prefix : LIB_PREFIXES) {
            if (path.startsWith(prefix) && path.endsWith(".jar")) {
                return true;
            }
        }
        return false;
    }

    private static String stripClassPrefix(String path) {
        for (String prefix : CLASS_PREFIXES) {
            if (path.startsWith(prefix)) {
                path = path.substring(prefix.length());
                break;
            }
        }
        return classNameFromPath(path);
    }

    private static String classNameFromPath(String path) {
        return path.endsWith(".class") ? path.substring(0, path.length() - 6) : path;
    }
}
