package io.just.sast.frontend.asm;

import io.just.sast.util.IoUtil;
import io.just.sast.util.JustLogger;
import io.just.sast.util.ArchiveLimits;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PushbackInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;
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
    private static final int MAX_NESTING = ArchiveLimits.MAX_NESTING;
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
            if (ArchiveLimits.isLinkOrReparsePoint(target)) {
                throw new IOException("不读取符号链接或 reparse point: " + target);
            }
            String name = target.getFileName().toString();
            if (name.endsWith(".jar") || name.endsWith(".zip") || name.endsWith(".war")) {
                readJarFile(target, name, 0, state);
            } else if (name.endsWith(".class")) {
                if (Files.size(target) > ArchiveLimits.MAX_ENTRY_UNCOMPRESSED_BYTES) {
                    state.markBudget("CLASS_ENTRY_CAP");
                } else {
                    try (InputStream input = Files.newInputStream(target)) {
                        state.emit(new ClassBytes(classNameFromPath(name),
                                state.readBytes(input), name));
                    }
                }
            } else {
                throw new IOException("不支持的输入: " + target + "（仅支持 .jar/.zip/.class/目录）");
            }
        }
        return new StreamResult(state.emitted, List.copyOf(state.reasons));
    }

    private void readDirectory(Path dir, String origin, ReaderState state) throws IOException {
        try (Stream<Path> stream = Files.walk(dir)) {
            var classes = stream.filter(Files::isRegularFile)
                    .filter(p -> !ArchiveLimits.isLinkOrReparsePoint(p))
                    .filter(p -> p.getFileName().toString().endsWith(".class")).iterator();
            List<Path> ordered = new ArrayList<>();
            while (classes.hasNext()) {
                ordered.add(classes.next());
            }
            ordered.sort(Comparator.comparing(path -> dir.relativize(path).toString()
                    .replace('\\', '/')));
            for (Path p : ordered) {
                if (state.atCapacity()) {
                    state.markCap("目录 " + dir);
                    return;
                }
                try {
                    String rel = dir.relativize(p).toString().replace('\\', '/');
                    if (ArchiveLimits.isLinkOrReparsePoint(p)) {
                        state.reasons.add("LINK_OR_REPARSE_SKIPPED");
                        continue;
                    }
                    if (!ArchiveLimits.safeEntryName(rel)) {
                        state.reasons.add("UNSAFE_ENTRY_PATH");
                        continue;
                    }
                    if (Files.size(p) > ArchiveLimits.MAX_ENTRY_UNCOMPRESSED_BYTES) {
                        state.markBudget("CLASS_ENTRY_CAP");
                        continue;
                    }
                    try (InputStream input = Files.newInputStream(p)) {
                        state.emit(new ClassBytes(classNameFromPath(rel), state.readBytes(input), origin));
                    }
                } catch (IOException e) {
                    JustLogger.warn("读取失败 {}: {}", p, e.getMessage());
                    state.reasons.add("READ_ERROR");
                }
            }
        }
    }

    private void readJarFile(Path jar, String origin, int depth, ReaderState state) throws IOException {
        try {
            ArchiveLimits.checkContainerSize(jar);
        } catch (IOException e) {
            state.markBudget("ARCHIVE_COMPRESSED_BYTES_CAP");
            return;
        }
        try (ZipFile zip = new ZipFile(jar.toFile())) {
            List<ZipEntry> entries = new ArrayList<>();
            Enumeration<? extends ZipEntry> enumeration = zip.entries();
            while (enumeration.hasMoreElements()) {
                entries.add(enumeration.nextElement());
            }
            entries.sort(Comparator.comparing(ZipEntry::getName));
            for (ZipEntry entry : entries) {
                if (!state.observeEntry(entry)) {
                    if (state.budgetExceeded()) {
                        return;
                    }
                    continue;
                }
                if (state.atCapacity()) {
                    state.markCap("解析 " + jar);
                    return;
                }
                String path = entry.getName();
                if (!ArchiveLimits.safeEntryName(path)) {
                    state.reasons.add("UNSAFE_ENTRY_PATH");
                    continue;
                }
                if (path.startsWith(SKIPPED_MULTIRELEASE)) {
                    state.reasons.add("MULTI_RELEASE_SKIPPED");
                    continue; // multi-release 变体暂不解析
                }
                if (entry.isDirectory()) {
                    continue;
                }
                if (path.endsWith(".class")) {
                    try (var input = zip.getInputStream(entry)) {
                        state.emit(new ClassBytes(stripClassPrefix(path), state.readBytes(input),
                                origin + "!" + path));
                    }
                } else if (isNestedLib(path)) {
                    if (depth >= MAX_NESTING) {
                        state.reasons.add("NESTING_CAP:" + MAX_NESTING);
                        continue;
                    }
                    try (var input = zip.getInputStream(entry)) {
                        // Parse the nested stream in place. Copying every nested JAR first
                        // doubled the global uncompressed accounting and created a large
                        // transient allocation on ordinary fat artifacts.
                        readNestedJar(state.containerStream(input), origin + "!" + path,
                                depth + 1, state);
                    }
                }
            }
        } catch (ZipException corrupt) {
            // A malformed central directory or entry must be a stable completeness reason,
            // not an untyped frontend exception. Already-emitted classes remain usable, but
            // callers must see the scan as PARTIAL and can decide whether to reject it.
            state.markArchiveCorrupt();
            JustLogger.warn("损坏 ZIP/JAR，跳过剩余内容 {}: {}", jar, corrupt.getMessage());
        }
    }

    /** 嵌套 jar 内继续递归；直接消费当前 zip entry，不复制整个嵌套 jar。 */
    private void readNestedJar(InputStream input, String origin, int depth,
                               ReaderState state) throws IOException {
        // Closing a child ZipInputStream must not close its parent's current entry. The
        // wrapper is also what lets the top-level ZipFile close the entry deterministically.
        PushbackInputStream checkedInput = new PushbackInputStream(
                new NonClosingInputStream(input), 4);
        byte[] signature = new byte[4];
        int read = 0;
        while (read < signature.length) {
            int count = checkedInput.read(signature, read, signature.length - read);
            if (count < 0) {
                break;
            }
            if (count == 0) {
                continue;
            }
            read += count;
        }
        if (read < signature.length || !isZipSignature(signature)) {
            state.markArchiveCorrupt();
            JustLogger.warn("嵌套 ZIP/JAR 缺少有效 local header，跳过剩余内容 {}", origin);
            return;
        }
        checkedInput.unread(signature);
        try (ZipInputStream zip = new ZipInputStream(checkedInput)) {
            ZipEntry entry;
            while ((entry = zip.getNextEntry()) != null) {
                if (!state.observeEntry(entry)) {
                    if (state.budgetExceeded()) {
                        return;
                    }
                    continue;
                }
                if (state.atCapacity()) {
                    state.markCap("解析嵌套 jar " + origin);
                    return;
                }
                String path = entry.getName();
                if (!ArchiveLimits.safeEntryName(path)) {
                    state.reasons.add("UNSAFE_ENTRY_PATH");
                    continue;
                }
                if (path.startsWith(SKIPPED_MULTIRELEASE)) {
                    state.reasons.add("MULTI_RELEASE_SKIPPED");
                    continue;
                }
                if (entry.isDirectory()) {
                    continue;
                }
                if (path.endsWith(".class")) {
                    state.emit(new ClassBytes(stripClassPrefix(path), state.readBytes(zip),
                            origin + "!" + path));
                } else if (path.endsWith(".jar")) {
                    if (depth >= MAX_NESTING) {
                        state.reasons.add("NESTING_CAP:" + MAX_NESTING);
                        continue;
                    }
                    readNestedJar(zip, origin + "!" + path, depth + 1, state);
                }
            }
        } catch (ZipException corrupt) {
            state.markArchiveCorrupt();
            JustLogger.warn("损坏嵌套 ZIP/JAR，跳过剩余内容 {}: {}", origin, corrupt.getMessage());
        }
    }

    private static final class ReaderState {
        private final ClassConsumer consumer;
        private final Set<String> reasons = new LinkedHashSet<>();
        private final Set<String> emittedClassNames = new LinkedHashSet<>();
        private final ArchiveLimits.Tracker archiveBudget = new ArchiveLimits.Tracker();
        private int emitted;
        private boolean budgetExceeded;

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

        private void markBudget(String reason) {
            budgetExceeded = true;
            reasons.add(reason);
        }

        private void markArchiveCorrupt() {
            reasons.add("ARCHIVE_CORRUPT");
        }

        private boolean budgetExceeded() {
            return budgetExceeded;
        }

        private boolean observeEntry(ZipEntry entry) {
            if (budgetExceeded) {
                return false;
            }
            try {
                archiveBudget.observe(entry);
            } catch (IOException e) {
                markBudget(limitReason(e));
                return false;
            }
            return true;
        }

        private byte[] readBytes(InputStream input) throws IOException {
            long remaining = archiveBudget.remainingReadBytes();
            if (remaining <= 0) {
                markBudget("ARCHIVE_UNCOMPRESSED_BYTES_CAP");
                throw new IOException("archive uncompressed byte budget exceeded");
            }
            long limit = Math.min(ArchiveLimits.MAX_ENTRY_UNCOMPRESSED_BYTES, remaining);
            byte[] bytes;
            try {
                bytes = IoUtil.readAll(input, limit);
            } catch (IOException e) {
                markBudget("ARCHIVE_ENTRY_READ_CAP");
                throw e;
            }
            try {
                archiveBudget.recordRead(bytes.length);
            } catch (IOException e) {
                markBudget("ARCHIVE_UNCOMPRESSED_BYTES_CAP");
                throw e;
            }
            return bytes;
        }

        private InputStream containerStream(InputStream input) {
            return new FilterInputStream(input) {
                @Override
                public int read() throws IOException {
                    int value = super.read();
                    if (value >= 0) {
                        archiveBudget.recordContainerRead(1);
                    }
                    return value;
                }

                @Override
                public int read(byte[] buffer, int offset, int length) throws IOException {
                    int count = super.read(buffer, offset, length);
                    if (count > 0) {
                        archiveBudget.recordContainerRead(count);
                    }
                    return count;
                }

                @Override
                public long skip(long count) throws IOException {
                    long skipped = super.skip(count);
                    if (skipped > 0) {
                        archiveBudget.recordContainerRead(skipped);
                    }
                    return skipped;
                }
            };
        }

        private static String limitReason(IOException error) {
            String message = error.getMessage() == null ? "" : error.getMessage();
            if (message.contains("entry count")) {
                return "ARCHIVE_ENTRY_CAP:" + ArchiveLimits.MAX_ENTRIES;
            }
            if (message.contains("compressed bytes")) {
                return "ARCHIVE_COMPRESSED_BYTES_CAP";
            }
            if (message.contains("compression ratio")) {
                return "ARCHIVE_COMPRESSION_RATIO_CAP";
            }
            if (message.contains("declared bytes")) {
                return "ARCHIVE_UNCOMPRESSED_BYTES_CAP";
            }
            return "ARCHIVE_ENTRY_BYTES_CAP";
        }

        private void emit(ClassBytes bytes) throws IOException {
            if (atCapacity()) {
                markCap(bytes.origin());
                return;
            }
            if (!emittedClassNames.add(bytes.className())) {
                reasons.add("DUPLICATE_CLASS:" + bytes.className());
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

    private static boolean isZipSignature(byte[] signature) {
        return signature != null && signature.length >= 4
                && signature[0] == 'P' && signature[1] == 'K'
                && ((signature[2] == 3 && signature[3] == 4)
                    || (signature[2] == 5 && signature[3] == 6)
                    || (signature[2] == 7 && signature[3] == 8));
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
