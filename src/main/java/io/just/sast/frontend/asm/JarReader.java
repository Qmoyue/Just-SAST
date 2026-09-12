package io.just.sast.frontend.asm;

import io.just.sast.util.IoUtil;
import io.just.sast.util.JustLogger;
import io.just.sast.util.ArchiveLimits;
import io.just.sast.run.InputBudget;

import java.io.FilterInputStream;
import java.io.EOFException;
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
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;
import java.util.jar.Manifest;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;
import java.util.zip.CRC32;
import java.util.zip.CheckedInputStream;

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

    private static final String[] CLASS_PREFIXES = {"BOOT-INF/classes/", "WEB-INF/classes/"};
    private static final String[] LIB_PREFIXES = {"BOOT-INF/lib/", "WEB-INF/lib/"};
    private static final String SKIPPED_MULTIRELEASE = "META-INF/versions/";

    public List<ClassBytes> read(Path target) throws IOException {
        return readDetailed(target).classes();
    }

    public ReadResult readDetailed(Path target) throws IOException {
        return readDetailed(target, runtimeFeature());
    }

    /** Read using the class-file view selected by a target JDK feature version. */
    public ReadResult readDetailed(Path target, int targetFeature) throws IOException {
        return readDetailed(target, targetFeature, InputBudget.defaults());
    }

    /** Read with one explicit versioned input policy shared across nested archives. */
    public ReadResult readDetailed(Path target, int targetFeature, InputBudget budget)
            throws IOException {
        InputBudget policy = budget == null ? InputBudget.defaults() : budget;
        List<ClassBytes> out = new ArrayList<>();
        StreamResult result = streamDetailed(target, out::add, targetFeature, policy,
                policy.tracker());
        return new ReadResult(out, result.completenessReasons());
    }

    /** Read while reusing a caller-owned tracker across several archive inputs. */
    public ReadResult readDetailed(Path target, int targetFeature, InputBudget budget,
                                   InputBudget.Tracker tracker) throws IOException {
        InputBudget policy = budget == null ? InputBudget.defaults() : budget;
        List<ClassBytes> out = new ArrayList<>();
        StreamResult result = streamDetailed(target, out::add, targetFeature, policy, tracker);
        return new ReadResult(out, result.completenessReasons());
    }

    /**
     * 按输入顺序逐个发出 class。回调返回后，读取器不再持有该条目的 byte[]；这让前端
     * 可以用固定大小批次解析大型 fat jar，而不是把整个工件的原始字节挂到 CPG 构建前。
     */
    public StreamResult streamDetailed(Path target, ClassConsumer consumer) throws IOException {
        return streamDetailed(target, consumer, runtimeFeature());
    }

    /**
     * Stream a JAR while applying the standard multi-release selection rule.  The selected
     * feature is a policy input, not the scanner runtime version; callers scanning against an
     * external JDK must pass that JDK's feature.  Directories and single class files are
     * unaffected.
     */
    public StreamResult streamDetailed(Path target, ClassConsumer consumer,
                                       int targetFeature) throws IOException {
        return streamDetailed(target, consumer, targetFeature, InputBudget.defaults());
    }

    /** Stream with one explicit versioned input policy shared across nested archives. */
    public StreamResult streamDetailed(Path target, ClassConsumer consumer,
                                       int targetFeature, InputBudget budget) throws IOException {
        InputBudget policy = budget == null ? InputBudget.defaults() : budget;
        return streamDetailed(target, consumer, targetFeature, policy, policy.tracker());
    }

    /**
     * Stream with an explicit policy and caller-owned tracker.  The tracker is intended for
     * one complete frontend input set (target plus dependencies), so separate archives cannot
     * reset the aggregate entry/byte/time accounting by invoking this reader repeatedly.
     */
    public StreamResult streamDetailed(Path target, ClassConsumer consumer,
                                       int targetFeature, InputBudget budget,
                                       InputBudget.Tracker tracker) throws IOException {
        if (target == null || consumer == null) {
            throw new IllegalArgumentException("target and consumer are required");
        }
        if (!Files.exists(target)) {
            throw new IOException("目标不存在: " + target);
        }
        ArchiveLimits.checkPathAncestors(target, budget);
        ReaderState state = new ReaderState(consumer, targetFeature, budget, tracker);
        // Reject a reparse point before deciding whether the path is a directory.  The
        // default Files.isDirectory call follows a directory symlink, which would let a
        // link escape the explicitly selected scan root and bypass the archive policy.
        if (ArchiveLimits.isLinkOrReparsePoint(target)) {
            throw new IOException("不读取符号链接或 reparse point: " + target);
        }
        if (Files.isDirectory(target, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
            ArchiveLimits.DirectoryReadSnapshot snapshot = ArchiveLimits.snapshotDirectory(
                    target, state.budget, "CLASS_DIRECTORY");
            IOException failure = null;
            try {
                readDirectory(target, target.getFileName().toString(), state);
            } catch (IOException readFailure) {
                failure = readFailure;
            }
            try {
                ArchiveLimits.verifyDirectoryUnchanged(snapshot, "CLASS_DIRECTORY");
            } catch (IOException changed) {
                if (failure == null) {
                    failure = changed;
                } else {
                    failure.addSuppressed(changed);
                }
            }
            if (failure != null) {
                throw failure;
            }
        } else {
            String name = target.getFileName().toString();
            if (name.endsWith(".jar") || name.endsWith(".zip") || name.endsWith(".war")) {
                readJarFile(target, name, 0, state);
            } else if (name.endsWith(".class")) {
                java.nio.file.attribute.BasicFileAttributes before = Files.readAttributes(target,
                        java.nio.file.attribute.BasicFileAttributes.class,
                        java.nio.file.LinkOption.NOFOLLOW_LINKS);
                if (!before.isRegularFile()) {
                    throw new IOException("不支持的 class 输入类型: " + target);
                }
                long size = before.size();
                if (!ArchiveLimits.safeEntryName(name, state.budget)) {
                    state.markBudget("UNSAFE_ENTRY_PATH");
                } else if (size > state.budget.maxEntryBytes()) {
                    state.markBudget("CLASS_ENTRY_CAP");
                } else {
                    try {
                        state.archiveBudget.observeFile(name, size);
                    } catch (IOException failure) {
                        state.markBudget(ReaderState.limitReason(failure, state.budget));
                        return new StreamResult(state.emitted, List.copyOf(state.reasons));
                    }
                    try (IoUtil.OpenedInput opened = IoUtil.openRegularFile(target, "CLASS_INPUT")) {
                        state.emit(new ClassBytes(classNameFromPath(name),
                                state.readBytes(opened.stream()), name));
                    }
                    java.nio.file.attribute.BasicFileAttributes after = Files.readAttributes(target,
                            java.nio.file.attribute.BasicFileAttributes.class,
                            java.nio.file.LinkOption.NOFOLLOW_LINKS);
                    if (!sameClassFileIdentity(before, after, target)) {
                        throw new IOException("CLASS_INPUT_CHANGED_DURING_READ");
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
            List<Path> ordered = new ArrayList<>();
            var paths = stream.iterator();
            while (paths.hasNext()) {
                Path candidate = paths.next();
                if (!state.visitDirectoryPath(candidate)) {
                    return;
                }
                if (Files.isRegularFile(candidate, java.nio.file.LinkOption.NOFOLLOW_LINKS)
                        && !ArchiveLimits.isLinkOrReparsePoint(candidate)
                        && candidate.getFileName() != null
                        && candidate.getFileName().toString().endsWith(".class")) {
                    ordered.add(candidate);
                }
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
                    if (!ArchiveLimits.safeEntryName(rel, state.budget)) {
                        state.reasons.add("UNSAFE_ENTRY_PATH");
                        continue;
                    }
                    java.nio.file.attribute.BasicFileAttributes before = Files.readAttributes(p,
                            java.nio.file.attribute.BasicFileAttributes.class,
                            java.nio.file.LinkOption.NOFOLLOW_LINKS);
                    if (!before.isRegularFile() || ArchiveLimits.isLinkOrReparsePoint(p)) {
                        state.reasons.add("LINK_OR_REPARSE_SKIPPED");
                        continue;
                    }
                    if (before.size() > state.budget.maxEntryBytes()) {
                        state.markBudget("CLASS_ENTRY_CAP");
                        continue;
                    }
                    state.archiveBudget.observeFile(rel, before.size());
                    try (IoUtil.OpenedInput opened = IoUtil.openRegularFile(p, "CLASS_DIRECTORY")) {
                        state.emit(new ClassBytes(classNameFromPath(rel),
                                state.readBytes(opened.stream()), origin));
                    }
                    java.nio.file.attribute.BasicFileAttributes after = Files.readAttributes(p,
                            java.nio.file.attribute.BasicFileAttributes.class,
                            java.nio.file.LinkOption.NOFOLLOW_LINKS);
                    if (!sameClassFileIdentity(before, after, p)) {
                        throw new IOException("CLASS_INPUT_CHANGED_DURING_READ");
                    }
                } catch (IOException e) {
                    JustLogger.warn("读取失败 {}: {}", p, e.getMessage());
                    if (ReaderState.isBudgetFailure(e)) {
                        state.markBudget(ReaderState.limitReason(e, state.budget));
                    } else {
                        state.reasons.add("READ_ERROR");
                    }
                }
            }
        }
    }

    private static boolean sameClassFileIdentity(
            java.nio.file.attribute.BasicFileAttributes before,
            java.nio.file.attribute.BasicFileAttributes after,
            Path path) {
        if (before == null || after == null || path == null
                || !after.isRegularFile() || ArchiveLimits.isLinkOrReparsePoint(path)
                || before.size() != after.size()
                || !before.creationTime().equals(after.creationTime())
                || !before.lastModifiedTime().equals(after.lastModifiedTime())) {
            return false;
        }
        if (before.fileKey() != null || after.fileKey() != null) {
            return before.fileKey() != null && after.fileKey() != null
                    && before.fileKey().equals(after.fileKey());
        }
        return before.creationTime().equals(after.creationTime());
    }

    private void readJarFile(Path jar, String origin, int depth, ReaderState state) throws IOException {
        try {
            ArchiveLimits.checkContainerSize(jar, state.budget);
        } catch (IOException e) {
            state.markBudget("ARCHIVE_COMPRESSED_BYTES_CAP");
            return;
        }
        ArchiveLimits.FileReadSnapshot snapshot = ArchiveLimits.snapshotRegularFile(
                jar, state.budget, "ARCHIVE");
        try (ArchiveLimits.ZipFileHandle handle = ArchiveLimits.openZipFile(snapshot, "ARCHIVE")) {
            ZipFile zip = handle.zip();
            List<ZipEntry> entries = new ArrayList<>();
            Set<String> seenEntryNames = new LinkedHashSet<>();
            Enumeration<? extends ZipEntry> enumeration = zip.entries();
            while (enumeration.hasMoreElements()) {
                ZipEntry entry = enumeration.nextElement();
                if (entry == null || !seenEntryNames.add(entry.getName())) {
                    state.markArchiveDuplicate();
                    return;
                }
                entries.add(entry);
            }
            entries.sort(Comparator.comparing(ZipEntry::getName));
            MultiReleaseSelection multiRelease = multiReleaseSelection(zip, entries, state);
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
                if (!ArchiveLimits.safeEntryName(path, state.budget)) {
                    state.reasons.add("UNSAFE_ENTRY_PATH");
                    continue;
                }
                if (multiRelease.skip(path)) {
                    continue;
                }
                if (entry.isDirectory()) {
                    continue;
                }
                try {
                    if (path.endsWith(".class")) {
                        byte[] classBytes;
                        try (var input = zip.getInputStream(entry)) {
                            classBytes = state.readEntryBytes(entry, input);
                        }
                        String classPath = multiRelease.logicalPath(path);
                        state.emit(new ClassBytes(stripClassPrefix(classPath), classBytes,
                                origin + "!" + path));
                    } else if (isNestedLib(path)) {
                        if (depth >= state.budget.maxArchiveNesting()) {
                            state.reasons.add("NESTING_CAP:" + state.budget.maxArchiveNesting());
                            continue;
                        }
                        CRC32 crc = new CRC32();
                        try (var input = new CheckedInputStream(zip.getInputStream(entry), crc)) {
                            // Parse the nested stream in place. Copying every nested JAR first
                            // doubled the global uncompressed accounting and created a large
                            // transient allocation on ordinary fat artifacts.
                            readNestedJar(input, origin + "!" + path, depth + 1, state, true);
                        }
                        state.verifyCrc(entry, crc.getValue());
                    }
                } catch (IOException failure) {
                    if (state.markEntryFailure(failure)) {
                        return;
                    }
                    if (state.markArchiveReadCorruption(failure)) {
                        // ZipFile entries are independently addressable.  A corrupt class or
                        // nested library must make completeness PARTIAL, but it must not hide
                        // later valid application/dependency entries in the same fat artifact.
                        // Continue the deterministic sorted walk and keep the static facts
                        // that can still be read.
                        continue;
                    }
                    throw failure;
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
                               ReaderState state, boolean accountContainer) throws IOException {
        // Closing a child ZipInputStream must not close its parent's current entry. The
        // wrapper is also what lets the top-level ZipFile close the entry deterministically.
        InputStream source = accountContainer ? state.containerStream(input) : input;
        PushbackInputStream checkedInput = new PushbackInputStream(
                new NonClosingInputStream(source), 4);
        byte[] signature = new byte[4];
        int read = 0;
        int emptyReads = 0;
        while (read < signature.length) {
            state.archiveBudget.checkTime();
            int count = checkedInput.read(signature, read, signature.length - read);
            if (count < 0) {
                break;
            }
            if (count == 0) {
                if (++emptyReads > 16) {
                    state.markArchiveCorrupt();
                    JustLogger.warn("嵌套 ZIP/JAR 输入无进展，跳过剩余内容 {}", origin);
                    return;
                }
                continue;
            }
            emptyReads = 0;
            read += count;
        }
        if (read < signature.length || !isZipSignature(signature)) {
            state.markArchiveCorrupt();
            JustLogger.warn("嵌套 ZIP/JAR 缺少有效 local header，跳过剩余内容 {}", origin);
            return;
        }
        checkedInput.unread(signature);
        boolean innerArchiveFullyWalked = false;
        // Keep the pushback buffer open after ZipInputStream.close(): a valid nested ZIP may
        // leave alignment bytes unread, and those bytes still belong to the outer entry whose
        // CRC is checked by the caller.
        try (ZipInputStream zip = new ZipInputStream(new NonClosingInputStream(checkedInput))) {
            List<NestedPayload> payloads = new ArrayList<>();
            ZipEntry entry;
            boolean multiRelease = false;
            Set<String> seenEntryNames = new LinkedHashSet<>();
            while ((entry = zip.getNextEntry()) != null) {
                if (!seenEntryNames.add(entry.getName())) {
                    state.markArchiveDuplicate();
                    return;
                }
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
                if (!ArchiveLimits.safeEntryName(path, state.budget)) {
                    state.reasons.add("UNSAFE_ENTRY_PATH");
                    continue;
                }
                if (entry.isDirectory()) {
                    continue;
                }
                if ("META-INF/MANIFEST.MF".equalsIgnoreCase(path)
                        || path.endsWith(".class") || path.endsWith(".jar")) {
                    byte[] payloadBytes;
                    try {
                        payloadBytes = state.readEntryBytes(entry, zip);
                    } catch (IOException failure) {
                        if (state.markEntryFailure(failure)) {
                            return;
                        }
                        if (state.markArchiveReadCorruption(failure)) {
                            return;
                        }
                        throw failure;
                    }
                    payloads.add(new NestedPayload(path, payloadBytes));
                }
            }
            for (NestedPayload payload : payloads) {
                if ("META-INF/MANIFEST.MF".equalsIgnoreCase(payload.path())) {
                    try {
                        multiRelease = "true".equalsIgnoreCase(new Manifest(
                                new java.io.ByteArrayInputStream(payload.bytes()))
                                .getMainAttributes().getValue("Multi-Release"));
                    } catch (IOException | RuntimeException malformedManifest) {
                        state.reasons.add("MULTI_RELEASE_MANIFEST_INVALID");
                    }
                    break;
                }
            }
            NestedMultiReleaseSelection selection = NestedMultiReleaseSelection.create(
                    payloads, state.targetFeature, multiRelease);
            for (NestedPayload payload : payloads) {
                String path = payload.path();
                if (selection.skip(path)) {
                    continue;
                }
                if (path.endsWith(".class")) {
                    state.emit(new ClassBytes(stripClassPrefix(selection.logicalPath(path)),
                            payload.bytes(), origin + "!" + path));
                } else if (path.endsWith(".jar")) {
                    if (depth >= state.budget.maxArchiveNesting()) {
                        state.reasons.add("NESTING_CAP:" + state.budget.maxArchiveNesting());
                        continue;
                    }
                    readNestedJar(new java.io.ByteArrayInputStream(payload.bytes()),
                            origin + "!" + path, depth + 1, state, false);
                }
            }
            // Spring Boot's nested-jar layout may append alignment bytes after an otherwise
            // valid inner ZIP central directory. ZipInputStream stops at that directory and
            // intentionally leaves the tail unread; consume the tail before checking the
            // outer ZipFile entry CRC. The bytes remain subject to the caller-owned input
            // tracker and parse-time limit, so this does not relax any archive budget.
            innerArchiveFullyWalked = true;
        } catch (ZipException corrupt) {
            state.markArchiveCorrupt();
            JustLogger.warn("损坏嵌套 ZIP/JAR，跳过剩余内容 {}: {}", origin, corrupt.getMessage());
        } catch (IllegalArgumentException malformedEntryName) {
            // ZipInputStream decodes entry names while advancing to the next local header.
            // A malformed UTF-8 name is surfaced by the JDK as an unchecked
            // IllegalArgumentException, not ZipException; keep it inside the bounded parser
            // boundary so hostile bytes become an auditable PARTIAL result rather than escaping
            // into the scanner.
            state.markArchiveCorrupt();
            JustLogger.warn("嵌套 ZIP/JAR entry 名称编码非法，跳过剩余内容 {}: {}",
                    origin, malformedEntryName.getMessage());
        }
        if (accountContainer && innerArchiveFullyWalked) {
            drainNestedRemainder(checkedInput, state);
        }
    }

    /** Consume legal bytes after an inner ZIP's end record so the outer entry CRC is complete. */
    private static void drainNestedRemainder(PushbackInputStream input, ReaderState state)
            throws IOException {
        byte[] discard = new byte[8192];
        int emptyReads = 0;
        while (true) {
            state.archiveBudget.checkTime();
            int count = input.read(discard);
            if (count < 0) {
                return;
            }
            if (count == 0) {
                if (++emptyReads > 16) {
                    state.markArchiveCorrupt();
                    return;
                }
                int one = input.read();
                if (one < 0) {
                    return;
                }
                emptyReads = 0;
                continue;
            }
            emptyReads = 0;
        }
    }

    private static final class ReaderState {
        private final ClassConsumer consumer;
        private final int targetFeature;
        private final InputBudget budget;
        private final Set<String> reasons = new LinkedHashSet<>();
        private final Set<String> emittedClassNames = new LinkedHashSet<>();
        private final InputBudget.Tracker archiveBudget;
        private int emitted;
        private boolean budgetExceeded;
        private int directoryEntries;

        private ReaderState(ClassConsumer consumer, int targetFeature, InputBudget budget,
                            InputBudget.Tracker tracker) {
            this.consumer = consumer;
            this.targetFeature = targetFeature > 0 ? targetFeature : runtimeFeature();
            this.budget = budget == null ? InputBudget.defaults() : budget;
            this.archiveBudget = tracker == null ? this.budget.tracker() : tracker;
        }

        private boolean atCapacity() {
            return emitted >= budget.maxClassEntries();
        }

        private void markCap(String where) {
            JustLogger.warn("class 条目超过上限 {}，停止{}", budget.maxClassEntries(), where);
            reasons.add("CLASS_CAP:" + budget.maxClassEntries());
        }

        private void markBudget(String reason) {
            budgetExceeded = true;
            reasons.add(reason);
        }

        private void markArchiveCorrupt() {
            reasons.add("ARCHIVE_CORRUPT");
        }

        private void markArchiveDuplicate() {
            budgetExceeded = true;
            reasons.add("ARCHIVE_DUPLICATE_ENTRY");
        }

        /** Convert bounded-entry failures into an auditable partial result. */
        private boolean markEntryFailure(IOException failure) {
            if (!isBudgetFailure(failure)) {
                return false;
            }
            markBudget(limitReason(failure, budget));
            return true;
        }

        /** ZipFile may surface a forged central-directory length as EOFException rather than ZipException. */
        private boolean markArchiveReadCorruption(IOException failure) {
            if (failure instanceof ZipException || failure instanceof EOFException) {
                markArchiveCorrupt();
                return true;
            }
            return false;
        }

        private boolean budgetExceeded() {
            return budgetExceeded;
        }

        private boolean visitDirectoryPath(Path candidate) throws IOException {
            archiveBudget.checkTime();
            if (++directoryEntries > budget.maxArchiveEntries()) {
                markBudget("ARCHIVE_ENTRY_CAP:" + budget.maxArchiveEntries());
                return false;
            }
            try {
                archiveBudget.observeFilesystemEntry();
            } catch (IOException failure) {
                markBudget(limitReason(failure, budget));
                return false;
            }
            return true;
        }

        private boolean observeEntry(ZipEntry entry) {
            if (budgetExceeded) {
                return false;
            }
            try {
                archiveBudget.observe(entry);
            } catch (IOException e) {
                markBudget(limitReason(e, archiveBudget.budget()));
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
            long limit = Math.min(budget.maxEntryBytes(), remaining);
            byte[] bytes;
            try {
                bytes = IoUtil.readAll(input, limit, archiveBudget);
            } catch (IOException e) {
                if (e instanceof ZipException || e instanceof EOFException) {
                    markArchiveCorrupt();
                } else {
                    markBudget(e.getMessage() != null && e.getMessage().startsWith("INPUT_PARSE_TIME_CAP")
                            ? "ARCHIVE_PARSE_TIME_CAP" : "ARCHIVE_ENTRY_READ_CAP");
                }
                throw e;
            }
            return bytes;
        }

        private byte[] readEntryBytes(ZipEntry entry, InputStream input) throws IOException {
            byte[] bytes = readBytes(input);
            if (entry != null && entry.getCrc() >= 0L) {
                CRC32 crc = new CRC32();
                crc.update(bytes);
                verifyCrc(entry, crc.getValue());
            }
            return bytes;
        }

        private void verifyCrc(ZipEntry entry, long actual) throws ZipException {
            if (entry != null && entry.getCrc() >= 0L && entry.getCrc() != actual) {
                markArchiveCorrupt();
                throw new ZipException("ARCHIVE_CRC_MISMATCH:" + entry.getName());
            }
        }

        private InputStream containerStream(InputStream input) {
            return new FilterInputStream(input) {
                @Override
                public int read() throws IOException {
                    return archiveBudget.readContainerByteBounded(input,
                            "ARCHIVE_UNCOMPRESSED_BYTES_CAP");
                }

                @Override
                public int read(byte[] buffer, int offset, int length) throws IOException {
                    if (buffer == null) {
                        throw new NullPointerException("buffer");
                    }
                    if (offset < 0 || length < 0 || offset > buffer.length - length) {
                        throw new IndexOutOfBoundsException();
                    }
                    if (length == 0) {
                        return 0;
                    }
                    return archiveBudget.readContainerBounded(input, buffer, offset, length,
                            "ARCHIVE_UNCOMPRESSED_BYTES_CAP");
                }

                @Override
                public long skip(long count) throws IOException {
                    if (count <= 0) {
                        return 0L;
                    }
                    return archiveBudget.skipContainerBounded(input, count);
                }
            };
        }

        private static String limitReason(IOException error, InputBudget budget) {
            String message = error.getMessage() == null ? "" : error.getMessage();
            if (message.contains("entry count")) {
                return "ARCHIVE_ENTRY_CAP:" + budget.maxArchiveEntries();
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
            if (message.contains("INPUT_PARSE_TIME_CAP")) {
                return "ARCHIVE_PARSE_TIME_CAP";
            }
            if (message.contains("INPUT_STREAM_NO_PROGRESS")) {
                return "ARCHIVE_STREAM_NO_PROGRESS";
            }
            return "ARCHIVE_ENTRY_BYTES_CAP";
        }

        private static boolean isBudgetFailure(IOException error) {
            String message = error == null || error.getMessage() == null
                    ? "" : error.getMessage();
            return message.contains("limit") || message.contains("exceed")
                    || message.contains("上限") || message.contains("条目")
                    || message.contains("字节")
                    || message.startsWith("INPUT_PARSE_TIME_CAP")
                    || message.startsWith("INPUT_STREAM_NO_PROGRESS");
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

    private static int runtimeFeature() {
        try {
            return Runtime.version().feature();
        } catch (RuntimeException ignored) {
            return 8;
        }
    }

    /**
     * Selection view for a single ZipFile.  The manifest is read before classes, so a valid
     * multi-release archive never emits its base class before a versioned replacement.  A
     * versioned path is kept under its logical class name; the archive origin still retains the
     * physical path for diagnostics.
     */
    private static MultiReleaseSelection multiReleaseSelection(ZipFile zip,
                                                                List<ZipEntry> entries,
                                                                ReaderState state) {
        boolean enabled = false;
        ZipEntry manifest = null;
        for (ZipEntry entry : entries) {
            if ("META-INF/MANIFEST.MF".equalsIgnoreCase(entry.getName())) {
                manifest = entry;
                break;
            }
        }
        if (manifest != null) {
            try (InputStream input = zip.getInputStream(manifest)) {
                byte[] bytes = state.readBytes(input);
                enabled = "true".equalsIgnoreCase(new Manifest(
                        new java.io.ByteArrayInputStream(bytes)).getMainAttributes()
                        .getValue("Multi-Release"));
            } catch (Exception failure) {
                // A malformed manifest must not cause a versioned class to masquerade as a
                // normal application class. Keep the base-only view and make the boundary
                // visible to completeness/report consumers.
                state.reasons.add("MULTI_RELEASE_MANIFEST_INVALID");
            }
        }
        return MultiReleaseSelection.create(entries, state.targetFeature, enabled);
    }

    private static final class MultiReleaseSelection {
        private final Map<String, String> selectedByLogicalPath;
        private final Set<String> selectedPhysicalPaths;

        private MultiReleaseSelection(Map<String, String> selectedByLogicalPath,
                                      Set<String> selectedPhysicalPaths) {
            this.selectedByLogicalPath = selectedByLogicalPath;
            this.selectedPhysicalPaths = selectedPhysicalPaths;
        }

        private static MultiReleaseSelection create(List<ZipEntry> entries, int targetFeature,
                                                    boolean enabled) {
            Map<String, VersionedPath> best = new HashMap<>();
            if (enabled && targetFeature >= 9) {
                for (ZipEntry entry : entries) {
                    VersionedPath candidate = VersionedPath.parse(entry.getName());
                    if (candidate == null || candidate.version() > targetFeature) {
                        continue;
                    }
                    VersionedPath previous = best.get(candidate.logicalPath());
                    if (previous == null || candidate.version() > previous.version()
                            || (candidate.version() == previous.version()
                            && candidate.physicalPath().compareTo(previous.physicalPath()) < 0)) {
                        best.put(candidate.logicalPath(), candidate);
                    }
                }
            }
            Map<String, String> selected = new HashMap<>();
            Set<String> physical = new java.util.HashSet<>();
            for (VersionedPath path : best.values()) {
                selected.put(path.logicalPath(), path.physicalPath());
                physical.add(path.physicalPath());
            }
            return new MultiReleaseSelection(Map.copyOf(selected), Set.copyOf(physical));
        }

        private boolean skip(String path) {
            if (path == null) {
                return true;
            }
            VersionedPath versioned = VersionedPath.parse(path);
            if (versioned != null) {
                return !selectedPhysicalPaths.contains(path);
            }
            if (path.startsWith(SKIPPED_MULTIRELEASE)) {
                return true;
            }
            return selectedByLogicalPath.containsKey(path);
        }

        private String logicalPath(String path) {
            VersionedPath versioned = VersionedPath.parse(path);
            return versioned == null ? path : versioned.logicalPath();
        }
    }

    /** Bounded bytes retained only for nested entries whose semantics require a second pass. */
    private record NestedPayload(String path, byte[] bytes) {
        private NestedPayload {
            path = path == null ? "" : path;
            bytes = bytes == null ? new byte[0] : bytes;
        }
    }

    /** Multi-release selection for a nested ZipInputStream after its bounded first pass. */
    private static final class NestedMultiReleaseSelection {
        private final Map<String, String> selectedByLogicalPath;
        private final Set<String> selectedPhysicalPaths;

        private NestedMultiReleaseSelection(Map<String, String> selectedByLogicalPath,
                                            Set<String> selectedPhysicalPaths) {
            this.selectedByLogicalPath = selectedByLogicalPath;
            this.selectedPhysicalPaths = selectedPhysicalPaths;
        }

        private static NestedMultiReleaseSelection create(List<NestedPayload> payloads,
                                                           int targetFeature, boolean enabled) {
            Map<String, VersionedPath> best = new HashMap<>();
            if (enabled && targetFeature >= 9) {
                for (NestedPayload payload : payloads) {
                    VersionedPath candidate = VersionedPath.parse(payload.path());
                    if (candidate == null || candidate.version() > targetFeature) {
                        continue;
                    }
                    VersionedPath previous = best.get(candidate.logicalPath());
                    if (previous == null || candidate.version() > previous.version()
                            || (candidate.version() == previous.version()
                            && candidate.physicalPath().compareTo(previous.physicalPath()) < 0)) {
                        best.put(candidate.logicalPath(), candidate);
                    }
                }
            }
            Map<String, String> selected = new HashMap<>();
            Set<String> physical = new java.util.HashSet<>();
            for (VersionedPath path : best.values()) {
                selected.put(path.logicalPath(), path.physicalPath());
                physical.add(path.physicalPath());
            }
            return new NestedMultiReleaseSelection(Map.copyOf(selected), Set.copyOf(physical));
        }

        private boolean skip(String path) {
            VersionedPath versioned = VersionedPath.parse(path);
            if (versioned != null) {
                return !selectedPhysicalPaths.contains(path);
            }
            if (path != null && path.startsWith(SKIPPED_MULTIRELEASE)) {
                return true;
            }
            return selectedByLogicalPath.containsKey(path);
        }

        private String logicalPath(String path) {
            VersionedPath versioned = VersionedPath.parse(path);
            return versioned == null ? path : versioned.logicalPath();
        }
    }

    private record VersionedPath(String physicalPath, String logicalPath, int version) {
        private static VersionedPath parse(String path) {
            if (path == null || !path.startsWith(SKIPPED_MULTIRELEASE)) {
                return null;
            }
            String rest = path.substring(SKIPPED_MULTIRELEASE.length());
            int slash = rest.indexOf('/');
            if (slash <= 0 || slash == rest.length() - 1) {
                return null;
            }
            int version;
            try {
                version = Integer.parseInt(rest.substring(0, slash));
            } catch (NumberFormatException ignored) {
                return null;
            }
            if (version < 9 || !rest.substring(slash + 1).endsWith(".class")) {
                return null;
            }
            return new VersionedPath(path, rest.substring(slash + 1), version);
        }
    }
}
