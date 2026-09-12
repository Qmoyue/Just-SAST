package io.just.sast.report;

import io.just.sast.run.InputBudget;
import io.just.sast.util.ArchiveLimits;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.concurrent.atomic.AtomicLong;

/** Small report-output boundary: a failed writer must not publish a plausible partial file. */
final class AtomicFiles {

    @FunctionalInterface
    interface CommitHook {
        void beforeFinalMove() throws IOException;
    }

    /*
     * Report temp names do not carry security material and are never published. UUID.randomUUID
     * nevertheless initializes the platform SecureRandom on the first report write; on some
     * Windows hosts that blocks for several seconds and made a tiny findings report look like
     * an analysis bottleneck. CREATE_NEW remains the collision guard; the process id, monotonic
     * clock and counter provide a cheap per-process namespace without touching entropy sources.
     */
    private static final AtomicLong TEMP_COUNTER = new AtomicLong();
    private static final String PROCESS_TOKEN = Long.toUnsignedString(ProcessHandle.current().pid(), 36);

    private AtomicFiles() {
    }

    static Path tempSibling(Path target) throws IOException {
        Path absolute = target.toAbsolutePath().normalize();
        Path parent = absolute.getParent();
        if (parent == null) {
            throw new IOException("report target has no parent: " + target);
        }
        ReportLayout.ensureDirectory(parent);
        long counter = TEMP_COUNTER.incrementAndGet();
        String token = Long.toUnsignedString(System.nanoTime(), 36) + "-" + counter;
        return parent.resolve("." + absolute.getFileName() + ".tmp-"
                + PROCESS_TOKEN + "-" + token);
    }

    static BufferedWriter newUtf8Writer(Path temp) throws IOException {
        return Files.newBufferedWriter(temp, StandardCharsets.UTF_8,
                StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
    }

    static void commit(Path temp, Path target) throws IOException {
        commitInternal(temp, target, null);
    }

    /**
     * Contract-only seam for deterministic parent replacement tests. Normal callers must use
     * {@link #commit(Path, Path)} so no callback can widen the commit race window.
     */
    static void commitForContract(Path temp, Path target, CommitHook hook) throws IOException {
        commitInternal(temp, target, hook);
    }

    private static void commitInternal(Path temp, Path target, CommitHook hook) throws IOException {
        if (temp == null || target == null) {
            throw new IOException("report temp/target is null");
        }
        Path normalizedTemp = temp.toAbsolutePath().normalize();
        Path normalizedTarget = target.toAbsolutePath().normalize();
        Path parent = normalizedTarget.getParent();
        if (parent == null || normalizedTemp.getParent() == null
                || !normalizedTemp.getParent().equals(parent)) {
            throw new IOException("REPORT_OUTPUT_PARENT_CHANGED_DURING_READ");
        }
        ArchiveLimits.DirectoryReadSnapshot parentSnapshot = ArchiveLimits.snapshotDirectory(
                parent, InputBudget.defaults(), "REPORT_OUTPUT_PARENT");
        if (!Files.isRegularFile(normalizedTemp, LinkOption.NOFOLLOW_LINKS)
                || ArchiveLimits.isLinkOrReparsePoint(normalizedTemp)) {
            throw new IOException("REPORT_TEMP_UNSAFE");
        }
        boolean targetPresentBefore = Files.exists(normalizedTarget, LinkOption.NOFOLLOW_LINKS);
        ArchiveLimits.FileReadSnapshot targetSnapshot = null;
        boolean committed = false;
        try {
            if (targetPresentBefore) {
                if (!Files.isRegularFile(normalizedTarget, LinkOption.NOFOLLOW_LINKS)
                        || ArchiveLimits.isLinkOrReparsePoint(normalizedTarget)) {
                    throw new IOException("REPORT_OUTPUT_TARGET_UNSAFE");
                }
                targetSnapshot = ArchiveLimits.snapshotRegularFile(normalizedTarget,
                        InputBudget.defaults(), "REPORT_OUTPUT_TARGET");
            }
            ArchiveLimits.verifyDirectoryUnchanged(parentSnapshot, "REPORT_OUTPUT_PARENT");
            if (hook != null) {
                hook.beforeFinalMove();
            }
            // Recheck after the last caller-observable operation. Portable NIO cannot make the
            // subsequent path move parent-relative, but it must not knowingly publish through
            // a replaced/reparse parent.
            ArchiveLimits.verifyDirectoryUnchanged(parentSnapshot, "REPORT_OUTPUT_PARENT");
            if (targetPresentBefore) {
                if (!Files.exists(normalizedTarget, LinkOption.NOFOLLOW_LINKS)
                        || !Files.isRegularFile(normalizedTarget, LinkOption.NOFOLLOW_LINKS)) {
                    throw new IOException("REPORT_OUTPUT_TARGET_CHANGED_DURING_READ");
                }
                if (ArchiveLimits.isLinkOrReparsePoint(normalizedTarget)) {
                    throw new IOException("REPORT_OUTPUT_TARGET_UNSAFE");
                }
                try {
                    ArchiveLimits.verifyRegularFileUnchanged(targetSnapshot,
                            "REPORT_OUTPUT_TARGET");
                } catch (IOException changed) {
                    throw new IOException("REPORT_OUTPUT_TARGET_CHANGED_DURING_READ", changed);
                }
            } else if (Files.exists(normalizedTarget, LinkOption.NOFOLLOW_LINKS)) {
                if (ArchiveLimits.isLinkOrReparsePoint(normalizedTarget)) {
                    throw new IOException("REPORT_OUTPUT_TARGET_UNSAFE");
                }
                throw new IOException("REPORT_OUTPUT_TARGET_CHANGED_DURING_READ");
            }
            try {
                Files.move(normalizedTemp, normalizedTarget,
                        StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException unsupported) {
                Files.move(normalizedTemp, normalizedTarget,
                        StandardCopyOption.REPLACE_EXISTING);
            }
            committed = true;
        } finally {
            if (!committed) {
                deleteTempIfSafe(normalizedTemp, parentSnapshot);
            }
        }
    }

    private static void deleteTempIfSafe(Path temp, ArchiveLimits.DirectoryReadSnapshot parentSnapshot) {
        try {
            ArchiveLimits.verifyDirectoryUnchanged(parentSnapshot, "REPORT_OUTPUT_PARENT");
            if (Files.isRegularFile(temp, LinkOption.NOFOLLOW_LINKS)
                    && !ArchiveLimits.isLinkOrReparsePoint(temp)) {
                Files.deleteIfExists(temp);
            }
        } catch (IOException | RuntimeException ignored) {
            // A changed/reparse parent is deliberately left for operator recovery; following
            // it to clean a path could delete outside the trusted report tree.
        }
    }

    static void writeUtf8(Path target, String content) throws IOException {
        Path temp = tempSibling(target);
        boolean committed = false;
        try {
            try (BufferedWriter writer = newUtf8Writer(temp)) {
                writer.write(content == null ? "" : content);
            }
            commit(temp, target);
            committed = true;
        } finally {
            if (!committed) {
                Files.deleteIfExists(temp);
            }
        }
    }
}
