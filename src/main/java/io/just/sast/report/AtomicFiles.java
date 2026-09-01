package io.just.sast.report;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.concurrent.atomic.AtomicLong;

/** Small report-output boundary: a failed writer must not publish a plausible partial file. */
final class AtomicFiles {

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
        Files.createDirectories(parent);
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
        if (temp == null || target == null) {
            throw new IOException("report temp/target is null");
        }
        Path normalizedTemp = temp.toAbsolutePath().normalize();
        Path normalizedTarget = target.toAbsolutePath().normalize();
        try {
            try {
                Files.move(normalizedTemp, normalizedTarget,
                        StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException unsupported) {
                Files.move(normalizedTemp, normalizedTarget,
                        StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(normalizedTemp);
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
