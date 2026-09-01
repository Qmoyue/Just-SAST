package io.just.sast.util;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.zip.ZipEntry;

/**
 * Shared archive limits for the static frontend and the dynamic classpath expander.
 * Values are deliberately conservative but large enough for ordinary fat JAR/WAR inputs.
 */
public final class ArchiveLimits {

    public static final int MAX_ENTRIES = 250_000;
    public static final long MAX_ENTRY_UNCOMPRESSED_BYTES = 64L * 1024 * 1024;
    public static final long MAX_TOTAL_UNCOMPRESSED_BYTES = 512L * 1024 * 1024;
    public static final long MAX_TOTAL_COMPRESSED_BYTES = 256L * 1024 * 1024;
    public static final long MAX_COMPRESSION_RATIO = 1_000L;
    public static final int MAX_NESTING = 4;

    private ArchiveLimits() {
    }

    /**
     * Check the physical container before opening it. ZIP central-directory sizes are
     * attacker-controlled metadata and may be absent or deliberately understated; the
     * physical file-size guard closes the gap for top-level inputs and classpath expansion.
     */
    public static void checkContainerSize(Path container) throws IOException {
        if (container == null) {
            throw new IOException("archive container is null");
        }
        long size = Files.size(container);
        if (size > MAX_TOTAL_COMPRESSED_BYTES) {
            throw new IOException("archive physical compressed bytes exceed limit: "
                    + MAX_TOTAL_COMPRESSED_BYTES);
        }
    }

    /** Return true for symbolic links and Windows reparse points without following them. */
    public static boolean isLinkOrReparsePoint(Path path) {
        if (path == null || Files.isSymbolicLink(path)) {
            return path != null;
        }
        try {
            return Boolean.TRUE.equals(Files.getAttribute(path, "dos:reparsePoint",
                    LinkOption.NOFOLLOW_LINKS));
        } catch (UnsupportedOperationException | IOException | SecurityException
                 | IllegalArgumentException ignored) {
            // Unix providers do not expose the DOS attribute; symbolic-link detection above
            // remains the portable check. Callers still use real-path containment where it is
            // available before opening untrusted files.
            return false;
        }
    }

    /** Reject absolute and parent-traversal archive names before resolving them. */
    public static boolean safeEntryName(String name) {
        if (name == null || name.isBlank() || name.startsWith("/") || name.startsWith("\\")
                || name.matches("^[A-Za-z]:.*")) {
            return false;
        }
        String normalized = name.replace('\\', '/');
        // Directory entries conventionally end with a slash. The slash itself is
        // harmless; empty path components inside the name are not.
        while (normalized.endsWith("/")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        if (normalized.isBlank()) {
            return false;
        }
        for (String component : normalized.split("/", -1)) {
            if (component.isEmpty() || ".".equals(component) || "..".equals(component)) {
                return false;
            }
        }
        return true;
    }

    /** Declared ZIP sizes are advisory; unknown sizes are checked while bytes are read. */
    public static boolean safeCompressionRatio(long compressed, long uncompressed) {
        if (uncompressed < 0 || compressed < 0) {
            return true;
        }
        if (uncompressed == 0) {
            return true;
        }
        if (compressed == 0) {
            return uncompressed <= 1024;
        }
        if (compressed > Long.MAX_VALUE / MAX_COMPRESSION_RATIO) {
            return true;
        }
        return uncompressed <= compressed * MAX_COMPRESSION_RATIO
                || uncompressed <= MAX_COMPRESSION_RATIO;
    }

    /**
     * Mutable accounting for one archive expansion. Declared ZIP sizes and bytes actually
     * read are tracked independently: a corrupt archive must not bypass the read limit by
     * lying in its central directory, while a conservative declared-size cap rejects an
     * archive before it is expanded.
     */
    public static final class Tracker {
        private int entries;
        private long compressedBytes;
        private long declaredUncompressedBytes;
        private long readUncompressedBytes;
        private long readContainerBytes;

        public void observe(ZipEntry entry) throws IOException {
            if (entry == null) {
                throw new IOException("null archive entry");
            }
            if (++entries > MAX_ENTRIES) {
                throw new IOException("archive entry count exceeds limit: " + MAX_ENTRIES);
            }
            long compressed = entry.getCompressedSize();
            long uncompressed = entry.getSize();
            if (compressed >= 0) {
                if (compressed > MAX_TOTAL_COMPRESSED_BYTES - compressedBytes) {
                    throw new IOException("archive compressed bytes exceed limit");
                }
                compressedBytes += compressed;
            }
            if (uncompressed > MAX_ENTRY_UNCOMPRESSED_BYTES) {
                throw new IOException("archive entry exceeds limit: " + entry.getName());
            }
            if (!safeCompressionRatio(compressed, uncompressed)) {
                throw new IOException("archive compression ratio exceeds limit: " + entry.getName());
            }
            if (uncompressed >= 0) {
                if (uncompressed > MAX_TOTAL_UNCOMPRESSED_BYTES - declaredUncompressedBytes) {
                    throw new IOException("archive declared bytes exceed limit");
                }
                declaredUncompressedBytes += uncompressed;
            }
        }

        public long remainingReadBytes() {
            return MAX_TOTAL_UNCOMPRESSED_BYTES - readUncompressedBytes - readContainerBytes;
        }

        public void recordRead(long bytes) throws IOException {
            if (bytes < 0 || bytes > remainingReadBytes()) {
                throw new IOException("archive bytes read exceed limit");
            }
            readUncompressedBytes += bytes;
        }

        /** Account for the raw bytes of an embedded archive before its entries are expanded. */
        public void recordContainerRead(long bytes) throws IOException {
            if (bytes < 0 || bytes > remainingReadBytes()) {
                throw new IOException("archive container bytes read exceed limit");
            }
            readContainerBytes += bytes;
        }

        public int entries() {
            return entries;
        }

        public long compressedBytes() {
            return compressedBytes;
        }

        public long declaredUncompressedBytes() {
            return declaredUncompressedBytes;
        }

        public long readUncompressedBytes() {
            return readUncompressedBytes;
        }

        public long readContainerBytes() {
            return readContainerBytes;
        }
    }
}
