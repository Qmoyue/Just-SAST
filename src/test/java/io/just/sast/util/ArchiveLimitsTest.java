package io.just.sast.util;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.zip.ZipEntry;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ArchiveLimitsTest {

    @Test
    void rejectsAbsoluteAndTraversalNames() {
        assertTrue(ArchiveLimits.safeEntryName("BOOT-INF/classes/app/Main.class"));
        assertFalse(ArchiveLimits.safeEntryName("../outside.class"));
        assertFalse(ArchiveLimits.safeEntryName("BOOT-INF/classes/../outside.class"));
        assertFalse(ArchiveLimits.safeEntryName("C:\\outside.class"));
        assertFalse(ArchiveLimits.safeEntryName("/outside.class"));
        assertFalse(ArchiveLimits.safeEntryName("BOOT-INF//classes/Main.class"));
    }

    @Test
    void zeroProgressStreamCannotSpinForever() throws Exception {
        InputStream input = new InputStream() {
            private int calls;

            @Override
            public int read(byte[] buffer, int offset, int length) {
                if (calls++ == 0) {
                    return 0;
                }
                return -1;
            }

            @Override
            public int read() {
                return 'x';
            }
        };
        assertArrayEquals(new byte[]{'x'}, IoUtil.readAll(input, 1));
    }

    @Test
    void zeroProgressStillHonorsLimit() {
        InputStream input = new InputStream() {
            @Override
            public int read(byte[] buffer, int offset, int length) {
                return 0;
            }

            @Override
            public int read() {
                return 'x';
            }
        };
        assertThrows(IOException.class, () -> IoUtil.readAll(input, 0));
    }

    @Test
    void trackerRejectsDeclaredEntryLimit() {
        ArchiveLimits.Tracker tracker = new ArchiveLimits.Tracker();
        ZipEntry entry = new ZipEntry("large.bin");
        entry.setSize(ArchiveLimits.MAX_ENTRY_UNCOMPRESSED_BYTES + 1);
        assertThrows(IOException.class, () -> tracker.observe(entry));
    }

    @Test
    void trackerAccountsEmbeddedContainerBytes() throws Exception {
        ArchiveLimits.Tracker tracker = new ArchiveLimits.Tracker();
        tracker.recordContainerRead(7);
        assertEquals(ArchiveLimits.MAX_TOTAL_UNCOMPRESSED_BYTES - 7,
                tracker.remainingReadBytes());
        assertThrows(IOException.class, () -> tracker.recordContainerRead(
                ArchiveLimits.MAX_TOTAL_UNCOMPRESSED_BYTES));
    }

    @Test
    void physicalContainerLimitIsCheckedBeforeOpening(@TempDir Path tmp) throws Exception {
        Path oversized = tmp.resolve("oversized.jar");
        try (var channel = java.nio.channels.FileChannel.open(oversized,
                java.nio.file.StandardOpenOption.CREATE,
                java.nio.file.StandardOpenOption.WRITE)) {
            channel.position(ArchiveLimits.MAX_TOTAL_COMPRESSED_BYTES);
            channel.write(java.nio.ByteBuffer.wrap(new byte[]{1}));
        }
        assertThrows(IOException.class, () -> ArchiveLimits.checkContainerSize(oversized));
    }

    @Test
    void detectsSymbolicLinkWithoutFollowingIt(@TempDir Path tmp) throws Exception {
        Path target = tmp.resolve("target.jar");
        Path link = tmp.resolve("link.jar");
        java.nio.file.Files.write(target, new byte[]{1});
        try {
            java.nio.file.Files.createSymbolicLink(link, target.getFileName());
        } catch (UnsupportedOperationException | java.io.IOException | SecurityException unsupported) {
            return;
        }
        assertTrue(ArchiveLimits.isLinkOrReparsePoint(link));
        assertFalse(ArchiveLimits.isLinkOrReparsePoint(target));
    }
}
