package io.just.sast.util;

import io.just.sast.run.InputBudget;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.nio.file.Files;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

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
    void rejectsExcessivePathComponentDepth() {
        String deep = "a/".repeat(InputBudget.defaults().maxPathDepth() + 1) + "file.class";
        assertFalse(ArchiveLimits.safeEntryName(deep));
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
    void trackedReaderRejectsPersistentNoProgress() {
        InputStream input = new InputStream() {
            @Override
            public int read(byte[] buffer, int offset, int length) {
                return 0;
            }

            @Override
            public int read() {
                return 0;
            }
        };
        assertThrows(IOException.class, () -> IoUtil.readAll(input, 2_048,
                InputBudget.defaults().tracker()));
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

    @Test
    void rejectsLinkOrNonDirectoryAncestor(@TempDir Path tmp) throws Exception {
        Path real = Files.createDirectories(tmp.resolve("real"));
        Path target = real.resolve("input.jar");
        Files.write(target, new byte[]{1});
        Path link = tmp.resolve("linked");
        try {
            Files.createSymbolicLink(link, real.getFileName());
        } catch (UnsupportedOperationException | IOException | SecurityException unsupported) {
            return;
        }
        assertThrows(IOException.class, () -> ArchiveLimits.checkPathAncestors(
                link.resolve("input.jar"), InputBudget.defaults()));
    }

    @Test
    void zipFileHandleBracketsProviderPathOpen(@TempDir Path tmp) throws Exception {
        Path archive = tmp.resolve("input.jar");
        try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(archive))) {
            zip.putNextEntry(new ZipEntry("A.class"));
            zip.write(new byte[]{1, 2, 3});
            zip.closeEntry();
        }
        ArchiveLimits.FileReadSnapshot snapshot = ArchiveLimits.snapshotRegularFile(
                archive, InputBudget.defaults(), "JDK_INDEX");
        try (ArchiveLimits.ZipFileHandle handle = ArchiveLimits.openZipFile(snapshot,
                "JDK_INDEX")) {
            assertFalse(handle.providerAtomicOpen(),
                    "ZipFile path construction is not a portable atomic parent-handle open");
            assertEquals(IoUtil.OpenCapability.SNAPSHOT_BRACKETED, handle.openCapability(),
                    "the non-atomic ZipFile limitation must be typed, not inferred from a boolean");
            assertEquals(IoUtil.ProviderAtomicStatus.SNAPSHOT_ONLY_PATH_OPEN,
                    handle.providerAtomicStatus());
            assertEquals("PROVIDER_PATH_ONLY_SNAPSHOT",
                    handle.providerAtomicStatus().reasonCode());
            assertFalse(handle.providerAtomicStatus().supportsAtomicOpen());
            assertTrue(handle.zip().getEntry("A.class") != null);
        }
    }

    @Test
    void zipFileHandleRejectsReplacementBeforeOpening(@TempDir Path tmp) throws Exception {
        Path archive = tmp.resolve("input.jar");
        try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(archive))) {
            zip.putNextEntry(new ZipEntry("A.class"));
            zip.write(new byte[]{1, 2, 3});
            zip.closeEntry();
        }
        ArchiveLimits.FileReadSnapshot snapshot = ArchiveLimits.snapshotRegularFile(
                archive, InputBudget.defaults(), "JDK_INDEX");
        Files.write(archive, new byte[]{9, 8, 7, 6},
                java.nio.file.StandardOpenOption.APPEND);
        IOException failure = assertThrows(IOException.class,
                () -> ArchiveLimits.openZipFile(snapshot, "JDK_INDEX"));
        assertTrue(failure.getMessage().contains("JDK_INDEX_CHANGED_DURING_READ"),
                failure.getMessage());
    }

    @Test
    void directorySnapshotExposesTypedNonAtomicCapability(@TempDir Path tmp) throws Exception {
        Path directory = Files.createDirectories(tmp.resolve("tree"));
        ArchiveLimits.DirectoryReadSnapshot snapshot = ArchiveLimits.snapshotDirectory(
                directory, InputBudget.defaults(), "TREE_INDEX");

        assertEquals(IoUtil.OpenCapability.SNAPSHOT_BRACKETED, snapshot.openCapability(),
                "directory identity snapshots must disclose that provider-atomic open is not proven");
        assertEquals(IoUtil.ProviderAtomicStatus.SNAPSHOT_ONLY_PATH_OPEN,
                snapshot.providerAtomicStatus());
        assertFalse(snapshot.providerAtomicStatus().supportsAtomicOpen());
    }
}
