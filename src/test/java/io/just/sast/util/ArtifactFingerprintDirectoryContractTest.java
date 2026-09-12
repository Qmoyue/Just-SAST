package io.just.sast.util;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Contract for fail-closed directory-walk identity checks under replacement. */
class ArtifactFingerprintDirectoryContractTest {

    @Test
    void replacedDirectoryWalkComponentFailsClosed(@TempDir Path tmp) throws Exception {
        Path root = Files.createDirectories(tmp.resolve("root"));
        Path nested = Files.createDirectories(root.resolve("nested"));
        ArtifactFingerprint.DirectorySnapshot snapshot =
                ArtifactFingerprint.snapshotDirectoryForContract(root);
        var before = Files.readAttributes(nested,
                java.nio.file.attribute.BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        Assumptions.assumeTrue(before.fileKey() != null || before.creationTime().toMillis() != 0L,
                "provider does not expose a stable directory identity");
        Files.delete(nested);
        Files.createDirectory(nested);
        var after = Files.readAttributes(nested,
                java.nio.file.attribute.BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        Assumptions.assumeTrue(identityDiffers(before, after),
                "provider did not expose a replacement identity change");
        IOException failure = assertThrows(IOException.class,
                () -> ArtifactFingerprint.verifyDirectoryForContract(snapshot));
        assertTrue(failure.getMessage().contains("artifact-directory-changed-during-hash"),
                failure.getMessage());
    }

    private static boolean identityDiffers(
            java.nio.file.attribute.BasicFileAttributes before,
            java.nio.file.attribute.BasicFileAttributes after) {
        if (before.fileKey() != null || after.fileKey() != null) {
            return before.fileKey() == null || after.fileKey() == null
                    || !before.fileKey().equals(after.fileKey());
        }
        return !before.creationTime().equals(after.creationTime());
    }
}
