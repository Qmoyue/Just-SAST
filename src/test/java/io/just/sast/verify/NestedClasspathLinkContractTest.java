package io.just.sast.verify;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Optional host-capability contract for output-parent link/reparse rejection. */
class NestedClasspathLinkContractTest {

    @Test
    void preexistingOutputParentLinkFailsClosed(@TempDir Path tmp) throws Exception {
        Path base = Files.createDirectories(tmp.resolve("base"));
        Path real = Files.createDirectories(tmp.resolve("real"));
        Path link = base.resolve("link");
        try {
            Files.createSymbolicLink(link, real.getFileName());
        } catch (UnsupportedOperationException | IOException | SecurityException unsupported) {
            Assumptions.assumeTrue(false,
                    "symbolic links unavailable: " + unsupported.getMessage());
        }
        IOException failure = assertThrows(IOException.class,
                () -> NestedClasspath.createOutputParentForContract(base, link.resolve("child")));
        assertTrue(failure.getMessage().contains("unsafe nested output parent"),
                failure.getMessage());
    }

    @Test
    void replacedOutputParentIdentityFailsClosed(@TempDir Path tmp) throws Exception {
        Path base = Files.createDirectories(tmp.resolve("base"));
        Path parent = Files.createDirectories(base.resolve("nested"));
        NestedClasspath.OutputParentSnapshot snapshot =
                NestedClasspath.snapshotOutputParentForContract(base, parent);
        var before = Files.readAttributes(parent,
                java.nio.file.attribute.BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        Assumptions.assumeTrue(before.fileKey() != null || before.creationTime().toMillis() != 0L,
                "provider does not expose a stable directory identity");
        Files.delete(parent);
        Files.createDirectory(parent);
        var after = Files.readAttributes(parent,
                java.nio.file.attribute.BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        Assumptions.assumeTrue(identityDiffers(before, after),
                "provider did not expose a replacement identity change");
        IOException failure = assertThrows(IOException.class,
                () -> NestedClasspath.verifyOutputParentForContract(snapshot));
        assertTrue(failure.getMessage().contains("output parent changed"),
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
