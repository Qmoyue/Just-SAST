package io.just.sast.report;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Contract for fail-closed cache tree checks when a directory is replaced mid-operation. */
class ScanCacheLinkContractTest {

    @Test
    void restoreParentReplacementFailsClosedBeforeCommit(@TempDir Path tmp) throws Exception {
        String key = "b".repeat(64);
        Path cacheEntry = tmp.resolve("cache").resolve(key);
        Path metadata = Files.createDirectories(cacheEntry.resolve("meta"));
        Files.writeString(metadata.resolve("scan-identity.json"),
                "{\"schema_version\":1,\"cache_key\":\"" + key + "\"}\n");
        Files.writeString(metadata.resolve("cache-complete.json"),
                "{\"schema_version\":1,\"cache_key\":\"" + key
                        + "\",\"completeness\":\"COMPLETE\"}\n");
        Files.writeString(cacheEntry.resolve("payload.txt"), "cache-payload");

        Path outputParent = Files.createDirectories(tmp.resolve("restore-parent"));
        Path output = Files.createDirectories(outputParent.resolve("out"));
        IOException failure = assertThrows(IOException.class, () ->
                ScanCache.restoreForContract(tmp.resolve("cache"), key, output,
                        () -> {
                            try (var walk = Files.walk(outputParent)) {
                                for (Path path : walk.sorted(java.util.Comparator.reverseOrder())
                                        .toList()) {
                                    Files.deleteIfExists(path);
                                }
                            }
                            Files.writeString(outputParent, "replacement-parent");
                        }));
        assertTrue(failure.getMessage().contains("CACHE_DIRECTORY_CHANGED_DURING_COPY"),
                failure.getMessage());
        assertTrue(Files.isRegularFile(outputParent, LinkOption.NOFOLLOW_LINKS),
                "the hostile replacement must remain visible for recovery inspection");
    }

    @Test
    void replacedCacheTreeDirectoryIdentityFailsClosed(@TempDir Path tmp) throws Exception {
        Path source = Files.createDirectories(tmp.resolve("source").resolve("nested"));
        ScanCache.DirectoryChainSnapshot snapshot =
                ScanCache.snapshotDirectoryChainForContract(source);
        var before = Files.readAttributes(source,
                java.nio.file.attribute.BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        Assumptions.assumeTrue(before.fileKey() != null || before.creationTime().toMillis() != 0L,
                "provider does not expose a stable directory identity");
        Files.delete(source);
        Files.createDirectory(source);
        var after = Files.readAttributes(source,
                java.nio.file.attribute.BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        Assumptions.assumeTrue(identityDiffers(before, after),
                "provider did not expose a replacement identity change");
        IOException failure = assertThrows(IOException.class,
                () -> ScanCache.verifyDirectoryChainForContract(snapshot));
        assertTrue(failure.getMessage().contains("CACHE_DIRECTORY_CHANGED_DURING_COPY"),
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
