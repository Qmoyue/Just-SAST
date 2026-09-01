package io.just.sast.util;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

class ArtifactFingerprintTest {

    @Test
    void directoryIdentityIsOrderIndependentAndChangesWithContent(@TempDir Path temp) throws Exception {
        Path root = Files.createDirectories(temp.resolve("classes"));
        Path first = root.resolve("b/B.class");
        Path second = root.resolve("a/A.class");
        Files.createDirectories(first.getParent());
        Files.createDirectories(second.getParent());
        Files.write(first, new byte[]{2, 3});
        Files.write(second, new byte[]{1});

        String before = ArtifactFingerprint.sha256(root);
        Files.write(first, new byte[]{2, 4});
        String after = ArtifactFingerprint.sha256(root);

        assertEquals(64, before.length());
        assertNotEquals(before, after);

        Path reordered = Files.createDirectories(temp.resolve("reordered"));
        Files.createDirectories(reordered.resolve("a"));
        Files.createDirectories(reordered.resolve("b"));
        Files.write(reordered.resolve("a/A.class"), new byte[]{1});
        Files.write(reordered.resolve("b/B.class"), new byte[]{2, 3});
        assertEquals(before, ArtifactFingerprint.sha256(reordered));
    }
}
