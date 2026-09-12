package io.just.sast.util;

import io.just.sast.run.InputBudget;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

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

    @Test
    void explicitBudgetBoundsDirectoryEntriesAndFileBytes(@TempDir Path temp) throws Exception {
        Path root = Files.createDirectories(temp.resolve("classes"));
        Files.write(root.resolve("A.class"), new byte[]{1, 2, 3, 4});
        InputBudget defaults = InputBudget.defaults();
        InputBudget oneEntry = new InputBudget(defaults.schemaVersion(), defaults.maxPhysicalBytes(),
                defaults.maxCompressedBytes(), defaults.maxUncompressedBytes(), 3,
                defaults.maxCompressionRatio(), 1, defaults.maxArchiveNesting(),
                defaults.maxClassEntries(), defaults.maxRuleInputBytes(), defaults.maxRuleCodePoints(),
                defaults.maxRuleAliases(), defaults.maxRuleNestingDepth(), defaults.maxRuleDocuments(),
                defaults.maxRuleCount(), defaults.maxRuleCollectionItems(), defaults.maxRuleNodes(),
                defaults.maxRuleScalarChars(), defaults.maxPathChars(), defaults.maxParseMillis());
        assertThrows(java.io.IOException.class, () -> ArtifactFingerprint.sha256(root, oneEntry));

        InputBudget tinyFile = new InputBudget(defaults.schemaVersion(), 3, 3,
                defaults.maxUncompressedBytes(), defaults.maxEntryBytes(), defaults.maxCompressionRatio(),
                defaults.maxArchiveEntries(), defaults.maxArchiveNesting(), defaults.maxClassEntries(),
                defaults.maxRuleInputBytes(), defaults.maxRuleCodePoints(), defaults.maxRuleAliases(),
                defaults.maxRuleNestingDepth(), defaults.maxRuleDocuments(), defaults.maxRuleCount(),
                defaults.maxRuleCollectionItems(), defaults.maxRuleNodes(), defaults.maxRuleScalarChars(),
                defaults.maxPathChars(), defaults.maxParseMillis());
        assertThrows(java.io.IOException.class,
                () -> ArtifactFingerprint.sha256(root.resolve("A.class"), tinyFile));
    }

    @Test
    void directoryBudgetCountsDirectoriesAsWellAsFiles(@TempDir Path temp) throws Exception {
        Path root = Files.createDirectories(temp.resolve("classes"));
        Path nested = Files.createDirectories(root.resolve("a/b"));
        Files.write(nested.resolve("A.class"), new byte[]{1});
        InputBudget defaults = InputBudget.defaults();
        InputBudget twoEntries = defaults.withArchiveLimits(defaults.maxPhysicalBytes(),
                defaults.maxCompressedBytes(), defaults.maxUncompressedBytes(),
                defaults.maxEntryBytes(), 2, defaults.maxArchiveNesting(),
                defaults.maxClassEntries());

        assertThrows(java.io.IOException.class, () -> ArtifactFingerprint.sha256(root, twoEntries));
    }

    @Test
    void callerTrackerRejectsAggregateFileReads(@TempDir Path temp) throws Exception {
        Path first = temp.resolve("first.bin");
        Path second = temp.resolve("second.bin");
        Files.write(first, new byte[]{1, 2, 3});
        Files.write(second, new byte[]{4, 5, 6});
        InputBudget defaults = InputBudget.defaults();
        InputBudget budget = defaults.withArchiveLimits(1024, 1024, 5, 1024,
                defaults.maxArchiveEntries(), defaults.maxArchiveNesting(),
                defaults.maxClassEntries());
        InputBudget.Tracker tracker = budget.tracker();

        ArtifactFingerprint.sha256(first, tracker);
        assertThrows(java.io.IOException.class, () -> ArtifactFingerprint.sha256(second, tracker));
    }

    @Test
    void directoryIdentityRejectsLinkInsteadOfSilentlyOmittingIt(@TempDir Path temp)
            throws Exception {
        Path root = Files.createDirectories(temp.resolve("classes"));
        Path real = Files.createDirectories(temp.resolve("real"));
        Files.write(real.resolve("Hidden.class"), new byte[]{1});
        Path link = root.resolve("linked");
        try {
            Files.createSymbolicLink(link, real.getFileName());
        } catch (UnsupportedOperationException | java.io.IOException | SecurityException unsupported) {
            Assumptions.assumeTrue(false, "symbolic links unavailable: " + unsupported.getMessage());
        }
        assertThrows(java.io.IOException.class, () -> ArtifactFingerprint.sha256(root));
    }
}
