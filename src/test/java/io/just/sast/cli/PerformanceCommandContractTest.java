package io.just.sast.cli;

import io.just.sast.run.InputBudget;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Contract tests for performance-runner output cleanup boundaries. */
class PerformanceCommandContractTest {

    @Test
    void cleanupRemovesBoundedTreeWithoutFollowingLinks(@TempDir Path temp) throws Exception {
        Path root = temp.resolve("run");
        Files.createDirectories(root.resolve("nested"));
        Files.writeString(root.resolve("nested/result.json"), "{}\n");

        assertTrue(PerformanceCommand.deleteTreeBounded(root, InputBudget.defaults()));
        assertFalse(Files.exists(root), "successful cleanup removes the complete output tree");
    }

    @Test
    void cleanupFailsClosedBeforeDeletingWhenSharedBudgetIsExhausted(@TempDir Path temp)
            throws Exception {
        Path root = temp.resolve("run");
        Files.createDirectories(root.resolve("nested"));
        Files.writeString(root.resolve("nested/result.json"), "{}\n");
        InputBudget defaults = InputBudget.defaults();
        InputBudget tiny = defaults.withArchiveLimits(defaults.maxPhysicalBytes(),
                defaults.maxCompressedBytes(), defaults.maxUncompressedBytes(),
                defaults.maxEntryBytes(), 1, defaults.maxArchiveNesting(),
                defaults.maxClassEntries());

        assertFalse(PerformanceCommand.deleteTreeBounded(root, tiny));
        assertTrue(Files.exists(root), "budget failure must retain the tree for diagnosis");
        assertTrue(Files.exists(root.resolve("nested/result.json")),
                "budget failure must not leave a partially deleted report tree");
    }

    @Test
    void resultReaderParentReplacementFailsClosed(@TempDir Path temp) throws Exception {
        Path parent = Files.createDirectories(temp.resolve("parent"));
        Path result = parent.resolve("scan-metadata.json");
        Files.writeString(result, "{}\n");
        var snapshot = PerformanceCommand.snapshotResultForContract(result);
        var before = Files.readAttributes(parent,
                java.nio.file.attribute.BasicFileAttributes.class,
                java.nio.file.LinkOption.NOFOLLOW_LINKS);
        org.junit.jupiter.api.Assumptions.assumeTrue(
                before.fileKey() != null || before.creationTime().toMillis() != 0L,
                "provider does not expose a stable directory identity");
        Files.delete(result);
        Files.delete(parent);
        Files.createDirectory(parent);
        Files.writeString(result, "{}\n");
        IOException failure = assertThrows(IOException.class,
                () -> PerformanceCommand.verifyResultSnapshotForContract(snapshot));
        assertTrue(failure.getMessage().contains("PERFORMANCE_RESULT_CHANGED_DURING_READ"),
                failure.getMessage());
    }

    @Test
    void resultReaderUsesOneCallerTotalBudget(@TempDir Path temp) throws Exception {
        Path first = temp.resolve("first.json");
        Path second = temp.resolve("second.json");
        Files.writeString(first, "a".repeat(700));
        Files.writeString(second, "b".repeat(700));
        InputBudget defaults = InputBudget.defaults();
        InputBudget budget = new InputBudget(defaults.schemaVersion(), defaults.maxPhysicalBytes(),
                defaults.maxCompressedBytes(), 1024, 1024, defaults.maxCompressionRatio(),
                defaults.maxArchiveEntries(), defaults.maxArchiveNesting(),
                defaults.maxClassEntries(), defaults.maxRuleInputBytes(), defaults.maxRuleCodePoints(),
                defaults.maxRuleAliases(), defaults.maxRuleNestingDepth(), defaults.maxRuleDocuments(),
                defaults.maxRuleCount(), defaults.maxRuleCollectionItems(), defaults.maxRuleNodes(),
                defaults.maxRuleScalarChars(), defaults.maxPathChars(), defaults.maxParseMillis());
        InputBudget.Tracker tracker = budget.tracker();
        assertTrue(PerformanceCommand.readBoundedTextForContract(first, budget, tracker)
                .startsWith("a"));
        IOException failure = assertThrows(IOException.class,
                () -> PerformanceCommand.readBoundedTextForContract(second, budget, tracker));
        assertTrue(failure.getMessage().contains("PERFORMANCE_METADATA_INPUT_LIMIT"),
                failure.getMessage());
    }
}
