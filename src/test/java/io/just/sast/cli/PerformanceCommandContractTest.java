package io.just.sast.cli;

import io.just.sast.run.InputBudget;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Contract tests for performance-runner output cleanup boundaries. */
class PerformanceCommandContractTest {

    @Test
    void generatedReportPolicyKeepsAggregateReadWithinTheScanBudget() {
        InputBudget defaults = InputBudget.defaults();
        InputBudget output = PerformanceCommand.outputInputPolicyForContract();

        assertTrue(output.maxEntryBytes() > defaults.maxEntryBytes());
        assertTrue(output.maxEntryBytes() <= defaults.maxUncompressedBytes());
        assertEquals(defaults.maxUncompressedBytes(), output.maxUncompressedBytes());
    }

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

    @Test
    void requiredColdMetadataCannotSilentlyTurnIntoZero() {
        String valid = "{\"phase_ms\":{\"static\":11,\"filter\":3},"
                + "\"heap_used_mb\":4,\"heap_peak_mb\":5,\"chains_found\":2,"
                + "\"completeness\":\"COMPLETE\"}";
        assertDoesNotThrow(() -> PerformanceCommand.validateMetadataForContract(valid));

        String missingStatic = "{\"phase_ms\":{\"filter\":3},"
                + "\"heap_used_mb\":4,\"heap_peak_mb\":5,\"chains_found\":2,"
                + "\"completeness\":\"COMPLETE\"}";
        IOException failure = assertThrows(IOException.class,
                () -> PerformanceCommand.validateMetadataForContract(missingStatic));
        assertTrue(failure.getMessage().contains("PERFORMANCE_METADATA_MISSING:phase_ms.static"),
                failure.getMessage());
    }
}
