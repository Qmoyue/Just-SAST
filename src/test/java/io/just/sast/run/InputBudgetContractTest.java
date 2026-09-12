package io.just.sast.run;

import io.just.sast.util.ArchiveLimits;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.ByteArrayInputStream;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.zip.ZipEntry;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Contract tests for the versioned, immutable input-budget policy and shared tracker. */
class InputBudgetContractTest {

    @Test
    void defaultsAreVersionedAndArchiveCompatibilityAliasesHaveOneOwner() {
        InputBudget budget = InputBudget.defaults();
        assertEquals(InputBudget.SCHEMA_VERSION, budget.schemaVersion());
        assertEquals(budget.maxArchiveEntries(), ArchiveLimits.MAX_ENTRIES);
        assertEquals(budget.maxEntryBytes(), ArchiveLimits.MAX_ENTRY_UNCOMPRESSED_BYTES);
        assertEquals(budget.maxUncompressedBytes(), ArchiveLimits.MAX_TOTAL_UNCOMPRESSED_BYTES);
        assertEquals(budget.maxCompressedBytes(), ArchiveLimits.MAX_TOTAL_COMPRESSED_BYTES);
        assertTrue(budget.toCanonicalJson().startsWith("{\"schema_version\":\"JUST-INPUT-BUDGET-V1\""));
        assertTrue(budget.toCanonicalJson().contains("\"max_rule_input_bytes\":16777216"));
    }

    @Test
    void trackerAccountsDeclaredAndReadBytesAcrossOneExpansion() throws Exception {
        InputBudget budget = smallBudget(32, 128, 8);
        InputBudget.Tracker tracker = budget.tracker();
        ZipEntry first = new ZipEntry("one.class");
        first.setCompressedSize(4);
        first.setSize(12);
        tracker.observe(first);
        tracker.recordRead(12);
        tracker.recordContainerRead(3);

        assertEquals(1, tracker.entries());
        assertEquals(4, tracker.compressedBytes());
        assertEquals(12, tracker.declaredUncompressedBytes());
        assertEquals(15, tracker.result().consumed());
        assertEquals(InputBudgetResult.State.WITHIN_LIMIT, tracker.result().state());
        assertEquals(17, tracker.remainingReadBytes());
    }

    @Test
    void trackerRejectsNestedTotalAndPerEntryLimitsWithoutReset() throws Exception {
        InputBudget budget = smallBudget(16, 16, 2);
        InputBudget.Tracker tracker = budget.tracker();
        ZipEntry oversized = new ZipEntry("oversized.class");
        oversized.setSize(17);
        assertThrows(IOException.class, () -> tracker.observe(oversized));

        ZipEntry first = new ZipEntry("first.class");
        first.setSize(8);
        tracker.observe(first);
        tracker.recordRead(8);
        assertThrows(IOException.class, () -> tracker.recordContainerRead(9));
        assertEquals(8, tracker.readUncompressedBytes());
        assertEquals(8, tracker.remainingReadBytes());
    }

    @Test
    void trackerClampsReadRequestsToLocalAndAggregateRemainingBudget() throws Exception {
        InputBudget budget = smallBudget(5, 32, 8);
        InputBudget.Tracker tracker = budget.tracker();

        assertEquals(5, tracker.boundedReadSize(100, 8192));
        tracker.recordRead(4);
        assertEquals(1, tracker.boundedReadSize(100, 8192));
        assertEquals(0, tracker.boundedReadSize(0, 8192));
        tracker.recordRead(1);
        assertEquals(0, tracker.boundedReadSize(100, 8192));
    }

    @Test
    void parallelBoundedReadsCannotConsumeTheSameAggregateRemainder() throws Exception {
        InputBudget budget = smallBudget(4, 32, 8);
        InputBudget.Tracker tracker = budget.tracker();
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            Future<Integer> first = pool.submit(() -> {
                start.await();
                byte[] buffer = new byte[4];
                return tracker.readBounded(new ByteArrayInputStream(new byte[] {1, 2, 3, 4}),
                        buffer, 0, buffer.length, 4, "TEST_AGGREGATE_LIMIT");
            });
            Future<Integer> second = pool.submit(() -> {
                start.await();
                byte[] buffer = new byte[4];
                return tracker.readBounded(new ByteArrayInputStream(new byte[] {5, 6, 7, 8}),
                        buffer, 0, buffer.length, 4, "TEST_AGGREGATE_LIMIT");
            });
            start.countDown();
            int successes = 0;
            int failures = 0;
            for (Future<Integer> result : new Future[] {first, second}) {
                try {
                    if (result.get(5, TimeUnit.SECONDS) == 4) {
                        successes++;
                    }
                } catch (Exception expected) {
                    failures++;
                }
            }
            assertEquals(1, successes, "one reader owns the aggregate remainder");
            assertEquals(1, failures, "the second reader fails closed at the boundary");
            assertEquals(4, tracker.readUncompressedBytes(),
                    "physical bounded reads and accounting must agree");
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    void invalidSchemaAndNonPositiveLimitsFailClosed() {
        InputBudget d = InputBudget.defaults();
        assertThrows(IllegalArgumentException.class, () -> new InputBudget(
                "future", d.maxPhysicalBytes(), d.maxCompressedBytes(), d.maxUncompressedBytes(),
                d.maxEntryBytes(), d.maxCompressionRatio(), d.maxArchiveEntries(),
                d.maxArchiveNesting(), d.maxClassEntries(), d.maxRuleInputBytes(),
                d.maxRuleCodePoints(), d.maxRuleAliases(), d.maxRuleNestingDepth(),
                d.maxRuleDocuments(), d.maxRuleCount(), d.maxRuleCollectionItems(),
                d.maxRuleNodes(), d.maxRuleScalarChars(), d.maxPathChars(), d.maxParseMillis()));
        assertThrows(IllegalArgumentException.class, () -> new InputBudget(
                d.schemaVersion(), 0, d.maxCompressedBytes(), d.maxUncompressedBytes(),
                d.maxEntryBytes(), d.maxCompressionRatio(), d.maxArchiveEntries(),
                d.maxArchiveNesting(), d.maxClassEntries(), d.maxRuleInputBytes(),
                d.maxRuleCodePoints(), d.maxRuleAliases(), d.maxRuleNestingDepth(),
                d.maxRuleDocuments(), d.maxRuleCount(), d.maxRuleCollectionItems(),
                d.maxRuleNodes(), d.maxRuleScalarChars(), d.maxPathChars(), d.maxParseMillis()));
    }

    @Test
    void archiveEntryPathLengthUsesTheVersionedBudget() {
        String longName = "a".repeat(InputBudget.defaults().maxPathChars() + 1) + ".class";
        assertFalse(ArchiveLimits.safeEntryName(longName),
                "path names over the shared limit must not reach archive resolution");
        assertFalse(ArchiveLimits.safeEntryName("safe/\0.class"),
                "NUL-containing names must not cross the archive/filesystem boundary");
    }

    @Test
    void trackerEnforcesAggregateRuleScalarCodePointLimit() throws Exception {
        InputBudget d = InputBudget.defaults();
        InputBudget budget = new InputBudget(d.schemaVersion(), d.maxPhysicalBytes(),
                d.maxCompressedBytes(), d.maxUncompressedBytes(), d.maxEntryBytes(),
                d.maxCompressionRatio(), d.maxArchiveEntries(), d.maxArchiveNesting(),
                d.maxClassEntries(), d.maxRuleInputBytes(), 3,
                d.maxRuleAliases(), d.maxRuleNestingDepth(), d.maxRuleDocuments(),
                d.maxRuleCount(), d.maxRuleCollectionItems(), d.maxRuleNodes(),
                d.maxRuleScalarChars(),
                d.maxPathChars(), d.maxParseMillis());
        InputBudget.Tracker tracker = budget.tracker();
        tracker.recordRuleScalarChars(2);
        IOException failure = assertThrows(IOException.class,
                () -> tracker.recordRuleScalarChars(2));
        assertTrue(failure.getMessage().startsWith("RULE_TOTAL_SCALAR_CHAR_LIMIT:"),
                failure.getMessage());
    }

    private static InputBudget smallBudget(long maxUncompressed, long maxEntry, int maxEntries) {
        InputBudget d = InputBudget.defaults();
        return new InputBudget(d.schemaVersion(), maxUncompressed, maxUncompressed,
                maxUncompressed, maxEntry, d.maxCompressionRatio(), maxEntries,
                d.maxArchiveNesting(), d.maxClassEntries(), d.maxRuleInputBytes(),
                d.maxRuleCodePoints(), d.maxRuleAliases(), d.maxRuleNestingDepth(),
                d.maxRuleDocuments(), d.maxRuleCount(), d.maxRuleCollectionItems(),
                d.maxRuleNodes(), d.maxRuleScalarChars(), d.maxPathChars(), d.maxParseMillis());
    }
}
