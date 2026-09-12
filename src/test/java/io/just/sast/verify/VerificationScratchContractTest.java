package io.just.sast.verify;

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

class VerificationScratchContractTest {

    @Test
    void componentCreationRejectsPreexistingFile(@TempDir Path temp) throws Exception {
        Path parent = Files.createDirectory(temp.resolve("parent"));
        Files.writeString(parent.resolve("tmp"), "not-a-directory");

        assertThrows(IOException.class,
                () -> VerificationScratch.createChild(parent, "tmp", InputBudget.defaults()));
    }

    @Test
    void treeMeasurementSharesEntryBudgetAndStopsBeforeUnboundedWalk(@TempDir Path temp)
            throws Exception {
        Path root = Files.createDirectory(temp.resolve("scratch"));
        Files.writeString(root.resolve("a"), "a");
        Files.writeString(root.resolve("b"), "b");
        InputBudget budget = InputBudget.defaults().withArchiveLimits(
                1024, 1024, 1024, 1024, 1, 1, 1);

        IOException failure = assertThrows(IOException.class,
                () -> VerificationScratch.measure(root, budget));
        assertTrue(failure.getMessage().contains("VERIFY_SCRATCH_ENTRY_LIMIT"),
                failure::getMessage);
    }

    @Test
    void treeMeasurementAccountsFilesAndDirectories(@TempDir Path temp) throws Exception {
        Path root = Files.createDirectory(temp.resolve("scratch"));
        Path child = Files.createDirectory(root.resolve("child"));
        Files.writeString(child.resolve("answer.txt"), "1234");

        VerificationScratch.TreeUsage usage = VerificationScratch.measure(root,
                InputBudget.defaults());
        assertEquals(3L, usage.entries());
        assertEquals(4L, usage.bytes());
        assertFalse(usage.limitExceeded());
    }

    @Test
    void treeMeasurementSharesCallerTotalAcrossIndependentRoots(@TempDir Path temp)
            throws Exception {
        Path first = Files.createDirectory(temp.resolve("first"));
        Files.createDirectory(first.resolve("nested"));
        Files.writeString(first.resolve("nested").resolve("a"), "a");
        Path second = Files.createDirectory(temp.resolve("second"));
        Files.createDirectory(second.resolve("nested"));
        Files.writeString(second.resolve("nested").resolve("b"), "b");
        InputBudget defaults = InputBudget.defaults();
        InputBudget budget = defaults.withArchiveLimits(defaults.maxPhysicalBytes(),
                defaults.maxCompressedBytes(), defaults.maxUncompressedBytes(),
                defaults.maxEntryBytes(), 3, defaults.maxArchiveNesting(),
                defaults.maxClassEntries());
        InputBudget.Tracker tracker = budget.tracker();
        VerificationScratch.measure(first, budget, tracker);
        IOException failure = assertThrows(IOException.class,
                () -> VerificationScratch.measure(second, budget, tracker));
        assertTrue(failure.getMessage().contains("VERIFY_SCRATCH_ENTRY_LIMIT"),
                failure::getMessage);
    }

    @Test
    void replacedScratchParentIdentityFailsClosed(@TempDir Path temp) throws Exception {
        Path parent = Files.createDirectory(temp.resolve("parent"));
        Path root = Files.createDirectory(parent.resolve("scratch"));
        var snapshot = VerificationScratch.snapshotRootForContract(root);
        var before = Files.readAttributes(parent,
                java.nio.file.attribute.BasicFileAttributes.class,
                java.nio.file.LinkOption.NOFOLLOW_LINKS);
        org.junit.jupiter.api.Assumptions.assumeTrue(
                before.fileKey() != null || before.creationTime().toMillis() != 0L,
                "provider does not expose a stable directory identity");
        assertTrue(VerificationScratch.deleteTree(root));
        Files.delete(parent);
        Files.createDirectory(parent);
        Files.createDirectory(root);
        IOException failure = assertThrows(IOException.class,
                () -> VerificationScratch.verifyRootSnapshotForContract(snapshot));
        assertTrue(failure.getMessage().contains("VERIFY_SCRATCH_ROOT_CHANGED_DURING_READ"),
                failure.getMessage());
    }

    @Test
    void replacedScratchFileEntryFailsClosed(@TempDir Path temp) throws Exception {
        Path file = temp.resolve("result.bin");
        Files.write(file, new byte[] {1, 2, 3});
        VerificationScratch.EntrySnapshot snapshot =
                VerificationScratch.snapshotEntryForContract(file);
        Files.write(file, new byte[] {1, 2, 3, 4, 5});

        IOException failure = assertThrows(IOException.class,
                () -> VerificationScratch.verifyEntryForContract(snapshot));
        assertTrue(failure.getMessage().contains("VERIFY_SCRATCH_ENTRY_CHANGED_DURING_READ"),
                failure::getMessage);
    }

    @Test
    void directoryEntryIdentityIgnoresExpectedChildMtimeMutation(@TempDir Path temp)
            throws Exception {
        Path directory = Files.createDirectory(temp.resolve("scratch"));
        VerificationScratch.EntrySnapshot snapshot =
                VerificationScratch.snapshotEntryForContract(directory);
        Files.createDirectory(directory.resolve("child"));

        assertDoesNotThrow(() -> VerificationScratch.verifyEntryForContract(snapshot));
    }
}
