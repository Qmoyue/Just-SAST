package io.just.sast.report;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Run-level report contract: only a complete staging tree may become visible. */
class ReportTransactionContractTest {

    @Test
    void recoveryReconcilesFailedAndCompleteStagingWithoutPublishing(@TempDir Path tmp)
            throws Exception {
        Path failedOutput = tmp.resolve("failed-report");
        Path failedStaging;
        try (ReportTransaction transaction = ReportTransaction.begin(failedOutput, false)) {
            failedStaging = transaction.stagingRoot();
        }
        ReportTransaction.RecoveryReport failed =
                ReportTransaction.reconcileRecovery(failedOutput);
        assertTrue(failed.entries().stream().anyMatch(entry ->
                        entry.path().equals(failedStaging)
                                && entry.status() == ReportTransaction.RecoveryStatus.FAILED_STAGING),
                failed.toString());
        assertFalse(Files.exists(failedOutput, java.nio.file.LinkOption.NOFOLLOW_LINKS),
                "failed staging must never be published by reconciliation");

        Path completeOutput = tmp.resolve("complete-report");
        Path completeStaging;
        try (ReportTransaction transaction = ReportTransaction.begin(completeOutput, false)) {
            completeStaging = transaction.stagingRoot();
            AtomicFiles.writeUtf8(transaction.layout().evidence().resolve("marker.txt"), "staged");
        }
        AtomicFiles.writeUtf8(completeStaging.resolve("meta/transaction.json"),
                "{\"schema_version\":\"just-run-v1\",\"run_id\":\"crash\","
                        + "\"state\":\"COMPLETE\"}\n");
        ReportTransaction.RecoveryReport complete =
                ReportTransaction.reconcileRecovery(completeOutput);
        assertTrue(complete.entries().stream().anyMatch(entry ->
                        entry.path().equals(completeStaging)
                                && entry.status() == ReportTransaction.RecoveryStatus.COMPLETE_STAGING),
                complete.toString());
        assertFalse(Files.exists(completeOutput, java.nio.file.LinkOption.NOFOLLOW_LINKS),
                "reconciliation is read-only and must not publish an orphan automatically");
    }

    @Test
    void recoveryProjectsClosedNonMutatingActions(@TempDir Path tmp) throws Exception {
        Path failedOutput = tmp.resolve("failed-policy");
        Path failedStaging;
        try (ReportTransaction transaction = ReportTransaction.begin(failedOutput, false)) {
            failedStaging = transaction.stagingRoot();
        }
        ReportTransaction.RecoveryReport failed =
                ReportTransaction.reconcileRecovery(failedOutput);
        ReportTransaction.RecoveryDecision failedDecision = failed.decisions().stream()
                .filter(decision -> decision.path().equals(failedStaging))
                .findFirst().orElseThrow();
        assertEquals(ReportTransaction.RecoveryAction.RETAIN_FOR_AUDIT,
                failedDecision.action());
        assertFalse(failedDecision.action().mayMutate(),
                "failed recovery must not authorize automatic mutation");

        Path completeOutput = tmp.resolve("complete-policy");
        Path completeStaging;
        try (ReportTransaction transaction = ReportTransaction.begin(completeOutput, false)) {
            completeStaging = transaction.stagingRoot();
            AtomicFiles.writeUtf8(transaction.layout().evidence().resolve("marker.txt"), "staged");
        }
        AtomicFiles.writeUtf8(completeStaging.resolve("meta/transaction.json"),
                "{\"schema_version\":\"just-run-v1\",\"run_id\":\"crash\","
                        + "\"state\":\"COMPLETE\"}\n");
        ReportTransaction.RecoveryReport complete =
                ReportTransaction.reconcileRecovery(completeOutput);
        ReportTransaction.RecoveryDecision completeDecision = complete.decisions().stream()
                .filter(decision -> decision.path().equals(completeStaging))
                .findFirst().orElseThrow();
        assertEquals(ReportTransaction.RecoveryAction.MANUAL_REVIEW_REQUIRED,
                completeDecision.action());
        assertFalse(completeDecision.action().mayMutate(),
                "complete orphan must require an explicit operator action");
        assertEquals("REPORT_RECOVERY_COMPLETE_STAGING_NOT_AUTO_PUBLISHED",
                completeDecision.reasonCode());
        assertFalse(Files.exists(completeOutput, java.nio.file.LinkOption.NOFOLLOW_LINKS));
    }

    @Test
    void successfulCommitPublishesCompleteStateAndAllFiles(@TempDir Path tmp) throws Exception {
        Path output = tmp.resolve("report");
        try (ReportTransaction transaction = ReportTransaction.begin(output, false)) {
            assertEquals("WRITING", Files.readString(transaction.runStateFile()).trim()
                    .replaceAll(".*\"state\"\\s*:\\s*\"([^\"]+)\".*", "$1"));
            AtomicFiles.writeUtf8(transaction.layout().evidence().resolve("marker.txt"), "new");
            transaction.commit();
        }

        assertTrue(Files.isDirectory(output));
        assertEquals("new", Files.readString(output.resolve("evidence/marker.txt")));
        String state = Files.readString(output.resolve("meta/transaction.json"));
        assertTrue(state.contains("\"state\":\"COMPLETE\""), state);
        assertFalse(Files.exists(output.resolve("run.json")),
                "transaction state is metadata, not a third report entry");
        assertFalse(hasSiblingWithPrefix(tmp, ".report.staging-"),
                "成功 commit 后不能残留 staging 目录");
    }

    @Test
    void failedReportDoesNotPublishOutputAndLeavesFailedRecoveryState(@TempDir Path tmp)
            throws Exception {
        Path output = tmp.resolve("report");
        Path failedStaging;
        try (ReportTransaction transaction = ReportTransaction.begin(output, false)) {
            failedStaging = transaction.stagingRoot();
            Files.createDirectory(transaction.layout().evidence().resolve("collision"));
            assertThrows(IOException.class, () -> AtomicFiles.writeUtf8(
                    transaction.layout().evidence().resolve("collision"), "partial"));
        }

        assertFalse(Files.exists(output), "报告写失败不得发布 output 根目录");
        assertTrue(Files.isDirectory(failedStaging), "失败 staging 必须可供恢复审计");
        assertTrue(Files.readString(failedStaging.resolve("meta/transaction.json"))
                .contains("\"state\":\"FAILED\""));
    }

    @Test
    void existingOutputRequiresExplicitOverwriteAndRemainsUntouched(@TempDir Path tmp)
            throws Exception {
        Path output = Files.createDirectory(tmp.resolve("report"));
        Files.writeString(output.resolve("old.txt"), "old");

        assertThrows(ReportTransaction.OutputExistsException.class,
                () -> ReportTransaction.begin(output, false));
        assertEquals("old", Files.readString(output.resolve("old.txt")));
        assertFalse(hasSiblingWithPrefix(tmp, ".report.staging-"));
    }

    @Test
    void explicitOverwriteSwapsWholeTreeWithoutMixingVersions(@TempDir Path tmp) throws Exception {
        Path output = Files.createDirectory(tmp.resolve("report"));
        Files.writeString(output.resolve("old.txt"), "old");

        try (ReportTransaction transaction = ReportTransaction.begin(output, true)) {
            AtomicFiles.writeUtf8(transaction.layout().evidence().resolve("new.txt"), "new");
            transaction.commit();
        }

        assertFalse(Files.exists(output.resolve("old.txt")), "旧版本文件不得混入新报告");
        assertEquals("new", Files.readString(output.resolve("evidence/new.txt")));
        assertTrue(Files.readString(output.resolve("meta/transaction.json"))
                .contains("\"state\":\"COMPLETE\""));
    }

    @Test
    void concurrentCommitCannotReplaceFirstCompleteRun(@TempDir Path tmp) throws Exception {
        Path output = tmp.resolve("report");
        try (ReportTransaction first = ReportTransaction.begin(output, false);
             ReportTransaction second = ReportTransaction.begin(output, false)) {
            AtomicFiles.writeUtf8(first.layout().evidence().resolve("winner.txt"), "first");
            first.commit();
            AtomicFiles.writeUtf8(second.layout().evidence().resolve("loser.txt"), "second");
            assertThrows(IOException.class, second::commit);
        }

        assertEquals("first", Files.readString(output.resolve("evidence/winner.txt")));
        assertFalse(Files.exists(output.resolve("evidence/loser.txt")));
    }

    private static boolean hasSiblingWithPrefix(Path parent, String prefix) throws IOException {
        try (var children = Files.list(parent)) {
            return children.anyMatch(path -> path.getFileName().toString().startsWith(prefix));
        }
    }
}
