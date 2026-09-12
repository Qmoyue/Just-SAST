package io.just.sast.report;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 单文件输出边界：失败提交不得留下可被误认的临时/半成品。 */
class AtomicFilesTest {

    @Test
    void failedCommitDoesNotPublishOrLeaveTemporaryFile(@TempDir Path tmp) throws Exception {
        Path target = tmp.resolve("findings.json");
        Files.createDirectory(target);

        assertThrows(IOException.class, () -> AtomicFiles.writeUtf8(target, "{\"partial\":true}"));
        try (var files = Files.list(tmp)) {
            assertTrue(files.noneMatch(path -> path.getFileName().toString()
                    .startsWith(".findings.json.tmp-")),
                    "失败 writer 必须清理 temp sibling");
        }
        assertTrue(Files.isDirectory(target), "失败提交不得覆盖已有目标");
    }

    @Test
    void commitParentReplacementFailsClosedBeforeMove(@TempDir Path tmp) throws Exception {
        Path parent = tmp.resolve("out");
        Files.createDirectory(parent);
        Path temp = parent.resolve(".findings.json.tmp-contract");
        Path target = parent.resolve("findings.json");
        Files.writeString(temp, "{\"staged\":true}");

        IOException failure = assertThrows(IOException.class,
                () -> AtomicFiles.commitForContract(temp, target, () -> {
                    Files.delete(temp);
                    Files.delete(parent);
                    Files.writeString(parent, "replacement");
                }));

        assertTrue(failure.getMessage() != null
                        && failure.getMessage().startsWith("REPORT_OUTPUT_PARENT_CHANGED"),
                "parent replacement must have a stable fail-closed reason: " + failure);
        assertTrue(Files.isRegularFile(parent), "hostile replacement must remain observable");
        assertTrue(!Files.exists(target), "commit must not publish through a replaced parent");
    }

    @Test
    void existingTargetReplacementAfterStagingFailsClosed(@TempDir Path tmp) throws Exception {
        Path parent = tmp.resolve("out");
        Files.createDirectory(parent);
        Path temp = parent.resolve(".findings.json.tmp-existing-target");
        Path target = parent.resolve("findings.json");
        Files.writeString(temp, "{\"staged\":true}");
        Files.writeString(target, "old-target");

        IOException failure = assertThrows(IOException.class,
                () -> AtomicFiles.commitForContract(temp, target, () -> {
                    Files.delete(target);
                    Files.writeString(target, "concurrent-target");
                }));

        assertTrue(failure.getMessage() != null
                        && failure.getMessage().startsWith("REPORT_OUTPUT_TARGET_CHANGED"),
                "a replaced existing target must fail closed: " + failure);
        assertTrue(Files.isRegularFile(target), "the concurrent target must remain observable");
        assertTrue(Files.readString(target).equals("concurrent-target"),
                "the concurrent target must not be overwritten");
        assertTrue(!Files.exists(temp), "a safe failed commit should clean its temp sibling");
    }

    @Test
    void targetAppearingAfterStagingFailsClosed(@TempDir Path tmp) throws Exception {
        Path parent = tmp.resolve("out");
        Files.createDirectory(parent);
        Path temp = parent.resolve(".findings.json.tmp-absent-target");
        Path target = parent.resolve("findings.json");
        Files.writeString(temp, "{\"staged\":true}");

        IOException failure = assertThrows(IOException.class,
                () -> AtomicFiles.commitForContract(temp, target, () ->
                        Files.writeString(target, "concurrent-target")));

        assertTrue(failure.getMessage() != null
                        && failure.getMessage().startsWith("REPORT_OUTPUT_TARGET_CHANGED"),
                "a newly-created target must fail closed: " + failure);
        assertTrue(Files.readString(target).equals("concurrent-target"),
                "the concurrent target must not be overwritten");
        assertTrue(!Files.exists(temp), "a safe failed commit should clean its temp sibling");
    }

}
