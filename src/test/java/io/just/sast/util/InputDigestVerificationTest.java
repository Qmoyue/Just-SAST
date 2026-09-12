package io.just.sast.util;

import io.just.sast.run.InputBudget;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class InputDigestVerificationTest {

    @Test
    void unchangedInputsMatchWithSharedTracker(@TempDir Path temp) throws Exception {
        Path target = temp.resolve("target.jar");
        Path dependency = temp.resolve("dependency.jar");
        Files.write(target, new byte[] {1, 2, 3});
        Files.write(dependency, new byte[] {4, 5});
        InputBudget budget = InputBudget.defaults();
        InputBudget.Tracker tracker = budget.tracker();
        String beforeTarget = ArtifactFingerprint.sha256(target, tracker);
        String beforeDependency = ArtifactFingerprint.sha256(dependency, tracker);

        InputDigestVerification result = InputDigestVerification.verify(target,
                List.of(dependency), beforeTarget, List.of(beforeDependency), tracker);

        assertEquals("MATCH", result.status());
        assertTrue(result.reasons().isEmpty());
        assertEquals(beforeTarget, result.targetAfter());
        assertEquals(List.of(beforeDependency), result.dependencyAfter());
    }

    @Test
    void changedInputIsNotReportedAsStable(@TempDir Path temp) throws Exception {
        Path target = temp.resolve("target.jar");
        Files.write(target, new byte[] {1, 2, 3});
        String before = ArtifactFingerprint.sha256(target);
        Files.write(target, new byte[] {9, 8, 7});

        InputDigestVerification result = InputDigestVerification.verify(target, List.of(), before,
                List.of(), InputBudget.defaults().tracker());

        assertEquals("CHANGED", result.status());
        assertTrue(result.reasons().contains("INPUT_DIGEST_CHANGED:TARGET"), result.reasons().toString());
    }

    @Test
    void exhaustedSharedTrackerIsVisibleAsUnavailable(@TempDir Path temp) throws Exception {
        Path target = temp.resolve("target.jar");
        Files.write(target, new byte[64]);
        String before = ArtifactFingerprint.sha256(target);
        InputBudget budget = InputBudget.defaults().withArchiveLimits(
                1024 * 1024, 1024 * 1024, 1, 128, 32, 1, 32);

        InputDigestVerification result = InputDigestVerification.verify(target, List.of(), before,
                List.of(), budget.tracker());

        assertEquals("UNAVAILABLE", result.status());
        assertTrue(result.reasons().stream().anyMatch(reason -> reason.startsWith("INPUT_DIGEST_AFTER_UNAVAILABLE")),
                result.reasons().toString());
    }
}
