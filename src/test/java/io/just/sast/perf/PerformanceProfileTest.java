package io.just.sast.perf;

import io.just.sast.run.InputBudget;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PerformanceProfileTest {

    @Test
    void readsNumericLimitsAndLeavesMissingDimensionsDisabled(@TempDir Path temp) throws Exception {
        Path profile = temp.resolve("fixed-runner.properties");
        Files.writeString(profile, "wall_p50_ms=50000\nwall_p95_ms=55000\n"
                + "static_p50_ms=45000\nstatic_p95_ms=50000\n");

        PerformanceProfile.Limits limits = PerformanceProfile.read(profile);

        assertEquals(50_000L, limits.wallP50Ms());
        assertEquals(55_000L, limits.wallP95Ms());
        assertEquals(45_000L, limits.staticP50Ms());
        assertEquals(50_000L, limits.staticP95Ms());
        assertEquals(0L, limits.filterP50Ms());
        assertEquals(0L, limits.filterP95Ms());
    }

    @Test
    void rejectsUnknownOrDisabledProfiles(@TempDir Path temp) throws Exception {
        Path unknown = temp.resolve("unknown.properties");
        Files.writeString(unknown, "wall_p50_ms=1\nwall_typo_ms=2\n");
        assertThrows(Exception.class, () -> PerformanceProfile.read(unknown));

        Path disabled = temp.resolve("disabled.properties");
        Files.writeString(disabled, "wall_p50_ms=0\nwall_p95_ms=0\n");
        assertThrows(Exception.class, () -> PerformanceProfile.read(disabled));
    }

    @Test
    void rejectsNegativeAndLinkedProfiles(@TempDir Path temp) throws Exception {
        Path negative = temp.resolve("negative.properties");
        Files.writeString(negative, "wall_p50_ms=-1\n");
        assertThrows(Exception.class, () -> PerformanceProfile.read(negative));

        Path target = temp.resolve("target.properties");
        Files.writeString(target, "wall_p50_ms=1\n");
        Path link = temp.resolve("link.properties");
        try {
            Files.createSymbolicLink(link, target);
            assertThrows(Exception.class, () -> PerformanceProfile.read(link));
        } catch (UnsupportedOperationException | java.nio.file.FileSystemException ignored) {
            // Link creation is an environment capability; the regular-file cases still run.
        }
    }

    @Test
    void explicitInputBudgetBoundsProfileBytes(@TempDir Path temp) throws Exception {
        Path profile = temp.resolve("bounded.properties");
        Files.writeString(profile, "wall_p50_ms=1\n");
        InputBudget budget = InputBudget.defaults().withArchiveLimits(
                1024, 1024, 1024, 4, 32, 1, 32);
        assertThrows(Exception.class, () -> PerformanceProfile.read(profile, budget));
        assertEquals(1L, PerformanceProfile.read(profile,
                InputBudget.defaults()).wallP50Ms());
    }

    @Test
    void replacedProfileIdentityFailsClosed(@TempDir Path temp) throws Exception {
        Path profile = temp.resolve("replace.properties");
        Files.writeString(profile, "wall_p50_ms=1\n");
        var snapshot = PerformanceProfile.snapshotForContract(profile);
        var before = Files.readAttributes(profile,
                java.nio.file.attribute.BasicFileAttributes.class,
                java.nio.file.LinkOption.NOFOLLOW_LINKS);
        org.junit.jupiter.api.Assumptions.assumeTrue(
                before.fileKey() != null,
                "provider does not expose a stable file identity; creation time alone is not enough");
        Files.delete(profile);
        Files.writeString(profile, "wall_p50_ms=1\n");
        IOException failure = assertThrows(IOException.class,
                () -> PerformanceProfile.verifySnapshotForContract(snapshot));
        assertTrue(failure.getMessage().contains("PERFORMANCE_PROFILE_CHANGED_DURING_READ"),
                failure.getMessage());
    }

    @Test
    void replacedProfileParentIdentityFailsClosed(@TempDir Path temp) throws Exception {
        Path parent = Files.createDirectories(temp.resolve("parent"));
        Path profile = parent.resolve("profile.properties");
        Files.writeString(profile, "wall_p50_ms=1\n");
        var snapshot = PerformanceProfile.snapshotForContract(profile);
        var before = Files.readAttributes(parent,
                java.nio.file.attribute.BasicFileAttributes.class,
                java.nio.file.LinkOption.NOFOLLOW_LINKS);
        org.junit.jupiter.api.Assumptions.assumeTrue(
                before.fileKey() != null,
                "provider does not expose a stable directory identity; creation time alone is not enough");
        Files.delete(profile);
        Files.delete(parent);
        Files.createDirectory(parent);
        Files.writeString(profile, "wall_p50_ms=1\n");
        IOException failure = assertThrows(IOException.class,
                () -> PerformanceProfile.verifySnapshotForContract(snapshot));
        assertTrue(failure.getMessage().contains("PERFORMANCE_PROFILE_CHANGED_DURING_READ"),
                failure.getMessage());
    }
}
