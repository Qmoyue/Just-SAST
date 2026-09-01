package io.just.sast.perf;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

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
        assertEquals(0L, limits.dynamicP50Ms());
        assertEquals(0L, limits.dynamicP95Ms());
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
}
