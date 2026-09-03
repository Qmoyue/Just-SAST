package io.just.sast.verify;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Capability contracts for the lightweight Job Object boundary. */
class OsIsolationTest {

    @Test
    void incompleteProcessResourceBackendIsNotProductionReady() {
        OsIsolation.Backend incomplete = backend(OsIsolation.Level.PROCESS_RESOURCE, Set.of());
        assertFalse(incomplete.productionReady());
    }

    @Test
    void requiredJobObjectCapabilitiesAreProductionReady() {
        OsIsolation.Backend complete = backend(OsIsolation.Level.PROCESS_RESOURCE, Set.of(
                "runner_attestation", "process_tree", "resource_limits", "scratch_write",
                "cpu_time_limit", "memory_limit", "active_process_limit", "kill_on_close",
                "wall_timeout"));
        assertTrue(complete.productionReady());
    }

    @Test
    void attestationVersionAndPolicyDigestAreStable() {
        OsIsolation.Backend first = backend(OsIsolation.Level.PROCESS_RESOURCE, Set.of(
                "runner_attestation", "process_tree", "resource_limits", "scratch_write",
                "cpu_time_limit", "memory_limit", "active_process_limit", "kill_on_close",
                "wall_timeout"));
        OsIsolation.Backend second = backend(OsIsolation.Level.PROCESS_RESOURCE, Set.of(
                "wall_timeout", "kill_on_close", "active_process_limit", "memory_limit",
                "cpu_time_limit", "scratch_write", "resource_limits", "process_tree",
                "runner_attestation"));
        assertEquals(OsIsolation.ATTESTATION_VERSION, first.attestationVersion());
        assertEquals(first.policyDigest(), second.policyDigest());
        assertNotEquals("", first.policyDigest());
    }

    @Test
    void unavailableResourceQueriesRemainUnknown() {
        OsIsolation.ResourceMetrics metrics = OsIsolation.ResourceMetrics.unknown();

        assertEquals(-1L, metrics.peakRssMb());
        assertEquals(-1L, metrics.peakJobMemoryMb());
        assertEquals(-1L, metrics.userCpuMs());
        assertEquals(-1L, metrics.totalProcesses());
        assertEquals(-1L, metrics.activeProcesses());
    }

    @Test
    void nonWindowsSelectionIsExplicitlyUnavailable() {
        if (System.getProperty("os.name", "").toLowerCase().contains("win")) {
            return;
        }
        OsIsolation.Backend selected = OsIsolation.select(Path.of("target.jar"));
        assertFalse(selected.available());
        assertEquals(OsIsolation.Level.NONE, selected.level());
        assertTrue(selected.reason().contains("linux")
                || selected.reason().contains("unsupported"));
    }

    private static OsIsolation.Backend backend(OsIsolation.Level level, Set<String> capabilities) {
        return new OsIsolation.Backend() {
            @Override
            public String id() {
                return "test-backend";
            }

            @Override
            public boolean available() {
                return true;
            }

            @Override
            public String reason() {
                return "test";
            }

            @Override
            public List<String> command(List<String> childCommand, Path scratchDirectory) {
                return childCommand == null ? List.of() : List.copyOf(childCommand);
            }

            @Override
            public OsIsolation.Session attach(Process process) throws IOException {
                throw new IOException("not used");
            }

            @Override
            public OsIsolation.Level level() {
                return level;
            }

            @Override
            public Set<String> capabilities() {
                return capabilities;
            }
        };
    }
}
