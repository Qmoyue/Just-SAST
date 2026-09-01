package io.just.sast.verify;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Capability-level contract tests; they do not require a privileged host runner. */
class OsIsolationTest {

    @TempDir
    Path temp;

    @Test
    void strictLevelWithoutProofCapabilitiesIsNotProductionReady() {
        OsIsolation.Backend incomplete = backend(OsIsolation.Level.OS_STRICT, Set.of());
        assertFalse(incomplete.productionReady());
    }

    @Test
    void strictLevelRequiresAllPlatformNeutralProofLayers() {
        OsIsolation.Backend complete = backend(OsIsolation.Level.OS_STRICT, Set.of(
                "runner_attestation", "process_tree", "resource_limits",
                "filesystem_policy", "network_policy"));
        assertTrue(complete.productionReady());
    }

    @Test
    void weakerLevelsNeverBecomeProductionReadyByCapabilityNames() {
        OsIsolation.Backend namespace = backend(OsIsolation.Level.OS_NAMESPACE, Set.of(
                "runner_attestation", "process_tree", "resource_limits",
                "filesystem_policy", "network_policy"));
        assertFalse(namespace.productionReady());
    }

    @Test
    void defaultAttestationVersionIsStableAndIncludedInPolicyIdentity() {
        OsIsolation.Backend backend = backend(OsIsolation.Level.OS_NAMESPACE, Set.of());
        OsIsolation.Backend otherVersion = new OsIsolation.Backend() {
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
                return OsIsolation.Level.OS_NAMESPACE;
            }

            @Override
            public Set<String> capabilities() {
                return Set.of();
            }

            @Override
            public String attestationVersion() {
                return "JUST_OS_ATTESTATION_TEST";
            }
        };

        assertEquals(OsIsolation.ATTESTATION_VERSION, backend.attestationVersion());
        assertTrue(!backend.policyDigest().isBlank());
        assertTrue(!backend.policyDigest().equals(otherVersion.policyDigest()));
    }

    @Test
    void preparedRootDigestIsPathIndependentAndChangesWithContent() throws Exception {
        Path first = temp.resolve("first");
        Path second = temp.resolve("second");
        Files.createDirectories(first.resolve("lib"));
        Files.createDirectories(second.resolve("lib"));
        Files.writeString(first.resolve("lib/runtime.txt"), "stable\n", StandardCharsets.UTF_8);
        Files.writeString(second.resolve("lib/runtime.txt"), "stable\n", StandardCharsets.UTF_8);

        String firstDigest = OsIsolation.preparedRootDigest(first);
        assertEquals(firstDigest, OsIsolation.preparedRootDigest(second));

        Files.writeString(second.resolve("lib/runtime.txt"), "changed\n", StandardCharsets.UTF_8);
        assertFalse(firstDigest.equals(OsIsolation.preparedRootDigest(second)));
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
