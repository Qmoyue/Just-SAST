package io.just.sast.verify;

import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.HopKind;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Opt-in Windows integration contract for the real child runner. It is kept out of the normal
 * fast suite because it starts a separate JVM and is enabled with
 * {@code -Djust.run.os-contract-tests=true} after packaging the release JAR.
 */
class WindowsRealVerificationContractTest {

    @Test
    void safeApplicationBodyRunsWithTheJobObjectBoundary(@TempDir Path temp) throws Exception {
        requireWindowsJobOptIn();
        Path target = fixtureJar(temp, "fixture/RealSinkFixture.class");
        Chain chain = applicationChain("contract-light-real-body");

        ParallelVerifier verifier = realVerifier(target, false);
        try {
            ParallelVerifier.VerifyResult result = verifier.verifyAll(List.of(chain)).get(0);
            assertEquals("SINK_EXECUTED_SAFE", result.status(), result::toString);
            assertTrue(result.sandboxReady(), result::toString);
            assertTrue(result.sinkDistorted(), result::toString);
            assertTrue(result.terminalExecuted(), result::toString);
            assertEquals("TERMINAL_EXECUTED_SAFE", result.verificationScope(), result::toString);
            assertEquals("CONTROLLED_EFFECT", result.sinkRisk(), result::toString);
            assertEquals("WINDOWS_JOB_OBJECT_JVM_POLICY", result.backend(), result::toString);
            assertEquals("LIGHT_SAFE_CALL", result.effectiveMode(), result::toString);
            assertTrue(result.detail().contains("body=1"), result::toString);
            assertTrue(result.detail().contains("loaded=1"), result::toString);
            assertTrue(result.detail().contains("arguments=1"), result::toString);
            assertTrue(result.detail().contains("nested_blocked=1"), result::toString);
            assertEquals(1L, verifier.resourceMetrics().get("cleanup_successes"));
            assertEquals(0L, verifier.resourceMetrics().get("cleanup_failures"));
            assertTrue(verifier.resourceMetrics().getOrDefault("child_process_peak", 0L) >= 1L);
        } finally {
            verifier.cleanup();
        }
    }

    @Test
    void highRiskNativeSinkStopsAtTheAuthenticatedPrefix(@TempDir Path temp) throws Exception {
        requireWindowsJobOptIn();
        Path target = fixtureJar(temp, "fixture/NativeFixture.class");
        Chain chain = new Chain("contract-prefix-native", "NATIVE", "HIGH",
                "fixture/NativeFixture", "trigger", "direct",
                "java/lang/System", "loadLibrary",
                List.of(new ChainHop("fixture/NativeFixture", "trigger",
                                "java/lang/System", "loadLibrary", HopKind.DIRECT_CALL, null,
                                "contract", "(Ljava/lang/String;)V", null),
                        new ChainHop("fixture/NativeFixture", "trigger",
                                "fixture/NativeFixture", "trigger", HopKind.ENTRY, null,
                                "contract", "()I", null)), 0,
                "(Ljava/lang/String;)V");

        ParallelVerifier verifier = realVerifier(target, false);
        try {
            ParallelVerifier.VerifyResult result = verifier.verifyAll(List.of(chain)).get(0);
            assertEquals("PRE_SINK_CONFIRMED", result.status(), result::toString);
            assertTrue(result.sandboxReady(), result::toString);
            assertFalse(result.terminalExecuted(), result::toString);
            assertEquals("PREFIX_ONLY", result.verificationScope(), result::toString);
            assertEquals("HIGH_RISK_TERMINAL", result.sinkRisk(), result::toString);
            assertEquals("HIGH_RISK_SINK", result.stopReason(), result::toString);
            assertEquals("PRE_SINK", result.lastConfirmedStage(), result::toString);
            assertTrue(result.detail().contains("effective_mode=PREFIX_ONLY"), result::toString);
            assertFalse(result.detail().contains("native_load=1"), result::toString);
        } finally {
            verifier.cleanup();
        }
    }

    @Test
    void realCallTimeoutFallsBackOnlyToTheJobObjectBoundary(@TempDir Path temp)
            throws Exception {
        requireWindowsJobOptIn();
        Path target = fixtureJar(temp, "fixture/SlowRealSinkFixture.class");
        Chain chain = new Chain("contract-tier-timeout", "APPLICATION_BODY", "HIGH",
                "fixture/SlowRealSinkFixture", "sink", "source",
                "fixture/SlowRealSinkFixture", "sink",
                List.of(new ChainHop("fixture/SlowRealSinkFixture", "sink",
                        "fixture/SlowRealSinkFixture", "sink", HopKind.ENTRY, null,
                        "contract", "(Ljava/lang/String;I)Ljava/lang/String;", null)), 0,
                "(Ljava/lang/String;I)Ljava/lang/String;");

        ParallelVerifier verifier = realVerifier(target, false);
        try {
            ParallelVerifier.VerifyResult result = verifier.verifyAll(List.of(chain)).get(0);
            assertEquals("SINK_BLOCKED", result.status(), result::toString);
            assertTrue(result.sandboxReady(), result::toString);
            assertEquals("BOUNDARY_ONLY", result.verificationScope(), result::toString);
            assertEquals("PROCESS_TIMEOUT", result.fallback(), result::toString);
            assertEquals("BOUNDARY", result.effectiveMode(), result::toString);
            assertTrue(result.detail().contains("fallback=PROCESS_TIMEOUT"), result::toString);
        } finally {
            verifier.cleanup();
        }
    }

    @Test
    void explicitIsolationRequestKeepsTheSameLightweightRunner(@TempDir Path temp)
            throws Exception {
        requireWindowsJobOptIn();
        Path target = fixtureJar(temp, "fixture/RealSinkFixture.class");
        ParallelVerifier verifier = new ParallelVerifier(target, List.of(), null, 0,
                false, true, true, null);
        try {
            assertEquals("WINDOWS_JOB_OBJECT_JVM_POLICY", verifier.backendId());
            assertEquals(OsIsolation.Level.PROCESS_RESOURCE, OsIsolation.Level.valueOf(
                    verifier.isolationLevel()));
            assertTrue(verifier.osIsolationReady());
        } finally {
            verifier.cleanup();
        }
    }

    private static Chain applicationChain(String key) {
        return new Chain(key, "APPLICATION_BODY", "HIGH",
                "fixture/RealSinkFixture", "sink", "source",
                "fixture/RealSinkFixture", "sink",
                List.of(new ChainHop("fixture/RealSinkFixture", "sink",
                        "fixture/RealSinkFixture", "sink", HopKind.ENTRY, null,
                        "contract", "(Ljava/lang/String;I)Ljava/lang/String;", null)), 0,
                "(Ljava/lang/String;I)Ljava/lang/String;");
    }

    private static ParallelVerifier realVerifier(Path target, boolean requireIsolation) {
        return new ParallelVerifier(target, List.of(), null, 0,
                false, true, requireIsolation, null);
    }

    private static Path fixtureJar(Path temp, String... entries) throws Exception {
        Path jar = temp.resolve("contract-fixtures.jar");
        try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(jar))) {
            for (String entry : entries) {
                output.putNextEntry(new JarEntry(entry));
                try (InputStream input = WindowsRealVerificationContractTest.class
                        .getClassLoader().getResourceAsStream(entry)) {
                    if (input == null) {
                        throw new IllegalStateException("missing test class: " + entry);
                    }
                    input.transferTo(output);
                }
                output.closeEntry();
            }
        }
        return jar;
    }

    private static void requireWindowsJobOptIn() {
        Assumptions.assumeTrue(System.getProperty("os.name", "").toLowerCase()
                .contains("win"));
        Assumptions.assumeTrue(Boolean.getBoolean("just.run.os-contract-tests"));
        Path release = Path.of("target", "just-sast-0.2.0.jar");
        Assumptions.assumeTrue(Files.isRegularFile(release),
                "package the release JAR before running the OS contract");
        OsIsolation.Backend backend = OsIsolation.select(release.toAbsolutePath().normalize());
        assertTrue(backend.productionReady(),
                "Windows Job Object runner unavailable: " + backend.reason());
        assertEquals(OsIsolation.Level.PROCESS_RESOURCE, backend.level());
        assertTrue(backend.capabilities().contains("cpu_time_limit"));
    }
}
