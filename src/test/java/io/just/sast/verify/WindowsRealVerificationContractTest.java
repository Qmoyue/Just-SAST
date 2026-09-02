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
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Opt-in Windows integration contract for the real child runner.  It is kept out of the normal
 * fast unit suite because it creates an AppContainer and a separate JVM; the final acceptance
 * run enables it with {@code -Djust.run.os-contract-tests=true}.
 */
class WindowsRealVerificationContractTest {

    @Test
    void exactApplicationBodyRunsWithTypedArgumentsAndBlocksNestedProcess(@TempDir Path temp)
            throws Exception {
        requireOptIn();
        Path target = fixtureJar(temp, "fixture/RealSinkFixture.class");
        Chain chain = new Chain("contract-real-body", "APPLICATION_BODY", "HIGH",
                "fixture/RealSinkFixture", "sink", "source",
                "fixture/RealSinkFixture", "sink",
                List.of(new ChainHop("fixture/RealSinkFixture", "sink",
                        "fixture/RealSinkFixture", "sink", HopKind.ENTRY, null,
                        "contract", "(Ljava/lang/String;I)Ljava/lang/String;", null)), 0,
                "(Ljava/lang/String;I)Ljava/lang/String;");

        ParallelVerifier verifier = strictRealVerifier(target);
        try {
            ParallelVerifier.VerifyResult result = verifier.verifyAll(List.of(chain)).get(0);
            assertEquals("SINK_EXECUTED_SAFE", result.status(), result::toString);
            assertTrue(result.sandboxReady(), result::toString);
            assertTrue(result.sinkDistorted(), result::toString);
            assertTrue(result.backend().contains("APPCONTAINER"), result::toString);
            assertTrue(result.detail().contains("body=1"), result::toString);
            assertTrue(result.detail().contains("nested_blocked=1"), result::toString);
            assertTrue(result.detail().contains("INT_FIXED_ZERO"), result::toString);
        } finally {
            verifier.cleanup();
        }
    }

    @Test
    void verifierOwnedNativeFixtureLoadsAndReturnsThroughNativeCallback(@TempDir Path temp)
            throws Exception {
        requireOptIn();
        Path target = fixtureJar(temp, "fixture/NativeFixture.class");
        Chain chain = new Chain("contract-real-jni", "NATIVE", "HIGH",
                "fixture/NativeFixture", "trigger", "direct",
                "java/lang/System", "loadLibrary",
                List.of(new ChainHop("fixture/NativeFixture", "trigger",
                        "java/lang/System", "loadLibrary", HopKind.DIRECT_CALL, null,
                        "contract", "(Ljava/lang/String;)V", null),
                        new ChainHop("fixture/NativeFixture", "trigger",
                                "fixture/NativeFixture", "trigger", HopKind.ENTRY, null,
                                "contract", "()I", null)), 0,
                "(Ljava/lang/String;)V");

        ParallelVerifier verifier = strictRealVerifier(target);
        try {
            ParallelVerifier.VerifyResult result = verifier.verifyAll(List.of(chain)).get(0);
            assertEquals("JNI_EXECUTED_SAFE", result.status(), result::toString);
            assertTrue(result.sandboxReady(), result::toString);
            assertTrue(result.sinkDistorted(), result::toString);
            assertTrue(result.detail().contains("native_load=1"), result::toString);
            assertTrue(result.detail().contains("native_call=1"), result::toString);
            assertTrue(result.detail().contains("native_digest=")
                    && !result.detail().contains("native_digest=none"), result::toString);
        } finally {
            verifier.cleanup();
        }
    }

    private static ParallelVerifier strictRealVerifier(Path target) {
        return new ParallelVerifier(target, List.of(), null, 0,
                false, true, true, null);
    }

    private static Path fixtureJar(Path temp, String... entries) throws Exception {
        Path jar = temp.resolve("contract-fixtures.jar");
        try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(jar))) {
            for (String entry : entries) {
                output.putNextEntry(new JarEntry(entry));
                try (InputStream input = WindowsRealVerificationContractTest.class
                        .getClassLoader().getResourceAsStream(entry)) {
                    if (input == null) throw new IllegalStateException("missing test class: " + entry);
                    input.transferTo(output);
                }
                output.closeEntry();
            }
        }
        return jar;
    }

    private static void requireOptIn() {
        Assumptions.assumeTrue(System.getProperty("os.name", "").toLowerCase()
                .contains("win"));
        Assumptions.assumeTrue(Boolean.getBoolean("just.run.os-contract-tests"));
        Path release = Path.of("target", "just-sast-0.2.0.jar");
        Assumptions.assumeTrue(Files.isRegularFile(release),
                "package the shaded release JAR before running the OS contract");
        OsIsolation.Backend backend = OsIsolation.select(release.toAbsolutePath().normalize());
        Assumptions.assumeTrue(backend.productionReady(),
                "strict Windows runner unavailable: " + backend.reason());
    }
}
