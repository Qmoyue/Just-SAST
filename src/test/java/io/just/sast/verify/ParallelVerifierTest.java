package io.just.sast.verify;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.FilePermission;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.HopKind;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;

/** 子 JVM 的环境边界是动态验证的用户可见安全契约。 */
class ParallelVerifierTest {

    @Test
    void verificationStatusIsClosedAndUnknownValuesAreNotPositiveEvidence() {
        ParallelVerifier.VerifyResult blocked = new ParallelVerifier.VerifyResult(
                "chain", "SINK_BLOCKED", "boundary");
        ParallelVerifier.VerifyResult unknown = new ParallelVerifier.VerifyResult(
                "chain", "new-status-from-future", "detail");

        assertEquals(ParallelVerifier.VerifyStatus.SINK_BLOCKED, blocked.statusCode());
        assertEquals("SINK_CANARY_BOUNDARY", blocked.evidence());
        assertEquals(ParallelVerifier.VerifyStatus.UNKNOWN, unknown.statusCode());
        assertEquals("UNKNOWN", unknown.evidence(),
                "未知状态不得被当作动态正向证据");
    }

    @Test
    void onlyTheCurrentProbeTokenCanProduceAStatus() {
        assertEquals("SINK_BLOCKED: java.lang.Runtime",
                ParallelVerifier.authenticatedStatus(
                        "JUST_VERIFY_V1:attempt-token:SINK_BLOCKED: java.lang.Runtime",
                        "attempt-token"));
        assertNull(ParallelVerifier.authenticatedStatus(
                "SINK_BLOCKED: java.lang.Runtime", "attempt-token"));
        assertNull(ParallelVerifier.authenticatedStatus(
                "JUST_VERIFY_V1:other-token:SINK_BLOCKED: java.lang.Runtime",
                "attempt-token"));
        assertNull(ParallelVerifier.authenticatedStatus(
                "JUST_VERIFY_V1:attempt-token:NOT_A_STATUS", "attempt-token"));
    }

    @Test
    void childEnvironmentDoesNotInheritSecretsOrJVMInjection() {
        Path javaHome = Path.of("C:/jdk");
        Path isoDir = Path.of("C:/isolated");
        Path isoTmp = isoDir.resolve("tmp");
        Map<String, String> parent = Map.of(
                "PATH", "C:/user/bin",
                "JAVA_TOOL_OPTIONS", "-javaagent:C:/secret/agent.jar",
                "AWS_SECRET_ACCESS_KEY", "secret",
                "SystemRoot", "C:/Windows");

        Map<String, String> result = ParallelVerifier.sanitizedEnvironment(
                parent, javaHome, isoDir, isoTmp);

        assertFalse(result.containsKey("JAVA_TOOL_OPTIONS"));
        assertFalse(result.containsKey("AWS_SECRET_ACCESS_KEY"));
        assertEquals(isoTmp.toString(), result.get("TEMP"));
        assertEquals(isoTmp.toString(), result.get("TMP"));
        if (System.getProperty("os.name", "").toLowerCase().contains("win")) {
            assertEquals(javaHome.resolve("bin").toString(), result.get("PATH"));
            assertEquals(isoDir.toString(), result.get("USERPROFILE"));
        } else {
            assertEquals("/usr/bin:/bin", result.get("PATH"));
            assertEquals(isoDir.toString(), result.get("HOME"));
        }
    }

    @Test
    void sandboxAllowsFilesBelowAnExplicitClasspathRoot(@TempDir Path tmp) throws Exception {
        Path classes = Files.createDirectories(tmp.resolve("classes"));
        Path applicationClass = Files.createFile(classes.resolve("sample.class"));
        SandboxSecurityManager manager = new SandboxSecurityManager(tmp, List.of(classes));
        manager.checkPermission(new FilePermission(applicationClass.toString(), "read"));
    }

    @Test
    void primaryArtifactCoverageSurvivesStrongerDependencyNoise(@TempDir Path tmp) throws Exception {
        Path target = tmp.resolve("target.jar");
        try (java.util.jar.JarOutputStream output = new java.util.jar.JarOutputStream(
                Files.newOutputStream(target))) {
            output.putNextEntry(new java.util.jar.JarEntry("app/Entry.class"));
            output.write(new byte[]{0});
            output.closeEntry();
        }
        List<ChainHop> dependencyHops = List.of(
                new ChainHop("dep/A", "a", "dep/B", "b", HopKind.DIRECT_CALL,
                        null, null, "()V", null),
                new ChainHop("dep/B", "b", "dep/C", "c", HopKind.DIRECT_CALL,
                        null, null, "()V", null),
                new ChainHop("dep/C", "c", "dep/D", "d", HopKind.DIRECT_CALL,
                        null, null, "()V", null),
                new ChainHop("dep/D", "d", "dep/E", "e", HopKind.DIRECT_CALL,
                        null, null, "()V", null));
        Chain dependency = new Chain("rule", "gadget", "HIGH", "dep/A", "a",
                "source", "java/lang/reflect/Method", "invoke", dependencyHops, 0);
        Chain application = new Chain("rule", "gadget", "HIGH", "app/Entry", "read",
                "deserialize", "java/lang/reflect/Method", "invoke", List.of(), 0);
        ParallelVerifier verifier = new ParallelVerifier(target, List.of(), null);

        List<Chain> selected = verifier.selectChains(List.of(dependency, application), 2);

        org.junit.jupiter.api.Assertions.assertTrue(selected.contains(application));
    }

}
