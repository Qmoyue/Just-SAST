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
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

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

        ParallelVerifier.VerifyResult safe = new ParallelVerifier.VerifyResult(
                "chain", "SAFE_EFFECT_OBSERVED", "INERT_COMMAND", 1, 0L);
        assertEquals(ParallelVerifier.VerifyStatus.SAFE_EFFECT_OBSERVED, safe.statusCode());
        assertEquals("SAFE_EFFECT_OBSERVED", safe.evidence());
    }

    @Test
    void resourceLimitDiagnosticsRemainNegativeEvidence() {
        assertTrue(ParallelVerifier.outOfMemoryDiagnostic(
                "java.lang.OutOfMemoryError: Java heap space"));
        assertTrue(ParallelVerifier.outOfMemoryDiagnostic("GC overhead limit exceeded"));
        assertFalse(ParallelVerifier.outOfMemoryDiagnostic(
                "JUST_VERIFY_V2:token:run:chain:sink:nonce:artifact:SINK_BLOCKED"));

        ParallelVerifier.VerifyResult oom = new ParallelVerifier.VerifyResult(
                "chain", "UNTESTABLE", "PROCESS_OOM");
        assertEquals("PROCESS_OOM", oom.evidence());
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
    void readinessMustPrecedeAuthenticatedTerminalEvidence() {
        String token = "attempt-token";
        ParallelVerifier.ProtocolEvidence valid = ParallelVerifier.protocolEvidence(
                "noise\nJUST_VERIFY_V1:" + token + ":SANDBOX_READY: WINDOWS_JOB_OBJECT_JVM_POLICY\n"
                        + "JUST_VERIFY_V1:" + token + ":SINK_BLOCKED: sink",
                token);
        ParallelVerifier.ProtocolEvidence invalid = ParallelVerifier.protocolEvidence(
                "JUST_VERIFY_V1:" + token + ":SINK_BLOCKED: sink\n"
                        + "JUST_VERIFY_V1:" + token + ":SANDBOX_READY: backend",
                token);

        assertEquals(true, valid.ready());
        assertEquals(true, valid.validOrder());
        assertEquals("WINDOWS_JOB_OBJECT_JVM_POLICY", valid.readyBackend());
        assertEquals("SINK_BLOCKED: sink", valid.terminal());
        assertEquals(false, invalid.validOrder());

        String safe = "JUST_VERIFY_V1:" + token + ":SAFE_EFFECT_OBSERVED:INERT_COMMAND";
        assertEquals("SAFE_EFFECT_OBSERVED:INERT_COMMAND",
                ParallelVerifier.authenticatedStatus(safe, token));
    }

    @Test
    void v2EvidenceBindsAttemptChainSinkAndArtifact() {
        ParallelVerifier.ProtocolIdentity identity = new ParallelVerifier.ProtocolIdentity(
                "token", "run", "chain-fingerprint", "sink-fingerprint", "nonce", "artifact");
        String prefix = "JUST_VERIFY_V2:token:run:chain-fingerprint:sink-fingerprint:nonce:artifact:";
        ParallelVerifier.ProtocolEvidence valid = ParallelVerifier.protocolEvidence(
                prefix + "SANDBOX_READY: WINDOWS_JOB_OBJECT_JVM_POLICY\n"
                        + prefix + "SINK_BLOCKED: sink", identity);
        assertTrue(valid.bindingValid());
        assertTrue(valid.ready());
        assertTrue(valid.validOrder());
        assertEquals("SINK_BLOCKED: sink", valid.terminal());

        ParallelVerifier.ProtocolEvidence tampered = ParallelVerifier.protocolEvidence(
                prefix + "SANDBOX_READY: WINDOWS_JOB_OBJECT_JVM_POLICY\n"
                        + "JUST_VERIFY_V2:token:run:other-chain:sink-fingerprint:nonce:artifact:"
                        + "SINK_BLOCKED: sink", identity);
        assertFalse(tampered.bindingValid());
    }

    @Test
    void anyTamperedV2FrameInvalidatesTheWholeAttempt() {
        ParallelVerifier.ProtocolIdentity identity = new ParallelVerifier.ProtocolIdentity(
                "token", "run", "chain-fingerprint", "sink-fingerprint", "nonce", "artifact");
        String prefix = "JUST_VERIFY_V2:token:run:chain-fingerprint:sink-fingerprint:nonce:artifact:";
        ParallelVerifier.ProtocolEvidence evidence = ParallelVerifier.protocolEvidence(
                prefix + "SANDBOX_READY: WINDOWS_JOB_OBJECT_JVM_POLICY\n"
                        + "JUST_VERIFY_V2:token:run:wrong-chain:sink-fingerprint:nonce:artifact:"
                        + "PARTIAL_PATH:tampered\n"
                        + prefix + "SINK_BLOCKED: sink", identity);

        assertFalse(evidence.bindingValid(), "坏帧之后不能被后续好帧重新认证");
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
    void sinkPolicyModeIsExplicitAndStable() {
        ParallelVerifier boundary = new ParallelVerifier(Path.of("."), List.of(),
                null, 0, false, null);
        ParallelVerifier safe = new ParallelVerifier(Path.of("."), List.of(),
                null, 0, true, null);

        assertEquals("BOUNDARY", boundary.policyMode());
        assertEquals("SAFE_EXEC", safe.policyMode());
        assertNotEquals(boundary.policyDigest(), safe.policyDigest());
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

    @Test
    void directKryoSourceIsEncodedForTheSourceAdapter() {
        List<ChainHop> hops = List.of(
                new ChainHop("app/Gadget", "toString", "java/lang/reflect/Method", "invoke",
                        HopKind.DIRECT_CALL, null, null, "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;", null),
                new ChainHop("com/sun/syndication/feed/impl/EqualsBean", "hashCode",
                        "com/sun/syndication/feed/impl/ToStringBean", "toString",
                        HopKind.DIRECT_CALL, null, null, "", null),
                new ChainHop("com/esotericsoftware/kryo/Kryo", "readClassAndObject",
                        "com/sun/syndication/feed/impl/EqualsBean", "hashCode",
                        HopKind.VIRTUAL_DISPATCH, null, null, "()I", null),
                new ChainHop("app/Controller", "read", "com/esotericsoftware/kryo/Kryo",
                        "readClassAndObject", HopKind.DIRECT_CALL, null, null,
                        "(Lcom/esotericsoftware/kryo/io/Input;)Ljava/lang/Object;", null),
                new ChainHop("app/Controller", "read", "app/Controller", "read",
                        HopKind.ENTRY, null, "source", "(Ljava/lang/String;)Ljava/lang/String;", null));
        Chain chain = new Chain("rule", "REFLECTIVE_INVOKE", "HIGH", "app/Controller", "read",
                "source", "java/lang/reflect/Method", "invoke", hops, 0);

        assertEquals(
                "com/sun/syndication/feed/impl/EqualsBean|hashCode|hashCode"
                        + "|com/esotericsoftware/kryo/Kryo|readClassAndObject"
                        + "|(Lcom/esotericsoftware/kryo/io/Input;)Ljava/lang/Object;"
                        + "|com/sun/syndication/feed/impl/ToStringBean"
                        + "|toString",
                ParallelVerifier.sourceTriggerSpec(chain));
    }

}
