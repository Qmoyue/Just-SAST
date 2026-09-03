package io.just.sast.verify;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.FilePermission;
import java.nio.charset.StandardCharsets;
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
    void tierFallbackClassifiesOnlyInfrastructureFailures() {
        ParallelVerifier.VerifyResult agentNotReady = new ParallelVerifier.VerifyResult(
                "chain", "UNTESTABLE",
                "requested_mode=LIGHT_SAFE_CALL;effective_mode=LIGHT_SAFE_CALL;fallback=none;"
                        + "UNTESTABLE: REAL_SINK_AGENT_NOT_READY");
        ParallelVerifier.VerifyResult timeout = new ParallelVerifier.VerifyResult(
                "chain", "TIMEOUT", "8s");
        ParallelVerifier.VerifyResult semanticPartial = new ParallelVerifier.VerifyResult(
                "chain", "PARTIAL", "PARTIAL_PATH:receiver-missing");
        ParallelVerifier.VerifyResult unsupported = new ParallelVerifier.VerifyResult(
                "chain", "UNTESTABLE", "SAFE_SANITIZER_UNAVAILABLE:safe-sanitizer-unavailable");

        assertTrue(ParallelVerifier.infrastructureFailure(agentNotReady));
        assertTrue(ParallelVerifier.infrastructureFailure(timeout));
        assertFalse(ParallelVerifier.infrastructureFailure(semanticPartial));
        assertTrue(ParallelVerifier.boundaryOnlyFailure(unsupported));
        assertEquals("UNTESTABLE:_REAL_SINK_AGENT_NOT_READY",
                ParallelVerifier.stableFailure(agentNotReady));
        assertEquals("PROCESS_TIMEOUT", ParallelVerifier.stableFailure(timeout));

        ParallelVerifier.VerifyResult incomplete = new ParallelVerifier.VerifyResult(
                "chain", "UNTESTABLE",
                "UNTESTABLE: REAL_SINK_EVIDENCE_INCOMPLETE;loaded=1;arguments=0;body=1");
        assertTrue(ParallelVerifier.infrastructureFailure(incomplete));
        assertEquals("UNTESTABLE:REAL_SINK_EVIDENCE_INCOMPLETE_loaded=1_arguments=0",
                ParallelVerifier.stableFailure(incomplete));
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
    void realPositiveEvidenceRequiresACompletedTypedObservation() {
        String expectedNativeDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assertTrue(ParallelVerifier.realEvidenceComplete(
                "SINK_EXECUTED_SAFE:body=1;body_returned=1;call=0;attempted=0"
                        + ";loaded=1;arguments=1"
                        + ";native_load=0;native_call=0;native_spec=;native_digest=none;sanitizer=INT_FIXED_ZERO",
                "APPLICATION_BODY"));
        assertFalse(ParallelVerifier.realEvidenceComplete(
                "SINK_EXECUTED_SAFE:body=1;body_returned=0;call=1;attempted=1",
                "APPLICATION_BODY"));
        assertTrue(ParallelVerifier.realEvidenceComplete(
                "SINK_EXECUTED_SAFE:body=0;body_returned=0;call=1;attempted=1"
                        + ";loaded=1;arguments=1"
                        + ";native_load=0;native_call=0;native_spec=;native_digest=none;sanitizer=COMMAND_FIXED_JAVA_VERSION",
                "RUNTIME_EXEC"));
        assertTrue(ParallelVerifier.realEvidenceComplete(
                "JNI_EXECUTED_SAFE:body=0;body_returned=0;call=1;attempted=1"
                        + ";loaded=1;arguments=1"
                        + ";native_load=1;native_call=1;native_spec=fixture/NativeFixture#value#()I"
                        + ";native_digest=" + expectedNativeDigest,
                "NATIVE_FIXTURE"));
        assertTrue(ParallelVerifier.realEvidenceComplete(
                "JNI_EXECUTED_SAFE:body=0;body_returned=0;call=1;attempted=1"
                        + ";loaded=1;arguments=1"
                        + ";native_load=1;native_call=1;native_spec=fixture/NativeFixture#value#()I"
                        + ";native_digest=" + expectedNativeDigest,
                "NATIVE_FIXTURE", expectedNativeDigest));
        assertFalse(ParallelVerifier.realEvidenceComplete(
                "JNI_EXECUTED_SAFE:body=0;body_returned=0;call=1;attempted=1"
                        + ";loaded=1;arguments=1"
                        + ";native_load=1;native_call=1;native_spec=fixture/NativeFixture#value#()I"
                        + ";native_digest=abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
                "NATIVE_FIXTURE", expectedNativeDigest));
        assertFalse(ParallelVerifier.realEvidenceComplete(
                "JNI_EXECUTED_SAFE:body=0;body_returned=0;call=1;attempted=1"
                        + ";native_load=1;native_call=1;native_spec=fixture/NativeFixture#value#()I"
                        + ";native_digest=none",
                "NATIVE_FIXTURE"));
        assertFalse(ParallelVerifier.realEvidenceComplete(
                "SINK_EXECUTED_SAFE:body=1;body_returned=1;call=0;attempted=0"
                        + ";loaded=1;arguments=0;native_load=0;native_call=0",
                "APPLICATION_BODY"));
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
                prefix + "SANDBOX_READY: WINDOWS_JOB_OBJECT_JVM_POLICY|policy=policy-digest\n"
                        + prefix + "SINK_BLOCKED: sink", identity);
        assertTrue(valid.bindingValid());
        assertTrue(valid.ready());
        assertTrue(valid.validOrder());
        assertEquals("policy-digest", valid.readyPolicyDigest());
        assertEquals("SINK_BLOCKED: sink", valid.terminal());

        ParallelVerifier.ProtocolEvidence tampered = ParallelVerifier.protocolEvidence(
                prefix + "SANDBOX_READY: WINDOWS_JOB_OBJECT_JVM_POLICY\n"
                        + "JUST_VERIFY_V2:token:run:other-chain:sink-fingerprint:nonce:artifact:"
                        + "SINK_BLOCKED: sink", identity);
        assertFalse(tampered.bindingValid());
    }

    @Test
    void windowsReadyEvidenceCarriesTheParentEstablishedJobBoundary() {
        ParallelVerifier.ProtocolIdentity identity = new ParallelVerifier.ProtocolIdentity(
                "token", "run", "chain-fingerprint", "sink-fingerprint", "nonce", "artifact");
        String prefix = "JUST_VERIFY_V2:token:run:chain-fingerprint:sink-fingerprint:nonce:artifact:";
        ParallelVerifier.ProtocolEvidence evidence = ParallelVerifier.protocolEvidence(
                prefix + "SANDBOX_READY: WINDOWS_JOB_OBJECT_JVM_POLICY|job=1"
                        + "|policy=policy-digest|attestation=" + OsIsolation.ATTESTATION_VERSION,
                identity);

        assertTrue(evidence.ready());
        assertTrue(evidence.jobReady());
        assertEquals("WINDOWS_JOB_OBJECT_JVM_POLICY", evidence.readyBackend());
    }

    @Test
    void readyEvidenceCarriesTheJobObjectAttestation() {
        ParallelVerifier.ProtocolIdentity identity = new ParallelVerifier.ProtocolIdentity(
                "token", "run", "chain-fingerprint", "sink-fingerprint", "nonce", "artifact");
        String prefix = "JUST_VERIFY_V2:token:run:chain-fingerprint:sink-fingerprint:nonce:artifact:";
        ParallelVerifier.ProtocolEvidence evidence = ParallelVerifier.protocolEvidence(
                prefix + "SANDBOX_READY: WINDOWS_JOB_OBJECT_JVM_POLICY|job=1"
                        + "|policy=policy-digest|attestation=" + OsIsolation.ATTESTATION_VERSION,
                identity);

        assertTrue(evidence.ready());
        assertTrue(evidence.jobReady());
        assertEquals("WINDOWS_JOB_OBJECT_JVM_POLICY", evidence.readyBackend());
        assertEquals("policy-digest", evidence.readyPolicyDigest());
        assertEquals(OsIsolation.ATTESTATION_VERSION, evidence.attestationVersion());
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
    void resultChannelAuthenticatesProbeFramesAndRejectsTampering(@TempDir Path tmp)
            throws Exception {
        ParallelVerifier.ProtocolIdentity identity = new ParallelVerifier.ProtocolIdentity(
                "token", "run", "chain-fingerprint", "sink-fingerprint", "nonce", "artifact");
        String secret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        String prefix = "JUST_VERIFY_V2:token:run:chain-fingerprint:sink-fingerprint:nonce:artifact:";
        String ready = prefix + "SANDBOX_READY: backend|policy=policy-digest";
        String terminal = prefix + "SINK_BLOCKED: sink";
        String content = "JUST_VERIFY_RESULT_V1:" + ParallelVerifier.resultMac(secret, ready)
                + ":" + ready + "\n"
                + "JUST_VERIFY_RESULT_V1:" + ParallelVerifier.resultMac(secret, terminal)
                + ":" + terminal + "\n";
        Path result = tmp.resolve("verification.result");
        Files.writeString(result, content, java.nio.charset.StandardCharsets.US_ASCII);

        ParallelVerifier.ProtocolEvidence valid = ParallelVerifier.protocolEvidence(
                result, identity, secret);
        assertTrue(valid.bindingValid());
        assertTrue(valid.ready());
        assertEquals("SINK_BLOCKED: sink", valid.terminal());

        Files.writeString(result, content.replace("SINK_BLOCKED: sink", "SINK_BLOCKED: forged"),
                java.nio.charset.StandardCharsets.US_ASCII);
        ParallelVerifier.ProtocolEvidence tampered = ParallelVerifier.protocolEvidence(
                result, identity, secret);
        assertFalse(tampered.bindingValid(), "未重新计算 HMAC 的目标输出不能伪造终态");
    }

    @Test
    void readyEventCarriesTheVersionedIsolationAttestation() {
        ParallelVerifier.ProtocolIdentity identity = new ParallelVerifier.ProtocolIdentity(
                "token", "run", "chain-fingerprint", "sink-fingerprint", "nonce", "artifact");
        String prefix = "JUST_VERIFY_V2:token:run:chain-fingerprint:sink-fingerprint:nonce:artifact:";
        ParallelVerifier.ProtocolEvidence evidence = ParallelVerifier.protocolEvidence(
                prefix + "SANDBOX_READY: WINDOWS_JOB_OBJECT_JVM_POLICY|job=1|policy=policy-digest"
                        + "|attestation=" + OsIsolation.ATTESTATION_VERSION,
                identity);

        assertTrue(evidence.ready());
        assertEquals(OsIsolation.ATTESTATION_VERSION, evidence.attestationVersion());
        assertTrue(evidence.jobReady());
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
    void windowsBrokerKeepsProfileRootsSeparateFromTargetScratch() {
        if (!System.getProperty("os.name", "").toLowerCase().contains("win")) {
            return;
        }
        Path javaHome = Path.of("C:/jdk");
        Path isoDir = Path.of("C:/isolated");
        Path isoTmp = isoDir.resolve("tmp");
        Map<String, String> parent = Map.of(
                "SystemRoot", "C:/Windows",
                "USERPROFILE", "C:/Users/runner",
                "LOCALAPPDATA", "C:/Users/runner/AppData/Local",
                "APPDATA", "C:/Users/runner/AppData/Roaming",
                "JAVA_TOOL_OPTIONS", "-javaagent:C:/secret/agent.jar");

        Map<String, String> result = ParallelVerifier.sanitizedEnvironment(
                parent, javaHome, isoDir, isoTmp);

        assertEquals(isoDir.toString(), result.get("USERPROFILE"));
        assertFalse(result.containsKey("LOCALAPPDATA"));
        assertFalse(result.containsKey("APPDATA"));
        assertFalse(result.containsKey("JAVA_TOOL_OPTIONS"));
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
    void hostCapabilityIsKnownBeforeAnyChildAttempt() {
        ParallelVerifier verifier = new ParallelVerifier(Path.of("."), List.of(), null);

        assertNotEquals("NOT_RUN", verifier.hostCapability());
        assertEquals("NOT_RUN", verifier.capability());
    }

    @Test
    void isolationPreflightResultCarriesTheHostPolicyIdentity() {
        ParallelVerifier verifier = new ParallelVerifier(Path.of("."), List.of(), null);
        if (verifier.osIsolationReady()) {
            return;
        }
        Chain chain = new Chain("rule", "category", "HIGH", "fixture/Entry", "readObject",
                "METHOD", "fixture/Sink", "call", List.of(), 0);

        ParallelVerifier.VerifyResult result = verifier.isolationUnavailableResult(chain);

        assertEquals("UNTESTABLE", result.status());
        assertEquals(verifier.backendId(), result.backend());
        assertEquals(verifier.policyDigest(), result.policyDigest());
        assertEquals("SANDBOX_UNAVAILABLE", result.evidence());
        assertEquals("NOT_STARTED", result.cleanup());
    }

    @Test
    void explicitTargetJdkNeverFallsBackToTheScannerRuntime(@TempDir Path tmp) throws Exception {
        Path targetJdk = Files.createDirectories(tmp.resolve("jdk11"));
        Files.createDirectories(targetJdk.resolve("bin"));
        Files.writeString(targetJdk.resolve("bin").resolve("java"), "not-an-executable",
                StandardCharsets.US_ASCII);
        Files.writeString(targetJdk.resolve("release"), "JAVA_VERSION=\"11.0.24\"\n",
                StandardCharsets.US_ASCII);

        Chain chain = new Chain("runtime-selection", "fixture", "HIGH", "fixture/Entry",
                "run", "source", "fixture/Sink", "call", List.of(), 0);
        ParallelVerifier verifier = new ParallelVerifier(Path.of("."), List.of(), targetJdk,
                61, false, false, false, null);
        try {
            ParallelVerifier.VerifyResult result = verifier.verifyAll(List.of(chain)).get(0);
            assertEquals("UNTESTABLE", result.status());
            assertTrue(result.detail().contains("target-jdk-too-old"), result::toString);
            assertEquals("JVM_RUNTIME_UNAVAILABLE", verifier.capability());
        } finally {
            verifier.cleanup();
        }
    }

    @Test
    void batchDeadlineCoversQueuedWorkerWaves() {
        assertEquals(11, ParallelVerifier.batchTimeoutSeconds(1, 4));
        assertEquals(11, ParallelVerifier.batchTimeoutSeconds(4, 4));
        assertEquals(19, ParallelVerifier.batchTimeoutSeconds(5, 4));
        assertEquals(43, ParallelVerifier.batchTimeoutSeconds(20, 4));
        assertEquals(0, ParallelVerifier.batchTimeoutSeconds(0, 4));
        assertEquals(27, ParallelVerifier.batchTimeoutSeconds(1, 4, 3));
        assertEquals(19, ParallelVerifier.batchTimeoutSeconds(1, 4, 2));
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
