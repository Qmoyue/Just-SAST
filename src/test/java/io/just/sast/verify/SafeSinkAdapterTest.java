package io.just.sast.verify;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;

/** Policy tests verify fixed adapter effects; no target sink is ever invoked. */
class SafeSinkAdapterTest {

    @Test
    void boundaryPolicyAlwaysStopsBeforeSinkBody() {
        SafeSinkAdapter.Decision decision = SafeSinkAdapter.decide(
                SafeSinkAdapter.boundary(),
                new SafeSinkAdapter.Sink("COMMAND_EXEC", "java/lang/Runtime", "exec", ""));

        assertEquals(SafeSinkAdapter.Mode.BOUNDARY,
                SafeSinkAdapter.boundary().mode());
        assertEquals(SafeSinkAdapter.Disposition.CANARY_BOUNDARY, decision.disposition());
        assertTrue(decision.permitted(), "canary boundary is the safe observation point");
        assertTrue(decision.distorted());
        assertFalse(decision.adapterSelected());
    }

    @Test
    void safeExecutionUsesOnlyInertOrMockStrategies(@TempDir Path scratch) {
        SafeSinkAdapter.Policy policy = SafeSinkAdapter.safeExecution(scratch);

        SafeSinkAdapter.Decision command = SafeSinkAdapter.decide(policy,
                new SafeSinkAdapter.Sink("COMMAND_EXEC", "java/lang/Runtime", "exec", ""));
        SafeSinkAdapter.Decision network = SafeSinkAdapter.decide(policy,
                new SafeSinkAdapter.Sink("SSRF", "java/net/Socket", "<init>", ""));
        SafeSinkAdapter.Decision nativeSink = SafeSinkAdapter.decide(policy,
                new SafeSinkAdapter.Sink("NATIVE", "java/lang/System", "load", ""));

        assertEquals(SafeSinkAdapter.Disposition.INERT_COMMAND, command.disposition());
        assertEquals(SafeSinkAdapter.Disposition.LOOPBACK_MOCK, network.disposition());
        assertEquals(SafeSinkAdapter.Disposition.CANARY_BOUNDARY, nativeSink.disposition());
        assertTrue(command.adapterSelected());
        assertTrue(network.adapterSelected());
        assertFalse(nativeSink.adapterSelected(), "native remains boundary-only");
    }

    @Test
    void codeGenerationAndNativeFamiliesRemainBoundaryOnly(@TempDir Path scratch) {
        SafeSinkAdapter.Policy policy = SafeSinkAdapter.safeExecution(scratch);

        SafeSinkAdapter.Decision templates = SafeSinkAdapter.decide(policy,
                new SafeSinkAdapter.Sink("TEMPLATES_NEW_TRANSFORMER",
                        "com/sun/org/apache/xalan/internal/xsltc/trax/TemplatesImpl",
                        "newTransformer", "()Ljavax/xml/transform/Transformer;"));
        SafeSinkAdapter.Decision nativeSink = SafeSinkAdapter.decide(policy,
                new SafeSinkAdapter.Sink("JNI_CALLBACK", "app/Native", "invoke", "()V"));

        assertEquals(SafeSinkAdapter.Capability.CODE_EXECUTION, templates.capability());
        assertEquals(SafeSinkAdapter.Disposition.CANARY_BOUNDARY, templates.disposition());
        assertFalse(templates.adapterSelected());
        assertEquals(SafeSinkAdapter.Capability.NATIVE, nativeSink.capability());
        assertEquals(SafeSinkAdapter.Disposition.CANARY_BOUNDARY, nativeSink.disposition());
        assertFalse(nativeSink.adapterSelected());
    }

    @Test
    void nativeApiCannotBeReclassifiedByAGenericCodeExecutionRule() {
        SafeSinkAdapter.Decision decision = SafeSinkAdapter.decide(
                SafeSinkAdapter.safeExecution(Path.of(".")),
                new SafeSinkAdapter.Sink("CODE_EXEC", "java/lang/System", "load", ""));

        assertEquals(SafeSinkAdapter.Capability.NATIVE, decision.capability());
        assertEquals(SafeSinkAdapter.Disposition.CANARY_BOUNDARY, decision.disposition());
        assertFalse(decision.adapterSelected());
    }

    @Test
    void remoteNamingAndRmiRemainBoundaryOnlyInSafeReal(@TempDir Path scratch) {
        SafeSinkAdapter.Policy policy = SafeSinkAdapter.safeRealExecution(scratch);

        SafeSinkAdapter.Decision jndi = SafeSinkAdapter.decide(policy,
                new SafeSinkAdapter.Sink("JNDI_LOOKUP", "javax/naming/InitialContext",
                        "lookup", "(Ljava/lang/String;)Ljava/lang/Object;"));
        SafeSinkAdapter.Decision jrmp = SafeSinkAdapter.decide(policy,
                new SafeSinkAdapter.Sink("JRMP", "java/rmi/registry/Registry", "lookup",
                        "(Ljava/lang/String;)Ljava/lang/Object;"));
        SafeSinkAdapter.Decision genericRmi = SafeSinkAdapter.decide(policy,
                new SafeSinkAdapter.Sink("CALL", "java/rmi/server/RemoteObject", "invoke", "()V"));

        assertEquals(SafeSinkAdapter.Capability.REMOTE_LOOKUP, jndi.capability());
        assertEquals(SafeSinkAdapter.Capability.REMOTE_LOOKUP, jrmp.capability());
        assertEquals(SafeSinkAdapter.Capability.REMOTE_LOOKUP, genericRmi.capability());
        assertEquals(SafeSinkAdapter.Disposition.CANARY_BOUNDARY, jndi.disposition());
        assertEquals(SafeSinkAdapter.Disposition.CANARY_BOUNDARY, jrmp.disposition());
        assertEquals(SafeSinkAdapter.Disposition.CANARY_BOUNDARY, genericRmi.disposition());
        assertFalse(jndi.adapterSelected());
        assertFalse(jrmp.adapterSelected());
        assertFalse(genericRmi.adapterSelected());
    }

    @Test
    void safeExecutionObservesOnlyFixedAdapterEffects(@TempDir Path scratch) throws Exception {
        SafeSinkAdapter.Policy policy = SafeSinkAdapter.safeExecution(scratch);

        SafeSinkAdapter.AdapterResult command = SafeSinkAdapter.observe(policy,
                new SafeSinkAdapter.Sink("COMMAND_EXEC", "java/lang/Runtime", "exec", ""), null);
        SafeSinkAdapter.AdapterResult network = SafeSinkAdapter.observe(policy,
                new SafeSinkAdapter.Sink("SSRF", "java/net/Socket", "connect", ""), null);
        SafeSinkAdapter.AdapterResult data = SafeSinkAdapter.observe(policy,
                new SafeSinkAdapter.Sink("JDBC", "java/sql/Connection", "execute", ""), null);
        SafeSinkAdapter.AdapterResult file = SafeSinkAdapter.observe(policy,
                new SafeSinkAdapter.Sink("FILE_WRITE", "java/nio/file/Files", "write", ""), null);
        SafeSinkAdapter.AdapterResult reflection = SafeSinkAdapter.observe(policy,
                new SafeSinkAdapter.Sink("REFLECTION", "java/lang/reflect/Method", "invoke", ""), null);

        assertTrue(command.effectObserved());
        assertEquals("INERT_COMMAND_RECORDED", command.effect());
        assertTrue(network.effectObserved(), String.valueOf(network));
        assertTrue(data.effectObserved());
        assertTrue(file.effectObserved(), String.valueOf(file));
        assertEquals("JUST_SAFE_EFFECT\n",
                Files.readString(scratch.resolve("just-safe-effect.marker")));
        assertFalse(reflection.effectObserved(), "reflection remains canary-only");
        assertEquals(SafeSinkAdapter.Disposition.CANARY_BOUNDARY,
                reflection.decision().disposition());
    }

    @Test
    void boundaryObservationCannotClaimAnEffect(@TempDir Path scratch) {
        SafeSinkAdapter.AdapterResult result = SafeSinkAdapter.observe(
                SafeSinkAdapter.boundary(),
                new SafeSinkAdapter.Sink("COMMAND_EXEC", "java/lang/Runtime", "exec", ""),
                null);

        assertFalse(result.effectObserved());
        assertEquals("NO_EFFECT_EXECUTED", result.effect());
        assertEquals(SafeSinkAdapter.Disposition.CANARY_BOUNDARY,
                result.decision().disposition());
    }

    @Test
    void fileAdapterRejectsPathsOutsideCanonicalScratch(@TempDir Path scratch) throws Exception {
        SafeSinkAdapter.Policy policy = SafeSinkAdapter.safeExecution(scratch);
        Path inside = scratch.resolve("nested").resolve("effect.bin");
        Files.createDirectories(inside.getParent());
        Path outside = scratch.getParent().resolve("outside-effect.bin");

        assertTrue(SafeSinkAdapter.isWithinScratch(policy, inside));
        assertFalse(SafeSinkAdapter.isWithinScratch(policy, outside));
        SafeSinkAdapter.AdapterResult rejected = SafeSinkAdapter.preflight(policy,
                new SafeSinkAdapter.Sink("FILE_WRITE", "java/nio/file/Files", "write", ""),
                outside);
        assertEquals(SafeSinkAdapter.Disposition.DENIED,
                rejected.decision().disposition());
        assertFalse(rejected.decision().permitted());
        assertFalse(rejected.effectObserved(), "preflight cannot claim an effect");
    }

    @Test
    void symlinkedScratchRootAndMissingRootFailClosed(@TempDir Path scratch) throws Exception {
        Path missing = scratch.resolve("missing");
        assertThrows(IllegalArgumentException.class,
                () -> SafeSinkAdapter.safeExecution(missing));

        Path link = scratch.resolve("scratch-link");
        try {
            Files.createSymbolicLink(link, scratch);
            assertThrows(IllegalArgumentException.class,
                    () -> SafeSinkAdapter.safeExecution(link));
        } catch (UnsupportedOperationException | java.nio.file.FileSystemException ignored) {
            // Symlink creation is an environment capability; the missing-root contract above
            // still executes on every platform.
        }
    }

    @Test
    void policyDigestIdentifiesModeButNotRandomScratchDirectory(@TempDir Path first,
                                                                 @TempDir Path second) {
        SafeSinkAdapter.Policy firstPolicy = SafeSinkAdapter.safeExecution(first);
        SafeSinkAdapter.Policy secondPolicy = SafeSinkAdapter.safeExecution(second);

        assertEquals(firstPolicy.digest(), secondPolicy.digest());
        assertNotEquals(firstPolicy.digest(), SafeSinkAdapter.boundary().digest());
        assertEquals(firstPolicy.digest(),
                SafeSinkAdapter.policyDigest(SafeSinkAdapter.Mode.SAFE_EXEC));
    }

    @Test
    void safeRealCannotObserveAnAdapterEffect(@TempDir Path scratch) throws Exception {
        SafeSinkAdapter.Policy policy = SafeSinkAdapter.safeRealExecution(scratch);
        Path javaHome = Path.of(System.getProperty("java.home"));
        String executableName = System.getProperty("os.name", "").toLowerCase()
                .contains("win") ? "java.exe" : "java";
        Path java = javaHome.resolve("bin").resolve(executableName);

        SafeSinkAdapter.AdapterResult command = SafeSinkAdapter.observe(policy,
                new SafeSinkAdapter.Sink("COMMAND_EXEC", "java/lang/Runtime", "exec",
                        "(Ljava/lang/String;)Ljava/lang/Process;"),
                null, java);
        SafeSinkAdapter.AdapterResult network = SafeSinkAdapter.observe(policy,
                new SafeSinkAdapter.Sink("SSRF", "java/net/Socket", "connect",
                        "(Ljava/net/SocketAddress;)V"), null, java);
        SafeSinkAdapter.AdapterResult file = SafeSinkAdapter.observe(policy,
                new SafeSinkAdapter.Sink("FILE_WRITE", "java/nio/file/Files", "newOutputStream",
                        "(Ljava/nio/file/Path;[Ljava/nio/file/OpenOption;)Ljava/io/OutputStream;"),
                null, java);

        assertFalse(command.effectObserved(), String.valueOf(command));
        assertEquals(SafeSinkAdapter.Disposition.REAL_TARGET_SINK,
                command.decision().disposition());
        assertFalse(network.effectObserved());
        assertEquals(SafeSinkAdapter.Disposition.REAL_TARGET_SINK,
                network.decision().disposition());
        assertFalse(file.effectObserved());
        assertEquals(SafeSinkAdapter.Disposition.REAL_TARGET_SINK,
                file.decision().disposition());
        assertFalse(Files.exists(scratch.resolve("just-safe-effect.marker")));
        assertNotEquals(policy.digest(), SafeSinkAdapter.policyDigest(SafeSinkAdapter.Mode.SAFE_EXEC));
    }
}
