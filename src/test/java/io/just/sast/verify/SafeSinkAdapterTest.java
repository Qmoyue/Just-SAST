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
        assertTrue(network.effectObserved());
        assertTrue(data.effectObserved());
        assertTrue(file.effectObserved());
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
}
