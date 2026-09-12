package io.just.sast.verify;

import io.just.sast.blackboard.Chain;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** P2.1 characterization seam for the probe and verifier owners. */
class OwnerBehaviorCharacterizationTest {

    @Test
    void probeHelpersAreBoundedAndUnknownEvidenceIsNegative() {
        assertFalse(ChainVerifyProbe.isTriggerMode(null));
        assertTrue(ChainVerifyProbe.isTriggerMode("TRIGGER_HASH"));
        assertEquals(null, ChainVerifyProbe.markerSpec(new RuntimeException("plain")));
        assertFalse(ChainVerifyProbe.reachesSink(new RuntimeException("plain"),
                "java.lang.Runtime", "exec"));
        assertFalse(ChainVerifyProbe.entryReached(new RuntimeException("plain"),
                "app.Entry", "run"));
        assertEquals(null, ChainVerifyProbe.newCollection(String.class));
        assertTrue(ChainVerifyProbe.newCollection(Map.class) instanceof java.util.HashMap);
    }

    @Test
    void verifierSelectionAndLifecycleAreDeterministicForEmptyAndInvalidInputs() {
        ParallelVerifier verifier = new ParallelVerifier(Path.of("."), List.of(), null);
        try {
            assertEquals(List.of(), verifier.selectChains(List.of(), 0));
            assertEquals(List.of(), verifier.selectChains(null, 20));
            assertEquals(List.of(), verifier.verifyAll(List.of()));
            assertEquals("NOT_RUN", verifier.capability());
            assertTrue(verifier.hostCapability() != null && !verifier.hostCapability().isBlank());
            assertDoesNotThrow(verifier::cleanup);
            assertDoesNotThrow(verifier::cleanup);
        } finally {
            verifier.cleanup();
        }
    }

    @Test
    void verifierRejectsMissingTargetAsAnExplicitConstructionError() {
        try {
            new ParallelVerifier(null, List.of(), null);
        } catch (NullPointerException expected) {
            // Current public constructor behavior is recorded before the P2 owner split.
            return;
        }
        throw new AssertionError("null target must remain an explicit construction error until the API is changed");
    }
}
