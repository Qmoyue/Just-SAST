package io.just.sast.blackboard;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class VerificationDisclosureContractTest {

    @Test
    void staticOnlyDisclosureCannotClaimTargetExecution() {
        VerificationSummary summary = VerificationSummary.empty("DISABLED", 20);

        VerificationSummary.SafetyDisclosure disclosure = summary.safetyDisclosure();

        assertEquals("STATIC_ONLY", disclosure.verificationMode());
        assertFalse(disclosure.targetCodeExecutionPossible());
        assertEquals("NO", disclosure.targetCodeExecuted());
        assertTrue(disclosure.resourceContainmentOnly());
        assertFalse(disclosure.filesystemIsolation());
        assertFalse(disclosure.networkIsolation());
        assertTrue(disclosure.recommendedForUntrustedArtifacts());
        assertEquals("NOT_REQUESTED", disclosure.isolationStatus());
        assertTrue(disclosure.failClosedOnIsolationFailure());
    }

    @Test
    void staticOnlyLabelUsedByScanPipelineHasTheSameDisclosure() {
        VerificationSummary.SafetyDisclosure disclosure =
                VerificationSummary.empty("STATIC_ONLY", 0).safetyDisclosure();

        assertEquals("STATIC_ONLY", disclosure.verificationMode());
        assertFalse(disclosure.targetCodeExecutionPossible());
        assertEquals("NO", disclosure.targetCodeExecuted());
        assertTrue(disclosure.recommendedForUntrustedArtifacts());
    }

    @Test
    void autoDisclosureRequiresTrustedTargetAndPreservesIsolationUnknown() {
        VerificationSummary summary = new VerificationSummary(
                "UNTESTABLE", 20, 1, 0, 1, Map.of("UNTESTABLE", 1), Map.of(),
                List.of(new VerificationSummary.ChainResult(1, "entry|sink", "UNTESTABLE",
                        "SANDBOX_UNAVAILABLE:JOB_OBJECT_REQUIRED", "UNKNOWN", 0, 1, 2)),
                "WINDOWS_JOB_OBJECT_JVM_POLICY", "17.0.19", "policy", false, false,
                "CLEANUP_BEST_EFFORT");

        VerificationSummary.SafetyDisclosure disclosure = summary.safetyDisclosure();

        assertEquals("AUTO", disclosure.verificationMode());
        assertTrue(disclosure.targetCodeExecutionPossible());
        assertEquals("NO", disclosure.targetCodeExecuted());
        assertEquals("TRUSTED_LOCAL_TARGET_REQUIRED", disclosure.targetTrust());
        assertEquals("WINDOWS_JOB_OBJECT", disclosure.isolationBackend());
        assertEquals("UNAVAILABLE", disclosure.isolationStatus());
        assertFalse(disclosure.dangerousSinkExecuted());
        assertFalse(disclosure.recommendedForUntrustedArtifacts());
    }

    @Test
    void observedPrefixIsExecutionEvidenceButNotDangerousSinkExecution() {
        VerificationSummary summary = new VerificationSummary(
                "WINDOWS_JOB_OBJECT", 1, 1, 0, 1, Map.of("SINK_BLOCKED", 1), Map.of(),
                List.of(new VerificationSummary.ChainResult(1, "entry|sink", "SINK_BLOCKED",
                        "canary", "HIGH", 19, 1, 3, "SINK_CANARY_BOUNDARY",
                        "WINDOWS_JOB_OBJECT", "17.0.19", "policy", true, true,
                        "CLEANED")),
                "WINDOWS_JOB_OBJECT", "17.0.19", "policy", true, true, "CLEANED");

        VerificationSummary.SafetyDisclosure disclosure = summary.safetyDisclosure();

        assertTrue(disclosure.targetCodeExecutionPossible());
        assertEquals("YES", disclosure.targetCodeExecuted());
        assertEquals("READY", disclosure.isolationStatus());
        assertFalse(disclosure.dangerousSinkExecuted());
    }
}
