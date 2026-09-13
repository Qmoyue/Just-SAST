package io.just.sast.blackboard;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

/** Contract tests for the sole legacy verification-detail compatibility boundary. */
class VerificationDetailAdapterContractTest {
    @Test
    void legacyFieldsMapToClosedOutcomeWithoutPromotingABoundary() {
        VerificationOutcome outcome = VerificationOutcome.fromLegacy(
                "SINK_BLOCKED",
                "requested_mode=LIGHT_SAFE_CALL;effective_mode=BOUNDARY;fallback=none;",
                null);

        assertEquals(VerificationOutcome.Status.SINK_BLOCKED, outcome.status());
        assertEquals("SINK_CANARY_BOUNDARY", outcome.evidence());
        assertEquals("LIGHT_SAFE_CALL", outcome.requestedMode());
        assertEquals("BOUNDARY", outcome.effectiveMode());
        assertEquals("none", outcome.fallback());
        assertEquals(VerificationOutcome.Scope.BOUNDARY_ONLY, outcome.scope());
        assertEquals(VerificationOutcome.StopReason.SINK_BOUNDARY_CANARY,
                outcome.stopReason());
        assertEquals(VerificationOutcome.Stage.SINK_BOUNDARY, outcome.lastConfirmedStage());
        assertFalse(outcome.terminalExecuted());
    }

    @Test
    void unknownAndMalformedWireValuesStayUnknownAndDoNotBecomePositiveEvidence() {
        VerificationOutcome unknown = VerificationDetailAdapter.fromLegacy(
                "future-status", "prefixrequested_mode=SAFE;requested_mode=;", null);
        assertEquals(VerificationOutcome.Status.UNKNOWN, unknown.status());
        assertEquals("UNKNOWN", unknown.evidence());
        assertEquals("UNKNOWN", unknown.requestedMode());
        assertEquals(VerificationOutcome.Scope.NONE, unknown.scope());
        assertEquals(VerificationOutcome.StopReason.NONE, unknown.stopReason());
        assertFalse(unknown.terminalExecuted());

        VerificationOutcome explicit = VerificationDetailAdapter.fromLegacy(
                "PARTIAL", "requested_mode=BOUNDARY;", "EXPLICIT_SEGMENT_OBSERVED");
        assertEquals("EXPLICIT_SEGMENT_OBSERVED", explicit.evidence());
        assertEquals(VerificationOutcome.Status.PARTIAL, explicit.status());
        assertEquals(VerificationOutcome.Stage.NONE, explicit.lastConfirmedStage());

        assertEquals(VerificationOutcome.Status.SAFE_EFFECT_OBSERVED,
                VerificationOutcome.Status.fromWire("SAFE_SINK_EXECUTED"));
    }

    @Test
    void typedAttemptHasStableIdentityAndRejectsInvalidResourceMetadata() {
        VerificationAttempt first = VerificationAttempt.fromLegacy(
                "entry-to-terminal", 1, 12L, "TIMEOUT", "8s", null);
        VerificationAttempt second = VerificationAttempt.fromLegacy(
                "entry-to-terminal", 1, 99L, "TIMEOUT", "different-detail", null);
        assertEquals(first.id(), second.id(), "attempt identity is static chain plus ordinal");
        assertEquals(VerificationOutcome.Status.TIMEOUT, first.outcome().status());
        assertEquals(VerificationOutcome.StopReason.PROCESS_TIMEOUT,
                first.outcome().stopReason());
        assertNotEquals(first.durationMs(), second.durationMs());
        assertThrows(IllegalArgumentException.class,
                () -> VerificationAttempt.fromLegacy("entry", 0, 1L, "FAILED", "", null));
        assertThrows(IllegalArgumentException.class,
                () -> VerificationAttempt.fromLegacy("entry", 1, -1L, "FAILED", "", null));
    }

    @Test
    void wireStatusIsRetainedWhileTypedOutcomeOwnsPolicy() {
        VerificationOutcome typed = new VerificationOutcome(
                VerificationOutcome.Status.SINK_BLOCKED,
                "typed-detail", "SINK_CANARY_BOUNDARY", "LIGHT_SAFE_CALL", "BOUNDARY",
                "none", VerificationOutcome.Scope.BOUNDARY_ONLY, "HIGH_RISK_TERMINAL", false,
                VerificationOutcome.StopReason.SINK_BOUNDARY_CANARY,
                VerificationOutcome.Stage.SINK_BOUNDARY);
        VerificationSummary.ChainResult result = new VerificationSummary.ChainResult(
                1, "chain", "future-status", "HIGH", 90, 1, 4L, typed,
                "WINDOWS_JOB_OBJECT", "17.0.19", "policy", false, true, "CLEANED");

        assertEquals("future-status", result.status(), "legacy wire value must round-trip");
        assertEquals(VerificationOutcome.Status.SINK_BLOCKED, result.outcomeStatus(),
                "policy must consume the closed typed outcome");
        assertEquals("SINK_CANARY_BOUNDARY", result.evidence());
        assertEquals(VerificationOutcome.Scope.BOUNDARY_ONLY,
                VerificationOutcome.Scope.fromWire(result.verificationScope()));
    }

    @Test
    void dynamicUnknownIsAdditiveAndCannotRewriteStaticFindingAxes() {
        FindingState staticState = new FindingState(
                FindingState.EntryStatus.EXTERNAL_ENTRY,
                FindingState.ChainProgress.IMPACT_CHAIN_COMPLETE,
                FindingState.Feasibility.SAT,
                FindingState.Completeness.COMPLETE,
                FindingState.Verification.NOT_ATTEMPTED,
                FindingState.Risk.HIGH);
        VerificationAttempt attempt = VerificationAttempt.fromLegacy(
                "application-chain", 1, 10L, "UNTESTABLE", "PROCESS_TIMEOUT", null);

        assertTrue(staticState.defaultFindingEligible());
        assertEquals(VerificationOutcome.Status.UNTESTABLE, attempt.outcome().status());
        assertEquals(FindingState.Eligibility.ELIGIBLE_APPLICATION_CHAIN,
                staticState.eligibility());
    }

    @Test
    void legacyNoteStatusUsesClosedPrecedenceAtOneBoundary() {
        assertEquals("SINK_BLOCKED", VerificationDetailAdapter.statusFromLegacyNotes(
                List.of("verify:executed", "verify:pre-sink-confirmed", "verify:sink-blocked")));
        assertEquals("PARTIAL", VerificationDetailAdapter.statusFromLegacyNotes(
                List.of("degrade:partial-path")));
        assertEquals("", VerificationDetailAdapter.statusFromLegacyNotes(
                List.of("verify:future-status", "degrade:unknown")));
    }
}
