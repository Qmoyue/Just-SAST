package io.just.sast.blackboard;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Contract tests for the six-axis state seam; no report wording or private container is used. */
class FindingStateContractTest {

    @Test
    void axesAreClosedAndStable() {
        assertArrayEquals(new String[]{"NO_APPLICATION_ENTRY", "APPLICATION_ENTRY", "EXTERNAL_ENTRY"},
                java.util.Arrays.stream(FindingState.EntryStatus.values()).map(Enum::name).toArray());
        assertArrayEquals(new String[]{"ENTRY_IDENTIFIED", "BOUNDARY_REACHED", "DEPENDENCY_JOINED",
                        "IMPACT_CHAIN_COMPLETE"},
                java.util.Arrays.stream(FindingState.ChainProgress.values()).map(Enum::name).toArray());
        assertTrue(java.util.Arrays.stream(FindingState.Verification.values())
                .anyMatch(value -> value == FindingState.Verification.CONTRADICTION_OBSERVED));
    }

    @Test
    void onlyExternalCompleteSatImpactIsDefaultEligible() {
        FindingState state = new FindingState(FindingState.EntryStatus.EXTERNAL_ENTRY,
                FindingState.ChainProgress.IMPACT_CHAIN_COMPLETE, FindingState.Feasibility.SAT,
                FindingState.Completeness.COMPLETE, FindingState.Verification.UNKNOWN,
                FindingState.Risk.HIGH);
        assertTrue(state.defaultFindingEligible());
        assertEquals(FindingState.Eligibility.ELIGIBLE_APPLICATION_CHAIN, state.eligibility());
        assertTrue(state.applicationAnchored());
        assertTrue(state.dependencyJoined());
    }

    @Test
    void applicationEntryWithoutExternalControlIsNotDefaultFinding() {
        FindingState state = new FindingState(FindingState.EntryStatus.APPLICATION_ENTRY,
                FindingState.ChainProgress.IMPACT_CHAIN_COMPLETE, FindingState.Feasibility.SAT,
                FindingState.Completeness.COMPLETE, FindingState.Verification.NOT_ATTEMPTED,
                FindingState.Risk.HIGH);
        assertEquals(FindingState.Eligibility.APPLICATION_ENTRY_NOT_EXTERNAL, state.eligibility());
    }

    @Test
    void dynamicUnknownDoesNotEraseStaticFacts() {
        FindingState state = new FindingState(FindingState.EntryStatus.EXTERNAL_ENTRY,
                FindingState.ChainProgress.IMPACT_CHAIN_COMPLETE, FindingState.Feasibility.SAT,
                FindingState.Completeness.COMPLETE, FindingState.Verification.UNSUPPORTED,
                FindingState.Risk.CRITICAL);
        assertTrue(state.defaultFindingEligible());
    }

    @Test
    void intermediateAndKernelStatesRemainRepresentable() {
        FindingState partial = new FindingState(
                FindingState.EntryStatus.EXTERNAL_ENTRY,
                FindingState.ChainProgress.IMPACT_CHAIN_COMPLETE, FindingState.Feasibility.UNKNOWN,
                FindingState.Completeness.PARTIAL, FindingState.Verification.FAILED,
                FindingState.Risk.HIGH);
        assertEquals(FindingState.Eligibility.CONSTRAINTS_UNKNOWN, partial.eligibility());

        FindingState kernel = new FindingState(
                FindingState.EntryStatus.NO_APPLICATION_ENTRY,
                FindingState.ChainProgress.DEPENDENCY_JOINED, FindingState.Feasibility.SAT,
                FindingState.Completeness.COMPLETE, FindingState.Verification.NOT_ATTEMPTED,
                FindingState.Risk.HIGH);
        assertEquals(FindingState.Eligibility.NO_APPLICATION_ENTRY, kernel.eligibility());
    }

    @Test
    void invalidDefaultExportCombinationsFailClosed() {
        assertThrows(IllegalStateException.class, () -> new FindingState(
                FindingState.EntryStatus.APPLICATION_ENTRY,
                FindingState.ChainProgress.IMPACT_CHAIN_COMPLETE, FindingState.Feasibility.SAT,
                FindingState.Completeness.COMPLETE, FindingState.Verification.NOT_ATTEMPTED,
                FindingState.Risk.HIGH).requireDefaultFinding());
        assertThrows(IllegalStateException.class, () -> new FindingState(
                FindingState.EntryStatus.EXTERNAL_ENTRY,
                FindingState.ChainProgress.IMPACT_CHAIN_COMPLETE, FindingState.Feasibility.UNKNOWN,
                FindingState.Completeness.COMPLETE, FindingState.Verification.NOT_ATTEMPTED,
                FindingState.Risk.HIGH).requireDefaultFinding());
        assertThrows(IllegalStateException.class, () -> new FindingState(
                FindingState.EntryStatus.EXTERNAL_ENTRY,
                FindingState.ChainProgress.DEPENDENCY_JOINED, FindingState.Feasibility.SAT,
                FindingState.Completeness.PARTIAL,
                FindingState.Verification.CONTRADICTION_OBSERVED, FindingState.Risk.HIGH)
                .requireDefaultFinding());
    }

    @Test
    void legacyAdapterIsStrictAndStable() {
        FindingState state = FindingState.fromLegacy("external-entry", "impact-chain-complete",
                "sat", "complete", "dynamic-segment-confirmed", "high");
        assertEquals(FindingState.Eligibility.ELIGIBLE_APPLICATION_CHAIN, state.eligibility());
        assertThrows(IllegalStateException.class, () -> FindingState.fromLegacy(
                "application-entry", "impact-chain-complete", "unsat", "complete",
                "unknown", "high").requireDefaultFinding());
    }
}
