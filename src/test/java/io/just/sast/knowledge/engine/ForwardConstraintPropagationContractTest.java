package io.just.sast.knowledge.engine;

import io.just.sast.analysis.taint.FilterAnalysis;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Constraint gates must distinguish proof of impossibility from an unknown/budget boundary. */
class ForwardConstraintPropagationContractTest {

    @Test
    void onlyProvenUnreachableBlocksAndUnknownRemainsConservative() {
        ForwardConstraintPropagation.Decision keep =
                ForwardConstraintPropagation.from(FilterAnalysis.cfgPath(false, false));
        ForwardConstraintPropagation.Decision unreachable =
                ForwardConstraintPropagation.from(FilterAnalysis.cfgPath(true, false));
        ForwardConstraintPropagation.Decision unknown =
                ForwardConstraintPropagation.from(FilterAnalysis.unknown(
                        FilterAnalysis.Kind.CFG_PATH, "CFG_UNKNOWN"));
        ForwardConstraintPropagation.Decision budget =
                ForwardConstraintPropagation.from(new FilterAnalysis.Decision(
                        FilterAnalysis.Kind.CFG_PATH, FilterAnalysis.Status.BUDGET_EXCEEDED,
                        "CFG_BUDGET"));

        assertEquals(ForwardConstraintPropagation.Status.PROPAGATE, keep.status());
        assertEquals(ForwardConstraintPropagation.Status.BLOCKED, unreachable.status());
        assertTrue(unreachable.blocksPath());
        assertEquals(ForwardConstraintPropagation.Status.UNKNOWN, unknown.status());
        assertTrue(unknown.preservesCandidate());
        assertEquals(ForwardConstraintPropagation.Status.UNKNOWN, budget.status());
        assertTrue(budget.preservesCandidate());
    }

    @Test
    void missingDecisionIsAnExplicitUnknownBoundary() {
        ForwardConstraintPropagation.Decision decision = ForwardConstraintPropagation.from(null);
        assertEquals(ForwardConstraintPropagation.Status.UNKNOWN, decision.status());
        assertEquals("FORWARD_CONSTRAINT_UNKNOWN", decision.reasonCode());
        assertTrue(decision.preservesCandidate());
    }
}
