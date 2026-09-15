package io.just.sast.analysis.taint;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;

/** Closed-state contract for path/filter decisions. */
class FilterAnalysisContractTest {

    @Test
    void proofRejectsOnlyWhenTheTypedStatusIsExplicit() {
        FilterAnalysis.Decision rejected = FilterAnalysis.cfgPath(true, false);
        FilterAnalysis.Decision budget = FilterAnalysis.cfgPath(false, true);
        FilterAnalysis.Decision kept = FilterAnalysis.cfgPath(false, false);

        assertTrue(rejected.rejectsPath());
        assertFalse(budget.rejectsPath());
        assertTrue(budget.isUnknown());
        assertFalse(kept.isUnknown());
        assertEquals(FilterAnalysis.Status.PROVEN_RETAINED, kept.status());
        assertEquals("CFG_EXACT_PATH_UNREACHABLE", rejected.reasonCode());
    }

    @Test
    void exceptionAndReflectiveFiltersRemainIndependentAxes() {
        FilterAnalysis.Decision exception = FilterAnalysis.exceptionHandler(true);
        FilterAnalysis.Decision reflection = FilterAnalysis.reflectiveInvocation(false);

        assertEquals(FilterAnalysis.Kind.EXCEPTION_HANDLER, exception.kind());
        assertEquals(FilterAnalysis.Kind.REFLECTIVE_INVOCATION, reflection.kind());
        assertTrue(exception.rejectsPath());
        assertTrue(reflection.rejectsPath());
        assertEquals("REFLECTIVE_PRECONDITION_UNSAT", reflection.reasonCode());
    }

    @Test
    void malformedReasonIsClosedAndNormalized() {
        FilterAnalysis.Decision unknown = FilterAnalysis.unknown(null, "  unsupported_filter  ");
        assertEquals(FilterAnalysis.Kind.CFG_PATH, unknown.kind());
        assertEquals(FilterAnalysis.Status.UNKNOWN, unknown.status());
        assertEquals("UNSUPPORTED_FILTER", unknown.reasonCode());
        assertTrue(unknown.preservesPath());
    }

    @Test
    void allNonRejectingStatesPreserveCandidatesAndEvidenceIsClosed() {
        assertTrue(FilterAnalysis.cfgPath(false, false, false).preservesPath());
        assertEquals(FilterAnalysis.Status.UNKNOWN,
                FilterAnalysis.cfgPath(false, false, false).status());
        assertEquals(FilterAnalysis.Status.UNKNOWN,
                FilterAnalysis.reflectiveInvocation(true).status());

        FilterAnalysis.Evidence evidence = new FilterAnalysis.Evidence(
                FilterAnalysis.Kind.CFG_PATH, "fixture/Host#run()V@3",
                FilterAnalysis.Status.BUDGET_EXCEEDED, " budget ", "domain", "semantic",
                4, 3, 2, 1, 5, 7);
        assertEquals("BUDGET", evidence.reasonCode());
        assertEquals("fixture/Host#run()V@3", evidence.location());
        assertEquals(5L, evidence.expanded());
    }
}
