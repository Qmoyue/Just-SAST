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
}
