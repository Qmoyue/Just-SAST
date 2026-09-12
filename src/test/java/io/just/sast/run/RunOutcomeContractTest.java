package io.just.sast.run;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Characterization contract for the single run-result owner. */
class RunOutcomeContractTest {

    @Test
    void exitReasonsPreserveThePublicProcessCodes() {
        assertEquals(0, ExitReason.OK.code());
        assertEquals(2, ExitReason.USAGE.code());
        assertEquals(3, ExitReason.INTERNAL.code());
        assertEquals(78, ExitReason.UNSUPPORTED_RUNTIME.code());
        assertEquals(ExitReason.INTERNAL, ExitReason.fromCode(99));
    }

    @Test
    void scanClassificationSeparatesPartialFromProcessFailure() {
        RunOutcome complete = RunOutcome.forScan("COMPLETE", "COMPLETE", List.of());
        RunOutcome partial = RunOutcome.forScan("PARTIAL", "COMPLETE", List.of());
        RunOutcome unknown = RunOutcome.forScan("COMPLETE", "UNKNOWN", List.of("TIMEOUT"));

        assertEquals(RunOutcome.Status.SUCCESS, complete.status());
        assertEquals(0, complete.exitCode());
        assertTrue(complete.cacheable());
        assertEquals(RunOutcome.Status.PARTIAL, partial.status());
        assertEquals(0, partial.exitCode());
        assertFalse(partial.cacheable());
        assertEquals(SupportStatus.UNKNOWN, unknown.supportStatus());
        assertTrue(unknown.reasonCodes().contains("ANALYSIS_STATUS_UNKNOWN"));
        assertTrue(unknown.reasonCodes().contains("DYNAMIC_INCOMPLETE"));
    }

    @Test
    void budgetStatesAreClosedAndCacheabilityFailsClosed() {
        assertTrue(InputBudgetResult.notRequested().reusable());
        assertTrue(InputBudgetResult.within(4, 4).reusable());
        assertFalse(InputBudgetResult.exhausted(4, 5, "limit").reusable());
        assertFalse(InputBudgetResult.invalid("bad").reusable());
        assertEquals(InputBudgetResult.State.EXHAUSTED,
                InputBudgetResult.within(4, 5).state());
        RunOutcome bounded = new RunOutcome(RunOutcome.Status.SUCCESS, ExitReason.OK,
                SupportStatus.SUPPORTED, InputBudgetResult.exhausted(1, 1, "limit"),
                List.of(), "");
        assertFalse(bounded.cacheable());
    }

    @Test
    void canonicalJsonIsStableAndContainsAllAxes() {
        RunOutcome outcome = RunOutcome.usage("bad argument", "quoted\nvalue");
        String json = outcome.toCanonicalJson();
        assertEquals(json, outcome.toCanonicalJson());
        assertTrue(json.contains("\"status\":\"USAGE_ERROR\""));
        assertTrue(json.contains("\"exit_reason\":\"USAGE\""));
        assertTrue(json.contains("\"exit_code\":2"));
        assertTrue(json.contains("\"support_status\":\"NOT_APPLICABLE\""));
        assertTrue(json.contains("BAD_ARGUMENT"));
        assertTrue(json.contains("quoted\\nvalue"));
    }

    @Test
    void performanceNoSamplesIsNotRunAndFailedGateIsInternal() {
        RunOutcome noSamples = RunOutcome.forPerformance(false, false);
        RunOutcome failed = RunOutcome.forPerformance(false, true);
        assertEquals(RunOutcome.Status.NOT_RUN, noSamples.status());
        assertEquals(3, noSamples.exitCode());
        assertEquals(RunOutcome.Status.FAILED, failed.status());
        assertEquals(ExitReason.INTERNAL, failed.exitReason());
    }
}
