package io.just.sast.analysis.taint;

import io.just.sast.model.InsnFact;
import io.just.sast.model.MethodInfo;
import io.just.sast.model.Op;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Modifier;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Contract tests for the typed method-summary projection. */
class OriginSummaryBuilderContractTest {

    @Test
    void completeSummaryIsDeterministicAndReportsBoundedRelationCounts() {
        MethodInfo method = new MethodInfo("pkg/T", "run", "()V", Modifier.PUBLIC,
                List.of(new InsnFact(0, Op.RETURN, List.of())), List.of(), false);
        ForwardOrigins.Result result = new ForwardOrigins.Result(
                Map.of(0, new ForwardOrigins.State(List.of(), List.of())),
                Map.of(), Map.of(), Map.of(), false, Set.of());

        OriginSummary summary = OriginSummaryBuilder.build(method, result);
        assertEquals("pkg/T#run()V", summary.methodKey());
        assertEquals(1, summary.stateCount());
        assertEquals(0, summary.arrayRelationCount());
        assertTrue(summary.complete());
        assertEquals(summary.canonical(), OriginSummaryBuilder.build(method, result).canonical());
    }

    @Test
    void incompleteReasonsAreSortedAndCannotBeHiddenByCompleteFlag() {
        ForwardOrigins.Result result = new ForwardOrigins.Result(Map.of(), Map.of(), Map.of(),
                Map.of(), true, Set.of("Z_REASON", "A_REASON"));
        OriginSummary summary = OriginSummaryBuilder.build("pkg/T#bad()V", result);

        assertFalse(summary.complete());
        assertEquals(Set.of("A_REASON", "Z_REASON"), summary.unresolvedReasons());
        assertTrue(summary.canonical().contains("reasons=A_REASON,Z_REASON"));
        assertNotEquals("", summary.methodKey());
    }

    @Test
    void missingResultIsAnExplicitIncompleteBoundary() {
        OriginSummary summary = OriginSummaryBuilder.build("pkg/T#missing()V", null);

        assertFalse(summary.complete());
        assertEquals(Set.of("MISSING_ORIGIN_RESULT"), summary.unresolvedReasons());
        assertTrue(summary.result().incomplete());
    }
}
