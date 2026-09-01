package io.just.sast.blackboard;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ConstructionSummaryTest {

    @Test
    void separatesPlanShapeTriggerAndSinkControlEvidence() {
        Chain chain = new Chain("RULE", "COMMAND_EXEC", "HIGH", "app/Entry", "readObject",
                "readObject", "java/lang/Runtime", "exec", List.of(new ChainHop(
                "app/Entry", "readObject", "java/lang/Runtime", "exec", HopKind.DIRECT_CALL,
                null, "test", "(Ljava/lang/String;)Ljava/lang/Process;", 0)), 0,
                "(Ljava/lang/String;)Ljava/lang/Process;", "TERMINAL",
                new ObjectGraphPlan(List.of(new ObjectGraphPlan.Node("entry", "app/Entry",
                        ObjectGraphPlan.NodeKind.ALLOCATE, List.of())), List.of()));
        VerificationSummary.ChainResult result = new VerificationSummary.ChainResult(
                1, chain.key(), "SINK_BLOCKED", "canary", "HIGH", 90, 1, 2,
                "SINK_CANARY_BOUNDARY", "backend", "jdk", "policy", true, true, "CLEAN");

        ConstructionSummary summary = ConstructionSummary.summarize(chain, List.of(), result);

        assertEquals("DECLARED_SHAPE", summary.typeStatus());
        assertEquals("NO_FIELD_ASSIGNMENTS", summary.fieldStatus());
        assertEquals("DYNAMIC_CANARY_BOUNDARY", summary.triggerStatus());
        assertEquals("DYNAMIC_CANARY_REACHED", summary.sinkControlStatus());
        assertTrue(summary.reasons().contains("SINK_DISTORTED:SINK_BLOCKED"));
    }

    @Test
    void capabilitySinkCannotBecomeTerminalControlEvidence() {
        Chain chain = new Chain("RULE", "CLASSLOAD", "MEDIUM", "app/Entry", "readObject",
                "readObject", "java/lang/Class", "forName", List.of(), 0,
                "(Ljava/lang/String;)Ljava/lang/Class;", "CAPABILITY");

        ConstructionSummary summary = ConstructionSummary.summarize(chain, List.of(), null);

        assertEquals("CAPABILITY_ONLY", summary.sinkControlStatus());
        assertTrue(summary.reasons().contains("CAPABILITY_SINK"));
    }

    @Test
    void rerootedOrComposedChainsMustRetainTheDeclaredPlan() {
        ObjectGraphPlan plan = new ObjectGraphPlan(
                List.of(new ObjectGraphPlan.Node("entry", "app/Entry",
                        ObjectGraphPlan.NodeKind.ALLOCATE, List.of())), List.of());
        Chain original = new Chain("RULE", "COMMAND_EXEC", "HIGH", "app/Entry", "readObject",
                "readObject", "java/lang/Runtime", "exec", List.of(), 0,
                "()V", "TERMINAL", plan);
        Chain copied = new Chain(original.ruleId(), original.category(), original.severity(),
                "app/Outer", "readObject", "readObject", original.sinkClass(),
                original.sinkMethod(), original.hops(), original.unresolvedHops(),
                original.sinkDescriptor(), original.sinkRole(), original.constructionPlan());

        assertEquals(plan.fingerprint(), copied.constructionPlan().fingerprint());
        assertEquals("DECLARED_SHAPE",
                ConstructionSummary.summarize(copied, List.of(), null).typeStatus());
    }
}
