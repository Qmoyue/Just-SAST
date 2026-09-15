package io.just.sast.chain;

import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.HopKind;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ChainPrecisionTest {

    @Test
    void directChainHasConcreteCompleteStaticDimensions() {
        Chain chain = new Chain("R", "COMMAND_EXEC", "HIGH", "app/Entry", "readObject",
                "readObject", "java/lang/Runtime", "exec", List.of(
                new ChainHop("app/Entry", "readObject", "java/lang/Runtime", "exec",
                        HopKind.DIRECT_CALL, null, "direct", "(Ljava/lang/String;)Ljava/lang/Process;", 0)),
                0, "(Ljava/lang/String;)Ljava/lang/Process;", "TERMINAL");

        ChainPrecision.Assessment assessment = ChainPrecision.assess(chain, List.of());

        assertEquals("CONCRETE", assessment.controllability());
        assertEquals("EXACT", assessment.dispatchPrecision());
        assertEquals("NOT_APPLICABLE", assessment.fieldPrecision());
        assertEquals("NOT_APPLICABLE", assessment.reflectionPrecision());
        assertEquals("COMPLETE", assessment.completeness());
        assertTrue(assessment.compact().contains("controllability=CONCRETE"));
    }

    @Test
    void exactFieldFlowDoesNotPretendToBePointsToEvidence() {
        Chain chain = new Chain("R", "FIELD", "HIGH", "app/Entry", "readObject",
                "readObject", "app/Holder", "value", List.of(
                new ChainHop("app/Entry", "readObject", "app/Holder", "value",
                        HopKind.FIELD_FLOW, "value", "field-read", "Ljava/lang/Object;", null,
                        "app/Holder")), 0);

        ChainPrecision.Assessment assessment = ChainPrecision.assess(chain, List.of());

        assertEquals("CONCRETE", assessment.controllability());
        assertEquals("EXACT", assessment.dispatchPrecision());
        assertEquals("EXACT_DECLARATION", assessment.fieldPrecision());
    }

    @Test
    void receiverEvidenceUsesStableNarrowToBroadLabels() {
        Chain exact = virtualChain("receiver-exact");
        Chain sealed = virtualChain("receiver-sealed-set");
        Chain cha = virtualChain("receiver-cha-bounded");

        assertEquals("CONCRETE", ChainPrecision.assess(exact, List.of()).controllability());
        assertEquals("RECEIVER_EXACT", ChainPrecision.assess(exact, List.of()).dispatchPrecision());
        assertEquals("SEALED_SET", ChainPrecision.assess(sealed, List.of()).controllability());
        assertEquals("SEALED_SET", ChainPrecision.assess(sealed, List.of()).dispatchPrecision());
        assertEquals("CHA_BOUNDED", ChainPrecision.assess(cha, List.of()).controllability());
        assertEquals("CHA_BOUNDED", ChainPrecision.assess(cha, List.of()).dispatchPrecision());
    }

    @Test
    void unknownReceiverEvidenceRemainsRecallPreservingButNotHighConfidence() {
        Chain chain = virtualChain("receiver-unknown");

        ChainPrecision.Assessment assessment = ChainPrecision.assess(chain, List.of());

        assertEquals("UNKNOWN", assessment.controllability());
        assertEquals("UNKNOWN", assessment.dispatchPrecision());
        assertEquals("PARTIAL", assessment.completeness());
        assertFalse(ChainPrecision.isHighConfidence(chain, List.of("static:constructible")));
    }

    @Test
    void staticReflectionAndFieldDimensionsExposeBoundedEvidence() {
        Chain chain = new Chain("R", "REFLECT", "HIGH", "app/Entry", "readObject",
                "readObject", "java/lang/reflect/Method", "invoke", List.of(
                new ChainHop("app/Entry", "readObject", "app/Holder", "call",
                        HopKind.VIRTUAL_DISPATCH, null, "points-to-bounded", "()V", null),
                new ChainHop("app/Entry", "readObject", "app/Holder", "value",
                        HopKind.FIELD_FLOW, "value", "reflective-recovered", "", null,
                        "app/Holder")), 0, "()V", "TERMINAL");

        ChainPrecision.Assessment assessment = ChainPrecision.assess(chain,
                List.of("static:constructible"));

        assertEquals("POINTS_TO_BOUNDED", assessment.controllability());
        assertEquals("POINTS_TO_BOUNDED", assessment.dispatchPrecision());
        assertEquals("EXACT_DECLARATION", assessment.fieldPrecision());
        assertEquals("RECOVERED_BOUNDED", assessment.reflectionPrecision());
        assertEquals("CONSTRUCTIBLE", assessment.construction());
        assertTrue(assessment.reasons().isEmpty());
    }

    @Test
    void budgetAndUnresolvedFactsCannotLookComplete() {
        Chain chain = new Chain("R", "REFLECT", "HIGH", "app/Entry", "readObject",
                "readObject", "java/lang/reflect/Method", "invoke", List.of(
                new ChainHop("app/Entry", "readObject", "java/lang/reflect/Method", "invoke",
                        HopKind.VIRTUAL_DISPATCH, null, "dispatch-budget", "()V", null)), 1);

        ChainPrecision.Assessment assessment = ChainPrecision.assess(chain,
                List.of("degrade:REFLECTION_BUDGET"));

        assertEquals("UNKNOWN", assessment.controllability());
        assertEquals("PARTIAL", assessment.completeness());
        assertTrue(assessment.reasons().contains("DISPATCH_BUDGET"));
        assertTrue(assessment.reasons().contains("REFLECTION_BUDGET"));
    }

    @Test
    void externalSerializedProxyIdentityCannotLookConcreteOrComplete() {
        Chain chain = new Chain("R", "COMMAND_EXEC", "HIGH", "app/Entry", "readObject",
                "readObject", "java/lang/Runtime", "exec", List.of(
                new ChainHop("app/Trigger", "readObject", "app/Handler", "invoke",
                        HopKind.VIRTUAL_DISPATCH, null, "serialized-proxy-interface",
                        "(Ljava/lang/Object;Ljava/lang/reflect/Method;[Ljava/lang/Object;)Ljava/lang/Object;",
                        null)), 0, "(Ljava/lang/String;)Ljava/lang/Process;", "TERMINAL");

        ChainPrecision.Assessment assessment = ChainPrecision.assess(chain, List.of());

        assertEquals("UNKNOWN", assessment.controllability());
        assertEquals("UNKNOWN", assessment.dispatchPrecision());
        assertEquals("UNKNOWN", assessment.reflectionPrecision());
        assertEquals("PARTIAL", assessment.completeness());
        assertTrue(assessment.reasons().contains("EXTERNAL_PROXY_OBJECT_IDENTITY_UNRESOLVED"));
    }

    @Test
    void staticHighConfidenceRequiresCompleteStaticEvidence() {
        Chain complete = new Chain("R", "COMMAND_EXEC", "HIGH", "app/Entry", "readObject",
                "readObject", "java/lang/Runtime", "exec", List.of(
                new ChainHop("app/Entry", "readObject", "java/lang/Runtime", "exec",
                        HopKind.DIRECT_CALL, null, "direct", "(Ljava/lang/String;)Ljava/lang/Process;", 0)),
                0, "(Ljava/lang/String;)Ljava/lang/Process;", "TERMINAL");

        assertTrue(ChainPrecision.isHighConfidence(complete, List.of("static:constructible")));
        assertFalse(ChainPrecision.isHighConfidence(complete, List.of("degrade:partial-path")));
        assertFalse(ChainPrecision.isHighConfidence(complete, List.of()));
    }

    private static Chain virtualChain(String reason) {
        return new Chain("R", "DISPATCH", "HIGH", "app/Entry", "readObject",
                "readObject", "app/Target", "run", List.of(
                new ChainHop("app/Entry", "readObject", "app/Target", "run",
                        HopKind.VIRTUAL_DISPATCH, null, reason, "()V", null)), 0,
                "()V", "TERMINAL");
    }
}
