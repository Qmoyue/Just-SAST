package io.just.sast.chain;

import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.HopKind;
import io.just.sast.blackboard.VerificationSummary;
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
        assertEquals("RECEIVER_EXACT", ChainPrecision.assess(exact, List.of())
                .dispatchPrecision());
        assertEquals("SEALED_SET", ChainPrecision.assess(sealed, List.of()).controllability());
        assertEquals("SEALED_SET", ChainPrecision.assess(sealed, List.of())
                .dispatchPrecision());
        assertEquals("CHA_BOUNDED", ChainPrecision.assess(cha, List.of()).controllability());
        assertEquals("CHA_BOUNDED", ChainPrecision.assess(cha, List.of())
                .dispatchPrecision());
    }

    @Test
    void unknownReceiverEvidenceRemainsRecallPreservingButNotHighConfidence() {
        Chain chain = virtualChain("receiver-unknown");

        ChainPrecision.Assessment assessment = ChainPrecision.assess(chain, List.of());

        assertEquals("UNKNOWN", assessment.controllability());
        assertEquals("UNKNOWN", assessment.dispatchPrecision());
        assertEquals("PARTIAL", assessment.completeness());
    }

    @Test
    void dynamicAndFieldDimensionsExposeBoundedEvidence() {
        Chain chain = new Chain("R", "REFLECT", "HIGH", "app/Entry", "readObject",
                "readObject", "java/lang/reflect/Method", "invoke", List.of(
                new ChainHop("app/Entry", "readObject", "app/Holder", "call",
                        HopKind.VIRTUAL_DISPATCH, null, "points-to-bounded", "()V", null),
                new ChainHop("app/Entry", "readObject", "app/Holder", "value",
                        HopKind.FIELD_FLOW, "value", "reflective-recovered", "", null,
                        "app/Holder")), 0, "()V", "TERMINAL");
        VerificationSummary.ChainResult result = new VerificationSummary.ChainResult(
                1, chain.key(), "SAFE_EFFECT_OBSERVED", "adapter", "DEGRADED", 3, 1,
                2, "SAFE_EFFECT_OBSERVED", "NSJAIL", "17", "policy", true, true, "CLEAN");

        ChainPrecision.Assessment assessment = ChainPrecision.assess(chain,
                List.of("verify:safe-effect-observed"), result);

        assertEquals("POINTS_TO_BOUNDED", assessment.controllability());
        assertEquals("POINTS_TO_BOUNDED", assessment.dispatchPrecision());
        assertEquals("EXACT_DECLARATION", assessment.fieldPrecision());
        assertEquals("RECOVERED_BOUNDED", assessment.reflectionPrecision());
        assertEquals("SAFE_EFFECT_DISTORTED", assessment.runtime());
        assertEquals("OS_STRICT_ATTESTED", assessment.isolation());
        assertTrue(assessment.reasons().contains("SAFE_ADAPTER_DISTORTED"));
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
    void legacySafeSinkLabelRemainsDistortedAndNonReflectiveIsNotPenalized() {
        Chain chain = new Chain("R", "COMMAND_EXEC", "HIGH", "app/Entry", "readObject",
                "readObject", "java/lang/Runtime", "exec", List.of(
                new ChainHop("app/Entry", "readObject", "java/lang/Runtime", "exec",
                        HopKind.DIRECT_CALL, null, "direct", "()V", null)), 0);
        VerificationSummary.ChainResult result = new VerificationSummary.ChainResult(
                1, chain.key(), "SAFE_SINK_EXECUTED", "legacy", "DEGRADED", 1, 1,
                1, "SAFE_EFFECT_OBSERVED", "LEGACY", "8", "policy", true, true, "CLEAN");

        ChainPrecision.Assessment assessment = ChainPrecision.assess(chain, List.of(), result);

        assertEquals("SAFE_EFFECT_DISTORTED", assessment.runtime());
        assertEquals("NOT_APPLICABLE", assessment.reflectionPrecision());
        assertTrue(assessment.reasons().contains("SAFE_ADAPTER_DISTORTED"));
    }

    @Test
    void highConfidenceRequiresAuthenticatedBoundaryStrictIsolationAndCompleteConstruction() {
        Chain chain = new Chain("R", "COMMAND_EXEC", "HIGH", "app/Entry", "readObject",
                "readObject", "java/lang/Runtime", "exec", List.of(
                new ChainHop("app/Entry", "readObject", "java/lang/Runtime", "exec",
                        HopKind.DIRECT_CALL, null, "direct", "(Ljava/lang/String;)Ljava/lang/Process;", 0)),
                0, "(Ljava/lang/String;)Ljava/lang/Process;", "TERMINAL");
        VerificationSummary.ChainResult boundary = new VerificationSummary.ChainResult(
                1, chain.key(), "SINK_BLOCKED", "canary", "FEASIBLE", 10, 1, 3,
                "SINK_CANARY_BOUNDARY", "LINUX_NSJAIL_STRICT", "17", "policy", false,
                true, "CLEANED");

        assertTrue(ChainPrecision.isHighConfidence(chain,
                List.of("verify:constructible", "verify:sink-blocked"), boundary));
        assertFalse(ChainPrecision.isHighConfidence(chain,
                List.of("verify:constructible", "verify:safe-effect-observed"),
                new VerificationSummary.ChainResult(1, chain.key(), "SAFE_EFFECT_OBSERVED",
                        "adapter", "DEGRADED", 3, 1, 3, "SAFE_EFFECT_OBSERVED",
                        "LINUX_NSJAIL_STRICT", "17", "policy", true, true, "CLEANED")));
        assertFalse(ChainPrecision.isHighConfidence(chain,
                List.of("verify:constructible", "degrade:partial-path"), boundary));
    }

    private static Chain virtualChain(String reason) {
        return new Chain("R", "DISPATCH", "HIGH", "app/Entry", "readObject",
                "readObject", "app/Target", "run", List.of(
                new ChainHop("app/Entry", "readObject", "app/Target", "run",
                        HopKind.VIRTUAL_DISPATCH, null, reason, "()V", null)), 0,
                "()V", "TERMINAL");
    }
}
