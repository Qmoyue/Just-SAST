package io.just.sast.blackboard;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** Sink risk is a shared rule/chain contract, not a verifier-only heuristic. */
class SinkRiskTest {

    @Test
    void mechanicalDangerCannotBeDowngradedByRuleMetadata() {
        assertEquals(SinkRisk.HIGH_RISK_TERMINAL,
                SinkRisk.resolve(SinkRisk.SAFE_CALLABLE, "NATIVE",
                        "java/lang/System", "loadLibrary"));
        assertEquals(SinkRisk.HIGH_RISK_TERMINAL,
                SinkRisk.resolve(SinkRisk.CONTROLLED_EFFECT, "JNDI",
                        "javax/naming/Context", "lookup"));
    }

    @Test
    void controlledEndpointsMayUseDeclaredSafePolicy() {
        assertEquals(SinkRisk.CONTROLLED_EFFECT,
                SinkRisk.resolve(null, "COMMAND", "java/lang/Runtime", "exec"));
        assertEquals(SinkRisk.SAFE_CALLABLE,
                SinkRisk.resolve(SinkRisk.SAFE_CALLABLE, "APPLICATION_BODY",
                        "fixture/Body", "sink"));
    }

    @Test
    void unknownEndpointDefaultsToHighRiskAndInvalidMetadataFails() {
        assertEquals(SinkRisk.HIGH_RISK_TERMINAL,
                SinkRisk.resolve(null, "custom", "example/Unknown", "call"));
        assertThrows(IllegalArgumentException.class, () -> SinkRisk.parse("unsafe-ish"));
    }
}
