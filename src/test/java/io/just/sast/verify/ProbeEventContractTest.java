package io.just.sast.verify;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Probe event contract keeps boundary, safe terminal and unknown states distinct. */
class ProbeEventContractTest {

    @Test
    void mapsWireStatusesToClosedGateKindsWithoutOverclaiming() {
        ProbeEvent ready = ProbeEvent.fromWire("SANDBOX_READY: backend");
        assertEquals(ProbeEvent.Kind.ISOLATION_READY, ready.kind());
        assertFalse(ready.terminal());

        ProbeEvent boundary = ProbeEvent.fromWire("SINK_BLOCKED: sink");
        assertEquals(ProbeEvent.Kind.SINK_BOUNDARY, boundary.kind());
        assertTrue(boundary.terminal());
        assertFalse(boundary.targetCodeExecuted());

        ProbeEvent safe = ProbeEvent.fromWire("SINK_EXECUTED_SAFE: call=1");
        assertEquals(ProbeEvent.Kind.SAFE_TERMINAL, safe.kind());
        assertTrue(safe.targetCodeExecuted());

        ProbeEvent mock = ProbeEvent.fromWire("SAFE_EFFECT_OBSERVED: inert");
        assertFalse(mock.targetCodeExecuted());
        assertEquals(ProbeEvent.Kind.SAFE_TERMINAL, mock.kind());
    }

    @Test
    void malformedStatusIsTerminalUnknownAndBounded() {
        ProbeEvent event = ProbeEvent.fromWire("x\ny");
        assertEquals(ProbeEvent.Kind.UNKNOWN, event.kind());
        assertTrue(event.terminal());
        assertEquals("x y", event.wireStatus());

        ProbeEvent nullEvent = ProbeEvent.fromWire(null);
        assertEquals(ProbeEvent.Kind.ISOLATION_FAILURE, nullEvent.kind());
        assertTrue(nullEvent.wireStatus().startsWith("UNTESTABLE"));
    }
}
