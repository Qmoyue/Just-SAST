package io.just.sast.verify;

/**
 * Closed interpretation of one probe-owned wire event.  This is a child-side event model only;
 * it never upgrades a static chain or claims a dangerous sink executed.  The raw wire status is
 * retained for the authenticated protocol and legacy report adapter.
 */
public record ProbeEvent(Kind kind, String wireStatus, boolean terminal,
                        boolean targetCodeExecuted) {

    public enum Kind {
        ISOLATION_READY,
        SINK_BOUNDARY,
        SAFE_TERMINAL,
        PREFIX_CONFIRMED,
        ISOLATION_FAILURE,
        PARTIAL,
        UNKNOWN
    }

    public ProbeEvent {
        kind = kind == null ? Kind.UNKNOWN : kind;
        wireStatus = normalize(wireStatus);
    }

    public static ProbeEvent fromWire(String status) {
        String wire = normalize(status);
        if (wire.startsWith("SANDBOX_READY")) {
            return new ProbeEvent(Kind.ISOLATION_READY, wire, false, false);
        }
        if (wire.startsWith("SINK_BLOCKED") || wire.startsWith("SINK_TRIGGERED")) {
            return new ProbeEvent(Kind.SINK_BOUNDARY, wire, true, false);
        }
        if (wire.startsWith("SINK_EXECUTED_SAFE") || wire.startsWith("JNI_EXECUTED_SAFE")
                || wire.startsWith("SAFE_EFFECT_OBSERVED")) {
            return new ProbeEvent(Kind.SAFE_TERMINAL, wire, true,
                    !wire.startsWith("SAFE_EFFECT_OBSERVED"));
        }
        if (wire.startsWith("CONCRETE_REACHED") || wire.startsWith("EXECUTED")) {
            return new ProbeEvent(Kind.PREFIX_CONFIRMED, wire, false, true);
        }
        if (wire.startsWith("SANDBOX_UNAVAILABLE") || wire.startsWith("UNTESTABLE")) {
            return new ProbeEvent(Kind.ISOLATION_FAILURE, wire, true, false);
        }
        if (wire.startsWith("PARTIAL_PATH")) {
            return new ProbeEvent(Kind.PARTIAL, wire, true, false);
        }
        return new ProbeEvent(Kind.UNKNOWN, wire, true, false);
    }

    private static String normalize(String value) {
        String safe = value == null ? "UNTESTABLE: null-status"
                : value.replace('\r', ' ').replace('\n', ' ');
        return safe.length() > 4096 ? safe.substring(0, 4096) : safe;
    }
}
