package io.just.sast.blackboard;

/** Explicit cross-protocol/cross-artifact bridge; a lookup/connect is not terminal by itself. */
public record BridgeEvidence(
        String id,
        Kind kind,
        String fromAtomId,
        String toAtomId,
        String protocol,
        Status status) implements EvidenceNode {

    public enum Kind {
        JNDI_RMI,
        JDBC_DRIVER,
        REMOTE_RESPONSE_DESERIALIZATION,
        SECOND_DESERIALIZATION,
        REFLECTION,
        CONFIGURATION,
        UNKNOWN
    }

    public enum Status {
        PROVED,
        PARTIAL,
        UNKNOWN,
        BLOCKED
    }

    public BridgeEvidence {
        kind = java.util.Objects.requireNonNull(kind, "kind");
        fromAtomId = EvidenceIdSupport.requireId("atom", fromAtomId);
        toAtomId = EvidenceIdSupport.requireId("atom", toAtomId);
        protocol = EvidenceIdSupport.requireText("protocol", protocol);
        status = java.util.Objects.requireNonNull(status, "status");
        String expected = EvidenceIdSupport.id("bridge", kind.name(), fromAtomId, toAtomId,
                protocol, status.name());
        id = id == null || id.isBlank() ? expected : EvidenceIdSupport.requireId("bridge", id);
        if (!expected.equals(id)) {
            throw new IllegalArgumentException("bridge id does not match canonical evidence");
        }
    }

    public static BridgeEvidence of(Kind kind, String fromAtomId, String toAtomId,
                                    String protocol, Status status) {
        return new BridgeEvidence(null, kind, fromAtomId, toAtomId, protocol, status);
    }

    @Override
    public NodeKind nodeKind() {
        return NodeKind.PROTOCOL_BRIDGE;
    }

    @Override
    public String canonical() {
        return "bridge|" + id + '|' + kind + '|' + fromAtomId + '|' + toAtomId + '|'
                + protocol + '|' + status;
    }

    @Override
    public String toCanonicalJson() {
        return "{\"id\":\"" + EvidenceIdSupport.json(id)
                + "\",\"kind\":\"PROTOCOL_BRIDGE\",\"bridgeKind\":\"" + kind
                + "\",\"fromAtomId\":\"" + EvidenceIdSupport.json(fromAtomId)
                + "\",\"toAtomId\":\"" + EvidenceIdSupport.json(toAtomId)
                + "\",\"protocol\":\"" + EvidenceIdSupport.json(protocol)
                + "\",\"status\":\"" + status + "\"}";
    }
}
