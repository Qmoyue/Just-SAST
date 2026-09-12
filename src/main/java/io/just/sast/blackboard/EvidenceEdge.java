package io.just.sast.blackboard;

/** Typed directed relationship in an EvidenceGraph. */
public record EvidenceEdge(
        String id,
        String fromId,
        String toId,
        Kind kind,
        String reasonCode) {

    public enum Kind {
        SUPPORTS,
        JOINS,
        BRIDGES,
        FLOWS_TO,
        DERIVES,
        REQUIRES,
        CONTRADICTS
    }

    public EvidenceEdge {
        fromId = EvidenceIdSupport.requireText("fromId", fromId);
        toId = EvidenceIdSupport.requireText("toId", toId);
        if (fromId.equals(toId)) {
            throw new IllegalArgumentException("evidence edge cannot point to itself");
        }
        kind = java.util.Objects.requireNonNull(kind, "kind");
        reasonCode = EvidenceIdSupport.requireText("reasonCode", reasonCode);
        String expected = EvidenceIdSupport.id("edge", fromId, toId, kind.name(), reasonCode);
        id = id == null || id.isBlank() ? expected : EvidenceIdSupport.requireId("edge", id);
        if (!expected.equals(id)) {
            throw new IllegalArgumentException("edge id does not match canonical evidence");
        }
    }

    public static EvidenceEdge of(String fromId, String toId, Kind kind, String reasonCode) {
        return new EvidenceEdge(null, fromId, toId, kind, reasonCode);
    }

    public String canonical() {
        return "edge|" + id + '|' + fromId + '|' + toId + '|' + kind + '|' + reasonCode;
    }

    public String toCanonicalJson() {
        return "{\"id\":\"" + EvidenceIdSupport.json(id)
                + "\",\"from\":\"" + EvidenceIdSupport.json(fromId)
                + "\",\"to\":\"" + EvidenceIdSupport.json(toId)
                + "\",\"kind\":\"" + kind + "\",\"reasonCode\":\""
                + EvidenceIdSupport.json(reasonCode) + "\"}";
    }
}
