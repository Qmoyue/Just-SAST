package io.just.sast.blackboard;

import java.util.Collections;
import java.util.Map;
import java.util.TreeMap;

/** One typed, immutable observation; free-form notes are not an evidence source. */
public record EvidenceAtom(
        String id,
        Kind kind,
        String artifactDigest,
        String owner,
        String member,
        String evidenceCode,
        Map<String, String> attributes) implements EvidenceNode {

    public enum Kind {
        APPLICATION_ENTRY,
        DESERIALIZATION_SITE,
        BINDING_SITE,
        LOOKUP_SITE,
        CONFIG_SITE,
        CALL_EDGE,
        DATA_FLOW,
        DEPENDENCY_SEGMENT,
        TERMINAL_IMPACT,
        CONSTRAINT,
        FILTER,
        DYNAMIC_OBSERVATION,
        PROTOCOL_BRIDGE,
        UNKNOWN
    }

    public EvidenceAtom {
        kind = java.util.Objects.requireNonNull(kind, "kind");
        artifactDigest = EvidenceIdSupport.normalize(artifactDigest);
        owner = EvidenceIdSupport.normalize(owner);
        member = EvidenceIdSupport.normalize(member);
        evidenceCode = EvidenceIdSupport.requireText("evidenceCode", evidenceCode);
        TreeMap<String, String> sorted = new TreeMap<>();
        if (attributes != null) {
            attributes.forEach((key, value) -> {
                if (key == null || key.isBlank() || value == null) {
                    throw new IllegalArgumentException("evidence attributes must be non-null");
                }
                sorted.put(key.trim(), value);
            });
        }
        // Keep the sorted iteration order instead of Map.copyOf's deliberately
        // unspecified order.  Canonical IDs, JSON and graph digests must be
        // identical across JVMs and construction order.
        attributes = Collections.unmodifiableMap(new TreeMap<>(sorted));
        String expected = EvidenceIdSupport.id("atom", kind.name(), artifactDigest, owner,
                member, evidenceCode, canonicalAttributes(attributes));
        id = id == null || id.isBlank() ? expected : EvidenceIdSupport.requireId("atom", id);
        if (!expected.equals(id)) {
            throw new IllegalArgumentException("atom id does not match canonical evidence");
        }
    }

    public static EvidenceAtom of(Kind kind, String artifactDigest, String owner, String member,
                                  String evidenceCode, Map<String, String> attributes) {
        return new EvidenceAtom(null, kind, artifactDigest, owner, member, evidenceCode,
                attributes);
    }

    @Override
    public NodeKind nodeKind() {
        return NodeKind.ATOM;
    }

    @Override
    public String canonical() {
        return "atom|" + id + '|' + kind + '|' + artifactDigest + '|' + owner + '|'
                + member + '|' + evidenceCode + '|' + canonicalAttributes(attributes);
    }

    public String toCanonicalJson() {
        StringBuilder json = new StringBuilder("{\"id\":\"")
                .append(EvidenceIdSupport.json(id)).append("\",\"kind\":\"")
                .append(kind).append("\",\"artifactDigest\":\"")
                .append(EvidenceIdSupport.json(artifactDigest)).append("\",\"owner\":\"")
                .append(EvidenceIdSupport.json(owner)).append("\",\"member\":\"")
                .append(EvidenceIdSupport.json(member)).append("\",\"evidenceCode\":\"")
                .append(EvidenceIdSupport.json(evidenceCode)).append("\",\"attributes\":{");
        int index = 0;
        for (Map.Entry<String, String> entry : attributes.entrySet()) {
            if (index++ > 0) {
                json.append(',');
            }
            json.append('"').append(EvidenceIdSupport.json(entry.getKey())).append("\":\"")
                    .append(EvidenceIdSupport.json(entry.getValue())).append('"');
        }
        return json.append("}}").toString();
    }

    private static String canonicalAttributes(Map<String, String> attributes) {
        StringBuilder value = new StringBuilder();
        attributes.forEach((key, item) -> value.append(key.length()).append(':').append(key)
                .append('=').append(item.length()).append(':').append(item).append(';'));
        return value.toString();
    }
}
