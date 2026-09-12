package io.just.sast.blackboard;

/** Stable identity for a normalized report finding. */
public record FindingId(String value) implements Comparable<FindingId> {
    public FindingId {
        value = EvidenceIdSupport.requireId("finding", value);
    }

    public static FindingId fromCanonical(String... parts) {
        return new FindingId(EvidenceIdSupport.id("finding", parts));
    }

    @Override
    public int compareTo(FindingId other) {
        return value.compareTo(other.value);
    }

    @Override
    public String toString() {
        return value;
    }
}
