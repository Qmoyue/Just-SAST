package io.just.sast.blackboard;

/** Stable identity for one bounded dynamic verification attempt. */
public record AttemptId(String value) implements Comparable<AttemptId> {
    public AttemptId {
        value = EvidenceIdSupport.requireId("attempt", value);
    }

    public static AttemptId fromCanonical(String... parts) {
        return new AttemptId(EvidenceIdSupport.id("attempt", parts));
    }

    @Override
    public int compareTo(AttemptId other) {
        return value.compareTo(other.value);
    }

    @Override
    public String toString() {
        return value;
    }
}
