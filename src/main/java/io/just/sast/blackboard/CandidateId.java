package io.just.sast.blackboard;

/** Stable identity for a pre-normalization candidate path. */
public record CandidateId(String value) implements Comparable<CandidateId> {
    public CandidateId {
        value = EvidenceIdSupport.requireId("candidate", value);
    }

    public static CandidateId fromCanonical(String... parts) {
        return new CandidateId(EvidenceIdSupport.id("candidate", parts));
    }

    @Override
    public int compareTo(CandidateId other) {
        return value.compareTo(other.value);
    }

    @Override
    public String toString() {
        return value;
    }
}
