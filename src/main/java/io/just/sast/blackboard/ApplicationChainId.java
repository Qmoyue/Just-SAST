package io.just.sast.blackboard;

/** Stable identity for an application-anchored chain, independent of rendering/ranking. */
public record ApplicationChainId(String value) implements Comparable<ApplicationChainId> {
    public ApplicationChainId {
        value = EvidenceIdSupport.requireId("appchain", value);
    }

    public static ApplicationChainId fromCanonical(String... parts) {
        return new ApplicationChainId(EvidenceIdSupport.id("appchain", parts));
    }

    @Override
    public int compareTo(ApplicationChainId other) {
        return value.compareTo(other.value);
    }

    @Override
    public String toString() {
        return value;
    }
}
