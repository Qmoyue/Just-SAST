package io.just.sast.blackboard;

/** Stable identity for one dependency/JDK gadget segment. */
public record GadgetSegmentId(String value) implements Comparable<GadgetSegmentId> {
    public GadgetSegmentId {
        value = EvidenceIdSupport.requireId("segment", value);
    }

    public static GadgetSegmentId fromCanonical(String... parts) {
        return new GadgetSegmentId(EvidenceIdSupport.id("segment", parts));
    }

    @Override
    public int compareTo(GadgetSegmentId other) {
        return value.compareTo(other.value);
    }

    @Override
    public String toString() {
        return value;
    }
}
