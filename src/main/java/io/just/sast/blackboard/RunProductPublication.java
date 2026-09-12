package io.just.sast.blackboard;

import java.util.Objects;

/** Immutable publication receipt for one run product contribution. */
public record RunProductPublication(RunProduct product, String producerId, Phase phase)
        implements BlackboardFact {

    public RunProductPublication {
        product = Objects.requireNonNull(product, "product");
        producerId = requireText(producerId, "producerId");
        phase = Objects.requireNonNull(phase, "phase");
    }

    private static String requireText(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
        return value;
    }
}
