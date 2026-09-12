package io.just.sast.model;

import java.util.Objects;

/** Versioned, path-independent identity of a JVM type. */
public record TypeId(String internalName) implements Comparable<TypeId> {

    public TypeId {
        internalName = normalize(internalName);
    }

    public static TypeId of(String internalName) {
        return new TypeId(internalName);
    }

    /** Canonical identity; the prefix is part of the model contract. */
    public String canonical() {
        return "type-v1:" + internalName;
    }

    @Override
    public int compareTo(TypeId other) {
        return canonical().compareTo(other.canonical());
    }

    private static String normalize(String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("type internal name must not be blank");
        }
        String normalized = value.trim().replace('.', '/');
        if (normalized.startsWith("L") && normalized.endsWith(";")) {
            normalized = normalized.substring(1, normalized.length() - 1);
        }
        if (normalized.isBlank() || normalized.indexOf('\u0000') >= 0) {
            throw new IllegalArgumentException("invalid type internal name");
        }
        return normalized;
    }
}
