package io.just.sast.model;

/** Versioned, path-independent identity of a JVM method. */
public record MethodId(TypeId owner, String name, String descriptor) implements Comparable<MethodId> {

    public MethodId {
        owner = java.util.Objects.requireNonNull(owner, "owner");
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("method name must not be blank");
        }
        name = name.trim();
        if (descriptor == null || descriptor.isBlank()) {
            throw new IllegalArgumentException("method descriptor must not be blank");
        }
        descriptor = descriptor.trim();
    }

    public static MethodId of(String owner, String name, String descriptor) {
        return new MethodId(TypeId.of(owner), name, descriptor);
    }

    public static MethodId of(MethodInfo method) {
        java.util.Objects.requireNonNull(method, "method");
        return of(method.owner(), method.name(), method.descriptor());
    }

    /** Canonical identity; the prefix is part of the model contract. */
    public String canonical() {
        return "method-v1:" + owner.internalName() + '#' + name + descriptor;
    }

    @Override
    public int compareTo(MethodId other) {
        return canonical().compareTo(other.canonical());
    }
}
