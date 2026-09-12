package io.just.sast.analysis.taint;

import io.just.sast.model.FieldRef;
import io.just.sast.model.InsnFact;
import io.just.sast.model.Op;

import java.util.Locale;
import java.util.Objects;
import java.util.Optional;

/**
 * Stable identity for one JVM field declaration.
 *
 * <p>The receiver is deliberately not part of this value.  A receiver is an
 * origin/alias fact carried by {@link ValueOrigin.FieldRead}; keeping it out
 * of the declaration key prevents instance fields on different objects from
 * being accidentally treated as different declarations while still allowing
 * the transfer layer to preserve the receiver separately.</p>
 */
public record FieldAlias(String owner, String name, String descriptor, boolean isStatic)
        implements Comparable<FieldAlias> {

    public FieldAlias {
        owner = normalize(owner);
        name = normalize(name);
        descriptor = normalize(descriptor);
    }

    /** Build an alias from a frontend field reference. */
    public static FieldAlias of(FieldRef ref, boolean isStatic) {
        Objects.requireNonNull(ref, "ref");
        return new FieldAlias(ref.owner(), ref.name(), ref.descriptor(), isStatic);
    }

    /** Safely extract a field declaration from a bytecode fact. */
    public static Optional<FieldAlias> from(InsnFact insn) {
        if (insn == null || !isFieldOperation(insn.op())) {
            return Optional.empty();
        }
        try {
            FieldRef ref = insn.fieldRef();
            if (ref == null) {
                return Optional.empty();
            }
            boolean isStatic = insn.op() == Op.GETSTATIC || insn.op() == Op.PUTSTATIC;
            return Optional.of(of(ref, isStatic));
        } catch (RuntimeException malformedOperands) {
            // Hostile or truncated bytecode is an unknown fact, not an
            // analysis crash and never an affirmative field match.
            return Optional.empty();
        }
    }

    /** Safely extract the declaration portion of a field-read origin. */
    public static Optional<FieldAlias> from(ValueOrigin.FieldRead field) {
        if (field == null) {
            return Optional.empty();
        }
        return Optional.of(new FieldAlias(field.owner(), field.field(), field.descriptor(), field.isStatic()));
    }

    /** True for JVM field reads and writes represented by the model. */
    public static boolean isFieldOperation(Op op) {
        return op == Op.GETFIELD || op == Op.PUTFIELD
                || op == Op.GETSTATIC || op == Op.PUTSTATIC;
    }

    /**
     * Match the historical field semantics: an absent descriptor is a
     * compatibility wildcard, while a supplied descriptor is exact.
     */
    public boolean matches(FieldAlias other) {
        if (other == null || !owner.equals(other.owner) || !name.equals(other.name)
                || isStatic != other.isStatic) {
            return false;
        }
        return descriptor.isBlank() || other.descriptor.isBlank()
                || descriptor.equals(other.descriptor);
    }

    /** Canonical, bounded key for caches/evidence; never includes receiver text. */
    public String canonical() {
        return "field-v1:" + owner + "#" + name + "#" + descriptor + "#"
                + (isStatic ? "static" : "instance");
    }

    /** Legacy key used by the field-reader index, retained byte-for-byte. */
    public String legacyKey() {
        return owner + "#" + name + "#" + descriptor + "#" + isStatic;
    }

    @Override
    public int compareTo(FieldAlias other) {
        int ownerCmp = owner.compareTo(other.owner);
        if (ownerCmp != 0) {
            return ownerCmp;
        }
        int nameCmp = name.compareTo(other.name);
        if (nameCmp != 0) {
            return nameCmp;
        }
        int descriptorCmp = descriptor.compareTo(other.descriptor);
        if (descriptorCmp != 0) {
            return descriptorCmp;
        }
        return Boolean.compare(isStatic, other.isStatic);
    }

    private static String normalize(String value) {
        return value == null ? "" : value.trim();
    }
}
