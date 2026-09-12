package io.just.sast.analysis.taint;

import io.just.sast.model.FieldRef;
import io.just.sast.model.InsnFact;

import java.util.Optional;

/**
 * Pure field/alias transfer operations shared by forward origin consumers.
 * The class has no graph, cache, or global state and therefore cannot create
 * a hidden dependency between knowledge sources.
 */
public final class FieldAliasTransfer {

    private FieldAliasTransfer() {
    }

    public static Optional<FieldAlias> declaration(InsnFact insn) {
        return FieldAlias.from(insn);
    }

    public static Optional<FieldAlias> declaration(ValueOrigin.FieldRead field) {
        return FieldAlias.from(field);
    }

    public static FieldAlias declaration(FieldRef ref, boolean isStatic) {
        return FieldAlias.of(ref, isStatic);
    }

    /** Descriptor-aware declaration match with compatibility wildcard rules. */
    public static boolean same(FieldAlias left, FieldAlias right) {
        return left != null && left.matches(right);
    }

    /** Preserve receiver alias information while transferring a field read. */
    public static ValueOrigin.FieldRead read(FieldAlias field, ValueOrigin receiver) {
        if (field == null) {
            throw new IllegalArgumentException("field alias is required");
        }
        return new ValueOrigin.FieldRead(field.owner(), field.name(), field.descriptor(),
                field.isStatic(), receiver);
    }

    /** Produce the exact pre-typed index key for compatibility consumers. */
    public static String legacyKey(FieldAlias field) {
        return field == null ? "" : field.legacyKey();
    }
}
