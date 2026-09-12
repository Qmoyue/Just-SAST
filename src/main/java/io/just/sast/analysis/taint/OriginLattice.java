package io.just.sast.analysis.taint;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Monotone, bounded origin lattice used by the forward interpreter and OriginSupport.
 *
 * <p>Empty is the bottom value, a finite set is an exact may-origin value, and
 * {@code truncated=true} records that the finite representation is only a retained prefix of
 * a larger union.  No caller may treat a truncated value as a proof of uniqueness.  The hot
 * {@link #joinTrusted(Set, Set, int, boolean)} path reuses immutable input sets; public
 * snapshots defensively copy and sort values for deterministic evidence.</p>
 */
public final class OriginLattice {
    public static final int DEFAULT_MAX_ORIGINS = 512;

    private OriginLattice() {
    }

    /** Immutable result of a bounded join. */
    public static final class Join {
        private final Set<ValueOrigin> values;
        private final boolean truncated;

        private Join(Set<ValueOrigin> values, boolean truncated) {
            this.values = values == null ? Set.of() : values;
            this.truncated = truncated;
        }

        public Set<ValueOrigin> values() {
            return values;
        }

        public boolean truncated() {
            return truncated;
        }
    }

    /** Deterministic defensive snapshot for model/evidence consumers. */
    public static Join snapshot(Collection<ValueOrigin> values) {
        if (values == null || values.isEmpty()) {
            return new Join(Set.of(), false);
        }
        List<ValueOrigin> ordered = new ArrayList<>();
        for (ValueOrigin value : values) {
            if (value != null) {
                ordered.add(value);
            }
        }
        ordered.sort(java.util.Comparator.comparing(ValueOriginOrder::key));
        return new Join(Collections.unmodifiableSet(new LinkedHashSet<>(ordered)), false);
    }

    /**
     * Join immutable origin sets already owned by the interpreter.  This method is package
     * private so ordinary callers use {@link #snapshot(Collection)} and cannot accidentally
     * retain mutable input.  The identity-preserving subset fast paths are part of the solver's
     * allocation budget, not a semantic distinction.
     */
    static Join joinTrusted(Set<ValueOrigin> left, Set<ValueOrigin> right,
                            int maxOrigins, boolean interrupted) {
        int limit = Math.max(1, maxOrigins);
        if (interrupted) {
            return new Join(truncateTrusted(left, right, limit), true);
        }
        if (left == null || left.isEmpty()) {
            return boundedSingleTrusted(right, limit);
        }
        if (right == null || right.isEmpty()) {
            return boundedSingleTrusted(left, limit);
        }
        if (left == right && left.size() <= limit) {
            return new Join(left, false);
        }
        long combined = (long) left.size() + right.size();
        if (combined <= limit) {
            if (left.size() >= right.size() && left.containsAll(right)) {
                return new Join(left, false);
            }
            if (right.size() > left.size() && right.containsAll(left)) {
                return new Join(right, false);
            }
            LinkedHashSet<ValueOrigin> merged = new LinkedHashSet<>(left);
            merged.addAll(right);
            return new Join(Collections.unmodifiableSet(merged), false);
        }
        return new Join(truncateTrusted(left, right, limit), true);
    }

    static Set<ValueOrigin> truncateTrusted(Set<ValueOrigin> first,
                                             Set<ValueOrigin> second,
                                             int maxOrigins) {
        int limit = Math.max(1, maxOrigins);
        LinkedHashSet<ValueOrigin> retained = new LinkedHashSet<>(limit);
        append(retained, first, limit);
        append(retained, second, limit);
        return Collections.unmodifiableSet(retained);
    }

    private static Join boundedSingleTrusted(Set<ValueOrigin> values, int maxOrigins) {
        if (values == null || values.isEmpty() || values.size() <= maxOrigins) {
            return new Join(values == null ? Set.of() : values, false);
        }
        return new Join(truncateTrusted(values, Set.of(), maxOrigins), true);
    }

    private static void append(LinkedHashSet<ValueOrigin> retained,
                               Set<ValueOrigin> values, int limit) {
        if (values == null || retained.size() >= limit) {
            return;
        }
        for (ValueOrigin value : values) {
            if (value != null) {
                retained.add(value);
            }
            if (retained.size() >= limit) {
                return;
            }
        }
    }
}
