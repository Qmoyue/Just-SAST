package io.just.sast.analysis.taint;

import java.util.LinkedHashSet;
import java.util.Collections;
import java.util.Set;

/**
 * Resolves the bounded standard-container relation recorded by {@link ForwardOrigins}.
 *
 * <p>The relation is deliberately separate from a normal {@link ValueOrigin}: a list entry
 * or map value is not the list/map object.  Model rules opt into this projection with the
 * explicit {@code element(this)} or {@code element(argN)} syntax.  If no relation is known,
 * the input origin is retained as the conservative container boundary; unknown origins are
 * never widened to a different object.</p>
 */
public final class ContainerElementSources {

    private static final int MAX_UNWRAP_DEPTH = 8;

    private ContainerElementSources() {
    }

    /** Return the finite base origins behind a standard container/view value. */
    public static Set<ValueOrigin> resolve(ValueOrigin origin, ForwardOrigins.Result result) {
        if (origin == null) {
            return Set.of();
        }
        LinkedHashSet<ValueOrigin> resolved = new LinkedHashSet<>();
        collect(origin, result, 0, new LinkedHashSet<>(), resolved);
        return resolved.isEmpty() ? Set.of(origin) : Collections.unmodifiableSet(resolved);
    }

    private static void collect(ValueOrigin origin, ForwardOrigins.Result result, int depth,
                                Set<ValueOrigin> visiting, Set<ValueOrigin> resolved) {
        if (origin == null || depth > MAX_UNWRAP_DEPTH || !visiting.add(origin)) {
            if (origin != null) {
                resolved.add(origin);
            }
            return;
        }
        try {
            Set<ValueOrigin> parents = result == null ? Set.of()
                    : result.containerElements().getOrDefault(origin, Set.of());
            if (parents.isEmpty()) {
                resolved.add(origin);
                return;
            }
            for (ValueOrigin parent : ValueOriginOrder.sorted(parents)) {
                collect(parent, result, depth + 1, visiting, resolved);
            }
        } finally {
            visiting.remove(origin);
        }
    }
}
