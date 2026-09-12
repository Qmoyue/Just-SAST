package io.just.sast.util;

import io.just.sast.blackboard.Chain;

import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

/**
 * Single owner for deferred {@link Chain} payload lifecycle.
 *
 * <p>The endpoint is admitted separately from its payload.  This helper keeps one accepted
 * payload instance for repeated admission/report reads, including typed {@code null} and
 * runtime-failure results, while preserving the original supplier exception for the caller's
 * failure policy.</p>
 */
public final class ChainMaterializer {

    private ChainMaterializer() {
    }

    /** Return a thread-safe, null-aware, at-most-once chain materializer. */
    public static Supplier<Chain> memoize(Supplier<Chain> delegate) {
        Objects.requireNonNull(delegate, "delegate");
        AtomicReference<MaterializationState> cached = new AtomicReference<>();
        return () -> {
            MaterializationState existing = cached.get();
            if (existing == null) {
                synchronized (cached) {
                    existing = cached.get();
                    if (existing == null) {
                        try {
                            existing = new MaterializationState(delegate.get(), null);
                        } catch (RuntimeException failure) {
                            // A deferred chain is derived from immutable analysis facts. A
                            // deterministic runtime failure is therefore a typed fail-closed
                            // result and must not be retried by later consumers.
                            existing = new MaterializationState(null, failure);
                        }
                        cached.set(existing);
                    }
                }
            }
            if (existing.failure() != null) {
                throw existing.failure();
            }
            return existing.chain();
        };
    }

    /** Null-aware terminal state shared by all lazy chain producers. */
    private record MaterializationState(Chain chain, RuntimeException failure) {
    }
}
