package io.just.sast.knowledge.engine;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * The single owner of the forward method worklist and its pending-key invariant.
 *
 * <p>The engine deliberately keeps scheduling separate from taint facts: a key is present in
 * {@code pending} exactly while it is queued, and may be offered again after it is consumed.
 * This preserves fixed-point requeue semantics while removing the former queue/set dual state
 * from the solver.  The class is intentionally not thread-safe; one forward engine owns one
 * scan-local instance and cancellation is observed by that owner.</p>
 */
public final class ForwardWorklist {
    private final Deque<String> queue = new ArrayDeque<>();
    private final Set<String> pending = new HashSet<>();
    private long acceptedOffers;
    private long duplicateOffers;
    private long consumedItems;
    private int peakPending;
    private long pendingKeyChars;
    private long peakPendingKeyChars;

    /** Immutable scheduler telemetry and queue snapshot for characterization/diagnostics. */
    public record Snapshot(List<String> queuedKeys, int pendingCount, long acceptedOffers,
                           long duplicateOffers, long consumedItems, int peakPending,
                           long peakPendingKeyChars) {
        public Snapshot {
            queuedKeys = queuedKeys == null ? List.of() : List.copyOf(queuedKeys);
            if (pendingCount < 0 || acceptedOffers < 0 || duplicateOffers < 0
                    || consumedItems < 0 || peakPending < pendingCount
                    || peakPendingKeyChars < 0) {
                throw new IllegalArgumentException("negative worklist telemetry");
            }
        }
    }

    /** Offer a method key once while it is pending. Invalid/blank keys are rejected. */
    public boolean offer(String methodKey) {
        if (methodKey == null || methodKey.isBlank()) {
            return false;
        }
        if (!pending.add(methodKey)) {
            duplicateOffers++;
            return false;
        }
        queue.addLast(methodKey);
        acceptedOffers++;
        peakPending = Math.max(peakPending, pending.size());
        pendingKeyChars = safeAdd(pendingKeyChars, methodKey.length());
        peakPendingKeyChars = Math.max(peakPendingKeyChars, pendingKeyChars);
        return true;
    }

    /** Consume the oldest pending method key, or {@code null} when empty. */
    public String poll() {
        String methodKey = queue.pollFirst();
        if (methodKey == null) {
            return null;
        }
        pending.remove(methodKey);
        pendingKeyChars = Math.max(0L, pendingKeyChars - methodKey.length());
        consumedItems++;
        return methodKey;
    }

    /** Consume all currently queued keys in insertion order. */
    public List<String> drain() {
        List<String> result = new ArrayList<>(queue.size());
        for (String methodKey; (methodKey = poll()) != null; ) {
            result.add(methodKey);
        }
        return result.isEmpty() ? List.of() : List.copyOf(result);
    }

    /** Remove all pending work without resetting monotonic telemetry. */
    public void clear() {
        queue.clear();
        pending.clear();
        pendingKeyChars = 0L;
    }

    public boolean isEmpty() {
        return queue.isEmpty();
    }

    public int size() {
        return queue.size();
    }

    public long acceptedOffers() {
        return acceptedOffers;
    }

    public long duplicateOffers() {
        return duplicateOffers;
    }

    public long consumedItems() {
        return consumedItems;
    }

    public int peakPending() {
        return peakPending;
    }

    public long peakPendingKeyChars() {
        return peakPendingKeyChars;
    }

    public Snapshot snapshot() {
        return new Snapshot(new ArrayList<>(queue), pending.size(), acceptedOffers,
                duplicateOffers, consumedItems, peakPending, peakPendingKeyChars);
    }

    private static long safeAdd(long left, long right) {
        if (right > 0L && left > Long.MAX_VALUE - right) {
            return Long.MAX_VALUE;
        }
        return left + right;
    }
}
