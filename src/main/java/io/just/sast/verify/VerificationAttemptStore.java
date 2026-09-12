package io.just.sast.verify;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Ordered result store for one bounded verification batch.
 *
 * <p>Worker completion order is intentionally not the report order.  This store owns the
 * index-addressed snapshot and makes timeout/error filling explicit, so a future scheduler can
 * change its executor without changing deterministic result alignment or retry semantics.</p>
 */
final class VerificationAttemptStore {

    private final List<ParallelVerifier.VerifyResult> results;
    private int recorded;

    VerificationAttemptStore(int size) {
        if (size < 0) {
            throw new IllegalArgumentException("size must not be negative");
        }
        results = new ArrayList<>(Collections.nCopies(size, null));
    }

    synchronized void record(int index, ParallelVerifier.VerifyResult result) {
        checkIndex(index);
        if (result == null) {
            throw new IllegalArgumentException("verification result must not be null");
        }
        if (results.get(index) == null) {
            recorded++;
        }
        results.set(index, result);
    }

    synchronized boolean isRecorded(int index) {
        checkIndex(index);
        return results.get(index) != null;
    }

    synchronized int recordedCount() {
        return recorded;
    }

    synchronized List<ParallelVerifier.VerifyResult> ordered() {
        return List.copyOf(results);
    }

    private void checkIndex(int index) {
        if (index < 0 || index >= results.size()) {
            throw new IndexOutOfBoundsException("attempt index=" + index
                    + ", size=" + results.size());
        }
    }
}
