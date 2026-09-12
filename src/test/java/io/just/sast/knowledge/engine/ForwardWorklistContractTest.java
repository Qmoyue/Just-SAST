package io.just.sast.knowledge.engine;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Stable contract for the forward scheduler's bounded queue state. */
class ForwardWorklistContractTest {

    @Test
    void offersAreDeduplicatedOnlyWhileQueuedAndOrderIsStable() {
        ForwardWorklist worklist = new ForwardWorklist();

        assertTrue(worklist.offer("method#b()V"));
        assertFalse(worklist.offer("method#b()V"));
        assertTrue(worklist.offer("method#a()V"));
        assertEquals(2, worklist.size());
        assertEquals("method#b()V", worklist.poll());
        assertEquals("method#a()V", worklist.poll());
        assertEquals(0, worklist.size());

        // A key can be scheduled again after it was consumed, which is required for
        // fixed-point propagation when a later fact changes the same method.
        assertTrue(worklist.offer("method#b()V"));
        assertEquals(List.of("method#b()V"), worklist.drain());
        assertTrue(worklist.isEmpty());
        assertEquals(3, worklist.acceptedOffers());
        assertEquals(1, worklist.duplicateOffers());
        assertEquals(2, worklist.peakPending());
        assertTrue(worklist.peakPendingKeyChars() > 0L);
    }

    @Test
    void malformedKeysAreRejectedAndClearRemovesPendingState() {
        ForwardWorklist worklist = new ForwardWorklist();

        assertFalse(worklist.offer(null));
        assertFalse(worklist.offer(""));
        assertFalse(worklist.offer("   "));
        assertTrue(worklist.offer("method#x()V"));
        worklist.clear();
        assertTrue(worklist.isEmpty());
        assertEquals(0, worklist.drain().size());
        assertTrue(worklist.offer("method#x()V"));
    }

    @Test
    void snapshotIsImmutableAndRetainsQueueOrder() {
        ForwardWorklist worklist = new ForwardWorklist();
        worklist.offer("method#b()V");
        worklist.offer("method#a()V");

        ForwardWorklist.Snapshot snapshot = worklist.snapshot();
        assertEquals(List.of("method#b()V", "method#a()V"), snapshot.queuedKeys());
        assertEquals(2, snapshot.acceptedOffers());
        assertEquals(2, snapshot.pendingCount());
        assertEquals(2, snapshot.peakPending());
        assertTrue(snapshot.peakPendingKeyChars() > 0L);
        try {
            snapshot.queuedKeys().add("method#c()V");
        } catch (UnsupportedOperationException expected) {
            // Defensive immutability is part of the public seam.
        }
        assertEquals(List.of("method#b()V", "method#a()V"), snapshot.queuedKeys());
    }
}
