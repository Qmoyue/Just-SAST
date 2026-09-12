package io.just.sast.knowledge.engine;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Contract for run-local counters and budget state extracted from ForwardEngine. */
class ForwardStateStoreContractTest {

    @Test
    void runCountersAndFactVersionsAreTypedAndResetPerRun() {
        ForwardStateStore store = new ForwardStateStore();
        store.configureBudget(10, 3, 2);
        store.recordStep();
        store.recordMethodPass();
        store.recordRound();
        store.recordPrimaryFact();
        store.recordAlternativeFact();

        assertEquals(1, store.steps());
        assertEquals(1, store.methodPasses());
        assertEquals(1, store.rounds());
        assertEquals(1, store.primaryFactUpdates());
        assertEquals(1, store.alternativeFactUpdates());
        assertEquals(2, store.factCount());
        assertEquals(2, store.factVersion());
        assertEquals(1, store.primaryFactVersion());
        assertEquals(1, store.candidateFactVersion());
        assertTrue(store.withinBudget(1));
        assertFalse(store.withinBudget(2));

        store.beginRun();
        assertEquals(0, store.steps());
        assertEquals(0, store.methodPasses());
        assertEquals(0, store.rounds());
        assertEquals(0, store.primaryFactUpdates());
        assertEquals(0, store.alternativeFactUpdates());
        assertEquals(0, store.factCount());
        assertEquals(2, store.factVersion());
        assertEquals(1, store.primaryFactVersion());
        assertEquals(1, store.candidateFactVersion());
    }

    @Test
    void worklistAndSnapshotShareOneStateOwner() {
        ForwardStateStore store = new ForwardStateStore();
        store.configureBudget(1, 1, 1);
        assertTrue(store.worklist().offer("a#x()V"));
        store.recordStep();
        ForwardStateStore.Snapshot snapshot = store.snapshot();

        assertEquals(1, snapshot.worklist().pendingCount());
        assertEquals(1, snapshot.steps());
        assertEquals(1, snapshot.budget().stepLimit());
        store.worklist().clear();
        assertEquals(1, snapshot.worklist().pendingCount());
    }
}
