package io.just.sast.knowledge.backward;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BackwardBudgetAllocatorTest {

    @Test
    void largeSinkPopulationIsNotIncompleteBeforeItsAllocatedWorkRuns() {
        BackwardTaintAnalysis.FairBudgetAllocator allocator =
                new BackwardTaintAnalysis.FairBudgetAllocator(100, 10, 20);

        assertFalse(allocator.exhausted());
        for (int sink = 0; sink < 20; sink++) {
            int allocation = allocator.claim(sink);
            allocator.record(sink, allocation, 0);
        }
        assertFalse(allocator.exhausted());
    }

    @Test
    void allocatorBecomesIncompleteOnlyAfterAllAllocatedStepsAreConsumed() {
        BackwardTaintAnalysis.FairBudgetAllocator allocator =
                new BackwardTaintAnalysis.FairBudgetAllocator(100, 10, 20);

        for (int sink = 0; sink < 20; sink++) {
            int allocation = allocator.claim(sink);
            allocator.record(sink, allocation, allocation);
        }
        assertTrue(allocator.exhausted());
    }
}
