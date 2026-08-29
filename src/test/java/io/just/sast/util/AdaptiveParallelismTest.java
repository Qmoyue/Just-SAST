package io.just.sast.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 自适应调度只改变 worker 数，不改变任务集合；决策核心用纯函数锁住边界。 */
class AdaptiveParallelismTest {

    @Test
    void noTasksDoesNotReserveWorkers() {
        var decision = AdaptiveParallelism.chooseFor(0, 16, 32, -1.0d, -1.0d);
        assertEquals(0, decision.workers());
        assertEquals("no-tasks", decision.reason());
    }

    @Test
    void leavesDesktopHeadroomAndHonorsStageCap() {
        var decision = AdaptiveParallelism.chooseFor(1000, 16, 32, -1.0d, -1.0d);
        assertEquals(16, decision.workers());
        assertTrue(decision.workers() < decision.availableProcessors());
    }

    @Test
    void loadOnlyReducesConcurrencyNeverAnalysisCapacity() {
        var cpuBusy = AdaptiveParallelism.chooseFor(1000, 16, 32, 0.95d, 0.10d);
        var heapBusy = AdaptiveParallelism.chooseFor(1000, 16, 32, 0.10d, 0.95d);
        assertEquals(8, cpuBusy.workers());
        assertEquals(8, heapBusy.workers());
        assertTrue(cpuBusy.workers() >= 1);
        assertTrue(heapBusy.workers() >= 1);
    }

    @Test
    void leaseIsBoundedAndRestoresItsClaim() {
        var decision = AdaptiveParallelism.chooseFor(8, 4, 8, -1.0d, -1.0d);
        try (var lease = AdaptiveParallelism.reserve(decision)) {
            assertTrue(lease.workers() >= 1);
            assertTrue(lease.workers() <= decision.workers());
        }
    }
}
