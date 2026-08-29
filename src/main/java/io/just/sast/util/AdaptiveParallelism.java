package io.just.sast.util;

import java.lang.management.ManagementFactory;
import java.util.concurrent.Semaphore;

/**
 * 计算阶段的有界并行度选择器。
 *
 * <p>扫描器是 CPU 与内存共同受限的工作负载。固定使用所有逻辑处理器会让桌面环境
 * 卡顿，固定使用很小的线程数又会浪费 CI/服务器资源；这里把“调度多少任务”与分析
 * 语义预算分开，任何降档都只降低并发度，不跳过方法、路径或规则。</p>
 */
public final class AdaptiveParallelism {

    private static final double CPU_BUSY = 0.75d;
    private static final double CPU_SATURATED = 0.90d;
    private static final double HEAP_BUSY = 0.80d;
    private static final double HEAP_SATURATED = 0.90d;
    /** 同一扫描 JVM 内多个知识源可能同时并行；共享配额避免两套 worker 各自“看见空闲”而叠加。 */
    private static final Semaphore CPU_PERMITS = new Semaphore(initialCapacity());

    private AdaptiveParallelism() {
    }

    /** 并行度决策，供日志/统计和测试使用。负载值不可用时为 -1。 */
    public record Decision(int workers, int availableProcessors, double cpuLoad,
                           double heapPressure, String reason) {
    }

    /**
     * 按当前 JVM/主机状态选择 worker 数。返回值至少为 1（有任务时）。
     * maxWorkers 是阶段安全上限，不是语义截断；taskCount 只用于避免空 worker。
     */
    public static Decision choose(int taskCount, int maxWorkers) {
        int available = Math.max(1, Runtime.getRuntime().availableProcessors());
        double cpuLoad = cpuLoad();
        double heapPressure = heapPressure();
        return chooseFor(taskCount, maxWorkers, available, cpuLoad, heapPressure);
    }

    /**
     * 从本次 JVM 的 CPU 配额中领取并行度。领取失败时仍返回 1，保证不会因调度器互等；
     * 未领取到配额的单 worker 只承担一个保守的过量线程，任务结束后不需要归还。
     */
    public static Lease reserve(Decision decision) {
        int requested = Math.max(0, decision.workers());
        if (requested == 0) {
            return new Lease(0, 0);
        }
        int available = CPU_PERMITS.availablePermits();
        int target = Math.max(1, Math.min(requested, available));
        for (int workers = target; workers >= 1; workers--) {
            if (CPU_PERMITS.tryAcquire(workers)) {
                return new Lease(workers, workers);
            }
        }
        return new Lease(1, 0);
    }

    /** 有界 CPU 配额租约；只影响执行调度，不改变分析预算与结果集合。 */
    public static final class Lease implements AutoCloseable {
        private final int workers;
        private final int permits;
        private boolean closed;

        private Lease(int workers, int permits) {
            this.workers = workers;
            this.permits = permits;
        }

        public int workers() {
            return workers;
        }

        @Override
        public void close() {
            if (!closed) {
                closed = true;
                if (permits > 0) {
                    CPU_PERMITS.release(permits);
                }
            }
        }
    }

    /** 纯函数决策核心，测试不依赖当前机器负载。 */
    static Decision chooseFor(int taskCount, int maxWorkers, int availableProcessors,
                             double cpuLoad, double heapPressure) {
        int tasks = Math.max(0, taskCount);
        if (tasks == 0) {
            return new Decision(0, Math.max(1, availableProcessors), cpuLoad, heapPressure,
                    "no-tasks");
        }
        int available = Math.max(1, availableProcessors);
        int cap = Math.max(1, Math.min(maxWorkers, available));
        int reserve = available <= 1 ? 0 : (available >= 8 ? Math.max(1, available / 8) : 1);
        int workers = Math.min(tasks, Math.min(cap, Math.max(1, available - reserve)));
        String reason = "headroom";
        if (cpuLoad >= CPU_SATURATED || heapPressure >= HEAP_SATURATED) {
            workers = Math.max(1, workers / 2);
            reason = cpuLoad >= CPU_SATURATED && heapPressure >= HEAP_SATURATED
                    ? "cpu+heap-saturated" : (cpuLoad >= CPU_SATURATED ? "cpu-saturated" : "heap-saturated");
        } else if (cpuLoad >= CPU_BUSY || heapPressure >= HEAP_BUSY) {
            workers = Math.max(1, (workers * 3) / 4);
            reason = cpuLoad >= CPU_BUSY && heapPressure >= HEAP_BUSY
                    ? "cpu+heap-busy" : (cpuLoad >= CPU_BUSY ? "cpu-busy" : "heap-busy");
        }
        return new Decision(workers, available, cpuLoad, heapPressure, reason);
    }

    private static double cpuLoad() {
        try {
            var bean = ManagementFactory.getOperatingSystemMXBean();
            if (bean instanceof com.sun.management.OperatingSystemMXBean sunBean) {
                double load = sunBean.getCpuLoad();
                return load >= 0.0d && load <= 1.0d ? load : -1.0d;
            }
        } catch (RuntimeException ignored) {
            // 负载采样不是扫描正确性的依赖；不可用时退回处理器/堆启发式。
        }
        return -1.0d;
    }

    private static double heapPressure() {
        Runtime runtime = Runtime.getRuntime();
        long max = runtime.maxMemory();
        if (max <= 0L) {
            return -1.0d;
        }
        long used = runtime.totalMemory() - runtime.freeMemory();
        return Math.max(0.0d, Math.min(1.0d, (double) used / (double) max));
    }

    private static int initialCapacity() {
        int available = Math.max(1, Runtime.getRuntime().availableProcessors());
        if (available == 1) {
            return 1;
        }
        int reserve = available >= 8 ? Math.max(1, available / 8) : 1;
        return Math.max(1, available - reserve);
    }
}
