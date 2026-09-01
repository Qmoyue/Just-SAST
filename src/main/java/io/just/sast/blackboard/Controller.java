package io.just.sast.blackboard;

import io.just.sast.util.JustLogger;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 黑板控制器：三阶段调度（init 串行 → 阶段屏障）。
 *
 * <p>ANALYSIS 使用有界 executor 并行执行自足知识源；COMPOSITION/CALIBRATION 使用单线程
 * executor 保持 priority 顺序，同时拥有可取消的阶段 deadline。任何 worker 未能收尾时，
 * 控制器会停止推进屏障并把原因写入黑板，避免未结束插件与后续阶段并发修改结果。</p>
 */
public final class Controller {

    /** 单阶段事件派生上限（有界恢复：防事件风暴）。 */
    private static final int MAX_DISPATCH = 1_000_000;
    /** 插件不是可信代码；阶段屏障不能无限等待失控知识源。 */
    private static final long PHASE_TIMEOUT_SECONDS = 300L;
    private static final long WORKER_SHUTDOWN_MILLIS = 2_000L;

    private final Blackboard blackboard;
    private final List<KnowledgeSource> sources;

    public Controller(Blackboard blackboard, List<KnowledgeSource> sources) {
        this.blackboard = blackboard;
        this.sources = sources == null ? List.of() : List.copyOf(sources);
    }

    public void run() {
        ExecutorService phaseExecutor = Executors.newSingleThreadExecutor(
                new NamedThreadFactory("just-phase-"));
        boolean completed = false;
        try {
            // priority 升序（稳定）：同阶段执行序显式化。
            List<KnowledgeSource> ordered = new ArrayList<>(sources);
            ordered.sort(Comparator.comparingInt(KnowledgeSource::priority));
            Map<Phase, Map<EventType, List<KnowledgeSource>>> subsByPhase =
                    new EnumMap<>(Phase.class);
            Set<KnowledgeSource> initialized = java.util.Collections.newSetFromMap(
                    new java.util.IdentityHashMap<>());
            for (KnowledgeSource source : ordered) {
                try {
                    source.init(blackboard);
                    Phase phase = source.phase();
                    Set<EventType> interests = source.interests();
                    if (phase == null || interests == null) {
                        throw new IllegalArgumentException("phase/interests must not be null");
                    }
                    initialized.add(source);
                    Map<EventType, List<KnowledgeSource>> subscriptions =
                            subsByPhase.computeIfAbsent(phase,
                                    ignored -> new EnumMap<>(EventType.class));
                    for (EventType type : interests) {
                        if (type != null) {
                            subscriptions.computeIfAbsent(type,
                                    ignored -> new ArrayList<>(1)).add(source);
                        }
                    }
                } catch (Throwable failure) {
                    sourceFailure(source, "INIT", failure);
                }
            }

            int dispatched = 0;
            DispatchResult analysis = dispatchParallel(
                    subsByPhase.getOrDefault(Phase.ANALYSIS, Map.of()), initialized);
            dispatched += analysis.dispatched();
            if (!analysis.completed()) {
                return;
            }

            // COMPOSITION / CALIBRATION 串行（priority 序，跨源数据依赖）。
            blackboard.sortChainsForPhase();
            blackboard.publish(Event.of(EventType.SCAN_ANALYZED, -1, null));
            DispatchResult composition = drain(
                    subsByPhase.getOrDefault(Phase.COMPOSITION, Map.of()), phaseExecutor);
            dispatched += composition.dispatched();
            if (!composition.completed()) {
                return;
            }

            blackboard.sortChainsForPhase();
            blackboard.publish(Event.of(EventType.SCAN_COMPLETE, -1, null));
            DispatchResult calibration = drain(
                    subsByPhase.getOrDefault(Phase.CALIBRATION, Map.of()), phaseExecutor);
            dispatched += calibration.dispatched();
            if (!calibration.completed()) {
                return;
            }

            JustLogger.info("黑板分析完成：分发事件 {} 次，链 {} 条（校准拒绝 {} 条）",
                    dispatched, blackboard.chains().size(), blackboard.calibrationCount());
            completed = true;
        } finally {
            shutdown(phaseExecutor, "phase");
            if (!completed) {
                blackboard.markIncomplete("CONTROLLER_ABORTED");
            }
        }
    }

    /** ANALYSIS 并行派发：有界 executor + deadline + 屏障后再进入后续阶段。 */
    private DispatchResult dispatchParallel(Map<EventType, List<KnowledgeSource>> subscriptions,
                                            Set<KnowledgeSource> initialized) {
        List<KnowledgeSource> started = new ArrayList<>();
        Set<KnowledgeSource> seen = java.util.Collections.newSetFromMap(
                new java.util.IdentityHashMap<>());
        for (KnowledgeSource source : subscriptions.getOrDefault(EventType.SCAN_START, List.of())) {
            if (initialized.contains(source) && seen.add(source)) {
                started.add(source);
            }
        }
        if (started.isEmpty()) {
            blackboard.clearEvents();
            return new DispatchResult(0, true);
        }

        int workers = Math.max(1, Math.min(started.size(),
                Math.max(1, Runtime.getRuntime().availableProcessors())));
        ExecutorService executor = Executors.newFixedThreadPool(workers,
                new NamedThreadFactory("just-ks-"));
        List<Future<?>> futures = new ArrayList<>(started.size());
        for (KnowledgeSource source : started) {
            futures.add(executor.submit(() -> {
                try {
                    source.onEvent(blackboard, Event.of(EventType.SCAN_START, -1, null));
                } catch (Throwable failure) {
                    sourceFailure(source, "EVENT", failure);
                }
            }));
        }

        long deadline = deadlineNanos();
        boolean completed = true;
        for (int i = 0; i < futures.size(); i++) {
            try {
                futures.get(i).get(remainingNanos(deadline), TimeUnit.NANOSECONDS);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                blackboard.markIncomplete("CONTROLLER_INTERRUPTED");
                completed = false;
                break;
            } catch (TimeoutException timeout) {
                futures.get(i).cancel(true);
                sourceFailure(started.get(i), "TIMEOUT", timeout);
                completed = false;
                break;
            } catch (ExecutionException failure) {
                sourceFailure(started.get(i), "WORKER",
                        failure.getCause() == null ? failure : failure.getCause());
            }
        }
        if (!completed) {
            futures.forEach(future -> future.cancel(true));
        }
        shutdown(executor, "analysis");
        return new DispatchResult(started.size(), completed);
    }

    private record DispatchResult(int dispatched, boolean completed) {
    }

    /**
     * 排空事件队列。每个 handler 仍按 priority 串行执行，但运行在可取消的单线程
     * executor 中；超时后不进入下一个阶段，避免后续阶段与失控 worker 并发修改结果。
     */
    private DispatchResult drain(Map<EventType, List<KnowledgeSource>> subscriptions,
                                 ExecutorService executor) {
        int dispatched = 0;
        List<Event> deferred = new ArrayList<>();
        long deadline = deadlineNanos();
        while (blackboard.hasEvents()) {
            if (dispatched >= MAX_DISPATCH) {
                JustLogger.warn("事件派生超上限 {}，本阶段提前结束", MAX_DISPATCH);
                blackboard.markIncomplete("EVENT_DISPATCH_CAP:" + MAX_DISPATCH);
                blackboard.clearEvents();
                return new DispatchResult(dispatched, false);
            }
            Event event = blackboard.poll();
            if (event == null) {
                break;
            }
            boolean barrier = event.type() == EventType.SCAN_ANALYZED
                    || event.type() == EventType.SCAN_COMPLETE;
            List<KnowledgeSource> interested = subscriptions.get(event.type());
            if (interested == null && !barrier) {
                deferred.add(event);
                continue;
            }
            if (interested == null) {
                continue;
            }
            for (KnowledgeSource source : interested) {
                Future<?> future = executor.submit(() -> source.onEvent(blackboard, event));
                try {
                    future.get(remainingNanos(deadline), TimeUnit.NANOSECONDS);
                    dispatched++;
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    future.cancel(true);
                    blackboard.markIncomplete("CONTROLLER_INTERRUPTED");
                    return new DispatchResult(dispatched, false);
                } catch (TimeoutException timeout) {
                    future.cancel(true);
                    sourceFailure(source, "TIMEOUT", timeout);
                    return new DispatchResult(dispatched, false);
                } catch (ExecutionException failure) {
                    sourceFailure(source, "EVENT",
                            failure.getCause() == null ? failure : failure.getCause());
                }
            }
        }
        for (Event event : deferred) {
            blackboard.publish(event);
        }
        return new DispatchResult(dispatched, true);
    }

    private long deadlineNanos() {
        return System.nanoTime() + TimeUnit.SECONDS.toNanos(PHASE_TIMEOUT_SECONDS);
    }

    private static long remainingNanos(long deadline) throws TimeoutException {
        long remaining = deadline - System.nanoTime();
        if (remaining <= 0L) {
            throw new TimeoutException("phase deadline exceeded");
        }
        return remaining;
    }

    private void sourceFailure(KnowledgeSource source, String phase, Throwable failure) {
        String id;
        try {
            id = source == null || source.id() == null ? "<unknown>" : source.id();
        } catch (Throwable ignored) {
            id = "<unknown>";
        }
        blackboard.markIncomplete("SOURCE_FAILED:" + id + ":" + phase);
        JustLogger.error("知识源 {} {} 失败（已隔离）: {}", id, phase,
                failure == null ? "unknown" : failure.toString());
    }

    private static void shutdown(ExecutorService executor, String phase) {
        if (executor == null) {
            return;
        }
        executor.shutdownNow();
        try {
            if (!executor.awaitTermination(WORKER_SHUTDOWN_MILLIS, TimeUnit.MILLISECONDS)) {
                JustLogger.error("{} 阶段 worker 未在收尾窗口退出", phase);
            }
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            JustLogger.error("{} 阶段 worker 收尾被中断", phase);
        }
    }

    private static final class NamedThreadFactory implements ThreadFactory {
        private final String prefix;
        private final AtomicInteger sequence = new AtomicInteger();

        private NamedThreadFactory(String prefix) {
            this.prefix = prefix;
        }

        @Override
        public Thread newThread(Runnable runnable) {
            Thread thread = new Thread(runnable, prefix + sequence.incrementAndGet());
            thread.setDaemon(true);
            return thread;
        }
    }
}
