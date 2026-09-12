package io.just.sast.verify;

import io.just.sast.blackboard.Chain;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.function.BiConsumer;
import java.util.function.BiFunction;
import java.util.function.Function;

/**
 * Deterministic, bounded completion scheduler for one verifier attempt.
 *
 * <p>The scheduler owns only submission/completion/deadline mechanics.  It does not classify
 * probe statuses or decide whether a timeout is a contradiction.  Callers provide typed result
 * factories for worker failures and deadline exhaustion; both results are retained in input
 * order by the shared {@link VerificationAttemptStore}.  This keeps scheduling policy separate
 * from the child protocol and from the verifier's semantic result mapping.</p>
 */
final class VerificationScheduler {

    private VerificationScheduler() {
    }

    record Batch(List<ParallelVerifier.VerifyResult> results, int submitted, int completed,
                 int failed, int timedOut, long durationMs) {
        Batch {
            results = List.copyOf(results == null ? List.of() : results);
            submitted = Math.max(0, submitted);
            completed = Math.max(0, completed);
            failed = Math.max(0, failed);
            timedOut = Math.max(0, timedOut);
            durationMs = Math.max(0L, durationMs);
        }
    }

    /**
     * Submit all inputs, poll one shared deadline and return a complete input-indexed snapshot.
     * No caller may observe completion order, and every submitted slot receives exactly one
     * result, including interruption, worker failure and future timeout.
     */
    static Batch run(List<Chain> chains, ExecutorService pool, int workers, int timeoutSeconds,
                     Function<Chain, ParallelVerifier.VerifyResult> worker,
                     BiFunction<Chain, Long, ParallelVerifier.VerifyResult> timeoutFactory,
                     BiFunction<Chain, Exception, ParallelVerifier.VerifyResult> failureFactory,
                     BiConsumer<String, Long> phaseObserver) {
        if (chains == null || chains.isEmpty()) {
            return new Batch(List.of(), 0, 0, 0, 0, 0L);
        }
        if (pool == null || worker == null || timeoutFactory == null || failureFactory == null) {
            throw new IllegalArgumentException("scheduler dependencies are required");
        }
        long started = System.nanoTime();
        ExecutorCompletionService<IndexedResult> completion =
                new ExecutorCompletionService<>(pool);
        Map<Future<IndexedResult>, Integer> pending = new HashMap<>();
        VerificationAttemptStore attemptStore = new VerificationAttemptStore(chains.size());
        for (int i = 0; i < chains.size(); i++) {
            final int index = i;
            final Chain chain = chains.get(i);
            final long queuedAt = System.nanoTime();
            Future<IndexedResult> future = completion.submit(() -> {
                if (phaseObserver != null) {
                    phaseObserver.accept("queue", Math.max(0L, System.nanoTime() - queuedAt));
                }
                return new IndexedResult(index, worker.apply(chain));
            });
            pending.put(future, index);
        }
        int timeout = Math.max(0, timeoutSeconds);
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(timeout);
        int completed = 0;
        int failed = 0;
        while (!pending.isEmpty()) {
            Future<IndexedResult> future;
            try {
                long remaining = deadline - System.nanoTime();
                if (remaining <= 0L) {
                    break;
                }
                future = completion.poll(remaining, TimeUnit.NANOSECONDS);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                break;
            }
            if (future == null) {
                break;
            }
            Integer expectedIndex = pending.remove(future);
            if (expectedIndex == null) {
                continue;
            }
            try {
                IndexedResult completedResult = future.get();
                attemptStore.record(completedResult.index(), completedResult.result());
                completed++;
            } catch (Exception failure) {
                Chain chain = chains.get(expectedIndex);
                attemptStore.record(expectedIndex, failureFactory.apply(chain, failure));
                failed++;
            }
        }
        int timedOut = pending.size();
        long timeoutMs = Math.max(0L, timeout) * 1000L;
        for (Map.Entry<Future<IndexedResult>, Integer> entry : pending.entrySet()) {
            entry.getKey().cancel(true);
            int index = entry.getValue();
            attemptStore.record(index, timeoutFactory.apply(chains.get(index), timeoutMs));
        }
        return new Batch(attemptStore.ordered(), chains.size(), completed, failed, timedOut,
                TimeUnit.NANOSECONDS.toMillis(Math.max(0L, System.nanoTime() - started)));
    }

    private record IndexedResult(int index, ParallelVerifier.VerifyResult result) {
    }
}
