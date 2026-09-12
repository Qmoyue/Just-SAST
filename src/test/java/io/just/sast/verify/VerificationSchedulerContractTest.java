package io.just.sast.verify;

import io.just.sast.blackboard.Chain;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Scheduler contract: bounded completion, fail-closed factories and input-order snapshots. */
class VerificationSchedulerContractTest {

    @Test
    void completionOrderCannotChangeResultOrder() throws Exception {
        var pool = Executors.newFixedThreadPool(2);
        try {
            List<Chain> chains = List.of(chain("first"), chain("second"));
            VerificationScheduler.Batch batch = VerificationScheduler.run(
                    chains, pool, 2, 2,
                    current -> {
                        if ("first".equals(current.entryClass())) {
                            try {
                                Thread.sleep(40L);
                            } catch (InterruptedException interrupted) {
                                Thread.currentThread().interrupt();
                            }
                        }
                        return new ParallelVerifier.VerifyResult(current.key(), "EXECUTED", "ok");
                    },
                    (current, timeoutMs) -> new ParallelVerifier.VerifyResult(
                            current.key(), "UNTESTABLE", "timeout=" + timeoutMs),
                    (current, failure) -> new ParallelVerifier.VerifyResult(
                            current.key(), "UNTESTABLE", "failure=" + failure.getClass().getSimpleName()),
                    (name, nanos) -> { });

            assertEquals(chains.stream().map(Chain::key).toList(),
                    batch.results().stream().map(ParallelVerifier.VerifyResult::chainKey).toList());
            assertEquals(2, batch.submitted());
            assertEquals(2, batch.completed());
            assertEquals(0, batch.failed());
            assertEquals(0, batch.timedOut());
        } finally {
            pool.shutdownNow();
            pool.awaitTermination(2, TimeUnit.SECONDS);
        }
    }

    @Test
    void deadlineProducesUnknownTimeoutForEveryPendingSlot() throws Exception {
        var pool = Executors.newFixedThreadPool(1);
        try {
            Chain chain = chain("blocked");
            VerificationScheduler.Batch batch = VerificationScheduler.run(
                    List.of(chain), pool, 1, 0,
                    ignored -> {
                        try {
                            Thread.sleep(10_000L);
                        } catch (InterruptedException interrupted) {
                            Thread.currentThread().interrupt();
                        }
                        return new ParallelVerifier.VerifyResult("blocked", "EXECUTED", "late");
                    },
                    (current, timeoutMs) -> new ParallelVerifier.VerifyResult(
                            current.key(), "UNTESTABLE", "verification-future-timeout"),
                    (current, failure) -> new ParallelVerifier.VerifyResult(
                            current.key(), "UNTESTABLE", "failure"),
                    (name, nanos) -> { });

            assertEquals(1, batch.timedOut());
            assertEquals(0, batch.completed());
            assertEquals("UNTESTABLE", batch.results().get(0).status());
        } finally {
            pool.shutdownNow();
            pool.awaitTermination(2, TimeUnit.SECONDS);
        }
    }

    @Test
    void workerFailureUsesTypedUnknownResult() throws Exception {
        var pool = Executors.newFixedThreadPool(1);
        try {
            Chain chain = chain("failure");
            VerificationScheduler.Batch batch = VerificationScheduler.run(
                    List.of(chain), pool, 1, 1,
                    ignored -> { throw new IllegalStateException("boom"); },
                    (current, timeoutMs) -> new ParallelVerifier.VerifyResult(
                            current.key(), "UNTESTABLE", "timeout"),
                    (current, failure) -> new ParallelVerifier.VerifyResult(
                            current.key(), "UNTESTABLE", "failure=" + failure.getClass().getSimpleName()),
                    (name, nanos) -> { });

            assertEquals(1, batch.failed());
            assertEquals("UNTESTABLE", batch.results().get(0).status());
            assertTrue(batch.results().get(0).detail().startsWith("failure="));
        } finally {
            pool.shutdownNow();
            pool.awaitTermination(2, TimeUnit.SECONDS);
        }
    }

    private static Chain chain(String owner) {
        return new Chain("rule", "category", "HIGH", "app/" + owner, "entry",
                "DIRECT", "sink/Target", "call", List.of(), 0);
    }
}
