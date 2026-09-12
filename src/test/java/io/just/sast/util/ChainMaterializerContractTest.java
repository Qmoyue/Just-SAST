package io.just.sast.util;

import io.just.sast.blackboard.Chain;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertNull;

class ChainMaterializerContractTest {

    @Test
    void memoizerSharesOneImmutableChain() {
        Chain expected = new Chain("runtime-exec", "CODE_EXEC", "HIGH",
                "fixture/app/Trigger", "readObject", "readObject",
                "java/lang/Runtime", "exec", List.of(), 0,
                "(Ljava/lang/String;)Ljava/lang/Process;", "TERMINAL");
        AtomicInteger materializations = new AtomicInteger();
        Supplier<Chain> memoized = ChainMaterializer.memoize(() -> {
            materializations.incrementAndGet();
            return expected;
        });

        assertSame(expected, memoized.get());
        assertSame(expected, memoized.get());
        assertEquals(1, materializations.get());
    }

    @Test
    void memoizerCachesTypedNull() {
        AtomicInteger materializations = new AtomicInteger();
        Supplier<Chain> memoized = ChainMaterializer.memoize(() -> {
            materializations.incrementAndGet();
            return null;
        });

        assertNull(memoized.get());
        assertNull(memoized.get());
        assertEquals(1, materializations.get());
    }

    @Test
    void memoizerCachesRuntimeFailureAsTypedFailClosedResult() {
        AtomicInteger attempts = new AtomicInteger();
        RuntimeException failure = new IllegalStateException("chain unavailable");
        Supplier<Chain> memoized = ChainMaterializer.memoize(() -> {
            attempts.incrementAndGet();
            throw failure;
        });

        RuntimeException first = assertThrows(RuntimeException.class, memoized::get);
        RuntimeException second = assertThrows(RuntimeException.class, memoized::get);
        assertSame(failure, first, "the first failure must remain observable");
        assertSame(failure, second, "repeated reads must reuse the same typed failure");
        assertEquals(1, attempts.get(),
                "a failed deferred chain must not rerun for every consumer");
    }
}
