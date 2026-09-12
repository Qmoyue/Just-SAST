package io.just.sast.verify;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** P2.5 protection for index-stable completion and explicit result replacement semantics. */
class VerificationAttemptStoreContractTest {

    @Test
    void completionOrderDoesNotChangeOrderedSnapshot() {
        VerificationAttemptStore store = new VerificationAttemptStore(2);
        ParallelVerifier.VerifyResult second = result("second");
        ParallelVerifier.VerifyResult first = result("first");
        store.record(1, second);
        store.record(0, first);

        assertEquals(List.of(first, second), store.ordered());
        assertEquals(2, store.recordedCount());
        assertTrue(store.isRecorded(0));
        assertTrue(store.isRecorded(1));
        assertThrows(UnsupportedOperationException.class,
                () -> store.ordered().set(0, second));
    }

    @Test
    void replacementDoesNotInflateRecordedCountAndMalformedWritesFailClosed() {
        VerificationAttemptStore store = new VerificationAttemptStore(1);
        ParallelVerifier.VerifyResult first = result("first");
        ParallelVerifier.VerifyResult replacement = result("replacement");
        store.record(0, first);
        store.record(0, replacement);

        assertEquals(1, store.recordedCount());
        assertEquals(replacement, store.ordered().get(0));
        assertThrows(IndexOutOfBoundsException.class,
                () -> new VerificationAttemptStore(0).isRecorded(0));
        assertThrows(IllegalArgumentException.class, () -> store.record(0, null));
        assertThrows(IndexOutOfBoundsException.class, () -> store.record(-1, first));
    }

    private static ParallelVerifier.VerifyResult result(String detail) {
        return new ParallelVerifier.VerifyResult("chain-" + detail, "UNKNOWN", detail);
    }
}
