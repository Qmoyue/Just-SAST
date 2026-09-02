package io.just.sast.blackboard;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ChainStoreTest {

    @Test
    void semanticReplacementKeepsOneStableSlotAfterPhaseSort() {
        Chain weaker = chain(2, "weak");
        Chain stronger = chain(0, "strong");
        ChainStore store = new ChainStore();

        assertTrue(store.add(weaker).accepted());
        assertTrue(store.add(stronger).accepted());
        assertEquals(1, store.snapshot().size());
        assertEquals("strong", store.snapshot().get(0).hops().get(0).reason());

        store.sortForPhase();
        assertFalse(store.add(chain(1, "middle")).accepted());
        assertEquals("strong", store.snapshot().get(0).hops().get(0).reason());
    }

    private static Chain chain(int unresolved, String reason) {
        ChainHop hop = new ChainHop("source/Entry", "readObject", "sink/Target", "run",
                HopKind.DIRECT_CALL, null, reason, "()V", null);
        return new Chain("RULE", "category", "HIGH", "source/Entry", "readObject",
                "readObject", "sink/Target", "run", List.of(hop), unresolved,
                "()V", "TERMINAL");
    }
}
