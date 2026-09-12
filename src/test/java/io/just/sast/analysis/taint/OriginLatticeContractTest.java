package io.just.sast.analysis.taint;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OriginLatticeContractTest {

    @Test
    void snapshotIsSortedImmutableAndNullTolerant() {
        OriginLattice.Join snapshot = OriginLattice.snapshot(Arrays.asList(
                new ValueOrigin.Constant("b"), null, new ValueOrigin.Constant("a")));
        assertEquals(List.of(new ValueOrigin.Constant("a"), new ValueOrigin.Constant("b")),
                List.copyOf(snapshot.values()));
        assertFalse(snapshot.truncated());
        assertThrows(UnsupportedOperationException.class,
                () -> snapshot.values().add(new ValueOrigin.Unknown()));
    }

    @Test
    void joinPreservesMonotonicityAndMarksBoundedLoss() {
        Set<ValueOrigin> left = new LinkedHashSet<>(List.of(new ValueOrigin.Constant("a")));
        Set<ValueOrigin> right = new LinkedHashSet<>(List.of(new ValueOrigin.Constant("b")));
        OriginLattice.Join exact = OriginLattice.joinTrusted(left, right, 4, false);
        assertEquals(Set.of(new ValueOrigin.Constant("a"), new ValueOrigin.Constant("b")), exact.values());
        assertFalse(exact.truncated());

        Set<ValueOrigin> many = new LinkedHashSet<>();
        for (int i = 0; i < 8; i++) {
            many.add(new ValueOrigin.Constant(i));
        }
        OriginLattice.Join bounded = OriginLattice.joinTrusted(many, Set.of(), 3, false);
        assertEquals(3, bounded.values().size());
        assertTrue(bounded.truncated());
        assertSame(left, OriginLattice.joinTrusted(left, Set.of(), 4, false).values());
        assertTrue(OriginLattice.joinTrusted(left, right, 4, true).truncated());
    }
}
