package io.just.sast.cli;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Protects the closed, monotonic GC telemetry contract used by resource baselines. */
class GcTelemetryContractTest {

    @Test
    void monotonicSnapshotsExposeOnlyTheScanDelta() {
        ScanPipeline.GcSnapshot before = new ScanPipeline.GcSnapshot(3L, 7L, true);
        ScanPipeline.GcSnapshot after = new ScanPipeline.GcSnapshot(9L, 22L, true);

        ScanPipeline.GcSnapshot delta = after.delta(before);

        assertTrue(delta.observed());
        assertEquals(6L, delta.collectionCount());
        assertEquals(15L, delta.collectionTimeMs());
    }

    @Test
    void counterResetOrUnknownInputDoesNotBecomeZero() {
        ScanPipeline.GcSnapshot reset = new ScanPipeline.GcSnapshot(2L, 10L, true)
                .delta(new ScanPipeline.GcSnapshot(3L, 9L, true));
        ScanPipeline.GcSnapshot unavailable = ScanPipeline.GcSnapshot.unknown()
                .delta(new ScanPipeline.GcSnapshot(0L, 0L, true));

        assertFalse(reset.observed());
        assertEquals(-1L, reset.collectionCount());
        assertEquals(-1L, reset.collectionTimeMs());
        assertFalse(unavailable.observed());
        assertEquals(-1L, unavailable.collectionCount());
        assertEquals(-1L, unavailable.collectionTimeMs());
    }

    @Test
    void platformSnapshotUsesClosedValues() {
        ScanPipeline.GcSnapshot snapshot = ScanPipeline.gcSnapshot();
        if (snapshot.observed()) {
            assertTrue(snapshot.collectionCount() >= 0L);
            assertTrue(snapshot.collectionTimeMs() >= 0L);
        } else {
            assertEquals(-1L, snapshot.collectionCount());
            assertEquals(-1L, snapshot.collectionTimeMs());
        }
    }
}
