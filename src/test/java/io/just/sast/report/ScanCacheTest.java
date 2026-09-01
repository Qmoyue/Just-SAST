package io.just.sast.report;

import io.just.sast.blackboard.VerificationSummary;
import io.just.sast.util.ArtifactFingerprint;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ScanCacheTest {

    @Test
    void restoresOnlyTheSameCompleteReport(@TempDir Path tmp) throws Exception {
        Path artifact = tmp.resolve("app.jar");
        Files.writeString(artifact, "stable-input");
        Path source = tmp.resolve("source");
        ReportLayout sourceLayout = ReportLayout.create(source);
        String artifactHash = ArtifactFingerprint.sha256(artifact);
        String dependencyIdentity = ScanCache.dependencyIdentityFromHashes(List.of());
        String key = ScanIdentityWriter.cacheKey(artifactHash, dependencyIdentity, null, null,
                false, false, 0, false, false);
        new ScanIdentityWriter().write(sourceLayout, artifactHash, dependencyIdentity,
                "inventory", null, null, 0, false, false, 0, false, false);
        ScanStatistics complete = new ScanStatistics(1, 1, 0, 0, 0, 0,
                1, 1, 1, "COMPLETE", List.of(), java.util.Map.of(), java.util.Map.of(),
                "DISABLED", VerificationSummary.empty("DISABLED", 0), "COMPLETE", artifactHash);

        Path cache = tmp.resolve("cache");
        assertTrue(ScanCache.store(cache, key, source, complete));
        Path restored = tmp.resolve("restored");
        assertTrue(ScanCache.restore(cache, key, restored));
        assertTrue(Files.exists(restored.resolve("meta/scan-identity.json")));
        assertTrue(Files.readString(restored.resolve("meta/cache-event.json")).contains("\"hit\""));

        Files.writeString(artifact, "changed-input");
        ScanCache.Preflight changed = ScanCache.preflight(artifact, List.of(), null, null,
                false, false, 0, false, false);
        assertFalse(changed.cacheKey().equals(key));
        assertFalse(ScanCache.restore(cache, changed.cacheKey(), tmp.resolve("miss")));
    }

    @Test
    void neverCachesPartialOrNegativeDynamicResults(@TempDir Path tmp) {
        ScanStatistics partial = new ScanStatistics(0, 0, 0, 0, 0, 0,
                0, 0, 0, "PARTIAL", List.of("ANALYSIS_BOUND"), java.util.Map.of(),
                java.util.Map.of(), "PROCESS_RESOURCE",
                VerificationSummary.empty("PROCESS_RESOURCE", 1), "PARTIAL", "hash");
        assertFalse(ScanCache.cacheable(partial));
    }
}
