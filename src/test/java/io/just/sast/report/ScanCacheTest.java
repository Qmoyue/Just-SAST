package io.just.sast.report;

import io.just.sast.blackboard.VerificationSummary;
import io.just.sast.run.InputBudget;
import io.just.sast.util.ArtifactFingerprint;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
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
                false, "component");
        new ScanIdentityWriter().write(sourceLayout, artifactHash, dependencyIdentity,
                "inventory", null, null, 0, false, "component");
        assertFalse(Files.readString(source.resolve("meta/scan-identity.json"))
                .contains("verify"));
        ScanStatistics complete = new ScanStatistics(1, 1, 0, 0, 0, 0,
                1, 1, 1, "COMPLETE", List.of(), java.util.Map.of(), java.util.Map.of(),
                "DISABLED", VerificationSummary.empty("DISABLED", 0), "COMPLETE", artifactHash);
        assertTrue(complete.runOutcome().cacheable());

        Path cache = tmp.resolve("cache");
        assertTrue(ScanCache.store(cache, key, source, complete));
        Path restored = tmp.resolve("restored");
        assertTrue(ScanCache.restore(cache, key, restored));
        assertTrue(Files.exists(restored.resolve("meta/scan-identity.json")));
        assertTrue(Files.readString(restored.resolve("meta/cache-event.json")).contains("\"hit\""));

        Path precreated = tmp.resolve("precreated");
        Files.createDirectories(precreated);
        assertTrue(ScanCache.restore(cache, key, precreated));
        assertTrue(Files.exists(precreated.resolve("meta/scan-identity.json")));

        InputBudget tiny = InputBudget.defaults().withArchiveLimits(
                1024, 1024, 8, 8, 16, 2, 16);
        Path budgetCache = tmp.resolve("cache-budget");
        assertThrows(java.io.IOException.class,
                () -> ScanCache.store(budgetCache, key, source, complete, tiny));
        assertFalse(Files.exists(budgetCache.resolve(key), java.nio.file.LinkOption.NOFOLLOW_LINKS));
        assertThrows(java.io.IOException.class,
                () -> ScanCache.restore(cache, key, tmp.resolve("budget-rejected"), tiny));
        assertFalse(Files.exists(tmp.resolve("budget-rejected"),
                java.nio.file.LinkOption.NOFOLLOW_LINKS));

        Files.writeString(artifact, "changed-input");
        ScanCache.Preflight changed = ScanCache.preflight(artifact, List.of(), null, null,
                false, "component");
        assertFalse(changed.cacheKey().equals(key));
        assertFalse(ScanCache.restore(cache, changed.cacheKey(), tmp.resolve("miss")));
    }

    @Test
    void neverCachesPartialOrNegativeDynamicResults(@TempDir Path tmp) {
        ScanStatistics partial = new ScanStatistics(0, 0, 0, 0, 0, 0,
                0, 0, 0, "PARTIAL", List.of("ANALYSIS_BOUND"), java.util.Map.of(),
                java.util.Map.of(), "PROCESS_RESOURCE",
                VerificationSummary.empty("PROCESS_RESOURCE", 1), "PARTIAL", "hash");
        assertFalse(partial.runOutcome().cacheable());
        assertFalse(ScanCache.cacheable(partial));
    }

    @Test
    void inputBudgetVersionAndDigestParticipateInCacheIdentity(@TempDir Path tmp) throws Exception {
        Path artifact = tmp.resolve("app.jar");
        Files.writeString(artifact, "stable-input");
        String artifactHash = ArtifactFingerprint.sha256(artifact);
        String dependencyIdentity = ScanCache.dependencyIdentityFromHashes(List.of());
        String defaultKey = ScanIdentityWriter.cacheKey(artifactHash, dependencyIdentity,
                null, null, false, "component");
        InputBudget defaults = InputBudget.defaults();
        InputBudget changed = defaults.withRuleInputBytes(defaults.maxRuleInputBytes() / 2);
        String changedKey = ScanIdentityWriter.cacheKey(artifactHash, dependencyIdentity,
                null, null, false, "component", changed);
        assertFalse(defaultKey.equals(changedKey));
    }

    @Test
    void effectiveDependencyEnvironmentInvalidatesSameBytes(@TempDir Path tmp) throws Exception {
        Path artifact = tmp.resolve("app.jar");
        Files.writeString(artifact, "stable-input");
        ScanCache.Preflight first = ScanCache.preflight(artifact, List.of(), null, null,
                false, "component", "pom-environment-a");
        ScanCache.Preflight changed = ScanCache.preflight(artifact, List.of(), null, null,
                false, "component", "pom-environment-b");

        assertFalse(first.dependencyIdentity().equals(changed.dependencyIdentity()));
        assertFalse(first.cacheKey().equals(changed.cacheKey()));
    }

    @Test
    void preflightSharesInputBudgetAcrossTargetAndDependencies(@TempDir Path tmp) throws Exception {
        Path artifact = tmp.resolve("app.jar");
        Path dependency = tmp.resolve("dep.jar");
        Files.writeString(artifact, "abcd");
        Files.writeString(dependency, "efgh");
        InputBudget budget = InputBudget.defaults().withArchiveLimits(
                1024, 1024, 5, 1024, 16, 2, 16);

        assertThrows(java.io.IOException.class, () -> ScanCache.preflight(artifact,
                List.of(dependency), null, null, false, "component", budget));
    }

    @Test
    void scanIdentitySharesBudgetAcrossRulesAndJdkRelease(@TempDir Path tmp) throws Exception {
        Path rules = tmp.resolve("rules.yaml");
        Files.write(rules, new byte[]{1, 2, 3});
        Path jdk = Files.createDirectories(tmp.resolve("jdk"));
        Files.write(jdk.resolve("release"), new byte[]{4, 5, 6});
        InputBudget defaults = InputBudget.defaults();
        InputBudget budget = defaults.withArchiveLimits(
                1024, 1024, 5, 1024, 16, defaults.maxArchiveNesting(),
                defaults.maxClassEntries());

        InputBudget.Tracker directTracker = budget.tracker();
        ArtifactFingerprint.sha256(rules, directTracker);
        assertThrows(java.io.IOException.class, () -> ArtifactFingerprint.sha256(
                jdk.resolve("release"), directTracker));
        assertTrue(Files.isRegularFile(jdk.resolve("release"),
                java.nio.file.LinkOption.NOFOLLOW_LINKS));
        assertFalse(io.just.sast.util.ArchiveLimits.isLinkOrReparsePoint(jdk.resolve("release")));

        assertThrows(java.io.IOException.class, () -> ScanIdentityWriter.cacheKey(
                "a".repeat(64), "b".repeat(64), rules, jdk,
                false, "component", budget));
    }

    @Test
    void cacheMetadataSharesCallerBudgetAcrossSentinelAndIdentity(@TempDir Path tmp)
            throws Exception {
        String key = "a".repeat(64);
        Path metadata = tmp.resolve("cache").resolve(key).resolve("meta");
        Files.createDirectories(metadata);
        Files.writeString(metadata.resolve("scan-identity.json"),
                "{\"schema_version\":1,\"cache_key\":\"" + key + "\"}\n");
        Files.writeString(metadata.resolve("cache-complete.json"),
                "{\"schema_version\":1,\"cache_key\":\"" + key
                        + "\",\"completeness\":\"COMPLETE\"}\n");
        InputBudget defaults = InputBudget.defaults();
        InputBudget budget = defaults.withArchiveLimits(
                4096, 4096, 150, 150, 16, defaults.maxArchiveNesting(),
                defaults.maxClassEntries());

        assertThrows(java.io.IOException.class, () -> ScanCache.restore(
                tmp.resolve("cache"), key, tmp.resolve("restored"), budget));
        assertFalse(Files.exists(tmp.resolve("restored"),
                java.nio.file.LinkOption.NOFOLLOW_LINKS));
    }
}
