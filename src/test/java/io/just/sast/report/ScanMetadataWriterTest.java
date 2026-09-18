package io.just.sast.report;

import io.just.sast.analysis.taint.FilterAnalysis;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ScanMetadataWriterTest {

    @Test
    void metadataPersistsStaticRunAndFilterEvidence(@TempDir Path temp) throws Exception {
        ScanStatistics stats = stats();
        ReportLayout layout = ReportLayout.create(temp);
        new ScanMetadataWriter().write(layout, stats);

        String metadata = Files.readString(temp.resolve("meta/scan-metadata.json"));
        String run = Files.readString(temp.resolve("meta/run.json"));
        assertTrue(metadata.contains("\"run_outcome\":{\"schema_version\":1"));
        assertTrue(metadata.contains("\"artifact_sha256\":\"" + "a".repeat(64) + "\""));
        assertTrue(metadata.contains("\"filter_evidence\":"));
        assertTrue(metadata.contains("\"domain_digest\":\"" + "b".repeat(64) + "\""));
        assertTrue(metadata.contains("\"expanded\":4"));
        assertTrue(metadata.contains("\"filter_cost_nanos\":123"));
        assertFalse(metadata.contains("dynamic_verification"));
        assertFalse(metadata.contains("verificationMode"));
        assertTrue(run.contains("\"kind\":\"just-run\""));
        assertFalse(run.contains("verification"));
    }

    @Test
    void metadataExposesTimingAndDependencySourceSnapshot(@TempDir Path temp)
            throws Exception {
        ScanStatistics stats = stats();
        ReportLayout layout = ReportLayout.create(temp);
        new ScanMetadataWriter().write(layout, stats);

        String metadata = Files.readString(temp.resolve("meta/scan-metadata.json"));
        assertTrue(metadata.contains("\"dependency_resolution_ms\":8")
                        && metadata.contains("\"network_download_wall_ms\":12")
                        && metadata.contains("\"filter_ms\":0")
                        && metadata.contains("\"total_wall_ms\":49"), metadata);
        assertFalse(metadata.contains("verification"));
    }

    private static ScanStatistics stats() {
        Map<String, Long> metrics = Map.ofEntries(
                Map.entry("dependency_resolution_ms", 8L),
                Map.entry("network_download_wall_ms", 12L),
                Map.entry("network_request_ms", 15L),
                Map.entry("analysis_ms", 21L),
                Map.entry("filter_ms", 0L),
                Map.entry("report_ms", 5L),
                Map.entry("total_wall_ms", 49L),
                Map.entry("dependency_source_actual_application", 1L),
                Map.entry("dependency_source_actual_embedded", 2L),
                Map.entry("dependency_source_actual_explicit", 3L),
                Map.entry("dependency_source_pom_derived", 4L),
                Map.entry("dependency_source_cache", 5L),
                Map.entry("dependency_source_remote", 6L),
                Map.entry("dependency_source_jdk", 7L));
        Map<String, String> statuses = Map.ofEntries(
                Map.entry("dependency_resolution_ms", "OBSERVED"),
                Map.entry("network_download_wall_ms", "OBSERVED"),
                Map.entry("network_request_ms", "OBSERVED"),
                Map.entry("analysis_ms", "OBSERVED"),
                Map.entry("filter_ms", "NOT_APPLICABLE"),
                Map.entry("report_ms", "OBSERVED"),
                Map.entry("total_wall_ms", "OBSERVED"));
        return new ScanStatistics(1, 1, 0, 1, 1, 1,
                49L, 10L, 12L, "COMPLETE", List.of(),
                Map.of("dependency_resolution", 8L, "analysis", 21L, "report", 5L),
                metrics, "STATIC_ONLY", "a".repeat(64), statuses, Map.of(), Map.of(),
                List.of(new FilterAnalysis.Evidence(
                        FilterAnalysis.Kind.CFG_PATH,
                        "app.Entry#readObject@12",
                        FilterAnalysis.Status.PROVABLY_UNREACHABLE,
                        "CFG_EXACT_PATH_UNREACHABLE",
                        "b".repeat(64), "c".repeat(64), 4096,
                        3L, 1L, 2L, 4L, 123L)));
    }
}
