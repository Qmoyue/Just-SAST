package io.just.sast.report;

import io.just.sast.analysis.taint.FilterAnalysis;
import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.HopKind;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MultiFormatReporterTest {

    @Test
    void writesStaticDetailedViewsFromOneSnapshot(@TempDir Path temp) throws Exception {
        Chain chain = new Chain("RULE-1", "DESERIALIZE", "HIGH",
                "example.Entry", "readObject", "deserialize",
                "java.lang.reflect.Method", "invoke",
                List.of(new ChainHop("example.Entry", "readObject",
                        "java.lang.reflect.Method", "invoke", HopKind.DIRECT_CALL,
                        null, "test", "()V", null)), 0);

        FindingOutputReader.Snapshot snapshot = new FindingOutputReader().read(
                List.of(chain), Map.of(), Map.of(), Map.of());
        new MultiFormatReporter().write(ReportLayout.create(temp), snapshot);

        String json = Files.readString(temp.resolve("findings/findings.json"));
        assertTrue(json.startsWith("[\n") && json.endsWith("\n]\n"));
        assertTrue(json.contains("\"construction\":"));
        assertTrue(json.contains("\"sink_control\":\"STATIC_UNCERTAIN\""));
        assertFalse(json.contains("verification"));
        assertTrue(Files.readString(temp.resolve("findings/findings.html"))
                .contains("Static evidence only"));
        assertTrue(Files.readString(temp.resolve("findings/findings.md"))
                .contains("java.lang.reflect.Method"));
    }

    @Test
    void metadataPersistsStaticRunAndFilterEvidence(@TempDir Path temp) throws Exception {
        ScanStatistics stats = stats();
        ReportLayout layout = ReportLayout.create(temp);
        new MultiFormatReporter().writeMetadata(layout, stats);

        String metadata = Files.readString(temp.resolve("meta/scan-metadata.json"));
        String run = Files.readString(temp.resolve("meta/run.json"));
        assertTrue(metadata.contains("\"run_outcome\":{\"schema_version\":1"));
        assertTrue(metadata.contains("\"artifact_sha256\":\"" + "a".repeat(64) + "\""));
        assertTrue(metadata.contains("\"filter_evidence\":["));
        assertTrue(metadata.contains("\"domain_digest\":\"" + "b".repeat(64) + "\""));
        assertTrue(metadata.contains("\"expanded\":4"));
        assertTrue(metadata.contains("\"filter_cost_nanos\":123"));
        assertFalse(metadata.contains("dynamic_verification"));
        assertFalse(metadata.contains("verificationMode"));
        assertTrue(run.contains("\"kind\":\"just-run\""));
        assertFalse(run.contains("verification"));
    }

    @Test
    void metadataAndIndexExposeTimingAndDependencySourceSnapshot(@TempDir Path temp)
            throws Exception {
        ScanStatistics stats = stats();
        ReportLayout layout = ReportLayout.create(temp);
        new MultiFormatReporter().writeMetadata(layout, stats);
        new ReportIndexWriter().write(layout, stats);

        String metadata = Files.readString(temp.resolve("meta/scan-metadata.json"));
        String index = Files.readString(temp.resolve("index.md"));
        assertTrue(metadata.contains("\"dependency_resolution_ms\":8")
                        && metadata.contains("\"network_download_wall_ms\":12")
                        && metadata.contains("\"filter_ms\":0")
                        && metadata.contains("\"total_wall_ms\":49"), metadata);
        assertTrue(index.contains("| Dependency resolution | 8 ms (OBSERVED) |")
                        && index.contains("| Bounded filter | 0 ms (NOT_APPLICABLE) |")
                        && index.contains("actual_application=1")
                        && index.contains("pom_derived=4")
                        && index.contains("jdk=7"), index);
        assertFalse(index.contains("verification"));
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
