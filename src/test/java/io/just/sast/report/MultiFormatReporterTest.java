package io.just.sast.report;

import io.just.sast.blackboard.VerificationSummary;
import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.HopKind;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertTrue;

class MultiFormatReporterTest {

    @Test
    void writesLargeFindingFormatsIncrementally(@TempDir Path temp) throws Exception {
        Chain chain = new Chain("RULE-1", "DESERIALIZE", "HIGH",
                "example.Entry", "readObject", "deserialize",
                "java.lang.reflect.Method", "invoke",
                List.of(new ChainHop("example.Entry", "readObject",
                        "java.lang.reflect.Method", "invoke", HopKind.DIRECT_CALL,
                        null, "test", "()V", null)), 0);

        new MultiFormatReporter().write(temp, List.of(chain), Map.of(), Map.of());

        String json = Files.readString(temp.resolve("findings.json"));
        assertTrue(json.startsWith("[\n") && json.endsWith("\n]"));
        assertTrue(json.contains("\"construction\":")
                && json.contains("\"sink_control\":\"STATIC_UNCERTAIN\""));
        assertTrue(Files.readString(temp.resolve("findings.html")).contains("RULE-1"));
        assertTrue(Files.readString(temp.resolve("findings.html")).contains("Construction"));
        assertTrue(Files.readString(temp.resolve("findings.md")).contains("java.lang.reflect.Method"));
    }

    @Test
    void metadataPersistsDynamicVerificationAsSeparateDeterministicArtifact(@TempDir Path temp)
            throws Exception {
        VerificationSummary summary = new VerificationSummary(
                "JVM_SANDBOX", 4, 1, 0, 1,
                Map.of("CONFIRMED", 1), Map.of(),
                List.of(new VerificationSummary.ChainResult(
                        1, "entry|sink", "CONFIRMED", "SINK_REACHED",
                        "HIGH", 12, 1, 17)));
        ScanStatistics stats = new ScanStatistics(1, 1, 0, 1, 1, 1,
                20, 10, 12, "COMPLETE", List.of(), Map.of("report", 1L),
                Map.of("graph_nodes", 3L),
                "JVM_SANDBOX", summary, "UNKNOWN");

        new MultiFormatReporter().writeMetadata(temp, stats);

        String metadata = Files.readString(temp.resolve("scan-metadata.json"));
        String dynamic = Files.readString(temp.resolve("dynamic-verification.json"));
        String run = Files.readString(temp.resolve("run.json"));
        assertTrue(metadata.contains("\"dynamic_verification\""));
        assertTrue(metadata.contains("\"run_outcome\":{\"schema_version\":1")
                && metadata.contains("\"status\":\"PARTIAL\""));
        assertTrue(metadata.contains("\"schema_version\":1")
                && metadata.contains("\"verificationMode\":\"AUTO\"")
                && metadata.contains("\"targetCodeExecutionPossible\":true")
                && metadata.contains("\"resourceContainmentOnly\":true")
                && metadata.contains("\"filesystemIsolation\":false")
                && metadata.contains("\"isolation_level\":\"UNKNOWN\"")
                && metadata.contains("\"isolation_capabilities\":[]")
                && metadata.contains("\"artifact_sha256\":\"UNKNOWN\"")
                && metadata.contains("\"heap_peak_mb\":12")
                && metadata.contains("\"chain_proof_completeness\":\"UNKNOWN\"")
                && metadata.contains("\"metrics\":{\"graph_nodes\":3}")
                && metadata.contains("\"metric_status\":{}")
                && metadata.contains("\"metric_namespaces\":{}")
                && metadata.contains("\"metric_namespace_status\":{}"));
        assertTrue(run.contains("\"kind\":\"just-run\"")
                && run.contains("\"run_outcome\":{\"schema_version\":1")
                && run.contains("\"verificationMode\":\"AUTO\"")
                && run.contains("\"targetCodeExecutionPossible\":true")
                && run.contains("\"recommendedForUntrustedArtifacts\":false"));
        assertTrue(dynamic.contains("\"status\":\"CONFIRMED\"")
                && dynamic.contains("\"schema_version\":1")
                && dynamic.contains("\"artifact_sha256\":\"UNKNOWN\"")
                && dynamic.contains("\"confidence_score\":12")
                && dynamic.contains("\"duration_ms\":17"));
    }

    @Test
    void metadataAndIndexExposeOneTimingAndDependencySourceSnapshot(@TempDir Path temp)
            throws Exception {
        Map<String, Long> metrics = Map.ofEntries(
                Map.entry("dependency_resolution_ms", 8L),
                Map.entry("network_download_wall_ms", 12L),
                Map.entry("network_request_ms", 15L),
                Map.entry("analysis_ms", 21L),
                Map.entry("dynamic_filter_ms", 0L),
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
                Map.entry("dynamic_filter_ms", "NOT_APPLICABLE"),
                Map.entry("report_ms", "OBSERVED"),
                Map.entry("total_wall_ms", "OBSERVED"));
        ScanStatistics stats = new ScanStatistics(1, 1, 0, 1, 1, 1,
                49L, 10L, 12L, "COMPLETE", List.of(),
                Map.of("dependency_resolution", 8L, "analysis", 21L, "report", 5L),
                metrics, "STATIC_ONLY", VerificationSummary.empty("STATIC_ONLY", 0),
                "COMPLETE", "a".repeat(64), statuses, Map.of(), Map.of());

        new MultiFormatReporter().writeMetadata(temp, stats);
        new ReportIndexWriter().write(ReportLayout.flat(temp), stats);

        String metadata = Files.readString(temp.resolve("scan-metadata.json"));
        String index = Files.readString(temp.resolve("index.md"));
        assertTrue(metadata.contains("\"dependency_resolution_ms\":8")
                        && metadata.contains("\"network_download_wall_ms\":12")
                        && metadata.contains("\"dynamic_filter_ms\":0")
                        && metadata.contains("\"total_wall_ms\":49")
                        && metadata.contains("\"dynamic_filter_ms\":\"NOT_APPLICABLE\""),
                metadata);
        assertTrue(index.contains("| Dependency resolution | 8 ms (OBSERVED) |")
                        && index.contains("| Dynamic filter | 0 ms (NOT_APPLICABLE) |")
                        && index.contains("actual_application=1")
                        && index.contains("pom_derived=4")
                        && index.contains("jdk=7"), index);
    }

    @Test
    void findingsFormatsConsumeStructuredVerificationSnapshot(@TempDir Path temp) throws Exception {
        Chain chain = new Chain("RULE-2", "CODE_EXEC", "HIGH",
                "app.Entry", "readObject", "readObject", "java.lang.Runtime", "exec",
                List.of(new ChainHop("app.Entry", "readObject", "java.lang.Runtime", "exec",
                        HopKind.DIRECT_CALL, null, "call", "()V", null)), 0);
        VerificationSummary summary = new VerificationSummary(
                "WINDOWS_JOB_OBJECT", 1, 1, 0, 1,
                Map.of("SINK_BLOCKED", 1), Map.of(),
                List.of(new VerificationSummary.ChainResult(1, chain.key(), "SINK_BLOCKED",
                        "canary", "HIGH", 19, 1, 3, "SINK_CANARY_BOUNDARY",
                        "WINDOWS_JOB_OBJECT", "17.0.19", "policy-1", true, true, "CLEANED")));
        new MultiFormatReporter().write(ReportLayout.flat(temp), List.of(chain), Map.of(),
                Map.of(chain.key(), List.of("verify:stale-note")), summary);

        String json = Files.readString(temp.resolve("findings.json"));
        assertTrue(json.contains("\"verification_status\":\"SINK_BLOCKED\""));
        assertTrue(json.contains("\"verification_evidence\":\"SINK_CANARY_BOUNDARY\""));
        assertTrue(json.contains("\"verification_group\":\"boundary_only\""));
        assertTrue(json.contains("\"last_confirmed_stage\":\"SINK_BOUNDARY\""),
                "findings.json must close the last_confirmed_stage JSON string");
        assertTrue(json.contains("\"precision\":")
                && json.contains("\"high_confidence\":false"));
        assertTrue(!json.contains("]}\",\"construction\":"),
                "findings.json must remain valid JSON around the nested precision object");
        assertTrue(json.endsWith("\n]"));
        assertTrue(Files.readString(temp.resolve("findings.html")).contains("SINK_BLOCKED"));
        assertTrue(Files.readString(temp.resolve("findings.md")).contains("SINK_BLOCKED"));
        assertTrue(Files.readString(temp.resolve("findings.html")).contains("boundary_only"));
        assertTrue(Files.readString(temp.resolve("findings.md")).contains("boundary_only"));
    }
}
