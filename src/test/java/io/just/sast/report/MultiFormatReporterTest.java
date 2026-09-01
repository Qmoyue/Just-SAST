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
        assertTrue(metadata.contains("\"dynamic_verification\""));
        assertTrue(metadata.contains("\"schema_version\":1")
                && metadata.contains("\"isolation_level\":\"UNKNOWN\"")
                && metadata.contains("\"isolation_capabilities\":[]")
                && metadata.contains("\"artifact_sha256\":\"UNKNOWN\"")
                && metadata.contains("\"heap_peak_mb\":12")
                && metadata.contains("\"chain_proof_completeness\":\"UNKNOWN\"")
                && metadata.contains("\"metrics\":{\"graph_nodes\":3}"));
        assertTrue(dynamic.contains("\"status\":\"CONFIRMED\"")
                && dynamic.contains("\"schema_version\":1")
                && dynamic.contains("\"artifact_sha256\":\"UNKNOWN\"")
                && dynamic.contains("\"confidence_score\":12")
                && dynamic.contains("\"duration_ms\":17"));
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
        assertTrue(json.endsWith("\n]"));
        assertTrue(Files.readString(temp.resolve("findings.html")).contains("SINK_BLOCKED"));
        assertTrue(Files.readString(temp.resolve("findings.md")).contains("SINK_BLOCKED"));
    }
}
