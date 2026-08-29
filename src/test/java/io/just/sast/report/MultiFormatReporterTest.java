package io.just.sast.report;

import io.just.sast.blackboard.VerificationSummary;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertTrue;

class MultiFormatReporterTest {

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
                20, 10, "COMPLETE", List.of(), Map.of("report", 1L),
                "JVM_SANDBOX", summary);

        new MultiFormatReporter().writeMetadata(temp, stats);

        String metadata = Files.readString(temp.resolve("scan-metadata.json"));
        String dynamic = Files.readString(temp.resolve("dynamic-verification.json"));
        assertTrue(metadata.contains("\"dynamic_verification\""));
        assertTrue(dynamic.contains("\"status\":\"CONFIRMED\"")
                && dynamic.contains("\"confidence_score\":12")
                && dynamic.contains("\"duration_ms\":17"));
    }
}
