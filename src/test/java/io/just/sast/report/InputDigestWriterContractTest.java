package io.just.sast.report;

import io.just.sast.util.InputDigestVerification;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

class InputDigestWriterContractTest {

    @Test
    void writesTheClosedBeforeAfterShape(@TempDir Path temp) throws Exception {
        InputDigestVerification verification = new InputDigestVerification(
                "MATCH", "a".repeat(64), "a".repeat(64),
                List.of("b".repeat(64)), List.of("b".repeat(64)), List.of());
        ReportLayout layout = ReportLayout.create(temp);

        new InputDigestWriter().write(layout, verification);

        Path output = layout.meta().resolve("input-digest.json");
        assertTrue(Files.exists(output));
        String json = Files.readString(output);
        assertTrue(json.contains("\"schema_version\":1"));
        assertTrue(json.contains("\"status\":\"MATCH\""));
        assertTrue(json.contains("\"target\":{\"before\":\""));
        assertTrue(json.contains("\"dependencies\":[{\"index\":0"));
        assertTrue(json.contains("\"reasons\":[]"));
        assertTrue(json.endsWith("\n"));
    }

    @Test
    void unavailableEvidenceRetainsUnknownValuesAndReasons(@TempDir Path temp) throws Exception {
        InputDigestVerification verification = new InputDigestVerification(
                "UNAVAILABLE", "UNKNOWN", "UNKNOWN", List.of(), List.of(),
                List.of("INPUT_DIGEST_AFTER_UNAVAILABLE"));
        ReportLayout layout = ReportLayout.create(temp);

        new InputDigestWriter().write(layout, verification);

        String json = Files.readString(layout.meta().resolve("input-digest.json"));
        assertTrue(json.contains("\"status\":\"UNAVAILABLE\""));
        assertTrue(json.contains("\"before\":\"UNKNOWN\""));
        assertTrue(json.contains("INPUT_DIGEST_AFTER_UNAVAILABLE"));
    }
}
