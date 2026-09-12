package io.just.sast.report;

import io.just.sast.blackboard.FindingId;
import io.just.sast.blackboard.VerificationCoverage;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertTrue;

class VerificationCoverageWriterTest {

    @Test
    void writesTypedCoverageArtifact(@org.junit.jupiter.api.io.TempDir Path temp) throws Exception {
        String group = FindingId.fromCanonical("writer-group").value();
        VerificationCoverage coverage = new VerificationCoverage(
                VerificationCoverage.SCHEMA_VERSION, VerificationCoverage.Status.COMPLETE,
                1, 1, 1, 0, 1, 1,
                Map.of(group, List.of("chain")), Map.of(group, List.of("plan")),
                Map.of(group, List.of("APPLICATION_PREFIX")),
                Map.of(group, List.of("APPLICATION_PREFIX")), Set.of(group), Set.of(), Map.of(),
                "UNKNOWN").withComputedDigest();
        ReportLayout layout = ReportLayout.create(temp.resolve("report"));
        new VerificationCoverageWriter().write(layout, coverage);
        String json = Files.readString(layout.meta().resolve("verification-coverage.json"));
        assertTrue(json.contains("JUST-VERIFICATION-COVERAGE-V1"));
        assertTrue(json.contains(group));
    }
}
