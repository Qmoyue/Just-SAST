package io.just.sast.cli;

import io.just.sast.report.CanonicalReportReader;
import io.just.sast.report.ConciseReportWriter;
import io.just.sast.report.ReportLayout;
import io.just.sast.report.ScanStatistics;
import io.just.sast.run.InputBudget;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Contract tests for failure boundaries that must never publish a plausible empty report. */
class ReportFailureVisibilityContractTest {

    @Test
    void invalidCanonicalSchemaIsRejectedByTheReader(@TempDir Path temp) throws Exception {
        Path report = temp.resolve("invalid-report.json");
        Files.writeString(report, "{\"schema_version\":\"JUST-REPORT-V2\","
                + "\"mode\":\"component\","
                + "\"result\":{\"outcome\":\"NO_FINDINGS\",\"coverage\":\"COMPLETE\","
                + "\"candidates\":0,\"exported\":0},\"findings\":[],"
                + "\"provenance\":{\"artifact_sha256\":\"" + "a".repeat(64)
                + "\",\"detail\":\"test\"},\"unexpected\":true}");

        IOException failure = assertThrows(IOException.class,
                () -> new CanonicalReportReader().read(report, InputBudget.defaults(),
                        InputBudget.defaults().tracker()));

        assertTrue(failure.getMessage().startsWith("CANONICAL_REPORT_INVALID:"),
                failure.getMessage());
    }

    @Test
    void writerInternalFailurePropagatesBeforeEitherPublicFileIsWritten(@TempDir Path temp)
            throws Exception {
        Path output = temp.resolve("writer-failure");
        ReportLayout layout = ReportLayout.flat(output);

        assertThrows(NullPointerException.class,
                () -> new ConciseReportWriter().write(layout, "component", null,
                        ScanStatistics.empty()));

        assertFalse(Files.exists(output.resolve("report.json")));
        assertFalse(Files.exists(output.resolve("report.md")));
    }

    @Test
    void unparseableArchiveFailsBeforePublishingAnEmptyReport(@TempDir Path temp)
            throws Exception {
        Path input = temp.resolve("unparseable.jar");
        Files.writeString(input, "not a zip archive", StandardCharsets.US_ASCII);
        Path output = temp.resolve("scan-output");

        IOException failure = assertThrows(IOException.class,
                () -> ScanPipeline.run(input, null, output, null, false, true, null));

        assertTrue(failure.getMessage().contains("INPUT_UNPARSEABLE"),
                failure.getMessage());
        assertFalse(Files.exists(output),
                "an unparseable input must not publish a plausible empty report");
    }
}
