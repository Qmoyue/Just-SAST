package io.just.sast.report;

import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.FindingState;
import io.just.sast.blackboard.HopKind;
import io.just.sast.blackboard.VerificationSummary;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Golden contract for the small human/agent report surface. */
class ConciseReportContractTest {

    @Test
    void markdownAndJsonAreDeterministicAndShareTheSnapshot(@TempDir Path temp) throws Exception {
        Chain chain = chain();
        FindingOutputReader.Snapshot snapshot = new FindingOutputReader().read(
                List.of(chain), Map.of(), Map.of(), null);
        ScanStatistics statistics = new ScanStatistics(1, 2, 0, 1, 1, 1, 42, 3, 4,
                "COMPLETE", List.of(), Map.of(), Map.of(), "DISABLED",
                VerificationSummary.empty("DISABLED", 0), "COMPLETE", "A".repeat(64));
        Path first = temp.resolve("first");
        Path second = temp.resolve("second");
        ConciseReportWriter writer = new ConciseReportWriter();
        writer.write(ReportLayout.flat(first), "component", snapshot, statistics);
        writer.write(ReportLayout.flat(second), "component", snapshot, statistics);

        String firstJson = Files.readString(first.resolve("report.json"));
        String firstMarkdown = Files.readString(first.resolve("report.md"));
        assertEquals(firstJson, Files.readString(second.resolve("report.json")));
        assertEquals(firstMarkdown, Files.readString(second.resolve("report.md")));
        assertTrue(firstJson.contains("\"schema_version\":\"JUST-REPORT-V1\""));
        assertTrue(firstJson.contains("\"target_code_execution_possible\":false"));
        assertTrue(firstJson.contains("\"target_code_executed\":\"NO\""));
        assertTrue(firstMarkdown.contains("dep/Gadget#readObject` → `java/lang/Runtime#exec"));
        assertFalse(firstJson.contains("generated_bytes"));
    }

    @Test
    void applicationCandidateWithoutJoinStaysVisibleButIsNotExported(@TempDir Path temp)
            throws Exception {
        Chain chain = chain();
        FindingOutputReader.Snapshot snapshot = new FindingOutputReader().read(
                List.of(chain), Map.of(), Map.of(), null, Map.of(), true);
        ScanStatistics statistics = ScanStatistics.empty();
        Path output = temp.resolve("application");
        new ConciseReportWriter().write(ReportLayout.flat(output), "application", snapshot,
                statistics);
        String json = Files.readString(output.resolve("report.json"));
        assertTrue(json.contains("\"mode\":\"application\""));
        assertTrue(json.contains("\"exported\":false"),
                "a candidate without EntryChainJoinEvidence must not become a product finding");
        assertTrue(Files.readString(output.resolve("report.md")).contains("CANDIDATE"));
    }

    private static Chain chain() {
        return new Chain("JUST-SINK-COMMAND-EXEC-RUNTIME", "COMMAND", "HIGH",
                "dep/Gadget", "readObject", "readObject",
                "java/lang/Runtime", "exec",
                List.of(new ChainHop("dep/Gadget", "readObject", "java/lang/Runtime", "exec",
                        HopKind.DIRECT_CALL, "", "bytecode", "(Ljava/lang/String;)Ljava/lang/Process;",
                        0)), 0, "(Ljava/lang/String;)Ljava/lang/Process;");
    }
}
