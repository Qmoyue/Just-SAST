package io.just.sast.report;

import io.just.sast.blackboard.Chain;
import io.just.sast.run.InputBudget;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;

class BaselineSuppressionWriterTest {

    @Test
    void comparesSemanticIdentityAndKeepsUnusedSuppressionVisible(@TempDir Path tmp)
            throws Exception {
        Chain chain = new Chain("rule-a", "COMMAND", "HIGH", "app/Entry", "read",
                "readObject", "java/lang/Runtime", "exec", List.of(), 0);
        ReportLayout oldLayout = ReportLayout.create(tmp.resolve("old"));
        writeCanonical(oldLayout, chain);

        Path suppressions = tmp.resolve("suppressions.txt");
        Files.writeString(suppressions, "rule:rule-a\nrule:does-not-exist\n");
        ReportLayout currentLayout = ReportLayout.create(tmp.resolve("current"));
        new BaselineSuppressionWriter().write(currentLayout, oldLayout.root(), suppressions,
                List.of(chain), Map.of());

        String csv = Files.readString(currentLayout.evidence().resolve("baseline.csv"));
        String json = Files.readString(currentLayout.meta().resolve("baseline.json"));
        assertTrue(csv.contains("SUPPRESSED_BASELINE"));
        assertTrue(json.contains("\"unchanged\":1"));
        assertTrue(json.contains("rule:does-not-exist"));
    }

    @Test
    void invalidSelectorIsNotTreatedAsAHiddenCleanResult(@TempDir Path tmp) throws Exception {
        Chain chain = new Chain("rule-a", "COMMAND", "HIGH", "app/Entry", "read",
                "readObject", "java/lang/Runtime", "exec", List.of(), 0);
        ReportLayout currentLayout = ReportLayout.create(tmp.resolve("current"));
        Path suppressions = tmp.resolve("invalid-suppressions.txt");
        Files.writeString(suppressions, "rule:\nnot-a-selector\n");

        writeCanonical(currentLayout, chain);
        new BaselineSuppressionWriter().write(currentLayout, null, suppressions,
                List.of(chain), Map.of());

        String baseline = Files.readString(currentLayout.evidence().resolve("baseline.csv"));
        String summary = Files.readString(currentLayout.meta().resolve("baseline.json"));
        assertTrue(baseline.contains("\"NEW\""), baseline);
        assertTrue(summary.contains("not-a-selector"), summary);
        assertTrue(Files.exists(currentLayout.root().resolve("report.json")),
                "baseline/suppression must not delete the canonical report");
    }

    @Test
    void baselineReportRespectsCallerInputBudget(@TempDir Path tmp) throws Exception {
        Path baseline = tmp.resolve("baseline.json");
        Path suppressions = tmp.resolve("suppressions.txt");
        Files.writeString(baseline, "x".repeat(2048));
        Files.writeString(suppressions, "rule:rule-a\n");
        InputBudget defaults = InputBudget.defaults();
        InputBudget budget = defaults.withArchiveLimits(
                1024, 1024, 1024, 1024, 16,
                defaults.maxArchiveNesting(), defaults.maxClassEntries());

        ReportLayout layout = ReportLayout.create(tmp.resolve("current"));
        assertThrows(java.io.IOException.class, () -> new BaselineSuppressionWriter().write(
                layout, baseline, suppressions, List.of(), Map.of(), budget));
    }

    @Test
    void baselineKeepsDistinctPathVariantsUnderOneSemanticIdentity(@TempDir Path tmp)
            throws Exception {
        Chain first = variant("field-a", "reason-a");
        Chain second = variant("field-b", "reason-b");
        ReportLayout oldLayout = ReportLayout.create(tmp.resolve("old-variant"));
        writeCanonical(oldLayout, first);

        ReportLayout currentLayout = ReportLayout.create(tmp.resolve("current-variant"));
        new BaselineSuppressionWriter().write(currentLayout, oldLayout.root(), null,
                List.of(first, second), Map.of());

        String csv = Files.readString(currentLayout.evidence().resolve("baseline.csv"));
        String json = Files.readString(currentLayout.meta().resolve("baseline.json"));
        assertEquals(3, csv.lines().count(), csv);
        assertTrue(csv.contains("\"UNCHANGED\""), csv);
        assertTrue(csv.contains("\"NEW\""), csv);
        assertTrue(json.contains("\"added\":1"), json);
        assertTrue(json.contains("\"unchanged\":1"), json);
    }

    private static void writeCanonical(ReportLayout layout, Chain chain) throws Exception {
        FindingOutputReader.Snapshot snapshot = new FindingOutputReader().read(
                List.of(chain), Map.of(), Map.of(), Map.of());
        new ConciseReportWriter().write(layout, "component", snapshot, ScanStatistics.empty());
    }

    private static Chain variant(String field, String reason) {
        return new Chain("rule-variant", "COMMAND", "HIGH", "app/Entry", "read",
                "readObject", "java/lang/Runtime", "exec",
                List.of(new io.just.sast.blackboard.ChainHop("app/Entry", "read",
                        "java/lang/Runtime", "exec", io.just.sast.blackboard.HopKind.FIELD_FLOW,
                        field, reason, "()V", null)), 0);
    }
}
