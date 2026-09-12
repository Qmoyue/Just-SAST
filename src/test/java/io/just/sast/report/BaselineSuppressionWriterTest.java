package io.just.sast.report;

import io.just.sast.blackboard.Chain;
import io.just.sast.run.InputBudget;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;

class BaselineSuppressionWriterTest {

    @Test
    void comparesSemanticIdentityAndKeepsUnusedSuppressionVisible(@TempDir Path tmp)
            throws Exception {
        Chain chain = new Chain("rule-a", "COMMAND", "HIGH", "app/Entry", "read",
                "readObject", "java/lang/Runtime", "exec", List.of(), 0);
        ReportLayout oldLayout = ReportLayout.create(tmp.resolve("old"));
        new CsvReporter().write(oldLayout, List.of(chain), Map.of(), Map.of(), Map.of());

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

        new CsvReporter().write(currentLayout, List.of(chain), Map.of(), Map.of(), Map.of());
        new BaselineSuppressionWriter().write(currentLayout, null, suppressions,
                List.of(chain), Map.of());

        String baseline = Files.readString(currentLayout.evidence().resolve("baseline.csv"));
        String summary = Files.readString(currentLayout.meta().resolve("baseline.json"));
        assertTrue(baseline.contains("\"NEW\""), baseline);
        assertTrue(summary.contains("not-a-selector"), summary);
        assertTrue(Files.exists(currentLayout.findings().resolve("findings.csv")),
                "baseline/suppression must not delete the primary findings evidence");
    }

    @Test
    void baselineAndSuppressionShareCallerInputBudget(@TempDir Path tmp) throws Exception {
        String header = "rule_id,entry_class,entry_method,entry_descriptor,entry_kind,"
                + "sink_class,sink_method,sink_descriptor\n";
        Path baseline = tmp.resolve("baseline.csv");
        Path suppressions = tmp.resolve("suppressions.txt");
        Files.writeString(baseline, header);
        Files.writeString(suppressions, "rule:rule-a\n");
        long baselineBytes = Files.size(baseline);
        InputBudget defaults = InputBudget.defaults();
        InputBudget budget = defaults.withArchiveLimits(
                1024, 1024, baselineBytes + 1, 1024, 16,
                defaults.maxArchiveNesting(), defaults.maxClassEntries());

        ReportLayout layout = ReportLayout.create(tmp.resolve("current"));
        assertThrows(java.io.IOException.class, () -> new BaselineSuppressionWriter().write(
                layout, baseline, suppressions, List.of(), Map.of(), budget));
    }
}
