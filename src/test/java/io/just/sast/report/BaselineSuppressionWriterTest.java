package io.just.sast.report;

import io.just.sast.blackboard.Chain;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertTrue;

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
}
