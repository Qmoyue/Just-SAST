package io.just.sast.report;

import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.HopKind;
import io.just.sast.blackboard.SinkOutcome;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CsvReporterTest {

    @Test
    void writesStaticEvidenceAndCalibrationTables(@TempDir Path temp) throws Exception {
        Chain kept = chain("kept", "TERMINAL");
        Chain rejected = chain("rejected", "TERMINAL");
        SinkOutcome sink = new SinkOutcome("RULE", "COMMAND_EXEC", "java/lang/Runtime", "exec",
                "app/Entry", "readObject", 2, "FOUND", 3, 0, 0);

        new CsvReporter().write(temp, List.of(kept, rejected), Map.of(1L, sink),
                Map.of(rejected.key(), "STATIC_CALIBRATION"),
                Map.of(kept.key(), List.of("static:constructible")));

        String findings = Files.readString(temp.resolve("findings.csv"));
        assertTrue(findings.startsWith("\uFEFFchain_id,"));
        assertTrue(findings.contains("static_evidence"));
        assertFalse(findings.contains("verification"));
        assertTrue(findings.contains(kept.ruleId()));
        assertTrue(Files.readString(temp.resolve("calibrations.csv"))
                .contains("STATIC_CALIBRATION"));
        assertTrue(Files.readString(temp.resolve("sinks.csv")).contains("FOUND"));
        assertFalse(Files.readString(temp.resolve("findings.csv")).contains(rejected.ruleId()));
    }

    @Test
    void snapshotRendererCarriesStableStaticPath(@TempDir Path temp) throws Exception {
        Chain chain = new Chain("RULE-PATH", "COMMAND_EXEC", "HIGH", "app/Entry",
                "readObject", "readObject", "java/lang/Runtime", "exec", List.of(
                new ChainHop("app/Entry", "readObject", "app/Holder", "value",
                        HopKind.FIELD_FLOW, "value", "field", "Ljava/lang/Object;", null,
                        "app/Holder"),
                new ChainHop("app/Holder", "value", "java/lang/Runtime", "exec",
                        HopKind.DIRECT_CALL, null, "sink", "()V", null)), 0);
        FindingOutputReader.Snapshot snapshot = new FindingOutputReader().read(
                List.of(chain), Map.of(), Map.of(chain.key(), List.of("static:constructible")),
                Map.of());
        ReportLayout layout = ReportLayout.create(temp.resolve("report"));

        new CsvReporter().write(layout, Map.of(), snapshot,
                new java.util.LinkedHashMap<>());

        String findings = Files.readString(layout.evidence().resolve("findings.csv"));
        String chains = Files.readString(layout.evidence().resolve("chains.csv"));
        assertTrue(findings.contains("app/Entry"));
        assertTrue(chains.contains("app/Entry"));
        assertTrue(chains.contains("app/Entry,readObject"));
        assertFalse(findings.contains("verification"));
    }

    @Test
    void nullNotesRemainAStaticEmptyProjection(@TempDir Path temp) throws Exception {
        Chain chain = chain("null-notes", "TERMINAL");
        new CsvReporter().write(ReportLayout.flat(temp), List.of(chain), Map.of(), Map.of(),
                java.util.Collections.singletonMap(chain.key(), null));

        String findings = Files.readString(temp.resolve("findings.csv"));
        assertTrue(findings.contains("static_evidence"));
        assertFalse(findings.contains("verification"));
    }

    private static Chain chain(String name, String role) {
        return new Chain("RULE-" + name, "COMMAND_EXEC", "HIGH", "app/Entry",
                "readObject", "readObject", "java/lang/Runtime", "exec", List.of(
                new ChainHop("app/Entry", "readObject", "java/lang/Runtime", "exec",
                        HopKind.DIRECT_CALL, null, "test",
                        "(Ljava/lang/String;)Ljava/lang/Process;", 0)), 0,
                "(Ljava/lang/String;)Ljava/lang/Process;", role);
    }
}
