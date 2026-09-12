package io.just.sast.report;

import io.just.sast.config.Match;
import io.just.sast.config.Rule;
import io.just.sast.config.RuleSchemaV2;
import io.just.sast.config.RuleSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RuleSchemaShadowWriterContractTest {

    @Test
    void shadowIsDeterministicAndClassifiesLegacyTerminalChanges(@TempDir Path temp) throws Exception {
        Rule.CallMatcher lookup = new Rule.CallMatcher(Match.of("javax/naming/Context"),
                Match.of("lookup"), null);
        Rule.SinkRule rule = new Rule.SinkRule("LOOKUP", "JNDI", "HIGH", lookup,
                List.of(new Rule.TaintedPos.Arg(0)));
        RuleSet rules = new RuleSet(List.of(rule), List.of(), List.of(), List.of(), List.of());

        RuleSchemaV2.Shadow first = RuleSchemaV2.shadow(rules);
        RuleSchemaV2.Shadow second = RuleSchemaV2.shadow(rules);
        assertEquals(first.toCanonicalJson(), second.toCanonicalJson());
        assertEquals(first.digest(), second.digest());
        assertTrue(first.records().get(0).differences()
                .contains("SINK_TERMINAL_RECLASSIFIED_TO_CAPABILITY"));
        assertTrue(first.toCanonicalJson().contains("JUST-RULES-D002-V2"));
    }

    @Test
    void writerUsesAtomicMetadataArtifactAndPreservesDefaultFormats(@TempDir Path temp)
            throws Exception {
        ReportLayout layout = ReportLayout.create(temp);
        RuleSchemaShadowWriter writer = new RuleSchemaShadowWriter();
        Rule.CallMatcher call = new Rule.CallMatcher(Match.of("a/B"), Match.of("run"), null);
        Rule.SinkRule sink = new Rule.SinkRule("SINK", "CODE_EXEC", "HIGH", call,
                List.of(new Rule.TaintedPos.Arg(0)));
        Path path = writer.write(layout,
                new RuleSet(List.of(sink), List.of(), List.of(), List.of(), List.of()));
        assertEquals(layout.meta().resolve("rules-v2-shadow.json"), path);
        String json = Files.readString(path);
        assertTrue(json.startsWith("{\"schema_version\":\"JUST-RULES-D002-V2-SHADOW-1\""));
        assertTrue(json.contains("\"differences\":["));
        try (var files = Files.list(layout.meta())) {
            assertTrue(files.noneMatch(file -> file.getFileName().toString().endsWith(".tmp")));
        }
    }
}
