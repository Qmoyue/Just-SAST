package io.just.sast.report;

import io.just.sast.analysis.hierarchy.ClassHierarchy;
import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.HopKind;
import io.just.sast.config.Match;
import io.just.sast.config.Rule;
import io.just.sast.config.RuleSet;
import io.just.sast.model.ClassInfo;
import io.just.sast.model.MethodInfo;
import io.just.sast.run.RunOutcome;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.lang.reflect.Modifier;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Static SARIF contract: rules, level, location, fingerprints and shared evidence only. */
class SarifReporterTest {

    private static Chain chain(String severity) {
        ChainHop entry = new ChainHop("app/Gadget", "readObject", "app/Gadget", "readObject",
                HopKind.ENTRY, null, "deserialize", "(Ljava/io/ObjectInputStream;)V", null);
        return new Chain("T-RULE", "CODE_EXEC", severity, "app/Gadget", "readObject", "readObject",
                "java/lang/Runtime", "exec", List.of(entry), 0);
    }

    private static ClassHierarchy hierarchyWithLine() {
        MethodInfo readObject = new MethodInfo("app/Gadget", "readObject",
                "(Ljava/io/ObjectInputStream;)V", Modifier.PRIVATE, List.of(), List.of(), true, 42);
        ClassInfo cls = new ClassInfo("app/Gadget", "java/lang/Object", List.of(),
                Modifier.PUBLIC, List.of(readObject), List.of());
        return new ClassHierarchy(Map.of("app/Gadget", cls), null);
    }

    private static RuleSet rules() {
        return new RuleSet(List.of(new Rule.SinkRule("T-RULE", "CODE_EXEC", "HIGH",
                new Rule.CallMatcher(Match.of("java/lang/Runtime"), Match.of("exec"), null),
                List.of(new Rule.TaintedPos.Arg(0)))), List.of(), List.of(), List.of(), List.of());
    }

    @Test
    void emitsRulesLevelRegionAndStaticParity(@TempDir Path tmp) throws Exception {
        new SarifReporter().withHierarchy(hierarchyWithLine()).withRules(rules()).write(
                tmp, List.of(chain("HIGH")), Map.of(), Map.of());
        String sarif = Files.readString(tmp.resolve("findings.sarif"));

        assertTrue(sarif.contains("\"rules\": [{\"id\": \"T-RULE\""));
        assertTrue(sarif.contains("\"level\": \"error\""));
        assertTrue(sarif.contains("\"uri\": \"app/Gadget.class\""));
        assertTrue(sarif.contains("\"startLine\": 42"));
        assertTrue(sarif.contains("\"partialFingerprints\""));
        assertTrue(sarif.contains("\"precision\":{"));
        assertTrue(sarif.contains("\"construction\":{"));
        assertFalse(sarif.contains("verification"));
        assertTrue(sarif.contains("docs.oasis-open.org/sarif"));
        assertFalse(sarif.contains("\"startLine\": 42},\n          }"));
    }

    @Test
    void mediumSeverityMapsToWarningAndVariantsFold(@TempDir Path tmp) throws Exception {
        Chain a = chain("MEDIUM");
        Chain b = chain("MEDIUM");
        new SarifReporter().withRules(rules()).write(tmp, List.of(a, b), Map.of(), Map.of());
        String sarif = Files.readString(tmp.resolve("findings.sarif"));
        assertTrue(sarif.contains("\"level\": \"warning\""));
        assertTrue(sarif.contains("\"results\": [")
                        && sarif.indexOf("ruleId") == sarif.lastIndexOf("ruleId"));
        assertFalse(sarif.contains("startLine"));
        assertFalse(sarif.contains("verification"));
    }

    @Test
    void legacyDynamicNotesDoNotChangeStaticConfidence(@TempDir Path tmp) throws Exception {
        Chain c = chain("HIGH");
        new SarifReporter().withRules(rules()).write(
                tmp, List.of(c), Map.of(), Map.of(c.key(), List.of("verify:confirmed")));
        String sarif = Files.readString(tmp.resolve("findings.sarif"));
        assertTrue(sarif.contains("\"confidence\":\"FEASIBLE\""));
        assertFalse(sarif.contains("verification"));
    }

    @Test
    void exposesCanonicalRunOutcomeWhenThePipelineSuppliesIt(@TempDir Path tmp) throws Exception {
        new SarifReporter().withRules(rules()).write(
                ReportLayout.flat(tmp), new FindingOutputReader().read(
                        List.of(chain("HIGH")), Map.of(), Map.of()),
                RunOutcome.forScan("PARTIAL", "PARTIAL"));
        String sarif = Files.readString(tmp.resolve("findings.sarif"));
        assertTrue(sarif.contains("\"just/run_outcome\""));
        assertTrue(sarif.contains("\"status\":\"PARTIAL\""));
    }
}
