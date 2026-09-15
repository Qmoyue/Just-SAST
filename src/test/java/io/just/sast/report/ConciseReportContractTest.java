package io.just.sast.report;

import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.HopKind;
import io.just.sast.blackboard.ObjectGraphPlan;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Golden contract for the small human/agent static report surface. */
class ConciseReportContractTest {

    @Test
    void markdownAndJsonAreDeterministicAndShareTheSnapshot(@TempDir Path temp) throws Exception {
        Chain chain = chain();
        FindingOutputReader.Snapshot snapshot = new FindingOutputReader().read(
                List.of(chain), Map.of(), Map.of(), Map.of());
        ScanStatistics statistics = stats("A".repeat(64));
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
        assertTrue(firstJson.contains("\"target_code_executed\":false"));
        assertTrue(firstJson.contains("\"result_explanation\":{\"kind\":\"EXPORTED_CANDIDATES\""));
        assertTrue(firstJson.contains("\"arg_ordinal\":0"));
        assertTrue(firstJson.contains("\"constraints\":{"));
        assertTrue(firstMarkdown.contains("dep/Gadget#readObject` → `java/lang/Runtime#exec"));
        assertFalse(firstJson.contains("generated_bytes"));
        assertFalse(firstJson.contains("verification"));
    }

    @Test
    void applicationCandidateWithoutJoinStaysVisibleButIsNotExported(@TempDir Path temp)
            throws Exception {
        Chain chain = chain();
        FindingOutputReader.Snapshot snapshot = new FindingOutputReader().read(
                List.of(chain), Map.of(), Map.of(), Map.of(), true);
        Path output = temp.resolve("application");
        new ConciseReportWriter().write(ReportLayout.flat(output), "application", snapshot,
                ScanStatistics.empty());
        String json = Files.readString(output.resolve("report.json"));
        assertTrue(json.contains("\"mode\":\"application\""));
        assertTrue(json.contains("\"exported\":false"));
        assertTrue(Files.readString(output.resolve("report.md")).contains("CANDIDATE"));
    }

    @Test
    void emptyResultExplainsItsLimits(@TempDir Path temp) throws Exception {
        FindingOutputReader.Snapshot snapshot = new FindingOutputReader().read(
                List.of(), Map.of(), Map.of(), Map.of());
        Path output = temp.resolve("empty");
        new ConciseReportWriter().write(ReportLayout.flat(output), "component", snapshot,
                ScanStatistics.empty());
        String json = Files.readString(output.resolve("report.json"));
        String markdown = Files.readString(output.resolve("report.md"));
        assertTrue(json.contains("\"chains\":[]"));
        assertTrue(json.contains("\"kind\":\"EMPTY\""));
        assertTrue(json.contains("\"NO_CANDIDATES\""));
        assertTrue(markdown.contains("not proof that the artifact is safe"));
        assertTrue(markdown.contains("NO_CANDIDATES"));
    }

    @Test
    void fieldFlowCarriesObjectRelationAndPreciseHopIdentity(@TempDir Path temp)
            throws Exception {
        Chain chain = new Chain("JUST-FIELD-FLOW", "OBJECT", "MEDIUM",
                "app/Entry", "readObject", "readObject", "java/lang/Runtime", "exec",
                List.of(
                        new ChainHop("app/Holder", "value", "java/lang/Runtime", "exec",
                                HopKind.DIRECT_CALL, "", "sink call",
                                "(Ljava/lang/String;)Ljava/lang/Process;", 0),
                        new ChainHop("app/Entry", "readObject", "app/Holder", "value",
                                HopKind.FIELD_FLOW, "value", "field propagation", "", null,
                                "app/Holder")),
                0, "(Ljava/lang/String;)Ljava/lang/Process;");
        FindingOutputReader.Snapshot snapshot = new FindingOutputReader().read(
                List.of(chain), Map.of(), Map.of(), Map.of());
        Path output = temp.resolve("field");
        new ConciseReportWriter().write(ReportLayout.flat(output), "component", snapshot,
                stats("B".repeat(64)));
        String json = Files.readString(output.resolve("report.json"));
        String markdown = Files.readString(output.resolve("report.md"));
        assertTrue(json.contains("\"object_relations\":[{\"from\":\"app/Entry#readObject\""));
        assertTrue(json.contains("\"field_owner\":\"app/Holder\""));
        assertTrue(json.contains("\"arg_ordinal\":0"));
        assertTrue(markdown.contains("declared by `app/Holder`"));
    }

    @Test
    void reportUsesTheSharedSemanticRankingOrder(@TempDir Path temp) throws Exception {
        ObjectGraphPlan genericPlan = new ObjectGraphPlan(
                List.of(new ObjectGraphPlan.Node("entry", "app/Entry",
                        ObjectGraphPlan.NodeKind.ALLOCATE, List.of())), List.of());
        Chain generic = new Chain("RULE-generic", "COMMAND_EXEC", "HIGH", "app/Entry",
                "readObject", "deserialize", "java/lang/Runtime", "exec", List.of(
                new ChainHop("app/Entry", "readObject", "java/lang/Runtime", "exec",
                        HopKind.DIRECT_CALL, null, "call", "()V", null)), 0,
                "()V", "TERMINAL", genericPlan);
        Chain nested = new Chain("RULE-nested", "CODE_EXEC", "HIGH", "app/Entry",
                "deserialize", "deserialize", "app/Terminal", "run", List.of(
                new ChainHop("app/Entry", "deserialize", "java/lang/reflect/Method", "invoke",
                        HopKind.DIRECT_CALL, null, "call", "()V", null),
                new ChainHop("java/security/SignedObject", "getObject", "java/io/ObjectInputStream", "<init>",
                        HopKind.DIRECT_CALL, null, "fragment-activation-invoke", "()V", null),
                new ChainHop("java/io/ObjectInputStream", "<init>", "java/io/ObjectInput", "readObject",
                        HopKind.DIRECT_CALL, null, "fragment-activation-invoke",
                        "()Ljava/lang/Object;", null),
                new ChainHop("java/io/ObjectInput", "readObject", "app/Callback", "hashCode",
                        HopKind.DIRECT_CALL, null, "bridge-deser", "()V", null),
                new ChainHop("app/Callback", "hashCode", "app/Terminal", "run",
                        HopKind.DIRECT_CALL, null, "fragment-activation-deserialize", "()V", null)), 0,
                "()V", "TERMINAL");
        FindingOutputReader.Snapshot snapshot = new FindingOutputReader().read(
                List.of(generic, nested), Map.of(), Map.of(), Map.of());

        Path output = temp.resolve("ranking");
        new ConciseReportWriter().write(ReportLayout.flat(output), "component", snapshot,
                ScanStatistics.empty());
        String json = Files.readString(output.resolve("report.json"));
        int chains = json.indexOf("\"chains\":[");
        int nestedRank = json.indexOf("semantic=TYPED_NESTED_DESERIALIZATION", chains);
        int genericRank = json.indexOf("semantic=ORDINARY_CHAIN", chains);
        assertTrue(chains >= 0 && nestedRank > chains && genericRank > nestedRank,
                "concise report must preserve ChainRanking semantic order");
    }

    private static ScanStatistics stats(String artifactHash) {
        return new ScanStatistics(1, 2, 0, 1, 1, 1, 42, 3, 4,
                "COMPLETE", List.of(), Map.of(), Map.of(), "COMPLETE", artifactHash,
                Map.of(), Map.of(), Map.of(), List.of());
    }

    private static Chain chain() {
        return new Chain("JUST-SINK-COMMAND-EXEC-RUNTIME", "COMMAND", "HIGH",
                "dep/Gadget", "readObject", "readObject",
                "java/lang/Runtime", "exec",
                List.of(new ChainHop("dep/Gadget", "readObject", "java/lang/Runtime", "exec",
                        HopKind.DIRECT_CALL, "", "bytecode",
                        "(Ljava/lang/String;)Ljava/lang/Process;", 0)), 0,
                "(Ljava/lang/String;)Ljava/lang/Process;");
    }
}
