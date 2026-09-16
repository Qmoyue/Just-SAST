package io.just.sast.report;

import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.HopKind;
import io.just.sast.blackboard.ObjectGraphPlan;
import io.just.sast.cpg.graph.Graph;
import io.just.sast.model.ArtifactProvenance;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
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
        assertTrue(firstJson.contains("\"hop_index\":1"));
        assertTrue(firstMarkdown.contains("Finding ID:"));
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

    @Test
    void displayLimitDoesNotTruncateJsonOrVariantRows(@TempDir Path temp) throws Exception {
        List<Chain> chains = new ArrayList<>();
        for (int index = 0; index < 12; index++) {
            String owner = "dep/Gadget" + index;
            chains.add(new Chain("RULE-VARIANT-" + index, "COMMAND", "HIGH", owner,
                    "readObject", "readObject", "java/lang/Runtime", "exec",
                    List.of(new ChainHop(owner, "readObject", "java/lang/Runtime", "exec",
                            HopKind.DIRECT_CALL, "value" + index, "variant", "()V", index)),
                    0, "()V", "TERMINAL"));
        }
        FindingOutputReader.Snapshot snapshot = new FindingOutputReader().read(
                chains, Map.of(), Map.of(), Map.of());
        Path output = temp.resolve("display");
        new ConciseReportWriter().write(ReportLayout.flat(output), "component", snapshot,
                ScanStatistics.empty());

        String json = Files.readString(output.resolve("report.json"));
        String markdown = Files.readString(output.resolve("report.md"));
        assertEquals(12, occurrences(json, "\"chain_key\":"));
        assertTrue(json.contains("\"display_limit\":10"));
        assertTrue(json.contains("\"json_truncated\":false"));
        assertTrue(markdown.contains("detailed: 10; compact: 2; JSON candidates: 12"));
        assertTrue(markdown.contains("Remaining candidate summaries"));
    }

    @Test
    void hostileTextIsEscapedWithoutInventingOrDroppingEvidence(@TempDir Path temp)
            throws Exception {
        String hostile = "<script>alert(\"x\")</script>|`\n" + (char) 1;
        Chain chain = new Chain("RULE-" + hostile, "COMMAND", "HIGH",
                "app/" + hostile, "readObject", "readObject", "java/lang/Runtime", "exec",
                List.of(new ChainHop("app/" + hostile, "readObject", "java/lang/Runtime",
                        "exec", HopKind.DIRECT_CALL, hostile, hostile, "()V", null)), 0,
                "()V", "TERMINAL");
        FindingOutputReader.Snapshot base = new FindingOutputReader().read(
                List.of(chain), Map.of(), Map.of(chain.key(), List.of(hostile)), Map.of());
        ApplicationTrace trace = new ApplicationTrace(hostile, hostile, hostile, hostile,
                "BINDING_SITE", "TYPED_BINDING_TARGET", hostile, hostile, hostile, hostile,
                hostile);
        FindingOutputReader.Snapshot snapshot = new FindingOutputReader.Snapshot(
                base.schemaVersion(), base.findings(), base.byChainKey(),
                Map.of(chain.key(), trace));
        Path output = temp.resolve("hostile");
        new ConciseReportWriter().write(ReportLayout.flat(output), "component", snapshot,
                ScanStatistics.empty());
        new MultiFormatReporter().write(ReportLayout.flat(output.resolve("detailed")), snapshot);

        String json = Files.readString(output.resolve("report.json"));
        String markdown = Files.readString(output.resolve("report.md"));
        String html = Files.readString(output.resolve("detailed/findings.html"));
        assertTrue(json.contains("\\u0001"), json);
        assertTrue(markdown.contains("&lt;script&gt;"), markdown);
        assertFalse(markdown.contains("<script>"), markdown);
        assertTrue(html.contains("&lt;script&gt;"), html);
        CanonicalReportReader.Snapshot parsed = new CanonicalReportReader().read(
                output.resolve("report.json"), io.just.sast.run.InputBudget.defaults(),
                io.just.sast.run.InputBudget.defaults().tracker());
        assertEquals(1, parsed.chains().size());
    }

    @Test
    void activeReportSchemasDescribeTheStaticV3Surface() throws Exception {
        String concise = Files.readString(Path.of("docs/schemas/concise-report-v1.schema.json"));
        String finding = Files.readString(Path.of("docs/schemas/finding-output-v1.schema.json"));
        assertTrue(concise.contains("\"static_analysis\"")
                        && concise.contains("\"display_limit\"")
                        && concise.contains("\"filter_evidence\"")
                        && concise.contains("\"join_evidence\""), concise);
        assertTrue(finding.contains("\"entry_descriptor\"")
                        && finding.contains("\"application_trace\"")
                        && finding.contains("\"join_evidence\""), finding);
        assertFalse(concise.contains("verification"), concise);
        assertFalse(finding.contains("verification"), finding);
    }

    @Test
    void uniqueCpgCallSiteBecomesProvenHopLocation(@TempDir Path temp) throws Exception {
        Graph graph = new Graph();
        graph.methodNode("app/Entry", "readObject", "()V", false);
        graph.addCallNode("java/lang/Runtime", "exec", "()V", "INVOKEVIRTUAL", null,
                17, "app/Entry", "readObject", "()V");
        graph.freeze();
        Chain raw = new Chain("RULE-PROVENANCE", "COMMAND", "HIGH", "app/Entry",
                "readObject", "readObject", "java/lang/Runtime", "exec",
                List.of(
                        new ChainHop("app/Entry", "readObject", "java/lang/Runtime", "exec",
                                HopKind.DIRECT_CALL, null, "call", "()V", null),
                        new ChainHop("app/Entry", "readObject", "app/Entry", "readObject",
                                HopKind.ENTRY, null, "readObject", "()V", null)), 0, "()V");
        Chain enriched = HopProvenanceResolver.enrich(List.of(raw), graph,
                Map.of("app/Entry", new ArtifactProvenance("fixture.jar",
                        ArtifactProvenance.Role.APPLICATION, "A".repeat(64), 12))).get(0);
        FindingOutputReader.Snapshot snapshot = new FindingOutputReader().read(
                List.of(enriched), Map.of(), Map.of(), Map.of());
        Path output = temp.resolve("provenance");
        new ConciseReportWriter().write(ReportLayout.flat(output), "component", snapshot,
                ScanStatistics.empty());
        String json = Files.readString(output.resolve("report.json"));
        assertTrue(json.contains("\"status\":\"PROVEN\""), json);
        assertTrue(json.contains("\"basis\":\"CALLSITE_EXACT\""), json);
        assertTrue(json.contains("\"bytecode_offset\":17"), json);
        assertTrue(json.contains("\"logical_name\":\"fixture.jar\""), json);
        assertTrue(Files.readString(output.resolve("report.md")).contains("@17"));
    }

    @Test
    void ambiguousCpgCallSiteRemainsUnknown() throws Exception {
        Graph graph = new Graph();
        graph.methodNode("app/Entry", "readObject", "()V", false);
        graph.addCallNode("java/lang/Runtime", "exec", "()V", "INVOKEVIRTUAL", null,
                17, "app/Entry", "readObject", "()V");
        graph.addCallNode("java/lang/Runtime", "exec", "()V", "INVOKEVIRTUAL", null,
                23, "app/Entry", "readObject", "()V");
        graph.freeze();
        Chain raw = new Chain("RULE-AMBIGUOUS", "COMMAND", "HIGH", "app/Entry",
                "readObject", "readObject", "java/lang/Runtime", "exec",
                List.of(
                        new ChainHop("app/Entry", "readObject", "java/lang/Runtime", "exec",
                                HopKind.DIRECT_CALL, null, "call", "()V", null),
                        new ChainHop("app/Entry", "readObject", "app/Entry", "readObject",
                                HopKind.ENTRY, null, "readObject", "()V", null)), 0, "()V");
        Chain enriched = HopProvenanceResolver.enrich(List.of(raw), graph, Map.of()).get(0);
        assertEquals(io.just.sast.blackboard.HopProvenance.Status.UNKNOWN,
                enriched.hops().get(0).provenance().status());
        assertEquals(io.just.sast.blackboard.HopProvenance.Basis.CALLSITE_AMBIGUOUS,
                enriched.hops().get(0).provenance().basis());
        assertEquals(2, enriched.hops().get(0).provenance().candidateCount());
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

    private static int occurrences(String text, String needle) {
        int count = 0;
        int offset = 0;
        while ((offset = text.indexOf(needle, offset)) >= 0) {
            count++;
            offset += needle.length();
        }
        return count;
    }
}
