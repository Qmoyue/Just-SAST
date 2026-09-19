package io.just.sast.report;

import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.HopKind;
import io.just.sast.blackboard.ObjectGraphPlan;
import io.just.sast.cpg.graph.Graph;
import io.just.sast.model.ArtifactProvenance;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.yaml.snakeyaml.Yaml;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
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
        assertTrue(firstJson.contains("\"schema_version\":\"JUST-REPORT-V2\""));
        assertTrue(firstJson.contains("\"mode\":\"component\""));
        assertTrue(firstJson.contains("\"outcome\":\"FINDINGS_AVAILABLE\""));
        assertTrue(firstJson.contains("\"coverage\":\"COMPLETE\""));
        assertTrue(firstJson.contains("\"graph\":["));
        assertTrue(firstJson.contains("\"proof\":{"));
        assertTrue(firstMarkdown.contains("### 1."));
        assertTrue(firstMarkdown.contains("Graph:"));
        assertTrue(firstMarkdown.contains("[ENTRY] dep/Gadget#readObject"));
        assertTrue(firstMarkdown.contains("[IMPACT] java/lang/Runtime#exec"));
        assertFalse(firstJson.contains("generated_bytes"));
        assertFalse(firstJson.contains("verification"));
        assertFalse(firstJson.contains("analysis"));
    }

    @Test
    void publicJsonIsValidatedAsAStructuredDocument(@TempDir Path temp) throws Exception {
        FindingOutputReader.Snapshot snapshot = new FindingOutputReader().read(
                List.of(chain()), Map.of(), Map.of(), Map.of());
        Path output = temp.resolve("structured");
        new ConciseReportWriter().write(ReportLayout.flat(output), "component", snapshot,
                stats("A".repeat(64)));

        Map<?, ?> document = assertInstanceOf(Map.class,
                new Yaml().load(Files.readString(output.resolve("report.json"))));
        assertEquals("JUST-REPORT-V2", document.get("schema_version"));
        assertEquals("component", document.get("mode"));
        Map<?, ?> result = assertInstanceOf(Map.class, document.get("result"));
        assertEquals("FINDINGS_AVAILABLE", result.get("outcome"));
        assertEquals("COMPLETE", result.get("coverage"));
        List<?> findings = assertInstanceOf(List.class, document.get("findings"));
        Map<?, ?> finding = assertInstanceOf(Map.class, findings.get(0));
        List<?> graph = assertInstanceOf(List.class, finding.get("graph"));
        assertTrue(graph.size() >= 2);
        assertTrue(graph.stream().allMatch(Map.class::isInstance));
        assertFalse(document.containsKey("target_code_executed"));
        assertFalse(document.containsKey("verification"));
        assertFalse(document.containsKey("chains"));
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
        assertTrue(json.contains("\"findings\":[]"));
        assertTrue(json.contains("NO_APPLICATION_ENTRY"));
        assertTrue(json.contains("\"exported\":0"));
        assertFalse(Files.readString(output.resolve("report.md")).contains("CANDIDATE"));
    }

    @Test
    void applicationGraphKeepsDistinctTypedRolesWithTheSameLabel(@TempDir Path temp)
            throws Exception {
        Chain chain = chain();
        FindingOutputReader.Snapshot base = new FindingOutputReader().read(
                List.of(chain), Map.of(), Map.of(), Map.of());
        ApplicationTrace trace = new ApplicationTrace("app/Main", "main", "app/Main", "main",
                "HTTP_SERVER", "HTTP_SERVER", "dep/Gadget#readObject()V",
                "app/Main#main([Ljava/lang/String;)V->app/Main#main([Ljava/lang/String;)V",
                "dep/Gadget", "java/lang/Runtime", "exec",
                new ApplicationTrace.JoinEvidence("graph", "artifact", "index", "join", "chain",
                        "entry", "site", "dependency", "DIRECT_VALUE", "DERIVED_OBJECT",
                        "DESERIALIZATION", "EXACT", "UNKNOWN", "UNKNOWN", "SAT",
                        List.of("BRIDGE-1")));
        FindingOutputReader.Snapshot snapshot = new FindingOutputReader.Snapshot(
                base.schemaVersion(), base.findings(), base.byChainKey(),
                Map.of(chain.key(), trace));

        Path output = temp.resolve("application-graph");
        new ConciseReportWriter().write(ReportLayout.flat(output), "application", snapshot,
                ScanStatistics.empty());
        String json = Files.readString(output.resolve("report.json"));

        assertTrue(json.contains("\"role\":\"ENTRY\""), json);
        assertTrue(json.contains("\"role\":\"SITE\""), json);
        assertTrue(json.contains("\"role\":\"DESERIALIZE\""), json);
        assertTrue(json.contains("\"role\":\"BRIDGE\""), json);
        assertTrue(json.contains("\"role\":\"IMPACT\""), json);
    }

    @Test
    void capabilityBoundaryDoesNotInventATerminal(@TempDir Path temp) throws Exception {
        Chain chain = new Chain("JUST-SINK-REFLECTIVE-INVOKE", "REFLECTION", "HIGH",
                "app/Entry", "readObject", "readObject", "java/lang/reflect/Method", "invoke",
                List.of(new ChainHop("app/Entry", "readObject", "java/lang/reflect/Method",
                        "invoke", HopKind.DIRECT_CALL, null, "reflective capability", "()V", 0)),
                0, "()V", "CAPABILITY");
        FindingOutputReader.Snapshot snapshot = new FindingOutputReader().read(
                List.of(chain), Map.of(), Map.of(), Map.of());
        Path output = temp.resolve("capability");
        new ConciseReportWriter().write(ReportLayout.flat(output), "component", snapshot,
                ScanStatistics.empty());
        String json = Files.readString(output.resolve("report.json"));
        String markdown = Files.readString(output.resolve("report.md"));
        assertTrue(json.contains("\"role\":\"CAPABILITY_BOUNDARY\""));
        assertTrue(json.contains("\"role\":\"BOUNDARY\",\"label\":\"java/lang/reflect/Method#invoke\""));
        assertTrue(markdown.contains("[BOUNDARY] java/lang/reflect/Method#invoke"));
        assertTrue(markdown.contains("terminal: CAPABILITY_ONLY"));
        assertFalse(markdown.contains("[IMPACT] java/lang/reflect/Method#invoke"));
    }

    @Test
    void composedSuffixIsConnectedWithoutBecomingABytecodeClaim(@TempDir Path temp)
            throws Exception {
        Chain chain = new Chain("JUST-SINK-TEMPLATES", "COMMAND", "HIGH",
                "app/Entry", "readObject", "readObject",
                "com/sun/org/apache/xalan/internal/xsltc/trax/TemplatesImpl",
                "newTransformer",
                List.of(
                        new ChainHop("java/lang/reflect/Method", "invoke",
                                "com/sun/org/apache/xalan/internal/xsltc/trax/TemplatesImpl",
                                "newTransformer", HopKind.DIRECT_CALL, null,
                                "terminal suffix", "()V", null),
                        new ChainHop("app/Entry", "readObject",
                                "app/Bridge", "wagTail", HopKind.DIRECT_CALL,
                                null, "application prefix", "()V", null)),
                0, "()V", "TERMINAL");
        FindingOutputReader.Snapshot snapshot = new FindingOutputReader().read(
                List.of(chain), Map.of(), Map.of(), Map.of());
        Path output = temp.resolve("composed");
        new ConciseReportWriter().write(ReportLayout.flat(output), "component", snapshot,
                stats("C".repeat(64)));
        String json = Files.readString(output.resolve("report.json"));
        String markdown = Files.readString(output.resolve("report.md"));
        assertTrue(json.contains("java/lang/reflect/Method#invoke"));
        assertTrue(markdown.contains("[STEP] java/lang/reflect/Method#invoke"));
        assertTrue(markdown.contains("[IMPACT] com/sun/org/apache/xalan/internal/xsltc/trax/TemplatesImpl#newTransformer"));
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
        assertTrue(json.contains("\"findings\":[]"));
        assertTrue(json.contains("\"outcome\":\"NO_FINDINGS\""));
        assertTrue(json.contains("\"NO_STATIC_FINDINGS\""));
        assertTrue(markdown.contains("not proof that the artifact is safe"));
        assertTrue(markdown.contains("NO_STATIC_FINDINGS"));
    }

    @Test
    void partialAndUnknownStatusesNameTheirStaticProofGaps(@TempDir Path temp) throws Exception {
        Chain partial = new Chain("RULE-PARTIAL", "COMMAND", "HIGH", "dep/Partial",
                "readObject", "readObject", "java/lang/Runtime", "exec",
                List.of(new ChainHop("dep/Partial", "readObject", "java/lang/Runtime", "exec",
                        HopKind.DIRECT_CALL, null, "bounded hop", "()V", null)), 1);
        Chain unknown = new Chain("RULE-UNKNOWN", "COMMAND", "UNKNOWN", "unknown/Entry",
                "unknownMethod", "UNKNOWN", "unknown/Boundary", "unknownImpact", List.of(),
                0, "", "CAPABILITY");
        FindingOutputReader.Snapshot snapshot = new FindingOutputReader().read(
                List.of(partial, unknown), Map.of(), Map.of(), Map.of());
        Path output = temp.resolve("status");

        new ConciseReportWriter().write(ReportLayout.flat(output), "component", snapshot,
                ScanStatistics.empty());

        String json = Files.readString(output.resolve("report.json"));
        assertTrue(json.contains("\"status\":\"PARTIAL\""), json);
        assertTrue(json.contains("\"status\":\"UNKNOWN\""), json);
        assertTrue(json.contains("UNRESOLVED_HOPS"), json);
        assertTrue(json.contains("TERMINAL_IMPACT_NOT_PROVEN"), json);
    }

    @Test
    void dependencyInputIncompleteRemainsBoundedAndFailureIsNotAnEmptyFinding(@TempDir Path temp)
            throws Exception {
        FindingOutputReader.Snapshot snapshot = new FindingOutputReader().read(
                List.of(), Map.of(), Map.of(), Map.of());
        ScanStatistics incomplete = new ScanStatistics(0, 0, 0, 0, 0, 0,
                1, 1, 1, "PARTIAL", List.of("DEPENDENCY_INPUT_INCOMPLETE"),
                Map.of(), Map.of(), "PARTIAL", "D".repeat(64),
                Map.of(), Map.of(), Map.of(), List.of());
        Path output = temp.resolve("incomplete");

        new ConciseReportWriter().write(ReportLayout.flat(output), "component", snapshot,
                incomplete);

        String json = Files.readString(output.resolve("report.json"));
        assertTrue(json.contains("\"coverage\":\"BOUNDED\""), json);
        assertTrue(json.contains("DEPENDENCY_INPUT_INCOMPLETE"), json);
        assertTrue(json.contains("\"findings\":[]"), json);

        Path malformed = temp.resolve("malformed-report.json");
        Files.writeString(malformed, "{\"schema_version\":\"JUST-REPORT-V2\"}");
        assertThrows(java.io.IOException.class, () -> new CanonicalReportReader().read(
                malformed, io.just.sast.run.InputBudget.defaults(),
                io.just.sast.run.InputBudget.defaults().tracker()));
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
        assertTrue(json.contains("FIELD_FLOW"));
        assertFalse(json.contains("object_relations"));
        assertTrue(markdown.contains("[ENTRY] app/Entry#readObject"));
        assertTrue(markdown.contains("FIELD_FLOW"));
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
        int genericPosition = json.indexOf("\"label\":\"java/lang/Runtime#exec\"");
        int nestedPosition = json.indexOf("\"label\":\"app/Terminal#run\"");
        int expectedOrder = io.just.sast.chain.ChainRanking.compare(generic, nested,
                Map.of(), java.util.Set.of());
        assertTrue(genericPosition >= 0 && nestedPosition >= 0 && expectedOrder != 0,
                json);
        assertTrue((expectedOrder < 0) == (genericPosition < nestedPosition), json);
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
        chains.add(new Chain("RULE-BOUNDARY", "REFLECTION", "HIGH", "app/Reflective",
                "readObject", "readObject", "java/lang/reflect/Method", "invoke",
                List.of(new ChainHop("app/Reflective", "readObject",
                        "java/lang/reflect/Method", "invoke", HopKind.DIRECT_CALL,
                        null, "capability", "()V", null)), 0, "()V", "CAPABILITY"));
        FindingOutputReader.Snapshot snapshot = new FindingOutputReader().read(
                chains, Map.of(), Map.of(), Map.of());
        Path output = temp.resolve("display");
        new ConciseReportWriter().write(ReportLayout.flat(output), "component", snapshot,
                ScanStatistics.empty());

        String json = Files.readString(output.resolve("report.json"));
        String markdown = Files.readString(output.resolve("report.md"));
        assertEquals(13, occurrences(json, "\"id\":"));
        assertTrue(json.contains("\"candidates\":13"));
        assertTrue(json.contains("\"exported\":13"));
        assertTrue(markdown.contains("Candidates: 13"));
        assertTrue(markdown.contains("[BOUNDARY] java/lang/reflect/Method#invoke"));
        assertFalse(markdown.contains("Remaining candidate summaries"));
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

        String json = Files.readString(output.resolve("report.json"));
        String markdown = Files.readString(output.resolve("report.md"));
        assertTrue(json.contains("\\u0001"), json);
        assertTrue(markdown.contains("&lt;script&gt;"), markdown);
        assertFalse(markdown.contains("<script>"), markdown);
        CanonicalReportReader.Snapshot parsed = new CanonicalReportReader().read(
                output.resolve("report.json"), io.just.sast.run.InputBudget.defaults(),
                io.just.sast.run.InputBudget.defaults().tracker());
        assertEquals(1, parsed.chains().size());
    }

    @Test
    void activeReportSchemasDescribeTheStaticV3Surface() throws Exception {
        String concise = Files.readString(Path.of("docs/schemas/concise-report-v2.schema.json"));
        String finding = Files.readString(Path.of("docs/schemas/finding-output-v1.schema.json"));
        assertTrue(concise.contains("JUST-REPORT-V2")
                        && concise.contains("\"result\"")
                        && concise.contains("\"findings\"")
                        && concise.contains("\"provenance\"")
                        && concise.contains("\"graph\""), concise);
        assertTrue(finding.contains("\"entry_descriptor\"")
                        && finding.contains("\"application_trace\"")
                        && finding.contains("\"join_evidence\""), finding);
        assertFalse(concise.contains("verification"), concise);
        assertFalse(finding.contains("verification"), finding);
        assertFalse(concise.contains("target_code_executed"), concise);
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
        assertTrue(json.contains("\"status\":\"COMPLETE\""), json);
        assertTrue(json.contains("app/Entry#readObject"), json);
        assertFalse(json.contains("bytecode_offset"), json);
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
