package io.just.sast.report;

import io.just.sast.analysis.entry.ApplicationChainEvidence;
import io.just.sast.blackboard.ApplicationChainId;
import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.EntryChainJoinEvidence;
import io.just.sast.blackboard.EvidenceAtom;
import io.just.sast.blackboard.EvidenceEdge;
import io.just.sast.blackboard.EvidenceGraph;
import io.just.sast.blackboard.FindingState;
import io.just.sast.blackboard.GadgetSegmentId;
import io.just.sast.blackboard.HopKind;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertTrue;

/** Cross-renderer contract for the application-entry-to-chain path projection. */
class ApplicationPathReportContractTest {

    @Test
    void everyRendererCarriesTheTypedApplicationPath(@TempDir Path tmp) throws Exception {
        Chain chain = new Chain("RULE-APP-PATH", "COMMAND_EXEC", "HIGH", "dep/MetricDTO",
                "setValueByCommand", "deserialize", "java/lang/ProcessBuilder", "start",
                List.of(new ChainHop("dep/MetricDTO", "setValueByCommand",
                        "java/lang/ProcessBuilder", "start", HopKind.DIRECT_CALL, null,
                        "terminal", "()Ljava/lang/Process;", null),
                        new ChainHop("dep/MetricDTO", "setValueByCommand", "dep/MetricDTO",
                                "setValueByCommand", HopKind.ENTRY, null, "entry", "()V", null)), 0);
        String key = chain.key();
        EvidenceAtom entry = EvidenceAtom.of(EvidenceAtom.Kind.APPLICATION_ENTRY, "UNKNOWN",
                "app/ApiController", "putNote()Ljava/lang/Object;", "INDEX_TYPED_BINDING_ENTRY",
                Map.of("chain_key", key, "entry_join_kind", "TYPED_BINDING_TARGET",
                        "chain_entry_method", "dep/MetricDTO#setValueByCommand()V",
                        "entry_prefix_path", "app/ApiController#putNote()Ljava/lang/Object;"));
        EvidenceAtom site = EvidenceAtom.of(EvidenceAtom.Kind.BINDING_SITE, "UNKNOWN",
                "app/ApiController", "putNote()Ljava/lang/Object;", "INDEX_TYPED_BINDING_SITE",
                Map.of("chain_key", key));
        EvidenceAtom dependency = EvidenceAtom.of(EvidenceAtom.Kind.DEPENDENCY_SEGMENT,
                "UNKNOWN", "dep/MetricDTO", "setValueByCommand", "CHAIN_DEPENDENCY_SUFFIX",
                Map.of("chain_key", key));
        EvidenceAtom terminal = EvidenceAtom.of(EvidenceAtom.Kind.TERMINAL_IMPACT,
                "UNKNOWN", "java/lang/ProcessBuilder", "start", "INDEX_TERMINAL_IMPACT",
                Map.of("chain_key", key));
        ApplicationChainId appChain = ApplicationChainId.fromCanonical("chain", key);
        EntryChainJoinEvidence join = EntryChainJoinEvidence.of(appChain, entry.id(), site.id(),
                GadgetSegmentId.fromCanonical("chain", key, "dep/MetricDTO"),
                EntryChainJoinEvidence.ValueFlow.DIRECT_VALUE,
                EntryChainJoinEvidence.ObjectIdentity.DERIVED_OBJECT,
                EntryChainJoinEvidence.CallbackSemantics.DESERIALIZATION,
                EntryChainJoinEvidence.RuntimeTypeProof.EXACT,
                EntryChainJoinEvidence.ArtifactCompatibility.UNKNOWN,
                EntryChainJoinEvidence.FilterDominance.UNKNOWN,
                EntryChainJoinEvidence.ConstructionConstraint.SAT, List.of());
        EvidenceGraph graph = new EvidenceGraph(List.of(entry, site, dependency, terminal, join),
                List.of(EvidenceEdge.of(entry.id(), site.id(), EvidenceEdge.Kind.SUPPORTS,
                                "ENTRY_TO_SITE"),
                        EvidenceEdge.of(site.id(), join.id(), EvidenceEdge.Kind.JOINS,
                                "SITE_TO_JOIN"),
                        EvidenceEdge.of(join.id(), dependency.id(), EvidenceEdge.Kind.FLOWS_TO,
                                "JOIN_TO_DEPENDENCY"),
                        EvidenceEdge.of(dependency.id(), terminal.id(), EvidenceEdge.Kind.FLOWS_TO,
                                "DEPENDENCY_TO_TERMINAL")));
        ApplicationChainEvidence evidence = new ApplicationChainEvidence(
                ApplicationChainEvidence.SCHEMA_VERSION, "UNKNOWN", "UNKNOWN", true, graph,
                Map.of(appChain.value(), join), Map.of(), Map.of(key, "JOINED"), List.of());
        FindingState state = new FindingState(FindingState.EntryStatus.EXTERNAL_ENTRY,
                FindingState.ChainProgress.IMPACT_CHAIN_COMPLETE, FindingState.Feasibility.SAT,
                FindingState.Completeness.COMPLETE, FindingState.Risk.HIGH);
        FindingOutputReader.Snapshot snapshot = new FindingOutputReader().read(
                List.of(chain), Map.of(), Map.of(), Map.of(key, state), true, evidence);
        ReportLayout layout = ReportLayout.create(tmp.resolve("report"));

        new FindingOutputWriter().write(layout, snapshot);
        new ApplicationChainEvidenceWriter().write(layout, evidence);
        new CsvReporter().write(layout, Map.of(), snapshot, new java.util.LinkedHashMap<>());
        new MultiFormatReporter().write(layout, snapshot);
        new SarifReporter().write(layout, snapshot);

        String expectedEntry = "app/ApiController";
        String expectedPath = "app/ApiController#putNote()Ljava/lang/Object;";
        String findingOutput = Files.readString(layout.meta().resolve("finding-output.json"));
        String applicationEvidence = Files.readString(
                layout.meta().resolve("application-chain-evidence.json"));
        assertTrue(findingOutput.contains(expectedEntry));
        assertTrue(findingOutput.contains(join.id()));
        assertTrue(findingOutput.contains("\"artifact_digest\":\"UNKNOWN\""));
        assertTrue(findingOutput.contains("\"application_index_digest\":\"UNKNOWN\""));
        assertTrue(findingOutput.contains("\"dependency_segment_id\":\""
                + join.dependencySegmentId().value() + "\""));
        assertTrue(findingOutput.contains("\"construction_constraint\":\"SAT\""));
        assertTrue(applicationEvidence.contains("\"graph_digest\":\""
                + graph.canonicalDigest() + "\""));
        assertTrue(applicationEvidence.contains(join.id()));
        assertTrue(Files.readString(layout.evidence().resolve("chains.csv")).contains(expectedPath));
        assertTrue(Files.readString(layout.findings().resolve("findings.csv")).contains(expectedEntry));
        assertTrue(Files.readString(layout.findings().resolve("findings.json")).contains(expectedEntry));
        assertTrue(Files.readString(layout.findings().resolve("findings.html")).contains(expectedEntry));
        assertTrue(Files.readString(layout.findings().resolve("findings.md")).contains(expectedEntry));
        assertTrue(Files.readString(layout.findings().resolve("findings.sarif")).contains(expectedEntry));
    }
}
