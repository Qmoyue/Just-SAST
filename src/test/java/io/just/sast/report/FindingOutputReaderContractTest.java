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

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Contract tests for the one typed static report reader used by every renderer. */
class FindingOutputReaderContractTest {

    private static Chain chain(String method) {
        return new Chain("RULE-READER", "CODE_EXEC", "HIGH", "app/Entry", method,
                "readObject", "java/lang/Runtime", "exec", List.of(
                new ChainHop("app/Entry", method, "java/lang/Runtime", "exec",
                        HopKind.DIRECT_CALL, null, "terminal", "()V", null)), 0);
    }

    @Test
    void missingProducerStateIsConservativeAndDeterministic() {
        Chain first = chain("readObject");
        Chain duplicate = chain("readObject");
        FindingOutputReader reader = new FindingOutputReader();
        FindingOutputReader.Snapshot a = reader.read(List.of(duplicate, first), Map.of(),
                Map.of(first.key(), List.of("static:constructible")), Map.of());
        FindingOutputReader.Snapshot b = reader.read(List.of(first, duplicate), Map.of(),
                Map.of(first.key(), List.of("static:constructible")), Map.of());

        assertEquals(FindingOutputReader.SCHEMA_VERSION, a.schemaVersion());
        assertEquals(2, a.findings().size(), "variant rows remain visible to evidence writers");
        assertEquals(a.findings().stream().map(FindingOutputReader.Finding::id).toList(),
                b.findings().stream().map(FindingOutputReader.Finding::id).toList());
        FindingOutputReader.Finding view = a.require(first.key());
        assertEquals(FindingState.EntryStatus.NO_APPLICATION_ENTRY, view.state().entryStatus());
        assertEquals(FindingState.Feasibility.UNKNOWN, view.state().feasibility());
        assertFalse(view.state().defaultFindingEligible());
        assertTrue(view.confidence().reasons().isEmpty());
        assertFalse(a.toCanonicalJson().contains("verification"));
    }

    @Test
    void explicitTypedStateIsTheOnlyRouteToApplicationEligibility() {
        Chain candidate = chain("readObject");
        FindingState typed = new FindingState(
                FindingState.EntryStatus.EXTERNAL_ENTRY,
                FindingState.ChainProgress.IMPACT_CHAIN_COMPLETE,
                FindingState.Feasibility.SAT,
                FindingState.Completeness.COMPLETE,
                FindingState.Risk.HIGH);
        FindingOutputReader.Snapshot snapshot = new FindingOutputReader().read(
                List.of(candidate), Map.of(), Map.of(candidate.key(), List.of("static:old-note")),
                Map.of(candidate.key(), typed));
        FindingOutputReader.Finding view = snapshot.require(candidate.key());

        assertEquals(typed, view.state());
        assertTrue(view.state().defaultFindingEligible());
        assertTrue(view.typedViolations().isEmpty());
        String json = snapshot.toCanonicalJson();
        assertTrue(json.startsWith("{\"schema_version\":\"JUST-FINDING-OUTPUT-D004-V1\""));
        assertTrue(json.contains("\"entry_status\":\"EXTERNAL_ENTRY\""));
        assertFalse(json.contains("verification"));
        assertEquals(snapshot.digest(), new FindingOutputReader().read(
                List.of(candidate), Map.of(), Map.of(candidate.key(), List.of("static:old-note")),
                Map.of(candidate.key(), typed)).digest());
    }

    @Test
    void strictProductExportKeepsAuditRowsButHidesUnanchoredCandidates() {
        Chain candidate = chain("readObject");
        FindingOutputReader.Snapshot snapshot = new FindingOutputReader().read(
                List.of(candidate), Map.of(), Map.of(), Map.of(), true);

        assertEquals(1, snapshot.findings().size(),
                "canonical evidence must retain the rejected candidate");
        assertFalse(snapshot.findings().get(0).exported(),
                "strict product output must not export an unanchored chain");
        assertTrue(snapshot.exported().isEmpty());
    }

    @Test
    void emptyAndNullInputsProduceAnImmutableEmptySnapshot() {
        FindingOutputReader.Snapshot snapshot = new FindingOutputReader().read(
                null, null, null, Map.of(), false);
        assertTrue(snapshot.findings().isEmpty());
        assertTrue(snapshot.byChainKey().isEmpty());
        assertTrue(snapshot.applicationTraces().isEmpty());
    }

    @Test
    void applicationJoinIsProjectedAlongsideLegacyChainIdentity() {
        Chain candidate = chain("setValueByCommand");
        String chainKey = candidate.key();
        String entryMethod = "app/ApiController#putNote()Ljava/lang/Object;";
        EvidenceAtom entry = EvidenceAtom.of(EvidenceAtom.Kind.APPLICATION_ENTRY, "UNKNOWN",
                "app/ApiController", "putNote()Ljava/lang/Object;",
                "INDEX_TYPED_BINDING_ENTRY", Map.of(
                        "chain_key", chainKey,
                        "entry_join_kind", "TYPED_BINDING_TARGET",
                        "chain_entry_method", "app/Metric#setValueByCommand(Ljava/lang/String;)V",
                        "entry_prefix_path", entryMethod));
        EvidenceAtom site = EvidenceAtom.of(EvidenceAtom.Kind.BINDING_SITE, "UNKNOWN",
                "app/ApiController", "putNote()Ljava/lang/Object;",
                "INDEX_TYPED_BINDING_SITE", Map.of("chain_key", chainKey));
        EvidenceAtom dependency = EvidenceAtom.of(EvidenceAtom.Kind.DEPENDENCY_SEGMENT,
                "UNKNOWN", "dep/Gadget", "run", "CHAIN_DEPENDENCY_SUFFIX",
                Map.of("chain_key", chainKey));
        EvidenceAtom terminal = EvidenceAtom.of(EvidenceAtom.Kind.TERMINAL_IMPACT,
                "UNKNOWN", "java/lang/Runtime", "exec", "INDEX_TERMINAL_IMPACT",
                Map.of("chain_key", chainKey));
        ApplicationChainId appChain = ApplicationChainId.fromCanonical("chain", chainKey);
        EntryChainJoinEvidence join = EntryChainJoinEvidence.of(appChain, entry.id(), site.id(),
                GadgetSegmentId.fromCanonical("chain", chainKey, "dep/Gadget"),
                EntryChainJoinEvidence.ValueFlow.CALLBACK_ARGUMENT,
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
                Map.of(appChain.value(), join), Map.of(), Map.of(chainKey, "JOINED"), List.of());

        FindingOutputReader.Snapshot snapshot = new FindingOutputReader().read(
                List.of(candidate), Map.of(), Map.of(), Map.of(), true, evidence);
        ApplicationTrace trace = snapshot.applicationTrace(chainKey);
        assertTrue(trace != null);
        assertEquals("app/ApiController", trace.applicationEntryClass());
        assertEquals("app/ApiController", trace.applicationSiteClass());
        assertEquals("TYPED_BINDING_TARGET", trace.joinKind());
        assertEquals(entryMethod, trace.entryPrefixPath());
        assertEquals("UNKNOWN", trace.joinEvidence().artifactDigest());
        assertEquals("UNKNOWN", trace.joinEvidence().applicationIndexDigest());
        assertEquals(join.id(), trace.joinEvidence().joinId());
        assertTrue(snapshot.toCanonicalJson().contains("application_trace"));
    }
}
