package io.just.sast.report;

import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.EntryChainJoinEvidence;
import io.just.sast.blackboard.EvidenceAtom;
import io.just.sast.blackboard.EvidenceEdge;
import io.just.sast.blackboard.EvidenceGraph;
import io.just.sast.blackboard.FindingState;
import io.just.sast.blackboard.GadgetSegmentId;
import io.just.sast.blackboard.HopKind;
import io.just.sast.analysis.entry.ApplicationChainEvidence;
import io.just.sast.blackboard.ApplicationChainId;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Contract tests for report-boundary hop and application-join auditing. */
class ReportHopAuditContractTest {

    @Test
    void fastjsonSideEffectAllowsUnrelatedFinalDeclaredAndActualTypes() {
        Chain chain = new Chain("RULE-QIAO", "COMMAND_EXEC", "HIGH",
                "com/example/demo/dto/MetricDTO", "setValueByCommand", "deserialize",
                "java/lang/ProcessBuilder", "start", List.of(
                        new ChainHop("com/example/demo/dto/MetricDTO", "setValueByCommand",
                                "com/example/demo/dto/MetricDTO", "setValueByCommand",
                                HopKind.ENTRY, null, "deserialize", "(Ljava/lang/String;)V", null)),
                0, "()Ljava/lang/Process;");
        String key = chain.key();
        EvidenceAtom entry = EvidenceAtom.of(EvidenceAtom.Kind.APPLICATION_ENTRY, "UNKNOWN",
                "com/example/demo/ApiController",
                "putNote(Lcom/example/demo/dto/NoteDTO;)Ljava/lang/Object;",
                "INDEX_DESERIALIZATION_SIDE_EFFECT_ENTRY", Map.of(
                        "chain_key", key,
                        "entry_join_kind", "DESERIALIZATION_SIDE_EFFECT",
                        "chain_entry_method",
                        "com/example/demo/dto/MetricDTO#setValueByCommand(Ljava/lang/String;)V",
                        "entry_prefix_path",
                        "com/example/demo/ApiController#putNote(Lcom/example/demo/dto/NoteDTO;)Ljava/lang/Object;"));
        EvidenceAtom site = EvidenceAtom.of(EvidenceAtom.Kind.BINDING_SITE, "UNKNOWN",
                "com/example/demo/ApiController",
                "putNote(Lcom/example/demo/dto/NoteDTO;)Ljava/lang/Object;",
                "INDEX_DESERIALIZATION_SIDE_EFFECT_SITE", Map.of(
                        "chain_key", key,
                        "target_types", "com/example/demo/dto/NoteDTO",
                        "deserialization_side_effect_types", "com/example/demo/dto/MetricDTO"));
        EvidenceAtom dependency = EvidenceAtom.of(EvidenceAtom.Kind.DEPENDENCY_SEGMENT,
                "UNKNOWN", "java/lang/ProcessBuilder", "start", "CHAIN_DEPENDENCY_SUFFIX",
                Map.of("chain_key", key));
        EvidenceAtom terminal = EvidenceAtom.of(EvidenceAtom.Kind.TERMINAL_IMPACT,
                "UNKNOWN", "java/lang/ProcessBuilder", "start", "INDEX_TERMINAL_IMPACT",
                Map.of("chain_key", key, "descriptor", "()Ljava/lang/Process;"));
        ApplicationChainId applicationChain = ApplicationChainId.fromCanonical("chain", key);
        EntryChainJoinEvidence join = EntryChainJoinEvidence.of(applicationChain, entry.id(),
                site.id(), GadgetSegmentId.fromCanonical("chain", key, "process-builder"),
                EntryChainJoinEvidence.ValueFlow.CALLBACK_ARGUMENT,
                EntryChainJoinEvidence.ObjectIdentity.DERIVED_OBJECT,
                EntryChainJoinEvidence.CallbackSemantics.DESERIALIZATION,
                EntryChainJoinEvidence.RuntimeTypeProof.EXACT,
                EntryChainJoinEvidence.ArtifactCompatibility.UNKNOWN,
                EntryChainJoinEvidence.FilterDominance.NOT_PRESENT,
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
                Map.of(applicationChain.value(), join), Map.of(), Map.of(key, "JOINED"),
                List.of());
        FindingState state = new FindingState(FindingState.EntryStatus.EXTERNAL_ENTRY,
                FindingState.ChainProgress.IMPACT_CHAIN_COMPLETE, FindingState.Feasibility.SAT,
                FindingState.Completeness.COMPLETE, FindingState.Risk.HIGH);
        FindingOutputReader.Snapshot snapshot = new FindingOutputReader().read(
                List.of(chain), Map.of(), Map.of(), Map.of(key, state), true, evidence);
        ApplicationTrace trace = snapshot.applicationTrace(key);

        ReportHopAudit.Result audit = ReportHopAudit.inspect(snapshot.require(key), trace, true);

        assertTrue(audit.passed(), audit.issues().toString());
        assertTrue("DESERIALIZATION_SIDE_EFFECT".equals(trace.joinKind()));
        assertFalse("TYPED_BINDING_TARGET".equals(trace.joinKind()));
        assertFalse(trace.entryPrefixPath().contains("MetricDTO"),
                "declared NoteDTO path must remain distinct from the MetricDTO side effect");
    }

    @Test
    void completeApplicationFindingWithMissingBridgeBecomesNamedPartial() {
        Chain chain = terminalChain();
        FindingState state = new FindingState(FindingState.EntryStatus.EXTERNAL_ENTRY,
                FindingState.ChainProgress.IMPACT_CHAIN_COMPLETE, FindingState.Feasibility.SAT,
                FindingState.Completeness.COMPLETE, FindingState.Risk.HIGH);
        FindingOutputReader.Snapshot snapshot = new FindingOutputReader().read(
                List.of(chain), Map.of(), Map.of(), Map.of(chain.key(), state), true);
        ApplicationTrace trace = new ApplicationTrace(
                "app/Api", "put", "app/Api", "put", "BINDING_SITE",
                "TYPED_BINDING_TARGET", "dep/Gadget#readObject()V",
                "app/Api#put(Ldep/Input;)V", "dep/Gadget", "java/lang/Runtime", "exec");
        FindingOutputReader.Snapshot withTrace = new FindingOutputReader.Snapshot(
                snapshot.schemaVersion(), snapshot.findings(), snapshot.byChainKey(),
                Map.of(chain.key(), trace));

        ReportHopAudit.Result audit = ReportHopAudit.inspect(withTrace.require(chain.key()),
                trace, true);

        assertFalse(audit.passed());
        assertTrue(audit.limits().contains("BRIDGE_EVIDENCE_MISSING"));
        assertTrue(audit.limits().contains("CHAIN_ENTRY_DESCRIPTOR_UNKNOWN"));
        ConciseReportProjection projection = ConciseReportProjection.from(
                "application", withTrace, ScanStatistics.empty());
        assertEquals("PARTIAL", projection.findings().get(0).status().name());
        assertTrue(projection.findings().get(0).limits().contains("BRIDGE_EVIDENCE_MISSING"));
    }

    @Test
    void perHopAuditNamesOwnershipDescriptorAndIdentityGaps() {
        Chain chain = new Chain("RULE-BAD", "COMMAND", "HIGH", "app/Entry", "read",
                "readObject", "java/lang/Runtime", "exec", List.of(
                        new ChainHop("app/Entry", "read", "java/lang/Runtime", "exec",
                                HopKind.DIRECT_CALL, null, "call", "not-a-method-descriptor", -1)),
                0, "()Ljava/lang/Process;");
        FindingOutputReader.Snapshot snapshot = new FindingOutputReader().read(
                List.of(chain), Map.of(), Map.of(), Map.of());

        ReportHopAudit.Result audit = ReportHopAudit.inspect(snapshot.require(chain.key()),
                null, false);

        assertFalse(audit.passed());
        assertTrue(audit.hops().get(0).issues().contains("HOP_DESCRIPTOR_INVALID"));
        assertTrue(audit.hops().get(0).issues().contains("HOP_ARGUMENT_IDENTITY_INVALID"));
        assertTrue(audit.limits().contains("HOP_DESCRIPTOR_INVALID"));
    }

    private static Chain terminalChain() {
        return new Chain("RULE-APP", "COMMAND", "HIGH", "dep/Gadget", "readObject",
                "deserialize", "java/lang/Runtime", "exec", List.of(
                        new ChainHop("dep/Gadget", "readObject", "java/lang/Runtime", "exec",
                                HopKind.DIRECT_CALL, null, "terminal",
                                "(Ljava/lang/String;)Ljava/lang/Process;", 0)), 0,
                "(Ljava/lang/String;)Ljava/lang/Process;");
    }
}
