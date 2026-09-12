package io.just.sast.analysis.entry;

import io.just.sast.blackboard.ApplicationChainId;
import io.just.sast.blackboard.EntryChainJoinEvidence;
import io.just.sast.blackboard.EvidenceAtom;
import io.just.sast.blackboard.EvidenceGraph;
import io.just.sast.blackboard.FindingState;
import io.just.sast.blackboard.GadgetSegmentId;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Contract coverage for deterministic application-chain evidence publication. */
class ApplicationChainEvidenceContractTest {

    @Test
    void canonicalDigestAndJsonAreStable() {
        ApplicationChainEvidence first = evidence();
        ApplicationChainEvidence second = new ApplicationChainEvidence(
                ApplicationChainEvidence.SCHEMA_VERSION, first.artifactDigest(),
                first.applicationIndexDigest(), first.applicationScopeKnown(), first.graph(), first.joins(),
                first.states(), first.decisions(), first.reasons());

        assertEquals(first.semanticDigest(), second.semanticDigest());
        assertEquals(first.toCanonicalJson(), second.toCanonicalJson());
        assertTrue(first.toCanonicalJson().contains("join_count"));
        assertTrue(first.toCanonicalJson().contains("},\"join_count\":1"),
                "graph must be emitted as an object followed by the next field, not a quoted object");
        assertTrue(!first.toCanonicalJson().contains("}\",\"join_count\":"),
                "canonical application evidence must remain parseable JSON");
        assertEquals(1, first.joinedChainKeys().size());
    }

    @Test
    void evidenceMapUsesStableApplicationChainId() {
        ApplicationChainEvidence value = evidence();
        EntryChainJoinEvidence join = value.joins().values().iterator().next();
        assertTrue(value.joins().containsKey(join.applicationChainId().value()));
    }

    @Test
    void rejectsMismatchedEvidenceMapKey() {
        EntryChainJoinEvidence join = evidence().joins().values().iterator().next();
        assertThrows(IllegalArgumentException.class, () -> new ApplicationChainEvidence(
                ApplicationChainEvidence.SCHEMA_VERSION, "C".repeat(64), evidence().applicationIndexDigest(),
                evidence().applicationScopeKnown(), evidence().graph(),
                Map.of("appchain-" + "0".repeat(64), join), evidence().states(),
                evidence().decisions(), List.of()));
    }

    private static ApplicationChainEvidence evidence() {
        String chainKey = "chain-key";
        ApplicationChainId chainId = ApplicationChainId.fromCanonical("fixture", chainKey);
        EvidenceAtom entry = EvidenceAtom.of(EvidenceAtom.Kind.APPLICATION_ENTRY, "fixture",
                "fixture/app/App", "handle()V", "TEST_ENTRY", Map.of());
        EvidenceAtom site = EvidenceAtom.of(EvidenceAtom.Kind.DESERIALIZATION_SITE, "fixture",
                "fixture/app/App", "readObject()Ljava/lang/Object;", "TEST_SITE", Map.of());
        GadgetSegmentId segment = GadgetSegmentId.fromCanonical("fixture", chainKey,
                "fixture/lib/Gadget");
        EntryChainJoinEvidence join = EntryChainJoinEvidence.of(chainId, entry.id(), site.id(),
                segment, EntryChainJoinEvidence.ValueFlow.DIRECT_VALUE,
                EntryChainJoinEvidence.ObjectIdentity.SAME_OBJECT,
                EntryChainJoinEvidence.CallbackSemantics.DESERIALIZATION,
                EntryChainJoinEvidence.RuntimeTypeProof.EXACT,
                EntryChainJoinEvidence.ArtifactCompatibility.CROSS_ARTIFACT_VERIFIED,
                EntryChainJoinEvidence.FilterDominance.UNKNOWN,
                EntryChainJoinEvidence.ConstructionConstraint.SAT, List.of());
        EvidenceGraph graph = new EvidenceGraph(List.of(entry, site, join), List.of());
        FindingState state = new FindingState(FindingState.EntryStatus.EXTERNAL_ENTRY,
                FindingState.ChainProgress.IMPACT_CHAIN_COMPLETE,
                FindingState.Feasibility.SAT, FindingState.Completeness.COMPLETE,
                FindingState.Verification.NOT_ATTEMPTED, FindingState.Risk.HIGH);
        return new ApplicationChainEvidence(ApplicationChainEvidence.SCHEMA_VERSION,
                "A".repeat(64), "B".repeat(64), true, graph,
                Map.of(chainId.value(), join), Map.of(chainKey, state),
                Map.of(chainKey, "JOINED"), List.of("TEST_REASON"));
    }
}
