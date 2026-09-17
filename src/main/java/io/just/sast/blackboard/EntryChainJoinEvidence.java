package io.just.sast.blackboard;

import java.util.ArrayList;
import java.util.List;

/**
 * Typed proof that an application-owned entry/site joins a dependency gadget
 * segment.  The graph, not a class-name coincidence, is the owner of the join.
 */
public record EntryChainJoinEvidence(
        String id,
        ApplicationChainId applicationChainId,
        String applicationEntryAtomId,
        String applicationSiteAtomId,
        GadgetSegmentId dependencySegmentId,
        ValueFlow valueFlow,
        ObjectIdentity objectIdentity,
        CallbackSemantics callbackSemantics,
        RuntimeTypeProof runtimeTypeProof,
        ArtifactCompatibility artifactCompatibility,
        FilterDominance filterDominance,
        ConstructionConstraint constructionConstraint,
        List<String> bridgeEvidenceIds) implements EvidenceNode {

    public enum ValueFlow {
        DIRECT_VALUE,
        OBJECT_IDENTITY,
        CALLBACK_ARGUMENT,
        /** A finite collection element recovered from one serialized input object. */
        DESERIALIZED_ELEMENT,
        PROTOCOL_REPLY,
        DERIVED_VALUE,
        UNKNOWN
    }

    public enum ObjectIdentity {
        SAME_OBJECT,
        SERIALIZED_ROUND_TRIP,
        DERIVED_OBJECT,
        IDENTITY_UNKNOWN
    }

    public enum CallbackSemantics {
        DIRECT,
        DESERIALIZATION,
        FRAMEWORK_LIFECYCLE,
        REFLECTION_DISPATCH,
        PROTOCOL_REENTRY,
        UNKNOWN
    }

    public enum RuntimeTypeProof {
        EXACT,
        SEALED_SET,
        BOUNDED,
        UNKNOWN
    }

    public enum ArtifactCompatibility {
        SAME_ARTIFACT,
        CROSS_ARTIFACT_VERIFIED,
        JDK_COMPATIBLE,
        UNKNOWN
    }

    public enum FilterDominance {
        NOT_PRESENT,
        DOMINATES,
        DOES_NOT_DOMINATE,
        UNKNOWN
    }

    public enum ConstructionConstraint {
        SAT,
        UNSAT,
        UNKNOWN
    }

    public EntryChainJoinEvidence {
        applicationChainId = java.util.Objects.requireNonNull(applicationChainId,
                "applicationChainId");
        applicationEntryAtomId = EvidenceIdSupport.requireId("atom", applicationEntryAtomId);
        applicationSiteAtomId = EvidenceIdSupport.requireId("atom", applicationSiteAtomId);
        dependencySegmentId = java.util.Objects.requireNonNull(dependencySegmentId,
                "dependencySegmentId");
        valueFlow = java.util.Objects.requireNonNull(valueFlow, "valueFlow");
        objectIdentity = java.util.Objects.requireNonNull(objectIdentity, "objectIdentity");
        callbackSemantics = java.util.Objects.requireNonNull(callbackSemantics,
                "callbackSemantics");
        runtimeTypeProof = java.util.Objects.requireNonNull(runtimeTypeProof,
                "runtimeTypeProof");
        artifactCompatibility = java.util.Objects.requireNonNull(artifactCompatibility,
                "artifactCompatibility");
        filterDominance = java.util.Objects.requireNonNull(filterDominance, "filterDominance");
        constructionConstraint = java.util.Objects.requireNonNull(constructionConstraint,
                "constructionConstraint");
        ArrayList<String> bridges = new ArrayList<>();
        if (bridgeEvidenceIds != null) {
            for (String bridge : bridgeEvidenceIds) {
                bridges.add(EvidenceIdSupport.requireId("bridge", bridge));
            }
        }
        bridges.sort(String::compareTo);
        bridgeEvidenceIds = List.copyOf(new java.util.LinkedHashSet<>(bridges));
        String expected = EvidenceIdSupport.id("join", applicationChainId.value(),
                applicationEntryAtomId, applicationSiteAtomId, dependencySegmentId.value(),
                valueFlow.name(), objectIdentity.name(), callbackSemantics.name(),
                runtimeTypeProof.name(), artifactCompatibility.name(), filterDominance.name(),
                constructionConstraint.name(), String.join(",", bridgeEvidenceIds));
        id = id == null || id.isBlank() ? expected : EvidenceIdSupport.requireId("join", id);
        if (!expected.equals(id)) {
            throw new IllegalArgumentException("join id does not match canonical evidence");
        }
    }

    public static EntryChainJoinEvidence of(ApplicationChainId chainId, String entryAtomId,
                                             String siteAtomId, GadgetSegmentId segmentId,
                                             ValueFlow valueFlow, ObjectIdentity objectIdentity,
                                             CallbackSemantics callbackSemantics,
                                             RuntimeTypeProof runtimeTypeProof,
                                             ArtifactCompatibility artifactCompatibility,
                                             FilterDominance filterDominance,
                                             ConstructionConstraint constructionConstraint,
                                             List<String> bridgeIds) {
        return new EntryChainJoinEvidence(null, chainId, entryAtomId, siteAtomId, segmentId,
                valueFlow, objectIdentity, callbackSemantics, runtimeTypeProof,
                artifactCompatibility, filterDominance, constructionConstraint, bridgeIds);
    }

    @Override
    public NodeKind nodeKind() {
        return NodeKind.ENTRY_CHAIN_JOIN;
    }

    @Override
    public String canonical() {
        return "join|" + id + '|' + applicationChainId + '|' + applicationEntryAtomId + '|'
                + applicationSiteAtomId + '|' + dependencySegmentId + '|' + valueFlow + '|'
                + objectIdentity + '|' + callbackSemantics + '|' + runtimeTypeProof + '|'
                + artifactCompatibility + '|' + filterDominance + '|' + constructionConstraint
                + '|' + String.join(",", bridgeEvidenceIds);
    }

    @Override
    public String toCanonicalJson() {
        StringBuilder json = new StringBuilder("{\"id\":\"")
                .append(EvidenceIdSupport.json(id)).append("\",\"kind\":\"ENTRY_CHAIN_JOIN\"")
                .append(",\"applicationChainId\":\"")
                .append(EvidenceIdSupport.json(applicationChainId.value()))
                .append("\",\"applicationEntryAtomId\":\"")
                .append(EvidenceIdSupport.json(applicationEntryAtomId))
                .append("\",\"applicationSiteAtomId\":\"")
                .append(EvidenceIdSupport.json(applicationSiteAtomId))
                .append("\",\"dependencySegmentId\":\"")
                .append(EvidenceIdSupport.json(dependencySegmentId.value()))
                .append("\",\"valueFlow\":\"").append(valueFlow)
                .append("\",\"objectIdentity\":\"").append(objectIdentity)
                .append("\",\"callbackSemantics\":\"").append(callbackSemantics)
                .append("\",\"runtimeTypeProof\":\"").append(runtimeTypeProof)
                .append("\",\"artifactCompatibility\":\"").append(artifactCompatibility)
                .append("\",\"filterDominance\":\"").append(filterDominance)
                .append("\",\"constructionConstraint\":\"").append(constructionConstraint)
                .append("\",\"bridgeEvidenceIds\":[");
        for (int index = 0; index < bridgeEvidenceIds.size(); index++) {
            if (index > 0) {
                json.append(',');
            }
            json.append('"').append(EvidenceIdSupport.json(bridgeEvidenceIds.get(index))).append('"');
        }
        return json.append("]}").toString();
    }
}
