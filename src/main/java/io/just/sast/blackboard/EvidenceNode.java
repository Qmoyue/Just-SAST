package io.just.sast.blackboard;

/** Closed node family consumed by the immutable evidence graph. */
public sealed interface EvidenceNode extends BlackboardFact
        permits EvidenceAtom, EntryChainJoinEvidence, BridgeEvidence {
    String id();

    NodeKind nodeKind();

    /** Canonical, length-delimited representation used for graph digests. */
    String canonical();

    /** Deterministic schema representation; renderers must not parse free-form notes. */
    String toCanonicalJson();

    enum NodeKind {
        ATOM,
        ENTRY_CHAIN_JOIN,
        PROTOCOL_BRIDGE
    }
}
