package io.just.sast.blackboard;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Immutable, deterministic evidence DAG/graph.  It stores facts only; ranking,
 * dynamic scheduling and report policy remain separate consumers.
 */
public record EvidenceGraph(List<EvidenceNode> nodes, List<EvidenceEdge> edges)
        implements BlackboardFact {

    public EvidenceGraph {
        Objects.requireNonNull(nodes, "nodes");
        Objects.requireNonNull(edges, "edges");
        ArrayList<EvidenceNode> orderedNodes = new ArrayList<>(nodes);
        orderedNodes.forEach(node -> {
            if (node == null) {
                throw new IllegalArgumentException("evidence graph cannot contain null node");
            }
        });
        orderedNodes.sort(Comparator.comparing(EvidenceNode::id)
                .thenComparing(node -> node.nodeKind().name()));
        Set<String> nodeIds = new HashSet<>();
        for (EvidenceNode node : orderedNodes) {
            if (!nodeIds.add(node.id())) {
                throw new IllegalArgumentException("duplicate evidence node id: " + node.id());
            }
        }
        Map<String, EvidenceNode> nodeById = new HashMap<>();
        for (EvidenceNode node : orderedNodes) {
            nodeById.put(node.id(), node);
        }
        validateJoinReferences(orderedNodes, nodeById);
        ArrayList<EvidenceEdge> orderedEdges = new ArrayList<>(edges);
        orderedEdges.forEach(edge -> {
            if (edge == null) {
                throw new IllegalArgumentException("evidence graph cannot contain null edge");
            }
            if (!nodeIds.contains(edge.fromId()) || !nodeIds.contains(edge.toId())) {
                throw new IllegalArgumentException("dangling evidence edge: " + edge.id());
            }
        });
        orderedEdges.sort(Comparator.comparing(EvidenceEdge::fromId)
                .thenComparing(EvidenceEdge::toId)
                .thenComparing(edge -> edge.kind().name())
                .thenComparing(EvidenceEdge::id));
        Set<String> edgeIds = new HashSet<>();
        for (EvidenceEdge edge : orderedEdges) {
            if (!edgeIds.add(edge.id())) {
                throw new IllegalArgumentException("duplicate evidence edge id: " + edge.id());
            }
        }
        nodes = List.copyOf(orderedNodes);
        edges = List.copyOf(orderedEdges);
    }

    private static void validateJoinReferences(List<EvidenceNode> orderedNodes,
                                                Map<String, EvidenceNode> nodeById) {
        for (EvidenceNode node : orderedNodes) {
            if (!(node instanceof EntryChainJoinEvidence join)) {
                continue;
            }
            EvidenceNode entry = nodeById.get(join.applicationEntryAtomId());
            if (!(entry instanceof EvidenceAtom entryAtom)
                    || entryAtom.kind() != EvidenceAtom.Kind.APPLICATION_ENTRY) {
                throw new IllegalArgumentException("join entry must reference an application-entry atom: "
                        + join.id());
            }
            EvidenceNode site = nodeById.get(join.applicationSiteAtomId());
            if (!(site instanceof EvidenceAtom siteAtom)
                    || !isApplicationSite(siteAtom.kind())) {
                throw new IllegalArgumentException("join site must reference an application-site atom: "
                        + join.id());
            }
            for (String bridgeId : join.bridgeEvidenceIds()) {
                if (!(nodeById.get(bridgeId) instanceof BridgeEvidence)) {
                    throw new IllegalArgumentException("join bridge reference is not a graph bridge: "
                            + bridgeId);
                }
            }
        }
    }

    private static boolean isApplicationSite(EvidenceAtom.Kind kind) {
        return kind == EvidenceAtom.Kind.DESERIALIZATION_SITE
                || kind == EvidenceAtom.Kind.BINDING_SITE
                || kind == EvidenceAtom.Kind.LOOKUP_SITE
                || kind == EvidenceAtom.Kind.CONFIG_SITE;
    }

    public static EvidenceGraph empty() {
        return new EvidenceGraph(List.of(), List.of());
    }

    public EvidenceGraph withNode(EvidenceNode node) {
        ArrayList<EvidenceNode> next = new ArrayList<>(nodes);
        next.add(java.util.Objects.requireNonNull(node, "node"));
        return new EvidenceGraph(next, edges);
    }

    public EvidenceGraph withEdge(EvidenceEdge edge) {
        ArrayList<EvidenceEdge> next = new ArrayList<>(edges);
        next.add(java.util.Objects.requireNonNull(edge, "edge"));
        return new EvidenceGraph(nodes, next);
    }

    public String canonicalDigest() {
        StringBuilder canonical = new StringBuilder();
        nodes.forEach(node -> canonical.append(node.canonical()).append('\n'));
        edges.forEach(edge -> canonical.append(edge.canonical()).append('\n'));
        return EvidenceIdSupport.sha256(canonical.toString());
    }

    public String toCanonicalJson() {
        StringBuilder json = new StringBuilder("{\"schema\":\"evidence-graph-v1\",\"nodes\":[");
        for (int i = 0; i < nodes.size(); i++) {
            if (i > 0) {
                json.append(',');
            }
            EvidenceNode node = nodes.get(i);
            json.append(node.toCanonicalJson());
        }
        json.append("],\"edges\":[");
        for (int i = 0; i < edges.size(); i++) {
            if (i > 0) {
                json.append(',');
            }
            EvidenceEdge edge = edges.get(i);
            json.append(edge.toCanonicalJson());
        }
        return json.append("]}").toString();
    }
}
