package io.just.sast.report;

import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.HopKind;
import io.just.sast.blackboard.HopProvenance;
import io.just.sast.cpg.graph.Graph;
import io.just.sast.cpg.graph.Node;
import io.just.sast.model.ArtifactProvenance;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;

/** Projects frozen CPG call-site facts onto report hops without re-solving a chain. */
public final class HopProvenanceResolver {

    private HopProvenanceResolver() {
    }

    public static List<Chain> enrich(List<Chain> chains, Graph graph,
                                     Map<String, ArtifactProvenance> artifacts) {
        if (chains == null || chains.isEmpty()) {
            return List.of();
        }
        Map<String, ArtifactProvenance> owners = artifacts == null ? Map.of() : artifacts;
        List<Chain> result = new ArrayList<>(chains.size());
        for (Chain chain : chains) {
            if (chain == null) {
                continue;
            }
            Map<String, Set<String>> descriptors = methodDescriptors(chain);
            List<ChainHop> hops = new ArrayList<>(chain.hops().size());
            for (ChainHop hop : chain.hops()) {
                if (hop == null || hop.provenance() != null) {
                    hops.add(hop);
                    continue;
                }
                hops.add(hop.withProvenance(resolve(hop, descriptors, graph, owners)));
            }
            result.add(new Chain(chain.ruleId(), chain.category(), chain.severity(),
                    chain.entryClass(), chain.entryMethod(), chain.entryKind(),
                    chain.sinkClass(), chain.sinkMethod(), hops, chain.unresolvedHops(),
                    chain.sinkDescriptor(), chain.sinkRole(), chain.constructionPlan(),
                    chain.sinkRisk()));
        }
        return List.copyOf(result);
    }

    private static HopProvenance resolve(ChainHop hop,
                                         Map<String, Set<String>> descriptors,
                                         Graph graph,
                                         Map<String, ArtifactProvenance> artifacts) {
        ArtifactProvenance artifact = artifacts.get(hop.fromOwner());
        String fromDescriptor = unique(descriptors.get(methodKey(hop.fromOwner(), hop.fromName())));
        if (hop.kind() == HopKind.ENTRY) {
            return HopProvenance.unknown(fromDescriptor, HopProvenance.Basis.ENTRY_BOUNDARY,
                    0, artifact);
        }
        if (hop.kind() == HopKind.FIELD_FLOW) {
            return HopProvenance.unknown(fromDescriptor,
                    HopProvenance.Basis.FIELD_FLOW_NO_CALLSITE, 0, artifact);
        }
        if (graph == null) {
            return HopProvenance.unknown(fromDescriptor, HopProvenance.Basis.GRAPH_UNAVAILABLE,
                    0, artifact);
        }
        if (fromDescriptor == null || hop.desc() == null || hop.desc().isBlank()) {
            return HopProvenance.unknown(fromDescriptor,
                    HopProvenance.Basis.MISSING_DESCRIPTOR, 0, artifact);
        }
        String hostKey = methodKey(hop.fromOwner(), hop.fromName()) + fromDescriptor;
        List<Node> calls = graph.callsOfMethod(hostKey);
        List<Node> exact = calls.stream()
                .filter(call -> Objects.equals(call.owner(), hop.toOwner()))
                .filter(call -> Objects.equals(call.name(), hop.toName()))
                .filter(call -> Objects.equals(call.descriptor(), hop.desc()))
                .toList();
        if (exact.size() == 1 && exact.get(0).offset() >= 0) {
            return HopProvenance.exact(fromDescriptor, exact.get(0).offset(), artifact);
        }
        if (exact.size() > 1) {
            return HopProvenance.unknown(fromDescriptor,
                    HopProvenance.Basis.CALLSITE_AMBIGUOUS, exact.size(), artifact);
        }
        return HopProvenance.unknown(fromDescriptor,
                HopProvenance.Basis.CALLSITE_NOT_FOUND, 0, artifact);
    }

    private static Map<String, Set<String>> methodDescriptors(Chain chain) {
        Map<String, Set<String>> descriptors = new HashMap<>();
        String entryDescriptor = ChainIdentity.entryDescriptor(chain);
        if (!entryDescriptor.isBlank()) {
            add(descriptors, methodKey(chain.entryClass(), chain.entryMethod()), entryDescriptor);
        }
        for (ChainHop hop : chain.hops()) {
            if (hop == null || hop.desc() == null || hop.desc().isBlank()) {
                continue;
            }
            add(descriptors, methodKey(hop.toOwner(), hop.toName()), hop.desc());
        }
        return descriptors;
    }

    private static void add(Map<String, Set<String>> values, String key, String descriptor) {
        if (key == null || key.isBlank() || descriptor == null || descriptor.isBlank()) {
            return;
        }
        values.computeIfAbsent(key, ignored -> new TreeSet<>()).add(descriptor);
    }

    private static String unique(Set<String> values) {
        return values != null && values.size() == 1 ? values.iterator().next() : null;
    }

    private static String methodKey(String owner, String name) {
        if (owner == null || owner.isBlank() || name == null || name.isBlank()) {
            return "";
        }
        return owner + "#" + name;
    }
}
