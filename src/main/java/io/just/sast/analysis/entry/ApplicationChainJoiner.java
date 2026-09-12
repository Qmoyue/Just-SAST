package io.just.sast.analysis.entry;

import io.just.sast.blackboard.ApplicationChainId;
import io.just.sast.blackboard.Blackboard;
import io.just.sast.blackboard.BridgeEvidence;
import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.EntryChainJoinEvidence;
import io.just.sast.blackboard.EvidenceAtom;
import io.just.sast.blackboard.EvidenceEdge;
import io.just.sast.blackboard.EvidenceGraph;
import io.just.sast.blackboard.EvidenceNode;
import io.just.sast.blackboard.FindingState;
import io.just.sast.blackboard.GadgetSegmentId;
import io.just.sast.blackboard.HopKind;
import io.just.sast.blackboard.SinkRisk;
import io.just.sast.cpg.graph.Graph;
import io.just.sast.cpg.graph.Edge;
import io.just.sast.cpg.graph.Node;
import io.just.sast.model.Descriptor;

import java.util.ArrayList;
import java.util.ArrayDeque;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * Builds the first typed application-chain join product.
 *
 * <p>This is intentionally an admission/evidence seam, not a second taint solver.  A join is
 * emitted only when the immutable application index has an application-owned execution entry,
 * the entry and terminal are in the bounded entry∩terminal demand hint, and the chain contains
 * a dependency/JDK suffix.  Unjoined chains remain available to static/kernel consumers.</p>
 */
public final class ApplicationChainJoiner {

    private static final int MAX_JOINED_CHAINS = 50_000;

    private ApplicationChainJoiner() {
    }

    public static ApplicationChainEvidence build(Blackboard blackboard) {
        if (blackboard == null) {
            return ApplicationChainEvidence.empty(false, List.of("BLACKBOARD_MISSING"));
        }
        String digest = applicationDigest(blackboard);
        return build(blackboard.applicationEntryIndex(), blackboard.graph(),
                blackboard.chains(), blackboard.scanInputs().applicationScopeKnown(),
                digest, blackboard.completenessReasons());
    }

    public static ApplicationChainEvidence build(ApplicationEntryIndex index, Graph graph,
                                                  List<Chain> chains, boolean scopeKnown,
                                                  String artifactDigest, Set<String> scanReasons) {
        if (index == null || graph == null) {
            return ApplicationChainEvidence.empty(scopeKnown, List.of("INDEX_OR_GRAPH_MISSING"));
        }
        List<Chain> ordered = new ArrayList<>(chains == null ? List.of() : chains);
        ordered.removeIf(java.util.Objects::isNull);
        ordered.sort(Comparator.comparing(Chain::key));
        Map<String, EvidenceNode> nodes = new TreeMap<>();
        List<EvidenceEdge> edges = new ArrayList<>();
        Map<String, EntryChainJoinEvidence> joins = new TreeMap<>();
        Map<String, FindingState> states = new TreeMap<>();
        Map<String, String> decisions = new TreeMap<>();
        Map<String, ApplicationEntryIndex.CandidateAdmissionStatus> admissionDecisions =
                new TreeMap<>();
        List<String> reasons = new ArrayList<>();
        if (!scopeKnown) {
            reasons.add("APPLICATION_SCOPE_UNKNOWN");
        }
        if (scanReasons != null) {
            scanReasons.stream().filter(value -> value != null && !value.isBlank())
                    .map(value -> "SCAN_" + value.trim()).distinct().sorted().forEach(reasons::add);
        }

        int joined = 0;
        // A composed source chain may start at an application helper (for example a private
        // ticket decoder) while the externally reachable method is one caller above it.  Cache
        // the bounded graph-prefix lookup by chain entry so large candidate sets do not repeat
        // the same BFS for every sink variant.
        Map<String, EntryMatch> entryMatchCache = new HashMap<>();
        Map<String, List<String>> callTargetCache = new HashMap<>();
        for (Chain chain : ordered) {
            ApplicationEntryIndex.CandidateAdmissionDecision admission =
                    candidateAdmission(index, chain);
            admissionDecisions.put(chain.key(), admission.status());
            if (!admission.admitted()) {
                decisions.put(chain.key(), admission.reasonCode());
                continue;
            }
            Decision decision = decide(index, graph, chain, entryMatchCache, callTargetCache);
            decisions.put(chain.key(), decision.reason());
            if (decision.join() == null) {
                continue;
            }
            if (joined++ >= MAX_JOINED_CHAINS) {
                reasons.add("APPLICATION_CHAIN_JOIN_CAP:" + MAX_JOINED_CHAINS);
                break;
            }
            EntryChainJoinEvidence join = decision.join();
            // Evidence maps are keyed by the stable application-chain id.  The legacy chain key
            // remains in decisions/states for report and scheduler joins via joinedChainKeys().
            joins.put(join.applicationChainId().value(), join);
            states.put(chain.key(), decision.state());
            addNodes(nodes, decision.nodes());
            edges.addAll(decision.edges());
        }
        if (joins.isEmpty()) {
            reasons.add(scopeKnown ? "NO_APPLICATION_CHAIN_JOIN" : "NO_APPLICATION_SCOPE");
        }
        return new ApplicationChainEvidence(ApplicationChainEvidence.SCHEMA_VERSION,
                artifactDigest, index.semanticDigest(), scopeKnown,
                new EvidenceGraph(new ArrayList<>(nodes.values()), dedupeEdges(edges)), joins,
                states, decisions, admissionDecisions, reasons);
    }

    private static ApplicationEntryIndex.CandidateAdmissionDecision candidateAdmission(
            ApplicationEntryIndex index, Chain chain) {
        if (chain == null) {
            return new ApplicationEntryIndex.CandidateAdmissionDecision(
                    ApplicationEntryIndex.CandidateAdmissionStatus.APPLICATION_ENTRY_NOT_IN_CHAIN,
                    "", "", "", "", false, false, false);
        }
        String descriptor = entryDescriptor(chain);
        boolean continuation = hasSemanticContinuation(index, chain);
        return index.candidateAdmission(chain.entryClass(), chain.entryMethod(), descriptor,
                chain.sinkClass(), chain.sinkMethod(), chain.sinkDescriptor(), continuation);
    }

    private static Decision decide(ApplicationEntryIndex index, Graph graph, Chain chain,
                                   Map<String, EntryMatch> entryMatchCache,
                                   Map<String, List<String>> callTargetCache) {
        if (chain == null) {
            return Decision.rejected("CHAIN_MISSING");
        }
        EntryMatch entryMatch = findApplicationEntry(index, graph, chain, entryMatchCache,
                callTargetCache);
        if (entryMatch == null) {
            return Decision.rejected("APPLICATION_ENTRY_NOT_IN_CHAIN");
        }
        String entryKey = entryMatch.applicationEntryKey();
        Set<String> chainMethods = chainMethodIdentities(chain);
        ApplicationEntryIndex.TerminalDecision terminalDecision = index.terminalAdmission(
                chain.sinkClass(), chain.sinkMethod(), chain.sinkDescriptor());
        if (terminalDecision.status() == ApplicationEntryIndex.TerminalStatus.INTERMEDIATE_ONLY
                || (!terminalDecision.admitted() && !chain.terminalSink())) {
            return Decision.rejected(terminalDecision.reasonCode());
        }
        String terminalHostKey = terminalDecision.hostMethodKey();
        boolean continuationEvidence = entryMatch.typedBinding()
                || hasSemanticContinuation(index, chain);
        ApplicationEntryIndex.DemandDecision demand = index.demandAdmission(entryKey,
                terminalHostKey, continuationEvidence);
        if (!demand.admitted()) {
            return Decision.rejected(demand.reasonCode());
        }
        String dependencyOwner = dependencyOwner(index, chain);
        if (dependencyOwner == null) {
            return Decision.rejected("DEPENDENCY_SUFFIX_NOT_PRESENT");
        }
        if (!chainTouchesTerminal(index, graph, chain, chainMethods)) {
            return Decision.rejected("TERMINAL_SUFFIX_NOT_IN_CHAIN");
        }
        Map<String, String> entryAttributes = new TreeMap<>();
        entryAttributes.put("method_key", entryKey);
        entryAttributes.put("chain_entry_method", entryMatch.chainEntryKey());
        entryAttributes.put("entry_prefix_hops", Integer.toString(
                Math.max(0, entryMatch.path().size() - 1)));
        if (!entryMatch.path().isEmpty()) {
            // The path is a bounded list of canonical method keys, not a renderer note.  It is
            // part of the atom identity so a changed call prefix cannot reuse an old join ID.
            entryAttributes.put("entry_prefix_path", String.join("->", entryMatch.path()));
        }
        ApplicationEntryIndex.DeserializeSite site = entryMatch.bindingSite() != null
                ? entryMatch.bindingSite() : findSite(index, entryKey, chainMethods);
        if (entryMatch.typedBinding()) {
            entryAttributes.put("entry_join_kind", "TYPED_BINDING_TARGET");
            entryAttributes.put("binding_target_type", chain.entryClass());
            entryAttributes.put("binding_site_call_id", Long.toString(site.callId()));
            entryAttributes.put("binding_site_host", site.hostMethodKey());
        }
        EvidenceAtom entry = EvidenceAtom.of(EvidenceAtom.Kind.APPLICATION_ENTRY, "UNKNOWN",
                ownerOf(entryKey), memberOf(entryKey), entryMatch.path().isEmpty()
                        ? "INDEX_APPLICATION_ENTRY" : entryMatch.typedBinding()
                        ? "INDEX_TYPED_BINDING_ENTRY" : "INDEX_APPLICATION_CALL_PREFIX",
                entryAttributes);
        EvidenceAtom siteAtom = siteAtom(site, entryKey, chain, entryMatch);
        GadgetSegmentId segmentId = dependencySegmentId(index, chain, dependencyOwner);
        EvidenceAtom dependency = EvidenceAtom.of(EvidenceAtom.Kind.DEPENDENCY_SEGMENT,
                "UNKNOWN", dependencyOwner, chain.sinkMethod(), "CHAIN_DEPENDENCY_SUFFIX",
                Map.of("segment_id", segmentId.value(), "sink", chain.sinkClass() + "#"
                        + chain.sinkMethod(), "descriptor", chain.sinkDescriptor()));
        EvidenceAtom terminal = EvidenceAtom.of(EvidenceAtom.Kind.TERMINAL_IMPACT, "UNKNOWN",
                chain.sinkClass(), chain.sinkMethod(), "INDEX_TERMINAL_IMPACT",
                Map.of("descriptor", chain.sinkDescriptor(), "risk", chain.sinkRisk().name()));

        ApplicationChainId chainId = ApplicationChainId.fromCanonical("chain", chain.key());
        EntryChainJoinEvidence.ValueFlow flow = valueFlow(chain, entryMatch);
        EntryChainJoinEvidence.ObjectIdentity identity = flow == EntryChainJoinEvidence.ValueFlow.PROTOCOL_REPLY
                ? EntryChainJoinEvidence.ObjectIdentity.SERIALIZED_ROUND_TRIP
                : flow == EntryChainJoinEvidence.ValueFlow.DIRECT_VALUE
                ? EntryChainJoinEvidence.ObjectIdentity.SAME_OBJECT
                : EntryChainJoinEvidence.ObjectIdentity.DERIVED_OBJECT;
        EntryChainJoinEvidence.CallbackSemantics callback = callbackSemantics(chain, site);
        EntryChainJoinEvidence.RuntimeTypeProof runtimeType = entryMatch.typedBinding()
                ? EntryChainJoinEvidence.RuntimeTypeProof.EXACT
                : chain.unresolvedHops() == 0
                ? EntryChainJoinEvidence.RuntimeTypeProof.BOUNDED
                : EntryChainJoinEvidence.RuntimeTypeProof.UNKNOWN;
        // Artifact ownership and class-loader compatibility require the immutable provenance
        // map; a class-name boundary alone is not proof that two artifacts can link at runtime.
        // Keep this axis UNKNOWN until that provenance join is available rather than overclaiming
        // CROSS_ARTIFACT_VERIFIED from a dependency-looking owner.
        EntryChainJoinEvidence.ArtifactCompatibility compatibility =
                EntryChainJoinEvidence.ArtifactCompatibility.UNKNOWN;
        EntryChainJoinEvidence.ConstructionConstraint construction = chain.unresolvedHops() == 0
                ? EntryChainJoinEvidence.ConstructionConstraint.SAT
                : EntryChainJoinEvidence.ConstructionConstraint.UNKNOWN;

        List<BridgeEvidence> bridges = new ArrayList<>();
        if (site != null) {
            BridgeEvidence.Kind kind = bridgeKind(site.bridge());
            if (kind != BridgeEvidence.Kind.UNKNOWN) {
                bridges.add(BridgeEvidence.of(kind, siteAtom.id(), terminal.id(),
                        site.bridge(), BridgeEvidence.Status.PARTIAL));
            }
        }
        for (ChainHop hop : chain.hops()) {
            if (hop.reason() == null || !hop.reason().startsWith("bridge-")) {
                continue;
            }
            bridges.add(BridgeEvidence.of(bridgeKind(hop.reason()), siteAtom.id(), terminal.id(),
                    hop.reason(), BridgeEvidence.Status.PARTIAL));
        }
        List<String> bridgeIds = bridges.stream().map(BridgeEvidence::id).sorted().toList();
        EntryChainJoinEvidence join = EntryChainJoinEvidence.of(chainId, entry.id(), siteAtom.id(),
                segmentId, flow, identity, callback, runtimeType, compatibility,
                EntryChainJoinEvidence.FilterDominance.UNKNOWN, construction, bridgeIds);
        FindingState state = new FindingState(
                index.isExternalEntryMethod(entryKey) ? FindingState.EntryStatus.EXTERNAL_ENTRY
                        : FindingState.EntryStatus.APPLICATION_ENTRY,
                chain.unresolvedHops() == 0 && terminalDecision.admitted()
                        ? FindingState.ChainProgress.IMPACT_CHAIN_COMPLETE
                        : FindingState.ChainProgress.DEPENDENCY_JOINED,
                construction == EntryChainJoinEvidence.ConstructionConstraint.SAT
                        ? FindingState.Feasibility.SAT : FindingState.Feasibility.UNKNOWN,
                chain.unresolvedHops() == 0 ? FindingState.Completeness.COMPLETE
                        : FindingState.Completeness.PARTIAL,
                FindingState.Verification.NOT_ATTEMPTED, risk(chain.sinkRisk()));

        Map<String, EvidenceNode> localNodes = new LinkedHashMap<>();
        localNodes.put(entry.id(), entry);
        localNodes.put(siteAtom.id(), siteAtom);
        localNodes.put(dependency.id(), dependency);
        localNodes.put(terminal.id(), terminal);
        localNodes.put(join.id(), join);
        bridges.forEach(bridge -> localNodes.put(bridge.id(), bridge));
        List<EvidenceEdge> localEdges = new ArrayList<>();
        localEdges.add(EvidenceEdge.of(entry.id(), siteAtom.id(), EvidenceEdge.Kind.SUPPORTS,
                entryMatch.path().isEmpty() ? "APPLICATION_ENTRY_TO_DESERIALIZATION_SITE"
                        : "APPLICATION_ENTRY_CALL_PREFIX_TO_DESERIALIZATION_SITE"));
        localEdges.add(EvidenceEdge.of(siteAtom.id(), join.id(), EvidenceEdge.Kind.JOINS,
                "ENTRY_SITE_TO_DEPENDENCY_JOIN"));
        localEdges.add(EvidenceEdge.of(join.id(), dependency.id(), EvidenceEdge.Kind.FLOWS_TO,
                "DEPENDENCY_SUFFIX_ADMITTED"));
        localEdges.add(EvidenceEdge.of(dependency.id(), terminal.id(), EvidenceEdge.Kind.FLOWS_TO,
                "TERMINAL_IMPACT_REACHED"));
        for (BridgeEvidence bridge : bridges) {
            localEdges.add(EvidenceEdge.of(siteAtom.id(), bridge.id(), EvidenceEdge.Kind.BRIDGES,
                    "EXPLICIT_PROTOCOL_BRIDGE"));
            localEdges.add(EvidenceEdge.of(bridge.id(), dependency.id(), EvidenceEdge.Kind.BRIDGES,
                    "BRIDGE_TO_DEPENDENCY_SUFFIX"));
        }
        return new Decision("JOINED", join, state, localNodes.values().stream().toList(), localEdges);
    }

    /**
     * Determine whether the composed chain carries a typed continuation across the ordinary
     * call graph.  Protocol bridge reasons are converted to the closed BridgeEvidence kind;
     * an application→dependency ENTRY hop is the structural object-graph callback boundary.
     * No class/package/benchmark name is consulted.
     */
    private static boolean hasSemanticContinuation(ApplicationEntryIndex index, Chain chain) {
        if (index == null || chain == null) {
            return false;
        }
        for (ChainHop hop : chain.hops()) {
            if (hop == null) {
                continue;
            }
            if (bridgeKind(hop.reason()) != BridgeEvidence.Kind.UNKNOWN) {
                return true;
            }
            if (hop.kind() == HopKind.ENTRY && index.isApplicationOwner(hop.fromOwner())
                    && !index.isApplicationOwner(hop.toOwner())) {
                return true;
            }
        }
        return false;
    }

    private static EntryMatch findApplicationEntry(ApplicationEntryIndex index, Graph graph,
                                                   Chain chain,
                                                   Map<String, EntryMatch> cache,
                                                   Map<String, List<String>> callTargetCache) {
        Set<String> allowedMethods = index.entryForwardMethodKeys();
        EntryMatch typedBinding = findTypedBindingEntry(index, graph, chain, allowedMethods,
                callTargetCache);
        if (typedBinding != null) {
            return typedBinding;
        }
        Set<String> candidates = new TreeSet<>();
        String entryDescriptor = "";
        for (ChainHop hop : chain.hops()) {
            if (hop.kind() == HopKind.ENTRY && hop.desc() != null) {
                entryDescriptor = hop.desc();
                break;
            }
        }
        if (!entryDescriptor.isBlank()) {
            candidates.add(methodKey(chain.entryClass(), chain.entryMethod(), entryDescriptor));
        }
        candidates.addAll(index.applicationEntryMethods(chain.entryClass(), chain.entryMethod()));
        for (ChainHop hop : chain.hops()) {
            candidates.addAll(index.applicationEntryMethods(hop.fromOwner(), hop.fromName()));
            candidates.addAll(index.applicationEntryMethods(hop.toOwner(), hop.toName()));
        }
        String chainEntryKey = entryDescriptor.isBlank()
                ? methodKey(chain.entryClass(), chain.entryMethod(), "")
                : methodKey(chain.entryClass(), chain.entryMethod(), entryDescriptor);
        for (String candidate : candidates) {
            if (index.isApplicationEntryMethod(candidate) && candidate.equals(chainEntryKey)) {
                return new EntryMatch(candidate, chainEntryKey, List.of(candidate), null, false);
            }
        }

        // A source/bridge composer intentionally keeps the application helper as the chain
        // entry.  Recover only a concrete application caller path through graph call edges;
        // no name/package/classpath heuristic is allowed here.  A missing descriptor is not
        // enough to perform this join because overloaded helpers would be ambiguous.
        if (graph == null || entryDescriptor.isBlank()
                || !index.isEntryForwardReachable(chainEntryKey)) {
            return null;
        }
        EntryMatch cached = cache == null ? null : cache.get(chainEntryKey);
        if (cached != null) {
            return cached;
        }
        EntryMatch resolved = null;
        for (String root : index.applicationEntryMethods()) {
            List<String> path = boundedCallPath(graph, root, chainEntryKey, allowedMethods,
                    callTargetCache);
            if (path.isEmpty()) {
                continue;
            }
            EntryMatch candidate = new EntryMatch(root, chainEntryKey, path, null, false);
            if (resolved == null || candidate.applicationEntryKey()
                    .compareTo(resolved.applicationEntryKey()) < 0) {
                resolved = candidate;
            }
        }
        if (cache != null) {
            cache.put(chainEntryKey, resolved == null
                    ? EntryMatch.NOT_FOUND : resolved);
        }
        return resolved == EntryMatch.NOT_FOUND ? null : resolved;
    }

    /**
     * Join a typed deserializer/binder target to the application boundary when the bytecode
     * carries an exact Class literal. Framework binding is often reflective, so a direct CPG
     * edge from the servlet to the eventual setter does not exist; the class-literal fact is
     * the explicit type/value bridge that replaces a name-only heuristic.
     */
    private static EntryMatch findTypedBindingEntry(ApplicationEntryIndex index, Graph graph,
                                                    Chain chain, Set<String> allowedMethods,
                                                    Map<String, List<String>> callTargetCache) {
        if (index == null || chain == null || chain.entryClass() == null
                || chain.entryMethod() == null || !callbackAcceptsValue(chain)) {
            return null;
        }
        List<ApplicationEntryIndex.DeserializeSite> sites = index.typedBindingSitesForTarget(
                chain.entryClass());
        String chainEntryKey = methodKey(chain.entryClass(), chain.entryMethod(),
                entryDescriptor(chain));
        for (ApplicationEntryIndex.DeserializeSite site : sites) {
            String host = site.hostMethodKey();
            if (index.isExternalEntryMethod(host) || index.isApplicationEntryMethod(host)) {
                return new EntryMatch(host, chainEntryKey, List.of(host), site, true);
            }
            if (graph == null || !index.isEntryForwardReachable(host)) {
                continue;
            }
            EntryMatch best = null;
            for (String root : index.applicationEntryMethods()) {
                List<String> path = boundedCallPath(graph, root, host, allowedMethods,
                        callTargetCache);
                if (path.isEmpty()) {
                    continue;
                }
                EntryMatch candidate = new EntryMatch(root, chainEntryKey, path, site, true);
                if (best == null || candidate.path().size() < best.path().size()
                        || candidate.path().size() == best.path().size()
                        && candidate.applicationEntryKey().compareTo(best.applicationEntryKey()) < 0) {
                    best = candidate;
                }
            }
            if (best != null) {
                return best;
            }
        }
        return null;
    }

    private static boolean callbackAcceptsValue(Chain chain) {
        String descriptor = entryDescriptor(chain);
        if (descriptor == null || descriptor.isBlank()) {
            return false;
        }
        try {
            return Descriptor.paramCount(descriptor) > 0;
        } catch (RuntimeException ignored) {
            return false;
        }
    }

    private static boolean isTypedBindingBridge(String bridge) {
        String value = bridge == null ? "" : bridge.toLowerCase(java.util.Locale.ROOT);
        return value.contains("deserialize") || value.contains("bind")
                || value.contains("bean") || value.contains("json")
                || value.contains("yaml") || value.contains("xml");
    }

    private static final int MAX_ENTRY_PREFIX_METHODS = 2_048;
    private static final int MAX_ENTRY_PREFIX_HOPS = 64;

    /** Deterministic, bounded BFS over actual call edges from one application root. */
    private static List<String> boundedCallPath(Graph graph, String root, String target,
                                                Set<String> allowedMethods,
                                                Map<String, List<String>> callTargetCache) {
        if (graph == null || root == null || target == null || root.isBlank() || target.isBlank()) {
            return List.of();
        }
        if (root.equals(target)) {
            return List.of(root);
        }
        Set<String> allowed = allowedMethods == null ? Set.of() : allowedMethods;
        if (!allowed.contains(root) || !allowed.contains(target)) {
            return List.of();
        }
        Map<String, String> predecessor = new HashMap<>();
        ArrayDeque<String> work = new ArrayDeque<>();
        predecessor.put(root, null);
        work.add(root);
        while (!work.isEmpty() && predecessor.size() <= MAX_ENTRY_PREFIX_METHODS) {
            String current = work.removeFirst();
            for (String next : callTargets(graph, current, callTargetCache)) {
                    if (!allowed.contains(next) || predecessor.containsKey(next)) {
                        continue;
                    }
                    predecessor.put(next, current);
                    if (next.equals(target)) {
                        return reconstructPath(predecessor, target);
                    }
                    if (predecessor.size() >= MAX_ENTRY_PREFIX_METHODS) {
                        break;
                    }
                    work.addLast(next);
                }
        }
        return List.of();
    }

    /**
     * Return the deterministic, de-duplicated call targets for one method.  The cache is scoped
     * to one build so graph changes cannot leak across scans; keeping this adjacency separate
     * from the allowed-method filter lets every bounded BFS reuse the same immutable ordering.
     */
    private static List<String> callTargets(Graph graph, String current,
                                            Map<String, List<String>> callTargetCache) {
        if (graph == null || current == null || current.isBlank()) {
            return List.of();
        }
        if (callTargetCache != null) {
            List<String> cached = callTargetCache.get(current);
            if (cached != null) {
                return cached;
            }
        }
        List<Node> calls = new ArrayList<>(graph.callsOfMethod(current));
        calls.sort(Comparator.comparingLong(Node::id));
        List<String> targets = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        for (Node call : calls) {
            List<Edge> callEdges = new ArrayList<>();
            for (Edge edge : call.out()) {
                if (edge != null && isCallEdge(edge)) {
                    callEdges.add(edge);
                }
            }
            callEdges.sort(Comparator.comparing(edge -> methodKey(edge.to().owner(),
                    edge.to().name(), edge.to().descriptor())));
            for (Edge edge : callEdges) {
                String next = methodKey(edge.to().owner(), edge.to().name(),
                        edge.to().descriptor());
                if (seen.add(next)) {
                    targets.add(next);
                }
            }
        }
        List<String> immutable = List.copyOf(targets);
        if (callTargetCache != null) {
            callTargetCache.put(current, immutable);
        }
        return immutable;
    }

    private static List<String> reconstructPath(Map<String, String> predecessor, String target) {
        ArrayList<String> reversed = new ArrayList<>();
        String current = target;
        while (current != null && reversed.size() <= MAX_ENTRY_PREFIX_HOPS) {
            reversed.add(current);
            current = predecessor.get(current);
        }
        if (current != null) {
            return List.of();
        }
        java.util.Collections.reverse(reversed);
        return List.copyOf(reversed);
    }

    private static boolean isCallEdge(Edge edge) {
        return edge.type() == io.just.sast.cpg.graph.EdgeType.INVOKES
                || edge.type() == io.just.sast.cpg.graph.EdgeType.DISPATCHES
                || edge.type() == io.just.sast.cpg.graph.EdgeType.LAMBDA;
    }

    private static ApplicationEntryIndex.DeserializeSite findSite(ApplicationEntryIndex index,
                                                                    String entryKey,
                                                                    Set<String> chainMethods) {
        if (index == null) {
            return null;
        }
        Set<String> members = new TreeSet<>(chainMethods == null ? Set.of() : chainMethods);
        addMember(members, entryKey);
        return members.stream()
                .flatMap(member -> {
                    int separator = member.indexOf('#');
                    if (separator <= 0 || separator == member.length() - 1) {
                        return java.util.stream.Stream.empty();
                    }
                    return index.applicationInputSitesForMember(member.substring(0, separator),
                            member.substring(separator + 1)).stream();
                })
                .min(Comparator.comparingLong(ApplicationEntryIndex.DeserializeSite::callId)
                        .thenComparing(ApplicationEntryIndex.DeserializeSite::hostMethodKey))
                .orElse(null);
    }

    private static void addMember(Set<String> members, String methodKey) {
        if (methodKey != null && !methodKey.isBlank()) {
            members.add(methodIdentity(methodKey));
        }
    }

    /**
     * Build the bounded method-identity set shared by terminal proof and site lookup.
     *
     * <p>The identity intentionally omits descriptors: both consumers index host methods at
     * that granularity, while the terminal descriptor remains checked by the typed impact
     * lookup.  Keeping this set at the decision seam avoids rebuilding the same chain member
     * projection for every admission/evidence consumer.</p>
     */
    private static Set<String> chainMethodIdentities(Chain chain) {
        if (chain == null) {
            return Set.of();
        }
        Set<String> members = new TreeSet<>();
        members.add(methodIdentity(chain.entryClass(), chain.entryMethod()));
        for (ChainHop hop : chain.hops()) {
            if (hop == null) {
                continue;
            }
            members.add(methodIdentity(hop.fromOwner(), hop.fromName()));
            members.add(methodIdentity(hop.toOwner(), hop.toName()));
        }
        return Set.copyOf(members);
    }

    private static EvidenceAtom siteAtom(ApplicationEntryIndex.DeserializeSite site,
                                         String entryKey, Chain chain, EntryMatch match) {
        EvidenceAtom.Kind kind = site == null ? EvidenceAtom.Kind.DESERIALIZATION_SITE
                : siteKind(site.bridge());
        String owner = site == null ? ownerOf(entryKey) : site.owner();
        String member = site == null ? memberOf(entryKey) : site.name() + site.descriptor();
        String evidenceCode = site == null ? "APPLICATION_CALLBACK_ENTRY"
                : match != null && match.typedBinding()
                ? "INDEX_TYPED_BINDING_SITE" : "INDEX_DESERIALIZE_SITE";
        Map<String, String> attributes = new TreeMap<>();
        attributes.put("entry_method", entryKey);
        if (site != null) {
            attributes.put("bridge", site.bridge());
            attributes.put("external_input", Boolean.toString(site.externalInput()));
            // Physical call identity is semantic site identity; a raw chain key is not.
            attributes.put("call_id", Long.toString(site.callId()));
            attributes.put("host_method", site.hostMethodKey());
            if (!site.targetTypes().isEmpty()) {
                attributes.put("target_types", String.join(",", site.targetTypes()));
            }
            if (match != null && match.typedBinding()) {
                attributes.put("join_kind", "TYPED_BINDING_TARGET");
            }
        }
        return EvidenceAtom.of(kind, "UNKNOWN", owner, member, evidenceCode, attributes);
    }

    /**
     * Build a reusable dependency/JDK suffix identity without embedding the application chain
     * key.  The suffix retains every non-application hop and the sink overload/risk, so distinct
     * gadget routes are not collapsed merely because they end at the same API.
     */
    private static GadgetSegmentId dependencySegmentId(ApplicationEntryIndex index,
                                                        Chain chain,
                                                        String dependencyOwner) {
        List<String> suffix = new ArrayList<>();
        boolean dependencyStarted = false;
        for (ChainHop hop : chain.hops()) {
            boolean fromApplication = index.isApplicationOwner(hop.fromOwner());
            boolean toApplication = index.isApplicationOwner(hop.toOwner());
            if (!fromApplication || !toApplication) {
                dependencyStarted = true;
                suffix.add(segmentHopCanonical(hop));
            } else if (dependencyStarted) {
                // Reverse chains are sink -> entry. Once the application-owned prefix starts,
                // later hops belong to that prefix and must not split a reusable suffix.
                break;
            }
        }
        if (suffix.isEmpty()) {
            suffix.add("terminal-only");
        }
        return GadgetSegmentId.fromCanonical("segment-v2", dependencyOwner,
                chain.sinkClass(), chain.sinkMethod(), chain.sinkDescriptor(), chain.sinkRole(),
                chain.sinkRisk().name(), String.join(";", suffix));
    }

    private static String segmentHopCanonical(ChainHop hop) {
        return String.join("|", java.util.Objects.toString(hop.fromOwner(), ""),
                java.util.Objects.toString(hop.fromName(), ""),
                java.util.Objects.toString(hop.toOwner(), ""),
                java.util.Objects.toString(hop.toName(), ""), String.valueOf(hop.kind()),
                java.util.Objects.toString(hop.field(), ""),
                java.util.Objects.toString(hop.desc(), ""),
                java.util.Objects.toString(hop.argOrdinal(), ""),
                java.util.Objects.toString(hop.fieldOwner(), ""));
    }

    private static String dependencyOwner(ApplicationEntryIndex index, Chain chain) {
        boolean crossedBoundary = false;
        for (ChainHop hop : chain.hops()) {
            if (index.isApplicationOwner(hop.fromOwner()) && !index.isApplicationOwner(hop.toOwner())) {
                crossedBoundary = true;
                return hop.toOwner();
            }
            if (!index.isApplicationOwner(hop.fromOwner())) {
                crossedBoundary = true;
                return hop.fromOwner();
            }
            if (!index.isApplicationOwner(hop.toOwner())) {
                crossedBoundary = true;
                return hop.toOwner();
            }
        }
        if (crossedBoundary) {
            return index.isApplicationOwner(chain.sinkClass()) ? null : chain.sinkClass();
        }
        // Some composed chains record the terminal call in the sink fields and keep only an
        // ENTRY hop for the callback method.  The terminal impact index plus
        // chainTouchesTerminal() is the typed proof that a dependency/JDK suffix exists in
        // that representation; do not require a synthetic cross-artifact edge that the CPG
        // cannot express.
        return index.isApplicationOwner(chain.sinkClass()) ? null : chain.sinkClass();
    }

    private static boolean chainTouchesTerminal(ApplicationEntryIndex index, Graph graph,
                                                Chain chain, Set<String> chainMethods) {
        if (chain == null) {
            return false;
        }
        String sinkClass = chain.sinkClass();
        String sinkMethod = chain.sinkMethod();
        String sinkDescriptor = chain.sinkDescriptor();
        for (ChainHop hop : chain.hops()) {
            if (sameMethod(hop.fromOwner(), hop.fromName(), sinkClass, sinkMethod)
                    || sameMethod(hop.toOwner(), hop.toName(), sinkClass, sinkMethod)) {
                if (sinkDescriptor == null || sinkDescriptor.isBlank()
                        || sinkDescriptor.equals(hop.desc())
                        || hop.desc() == null || hop.desc().isBlank()) {
                    return true;
                }
            }
        }
        // Chain construction records the terminal call in the typed sink fields, while the
        // reverse trace may begin at the sink argument and therefore omit a separate terminal
        // hop.  Accept that representation only when the indexed terminal call's host method
        // is present in the actual chain and the graph still contains the call node.  This
        // prevents a sink name alone from satisfying the complete-terminal requirement.
        if (index == null || graph == null) {
            return false;
        }
        Set<String> members = chainMethods == null ? Set.of() : chainMethods;
        return index.terminalImpactsFor(sinkClass, sinkMethod, sinkDescriptor).stream()
                .anyMatch(impact -> {
            if (!impact.terminal()) {
                return false;
            }
            boolean sinkMatches = impact.owner().equals(sinkClass)
                    && impact.name().equals(sinkMethod)
                    && (sinkDescriptor == null || sinkDescriptor.isBlank()
                    || impact.descriptor().equals(sinkDescriptor));
            if (!sinkMatches || !members.contains(methodIdentity(impact.hostMethodKey()))) {
                return false;
            }
            long callId = impact.callId();
            return callId >= 0 && callId < graph.nodeCount() && graph.node(callId) != null;
        });
    }

    private static String entryDescriptor(Chain chain) {
        if (chain == null) return "";
        for (ChainHop hop : chain.hops()) {
            if (hop.kind() == HopKind.ENTRY && hop.desc() != null && !hop.desc().isBlank()) {
                return hop.desc();
            }
        }
        return "";
    }

    private static boolean sameMethod(String owner, String name, String expectedOwner,
                                      String expectedName) {
        return expectedOwner != null && expectedOwner.equals(owner)
                && expectedName != null && expectedName.equals(name);
    }

    private static EntryChainJoinEvidence.ValueFlow valueFlow(Chain chain, EntryMatch entryMatch) {
        // A graph-only caller prefix proves control reachability, not that the exact external
        // value survives parameter/field conversion.  Keep the axis UNKNOWN until a typed
        // value-flow fact or protocol bridge establishes that relation.
        if (entryMatch != null && entryMatch.typedBinding()) {
            return EntryChainJoinEvidence.ValueFlow.CALLBACK_ARGUMENT;
        }
        if (entryMatch != null && entryMatch.path() != null && entryMatch.path().size() > 1) {
            return EntryChainJoinEvidence.ValueFlow.UNKNOWN;
        }
        for (ChainHop hop : chain.hops()) {
            String reason = hop.reason() == null ? ""
                    : hop.reason().toLowerCase(java.util.Locale.ROOT);
            if (reason.contains("jndi") || reason.contains("rmi") || reason.contains("jdbc")
                    || reason.contains("second") || reason.contains("deserialize")) {
                return EntryChainJoinEvidence.ValueFlow.PROTOCOL_REPLY;
            }
            if (hop.kind() == HopKind.FIELD_FLOW) {
                return EntryChainJoinEvidence.ValueFlow.DERIVED_VALUE;
            }
        }
        return EntryChainJoinEvidence.ValueFlow.DIRECT_VALUE;
    }

    private static String methodIdentity(String owner, String name) {
        return (owner == null ? "" : owner) + "#" + (name == null ? "" : name);
    }

    private static String methodIdentity(String canonicalMethodKey) {
        int separator = canonicalMethodKey == null ? -1 : canonicalMethodKey.indexOf('#');
        if (separator <= 0) {
            return canonicalMethodKey == null ? "" : canonicalMethodKey;
        }
        String member = canonicalMethodKey.substring(separator + 1);
        int descriptor = member.indexOf('(');
        return canonicalMethodKey.substring(0, separator) + "#"
                + (descriptor < 0 ? member : member.substring(0, descriptor));
    }

    private static EntryChainJoinEvidence.CallbackSemantics callbackSemantics(
            Chain chain, ApplicationEntryIndex.DeserializeSite site) {
        if (site != null && site.bridge() != null && !site.bridge().isBlank()) {
            String bridge = site.bridge().toLowerCase(java.util.Locale.ROOT);
            if (bridge.contains("reflect")) return EntryChainJoinEvidence.CallbackSemantics.REFLECTION_DISPATCH;
            if (bridge.contains("lookup") || bridge.contains("rmi") || bridge.contains("jdbc")) {
                return EntryChainJoinEvidence.CallbackSemantics.PROTOCOL_REENTRY;
            }
            return EntryChainJoinEvidence.CallbackSemantics.DESERIALIZATION;
        }
        if (chain.entryKind() != null && chain.entryKind().toLowerCase(java.util.Locale.ROOT)
                .contains("read")) {
            return EntryChainJoinEvidence.CallbackSemantics.DESERIALIZATION;
        }
        return EntryChainJoinEvidence.CallbackSemantics.FRAMEWORK_LIFECYCLE;
    }

    private static EvidenceAtom.Kind siteKind(String bridge) {
        String value = bridge == null ? "" : bridge.toLowerCase(java.util.Locale.ROOT);
        if (value.contains("lookup") || value.contains("jdbc") || value.contains("jndi")) {
            return EvidenceAtom.Kind.LOOKUP_SITE;
        }
        if (value.contains("config")) return EvidenceAtom.Kind.CONFIG_SITE;
        if (value.contains("bind") || value.contains("bean")) return EvidenceAtom.Kind.BINDING_SITE;
        return EvidenceAtom.Kind.DESERIALIZATION_SITE;
    }

    private static BridgeEvidence.Kind bridgeKind(String reason) {
        String value = reason == null ? "" : reason.toLowerCase(java.util.Locale.ROOT);
        if (value.contains("jndi") || value.contains("rmi") || value.contains("lookup")) {
            return BridgeEvidence.Kind.JNDI_RMI;
        }
        if (value.contains("jdbc") || value.contains("driver")) return BridgeEvidence.Kind.JDBC_DRIVER;
        if (value.contains("second") || value.contains("remote") || value.contains("response")
                || value.contains("bridge-source-deserialize")) {
            return BridgeEvidence.Kind.SECOND_DESERIALIZATION;
        }
        if (value.contains("reflect")) return BridgeEvidence.Kind.REFLECTION;
        return BridgeEvidence.Kind.UNKNOWN;
    }

    private static FindingState.Risk risk(SinkRisk sinkRisk) {
        return switch (sinkRisk) {
            case SAFE_CALLABLE -> FindingState.Risk.LOW;
            case CONTROLLED_EFFECT -> FindingState.Risk.MEDIUM;
            case HIGH_RISK_TERMINAL -> FindingState.Risk.HIGH;
        };
    }

    private static String applicationDigest(Blackboard blackboard) {
        return "UNKNOWN";
    }

    private static void addNodes(Map<String, EvidenceNode> nodes, List<EvidenceNode> additions) {
        for (EvidenceNode node : additions) {
            nodes.putIfAbsent(node.id(), node);
        }
    }

    private static List<EvidenceEdge> dedupeEdges(List<EvidenceEdge> edges) {
        Map<String, EvidenceEdge> unique = new TreeMap<>();
        for (EvidenceEdge edge : edges) {
            if (edge != null) unique.putIfAbsent(edge.id(), edge);
        }
        return List.copyOf(unique.values());
    }

    private static String methodKey(String owner, String name, String descriptor) {
        return owner + "#" + name + (descriptor == null ? "" : descriptor);
    }

    private static String ownerOf(String key) {
        int separator = key == null ? -1 : key.indexOf('#');
        return separator <= 0 ? "" : key.substring(0, separator);
    }

    private static String memberOf(String key) {
        int separator = key == null ? -1 : key.indexOf('#');
        return separator < 0 ? "" : key.substring(separator + 1);
    }

    private record Decision(String reason, EntryChainJoinEvidence join, FindingState state,
                            List<EvidenceNode> nodes, List<EvidenceEdge> edges) {
        static Decision rejected(String reason) {
            return new Decision(reason, null, null, List.of(), List.of());
        }
    }

    private record EntryMatch(String applicationEntryKey, String chainEntryKey,
                              List<String> path,
                              ApplicationEntryIndex.DeserializeSite bindingSite,
                              boolean typedBinding) {
        private static final EntryMatch NOT_FOUND = new EntryMatch("", "", List.of(), null, false);

        private EntryMatch {
            applicationEntryKey = applicationEntryKey == null ? "" : applicationEntryKey;
            chainEntryKey = chainEntryKey == null ? "" : chainEntryKey;
            path = path == null ? List.of() : List.copyOf(path);
        }
    }
}
