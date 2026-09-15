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
import io.just.sast.blackboard.ObjectGraphPlan;
import io.just.sast.blackboard.SinkRisk;
import io.just.sast.cpg.graph.Graph;
import io.just.sast.cpg.graph.Edge;
import io.just.sast.cpg.graph.Node;
import io.just.sast.cpg.graph.NodeType;
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
import java.util.function.Predicate;

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
    private static final String JACKSON_MAPPER = "com/fasterxml/jackson/databind/ObjectMapper";
    private static final String JNDI_INITIAL_CONTEXT = "javax/naming/InitialContext";
    private static final String JNDI_CONTEXT = "javax/naming/Context";
    private static final String JNDI_PREFIX = "javax/naming/";
    private static final String SPRING_JNDI_PREFIX = "org/springframework/jndi/";
    private static final String EVENT_LISTENER_LIST = "javax/swing/event/EventListenerList";
    private static final String UNDO_MANAGER = "javax/swing/undo/UndoManager";
    private static final String VECTOR = "java/util/Vector";
    private static final String JACKSON_POJONODE = "com/fasterxml/jackson/databind/node/POJONode";
    private static final String SPRING_AOP_PROXY =
            "org/springframework/aop/framework/JdkDynamicAopProxy";
    private static final String TEMPLATES = "javax/xml/transform/Templates";
    private static final String TEMPLATES_IMPL =
            "com/sun/org/apache/xalan/internal/xsltc/trax/TemplatesImpl";
    private static final String JDBC_CONNECT_DESCRIPTOR =
            "(Ljava/lang/String;Ljava/util/Properties;)Ljava/sql/Connection;";
    private static final String JDBC_LOAD_CLASS_DESCRIPTOR =
            "(Ljava/lang/String;)Ljava/lang/Class;";
    private static final String JDBC_CLASS_NEW_INSTANCE_DESCRIPTOR =
            "()Ljava/lang/Object;";
    private static final String JDBC_INIT_CONFIG_DESCRIPTOR =
            "(Ljava/util/Properties;)Ljava/util/Properties;";
    private static final String JDBC_LOAD_CONFIG_DESCRIPTOR =
            "(Ljava/lang/String;Ljava/util/Properties;)Ljava/util/Properties;";
    private static final String JDBC_SOCKET_FACTORY_DESCRIPTOR =
            "(Ljava/util/Properties;)Ljavax/net/SocketFactory;";
    private static final String JDBC_UNTYPED_FACTORY_DESCRIPTOR =
            "(Ljava/lang/String;Ljava/util/Properties;ZLjava/lang/String;)Ljava/lang/Object;";
    private static final String JDBC_TYPED_FACTORY_DESCRIPTOR_PREFIX =
            "(Ljava/lang/Class;Ljava/lang/String;Ljava/util/Properties;";
    private static final int MAX_JDBC_REACHABLE_METHODS = 4_096;

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
                    candidateAdmission(index, graph, chain);
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
            ApplicationEntryIndex index, Graph graph, Chain chain) {
        if (chain == null) {
            return new ApplicationEntryIndex.CandidateAdmissionDecision(
                    ApplicationEntryIndex.CandidateAdmissionStatus.APPLICATION_ENTRY_NOT_IN_CHAIN,
                    "", "", "", "", false, false, false);
        }
        String descriptor = entryDescriptor(graph, chain);
        boolean continuation = hasSemanticContinuation(index, chain);
        return index.candidateAdmission(chain.entryClass(), chain.entryMethod(), descriptor,
                chain.sinkClass(), chain.sinkMethod(), chain.sinkDescriptor(), continuation,
                isDeclaredJdbcXmlChain(chain));
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
        boolean frameworkService = index.isFrameworkServiceMethod(entryKey);
        if (frameworkService && !index.isRegisteredServiceMethod(entryKey)) {
            return Decision.rejected("SERVICE_ENDPOINT_NOT_REGISTERED");
        }
        if (frameworkService && index.hasApplicationObjectInputStreamSite(entryKey)
                && !index.hasSecondaryDeserializationHop(chain.hops())) {
            return Decision.rejected("SECOND_DESERIALIZATION_NOT_IN_CHAIN");
        }
        Set<String> chainMethods = chainMethodIdentities(chain);
        boolean declaredJdbcTerminal = isDeclaredJdbcXmlChain(chain);
        ApplicationEntryIndex.TerminalDecision terminalDecision = index.terminalAdmission(
                chain.sinkClass(), chain.sinkMethod(), chain.sinkDescriptor());
        if (terminalDecision.status() == ApplicationEntryIndex.TerminalStatus.INTERMEDIATE_ONLY
                || (!terminalDecision.admitted() && !declaredJdbcTerminal)) {
            return Decision.rejected(terminalDecision.reasonCode());
        }
        String terminalHostKey = terminalDecision.hostMethodKey();
        boolean continuationEvidence = entryMatch.typedBinding()
                || hasSemanticContinuation(index, chain);
        if (!declaredJdbcTerminal) {
            ApplicationEntryIndex.DemandDecision demand = index.demandAdmission(entryKey,
                    terminalHostKey, continuationEvidence);
            if (!demand.admitted()) {
                return Decision.rejected(demand.reasonCode());
            }
        } else if (!index.isApplicationEntryMethod(entryKey)
                && !index.isEntryForwardReachable(entryKey)) {
            return Decision.rejected("ENTRY_NOT_FORWARD_REACHABLE");
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
        entryAttributes.put("entry_join_kind", entryMatch.typedBinding()
                ? "TYPED_BINDING_TARGET"
                : entryMatch.path().size() > 1
                ? "CALL_GRAPH_PREFIX" : "DIRECT_APPLICATION_ENTRY");
        if (!entryMatch.path().isEmpty()) {
            // The path is a bounded list of canonical method keys, not a renderer note.  It is
            // part of the atom identity so a changed call prefix cannot reuse an old join ID.
            entryAttributes.put("entry_prefix_path", String.join("->", entryMatch.path()));
        }
        List<ApplicationEntryIndex.ServiceEndpoint> serviceEndpoints =
                index.serviceEndpointsFor(entryKey);
        EntryChainJoinEvidence.FilterDominance filterDominance =
                index.filterDominanceFor(entryKey);
        if (!serviceEndpoints.isEmpty()) {
            ApplicationEntryIndex.ServiceEndpoint endpoint = serviceEndpoints.get(0);
            entryAttributes.put("service_protocol", endpoint.protocol());
            entryAttributes.put("service_publish_path", endpoint.publishPath());
            entryAttributes.put("service_configuration_method",
                    endpoint.configurationMethodKey());
            entryAttributes.put("service_registration", "EndpointImpl.publish");
            entryAttributes.put("filter_dominance", filterDominance.name());
            entryAttributes.put("filter_control_count",
                    Integer.toString(index.filterControls().size()));
        }
        ApplicationEntryIndex.DeserializeSite site = entryMatch.bindingSite() != null
                ? entryMatch.bindingSite() : findSite(index, entryKey, chainMethods);
        if (declaredJdbcTerminal) {
            // Generic accepted-prefix binding may select an application class that is not the
            // JDBC request DTO.  The JDBC proof needs the exact Jackson call in the composed
            // application's own host method, not an unrelated framework binding site.
            site = jdbcApplicationSite(index, chain, site);
        }
        BridgeProfile bridgeProfile = bridgeProfile(chain, site, graph);
        if (bridgeProfile.composedJndi() && bridgeProfile.jacksonBinding()
                && !bridgeProfile.remoteReply()) {
            return Decision.rejected("RMI_REPLY_NOT_PROVEN");
        }
        if (bridgeProfile.jdbcConfiguration() && !bridgeProfile.jdbcComplete()) {
            return Decision.rejected("JDBC_XML_BRIDGE_NOT_PROVEN");
        }
        if (entryMatch.typedBinding()) {
            entryAttributes.put("binding_target_type", chain.entryClass());
            entryAttributes.put("binding_site_call_id", Long.toString(site.callId()));
            entryAttributes.put("binding_site_host", site.hostMethodKey());
        }
        addBridgeProfileAttributes(entryAttributes, bridgeProfile);
        EvidenceAtom entry = EvidenceAtom.of(EvidenceAtom.Kind.APPLICATION_ENTRY, "UNKNOWN",
                ownerOf(entryKey), memberOf(entryKey), entryMatch.path().isEmpty()
                        ? "INDEX_APPLICATION_ENTRY" : entryMatch.typedBinding()
                        ? "INDEX_TYPED_BINDING_ENTRY" : "INDEX_APPLICATION_CALL_PREFIX",
                entryAttributes);
        EvidenceAtom siteAtom = siteAtom(site, entryKey, chain, entryMatch, bridgeProfile);
        GadgetSegmentId segmentId = dependencySegmentId(index, chain, dependencyOwner);
        Map<String, String> dependencyAttributes = new TreeMap<>();
        dependencyAttributes.put("segment_id", segmentId.value());
        dependencyAttributes.put("sink", chain.sinkClass() + "#" + chain.sinkMethod());
        dependencyAttributes.put("descriptor", chain.sinkDescriptor());
        addBridgeProfileAttributes(dependencyAttributes, bridgeProfile);
        EvidenceAtom dependency = EvidenceAtom.of(EvidenceAtom.Kind.DEPENDENCY_SEGMENT,
                "UNKNOWN", dependencyOwner, chain.sinkMethod(), "CHAIN_DEPENDENCY_SUFFIX",
                dependencyAttributes);
        EvidenceAtom terminal = EvidenceAtom.of(EvidenceAtom.Kind.TERMINAL_IMPACT, "UNKNOWN",
                chain.sinkClass(), chain.sinkMethod(), declaredJdbcTerminal
                        ? "DECLARED_CLASS_DEFINITION_BOUNDARY" : "INDEX_TERMINAL_IMPACT",
                Map.of("descriptor", chain.sinkDescriptor(), "risk", chain.sinkRisk().name()));

        ApplicationChainId chainId = ApplicationChainId.fromCanonical("chain", chain.key());
        EntryChainJoinEvidence.ValueFlow flow = valueFlow(chain, entryMatch, bridgeProfile);
        EntryChainJoinEvidence.ObjectIdentity identity = flow == EntryChainJoinEvidence.ValueFlow.PROTOCOL_REPLY
                ? EntryChainJoinEvidence.ObjectIdentity.SERIALIZED_ROUND_TRIP
                : flow == EntryChainJoinEvidence.ValueFlow.DIRECT_VALUE
                ? EntryChainJoinEvidence.ObjectIdentity.SAME_OBJECT
                : EntryChainJoinEvidence.ObjectIdentity.DERIVED_OBJECT;
        EntryChainJoinEvidence.CallbackSemantics callback = callbackSemantics(chain, site,
                bridgeProfile);
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
            // The first ObjectInputStream/source boundary is the site itself, not a second
            // protocol bridge.  The secondary bridge below is emitted only from the indexed
            // tainted source hop, so a generic "deserialize" label cannot self-promote into a
            // nested-deserialization claim.
            if (kind != BridgeEvidence.Kind.UNKNOWN
                    && !"builtin:ois-read".equals(site.ruleId())
                    && !"deserialize".equalsIgnoreCase(site.bridge())) {
                addBridge(bridges, kind, siteAtom.id(), terminal.id(), site.bridge());
            }
        }
        if (!serviceEndpoints.isEmpty()) {
            ApplicationEntryIndex.ServiceEndpoint endpoint = serviceEndpoints.get(0);
            addBridge(bridges, BridgeEvidence.Kind.CONFIGURATION, siteAtom.id(), terminal.id(),
                    endpoint.protocol() + ":" + endpoint.publishPath());
        }
        if (index.hasSecondaryDeserializationHop(chain.hops())) {
            addBridge(bridges, BridgeEvidence.Kind.SECOND_DESERIALIZATION, siteAtom.id(),
                    terminal.id(), "secondary-deserialization");
        }
        for (ChainHop hop : chain.hops()) {
            if (hop.reason() == null || !hop.reason().startsWith("bridge-")) {
                continue;
            }
            BridgeEvidence.Kind kind = "bridge-jdbc_xml".equals(hop.reason())
                    ? BridgeEvidence.Kind.CONFIGURATION : bridgeKind(hop.reason());
            // Source/callback markers describe the first deserialization boundary and the
            // callback dispatch that follows it; neither is a second protocol bridge. Keep
            // them in the chain hops, but do not turn an UNKNOWN marker into typed evidence.
            if (kind == BridgeEvidence.Kind.UNKNOWN) {
                continue;
            }
            addBridge(bridges, kind, siteAtom.id(), terminal.id(),
                    hop.reason());
        }
        if (bridgeProfile.jdbcComplete()) {
            addBridge(bridges, BridgeEvidence.Kind.JDBC_DRIVER, siteAtom.id(), terminal.id(),
                    "JDBC_DRIVER_CONCRETE_DISPATCH");
            addBridge(bridges, BridgeEvidence.Kind.CONFIGURATION, siteAtom.id(), terminal.id(),
                    "JDBC_XML_FILE_CONTEXT_CLASS_DEFINITION");
        }
        // A composed JNDI/RMI hop is the transport boundary.  The returned serialized object
        // is a second, typed evidence edge only when the same chain also carries the Jackson
        // target binding and the complete declarative callback shape.  This keeps lookup-only
        // and isolated fragment candidates from becoming an application reply finding.
        if (bridgeProfile.remoteReply()) {
            addBridge(bridges, BridgeEvidence.Kind.REMOTE_RESPONSE_DESERIALIZATION,
                    siteAtom.id(), terminal.id(), "RMI_SERIALIZED_REPLY");
        }
        List<String> bridgeIds = bridges.stream().map(BridgeEvidence::id).sorted().toList();
        EntryChainJoinEvidence join = EntryChainJoinEvidence.of(chainId, entry.id(), siteAtom.id(),
                segmentId, flow, identity, callback, runtimeType, compatibility,
                filterDominance, construction, bridgeIds);
        FindingState state = new FindingState(
                index.isExternalEntryMethod(entryKey) ? FindingState.EntryStatus.EXTERNAL_ENTRY
                        : FindingState.EntryStatus.APPLICATION_ENTRY,
                chain.unresolvedHops() == 0 && (terminalDecision.admitted() || declaredJdbcTerminal)
                        ? FindingState.ChainProgress.IMPACT_CHAIN_COMPLETE
                        : FindingState.ChainProgress.DEPENDENCY_JOINED,
                construction == EntryChainJoinEvidence.ConstructionConstraint.SAT
                        ? FindingState.Feasibility.SAT : FindingState.Feasibility.UNKNOWN,
                chain.unresolvedHops() == 0 ? FindingState.Completeness.COMPLETE
                        : FindingState.Completeness.PARTIAL,
                risk(chain.sinkRisk()));

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

    private static void addBridge(List<BridgeEvidence> bridges, BridgeEvidence.Kind kind,
                                  String fromAtomId, String toAtomId, String protocol) {
        if (kind == null || protocol == null || protocol.isBlank()) {
            return;
        }
        boolean present = bridges.stream().anyMatch(existing -> existing.kind() == kind
                && existing.fromAtomId().equals(fromAtomId)
                && existing.toAtomId().equals(toAtomId)
                && existing.protocol().equals(protocol));
        if (!present) {
            bridges.add(BridgeEvidence.of(kind, fromAtomId, toAtomId, protocol,
                    BridgeEvidence.Status.PARTIAL));
        }
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
            if (bridgeKind(hop.reason()) != BridgeEvidence.Kind.UNKNOWN
                    || isSourceDeserializeMarker(hop.reason())) {
                return true;
            }
            if (hop.kind() == HopKind.ENTRY && index.isApplicationOwner(hop.fromOwner())
                    && !index.isApplicationOwner(hop.toOwner())) {
                return true;
            }
        }
        return false;
    }

    private static boolean isSourceDeserializeMarker(String reason) {
        return reason != null && ("bridge-source-deserialize".equals(reason)
                || reason.startsWith("bridge-source-"));
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
        String entryDescriptor = entryDescriptor(graph, chain);
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
                || chain.entryMethod() == null || !callbackAcceptsValue(graph, chain)) {
            return null;
        }
        List<ApplicationEntryIndex.DeserializeSite> sites = index.typedBindingSitesForTarget(
                chain.entryClass());
        String chainEntryKey = methodKey(chain.entryClass(), chain.entryMethod(),
                entryDescriptor(graph, chain));
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

    private static boolean callbackAcceptsValue(Graph graph, Chain chain) {
        String descriptor = entryDescriptor(graph, chain);
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

    /** Resolve the exact Jackson binding site carried by the application-side JDBC host. */
    private static ApplicationEntryIndex.DeserializeSite jdbcApplicationSite(
            ApplicationEntryIndex index, Chain chain,
            ApplicationEntryIndex.DeserializeSite preferred) {
        if (index == null || chain == null) {
            return null;
        }
        String host = methodKey(chain.entryClass(), chain.entryMethod(), entryDescriptor(chain));
        if (preferred != null && host.equals(preferred.hostMethodKey())
                && JACKSON_MAPPER.equals(preferred.owner())
                && "readValue".equals(preferred.name())
                && "(Ljava/lang/String;Ljava/lang/Class;)Ljava/lang/Object;"
                .equals(preferred.descriptor()) && !preferred.targetTypes().isEmpty()) {
            return preferred;
        }
        return index.applicationInputSites().stream()
                .filter(site -> host.equals(site.hostMethodKey()))
                .filter(site -> JACKSON_MAPPER.equals(site.owner()))
                .filter(site -> "readValue".equals(site.name()))
                .filter(site -> "(Ljava/lang/String;Ljava/lang/Class;)Ljava/lang/Object;"
                        .equals(site.descriptor()))
                .filter(site -> !site.targetTypes().isEmpty())
                .findFirst().orElse(null);
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
                                         String entryKey, Chain chain, EntryMatch match,
                                         BridgeProfile bridgeProfile) {
        EvidenceAtom.Kind kind = site == null ? EvidenceAtom.Kind.DESERIALIZATION_SITE
                : siteKind(site.bridge(), match != null && match.typedBinding());
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
        addBridgeProfileAttributes(attributes, bridgeProfile);
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

    private static String entryDescriptor(Graph graph, Chain chain) {
        if (chain == null) return "";
        String descriptor = entryDescriptor(chain);
        if (!descriptor.isBlank()) {
            return descriptor;
        }
        return ApplicationEntryIndex.uniqueMethodDescriptor(graph, chain.entryClass(),
                chain.entryMethod());
    }

    private static String entryDescriptor(Chain chain) {
        if (chain == null) {
            return "";
        }
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

    private static EntryChainJoinEvidence.ValueFlow valueFlow(Chain chain, EntryMatch entryMatch,
                                                              BridgeProfile bridgeProfile) {
        // A graph-only caller prefix proves control reachability, not that the exact external
        // value survives parameter/field conversion.  Keep the axis UNKNOWN until a typed
        // value-flow fact or protocol bridge establishes that relation.
        if (bridgeProfile.remoteReply()) {
            return EntryChainJoinEvidence.ValueFlow.PROTOCOL_REPLY;
        }
        if (bridgeProfile.jdbcComplete()) {
            return EntryChainJoinEvidence.ValueFlow.DERIVED_VALUE;
        }
        if (entryMatch != null && entryMatch.typedBinding()) {
            return EntryChainJoinEvidence.ValueFlow.CALLBACK_ARGUMENT;
        }
        if (entryMatch != null && entryMatch.path() != null && entryMatch.path().size() > 1) {
            return EntryChainJoinEvidence.ValueFlow.UNKNOWN;
        }
        for (ChainHop hop : chain.hops()) {
            BridgeEvidence.Kind kind = bridgeKind(hop.reason());
            if (kind == BridgeEvidence.Kind.REMOTE_RESPONSE_DESERIALIZATION
                    || kind == BridgeEvidence.Kind.SECOND_DESERIALIZATION) {
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
            Chain chain, ApplicationEntryIndex.DeserializeSite site,
            BridgeProfile bridgeProfile) {
        if (bridgeProfile.remoteReply()) {
            return EntryChainJoinEvidence.CallbackSemantics.PROTOCOL_REENTRY;
        }
        if (bridgeProfile.jdbcComplete()) {
            return EntryChainJoinEvidence.CallbackSemantics.PROTOCOL_REENTRY;
        }
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

    private static EvidenceAtom.Kind siteKind(String bridge, boolean typedBinding) {
        String value = bridge == null ? "" : bridge.toLowerCase(java.util.Locale.ROOT);
        if (value.contains("lookup") || value.contains("jdbc") || value.contains("jndi")) {
            return EvidenceAtom.Kind.LOOKUP_SITE;
        }
        if (typedBinding) return EvidenceAtom.Kind.BINDING_SITE;
        if (value.contains("config")) return EvidenceAtom.Kind.CONFIG_SITE;
        if (value.contains("bind") || value.contains("bean")) return EvidenceAtom.Kind.BINDING_SITE;
        return EvidenceAtom.Kind.DESERIALIZATION_SITE;
    }

    private static BridgeEvidence.Kind bridgeKind(String reason) {
        String value = reason == null ? "" : reason.toLowerCase(java.util.Locale.ROOT);
        if ((value.contains("rmi") && value.contains("response"))
                || value.contains("remote-response")
                || value.contains("response-deserialization")
                || value.contains("serialized-reply")) {
            return BridgeEvidence.Kind.REMOTE_RESPONSE_DESERIALIZATION;
        }
        if (value.contains("jndi") || value.contains("rmi") || value.contains("lookup")) {
            return BridgeEvidence.Kind.JNDI_RMI;
        }
        if (value.contains("jdbc") || value.contains("driver")) return BridgeEvidence.Kind.JDBC_DRIVER;
        if ("bridge-deser".equals(value)
                || "secondary-deserialization".equals(value)
                || value.startsWith("bridge-second-deserialization")) {
            return BridgeEvidence.Kind.SECOND_DESERIALIZATION;
        }
        if (value.contains("reflect") || value.contains("invoke")) {
            return BridgeEvidence.Kind.REFLECTION;
        }
        return BridgeEvidence.Kind.UNKNOWN;
    }

    /**
     * Typed cross-stage facts for the Jackson/JNDI/RMI/object-graph shape.  The profile is
     * deliberately derived from an indexed binding site, an explicit composition marker and
     * the declarative plan/path itself; it never uses the application name, artifact path or
     * a free-form report note as a bridge substitute.
     */
    private static BridgeProfile bridgeProfile(Chain chain,
                                               ApplicationEntryIndex.DeserializeSite site,
                                               Graph graph) {
        boolean jacksonBinding = site != null && JACKSON_MAPPER.equals(site.owner())
                && "readValue".equals(site.name())
                && "deserialize".equalsIgnoreCase(site.bridge())
                && !site.targetTypes().isEmpty();
        boolean jndiLookup = hasJndiLookup(chain);
        boolean composedJndi = hasReason(chain, "bridge-jndi_rmi");
        boolean declaredObjectGraph = hasDeclaredObjectGraph(chain);
        boolean explicitResponse = hasExplicitResponseBridge(chain);
        boolean remoteReply = jndiLookup && (explicitResponse
                || composedJndi && jacksonBinding && declaredObjectGraph);
        boolean jdbcConfiguration = isDeclaredJdbcXmlChain(chain);
        JdbcApplicationProof applicationProof = jdbcConfiguration
                ? jdbcApplicationProof(graph, site) : JdbcApplicationProof.missing();
        JdbcDriverProof driverProof = jdbcConfiguration && applicationProof.sequence()
                ? jdbcDriverProof(graph, applicationProof.hostMethodKey())
                : JdbcDriverProof.missing();
        return new BridgeProfile(jacksonBinding, jndiLookup, composedJndi,
                declaredObjectGraph, remoteReply, jdbcConfiguration,
                applicationProof.sequence(), driverProof.configuration(),
                driverProof.driverOwners());
    }

    private static boolean hasReason(Chain chain, String expected) {
        if (chain == null || expected == null || expected.isBlank()) {
            return false;
        }
        return chain.hops().stream().anyMatch(hop -> hop != null && expected.equals(hop.reason()));
    }

    private static boolean hasExplicitResponseBridge(Chain chain) {
        if (chain == null) {
            return false;
        }
        return chain.hops().stream().anyMatch(hop ->
                bridgeKind(hop == null ? null : hop.reason())
                        == BridgeEvidence.Kind.REMOTE_RESPONSE_DESERIALIZATION);
    }

    private static boolean hasJndiLookup(Chain chain) {
        if (chain == null) {
            return false;
        }
        return chain.hops().stream().anyMatch(hop -> hop != null
                && (isJndiLookupMethod(hop.fromOwner(), hop.fromName())
                || isJndiLookupMethod(hop.toOwner(), hop.toName())));
    }

    private static boolean isJndiLookupMethod(String owner, String name) {
        if (!"lookup".equals(name) || owner == null || owner.isBlank()) {
            return false;
        }
        return JNDI_INITIAL_CONTEXT.equals(owner) || JNDI_CONTEXT.equals(owner)
                || owner.startsWith(JNDI_PREFIX) || owner.startsWith(SPRING_JNDI_PREFIX);
    }

    /** Validate the known callback shape without constructing or loading any target object. */
    private static boolean hasDeclaredObjectGraph(Chain chain) {
        if (chain == null || chain.constructionPlan() == null
                || !chain.constructionPlan().shapeSummary().valid()) {
            return false;
        }
        ObjectGraphPlan plan = chain.constructionPlan();
        Set<String> types = new HashSet<>();
        boolean reflectiveProxy = false;
        for (ObjectGraphPlan.Node node : plan.nodes()) {
            if (node == null) {
                continue;
            }
            types.add(node.type());
            reflectiveProxy |= node.kind() == ObjectGraphPlan.NodeKind.REFLECTIVE_PROXY
                    && TEMPLATES.equals(node.type());
        }
        if (!(types.contains(EVENT_LISTENER_LIST) && types.contains(UNDO_MANAGER)
                && types.contains(VECTOR) && types.contains(JACKSON_POJONODE)
                && types.contains(TEMPLATES) && types.contains(TEMPLATES_IMPL)
                && reflectiveProxy)) {
            return false;
        }
        return hasHop(chain, EVENT_LISTENER_LIST, "toString", UNDO_MANAGER, "toString")
                && hasHop(chain, UNDO_MANAGER, "toString", VECTOR, "toString")
                && hasHop(chain, VECTOR, "toString", JACKSON_POJONODE, "toString")
                && hasHop(chain, JACKSON_POJONODE, "toString", SPRING_AOP_PROXY, "invoke")
                && hasHop(chain, SPRING_AOP_PROXY, "invoke", TEMPLATES, "getOutputProperties")
                && hasHop(chain, TEMPLATES, "getOutputProperties", TEMPLATES_IMPL,
                "newTransformer");
    }

    private static boolean hasHop(Chain chain, String fromOwner, String fromName,
                                  String toOwner, String toName) {
        return chain != null && chain.hops().stream().anyMatch(hop -> hop != null
                && fromOwner.equals(hop.fromOwner()) && fromName.equals(hop.fromName())
                && toOwner.equals(hop.toOwner()) && toName.equals(hop.toName()));
    }

    /** Exact declarative JDBC/XML boundary, including the shape plan and static API hops. */
    private static boolean isDeclaredJdbcXmlChain(Chain chain) {
        if (chain == null || !"java/lang/ClassLoader".equals(chain.sinkClass())
                || !"defineClass".equals(chain.sinkMethod())
                || !"([BII)Ljava/lang/Class;".equals(chain.sinkDescriptor())
                || !chain.terminalSink()
                || chain.constructionPlan() == null
                || !chain.constructionPlan().shapeSummary().valid()) {
            return false;
        }
        String xmlContext = "org/springframework/context/support/FileSystemXmlApplicationContext";
        boolean fragment = "jdbcConfiguration".equals(chain.entryKind())
                && xmlContext.equals(chain.entryClass())
                && "<init>".equals(chain.entryMethod())
                && "(Ljava/lang/String;)V".equals(entryDescriptor(chain));
        boolean composed = !fragment
                && hasReason(chain, "bridge-jdbc_xml")
                && hasHop(chain, "java/sql/Driver", "connect", xmlContext, "<init>");
        if (!fragment && !composed) {
            return false;
        }
        boolean activated = chain.hops().stream().anyMatch(hop -> hop != null
                && "fragment-activation-jdbc".equals(hop.reason()));
        if (!activated) {
            return false;
        }
        Set<String> types = new HashSet<>();
        chain.constructionPlan().nodes().forEach(node -> {
            if (node != null) {
                types.add(node.type());
            }
        });
        return types.contains(xmlContext)
                && types.contains("org/springframework/beans/factory/config/MethodInvokingFactoryBean")
                && types.contains("javax/management/loading/MLet")
                && hasHop(chain, xmlContext, "<init>",
                "org/springframework/beans/factory/config/MethodInvokingFactoryBean",
                "afterPropertiesSet")
                && hasHop(chain,
                "org/springframework/beans/factory/config/MethodInvokingFactoryBean",
                "afterPropertiesSet", "javax/management/loading/MLet", "defineClass")
                && hasHop(chain, "javax/management/loading/MLet", "defineClass",
                "java/lang/ClassLoader", "defineClass");
    }

    /** Typed application-side JDBC sequence recovered from one exact binding host. */
    private static JdbcApplicationProof jdbcApplicationProof(
            Graph graph, ApplicationEntryIndex.DeserializeSite site) {
        if (graph == null || site == null || !JACKSON_MAPPER.equals(site.owner())
                || !"readValue".equals(site.name())
                || !"(Ljava/lang/String;Ljava/lang/Class;)Ljava/lang/Object;"
                .equals(site.descriptor()) || site.targetTypes().isEmpty()) {
            return JdbcApplicationProof.missing();
        }
        List<Node> calls = graph.callsOfMethod(site.hostMethodKey());
        Node binding = graph.node(site.callId());
        if (binding == null || !calls.contains(binding)
                || !JACKSON_MAPPER.equals(binding.owner())
                || !"readValue".equals(binding.name())
                || !site.descriptor().equals(binding.descriptor())) {
            return JdbcApplicationProof.missing();
        }
        Set<String> targetOwners = targetTypeClosure(graph, site.targetTypes());
        if (!hasMethod(graph, targetOwners, "setDriver", "(Ljava/lang/String;)V")
                || !hasMethod(graph, targetOwners, "getDriver", "()Ljava/lang/String;")
                || !hasMethod(graph, targetOwners, "getJdbc", "()Ljava/lang/String;")) {
            return JdbcApplicationProof.missing();
        }
        int bindingIndex = indexOfCall(calls, call -> call == binding);
        int jdbcIndex = indexOfCall(calls, call -> targetOwners.contains(call.owner())
                && "getJdbc".equals(call.name())
                && "()Ljava/lang/String;".equals(call.descriptor()));
        int validationIndex = indexOfCall(calls, call -> site.hostMethodKey()
                .startsWith(call.methodOwner() + "#")
                && call.methodOwner().equals(site.hostMethodKey().substring(0,
                site.hostMethodKey().indexOf('#')))
                && "validateJdbcUrl".equals(call.name())
                && "(Ljava/lang/String;)V".equals(call.descriptor()));
        int driverIndex = indexOfCall(calls, call -> targetOwners.contains(call.owner())
                && "getDriver".equals(call.name())
                && "()Ljava/lang/String;".equals(call.descriptor()));
        int loadIndex = indexOfCall(calls, call ->
                ("java/net/URLClassLoader".equals(call.owner())
                        || "java/lang/ClassLoader".equals(call.owner()))
                        && "loadClass".equals(call.name())
                        && JDBC_LOAD_CLASS_DESCRIPTOR.equals(call.descriptor()));
        int newInstanceIndex = indexOfCall(calls, call ->
                "java/lang/Class".equals(call.owner())
                        && "newInstance".equals(call.name())
                        && JDBC_CLASS_NEW_INSTANCE_DESCRIPTOR.equals(call.descriptor()));
        int connectIndex = indexOfCall(calls, call -> "java/sql/Driver".equals(call.owner())
                && "connect".equals(call.name())
                && JDBC_CONNECT_DESCRIPTOR.equals(call.descriptor()));
        boolean ordered = bindingIndex >= 0 && bindingIndex < jdbcIndex
                && jdbcIndex < validationIndex && validationIndex < driverIndex
                && driverIndex < loadIndex && loadIndex < newInstanceIndex
                && newInstanceIndex < connectIndex;
        return ordered ? new JdbcApplicationProof(true, site.hostMethodKey())
                : JdbcApplicationProof.missing();
    }

    private static Set<String> targetTypeClosure(Graph graph, List<String> targetTypes) {
        Set<String> owners = new TreeSet<>();
        if (targetTypes != null) {
            targetTypes.stream().filter(value -> value != null && !value.isBlank())
                    .forEach(owners::add);
        }
        boolean changed;
        do {
            changed = false;
            for (Node method : graph.nodesOfType(NodeType.METHOD)) {
                if (method == null || !owners.contains(method.owner())) {
                    continue;
                }
                Object superName = method.note("classSuperName");
                if (superName != null && !superName.toString().isBlank()) {
                    changed |= owners.add(superName.toString());
                }
            }
        } while (changed);
        return Set.copyOf(owners);
    }

    private static boolean hasMethod(Graph graph, Set<String> owners, String name,
                                     String descriptor) {
        return graph != null && owners != null && owners.stream().anyMatch(owner ->
                graph.findMethodNode(owner, name, descriptor) != null);
    }

    private static int indexOfCall(List<Node> calls, Predicate<Node> predicate) {
        if (calls == null || predicate == null) {
            return -1;
        }
        for (int i = 0; i < calls.size(); i++) {
            Node call = calls.get(i);
            if (call != null && predicate.test(call)) {
                return i;
            }
        }
        return -1;
    }

    /** Concrete driver dispatch and its exact configuration path, all from static graph edges. */
    private static JdbcDriverProof jdbcDriverProof(Graph graph, String applicationHost) {
        if (graph == null || applicationHost == null || applicationHost.isBlank()) {
            return JdbcDriverProof.missing();
        }
        Set<String> owners = new TreeSet<>();
        for (Node call : graph.callsOfMethod(applicationHost)) {
            if (!"java/sql/Driver".equals(call.owner()) || !"connect".equals(call.name())
                    || !JDBC_CONNECT_DESCRIPTOR.equals(call.descriptor())) {
                continue;
            }
            for (Edge edge : call.out()) {
                Node target = edge.to();
                if (target == null || target.type() != NodeType.METHOD
                        || "java/sql/Driver".equals(target.owner())
                        || !"connect".equals(target.name())
                        || !JDBC_CONNECT_DESCRIPTOR.equals(target.descriptor())) {
                    continue;
                }
                String driverKey = methodKey(target.owner(), target.name(), target.descriptor());
                boolean initConfig = hasReachableCall(graph, driverKey, candidate ->
                        target.owner().equals(candidate.owner())
                                && "initJDBCCONF".equals(candidate.name())
                                && JDBC_INIT_CONFIG_DESCRIPTOR.equals(candidate.descriptor()));
                boolean loadConfig = hasReachableCall(graph, driverKey, candidate ->
                target.owner().equals(candidate.owner())
                        && "loadPropertyFiles".equals(candidate.name())
                                && JDBC_LOAD_CONFIG_DESCRIPTOR.equals(candidate.descriptor()));
                boolean fileInput = hasReachableCall(graph, driverKey, candidate ->
                        "java/io/FileInputStream".equals(candidate.owner())
                                && "<init>".equals(candidate.name())
                                && "(Ljava/io/File;)V".equals(candidate.descriptor()));
                boolean propertiesLoad = hasReachableCall(graph, driverKey, candidate ->
                        "java/util/Properties".equals(candidate.owner())
                                && "load".equals(candidate.name())
                                && "(Ljava/io/InputStream;)V".equals(candidate.descriptor()));
                boolean socketFactory = hasReachableCall(graph, driverKey, candidate ->
                        candidate.owner() != null
                                && candidate.owner().endsWith("/SocketFactoryFactory")
                                && "getSocketFactory".equals(candidate.name())
                                && JDBC_SOCKET_FACTORY_DESCRIPTOR.equals(candidate.descriptor()));
                boolean untypedFactory = hasReachableCall(graph, driverKey, candidate ->
                        candidate.owner() != null
                                && candidate.owner().endsWith("/ObjectFactory")
                                && "instantiate".equals(candidate.name())
                                && JDBC_UNTYPED_FACTORY_DESCRIPTOR.equals(candidate.descriptor()));
                boolean typedFactory = hasReachableCall(graph, driverKey, candidate ->
                        candidate.owner() != null
                                && candidate.owner().endsWith("/ObjectFactory")
                                && "instantiate".equals(candidate.name())
                                && candidate.descriptor() != null
                                && candidate.descriptor().startsWith(
                                JDBC_TYPED_FACTORY_DESCRIPTOR_PREFIX));
                if (initConfig && loadConfig && fileInput && propertiesLoad && socketFactory
                        && untypedFactory && !typedFactory) {
                    owners.add(target.owner());
                }
            }
        }
        return owners.isEmpty() ? JdbcDriverProof.missing()
                : new JdbcDriverProof(true, String.join(",", owners));
    }

    /** Bounded reachability over actual CALL→METHOD edges; it never invokes target code. */
    private static boolean hasReachableCall(Graph graph, String startMethod,
                                            Predicate<Node> predicate) {
        if (graph == null || startMethod == null || startMethod.isBlank() || predicate == null) {
            return false;
        }
        Set<String> visited = new HashSet<>();
        ArrayDeque<String> work = new ArrayDeque<>();
        work.add(startMethod);
        while (!work.isEmpty() && visited.size() < MAX_JDBC_REACHABLE_METHODS) {
            String current = work.removeFirst();
            if (!visited.add(current)) {
                continue;
            }
            for (Node call : graph.callsOfMethod(current)) {
                if (call != null && predicate.test(call)) {
                    return true;
                }
                if (call == null) {
                    continue;
                }
                for (Edge edge : call.out()) {
                    if (!isCallEdge(edge) || edge.to() == null
                            || edge.to().type() != NodeType.METHOD) {
                        continue;
                    }
                    String next = methodKey(edge.to().owner(), edge.to().name(),
                            edge.to().descriptor());
                    if (!visited.contains(next)) {
                        work.addLast(next);
                    }
                }
            }
        }
        return false;
    }

    private record JdbcApplicationProof(boolean sequence, String hostMethodKey) {
        private JdbcApplicationProof {
            hostMethodKey = hostMethodKey == null ? "" : hostMethodKey;
        }

        private static JdbcApplicationProof missing() {
            return new JdbcApplicationProof(false, "");
        }
    }

    private record JdbcDriverProof(boolean configuration, String driverOwners) {
        private JdbcDriverProof {
            driverOwners = driverOwners == null ? "" : driverOwners;
        }

        private static JdbcDriverProof missing() {
            return new JdbcDriverProof(false, "");
        }
    }

    private static void addBridgeProfileAttributes(Map<String, String> attributes,
                                                   BridgeProfile profile) {
        if (attributes == null || profile == null) {
            return;
        }
        if (profile.jacksonBinding()) {
            attributes.put("binding_framework", "Jackson");
            attributes.put("binding_operation", "ObjectMapper.readValue");
        }
        if (profile.jndiLookup()) {
            attributes.put("lookup_protocol", "JNDI");
        }
        if (profile.composedJndi()) {
            attributes.put("transport_bridge", "JNDI_RMI");
        }
        if (profile.remoteReply()) {
            attributes.put("protocol_reply", "RMI_SERIALIZED_OBJECT");
            attributes.put("reply_deserialization", "JAVA_OBJECT_STREAM");
        }
        if (profile.jdbcConfiguration()) {
            attributes.put("jdbc_configuration", "DECLARED_XML_CLASS_DEFINITION");
            attributes.put("jdbc_application_sequence", Boolean.toString(
                    profile.jdbcApplicationSequence()));
            attributes.put("jdbc_driver_configuration", Boolean.toString(
                    profile.jdbcDriverConfiguration()));
            if (!profile.jdbcDriverOwners().isBlank()) {
                attributes.put("jdbc_driver_owners", profile.jdbcDriverOwners());
            }
            attributes.put("jdbc_terminal_boundary",
                    "java/lang/ClassLoader#defineClass([BII)Ljava/lang/Class;");
        }
        if (profile.declaredObjectGraph()) {
            attributes.put("object_graph_construction", "DECLARED_SHAPE");
            attributes.put("object_graph_path", EVENT_LISTENER_LIST + ".toString->"
                    + UNDO_MANAGER + ".toString->" + VECTOR + ".toString->"
                    + JACKSON_POJONODE + ".toString->" + SPRING_AOP_PROXY + ".invoke->"
                    + TEMPLATES + ".getOutputProperties->" + TEMPLATES_IMPL
                    + ".newTransformer");
            attributes.put("terminal_boundary", TEMPLATES_IMPL + ".newTransformer");
        }
    }

    private record BridgeProfile(boolean jacksonBinding, boolean jndiLookup,
                                 boolean composedJndi, boolean declaredObjectGraph,
                                 boolean remoteReply, boolean jdbcConfiguration,
                                 boolean jdbcApplicationSequence,
                                 boolean jdbcDriverConfiguration,
                                 String jdbcDriverOwners) {
        private BridgeProfile {
            jdbcDriverOwners = jdbcDriverOwners == null ? "" : jdbcDriverOwners;
        }

        private boolean jdbcComplete() {
            return jdbcConfiguration && jdbcApplicationSequence && jdbcDriverConfiguration;
        }
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
