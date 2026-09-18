package io.just.sast.report;

import io.just.sast.analysis.entry.ApplicationChainEvidence;
import io.just.sast.blackboard.ApplicationChainId;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.EvidenceAtom;
import io.just.sast.blackboard.EvidenceEdge;
import io.just.sast.blackboard.EvidenceNode;
import io.just.sast.blackboard.HopKind;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeSet;

/**
 * The report-facing projection of an application-entry join.
 *
 * <p>The legacy {@code Chain} deliberately starts at the deserialized object or callback.  That
 * is useful kernel evidence, but it is not an application path.  This immutable projection keeps
 * the application execution root, the binding/deserialization site and the typed prefix beside
 * the legacy chain key so every renderer can expose the same complete path without rewriting
 * chain identity or inferring an entry from a class name.</p>
 */
public record ApplicationTrace(
        String applicationEntryClass,
        String applicationEntryMethod,
        String applicationSiteClass,
        String applicationSiteMethod,
        String applicationSiteKind,
        String joinKind,
        String chainEntryMethod,
        String entryPrefixPath,
        String dependencyOwner,
        String terminalOwner,
        String terminalMethod,
        JoinEvidence joinEvidence) {

    /** Compatibility constructor for callers that only provide the path projection. */
    public ApplicationTrace(String applicationEntryClass, String applicationEntryMethod,
                            String applicationSiteClass, String applicationSiteMethod,
                            String applicationSiteKind, String joinKind,
                            String chainEntryMethod, String entryPrefixPath,
                            String dependencyOwner, String terminalOwner,
                            String terminalMethod) {
        this(applicationEntryClass, applicationEntryMethod, applicationSiteClass,
                applicationSiteMethod, applicationSiteKind, joinKind, chainEntryMethod,
                entryPrefixPath, dependencyOwner, terminalOwner, terminalMethod, null);
    }

    /** Stable typed references from a raw chain key to the immutable application evidence graph. */
    public record JoinEvidence(
            String evidenceGraphDigest,
            String artifactDigest,
            String applicationIndexDigest,
            String joinId,
            String applicationChainId,
            String entryAtomId,
            String siteAtomId,
            String dependencySegmentId,
            String valueFlow,
            String objectIdentity,
            String callbackSemantics,
            String runtimeTypeProof,
            String artifactCompatibility,
            String filterDominance,
            String constructionConstraint,
            List<String> bridgeEvidenceIds,
            StaticProof staticProof) {

        /** Compatibility constructor for evidence produced before typed provenance fields. */
        public JoinEvidence(String evidenceGraphDigest, String artifactDigest,
                            String applicationIndexDigest, String joinId,
                            String applicationChainId, String entryAtomId,
                            String siteAtomId, String dependencySegmentId,
                            String valueFlow, String objectIdentity,
                            String callbackSemantics, String runtimeTypeProof,
                            String artifactCompatibility, String filterDominance,
                            String constructionConstraint, List<String> bridgeEvidenceIds) {
            this(evidenceGraphDigest, artifactDigest, applicationIndexDigest, joinId,
                    applicationChainId, entryAtomId, siteAtomId, dependencySegmentId,
                    valueFlow, objectIdentity, callbackSemantics, runtimeTypeProof,
                    artifactCompatibility, filterDominance, constructionConstraint,
                    bridgeEvidenceIds, null);
        }

        public JoinEvidence {
            evidenceGraphDigest = required(evidenceGraphDigest, "evidenceGraphDigest");
            artifactDigest = required(artifactDigest, "artifactDigest");
            applicationIndexDigest = required(applicationIndexDigest, "applicationIndexDigest");
            joinId = required(joinId, "joinId");
            applicationChainId = required(applicationChainId, "applicationChainId");
            entryAtomId = required(entryAtomId, "entryAtomId");
            siteAtomId = required(siteAtomId, "siteAtomId");
            dependencySegmentId = required(dependencySegmentId, "dependencySegmentId");
            valueFlow = required(valueFlow, "valueFlow");
            objectIdentity = required(objectIdentity, "objectIdentity");
            callbackSemantics = required(callbackSemantics, "callbackSemantics");
            runtimeTypeProof = required(runtimeTypeProof, "runtimeTypeProof");
            artifactCompatibility = required(artifactCompatibility, "artifactCompatibility");
            filterDominance = required(filterDominance, "filterDominance");
            constructionConstraint = required(constructionConstraint, "constructionConstraint");
            if (bridgeEvidenceIds == null
                    || bridgeEvidenceIds.stream().anyMatch(value -> value == null || value.isBlank())) {
                throw new IllegalArgumentException("bridge evidence IDs must be non-null and non-blank");
            }
            bridgeEvidenceIds = List.copyOf(new TreeSet<>(bridgeEvidenceIds));
        }

        public String toCanonicalJson() {
            StringBuilder json = new StringBuilder("{\"evidence_graph_digest\":\"")
                    .append(esc(evidenceGraphDigest)).append("\",\"artifact_digest\":\"")
                    .append(esc(artifactDigest)).append("\",\"application_index_digest\":\"")
                    .append(esc(applicationIndexDigest)).append("\",\"join_id\":\"")
                    .append(esc(joinId)).append("\",\"application_chain_id\":\"")
                    .append(esc(applicationChainId)).append("\",\"entry_atom_id\":\"")
                    .append(esc(entryAtomId)).append("\",\"site_atom_id\":\"")
                    .append(esc(siteAtomId)).append("\",\"dependency_segment_id\":\"")
                    .append(esc(dependencySegmentId)).append("\",\"value_flow\":\"")
                    .append(esc(valueFlow)).append("\",\"object_identity\":\"")
                    .append(esc(objectIdentity)).append("\",\"callback_semantics\":\"")
                    .append(esc(callbackSemantics)).append("\",\"runtime_type_proof\":\"")
                    .append(esc(runtimeTypeProof)).append("\",\"artifact_compatibility\":\"")
                    .append(esc(artifactCompatibility)).append("\",\"filter_dominance\":\"")
                    .append(esc(filterDominance)).append("\",\"construction_constraint\":\"")
                    .append(esc(constructionConstraint)).append("\",\"bridge_evidence_ids\":[");
            for (int index = 0; index < bridgeEvidenceIds.size(); index++) {
                if (index > 0) {
                    json.append(',');
                }
                json.append('"').append(esc(bridgeEvidenceIds.get(index))).append('"');
            }
            json.append("],\"static_proof\":");
            return json.append(staticProof == null ? "null" : staticProof.toCanonicalJson())
                    .append('}').toString();
        }

        public String display() {
            String base = "join=" + joinId + "; value=" + valueFlow + "; object=" + objectIdentity
                    + "; callback=" + callbackSemantics + "; type=" + runtimeTypeProof
                    + "; artifact=" + artifactCompatibility + "; filter=" + filterDominance
                    + "; construction=" + constructionConstraint + "; bridges="
                    + String.join(",", bridgeEvidenceIds);
            return staticProof == null ? base : base + "; proof=" + staticProof.display();
        }

        private static String required(String value, String name) {
            if (value == null || value.isBlank()) {
                throw new IllegalArgumentException(name + " must be non-blank");
            }
            return value.trim();
        }
    }

    /**
     * Report-facing projection of the typed input/reflection proof.  It is deliberately a
     * compact value object: the full evidence graph remains in meta/application-chain-evidence,
     * while report.json carries the stages an agent needs to understand why a join is complete.
     */
    public record StaticProof(
            String inputFlowStatus,
            String inputFlowStages,
            List<String> inputParameterSlots,
            List<String> deserializedElementTypes,
            String reflectionResolution,
            String reflectionHost,
            String reflectionReceiverPrecision,
            String reflectionMethodName,
            String reflectionDescriptor,
            List<String> reflectionInputs,
            List<String> reflectionReasons) {

        public StaticProof {
            inputFlowStatus = optional(inputFlowStatus);
            inputFlowStages = optional(inputFlowStages);
            inputParameterSlots = stableList(inputParameterSlots);
            deserializedElementTypes = stableList(deserializedElementTypes);
            reflectionResolution = optional(reflectionResolution);
            reflectionHost = optional(reflectionHost);
            reflectionReceiverPrecision = optional(reflectionReceiverPrecision);
            reflectionMethodName = optional(reflectionMethodName);
            reflectionDescriptor = optional(reflectionDescriptor);
            reflectionInputs = stableList(reflectionInputs);
            reflectionReasons = stableList(reflectionReasons);
        }

        public boolean present() {
            return !inputFlowStatus.isBlank() || !inputFlowStages.isBlank()
                    || !deserializedElementTypes.isEmpty() || !reflectionResolution.isBlank()
                    || !reflectionHost.isBlank() || !reflectionInputs.isEmpty()
                    || !reflectionReasons.isEmpty();
        }

        public String display() {
            String input = inputFlowStages.isBlank() ? inputFlowStatus : inputFlowStages;
            String reflection = reflectionResolution.isBlank() ? "UNKNOWN" : reflectionResolution;
            if (!reflectionHost.isBlank()) {
                reflection += "@" + reflectionHost;
            }
            return "input=" + (input.isBlank() ? "UNKNOWN" : input)
                    + "; reflection=" + reflection;
        }

        public String toCanonicalJson() {
            return "{\"input_flow_status\":\"" + esc(inputFlowStatus)
                    + "\",\"input_flow_stages\":\"" + esc(inputFlowStages)
                    + "\",\"input_parameter_slots\":" + strings(inputParameterSlots)
                    + ",\"deserialized_element_types\":" + strings(deserializedElementTypes)
                    + ",\"reflection_resolution\":\"" + esc(reflectionResolution)
                    + "\",\"reflection_host\":\"" + esc(reflectionHost)
                    + "\",\"reflection_receiver_precision\":\""
                    + esc(reflectionReceiverPrecision)
                    + "\",\"reflection_method_name\":\"" + esc(reflectionMethodName)
                    + "\",\"reflection_descriptor\":\"" + esc(reflectionDescriptor)
                    + "\",\"reflection_inputs\":" + strings(reflectionInputs)
                    + ",\"reflection_reasons\":" + strings(reflectionReasons) + "}";
        }

        private static List<String> stableList(List<String> values) {
            if (values == null || values.isEmpty()) {
                return List.of();
            }
            return List.copyOf(values.stream().filter(Objects::nonNull)
                    .map(String::trim).filter(value -> !value.isBlank()).toList());
        }

        private static String optional(String value) {
            return value == null ? "" : value.trim();
        }

        private static String strings(List<String> values) {
            StringBuilder json = new StringBuilder("[");
            for (int index = 0; index < values.size(); index++) {
                if (index > 0) {
                    json.append(',');
                }
                json.append('"').append(esc(values.get(index))).append('"');
            }
            return json.append(']').toString();
        }

        private static String esc(String value) {
            return value.replace("\\", "\\\\").replace("\"", "\\\"")
                    .replace("\r", "\\r").replace("\n", "\\n");
        }
    }

    public ApplicationTrace {
        applicationEntryClass = normalize(applicationEntryClass);
        applicationEntryMethod = normalize(applicationEntryMethod);
        applicationSiteClass = normalize(applicationSiteClass);
        applicationSiteMethod = normalize(applicationSiteMethod);
        applicationSiteKind = normalize(applicationSiteKind);
        joinKind = normalize(joinKind);
        chainEntryMethod = normalize(chainEntryMethod);
        entryPrefixPath = normalize(entryPrefixPath);
        dependencyOwner = normalize(dependencyOwner);
        terminalOwner = normalize(terminalOwner);
        terminalMethod = normalize(terminalMethod);
    }

    /**
     * Build one deterministic raw-chain-key map from the typed evidence graph.  The graph is the
     * only source of this projection; no notes, ranking text or class-name guessing is allowed.
     */
    public static Map<String, ApplicationTrace> fromEvidence(ApplicationChainEvidence evidence) {
        if (evidence == null || evidence.joins().isEmpty()) {
            return Map.of();
        }
        Map<String, EvidenceNode> nodes = new LinkedHashMap<>();
        evidence.graph().nodes().forEach(node -> nodes.putIfAbsent(node.id(), node));
        // The join graph deliberately does not put a raw chain key on reusable entry/site/
        // dependency atoms: doing so would defeat atom sharing and make IDs depend on every
        // path variant.  The evidence product already owns the typed decisions map, so derive
        // the raw-key ↔ application-chain-id relation from that map instead of guessing from a
        // class name or parsing a renderer note.
        Map<String, String> rawKeyByChainId = new java.util.TreeMap<>();
        evidence.decisions().forEach((rawKey, decision) -> {
            if (rawKey != null && !rawKey.isBlank() && "JOINED".equals(decision)) {
                rawKeyByChainId.put(ApplicationChainId.fromCanonical("chain", rawKey).value(),
                        rawKey);
            }
        });
        Map<String, ApplicationTrace> traces = new java.util.TreeMap<>();
        evidence.joins().values().stream()
                .sorted(Comparator.comparing(join -> join.applicationChainId().value()))
                .forEach(join -> {
                    EvidenceAtom entry = atom(nodes.get(join.applicationEntryAtomId()));
                    EvidenceAtom site = atom(nodes.get(join.applicationSiteAtomId()));
                    if (entry == null || site == null) {
                        return;
                    }
                    String chainKey = rawKeyByChainId.getOrDefault(
                            join.applicationChainId().value(), "");
                    // Compatibility evidence produced by pre-grouping callers may still carry
                    // a raw key attribute.  It is only a fallback; production joins use the
                    // typed decisions relation above.
                    if (chainKey.isBlank()) chainKey = attribute(site, "chain_key");
                    if (chainKey.isBlank()) chainKey = attribute(entry, "chain_key");
                    if (chainKey.isBlank()) {
                        return;
                    }
                    EvidenceAtom dependency = dependencyFor(join, nodes, chainKey);
                    EvidenceAtom terminal = terminalFor(join, dependency, nodes, evidence.graph().edges(),
                            chainKey);
                    ApplicationTrace trace = new ApplicationTrace(
                            entry.owner(), entry.member(), site.owner(), site.member(),
                            site.kind().name(), attribute(entry, "entry_join_kind"),
                            attribute(entry, "chain_entry_method"),
                            attribute(entry, "entry_prefix_path"),
                            dependency == null ? "UNKNOWN" : dependency.owner(),
                            terminal == null ? "UNKNOWN" : terminal.owner(),
                            terminal == null ? "UNKNOWN" : terminal.member(),
                            new JoinEvidence(evidence.graph().canonicalDigest(),
                                    evidence.artifactDigest(), evidence.applicationIndexDigest(), join.id(),
                                    join.applicationChainId().value(),
                                    join.applicationEntryAtomId(), join.applicationSiteAtomId(),
                                    join.dependencySegmentId().value(), join.valueFlow().name(),
                                    join.objectIdentity().name(), join.callbackSemantics().name(),
                                    join.runtimeTypeProof().name(),
                                    join.artifactCompatibility().name(),
                                    join.filterDominance().name(),
                                    join.constructionConstraint().name(),
                                    join.bridgeEvidenceIds(), staticProof(site)));
                    traces.putIfAbsent(chainKey, trace);
                });
        return Map.copyOf(traces);
    }

    /** Human-readable application-root → legacy-chain path used by all report formats. */
    public String applicationPath(io.just.sast.blackboard.Chain chain) {
        Objects.requireNonNull(chain, "chain");
        String chainPath = pathSummary(chain);
        if (entryPrefixPath.isBlank()) {
            return chainPath;
        }
        String prefix = entryPrefixPath;
        String chainStart = chain.entryClass() + "." + chain.entryMethod();
        String canonicalStart = chain.entryClass() + "#" + chain.entryMethod();
        String suffix = chainPath;
        int firstArrow = chainPath.indexOf(" -> ");
        if (firstArrow >= 0 && (prefix.endsWith(chainStart) || prefix.endsWith(canonicalStart))) {
            suffix = chainPath.substring(firstArrow + 4);
        } else if (chainPath.startsWith(chainStart)
                && (prefix.endsWith(chainStart) || prefix.endsWith(canonicalStart))) {
            suffix = "";
        }
        if (suffix.isBlank()) {
            return prefix;
        }
        return prefix + " -> " + suffix;
    }

    /** Stable entry-to-impact path used by the canonical application trace projection. */
    private static String pathSummary(io.just.sast.blackboard.Chain chain) {
        StringBuilder out = new StringBuilder();
        List<ChainHop> hops = chain.hops();
        boolean first = true;
        for (int hopIndex = hops.size() - 1; hopIndex >= 0; hopIndex--) {
            ChainHop hop = hops.get(hopIndex);
            if (first) {
                out.append(hop.fromOwner()).append('.').append(hop.fromName());
                first = false;
            }
            if (hop.kind() != HopKind.ENTRY && hop.kind() != HopKind.FIELD_FLOW) {
                out.append(" -> ").append(hop.toOwner()).append('.').append(hop.toName());
            } else if (hop.kind() == HopKind.FIELD_FLOW) {
                out.append(" --[").append(hop.field()).append("]--> ")
                        .append(hop.toOwner()).append('.').append(hop.toName());
            }
        }
        return out.toString();
    }

    public String entryDisplay() {
        return applicationEntryClass + "." + applicationEntryMethod;
    }

    public String siteDisplay() {
        return applicationSiteClass + "." + applicationSiteMethod;
    }

    public String toCanonicalJson() {
        return "{\"application_entry_class\":\"" + esc(applicationEntryClass)
                + "\",\"application_entry_method\":\"" + esc(applicationEntryMethod)
                + "\",\"application_site_class\":\"" + esc(applicationSiteClass)
                + "\",\"application_site_method\":\"" + esc(applicationSiteMethod)
                + "\",\"application_site_kind\":\"" + esc(applicationSiteKind)
                + "\",\"join_kind\":\"" + esc(joinKind)
                + "\",\"chain_entry_method\":\"" + esc(chainEntryMethod)
                + "\",\"entry_prefix_path\":\"" + esc(entryPrefixPath)
                + "\",\"dependency_owner\":\"" + esc(dependencyOwner)
                + "\",\"terminal_owner\":\"" + esc(terminalOwner)
                + "\",\"terminal_method\":\"" + esc(terminalMethod)
                + "\",\"join_evidence\":"
                + (joinEvidence == null ? "null" : joinEvidence.toCanonicalJson()) + "}";
    }

    private static EvidenceAtom dependencyFor(io.just.sast.blackboard.EntryChainJoinEvidence join,
                                               Map<String, EvidenceNode> nodes, String chainKey) {
        return nodes.values().stream()
                .filter(node -> node instanceof EvidenceAtom atom
                        && atom.kind() == EvidenceAtom.Kind.DEPENDENCY_SEGMENT
                        && (join != null && join.dependencySegmentId().value()
                        .equals(attribute(atom, "segment_id"))
                        || chainKey.equals(attribute(atom, "chain_key"))))
                .map(node -> (EvidenceAtom) node)
                .findFirst().orElse(null);
    }

    private static EvidenceAtom terminalFor(io.just.sast.blackboard.EntryChainJoinEvidence join,
                                            EvidenceAtom dependency,
                                            Map<String, EvidenceNode> nodes,
                                            List<EvidenceEdge> edges,
                                            String chainKey) {
        if (dependency != null && edges != null) {
            for (EvidenceEdge edge : edges) {
                if (!dependency.id().equals(edge.fromId())
                        || edge.kind() != EvidenceEdge.Kind.FLOWS_TO) {
                    continue;
                }
                EvidenceNode target = nodes.get(edge.toId());
                if (target instanceof EvidenceAtom atom
                        && atom.kind() == EvidenceAtom.Kind.TERMINAL_IMPACT) {
                    return atom;
                }
            }
        }
        return nodes.values().stream()
                .filter(node -> node instanceof EvidenceAtom atom
                        && atom.kind() == EvidenceAtom.Kind.TERMINAL_IMPACT
                        && chainKey.equals(attribute(atom, "chain_key")))
                .map(node -> (EvidenceAtom) node)
                .findFirst().orElse(null);
    }

    private static EvidenceAtom atom(EvidenceNode node) {
        return node instanceof EvidenceAtom value ? value : null;
    }

    private static String attribute(EvidenceAtom atom, String key) {
        if (atom == null) {
            return "";
        }
        String value = atom.attributes().get(key);
        return value == null ? "" : value.trim();
    }

    private static StaticProof staticProof(EvidenceAtom site) {
        if (site == null) {
            return null;
        }
        String inputStatus = attribute(site, "input_flow_status");
        String inputStages = attribute(site, "input_flow_stages");
        List<String> inputSlots = splitCsv(attribute(site, "input_parameter_slots"));
        List<String> elementTypes = splitCsv(attribute(site, "deserialized_element_types"));
        String reflectionResolution = attribute(site, "reflection_resolution");
        String reflectionHost = attribute(site, "reflection_host");
        String receiverPrecision = attribute(site, "reflection_receiver_precision");
        String methodName = attribute(site, "reflection_method_name");
        String descriptor = attribute(site, "reflection_descriptor");
        List<String> inputs = splitCsv(attribute(site, "reflection_inputs"));
        List<String> reasons = splitCsv(attribute(site, "reflection_reasons"));
        StaticProof proof = new StaticProof(inputStatus, inputStages, inputSlots, elementTypes,
                reflectionResolution, reflectionHost, receiverPrecision, methodName, descriptor,
                inputs, reasons);
        return proof.present() ? proof : null;
    }

    private static List<String> splitCsv(String value) {
        if (value == null || value.isBlank()) {
            return List.of();
        }
        return List.copyOf(java.util.Arrays.stream(value.split(","))
                .map(String::trim).filter(item -> !item.isBlank()).toList());
    }

    private static String normalize(String value) {
        return value == null || value.isBlank() ? "UNKNOWN" : value.trim();
    }

    private static String esc(String value) {
        StringBuilder out = new StringBuilder(value.length() + 8);
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            switch (ch) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (ch < 0x20) {
                        out.append(String.format(java.util.Locale.ROOT, "\\u%04x", (int) ch));
                    } else {
                        out.append(ch);
                    }
                }
            }
        }
        return out.toString();
    }
}
