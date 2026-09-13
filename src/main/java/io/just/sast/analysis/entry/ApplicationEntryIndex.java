package io.just.sast.analysis.entry;

import io.just.sast.analysis.taint.SerializationModel;
import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.FindingState;
import io.just.sast.blackboard.HopKind;
import io.just.sast.blackboard.SinkRisk;
import io.just.sast.config.Rule;
import io.just.sast.config.RuleEngine;
import io.just.sast.config.RuleSchemaV2;
import io.just.sast.cpg.graph.Edge;
import io.just.sast.cpg.graph.EdgeType;
import io.just.sast.cpg.graph.Graph;
import io.just.sast.cpg.graph.Node;
import io.just.sast.cpg.graph.NodeType;
import io.just.sast.model.Descriptor;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.lang.reflect.Modifier;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * Immutable, bounded index for the first stage of demand-driven solving.
 *
 * <p>The index deliberately keeps application ownership separate from the presence of a
 * method in the graph.  A dependency or JDK method can be a terminal-relevant node, but it is
 * not an execution root merely because it is materialized in the same class path.  Callers must
 * provide the classes belonging to the target application and explicitly say whether that
 * scope is known.  An unknown scope produces no application-anchored roots (fail closed).</p>
 *
 * <p>This class only computes direct graph slices.  Reflection, object-graph callbacks and
 * protocol bridges remain typed semantic edges owned by their respective knowledge sources;
 * they are not guessed from class names here.  The forward and reverse slices are therefore
 * useful demand hints, not a replacement for the complete taint/evidence solver.</p>
 */
public final class ApplicationEntryIndex {

    public static final int MODEL_VERSION = 3;
    private static final int MAX_SLICE_METHODS = 100_000;
    private static final String FRAMEWORK_ENTRY_RULE = "builtin:framework-entry";
    private static final String FRAMEWORK_BINDING_RULE = "builtin:framework-binding";
    private static final Set<String> HTTP_CLASS_ANNOTATIONS = Set.of(
            "Lorg/springframework/web/bind/annotation/RestController;",
            "Lorg/springframework/stereotype/Controller;",
            "Lorg/springframework/web/bind/annotation/Controller;",
            "Ljavax/ws/rs/Path;", "Ljakarta/ws/rs/Path;");
    private static final Set<String> HTTP_METHOD_ANNOTATIONS = Set.of(
            "Lorg/springframework/web/bind/annotation/RequestMapping;",
            "Lorg/springframework/web/bind/annotation/GetMapping;",
            "Lorg/springframework/web/bind/annotation/PostMapping;",
            "Lorg/springframework/web/bind/annotation/PutMapping;",
            "Lorg/springframework/web/bind/annotation/DeleteMapping;",
            "Lorg/springframework/web/bind/annotation/PatchMapping;",
            "Ljavax/ws/rs/Path;", "Ljakarta/ws/rs/Path;",
            "Ljavax/ws/rs/GET;", "Ljakarta/ws/rs/GET;",
            "Ljavax/ws/rs/POST;", "Ljakarta/ws/rs/POST;",
            "Ljavax/ws/rs/PUT;", "Ljakarta/ws/rs/PUT;",
            "Ljavax/ws/rs/DELETE;", "Ljakarta/ws/rs/DELETE;",
            "Ljavax/ws/rs/PATCH;", "Ljakarta/ws/rs/PATCH;");
    private static final Set<String> SERVICE_METHOD_ANNOTATIONS = Set.of(
            "Ljavax/jws/WebMethod;", "Ljakarta/jws/WebMethod;");
    private static final Set<String> WEB_SERVICE_ANNOTATIONS = Set.of(
            "Ljavax/jws/WebService;", "Ljakarta/jws/WebService;");
    private static final Set<String> SERVLET_TYPES = Set.of(
            "javax/servlet/Servlet", "jakarta/servlet/Servlet",
            "javax/servlet/http/HttpServlet", "jakarta/servlet/http/HttpServlet",
            "javax/servlet/Filter", "jakarta/servlet/Filter");
    private static final Set<String> SERVLET_LIFECYCLE = Set.of(
            "service", "doGet", "doPost", "doPut", "doDelete", "doPatch", "init");
    /** Serialization callbacks that the object-graph mechanism can invoke during read. */
    private static final Set<String> MECHANISM_ENTRY_KINDS = Set.of(
            "readObject", "readObjectNoData", "readExternal", "readResolve", "validateObject");
    /** Object callbacks used by serialized hash/ordered containers, never independent roots. */
    private static final Set<String> SERIALIZED_TRIGGER_ENTRY_KINDS = Set.of(
            "hashCode", "equals", "compareTo", "compare", "toString");

    /** A method-level execution boundary discovered from a real application artifact. */
    public record ExecutionEntry(String methodKey, String owner, String name, String descriptor,
                                 String ruleId, String entryKind,
                                 FindingState.EntryStatus status,
                                 boolean applicationOwned, boolean externalControlProven) {
        public ExecutionEntry {
            methodKey = requireText(methodKey, "methodKey");
            owner = requireText(owner, "owner");
            name = requireText(name, "name");
            descriptor = descriptor == null ? "" : descriptor;
            ruleId = ruleId == null ? "" : ruleId;
            entryKind = entryKind == null ? "" : entryKind;
            status = Objects.requireNonNull(status, "status");
            if (applicationOwned != (status != FindingState.EntryStatus.NO_APPLICATION_ENTRY)) {
                throw new IllegalArgumentException("entry ownership/status mismatch");
            }
            if (externalControlProven && status != FindingState.EntryStatus.EXTERNAL_ENTRY) {
                throw new IllegalArgumentException("external control requires EXTERNAL_ENTRY");
            }
        }
    }

    /** A deserialization or binding site; constrained secondary sources remain visible. */
    public record DeserializeSite(long callId, String hostMethodKey, String owner, String name,
                                  String descriptor, String ruleId, String bridge,
                                  boolean applicationOwned, boolean externalInput,
                                  List<String> targetTypes) {
        /** Compatibility constructor for callers that predate typed binding targets. */
        public DeserializeSite(long callId, String hostMethodKey, String owner, String name,
                               String descriptor, String ruleId, String bridge,
                               boolean applicationOwned, boolean externalInput) {
            this(callId, hostMethodKey, owner, name, descriptor, ruleId, bridge,
                    applicationOwned, externalInput, List.of());
        }

        public DeserializeSite {
            if (callId < 0) {
                throw new IllegalArgumentException("callId must be non-negative");
            }
            hostMethodKey = requireText(hostMethodKey, "hostMethodKey");
            owner = requireText(owner, "owner");
            name = requireText(name, "name");
            descriptor = descriptor == null ? "" : descriptor;
            ruleId = ruleId == null ? "" : ruleId;
            bridge = bridge == null ? "" : bridge;
            List<String> normalizedTargets = new ArrayList<>();
            if (targetTypes != null) {
                for (String target : targetTypes) {
                    if (target != null && !target.isBlank() && target.indexOf('.') < 0
                            && target.indexOf('[') < 0) {
                        normalizedTargets.add(target.trim());
                    }
                }
            }
            targetTypes = normalizedTargets.stream().distinct().sorted().toList();
        }
    }

    /**
     * A typed deserialization host and the source frame that activates it.  Composition
     * consumes this immutable projection instead of rescanning CPG calls and re-deriving
     * source/rule semantics for every event.  The host may be outside the application scope;
     * the caller still applies the scope/entry admission policy before creating a product.
     */
    public record DeserializeHost(String hostMethodKey, String hostOwner, String hostName,
                                  String hostDescriptor, String frameOwner, String frameMethod,
                                  String frameDescriptor) {
        public DeserializeHost {
            hostMethodKey = requireText(hostMethodKey, "hostMethodKey");
            hostOwner = requireText(hostOwner, "hostOwner");
            hostName = requireText(hostName, "hostName");
            hostDescriptor = hostDescriptor == null ? "" : hostDescriptor;
            frameOwner = requireText(frameOwner, "frameOwner");
            frameMethod = requireText(frameMethod, "frameMethod");
            frameDescriptor = frameDescriptor == null ? "" : frameDescriptor;
            String expected = methodKey(hostOwner, hostName, hostDescriptor);
            if (!expected.equals(hostMethodKey)) {
                throw new IllegalArgumentException("host method key does not match host fields");
            }
        }
    }

    /** A sink call retained as a terminal/capability impact candidate. */
    public record TerminalImpact(long callId, String hostMethodKey, String owner, String name,
                                 String descriptor, String ruleId, Rule.SinkRole role,
                                 boolean applicationOwned, boolean terminal) {
        /** Compatibility constructor for callers that predate the typed terminal axis. */
        public TerminalImpact(long callId, String hostMethodKey, String owner, String name,
                              String descriptor, String ruleId, Rule.SinkRole role,
                              boolean applicationOwned) {
            this(callId, hostMethodKey, owner, name, descriptor, ruleId, role,
                    applicationOwned, role == Rule.SinkRole.TERMINAL);
        }

        public TerminalImpact {
            if (callId < 0) {
                throw new IllegalArgumentException("callId must be non-negative");
            }
            hostMethodKey = requireText(hostMethodKey, "hostMethodKey");
            owner = requireText(owner, "owner");
            name = requireText(name, "name");
            descriptor = descriptor == null ? "" : descriptor;
            ruleId = ruleId == null ? "" : ruleId;
            role = role == null ? Rule.SinkRole.TERMINAL : role;
        }
    }

    /** Closed lookup outcomes for the terminal impact used by the default join boundary. */
    public enum TerminalStatus {
        INDEXED,
        INTERMEDIATE_ONLY,
        NOT_INDEXED
    }

    /** Typed terminal lookup; a name-only or reverse-reachable method is never terminal proof. */
    public record TerminalDecision(TerminalStatus status, String owner, String name,
                                   String descriptor, long callId, String hostMethodKey) {
        public TerminalDecision {
            status = Objects.requireNonNull(status, "status");
            owner = owner == null ? "" : owner;
            name = name == null ? "" : name;
            descriptor = descriptor == null ? "" : descriptor;
            hostMethodKey = hostMethodKey == null ? "" : hostMethodKey;
            if (status == TerminalStatus.INDEXED
                    && (callId < 0 || hostMethodKey.isBlank())) {
                throw new IllegalArgumentException("indexed terminal requires call and host");
            }
            if (status != TerminalStatus.INDEXED && (callId != -1 || !hostMethodKey.isBlank())) {
                throw new IllegalArgumentException("non-indexed terminal cannot carry call/host");
            }
        }

        public boolean admitted() {
            return status == TerminalStatus.INDEXED;
        }

        public String reasonCode() {
            return switch (status) {
                case INDEXED -> "TERMINAL_INDEXED";
                case INTERMEDIATE_ONLY -> "TERMINAL_IMPACT_IS_INTERMEDIATE";
                case NOT_INDEXED -> "TERMINAL_IMPACT_NOT_INDEXED";
            };
        }
    }

    /** Stable key for the precomputed terminal-impact lookup (descriptor may be blank by name). */
    private record TerminalKey(String owner, String name, String descriptor) {
    }

    /** Closed admission outcomes for the entry-forward ∩ sink-reverse demand query. */
    public enum DemandStatus {
        ENTRY_TERMINAL_INTERSECTION,
        BRIDGE_CONTINUATION,
        ENTRY_NOT_APPLICATION,
        ENTRY_NOT_FORWARD_REACHABLE,
        TERMINAL_NOT_REVERSE_REACHABLE,
        TERMINAL_NOT_INDEXED,
        ENTRY_NOT_IN_TERMINAL_DEMAND,
        APPLICATION_SCOPE_UNKNOWN
    }

    /**
     * Immutable decision returned by the sole application-demand admission owner.  The
     * booleans are evidence axes, not a second eligibility state; callers must use
     * {@link #admitted()} and retain the closed {@link #status()} reason in reports.
     */
    public record DemandDecision(DemandStatus status, String entryMethodKey,
                                String terminalHostMethodKey, boolean entryForward,
                                boolean sinkReverse, boolean continuationEvidence) {
        public DemandDecision {
            status = Objects.requireNonNull(status, "status");
            entryMethodKey = entryMethodKey == null ? "" : entryMethodKey;
            terminalHostMethodKey = terminalHostMethodKey == null ? "" : terminalHostMethodKey;
        }

        public boolean admitted() {
            return status == DemandStatus.ENTRY_TERMINAL_INTERSECTION
                    || status == DemandStatus.BRIDGE_CONTINUATION;
        }

        public String reasonCode() {
            return status.name();
        }
    }

    /** Closed pre-materialization outcomes for a raw chain candidate. */
    public enum CandidateAdmissionStatus {
        ADMITTED,
        APPLICATION_SCOPE_UNKNOWN,
        APPLICATION_ENTRY_NOT_IN_CHAIN,
        ENTRY_NOT_FORWARD_REACHABLE,
        TERMINAL_IMPACT_NOT_INDEXED,
        TERMINAL_IMPACT_IS_INTERMEDIATE,
        TERMINAL_NOT_REVERSE_REACHABLE,
        ENTRY_NOT_IN_TERMINAL_DEMAND
    }

    /**
     * Typed, cheap admission result used before the joiner builds evidence nodes or walks a
     * caller prefix.  It is intentionally weaker than a completed join: the joiner must still
     * prove the concrete entry path, dependency suffix and terminal touch after admission.
     */
    public record CandidateAdmissionDecision(CandidateAdmissionStatus status,
                                             String entryMethodKey,
                                             String terminalOwner,
                                             String terminalName,
                                             String terminalDescriptor,
                                             boolean entryForward,
                                             boolean sinkReverse,
                                             boolean continuationEvidence) {
        public CandidateAdmissionDecision {
            status = Objects.requireNonNull(status, "status");
            entryMethodKey = entryMethodKey == null ? "" : entryMethodKey;
            terminalOwner = terminalOwner == null ? "" : terminalOwner;
            terminalName = terminalName == null ? "" : terminalName;
            terminalDescriptor = terminalDescriptor == null ? "" : terminalDescriptor;
        }

        public boolean admitted() {
            return status == CandidateAdmissionStatus.ADMITTED;
        }

        public String reasonCode() {
            return status.name();
        }
    }

    /**
     * Typed destination for a solver-produced chain.  The default chain store is reserved for
     * application candidates; dependency terminal segments and explicit bridge participants
     * remain available to the composition phase through separate stores.  A kernel-only route
     * is kept for callers that intentionally do not provide an application scope.
     */
    public enum ProducerAdmissionStatus {
        APPLICATION_CHAIN,
        BRIDGE_CONTINUATION,
        DEPENDENCY_SUFFIX,
        KERNEL_ONLY,
        REJECTED
    }

    /**
     * Closed materialization policy derived from the producer admission status.  Endpoint
     * retention and path materialization are intentionally separate decisions: a dependency
     * suffix can be retained for a later typed demand without allocating its path now.
     */
    public enum MaterializationPolicy {
        EAGER_APPLICATION,
        EAGER_BRIDGE,
        DEFERRED_SUFFIX,
        EAGER_KERNEL,
        REJECTED;

        /** Whether the producer is allowed to materialize its path at the admission boundary. */
        public boolean materializesImmediately() {
            return this == EAGER_APPLICATION || this == EAGER_BRIDGE || this == EAGER_KERNEL;
        }

        /** Whether the result remains an input to the typed composition phase. */
        public boolean retainsForComposition() {
            return this == EAGER_BRIDGE || this == DEFERRED_SUFFIX;
        }
    }

    /** Immutable producer decision; admission and routing are one typed query. */
    public record ProducerAdmissionDecision(ProducerAdmissionStatus status,
                                            CandidateAdmissionDecision candidate,
                                            TerminalDecision terminal,
                                            boolean continuationEvidence) {
        public ProducerAdmissionDecision {
            status = Objects.requireNonNull(status, "status");
            candidate = Objects.requireNonNull(candidate, "candidate");
            terminal = Objects.requireNonNull(terminal, "terminal");
        }

        public boolean materializeApplicationChain() {
            return materializationPolicy() == MaterializationPolicy.EAGER_APPLICATION;
        }

        public MaterializationPolicy materializationPolicy() {
            return switch (status) {
                case APPLICATION_CHAIN -> MaterializationPolicy.EAGER_APPLICATION;
                case BRIDGE_CONTINUATION -> MaterializationPolicy.EAGER_BRIDGE;
                case DEPENDENCY_SUFFIX -> MaterializationPolicy.DEFERRED_SUFFIX;
                case KERNEL_ONLY -> MaterializationPolicy.EAGER_KERNEL;
                case REJECTED -> MaterializationPolicy.REJECTED;
            };
        }

        public boolean retainForComposition() {
            return materializationPolicy().retainsForComposition();
        }

        public String reasonCode() {
            return status == ProducerAdmissionStatus.REJECTED
                    ? candidate.reasonCode() : status.name();
        }
    }

    /**
     * Cheap, immutable solver metadata used to decide whether a chain supplier may run.  It
     * deliberately contains only endpoint/rule identity and typed continuation evidence; path
     * hops and construction plans stay behind the lazy materializer until admission succeeds.
     */
    public record ProducerCandidate(String ruleId, String category, String severity,
                                    String entryOwner, String entryName, String entryDescriptor,
                                    String entryKind, String terminalOwner, String terminalName,
                                    String terminalDescriptor, String terminalRole,
                                    SinkRisk sinkRisk, boolean continuationEvidence) {
        public ProducerCandidate {
            ruleId = text(ruleId);
            category = text(category);
            severity = text(severity);
            entryOwner = text(entryOwner);
            entryName = text(entryName);
            entryDescriptor = text(entryDescriptor);
            entryKind = text(entryKind);
            terminalOwner = text(terminalOwner);
            terminalName = text(terminalName);
            terminalDescriptor = text(terminalDescriptor);
            terminalRole = terminalRole == null || terminalRole.isBlank()
                    ? "TERMINAL" : terminalRole;
            sinkRisk = sinkRisk == null
                    ? SinkRisk.resolve(null, category, terminalOwner, terminalName) : sinkRisk;
        }

        public String entryMethodKey() {
            return methodKey(entryOwner, entryName, entryDescriptor);
        }

        /** Verify that a lazy supplier returned the candidate it was admitted to build. */
        public boolean matches(Chain chain) {
            if (chain == null) {
                return false;
            }
            return ruleId.equals(text(chain.ruleId()))
                    && category.equals(text(chain.category()))
                    && severity.equals(text(chain.severity()))
                    && entryOwner.equals(text(chain.entryClass()))
                    && entryName.equals(text(chain.entryMethod()))
                    && entryDescriptor.equals(ApplicationEntryIndex.entryDescriptor(chain))
                    && entryKind.equals(text(chain.entryKind()))
                    && terminalOwner.equals(text(chain.sinkClass()))
                    && terminalName.equals(text(chain.sinkMethod()))
                    && terminalDescriptor.equals(text(chain.sinkDescriptor()))
                    && terminalRole.equals(text(chain.sinkRole()))
                    && sinkRisk == chain.sinkRisk();
        }

        private static String text(String value) {
            return value == null ? "" : value;
        }
    }

    private final boolean applicationScopeKnown;
    private final boolean hasDeserializeRoot;
    private final Set<String> applicationOwners;
    private final List<ExecutionEntry> executionEntries;
    private final List<ExecutionEntry> applicationExecutionEntries;
    private final Map<String, List<ExecutionEntry>> mechanismEntriesByOwner;
    private final List<DeserializeSite> deserializeSites;
    private final List<DeserializeHost> deserializeHosts;
    private final List<DeserializeSite> applicationInputSites;
    private final List<DeserializeSite> typedBindingSites;
    private final Map<String, List<DeserializeSite>> typedBindingSitesByTarget;
    private final Map<String, List<DeserializeSite>> applicationInputSitesByMember;
    private final List<TerminalImpact> terminalImpacts;
    private final List<String> entryForwardSlice;
    private final List<String> sinkReverseSlice;
    private final List<String> entryTerminalIntersection;
    private final List<String> dependencyCandidates;
    private final List<String> completenessReasons;
    private final Set<String> applicationEntryMethods;
    private final Map<String, List<String>> applicationEntryMethodsByMember;
    private final Set<String> entryTerminalMethods;
    private final Set<String> entryForwardMethods;
    private final Set<String> sinkReverseMethods;
    private final Set<String> terminalHostMethods;
    private final List<TerminalImpact> terminalDemandImpacts;
    private final Set<String> bindingCallbackMethods;
    private final Map<TerminalKey, List<TerminalImpact>> terminalImpactsBySignature;
    private final Map<TerminalKey, List<TerminalImpact>> terminalImpactsByName;
    private final String semanticDigest;

    private ApplicationEntryIndex(boolean applicationScopeKnown, boolean hasDeserializeRoot,
                                  Set<String> applicationOwners,
                                  List<ExecutionEntry> executionEntries,
                                  List<DeserializeSite> deserializeSites,
                                  List<DeserializeHost> deserializeHosts,
                                  List<TerminalImpact> terminalImpacts,
                                  List<String> entryForwardSlice,
                                  List<String> sinkReverseSlice,
                                  List<String> entryTerminalIntersection,
                                  List<String> dependencyCandidates,
                                  List<String> completenessReasons,
                                  Set<String> bindingCallbackMethods) {
        this.applicationScopeKnown = applicationScopeKnown;
        this.hasDeserializeRoot = hasDeserializeRoot;
        this.applicationOwners = immutableSorted(applicationOwners);
        this.executionEntries = List.copyOf(executionEntries);
        this.applicationExecutionEntries = this.executionEntries.stream()
                .filter(entry -> entry.status() != FindingState.EntryStatus.NO_APPLICATION_ENTRY)
                .toList();
        this.mechanismEntriesByOwner = immutableMechanismEntryIndex(this.executionEntries);
        this.deserializeSites = List.copyOf(deserializeSites);
        this.deserializeHosts = deserializeHosts == null
                ? List.of() : List.copyOf(deserializeHosts);
        this.applicationInputSites = this.deserializeSites.stream()
                .filter(ApplicationEntryIndex::isApplicationInputSite)
                .toList();
        this.typedBindingSites = this.applicationInputSites.stream()
                .filter(site -> isTypedBindingBridge(site.bridge()))
                .toList();
        this.typedBindingSitesByTarget = immutableBindingTargetIndex(this.typedBindingSites);
        this.applicationInputSitesByMember = immutableSiteMemberIndex(this.applicationInputSites);
        this.terminalImpacts = List.copyOf(terminalImpacts);
        this.entryForwardSlice = List.copyOf(entryForwardSlice);
        this.sinkReverseSlice = List.copyOf(sinkReverseSlice);
        this.entryTerminalIntersection = List.copyOf(entryTerminalIntersection);
        this.dependencyCandidates = List.copyOf(dependencyCandidates);
        this.completenessReasons = List.copyOf(new TreeSet<>(completenessReasons));
        this.applicationEntryMethods = immutableSorted(this.applicationExecutionEntries.stream()
                .map(ExecutionEntry::methodKey).collect(java.util.stream.Collectors.toSet()));
        this.applicationEntryMethodsByMember = immutableMemberIndex(this.applicationEntryMethods);
        this.entryTerminalMethods = immutableSorted(new TreeSet<>(this.entryTerminalIntersection));
        this.entryForwardMethods = immutableSorted(new TreeSet<>(this.entryForwardSlice));
        this.sinkReverseMethods = immutableSorted(new TreeSet<>(this.sinkReverseSlice));
        this.terminalHostMethods = immutableSorted(this.terminalImpacts.stream()
                .filter(TerminalImpact::terminal)
                .map(TerminalImpact::hostMethodKey)
                .collect(java.util.stream.Collectors.toSet()));
        this.terminalDemandImpacts = immutableTerminalDemandImpacts(this.terminalImpacts,
                this.sinkReverseMethods);
        this.bindingCallbackMethods = immutableSorted(bindingCallbackMethods);
        this.terminalImpactsBySignature = immutableTerminalIndex(this.terminalImpacts, false);
        this.terminalImpactsByName = immutableTerminalIndex(this.terminalImpacts, true);
        this.semanticDigest = digestCanonical();
    }

    /** Build deterministic exact-signature and descriptor-free terminal indexes once per scan. */
    private static Map<TerminalKey, List<TerminalImpact>> immutableTerminalIndex(
            List<TerminalImpact> impacts, boolean byName) {
        Map<TerminalKey, List<TerminalImpact>> grouped = new HashMap<>();
        for (TerminalImpact impact : impacts) {
            String descriptor = byName ? "" : impact.descriptor();
            TerminalKey key = new TerminalKey(impact.owner(), impact.name(), descriptor);
            grouped.computeIfAbsent(key, ignored -> new ArrayList<>()).add(impact);
        }
        Map<TerminalKey, List<TerminalImpact>> result = new HashMap<>();
        grouped.forEach((key, values) -> {
            values.sort(Comparator.comparingLong(TerminalImpact::callId));
            result.put(key, List.copyOf(values));
        });
        return Map.copyOf(result);
    }

    /**
     * Build the deterministic terminal-impact projection used by demand-driven composition.
     * Keeping this filter/sort in the immutable index prevents each consumer from rescanning
     * and resorting all sink impacts, while retaining every distinct call-site impact.
     */
    private static List<TerminalImpact> immutableTerminalDemandImpacts(
            List<TerminalImpact> impacts, Set<String> sinkReverseMethods) {
        if (impacts == null || impacts.isEmpty() || sinkReverseMethods == null
                || sinkReverseMethods.isEmpty()) {
            return List.of();
        }
        return impacts.stream()
                .filter(TerminalImpact::terminal)
                .filter(impact -> sinkReverseMethods.contains(impact.hostMethodKey()))
                .sorted(Comparator.comparing(TerminalImpact::owner)
                        .thenComparing(TerminalImpact::name)
                        .thenComparing(TerminalImpact::descriptor)
                        .thenComparingLong(TerminalImpact::callId))
                .toList();
    }

    /** Build a deterministic target-owner index for typed binding sites once per scan. */
    private static Map<String, List<DeserializeSite>> immutableBindingTargetIndex(
            List<DeserializeSite> sites) {
        Map<String, List<DeserializeSite>> grouped = new java.util.TreeMap<>();
        for (DeserializeSite site : sites) {
            for (String target : site.targetTypes()) {
                if (target == null || target.isBlank()) {
                    continue;
                }
                grouped.computeIfAbsent(target, ignored -> new ArrayList<>()).add(site);
            }
        }
        grouped.values().forEach(values -> values.sort(Comparator
                .comparingLong(DeserializeSite::callId)
                .thenComparing(DeserializeSite::hostMethodKey)));
        Map<String, List<DeserializeSite>> result = new java.util.TreeMap<>();
        grouped.forEach((target, values) -> result.put(target, List.copyOf(values)));
        return Map.copyOf(result);
    }

    /**
     * Build the immutable mechanism-callback projection used by object-graph rerooting.
     * Matching and subtype semantics are resolved once while constructing execution entries;
     * consumers must not rescan ClassInfo or RuleEngine for the same callback fact.  Entries
     * deliberately include dependency owners because this lookup is a mechanism fact, not an
     * application-entry admission.
     */
    private static Map<String, List<ExecutionEntry>> immutableMechanismEntryIndex(
            List<ExecutionEntry> entries) {
        if (entries == null || entries.isEmpty()) {
            return Map.of();
        }
        Map<String, List<ExecutionEntry>> grouped = new TreeMap<>();
        for (ExecutionEntry entry : entries) {
            if (entry == null || !MECHANISM_ENTRY_KINDS.contains(entry.entryKind())) {
                continue;
            }
            grouped.computeIfAbsent(entry.owner(), ignored -> new ArrayList<>()).add(entry);
        }
        Map<String, List<ExecutionEntry>> result = new TreeMap<>();
        grouped.forEach((owner, values) -> {
            values.sort(Comparator.comparing(ExecutionEntry::methodKey)
                    .thenComparing(ExecutionEntry::ruleId));
            result.put(owner, List.copyOf(values));
        });
        return Map.copyOf(result);
    }

    /** Build a deterministic host-owner/name index for application input-site lookups. */
    private static Map<String, List<DeserializeSite>> immutableSiteMemberIndex(
            List<DeserializeSite> sites) {
        Map<String, List<DeserializeSite>> grouped = new java.util.TreeMap<>();
        for (DeserializeSite site : sites) {
            String member = memberOfMethodKey(site.hostMethodKey());
            if (member.isBlank()) {
                continue;
            }
            grouped.computeIfAbsent(member, ignored -> new ArrayList<>()).add(site);
        }
        grouped.values().forEach(values -> values.sort(Comparator
                .comparingLong(DeserializeSite::callId)
                .thenComparing(DeserializeSite::hostMethodKey)));
        Map<String, List<DeserializeSite>> result = new java.util.TreeMap<>();
        grouped.forEach((member, values) -> result.put(member, List.copyOf(values)));
        return Map.copyOf(result);
    }

    /**
     * Build a deterministic index.  {@code applicationOwners} contains internal class names
     * from the first (target) artifact, not dependency/JDK classes.
     */
    public static ApplicationEntryIndex build(Graph graph, RuleEngine rules,
                                               Set<String> applicationOwners,
                                               boolean applicationScopeKnown) {
        return buildInternal(graph, rules, applicationOwners, applicationScopeKnown);
    }

    private static ApplicationEntryIndex buildInternal(Graph graph, RuleEngine rules,
                                                        Set<String> applicationOwners,
                                                        boolean applicationScopeKnown) {
        Objects.requireNonNull(graph, "graph");
        Objects.requireNonNull(rules, "rules");
        Set<String> owners = normalizeOwners(applicationOwners);
        List<String> reasons = new ArrayList<>();
        if (!applicationScopeKnown) {
            reasons.add("APPLICATION_SCOPE_UNKNOWN");
        }

        Map<String, Node> methods = new HashMap<>();
        Map<String, Set<String>> methodAnnotations = new HashMap<>();
        Map<String, Set<String>> classAnnotations = new HashMap<>();
        for (Node method : graph.nodesOfType(NodeType.METHOD)) {
            String key = methodKey(method.owner(), method.name(), method.descriptor());
            methods.put(key, method);
            methodAnnotations.put(key, annotationDescriptors(method,
                    "methodAnnotationDescriptors"));
            classAnnotations.computeIfAbsent(method.owner(), ignored -> new TreeSet<>())
                    .addAll(annotationDescriptors(method, "classAnnotationDescriptors"));
        }

        List<ExecutionEntry> entries = new ArrayList<>();
        boolean hasDeserializeRoot = false;
        for (Node method : graph.nodesOfType(NodeType.METHOD)) {
            String owner = method.owner();
            String key = methodKey(owner, method.name(), method.descriptor());
            Rule.MagicEntryRule rule = rules.matchingEntry(owner, method.name(), method.descriptor())
                    .orElse(null);
            if (!isPlatformOwner(owner)
                    && SerializationModel.magicEntry(rule, owner, method.name(), method.descriptor())
                    .isPresent()) {
                hasDeserializeRoot = true;
            }
            if (rule == null || !isExecutionEntryRule(rule)) {
                continue;
            }
            boolean owned = applicationScopeKnown && owners.contains(owner);
            FindingState.EntryStatus status = owned
                    ? FindingState.EntryStatus.APPLICATION_ENTRY
                    : FindingState.EntryStatus.NO_APPLICATION_ENTRY;
            entries.add(new ExecutionEntry(key, owner, method.name(), method.descriptor(),
                    rule.id(), rule.entryKind(), status, owned, false));
            continue;
        }
        // Framework/lifecycle facts are discovered from typed frontend metadata rather than
        // class names or benchmark fixtures.  Mapping/servlet binding parameters provide an
        // external-control proof; lifecycle/main/service boundaries without that proof remain
        // APPLICATION_ENTRY until a typed source/bridge establishes controllability.
        for (Node method : graph.nodesOfType(NodeType.METHOD)) {
            FrameworkEntry framework = frameworkEntry(method, methods, methodAnnotations,
                    classAnnotations);
            if (framework == null) {
                continue;
            }
            String owner = method.owner();
            String key = methodKey(owner, method.name(), method.descriptor());
            boolean owned = applicationScopeKnown && owners.contains(owner);
            FindingState.EntryStatus status = owned
                    ? (framework.externalControlProven()
                    ? FindingState.EntryStatus.EXTERNAL_ENTRY
                    : FindingState.EntryStatus.APPLICATION_ENTRY)
                    : FindingState.EntryStatus.NO_APPLICATION_ENTRY;
            entries.add(new ExecutionEntry(key, owner, method.name(), method.descriptor(),
                    FRAMEWORK_ENTRY_RULE, framework.entryKind(), status, owned,
                    owned && framework.externalControlProven()));
        }

        List<DeserializeSite> sites = new ArrayList<>();
        Map<String, Boolean> sourceHosts = new HashMap<>();
        Map<String, DeserializeHost> deserializeHosts = new TreeMap<>();
        Set<String> siteHosts = new TreeSet<>();
        Set<String> acceptedTypePrefixes = acceptedTypePrefixes(graph);
        List<String> acceptedApplicationTypes = owners.stream()
                .filter(owner -> acceptedTypePrefixes.stream().anyMatch(owner::startsWith))
                .sorted().toList();
        for (Node call : graph.nodesOfType(NodeType.CALL)) {
            String host = methodKey(call.methodOwner(), call.methodName(), call.methodDescriptor());
            Rule.SourceRule source = rules.matchingSource(call.owner(), call.name(), call.descriptor())
                    .orElse(null);
            boolean subtypeOis = rules.isSubtypeOf(call.owner(), "java/io/ObjectInputStream")
                    && ("readObject".equals(call.name())
                    || "readUnshared".equals(call.name())
                    || "readFields".equals(call.name()));
            boolean ois = SerializationModel.isOisRead(call.owner(), call.name(), call.descriptor())
                    || subtypeOis;
            if (source == null && !ois) {
                continue;
            }
            boolean externalInput = ois || isUnconditionalDeserialize(source);
            hasDeserializeRoot |= externalInput;
            boolean owned = applicationScopeKnown && owners.contains(call.methodOwner());
            String ruleId = source == null ? "builtin:ois-read" : source.id();
            String bridge = source == null ? "deserialize" : source.bridge();
            sites.add(new DeserializeSite(call.id(), host, call.owner(), call.name(),
                    call.descriptor(), ruleId, bridge, owned, externalInput,
                    classLiteralHints(call)));
            DeserializeHost deserializeHost = deserializeHost(call, source, ois, rules);
            if (deserializeHost != null) {
                deserializeHosts.putIfAbsent(deserializeHost.hostMethodKey(), deserializeHost);
            }
            siteHosts.add(host);
            Node hostNode = methods.get(host);
            // Java visibility is not an external-control proof.  A public service/helper that
            // happens to call ObjectInputStream is still an application-internal site; the
            // caller must be a typed framework/lifecycle boundary (or an explicitly configured
            // entry) before this source can become an application root.  Otherwise a public
            // decoder helper is promoted to EXTERNAL_ENTRY and every dependency callback below
            // it is misreported as an exposed application chain.
            boolean explicitExecutionBoundary = entries.stream().anyMatch(entry -> host.equals(entry.methodKey())
                    && (entry.externalControlProven()
                    // An explicit configured magic entry is already a user-declared
                    // execution boundary.  Keep its historical source upgrade, while never
                    // upgrading an arbitrary helper method that merely contains OIS.read.
                    || (!FRAMEWORK_ENTRY_RULE.equals(entry.ruleId())
                    && entry.status() == FindingState.EntryStatus.APPLICATION_ENTRY)));
            boolean publicDeserializeBoundary = externalInput && owned
                    && isPublicMethod(hostNode)
                    && entries.stream().anyMatch(entry -> host.equals(entry.methodKey())
                    && entry.externalControlProven());
            boolean boundaryExternal = explicitExecutionBoundary;
            if (externalInput && owned && boundaryExternal) {
                sourceHosts.put(host, true);
                if (publicDeserializeBoundary && hostNode != null) {
                    entries.add(new ExecutionEntry(host, hostNode.owner(), hostNode.name(),
                            hostNode.descriptor(), ruleId, "public-deserialize-source",
                            FindingState.EntryStatus.EXTERNAL_ENTRY, true, true));
                }
                if (hostNode != null) {
                    String entryKind = source == null ? "ois-read" : "source:" + bridge;
                    entries.add(new ExecutionEntry(host, hostNode.owner(), hostNode.name(),
                            hostNode.descriptor(), ruleId, entryKind,
                            FindingState.EntryStatus.EXTERNAL_ENTRY, true, true));
                }
            }
        }
        // Binding annotations are a boundary/site fact even when the bytecode does not contain
        // a recognizable deserializer call in the same method.  Keep one synthetic, stable site
        // per host so the joiner can demand a typed application-entry → binding → dependency
        // suffix.  It is deliberately not a dynamic-execution claim.
        for (Node method : graph.nodesOfType(NodeType.METHOD)) {
            FrameworkEntry framework = frameworkEntry(method, methods, methodAnnotations,
                    classAnnotations);
            if (framework == null || !framework.bindingCapable()
                    || !applicationScopeKnown || !owners.contains(method.owner())) {
                continue;
            }
            String host = methodKey(method.owner(), method.name(), method.descriptor());
            if (!siteHosts.add(host)) {
                continue;
            }
            List<String> declaredBindingTypes = referenceParameterTypes(method.descriptor());
            List<String> bindingTargets = new ArrayList<>(declaredBindingTypes);
            // Fastjson 1.2.83's addAccept path is a class-name allowlist, not a Java
            // assignability proof.  Its checkAutoType prefix branch returns an accepted
            // application class even when it is unrelated to the declared request type.  Keep
            // the declared type and the complete application-owned accepted-prefix scope as
            // separate typed alternatives; never widen it to dependency/JDK classes.
            bindingTargets.addAll(acceptedApplicationTypes);
            sites.add(new DeserializeSite(method.id(), host, method.owner(), method.name(),
                    method.descriptor(), FRAMEWORK_BINDING_RULE, "framework-binding", true, true,
                    bindingTargets));
            sourceHosts.put(host, true);
        }

        // A deserialize source is a typed object-binding boundary even when the frontend
        // cannot recover a concrete target class literal.  Restrict the generic fallback to
        // public, instance JavaBean setters and require an application-owned external
        // deserialize site in this artifact; an arbitrary public method must not become an
        // attacker entry merely because a source rule exists somewhere on the class path.
        boolean externalDeserializeSite = sites.stream().anyMatch(site -> site.applicationOwned()
                && site.externalInput() && isTypedBindingBridge(site.bridge()));
        Set<String> bindingCallbacks = new TreeSet<>();
        if (externalDeserializeSite) {
            for (Node method : graph.nodesOfType(NodeType.METHOD)) {
                if (applicationScopeKnown && owners.contains(method.owner())
                        && isPublicBeanSetter(method)) {
                    bindingCallbacks.add(methodKey(method.owner(), method.name(),
                            method.descriptor()));
                }
            }
        }

        List<TerminalImpact> impacts = new ArrayList<>();
        for (Node call : graph.nodesOfType(NodeType.CALL)) {
            Rule.SinkRule sink = rules.matchingSink(call).orElse(null);
            if (sink == null) {
                continue;
            }
            impacts.add(new TerminalImpact(call.id(),
                    methodKey(call.methodOwner(), call.methodName(), call.methodDescriptor()),
                    call.owner(), call.name(), call.descriptor(), sink.id(), sink.role(),
                    applicationScopeKnown && owners.contains(call.methodOwner()),
                    RuleSchemaV2.isTerminalSink(sink)));
        }

        sortEntries(entries);
        sites.sort(Comparator.comparingLong(DeserializeSite::callId));
        impacts.sort(Comparator.comparingLong(TerminalImpact::callId));

        Set<String> roots = new TreeSet<>();
        if (applicationScopeKnown) {
            entries.stream().filter(entry -> entry.status() != FindingState.EntryStatus.NO_APPLICATION_ENTRY)
                    .map(ExecutionEntry::methodKey).forEach(roots::add);
            sourceHosts.keySet().forEach(roots::add);
        }
        List<String> forward = forwardSlice(graph, methods, roots, reasons);

        Set<String> sinkHosts = new TreeSet<>();
        for (TerminalImpact impact : impacts) {
            if (impact.terminal()) {
                sinkHosts.add(impact.hostMethodKey());
            }
        }
        List<String> reverse = reverseSlice(graph, sinkHosts, reasons);
        Set<String> intersection = new TreeSet<>(forward);
        intersection.retainAll(reverse);
        List<String> dependency = intersection.stream()
                .filter(key -> !owners.contains(ownerOf(key)))
                .toList();
        if (entries.stream().noneMatch(
                entry -> entry.status() != FindingState.EntryStatus.NO_APPLICATION_ENTRY)) {
            reasons.add("NO_APPLICATION_ENTRY");
        }
        if (impacts.stream().noneMatch(TerminalImpact::terminal)) {
            reasons.add("NO_TERMINAL_IMPACT");
        }
        if (intersection.isEmpty() && applicationScopeKnown) {
            reasons.add("NO_ENTRY_TERMINAL_INTERSECTION");
        }
        return new ApplicationEntryIndex(applicationScopeKnown, hasDeserializeRoot, owners, entries, sites,
                List.copyOf(deserializeHosts.values()), impacts,
                forward, reverse, List.copyOf(intersection), dependency, reasons,
                bindingCallbacks);
    }

    public boolean applicationScopeKnown() {
        return applicationScopeKnown;
    }

    /**
     * Whether the graph contains a raw deserialization threat-model root.  This is deliberately
     * independent of application ownership: unknown-scope/kernel analysis still needs to know
     * that an OIS/framework boundary exists, while callers must apply their own application
     * entry/join admission before publishing a product finding.
     */
    public boolean hasDeserializeRoot() {
        return hasDeserializeRoot;
    }

    public Set<String> applicationOwners() {
        return applicationOwners;
    }

    public List<ExecutionEntry> executionEntries() {
        return executionEntries;
    }

    /**
     * Immutable serialization-mechanism callbacks for one concrete owner.  This is a
     * mechanism lookup only: callers still apply application ownership, field compatibility,
     * validation registration and terminal-demand admission before publishing a chain.
     */
    public List<ExecutionEntry> mechanismEntriesForOwner(String owner) {
        if (owner == null || owner.isBlank()) {
            return List.of();
        }
        return mechanismEntriesByOwner.getOrDefault(owner, List.of());
    }

    public List<ExecutionEntry> applicationEntries() {
        return applicationExecutionEntries;
    }

    /** Stable method keys for application-owned execution roots, including external sources. */
    public Set<String> applicationEntryMethods() {
        return applicationEntryMethods;
    }

    /** Stable application-entry keys grouped by owner/name for bounded join lookups. */
    public List<String> applicationEntryMethods(String owner, String name) {
        if (owner == null || name == null || owner.isBlank() || name.isBlank()) {
            return List.of();
        }
        return applicationEntryMethodsByMember.getOrDefault(owner + "#" + name, List.of());
    }

    /** Whether a method owner belongs to the first (application) artifact. */
    public boolean isApplicationOwner(String owner) {
        return applicationScopeKnown && owner != null && applicationOwners.contains(owner);
    }

    /** Whether a method is a validated application-owned execution root. */
    public boolean isApplicationEntryMethod(String methodKey) {
        return methodKey != null && applicationEntryMethods.contains(methodKey);
    }

    /**
     * Whether a callback method is a typed target of an application-owned external binding
     * site.  Reflective binders do not create a direct CPG call edge to the callback, so the
     * exact target type plus a value-bearing descriptor is the admission fact for that
     * application prefix.  A class being application-owned by itself is intentionally not
     * sufficient.
     */
    public boolean isApplicationBindingCallback(String owner, String name, String descriptor) {
        return isApplicationOwner(owner) && isApplicationBindingTarget(owner, name, descriptor);
    }

    /**
     * Whether a method is an exact target of an application-owned external binding site.  The
     * target may live in a dependency: the application-owned site is the execution boundary,
     * while the target class is the callback object selected by the typed binding value.
     */
    public boolean isApplicationBindingTarget(String owner, String name, String descriptor) {
        if (!applicationScopeKnown || owner == null || owner.isBlank()
                || name == null || name.isBlank() || descriptor == null || descriptor.isBlank()) {
            return false;
        }
        try {
            if (Descriptor.paramCount(descriptor) == 0) {
                return false;
            }
        } catch (RuntimeException ignored) {
            return false;
        }
        if (bindingCallbackMethods.contains(methodKey(owner, name, descriptor))) {
            return !typedBindingSites.isEmpty();
        }
        return typedBindingSites.stream().anyMatch(site -> site.targetTypes().contains(owner));
    }

    /** Whether a method has a concrete external-control proof at the application boundary. */
    public boolean isExternalEntryMethod(String methodKey) {
        if (methodKey == null) {
            return false;
        }
        return executionEntries.stream().anyMatch(entry -> methodKey.equals(entry.methodKey())
                && entry.status() == FindingState.EntryStatus.EXTERNAL_ENTRY
                && entry.externalControlProven());
    }

    /** Whether a method is in the bounded entry-forward ∩ sink-reverse demand hint. */
    public boolean isEntryTerminalMethod(String methodKey) {
        return methodKey != null && entryTerminalMethods.contains(methodKey);
    }

    public List<DeserializeSite> deserializeSites() {
        return deserializeSites;
    }

    /** Immutable source-host projection used by composition and object-graph consumers. */
    public List<DeserializeHost> deserializeHosts() {
        return deserializeHosts;
    }

    /** Immutable application-owned external-input sites for repeated joiner hot reads. */
    public List<DeserializeSite> applicationInputSites() {
        return applicationInputSites;
    }

    /** Immutable application-input sites grouped by host owner and method name. */
    public List<DeserializeSite> applicationInputSitesForMember(String owner, String name) {
        if (owner == null || owner.isBlank() || name == null || name.isBlank()) {
            return List.of();
        }
        return applicationInputSitesByMember.getOrDefault(owner + "#" + name, List.of());
    }

    /** Immutable typed binding subset of application-owned external-input sites. */
    public List<DeserializeSite> typedBindingSites() {
        return typedBindingSites;
    }

    /** Immutable typed binding sites whose exact target type is the supplied owner. */
    public List<DeserializeSite> typedBindingSitesForTarget(String owner) {
        if (owner == null || owner.isBlank()) {
            return List.of();
        }
        return typedBindingSitesByTarget.getOrDefault(owner, List.of());
    }

    public List<TerminalImpact> terminalImpacts() {
        return terminalImpacts;
    }

    /** Immutable terminal impacts that are both terminal and sink-reverse reachable. */
    public List<TerminalImpact> terminalDemandImpacts() {
        return terminalDemandImpacts;
    }

    /** Immutable exact-signature or descriptor-free terminal-impact lookup for hot joins. */
    public List<TerminalImpact> terminalImpactsFor(String owner, String name, String descriptor) {
        String requestedOwner = owner == null ? "" : owner;
        String requestedName = name == null ? "" : name;
        String requestedDescriptor = descriptor == null ? "" : descriptor;
        TerminalKey lookupKey = new TerminalKey(requestedOwner, requestedName,
                requestedDescriptor.isBlank() ? "" : requestedDescriptor);
        return (requestedDescriptor.isBlank() ? terminalImpactsByName : terminalImpactsBySignature)
                .getOrDefault(lookupKey, List.of());
    }

    /**
     * Resolve a chain sink against the immutable terminal-impact index.  This is the only
     * owner of terminal-vs-intermediate classification used by the default application join;
     * reverse reachability and a chain's claimed sink role cannot manufacture an impact.
     */
    public TerminalDecision terminalAdmission(String owner, String name, String descriptor) {
        String requestedOwner = owner == null ? "" : owner;
        String requestedName = name == null ? "" : name;
        String requestedDescriptor = descriptor == null ? "" : descriptor;
        List<TerminalImpact> matches = terminalImpactsFor(requestedOwner, requestedName,
                requestedDescriptor);
        TerminalImpact indexed = matches.stream().filter(TerminalImpact::terminal).findFirst()
                .orElse(null);
        if (indexed != null) {
            return new TerminalDecision(TerminalStatus.INDEXED, requestedOwner, requestedName,
                    requestedDescriptor, indexed.callId(), indexed.hostMethodKey());
        }
        if (matches.stream().anyMatch(impact -> !impact.terminal())) {
            return new TerminalDecision(TerminalStatus.INTERMEDIATE_ONLY, requestedOwner,
                    requestedName, requestedDescriptor, -1, "");
        }
        return new TerminalDecision(TerminalStatus.NOT_INDEXED, requestedOwner, requestedName,
                requestedDescriptor, -1, "");
    }

    public List<String> entryForwardSlice() {
        return entryForwardSlice;
    }

    /** Immutable O(1) membership view for hot join/admission reads. */
    public Set<String> entryForwardMethodKeys() {
        return entryForwardMethods;
    }

    public List<String> sinkReverseSlice() {
        return sinkReverseSlice;
    }

    /** Immutable O(1) membership view for hot terminal/admission reads. */
    public Set<String> sinkReverseMethodKeys() {
        return sinkReverseMethods;
    }

    public List<String> entryTerminalIntersection() {
        return entryTerminalIntersection;
    }

    /** O(1) membership query owned by the index; preserves the sorted slice accessor above. */
    public boolean isEntryForwardReachable(String methodKey) {
        return methodKey != null && entryForwardMethods.contains(methodKey);
    }

    /** O(1) membership query owned by the index; preserves the sorted reverse-slice accessor. */
    public boolean isSinkReverseReachable(String methodKey) {
        return methodKey != null && sinkReverseMethods.contains(methodKey);
    }

    /** O(1) membership query for the typed entry-forward ∩ terminal-reverse demand slice. */
    public boolean isEntryTerminalDemand(String methodKey) {
        return methodKey != null && entryTerminalMethods.contains(methodKey);
    }

    /** Methods outside the application scope that are reachable in the entry∩terminal hint. */
    public List<String> dependencyCandidates() {
        return dependencyCandidates;
    }

    public List<String> completenessReasons() {
        return completenessReasons;
    }

    public String semanticDigest() {
        return semanticDigest;
    }

    /** Only an application-owned root plus a non-empty direct slice may request dependency expansion. */
    public boolean allowsDependencyExpansion() {
        return applicationScopeKnown && !applicationExecutionEntries.isEmpty()
                && !entryTerminalIntersection.isEmpty();
    }

    /**
     * Answer whether one application execution root may request a terminal suffix.  Ordinary
     * joins require the exact root and exact terminal host to meet in the precomputed
     * entry-forward ∩ sink-reverse demand.  Protocol/object-graph/typed-binding continuations
     * may use the same root/terminal axes only when the caller supplies explicit typed bridge
     * evidence; the bridge does not make an unanchored dependency root eligible.
     */
    public DemandDecision demandAdmission(String entryMethodKey,
                                          String terminalHostMethodKey,
                                          boolean continuationEvidence) {
        String entry = entryMethodKey == null ? "" : entryMethodKey;
        String terminal = terminalHostMethodKey == null ? "" : terminalHostMethodKey;
        boolean entryKnown = applicationScopeKnown && applicationEntryMethods.contains(entry);
        boolean entryForward = entryForwardMethods.contains(entry);
        boolean sinkReverse = !terminal.isBlank() && sinkReverseMethods.contains(terminal);
        if (!applicationScopeKnown) {
            return new DemandDecision(DemandStatus.APPLICATION_SCOPE_UNKNOWN, entry, terminal,
                    entryForward, sinkReverse, continuationEvidence);
        }
        if (!entryKnown) {
            return new DemandDecision(DemandStatus.ENTRY_NOT_APPLICATION, entry, terminal,
                    entryForward, sinkReverse, continuationEvidence);
        }
        if (!entryForward) {
            return new DemandDecision(DemandStatus.ENTRY_NOT_FORWARD_REACHABLE, entry, terminal,
                    false, sinkReverse, continuationEvidence);
        }
        if (!terminalHostMethods.contains(terminal)) {
            return new DemandDecision(DemandStatus.TERMINAL_NOT_INDEXED, entry, terminal,
                    true, sinkReverse, continuationEvidence);
        }
        if (!sinkReverse) {
            return new DemandDecision(DemandStatus.TERMINAL_NOT_REVERSE_REACHABLE, entry, terminal,
                    true, false, continuationEvidence);
        }
        if (entryTerminalMethods.contains(entry)) {
            return new DemandDecision(DemandStatus.ENTRY_TERMINAL_INTERSECTION, entry, terminal,
                    true, true, continuationEvidence);
        }
        if (continuationEvidence) {
            return new DemandDecision(DemandStatus.BRIDGE_CONTINUATION, entry, terminal,
                    true, true, true);
        }
        return new DemandDecision(DemandStatus.ENTRY_NOT_IN_TERMINAL_DEMAND, entry, terminal,
                true, true, false);
    }

    /**
     * Admit a raw chain to the joiner's expensive materialization path only when its entry
     * owner is application-owned and its terminal impact is indexed in the sink-reverse slice.
     * Application helpers are accepted from the typed forward slice and reflective binding
     * callbacks from the exact target-type fact.  This is a candidate filter, not a completed
     * join; callers must retain the returned reason for every rejected raw chain.
     */
    public CandidateAdmissionDecision candidateAdmission(String entryOwner, String entryName,
                                                         String entryDescriptor,
                                                         String terminalOwner,
                                                         String terminalName,
                                                         String terminalDescriptor,
                                                         boolean continuationEvidence) {
        return candidateAdmission(entryOwner, entryName, entryDescriptor, terminalOwner,
                terminalName, terminalDescriptor, continuationEvidence, null, false);
    }

    /** Internal admission path allowing a producer to reuse its already-resolved terminal. */
    private CandidateAdmissionDecision candidateAdmission(String entryOwner, String entryName,
                                                          String entryDescriptor,
                                                          String terminalOwner,
                                                          String terminalName,
                                                          String terminalDescriptor,
                                                          boolean continuationEvidence,
                                                          TerminalDecision resolvedTerminal) {
        return candidateAdmission(entryOwner, entryName, entryDescriptor, terminalOwner,
                terminalName, terminalDescriptor, continuationEvidence, resolvedTerminal, false);
    }

    /** Internal trigger admission may cross the ordinary entry slice only after typed OIS evidence. */
    private CandidateAdmissionDecision candidateAdmission(String entryOwner, String entryName,
                                                          String entryDescriptor,
                                                          String terminalOwner,
                                                          String terminalName,
                                                          String terminalDescriptor,
                                                          boolean continuationEvidence,
                                                          TerminalDecision resolvedTerminal,
                                                          boolean serializedTriggerContinuation) {
        String owner = entryOwner == null ? "" : entryOwner;
        String name = entryName == null ? "" : entryName;
        String descriptor = entryDescriptor == null ? "" : entryDescriptor;
        String entryKey = methodKey(owner, name, descriptor);
        String sinkOwner = terminalOwner == null ? "" : terminalOwner;
        String sinkName = terminalName == null ? "" : terminalName;
        String sinkDescriptor = terminalDescriptor == null ? "" : terminalDescriptor;
        boolean entryForward = entryForwardMethods.contains(entryKey);
        boolean bindingCallback = isApplicationBindingCallback(owner, name, descriptor);
        boolean bindingTarget = isApplicationBindingTarget(owner, name, descriptor);
        if (!applicationScopeKnown) {
            return new CandidateAdmissionDecision(CandidateAdmissionStatus.APPLICATION_SCOPE_UNKNOWN,
                    entryKey, sinkOwner, sinkName, sinkDescriptor, entryForward, false,
                    continuationEvidence);
        }
        if (!isApplicationOwner(owner) && !bindingTarget) {
            return new CandidateAdmissionDecision(
                    CandidateAdmissionStatus.APPLICATION_ENTRY_NOT_IN_CHAIN, entryKey,
                    sinkOwner, sinkName, sinkDescriptor, entryForward, false,
                    continuationEvidence);
        }
        if (!applicationEntryMethods.contains(entryKey) && !entryForward
                && !bindingCallback && !bindingTarget && !serializedTriggerContinuation) {
            return new CandidateAdmissionDecision(
                    CandidateAdmissionStatus.ENTRY_NOT_FORWARD_REACHABLE, entryKey,
                    sinkOwner, sinkName, sinkDescriptor, false, false,
                    continuationEvidence);
        }
        TerminalDecision terminal = resolvedTerminal == null
                ? terminalAdmission(sinkOwner, sinkName, sinkDescriptor) : resolvedTerminal;
        if (terminal.status() == TerminalStatus.NOT_INDEXED) {
            return new CandidateAdmissionDecision(
                    CandidateAdmissionStatus.TERMINAL_IMPACT_NOT_INDEXED, entryKey,
                    sinkOwner, sinkName, sinkDescriptor, entryForward, false,
                    continuationEvidence);
        }
        if (terminal.status() == TerminalStatus.INTERMEDIATE_ONLY) {
            return new CandidateAdmissionDecision(
                    CandidateAdmissionStatus.TERMINAL_IMPACT_IS_INTERMEDIATE, entryKey,
                    sinkOwner, sinkName, sinkDescriptor, entryForward, false,
                    continuationEvidence);
        }
        boolean sinkReverse = sinkReverseMethods.contains(terminal.hostMethodKey());
        if (!sinkReverse) {
            return new CandidateAdmissionDecision(
                    CandidateAdmissionStatus.TERMINAL_NOT_REVERSE_REACHABLE, entryKey,
                    sinkOwner, sinkName, sinkDescriptor, entryForward, false,
                    continuationEvidence);
        }
        // A plain call-graph candidate must already lie in the entry-forward ∩
        // terminal-reverse demand slice before its path supplier is allowed to run.  Typed
        // bridge/continuation candidates are the only exception: their explicit semantic edge
        // may connect two graph slices that do not intersect in ordinary CPG edges, and the
        // later joiner still verifies the concrete bridge evidence.  This keeps the default
        // solver from materializing globally reachable but irrelevant chains only to discard
        // them after a full join walk.
        if (!entryTerminalMethods.contains(entryKey) && !continuationEvidence
                && !bindingCallback && !bindingTarget) {
            return new CandidateAdmissionDecision(
                    CandidateAdmissionStatus.ENTRY_NOT_IN_TERMINAL_DEMAND, entryKey,
                    sinkOwner, sinkName, sinkDescriptor, entryForward, true,
                    false);
        }
        return new CandidateAdmissionDecision(CandidateAdmissionStatus.ADMITTED, entryKey,
                sinkOwner, sinkName, sinkDescriptor, entryForward, true, continuationEvidence);
    }

    /** Resolve a cheap producer descriptor without reading or constructing its path payload. */
    public ProducerAdmissionDecision producerAdmission(ProducerCandidate candidate) {
        if (candidate == null) {
            CandidateAdmissionDecision missing = new CandidateAdmissionDecision(
                    CandidateAdmissionStatus.APPLICATION_ENTRY_NOT_IN_CHAIN, "", "", "", "",
                    false, false, false);
            return new ProducerAdmissionDecision(ProducerAdmissionStatus.REJECTED, missing,
                    new TerminalDecision(TerminalStatus.NOT_INDEXED, "", "", "", -1, ""),
                    false);
        }
        TerminalDecision terminal = terminalAdmission(candidate.terminalOwner(),
                candidate.terminalName(), candidate.terminalDescriptor());
        boolean serializedTriggerContinuation = candidate.continuationEvidence()
                && SERIALIZED_TRIGGER_ENTRY_KINDS.contains(candidate.entryKind())
                && isApplicationOwner(candidate.entryOwner());
        CandidateAdmissionDecision admission = candidateAdmission(candidate.entryOwner(),
                candidate.entryName(), candidate.entryDescriptor(), candidate.terminalOwner(),
                candidate.terminalName(), candidate.terminalDescriptor(),
                candidate.continuationEvidence(), terminal, serializedTriggerContinuation);
        if (!applicationScopeKnown) {
            return new ProducerAdmissionDecision(ProducerAdmissionStatus.KERNEL_ONLY,
                    admission, terminal, candidate.continuationEvidence());
        }
        if (admission.admitted() && serializedTriggerContinuation) {
            return new ProducerAdmissionDecision(ProducerAdmissionStatus.BRIDGE_CONTINUATION,
                    admission, terminal, true);
        }
        if (admission.admitted()) {
            return new ProducerAdmissionDecision(ProducerAdmissionStatus.APPLICATION_CHAIN,
                    admission, terminal, candidate.continuationEvidence());
        }
        if (admission.status() == CandidateAdmissionStatus.TERMINAL_IMPACT_IS_INTERMEDIATE
                && candidate.continuationEvidence()
                && isApplicationOwner(candidate.entryOwner())
                && (admission.entryForward() || applicationEntryMethods.contains(
                        admission.entryMethodKey())
                || isApplicationBindingCallback(candidate.entryOwner(), candidate.entryName(),
                        candidate.entryDescriptor()))) {
            // An application-owned prefix that currently ends at a typed capability/bridge is
            // still a valid application candidate.  Keep it in the default audit product so
            // the composition phase can attach the later terminal suffix; it is not eligible
            // for strict export until the immutable evidence state reaches IMPACT_COMPLETE.
            return new ProducerAdmissionDecision(ProducerAdmissionStatus.APPLICATION_CHAIN,
                    admission, terminal, true);
        }
        if (admission.status() == CandidateAdmissionStatus.TERMINAL_IMPACT_IS_INTERMEDIATE
                && candidate.continuationEvidence()) {
            return new ProducerAdmissionDecision(ProducerAdmissionStatus.BRIDGE_CONTINUATION,
                    admission, terminal, true);
        }
        boolean reverseReachableTerminal = terminal.admitted()
                && sinkReverseMethods.contains(terminal.hostMethodKey());
        if (reverseReachableTerminal && !isApplicationOwner(candidate.entryOwner())
                && !candidate.entryOwner().isBlank() && !candidate.entryName().isBlank()) {
            return new ProducerAdmissionDecision(ProducerAdmissionStatus.DEPENDENCY_SUFFIX,
                    admission, terminal, candidate.continuationEvidence());
        }
        return new ProducerAdmissionDecision(ProducerAdmissionStatus.REJECTED, admission,
                terminal, candidate.continuationEvidence());
    }

    /** Derive bridge continuation only from typed path hops, never from class-name similarity. */
    public boolean hasSemanticContinuation(List<ChainHop> hops) {
        if (hops == null) {
            return false;
        }
        if (hasTypedContinuationEvidence(hops)) {
            return true;
        }
        for (ChainHop hop : hops) {
            if (hop == null) {
                continue;
            }
            if (hop.kind() == HopKind.ENTRY && isApplicationOwner(hop.fromOwner())
                    && !isApplicationOwner(hop.toOwner())) {
                return true;
            }
        }
        return false;
    }

    /** Typed protocol/secondary-deserialization continuation independent of application scope. */
    public static boolean hasTypedContinuationEvidence(String reason) {
        String value = reason == null ? ""
                : reason.toLowerCase(java.util.Locale.ROOT);
        return value.contains("jndi") || value.contains("rmi") || value.contains("lookup")
                || value.contains("jdbc") || value.contains("driver")
                || value.contains("second") || value.contains("remote")
                || value.contains("response") || value.contains("reflect")
                || value.contains("method-handle") || value.contains("method-collection")
                || value.contains("serialized-proxy") || value.contains("native-callback")
                || value.contains("serialized-trigger")
                || value.startsWith("bridge-");
    }

    /** Typed protocol/secondary-deserialization continuation independent of application scope. */
    public static boolean hasTypedContinuationEvidence(List<ChainHop> hops) {
        if (hops == null) {
            return false;
        }
        for (ChainHop hop : hops) {
            if (hop == null) {
                continue;
            }
            if (hasTypedContinuationEvidence(hop.reason())) {
                return true;
            }
        }
        return false;
    }

    private static String entryDescriptor(Chain chain) {
        if (chain == null || chain.hops() == null) {
            return "";
        }
        for (ChainHop hop : chain.hops()) {
            if (hop != null && hop.kind() == HopKind.ENTRY && hop.desc() != null
                    && !hop.desc().isBlank()) {
                return hop.desc();
            }
        }
        return "";
    }

    private static String text(String value) {
        return value == null ? "" : value;
    }

    private static List<String> forwardSlice(Graph graph, Map<String, Node> methods,
                                             Set<String> roots, List<String> reasons) {
        Set<String> visited = new TreeSet<>();
        Deque<String> work = new ArrayDeque<>(roots);
        while (!work.isEmpty()) {
            String key = work.removeFirst();
            if (!visited.add(key)) {
                continue;
            }
            if (visited.size() >= MAX_SLICE_METHODS) {
                reasons.add("ENTRY_FORWARD_SLICE_CAP:" + MAX_SLICE_METHODS);
                break;
            }
            Node method = methods.get(key);
            if (method == null) {
                continue;
            }
            for (Node call : graph.callsOfMethod(key)) {
                for (Edge edge : call.out()) {
                    if (!isCallEdge(edge)) {
                        continue;
                    }
                    Node target = edge.to();
                    String targetKey = methodKey(target.owner(), target.name(), target.descriptor());
                    if (!visited.contains(targetKey)) {
                        work.addLast(targetKey);
                    }
                }
            }
        }
        return List.copyOf(visited);
    }

    private static List<String> reverseSlice(Graph graph, Set<String> sinkHosts,
                                             List<String> reasons) {
        Map<String, Set<String>> callersByCallee = new HashMap<>();
        for (Node call : graph.nodesOfType(NodeType.CALL)) {
            String caller = methodKey(call.methodOwner(), call.methodName(), call.methodDescriptor());
            for (Edge edge : call.out()) {
                if (!isCallEdge(edge)) {
                    continue;
                }
                String callee = methodKey(edge.to().owner(), edge.to().name(), edge.to().descriptor());
                callersByCallee.computeIfAbsent(callee, ignored -> new TreeSet<>()).add(caller);
            }
        }
        Set<String> visited = new TreeSet<>();
        Deque<String> work = new ArrayDeque<>(sinkHosts);
        while (!work.isEmpty()) {
            String callee = work.removeFirst();
            if (!visited.add(callee)) {
                continue;
            }
            if (visited.size() >= MAX_SLICE_METHODS) {
                reasons.add("SINK_REVERSE_SLICE_CAP:" + MAX_SLICE_METHODS);
                break;
            }
            for (String caller : callersByCallee.getOrDefault(callee, Set.of())) {
                if (!visited.contains(caller)) {
                    work.addLast(caller);
                }
            }
        }
        return List.copyOf(visited);
    }

    private static boolean isCallEdge(Edge edge) {
        return edge != null && (edge.type() == EdgeType.INVOKES
                || edge.type() == EdgeType.DISPATCHES || edge.type() == EdgeType.LAMBDA);
    }

    private static boolean isUnconditionalDeserialize(Rule.SourceRule source) {
        return source != null && !"serialize".equalsIgnoreCase(source.bridge())
                && (source.tainted() == null || source.tainted().isEmpty());
    }

    /**
     * Project one source call into the host/frame shape needed by composition.  This keeps
     * subtype-aware ObjectInputStream recognition and framework bridge matching in the index
     * owner; consumers must not rescan raw call nodes to reconstruct the same fact.
     */
    private static DeserializeHost deserializeHost(Node call, Rule.SourceRule source,
                                                   boolean directOisRead, RuleEngine rules) {
        if (call == null) {
            return null;
        }
        String frameOwner = call.owner();
        String frameMethod = call.name();
        String frameDescriptor = call.descriptor();
        boolean subtypeOisRead = rules != null && frameOwner != null
                && rules.isSubtypeOf(frameOwner, "java/io/ObjectInputStream")
                && ("readObject".equals(frameMethod) || "readUnshared".equals(frameMethod)
                || "readFields".equals(frameMethod));
        boolean deserializeBridge = source != null
                && "deserialize".equalsIgnoreCase(source.bridge());
        if ((!directOisRead && !subtypeOisRead && !deserializeBridge)
                || call.methodOwner() == null || call.methodName() == null) {
            return null;
        }
        String hostOwner = call.methodOwner();
        String hostName = call.methodName();
        String hostDescriptor = call.methodDescriptor();
        if (isJdkInternal(hostOwner) || frameOwner == null || frameOwner.isBlank()
                || frameMethod == null || frameMethod.isBlank()) {
            return null;
        }
        int slash = frameOwner.lastIndexOf('/');
        String framePackage = slash > 0 ? frameOwner.substring(0, slash + 1) : frameOwner;
        if (hostOwner.startsWith(framePackage)) {
            return null;
        }
        return new DeserializeHost(methodKey(hostOwner, hostName, hostDescriptor), hostOwner,
                hostName, hostDescriptor, frameOwner, frameMethod, frameDescriptor);
    }

    private static boolean isJdkInternal(String owner) {
        if (owner == null || owner.isBlank()) {
            return false;
        }
        return owner.startsWith("java/") || owner.startsWith("javax/")
                || owner.startsWith("sun/") || owner.startsWith("com/sun/")
                || owner.startsWith("jdk/") || owner.startsWith("org/w3c/")
                || owner.startsWith("org/xml/") || owner.startsWith("org/omg/");
    }

    private static boolean isPlatformOwner(String owner) {
        return owner != null && (owner.startsWith("java/") || owner.startsWith("javax/")
                || owner.startsWith("jdk/") || owner.startsWith("sun/")
                || owner.startsWith("com/sun/"));
    }

    private static boolean isApplicationInputSite(DeserializeSite site) {
        return site != null && site.applicationOwned() && site.externalInput()
                && !"serialize".equalsIgnoreCase(site.bridge());
    }

    private static boolean isTypedBindingBridge(String bridge) {
        String value = bridge == null ? "" : bridge.toLowerCase(java.util.Locale.ROOT);
        return value.contains("deserialize") || value.contains("bind")
                || value.contains("bean") || value.contains("json")
                || value.contains("yaml") || value.contains("xml");
    }

    private static boolean isExecutionEntryRule(Rule.MagicEntryRule rule) {
        if (rule == null || "serialize".equalsIgnoreCase(rule.direction())) {
            return false;
        }
        String kind = rule.entryKind();
        return kind != null && !"proxyInvoke".equals(kind)
                && !Set.of("hashCode", "equals", "compareTo", "compare", "toString")
                .contains(kind);
    }

    private record FrameworkEntry(String entryKind, boolean bindingCapable,
                                  boolean externalControlProven) {
    }

    private static FrameworkEntry frameworkEntry(Node method, Map<String, Node> methods,
                                                 Map<String, Set<String>> methodAnnotationByKey,
                                                 Map<String, Set<String>> classAnnotationByOwner) {
        if (method == null || method.owner() == null || method.name() == null
                || "<init>".equals(method.name()) || "<clinit>".equals(method.name())) {
            return null;
        }
        int access = intNote(method, "methodAccess");
        Set<String> methodAnnotations = annotationDescriptors(method, "methodAnnotationDescriptors");
        Set<String> classAnnotations = annotationDescriptors(method, "classAnnotationDescriptors");
        String methodKey = methodKey(method.owner(), method.name(), method.descriptor());
        // Interface-declared service annotations are inherited by the implementation at the
        // framework boundary, but are not copied into the implementation class file.  Join
        // the immutable class/method annotation facts by the JVM signature rather than by a
        // benchmark class name.  This covers JAX-WS/CXF (and similar interface-first APIs)
        // without treating every public implementation method as an entry.
        boolean interfaceWebService = false;
        Object interfaces = method.note("classInterfaces");
        if (interfaces instanceof Iterable<?> values) {
            for (Object value : values) {
                if (value == null) {
                    continue;
                }
                String interfaceOwner = value.toString();
                if (!intersects(classAnnotationByOwner.getOrDefault(interfaceOwner, Set.of()),
                        WEB_SERVICE_ANNOTATIONS)) {
                    continue;
                }
                String interfaceKey = methodKey(interfaceOwner, method.name(), method.descriptor());
                if (intersects(methodAnnotationByKey.getOrDefault(interfaceKey, Set.of()),
                        SERVICE_METHOD_ANNOTATIONS)) {
                    interfaceWebService = true;
                    break;
                }
            }
        }
        boolean mapped = intersects(methodAnnotations, HTTP_METHOD_ANNOTATIONS);
        boolean httpClass = intersects(classAnnotations, HTTP_CLASS_ANNOTATIONS);
        boolean webService = intersects(classAnnotations, WEB_SERVICE_ANNOTATIONS)
                || interfaceWebService;
        boolean servlet = servletType(method);

        if ("main".equals(method.name()) && "([Ljava/lang/String;)V".equals(method.descriptor())
                && Modifier.isStatic(access)) {
            return new FrameworkEntry("lifecycle-main", false, false);
        }
        // HttpServlet overrides are commonly protected (the public boundary is the servlet
        // container, not Java visibility).  Keep private helpers out while accepting public
        // or protected lifecycle callbacks with request/response parameters.
        if (servlet && SERVLET_LIFECYCLE.contains(method.name())
                && (Modifier.isPublic(access) || Modifier.isProtected(access))) {
            boolean binding = hasReferenceParameter(method.descriptor());
            return new FrameworkEntry("servlet-lifecycle", binding, binding);
        }
        // All annotation/service boundaries below are Java public API methods.  A protected
        // helper with a copied annotation is not an external execution root.
        if (!Modifier.isPublic(access)) {
            return null;
        }
        if (mapped && (httpClass || !methodAnnotations.isEmpty())) {
            boolean binding = hasReferenceParameter(method.descriptor());
            return new FrameworkEntry("framework-http", binding, binding);
        }
        if (webService && (intersects(methodAnnotations, SERVICE_METHOD_ANNOTATIONS)
                || interfaceWebService || hasReferenceParameter(method.descriptor()))) {
            boolean binding = hasReferenceParameter(method.descriptor());
            // An @WebMethod declared on a @WebService interface is a typed service boundary;
            // its parameters are externally supplied by the SOAP runtime.  A class annotation
            // alone remains application-only until a method-level operation is present.
            return new FrameworkEntry("framework-service", binding,
                    binding && (interfaceWebService || intersects(methodAnnotations,
                            SERVICE_METHOD_ANNOTATIONS)));
        }
        return null;
    }

    private static boolean servletType(Node method) {
        Set<String> types = new TreeSet<>();
        String superName = method.note("classSuperName") == null ? null
                : method.note("classSuperName").toString();
        if (superName != null) {
            types.add(superName);
        }
        Object interfaces = method.note("classInterfaces");
        if (interfaces instanceof Iterable<?> values) {
            for (Object value : values) {
                if (value != null) {
                    types.add(value.toString());
                }
            }
        }
        return types.stream().anyMatch(type -> SERVLET_TYPES.contains(type)
                || type.endsWith("/Servlet") || type.endsWith("/Filter"));
    }

    private static boolean intersects(Set<String> values, Set<String> wanted) {
        for (String value : values) {
            if (wanted.contains(value)) {
                return true;
            }
        }
        return false;
    }

    private static Set<String> annotationDescriptors(Node method, String key) {
        Object value = method.note(key);
        if (!(value instanceof Iterable<?> values)) {
            return Set.of();
        }
        Set<String> result = new TreeSet<>();
        for (Object item : values) {
            if (item != null && !item.toString().isBlank()) {
                result.add(item.toString());
            }
        }
        return result;
    }

    /**
     * Return constant auto-type package prefixes observed at a parser configuration boundary.
     * The CPG carries only a small frontend-owned literal window, so this method is both
     * deterministic and conservative: absent or non-constant configuration yields no prefix.
     */
    private static Set<String> acceptedTypePrefixes(Graph graph) {
        if (graph == null) {
            return Set.of();
        }
        Set<String> prefixes = new TreeSet<>();
        for (Node call : graph.nodesOfType(NodeType.CALL)) {
            if (!"com/alibaba/fastjson/parser/ParserConfig".equals(call.owner())
                    || !"addAccept".equals(call.name())) {
                continue;
            }
            Object hints = call.note("stringLiteralHints");
            if (!(hints instanceof Iterable<?> values)) {
                continue;
            }
            for (Object value : values) {
                if (value == null) {
                    continue;
                }
                String prefix = value.toString().trim().replace('.', '/');
                if (prefix.isBlank() || prefix.length() > 256 || !prefix.endsWith("/")) {
                    continue;
                }
                // A package prefix must not contain wildcards, descriptors, or path escapes.
                if (prefix.contains("*") || prefix.contains("[") || prefix.contains("..")) {
                    continue;
                }
                prefixes.add(prefix);
            }
        }
        return Set.copyOf(prefixes);
    }

    private static List<String> referenceParameterTypes(String descriptor) {
        if (descriptor == null || descriptor.isBlank()) {
            return List.of();
        }
        List<String> result = new ArrayList<>();
        try {
            for (int i = 0, count = Descriptor.paramCount(descriptor); i < count; i++) {
                String type = Descriptor.paramType(descriptor, i);
                if (type == null || type.isBlank()) {
                    continue;
                }
                if (type.startsWith("L") && type.endsWith(";")) {
                    result.add(type.substring(1, type.length() - 1));
                } else if (type.startsWith("[L") && type.endsWith(";")) {
                    result.add(type.substring(2, type.length() - 1));
                }
            }
        } catch (RuntimeException ignored) {
            return List.of();
        }
        return result.stream().filter(value -> !value.isBlank()).distinct().sorted().toList();
    }

    /**
     * Read the bounded, frontend-owned class-literal facts attached to a binding call.  The
     * index never recovers a target type from a free-form note or class-name similarity; an
     * absent/ill-typed note is simply an untyped binding site.
     */
    private static List<String> classLiteralHints(Node call) {
        if (call == null) {
            return List.of();
        }
        Object value = call.note("classLiteralHints");
        if (!(value instanceof Iterable<?> values)) {
            return List.of();
        }
        return java.util.stream.StreamSupport.stream(values.spliterator(), false)
                .filter(java.util.Objects::nonNull)
                .map(Object::toString)
                .filter(name -> !name.isBlank() && name.indexOf('.') < 0
                        && name.indexOf('[') < 0)
                .distinct().sorted().toList();
    }

    private static int intNote(Node method, String key) {
        Object value = method.note(key);
        if (value instanceof Number number) {
            return number.intValue();
        }
        return value == null ? 0 : Integer.parseInt(value.toString());
    }

    private static boolean isPublicMethod(Node method) {
        return method != null && Modifier.isPublic(intNote(method, "methodAccess"));
    }

    private static boolean isPublicBeanSetter(Node method) {
        if (method == null || !isPublicMethod(method)
                || Modifier.isStatic(intNote(method, "methodAccess"))
                || method.name() == null || !method.name().startsWith("set")) {
            return false;
        }
        try {
            return Descriptor.paramCount(method.descriptor()) == 1;
        } catch (RuntimeException ignored) {
            return false;
        }
    }

    private static boolean hasReferenceParameter(String descriptor) {
        try {
            for (int i = 0, count = Descriptor.paramCount(descriptor); i < count; i++) {
                String type = Descriptor.paramType(descriptor, i);
                if (type != null && (type.startsWith("L") || type.startsWith("["))) {
                    return true;
                }
            }
        } catch (RuntimeException ignored) {
            // A malformed descriptor is a parser diagnostic elsewhere, not an entry guess.
        }
        return false;
    }

    private String digestCanonical() {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            update(digest, "application-entry-index-v" + MODEL_VERSION);
            update(digest, "scope=" + applicationScopeKnown);
            applicationOwners.forEach(value -> update(digest, "owner=" + value));
            executionEntries.forEach(value -> update(digest, "entry=" + value));
            deserializeSites.forEach(value -> update(digest, "site=" + value));
            terminalImpacts.forEach(value -> update(digest, "impact=" + value));
            entryForwardSlice.forEach(value -> update(digest, "forward=" + value));
            sinkReverseSlice.forEach(value -> update(digest, "reverse=" + value));
            entryTerminalIntersection.forEach(value -> update(digest, "intersection=" + value));
            dependencyCandidates.forEach(value -> update(digest, "dependency=" + value));
            completenessReasons.forEach(value -> update(digest, "reason=" + value));
            StringBuilder result = new StringBuilder(64);
            for (byte value : digest.digest()) {
                result.append(String.format("%02x", value & 0xff));
            }
            return result.toString();
        } catch (NoSuchAlgorithmException impossible) {
            throw new AssertionError(impossible);
        }
    }

    private static void update(MessageDigest digest, String value) {
        digest.update(value.getBytes(StandardCharsets.UTF_8));
        digest.update((byte) '\n');
    }

    private static void sortEntries(List<ExecutionEntry> entries) {
        entries.sort(Comparator.comparing(ExecutionEntry::methodKey)
                .thenComparing(ExecutionEntry::ruleId));
    }

    private static Set<String> normalizeOwners(Set<String> values) {
        if (values == null || values.isEmpty()) {
            return Set.of();
        }
        return values.stream().filter(value -> value != null && !value.isBlank())
                .map(String::trim).collect(java.util.stream.Collectors.toUnmodifiableSet());
    }

    private static Set<String> immutableSorted(Set<String> values) {
        return java.util.Collections.unmodifiableSet(new TreeSet<>(values));
    }

    private static Map<String, List<String>> immutableMemberIndex(Set<String> methodKeys) {
        Map<String, List<String>> grouped = new HashMap<>();
        for (String methodKey : methodKeys) {
            if (methodKey == null) {
                continue;
            }
            int hash = methodKey.indexOf('#');
            int descriptor = methodKey.indexOf('(', hash + 1);
            if (hash <= 0 || descriptor <= hash + 1) {
                continue;
            }
            String member = methodKey.substring(0, descriptor);
            grouped.computeIfAbsent(member, ignored -> new ArrayList<>()).add(methodKey);
        }
        Map<String, List<String>> result = new HashMap<>();
        grouped.forEach((member, values) -> {
            values.sort(String::compareTo);
            result.put(member, List.copyOf(values));
        });
        return Map.copyOf(result);
    }

    private static String methodKey(String owner, String name, String descriptor) {
        return requireText(owner, "owner") + "#" + requireText(name, "name")
                + (descriptor == null ? "" : descriptor);
    }

    private static String memberOfMethodKey(String methodKey) {
        if (methodKey == null) {
            return "";
        }
        int hash = methodKey.indexOf('#');
        int descriptor = methodKey.indexOf('(', hash + 1);
        return hash <= 0 || descriptor <= hash + 1 ? "" : methodKey.substring(0, descriptor);
    }

    private static String ownerOf(String key) {
        int separator = key == null ? -1 : key.indexOf('#');
        return separator <= 0 ? "" : key.substring(0, separator);
    }

    private static String requireText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
        return value;
    }
}
