package io.just.sast.analysis.entry;

import io.just.sast.analysis.taint.SerializationModel;
import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.EntryChainJoinEvidence;
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
import io.just.sast.model.ApplicationResourceFacts;
import io.just.sast.model.HttpExternalSource;
import io.just.sast.model.HttpHandlerValue;
import io.just.sast.model.LambdaMetafactoryCallSite;

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

    public static final int MODEL_VERSION = 9;
    public static final String HTTP_SERVER_OWNER = "com/sun/net/httpserver/HttpServer";
    public static final String HTTP_SERVER_CREATE_CONTEXT_NAME = "createContext";
    public static final String HTTP_SERVER_CREATE_CONTEXT_DESCRIPTOR =
            "(Ljava/lang/String;Lcom/sun/net/httpserver/HttpHandler;)"
                    + "Lcom/sun/net/httpserver/HttpContext;";
    public static final String HTTP_HANDLER_DESCRIPTOR =
            "Lcom/sun/net/httpserver/HttpHandler;";
    public static final String HTTP_HANDLER_OWNER = "com/sun/net/httpserver/HttpHandler";
    public static final String HTTP_HANDLER_HANDLE_NAME = "handle";
    public static final String HTTP_HANDLER_HANDLE_DESCRIPTOR =
            "(Lcom/sun/net/httpserver/HttpExchange;)V";
    public static final String HTTP_EXCHANGE_OWNER = "com/sun/net/httpserver/HttpExchange";
    public static final String HTTP_HEADERS_OWNER = "com/sun/net/httpserver/Headers";
    public static final String HTTP_URI_OWNER = "java/net/URI";
    public static final String JAVA_INPUT_STREAM_OWNER = "java/io/InputStream";
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

    /** Immutable CXF endpoint registration fact recovered from application bytecode. */
    public record ServiceEndpoint(String configurationMethodKey, String serviceMethodKey,
                                  String protocol, String publishPath) {
        public ServiceEndpoint {
            configurationMethodKey = requireText(configurationMethodKey,
                    "configurationMethodKey");
            serviceMethodKey = requireText(serviceMethodKey, "serviceMethodKey");
            protocol = requireText(protocol, "protocol");
            publishPath = requireText(publishPath, "publishPath");
        }
    }

    /** Knowledge state for a value carried by a typed call-site fact. */
    public enum ValueState {
        CONSTANT,
        UNKNOWN
    }

    /**
     * One JVM value position at a concrete call site.  The ordinal is -1 for the receiver and
     * otherwise is the zero-based callee argument ordinal.  Identity is deliberately derived
     * from the physical call site and position; it is not a class/name guess and does not claim
     * that two positions alias until a later typed origin/bridge owner proves it.
     */
    public record HttpContextValue(long callId, String hostMethodKey, int callOffset,
                                   int argumentOrdinal, String declaredDescriptor,
                                   ValueState state, String constantValue) {
        public HttpContextValue {
            if (callId < 0) {
                throw new IllegalArgumentException("callId must be non-negative");
            }
            hostMethodKey = requireText(hostMethodKey, "hostMethodKey");
            if (callOffset < 0) {
                throw new IllegalArgumentException("callOffset must be non-negative");
            }
            if (argumentOrdinal < -1) {
                throw new IllegalArgumentException("argumentOrdinal must be -1 or greater");
            }
            declaredDescriptor = requireText(declaredDescriptor, "declaredDescriptor");
            state = Objects.requireNonNull(state, "state");
            if (state == ValueState.CONSTANT && constantValue == null) {
                throw new IllegalArgumentException("constant value is required when known");
            }
            if (state == ValueState.UNKNOWN && constantValue != null) {
                throw new IllegalArgumentException("unknown value cannot carry a constant");
            }
        }

        /** Stable identity for this exact call-site value position. */
        public String identity() {
            return "call:" + callId + "@" + hostMethodKey + ":" + argumentOrdinal;
        }
    }

    /**
     * Exact application-owned {@code HttpServer.createContext(String,HttpHandler)} registration.
     * The API hit is a site-registration fact only; it is not an external source or terminal.
     */
    public record HttpContextRegistration(long callId, String hostMethodKey, int callOffset,
                                          HttpContextValue receiver, HttpContextValue path,
                                          HttpContextValue handler) {
        public HttpContextRegistration {
            if (callId < 0) {
                throw new IllegalArgumentException("callId must be non-negative");
            }
            hostMethodKey = requireText(hostMethodKey, "hostMethodKey");
            if (callOffset < 0) {
                throw new IllegalArgumentException("callOffset must be non-negative");
            }
            receiver = Objects.requireNonNull(receiver, "receiver");
            path = Objects.requireNonNull(path, "path");
            handler = Objects.requireNonNull(handler, "handler");
            validateValue(receiver, callId, hostMethodKey, callOffset, -1,
                    "L" + HTTP_SERVER_OWNER + ";");
            validateValue(path, callId, hostMethodKey, callOffset, 0, "Ljava/lang/String;");
            validateValue(handler, callId, hostMethodKey, callOffset, 1,
                    HTTP_HANDLER_DESCRIPTOR);
        }

        private static void validateValue(HttpContextValue value, long callId,
                                          String hostMethodKey, int callOffset,
                                          int ordinal, String descriptor) {
            if (value.callId() != callId || !hostMethodKey.equals(value.hostMethodKey())
                    || value.callOffset() != callOffset
                    || value.argumentOrdinal() != ordinal
                    || !descriptor.equals(value.declaredDescriptor())) {
                throw new IllegalArgumentException("HTTP context value does not match call site");
            }
        }
    }

    /** One actual graph edge proving how the registered handler value reaches its callback. */
    public record HttpHandlerEdge(long fromCallId, String fromMethodKey, String targetMethodKey,
                                  String callbackMethodKey, EdgeType edgeType, String label) {
        public HttpHandlerEdge {
            if (fromCallId < 0) {
                throw new IllegalArgumentException("fromCallId must be non-negative");
            }
            fromMethodKey = requireText(fromMethodKey, "fromMethodKey");
            targetMethodKey = requireText(targetMethodKey, "targetMethodKey");
            callbackMethodKey = requireText(callbackMethodKey, "callbackMethodKey");
            edgeType = Objects.requireNonNull(edgeType, "edgeType");
            label = requireText(label, "label");
        }
    }

    /**
     * Verified HTTP application site: one exact registration, one handler value origin, one
     * actual callback edge and at least one typed external request value source.
     */
    public record HttpSite(HttpContextRegistration registration, HttpHandlerValue handlerValue,
                           String handlerMethodKey, HttpHandlerEdge handlerEdge,
                           List<HttpExternalSource> externalSources) {
        public HttpSite {
            registration = Objects.requireNonNull(registration, "registration");
            handlerValue = Objects.requireNonNull(handlerValue, "handlerValue");
            if (!registration.hostMethodKey().equals(handlerValue.hostMethodKey())) {
                throw new IllegalArgumentException("handler value host does not match registration");
            }
            handlerMethodKey = requireText(handlerMethodKey, "handlerMethodKey");
            handlerEdge = Objects.requireNonNull(handlerEdge, "handlerEdge");
            if (!registration.hostMethodKey().equals(handlerEdge.fromMethodKey())
                    || handlerEdge.fromCallId() != expectedEdgeCallId(handlerValue)
                    || !handlerMethodKey.equals(handlerEdge.callbackMethodKey())) {
                throw new IllegalArgumentException("handler edge does not match HTTP site");
            }
            if (externalSources == null || externalSources.isEmpty()
                    || externalSources.stream().anyMatch(source -> source == null
                    || !source.externalInput())) {
                throw new IllegalArgumentException("HTTP site needs external value sources");
            }
            externalSources = externalSources.stream()
                    .sorted(Comparator.comparingLong(HttpExternalSource::callId)
                            .thenComparing(HttpExternalSource::apiKey))
                    .toList();
        }

        public String entryMethodKey() {
            return registration.hostMethodKey();
        }

        public String identity() {
            return "http-site:call:" + registration.callId() + "->" + handlerMethodKey;
        }

        private static long expectedEdgeCallId(HttpHandlerValue value) {
            return value.lambda() ? value.producerCallId() : value.constructionCallId();
        }
    }

    /** Immutable route-control fact from a concrete Servlet Filter implementation. */
    public record FilterControl(String methodKey, String pathPrefix, String blockedPath,
                                String blockedMethod, boolean remoteAddressGuard,
                                boolean passThrough, boolean pathNormalization) {
        public FilterControl {
            methodKey = requireText(methodKey, "methodKey");
            pathPrefix = pathPrefix == null ? "" : pathPrefix.trim();
            blockedPath = blockedPath == null ? "" : blockedPath.trim();
            blockedMethod = blockedMethod == null ? "" : blockedMethod.trim();
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
        ENTRY_NOT_IN_TERMINAL_DEMAND,
        /** A rule-declared configuration fragment reaches a static class-definition boundary. */
        DECLARED_FRAGMENT_CONTINUATION
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
            return status == CandidateAdmissionStatus.ADMITTED
                    || status == CandidateAdmissionStatus.DECLARED_FRAGMENT_CONTINUATION;
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
                                    SinkRisk sinkRisk, boolean continuationEvidence,
                                    boolean declaredApplicationContinuation,
                                    boolean declaredFragmentContinuation) {
        public ProducerCandidate(String ruleId, String category, String severity,
                                  String entryOwner, String entryName, String entryDescriptor,
                                  String entryKind, String terminalOwner, String terminalName,
                                  String terminalDescriptor, String terminalRole,
                                  SinkRisk sinkRisk, boolean continuationEvidence) {
            this(ruleId, category, severity, entryOwner, entryName, entryDescriptor, entryKind,
                    terminalOwner, terminalName, terminalDescriptor, terminalRole, sinkRisk,
                    continuationEvidence, false, false);
        }

        /** Compatibility constructor for callers that already declare an application continuation. */
        public ProducerCandidate(String ruleId, String category, String severity,
                                  String entryOwner, String entryName, String entryDescriptor,
                                  String entryKind, String terminalOwner, String terminalName,
                                  String terminalDescriptor, String terminalRole,
                                  SinkRisk sinkRisk, boolean continuationEvidence,
                                  boolean declaredApplicationContinuation) {
            this(ruleId, category, severity, entryOwner, entryName, entryDescriptor, entryKind,
                    terminalOwner, terminalName, terminalDescriptor, terminalRole, sinkRisk,
                    continuationEvidence, declaredApplicationContinuation, false);
        }

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
    private final List<ServiceEndpoint> serviceEndpoints;
    private final Map<String, List<ServiceEndpoint>> serviceEndpointsByMethod;
    private final List<FilterControl> filterControls;
    private final Map<String, EntryChainJoinEvidence.FilterDominance> filterDominanceByService;
    private final List<ApplicationResourceFacts.RouteBinding> routeBindings;
    private final Map<String, List<ApplicationResourceFacts.RouteBinding>> routeBindingsByMember;
    private final List<HttpContextRegistration> httpContextRegistrations;
    private final Map<String, List<HttpContextRegistration>> httpContextRegistrationsByMethod;
    private final List<HttpExternalSource> httpExternalSources;
    private final Map<String, List<HttpExternalSource>> httpExternalSourcesByMethod;
    private final List<HttpSite> httpSites;
    private final Map<String, List<HttpSite>> httpSitesByMethod;
    private final Set<String> applicationSiteRoots;
    private final List<DeserializeSite> secondaryDeserializeSites;
    private final Set<String> applicationObjectInputHosts;
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
                                  List<ServiceEndpoint> serviceEndpoints,
                                  List<FilterControl> filterControls,
                                  ApplicationResourceFacts resourceFacts,
                                  List<HttpContextRegistration> httpContextRegistrations,
                                  List<HttpExternalSource> httpExternalSources,
                                  List<HttpSite> httpSites,
                                  Set<String> applicationSiteRoots,
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
        this.serviceEndpoints = immutableServiceEndpoints(serviceEndpoints);
        this.serviceEndpointsByMethod = immutableServiceEndpointIndex(this.serviceEndpoints);
        this.filterControls = immutableFilterControls(filterControls);
        this.filterDominanceByService = immutableFilterDominanceIndex(this.serviceEndpoints,
                this.filterControls);
        ApplicationResourceFacts resources = resourceFacts == null
                ? ApplicationResourceFacts.empty() : resourceFacts;
        this.routeBindings = immutableRouteBindings(resources);
        this.routeBindingsByMember = immutableRouteBindingIndex(this.routeBindings);
        this.httpContextRegistrations = immutableHttpContextRegistrations(
                httpContextRegistrations);
        this.httpContextRegistrationsByMethod = immutableHttpContextRegistrationIndex(
                this.httpContextRegistrations);
        this.httpExternalSources = immutableHttpExternalSources(httpExternalSources);
        this.httpExternalSourcesByMethod = immutableHttpExternalSourceIndex(
                this.httpExternalSources);
        this.httpSites = immutableHttpSites(httpSites);
        this.httpSitesByMethod = immutableHttpSiteIndex(this.httpSites);
        this.applicationSiteRoots = immutableSorted(applicationSiteRoots);
        this.secondaryDeserializeSites = this.deserializeSites.stream()
                .filter(ApplicationEntryIndex::isSecondaryDeserializeSite)
                .toList();
        this.applicationObjectInputHosts = immutableSorted(this.deserializeSites.stream()
                .filter(ApplicationEntryIndex::isObjectInputStreamSite)
                .filter(DeserializeSite::applicationOwned)
                .map(DeserializeSite::hostMethodKey)
                .collect(java.util.stream.Collectors.toSet()));
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

    /** Discover only exact application-owned HttpServer context registrations. */
    private static List<HttpContextRegistration> discoverHttpContextRegistrations(
            Graph graph, Set<String> applicationOwners, boolean applicationScopeKnown) {
        if (graph == null || !applicationScopeKnown || applicationOwners.isEmpty()) {
            return List.of();
        }
        List<HttpContextRegistration> result = new ArrayList<>();
        for (Node call : graph.nodesOfType(NodeType.CALL)) {
            if (!applicationOwners.contains(call.methodOwner())
                    || !HTTP_SERVER_OWNER.equals(call.owner())
                    || !HTTP_SERVER_CREATE_CONTEXT_NAME.equals(call.name())
                    || !HTTP_SERVER_CREATE_CONTEXT_DESCRIPTOR.equals(call.descriptor())
                    || "DYNAMIC".equals(call.invokeKind())) {
                continue;
            }
            String hostMethodKey = methodKey(call.methodOwner(), call.methodName(),
                    call.methodDescriptor());
            result.add(new HttpContextRegistration(call.id(), hostMethodKey, call.offset(),
                    new HttpContextValue(call.id(), hostMethodKey, call.offset(), -1,
                            "L" + HTTP_SERVER_OWNER + ";", ValueState.UNKNOWN, null),
                    new HttpContextValue(call.id(), hostMethodKey, call.offset(), 0,
                            "Ljava/lang/String;", ValueState.UNKNOWN, null),
                    new HttpContextValue(call.id(), hostMethodKey, call.offset(), 1,
                            HTTP_HANDLER_DESCRIPTOR, ValueState.UNKNOWN, null)));
        }
        return immutableHttpContextRegistrations(result);
    }

    /** Discover exact request-header/query/body API facts from application-owned call sites. */
    private static List<HttpExternalSource> discoverHttpExternalSources(
            Graph graph, Set<String> applicationOwners, boolean applicationScopeKnown,
            RuleEngine rules) {
        if (graph == null || !applicationScopeKnown || applicationOwners.isEmpty()) {
            return List.of();
        }
        List<HttpExternalSource> result = new ArrayList<>();
        for (Node call : graph.nodesOfType(NodeType.CALL)) {
            if (call == null || !applicationOwners.contains(call.methodOwner())) {
                continue;
            }
            HttpSourceSpec spec = httpSourceSpec(call, rules);
            if (spec == null) {
                continue;
            }
            String hostMethodKey = methodKey(call.methodOwner(), call.methodName(),
                    call.methodDescriptor());
            List<HttpExternalSource.Slot> arguments = new ArrayList<>();
            for (int index = 0; index < spec.argumentDescriptors().size(); index++) {
                arguments.add(new HttpExternalSource.Slot(index,
                        spec.argumentDescriptors().get(index)));
            }
            result.add(new HttpExternalSource(call.id(), hostMethodKey, call.offset(),
                    spec.apiOwner(), spec.apiName(), spec.apiDescriptor(), spec.kind(),
                    spec.valueRole(), new HttpExternalSource.Slot(-1, spec.receiverDescriptor()),
                    arguments, spec.valueDescriptor()));
        }
        return immutableHttpExternalSources(result);
    }

    /**
     * Join one exact HTTP registration to its handler value, callback edge and request value.
     * Source facts are intentionally grouped by the exact callback method key; a source in the
     * registration host or a nearby method cannot satisfy this join.
     */
    private static List<HttpSite> discoverHttpSites(
            Graph graph, Set<String> applicationOwners, boolean applicationScopeKnown,
            List<ExecutionEntry> entries, List<HttpContextRegistration> registrations,
            List<HttpExternalSource> sources) {
        if (graph == null || !applicationScopeKnown || applicationOwners.isEmpty()
                || registrations == null || registrations.isEmpty()
                || sources == null || sources.isEmpty()) {
            return List.of();
        }
        Map<String, List<HttpExternalSource>> externalSourcesByMethod = new TreeMap<>();
        for (HttpExternalSource source : sources) {
            if (source == null || !source.externalInput()
                    || !applicationOwners.contains(ownerOf(source.hostMethodKey()))) {
                continue;
            }
            externalSourcesByMethod.computeIfAbsent(source.hostMethodKey(),
                    ignored -> new ArrayList<>()).add(source);
        }
        if (externalSourcesByMethod.isEmpty()) {
            return List.of();
        }

        List<HttpSite> result = new ArrayList<>();
        for (HttpContextRegistration registration : registrations) {
            if (registration == null
                    || !applicationOwners.contains(ownerOf(registration.hostMethodKey()))) {
                continue;
            }
            Node registrationCall = graph.node(registration.callId());
            if (!isHttpContextCall(registrationCall, registration)) {
                continue;
            }
            List<HttpHandlerValue> values = httpHandlerValues(registrationCall);
            if (values.size() != 1) {
                continue;
            }
            HttpHandlerValue value = values.get(0);
            HttpSite site = joinHttpHandler(graph, applicationOwners, entries, registration,
                    value, externalSourcesByMethod);
            if (site != null) {
                result.add(site);
            }
        }
        return immutableHttpSites(result);
    }

    private static HttpSite joinHttpHandler(
            Graph graph, Set<String> applicationOwners, List<ExecutionEntry> entries,
            HttpContextRegistration registration, HttpHandlerValue value,
            Map<String, List<HttpExternalSource>> externalSourcesByMethod) {
        if (value == null || !registration.hostMethodKey().equals(value.hostMethodKey())
                || value.producerOffset() < 0) {
            return null;
        }
        return switch (value.kind()) {
            case LAMBDA -> joinLambdaHandler(graph, applicationOwners, registration, value,
                    externalSourcesByMethod);
            case ALLOCATION -> joinAllocatedHandler(graph, applicationOwners, entries,
                    registration, value, externalSourcesByMethod);
        };
    }

    private static HttpSite joinLambdaHandler(
            Graph graph, Set<String> applicationOwners, HttpContextRegistration registration,
            HttpHandlerValue value, Map<String, List<HttpExternalSource>> externalSourcesByMethod) {
        if (!HTTP_HANDLER_DESCRIPTOR.equals(value.typeDescriptor())
                || value.producerCallId() < 0 || value.constructionCallId() != -1) {
            return null;
        }
        Node producer = graph.node(value.producerCallId());
        if (producer == null || producer.type() != NodeType.CALL
                || !registration.hostMethodKey().equals(methodKey(producer.methodOwner(),
                producer.methodName(), producer.methodDescriptor()))
                || producer.offset() != value.producerOffset()
                || !"DYNAMIC".equals(producer.invokeKind())) {
            return null;
        }
        Object note = producer.note("lambdaCallSite");
        if (!(note instanceof LambdaMetafactoryCallSite site)
                || !isHttpHandlerSam(site.functionalInterfaceMethod())) {
            return null;
        }
        List<Edge> lambdaEdges = producer.out().stream()
                .filter(edge -> edge.type() == EdgeType.LAMBDA)
                .toList();
        if (lambdaEdges.size() != 1) {
            return null;
        }
        Edge edge = lambdaEdges.get(0);
        Node target = edge.to();
        if (target == null || target.type() != NodeType.METHOD
                || !applicationOwners.contains(target.owner())
                || !site.implementation().name().equals(target.name())
                || !site.implementation().descriptor().equals(target.descriptor())) {
            return null;
        }
        String handlerMethodKey = methodKey(target.owner(), target.name(), target.descriptor());
        List<HttpExternalSource> externalSources = externalSourcesByMethod.getOrDefault(
                handlerMethodKey, List.of());
        if (externalSources.isEmpty()) {
            return null;
        }
        HttpHandlerEdge handlerEdge = new HttpHandlerEdge(producer.id(), registration.hostMethodKey(),
                handlerMethodKey, handlerMethodKey, edge.type(), edge.label());
        return new HttpSite(registration, value, handlerMethodKey, handlerEdge, externalSources);
    }

    private static HttpSite joinAllocatedHandler(
            Graph graph, Set<String> applicationOwners, List<ExecutionEntry> entries,
            HttpContextRegistration registration, HttpHandlerValue value,
            Map<String, List<HttpExternalSource>> externalSourcesByMethod) {
        if (value.producerCallId() != -1 || value.constructionCallId() < 0
                || !applicationOwners.contains(value.typeOwner())
                || !value.typeDescriptor().equals("L" + value.typeOwner() + ";")) {
            return null;
        }
        Node construction = graph.node(value.constructionCallId());
        if (construction == null || construction.type() != NodeType.CALL
                || !registration.hostMethodKey().equals(methodKey(construction.methodOwner(),
                construction.methodName(), construction.methodDescriptor()))
                || !value.typeOwner().equals(construction.owner())
                || !"<init>".equals(construction.name())
                || !"SPECIAL".equals(construction.invokeKind())) {
            return null;
        }
        List<Edge> constructorEdges = construction.out().stream()
                .filter(edge -> edge.type() == EdgeType.INVOKES
                        && edge.to() != null && edge.to().type() == NodeType.METHOD
                        && value.typeOwner().equals(edge.to().owner())
                        && "<init>".equals(edge.to().name())
                        && construction.descriptor().equals(edge.to().descriptor()))
                .toList();
        if (constructorEdges.size() != 1) {
            return null;
        }
        Edge constructorEdge = constructorEdges.get(0);
        String handlerMethodKey = methodKey(value.typeOwner(), HTTP_HANDLER_HANDLE_NAME,
                HTTP_HANDLER_HANDLE_DESCRIPTOR);
        if (!isHttpHandlerEntry(entries, handlerMethodKey)) {
            return null;
        }
        List<HttpExternalSource> externalSources = externalSourcesByMethod.getOrDefault(
                handlerMethodKey, List.of());
        if (externalSources.isEmpty()) {
            return null;
        }
        HttpHandlerEdge handlerEdge = new HttpHandlerEdge(construction.id(),
                registration.hostMethodKey(), methodKey(constructorEdge.to().owner(),
                constructorEdge.to().name(), constructorEdge.to().descriptor()), handlerMethodKey,
                constructorEdge.type(), constructorEdge.label());
        return new HttpSite(registration, value, handlerMethodKey, handlerEdge, externalSources);
    }

    private static boolean isHttpContextCall(Node call, HttpContextRegistration registration) {
        return call != null && call.type() == NodeType.CALL
                && call.id() == registration.callId()
                && registration.callOffset() == call.offset()
                && registration.hostMethodKey().equals(methodKey(call.methodOwner(),
                call.methodName(), call.methodDescriptor()))
                && HTTP_SERVER_OWNER.equals(call.owner())
                && HTTP_SERVER_CREATE_CONTEXT_NAME.equals(call.name())
                && HTTP_SERVER_CREATE_CONTEXT_DESCRIPTOR.equals(call.descriptor())
                && !"DYNAMIC".equals(call.invokeKind());
    }

    private static List<HttpHandlerValue> httpHandlerValues(Node call) {
        if (call == null) {
            return List.of();
        }
        Object note = call.note(HttpHandlerValue.GRAPH_NOTE_KEY);
        if (!(note instanceof Iterable<?> values)) {
            return List.of();
        }
        List<HttpHandlerValue> result = new ArrayList<>();
        for (Object value : values) {
            if (!(value instanceof HttpHandlerValue handlerValue)) {
                return List.of();
            }
            result.add(handlerValue);
        }
        return List.copyOf(result);
    }

    private static boolean isHttpHandlerSam(io.just.sast.model.MethodRef method) {
        return method != null && HTTP_HANDLER_OWNER.equals(method.owner())
                && HTTP_HANDLER_HANDLE_NAME.equals(method.name())
                && HTTP_HANDLER_HANDLE_DESCRIPTOR.equals(method.descriptor());
    }

    private static boolean isHttpHandlerEntry(List<ExecutionEntry> entries,
                                              String methodKey) {
        if (entries == null || methodKey == null || methodKey.isBlank()) {
            return false;
        }
        return entries.stream().anyMatch(entry -> entry.applicationOwned()
                && "http-handler".equals(entry.entryKind())
                && methodKey.equals(entry.methodKey()));
    }

    private static HttpSourceSpec httpSourceSpec(Node call, RuleEngine rules) {
        if (call == null || call.owner() == null || call.name() == null
                || call.descriptor() == null) {
            return null;
        }
        if (isExactOrSubtype(call.owner(), HTTP_EXCHANGE_OWNER, rules)) {
            if ("getRequestHeaders".equals(call.name())
                    && "()Lcom/sun/net/httpserver/Headers;".equals(call.descriptor())) {
                return new HttpSourceSpec(HttpExternalSource.Kind.HEADER,
                        HttpExternalSource.ValueRole.CONTAINER, HTTP_EXCHANGE_OWNER,
                        "getRequestHeaders", call.descriptor(), "L" + HTTP_EXCHANGE_OWNER + ";",
                        List.of(), "L" + HTTP_HEADERS_OWNER + ";");
            }
            if ("getRequestURI".equals(call.name())
                    && "()Ljava/net/URI;".equals(call.descriptor())) {
                return new HttpSourceSpec(HttpExternalSource.Kind.QUERY,
                        HttpExternalSource.ValueRole.CONTAINER, HTTP_EXCHANGE_OWNER,
                        "getRequestURI", call.descriptor(), "L" + HTTP_EXCHANGE_OWNER + ";",
                        List.of(), "L" + HTTP_URI_OWNER + ";");
            }
            if ("getRequestBody".equals(call.name())
                    && "()Ljava/io/InputStream;".equals(call.descriptor())) {
                return new HttpSourceSpec(HttpExternalSource.Kind.BODY,
                        HttpExternalSource.ValueRole.CONTAINER, HTTP_EXCHANGE_OWNER,
                        "getRequestBody", call.descriptor(), "L" + HTTP_EXCHANGE_OWNER + ";",
                        List.of(), "L" + JAVA_INPUT_STREAM_OWNER + ";");
            }
        }
        if (isExactOrSubtype(call.owner(), HTTP_HEADERS_OWNER, rules)
                && "getFirst".equals(call.name())
                && "(Ljava/lang/String;)Ljava/lang/String;".equals(call.descriptor())) {
            return new HttpSourceSpec(HttpExternalSource.Kind.HEADER,
                    HttpExternalSource.ValueRole.VALUE, HTTP_HEADERS_OWNER, "getFirst",
                    call.descriptor(), "L" + HTTP_HEADERS_OWNER + ";",
                    List.of("Ljava/lang/String;"), "Ljava/lang/String;");
        }
        if (isExactOrSubtype(call.owner(), HTTP_URI_OWNER, rules)
                && ("getQuery".equals(call.name()) || "getRawQuery".equals(call.name()))
                && "()Ljava/lang/String;".equals(call.descriptor())) {
            return new HttpSourceSpec(HttpExternalSource.Kind.QUERY,
                    HttpExternalSource.ValueRole.VALUE, HTTP_URI_OWNER, call.name(),
                    call.descriptor(), "L" + HTTP_URI_OWNER + ";", List.of(),
                    "Ljava/lang/String;");
        }
        if (isExactOrSubtype(call.owner(), JAVA_INPUT_STREAM_OWNER, rules)) {
            if ("read".equals(call.name())
                    && ("()I".equals(call.descriptor())
                    || "([B)I".equals(call.descriptor())
                    || "([BII)I".equals(call.descriptor()))) {
                return new HttpSourceSpec(HttpExternalSource.Kind.BODY,
                        HttpExternalSource.ValueRole.VALUE, JAVA_INPUT_STREAM_OWNER, "read",
                        call.descriptor(), "L" + JAVA_INPUT_STREAM_OWNER + ";",
                        bodyArgumentDescriptors(call.descriptor()),
                        "I");
            }
            if ("readAllBytes".equals(call.name()) && "()[B".equals(call.descriptor())) {
                return new HttpSourceSpec(HttpExternalSource.Kind.BODY,
                        HttpExternalSource.ValueRole.VALUE, JAVA_INPUT_STREAM_OWNER, "readAllBytes",
                        call.descriptor(), "L" + JAVA_INPUT_STREAM_OWNER + ";",
                        List.of(), "[B");
            }
            if ("readNBytes".equals(call.name())
                    && ("(I)[B".equals(call.descriptor())
                    || "([BII)I".equals(call.descriptor()))) {
                return new HttpSourceSpec(HttpExternalSource.Kind.BODY,
                        HttpExternalSource.ValueRole.VALUE, JAVA_INPUT_STREAM_OWNER, "readNBytes",
                        call.descriptor(), "L" + JAVA_INPUT_STREAM_OWNER + ";",
                        bodyArgumentDescriptors(call.descriptor()),
                        "(I)[B".equals(call.descriptor()) ? "[B" : "I");
            }
        }
        return null;
    }

    private static List<String> bodyArgumentDescriptors(String descriptor) {
        return switch (descriptor) {
            case "()I" -> List.of();
            case "([B)I" -> List.of("[B");
            case "([BII)I" -> List.of("[B", "I", "I");
            default -> List.of("I");
        };
    }

    private static boolean isExactOrSubtype(String owner, String target, RuleEngine rules) {
        return target.equals(owner) || (rules != null && rules.isSubtypeOf(owner, target));
    }

    private record HttpSourceSpec(HttpExternalSource.Kind kind,
                                  HttpExternalSource.ValueRole valueRole,
                                  String apiOwner,
                                  String apiName,
                                  String apiDescriptor,
                                  String receiverDescriptor,
                                  List<String> argumentDescriptors,
                                  String valueDescriptor) {
        private HttpSourceSpec {
            argumentDescriptors = List.copyOf(argumentDescriptors);
        }
    }

    /** Discover CXF endpoint registration from the constructor/publish call sequence. */
    private static List<ServiceEndpoint> discoverServiceEndpoints(
            Graph graph, List<ExecutionEntry> entries, Set<String> applicationOwners,
            boolean applicationScopeKnown) {
        if (graph == null || !applicationScopeKnown || applicationOwners.isEmpty()) {
            return List.of();
        }
        Map<String, List<String>> serviceMethodsByOwner = new TreeMap<>();
        for (ExecutionEntry entry : entries) {
            if (entry.applicationOwned() && "framework-service".equals(entry.entryKind())) {
                serviceMethodsByOwner.computeIfAbsent(entry.owner(), ignored -> new ArrayList<>())
                        .add(entry.methodKey());
            }
        }
        if (serviceMethodsByOwner.isEmpty()) {
            return List.of();
        }
        serviceMethodsByOwner.values().forEach(values -> values.sort(String::compareTo));
        List<ServiceEndpoint> result = new ArrayList<>();
        for (Node method : graph.nodesOfType(NodeType.METHOD)) {
            if (method == null || !applicationOwners.contains(method.owner())) {
                continue;
            }
            String configurationMethod = methodKey(method.owner(), method.name(),
                    method.descriptor());
            List<Node> calls = new ArrayList<>(graph.callsOfMethod(configurationMethod));
            calls.sort(Comparator.comparingLong(Node::id));
            Set<String> constructedServiceOwners = new TreeSet<>();
            boolean endpointConstructed = false;
            for (Node call : calls) {
                if (isApplicationServiceConstructor(call, serviceMethodsByOwner.keySet())) {
                    constructedServiceOwners.add(call.owner());
                }
                if (isCxfEndpointConstructor(call)) {
                    endpointConstructed = !constructedServiceOwners.isEmpty();
                    continue;
                }
                if (!endpointConstructed || !isCxfEndpointPublish(call)) {
                    continue;
                }
                String publishPath = firstPathLiteral(call);
                if (!publishPath.isBlank()) {
                    for (String serviceOwner : constructedServiceOwners) {
                        for (String serviceMethod : serviceMethodsByOwner.getOrDefault(
                                serviceOwner, List.of())) {
                            result.add(new ServiceEndpoint(configurationMethod, serviceMethod,
                                    "SOAP/CXF", publishPath));
                        }
                    }
                }
                endpointConstructed = false;
            }
        }
        return immutableServiceEndpoints(result);
    }

    /** Discover only concrete Filter#doFilter control facts from application bytecode. */
    private static List<FilterControl> discoverFilterControls(Graph graph,
                                                               Set<String> applicationOwners,
                                                               boolean applicationScopeKnown) {
        if (graph == null || !applicationScopeKnown || applicationOwners.isEmpty()) {
            return List.of();
        }
        List<FilterControl> result = new ArrayList<>();
        for (Node method : graph.nodesOfType(NodeType.METHOD)) {
            if (method == null || !applicationOwners.contains(method.owner())
                    || !isFilterImplementation(method)
                    || !isFilterMethodDescriptor(method.descriptor())
                    || !"doFilter".equals(method.name())) {
                continue;
            }
            String methodKey = methodKey(method.owner(), method.name(), method.descriptor());
            List<Node> calls = new ArrayList<>(graph.callsOfMethod(methodKey));
            calls.sort(Comparator.comparingLong(Node::id));
            boolean requestUri = hasCall(calls, "javax/servlet/http/HttpServletRequest",
                    "getRequestURI", "()Ljava/lang/String;")
                    || hasCall(calls, "jakarta/servlet/http/HttpServletRequest",
                    "getRequestURI", "()Ljava/lang/String;");
            boolean requestMethod = hasCall(calls, "javax/servlet/http/HttpServletRequest",
                    "getMethod", "()Ljava/lang/String;")
                    || hasCall(calls, "jakarta/servlet/http/HttpServletRequest",
                    "getMethod", "()Ljava/lang/String;");
            boolean remoteAddress = hasCall(calls, "javax/servlet/http/HttpServletRequest",
                    "getRemoteAddr", "()Ljava/lang/String;")
                    || hasCall(calls, "jakarta/servlet/http/HttpServletRequest",
                    "getRemoteAddr", "()Ljava/lang/String;");
            boolean addressClassifier = remoteAddress && hasLocalStringBooleanCall(calls,
                    method.owner());
            boolean passThrough = hasCall(calls, "javax/servlet/FilterChain", "doFilter",
                    "(Ljavax/servlet/ServletRequest;Ljavax/servlet/ServletResponse;)V")
                    || hasCall(calls, "jakarta/servlet/FilterChain", "doFilter",
                    "(Ljakarta/servlet/ServletRequest;Ljakarta/servlet/ServletResponse;)V");
            String pathPrefix = firstPredicateLiteral(calls, "startsWith",
                    "(Ljava/lang/String;)Z", true);
            String blockedPath = firstPredicateLiteral(calls, "equals",
                    "(Ljava/lang/Object;)Z", true);
            String blockedMethod = firstPredicateLiteral(calls, "equalsIgnoreCase",
                    "(Ljava/lang/String;)Z", false);
            boolean normalized = hasLocalStringReturnCall(calls, method.owner());
            if (!requestUri && !requestMethod && !remoteAddress && !passThrough) {
                continue;
            }
            result.add(new FilterControl(methodKey, pathPrefix, blockedPath, blockedMethod,
                    addressClassifier, passThrough, normalized));
        }
        return immutableFilterControls(result);
    }

    private static boolean isApplicationServiceConstructor(Node call,
                                                            Set<String> serviceOwners) {
        return call != null && "<init>".equals(call.name())
                && serviceOwners.contains(call.owner());
    }

    private static boolean isCxfEndpointConstructor(Node call) {
        return call != null && "org/apache/cxf/jaxws/EndpointImpl".equals(call.owner())
                && "<init>".equals(call.name())
                && "(Lorg/apache/cxf/Bus;Ljava/lang/Object;)V".equals(call.descriptor());
    }

    private static boolean isCxfEndpointPublish(Node call) {
        return call != null && "org/apache/cxf/jaxws/EndpointImpl".equals(call.owner())
                && "publish".equals(call.name())
                && "(Ljava/lang/String;)V".equals(call.descriptor());
    }

    private static boolean isFilterImplementation(Node method) {
        Object interfaces = method == null ? null : method.note("classInterfaces");
        if (!(interfaces instanceof Iterable<?> values)) {
            return false;
        }
        for (Object value : values) {
            if ("javax/servlet/Filter".equals(String.valueOf(value))
                    || "jakarta/servlet/Filter".equals(String.valueOf(value))) {
                return true;
            }
        }
        return false;
    }

    private static boolean isFilterMethodDescriptor(String descriptor) {
        return "(Ljavax/servlet/ServletRequest;Ljavax/servlet/ServletResponse;"
                .concat("Ljavax/servlet/FilterChain;)V").equals(descriptor)
                || "(Ljakarta/servlet/ServletRequest;Ljakarta/servlet/ServletResponse;"
                .concat("Ljakarta/servlet/FilterChain;)V").equals(descriptor);
    }

    private static boolean hasCall(List<Node> calls, String owner, String name, String descriptor) {
        return calls.stream().anyMatch(call -> owner.equals(call.owner())
                && name.equals(call.name()) && descriptor.equals(call.descriptor()));
    }

    private static boolean hasLocalStringBooleanCall(List<Node> calls, String owner) {
        return calls.stream().anyMatch(call -> owner.equals(call.owner())
                && !"<init>".equals(call.name())
                && "(Ljava/lang/String;)Z".equals(call.descriptor()));
    }

    private static boolean hasLocalStringReturnCall(List<Node> calls, String owner) {
        return calls.stream().anyMatch(call -> owner.equals(call.owner())
                && "(Ljava/lang/String;)Ljava/lang/String;".equals(call.descriptor())
                && call.name().toLowerCase(java.util.Locale.ROOT).contains("normal"));
    }

    private static String firstPredicateLiteral(List<Node> calls, String name, String descriptor,
                                                boolean path) {
        for (Node call : calls) {
            if (!"java/lang/String".equals(call.owner()) || !name.equals(call.name())
                    || !descriptor.equals(call.descriptor())) {
                continue;
            }
            String value = firstStringHint(call, path);
            if (!value.isBlank()) {
                return value;
            }
        }
        return "";
    }

    private static String firstPathLiteral(Node call) {
        return firstStringHint(call, true);
    }

    private static String firstStringHint(Node call, boolean path) {
        if (call == null) {
            return "";
        }
        Object hints = call.note("stringLiteralHints");
        if (!(hints instanceof Iterable<?> values)) {
            return "";
        }
        for (Object value : values) {
            if (value == null) {
                continue;
            }
            String text = value.toString().trim();
            if (text.isBlank() || text.length() > 256) {
                continue;
            }
            if (path == text.startsWith("/")) {
                return text;
            }
        }
        return "";
    }

    private static List<ServiceEndpoint> immutableServiceEndpoints(
            List<ServiceEndpoint> endpoints) {
        if (endpoints == null || endpoints.isEmpty()) {
            return List.of();
        }
        return endpoints.stream().filter(Objects::nonNull)
                .sorted(Comparator.comparing(ServiceEndpoint::serviceMethodKey)
                        .thenComparing(ServiceEndpoint::configurationMethodKey)
                        .thenComparing(ServiceEndpoint::publishPath)
                        .thenComparing(ServiceEndpoint::protocol))
                .distinct().toList();
    }

    private static List<HttpContextRegistration> immutableHttpContextRegistrations(
            List<HttpContextRegistration> registrations) {
        Objects.requireNonNull(registrations, "registrations");
        if (registrations.isEmpty()) {
            return List.of();
        }
        return registrations.stream().map(registration ->
                        Objects.requireNonNull(registration, "registration"))
                .sorted(Comparator.comparing(HttpContextRegistration::hostMethodKey)
                        .thenComparingInt(HttpContextRegistration::callOffset)
                        .thenComparingLong(HttpContextRegistration::callId))
                .distinct().toList();
    }

    private static Map<String, List<HttpContextRegistration>>
    immutableHttpContextRegistrationIndex(List<HttpContextRegistration> registrations) {
        Objects.requireNonNull(registrations, "registrations");
        if (registrations.isEmpty()) {
            return Map.of();
        }
        Map<String, List<HttpContextRegistration>> grouped = new TreeMap<>();
        for (HttpContextRegistration registration : registrations) {
            grouped.computeIfAbsent(registration.hostMethodKey(), ignored -> new ArrayList<>())
                    .add(registration);
        }
        Map<String, List<HttpContextRegistration>> result = new TreeMap<>();
        grouped.forEach((key, values) -> result.put(key, List.copyOf(values)));
        return Map.copyOf(result);
    }

    private static List<HttpExternalSource> immutableHttpExternalSources(
            List<HttpExternalSource> sources) {
        Objects.requireNonNull(sources, "HTTP external sources");
        if (sources.isEmpty()) {
            return List.of();
        }
        return sources.stream().map(source ->
                        Objects.requireNonNull(source, "HTTP external source"))
                .sorted(Comparator.comparing(HttpExternalSource::hostMethodKey)
                        .thenComparingInt(HttpExternalSource::callOffset)
                        .thenComparingLong(HttpExternalSource::callId)
                        .thenComparing(HttpExternalSource::apiKey))
                .distinct().toList();
    }

    private static Map<String, List<HttpExternalSource>> immutableHttpExternalSourceIndex(
            List<HttpExternalSource> sources) {
        Objects.requireNonNull(sources, "HTTP external sources");
        if (sources.isEmpty()) {
            return Map.of();
        }
        Map<String, List<HttpExternalSource>> grouped = new TreeMap<>();
        for (HttpExternalSource source : sources) {
            grouped.computeIfAbsent(source.hostMethodKey(), ignored -> new ArrayList<>())
                    .add(source);
        }
        Map<String, List<HttpExternalSource>> result = new TreeMap<>();
        grouped.forEach((key, values) -> result.put(key, List.copyOf(values)));
        return Map.copyOf(result);
    }

    private static List<HttpSite> immutableHttpSites(List<HttpSite> sites) {
        Objects.requireNonNull(sites, "HTTP sites");
        if (sites.isEmpty()) {
            return List.of();
        }
        return sites.stream().map(site -> Objects.requireNonNull(site, "HTTP site"))
                .sorted(Comparator.comparing(HttpSite::entryMethodKey)
                        .thenComparingInt(site -> site.registration().callOffset())
                        .thenComparing(HttpSite::handlerMethodKey)
                        .thenComparing(site -> site.handlerValue().identity()))
                .distinct().toList();
    }

    private static Map<String, List<HttpSite>> immutableHttpSiteIndex(List<HttpSite> sites) {
        Objects.requireNonNull(sites, "HTTP sites");
        if (sites.isEmpty()) {
            return Map.of();
        }
        Map<String, List<HttpSite>> grouped = new TreeMap<>();
        for (HttpSite site : sites) {
            grouped.computeIfAbsent(site.entryMethodKey(), ignored -> new ArrayList<>())
                    .add(site);
        }
        Map<String, List<HttpSite>> result = new TreeMap<>();
        grouped.forEach((key, values) -> result.put(key, List.copyOf(values)));
        return Map.copyOf(result);
    }

    private static Map<String, List<ServiceEndpoint>> immutableServiceEndpointIndex(
            List<ServiceEndpoint> endpoints) {
        if (endpoints == null || endpoints.isEmpty()) {
            return Map.of();
        }
        Map<String, List<ServiceEndpoint>> grouped = new TreeMap<>();
        for (ServiceEndpoint endpoint : endpoints) {
            grouped.computeIfAbsent(endpoint.serviceMethodKey(), ignored -> new ArrayList<>())
                    .add(endpoint);
        }
        Map<String, List<ServiceEndpoint>> result = new TreeMap<>();
        grouped.forEach((key, values) -> result.put(key, List.copyOf(values)));
        return Map.copyOf(result);
    }

    private static List<FilterControl> immutableFilterControls(List<FilterControl> controls) {
        if (controls == null || controls.isEmpty()) {
            return List.of();
        }
        return controls.stream().filter(Objects::nonNull)
                .sorted(Comparator.comparing(FilterControl::methodKey)
                        .thenComparing(FilterControl::pathPrefix)
                        .thenComparing(FilterControl::blockedPath)
                        .thenComparing(FilterControl::blockedMethod))
                .distinct().toList();
    }

    private static List<ApplicationResourceFacts.RouteBinding> immutableRouteBindings(
            ApplicationResourceFacts resourceFacts) {
        if (resourceFacts == null || resourceFacts.routeBindings().isEmpty()) {
            return List.of();
        }
        return resourceFacts.routeBindings().stream().filter(Objects::nonNull)
                .sorted(Comparator.comparing(ApplicationResourceFacts.RouteBinding::resourcePath)
                        .thenComparing(ApplicationResourceFacts.RouteBinding::route)
                        .thenComparing(ApplicationResourceFacts.RouteBinding::handlerMemberKey)
                        .thenComparing(ApplicationResourceFacts.RouteBinding::servletClass)
                        .thenComparing(ApplicationResourceFacts.RouteBinding::servletPattern))
                .distinct().toList();
    }

    private static Map<String, List<ApplicationResourceFacts.RouteBinding>>
    immutableRouteBindingIndex(List<ApplicationResourceFacts.RouteBinding> bindings) {
        if (bindings == null || bindings.isEmpty()) {
            return Map.of();
        }
        Map<String, List<ApplicationResourceFacts.RouteBinding>> grouped = new TreeMap<>();
        for (ApplicationResourceFacts.RouteBinding binding : bindings) {
            if (binding == null || binding.handlerMemberKey().isBlank()) {
                continue;
            }
            grouped.computeIfAbsent(binding.handlerMemberKey(), ignored -> new ArrayList<>())
                    .add(binding);
        }
        Map<String, List<ApplicationResourceFacts.RouteBinding>> result = new TreeMap<>();
        grouped.forEach((key, values) -> result.put(key, List.copyOf(values)));
        return Map.copyOf(result);
    }

    private static Map<String, EntryChainJoinEvidence.FilterDominance>
    immutableFilterDominanceIndex(List<ServiceEndpoint> endpoints,
                                  List<FilterControl> controls) {
        if (endpoints == null || endpoints.isEmpty()) {
            return Map.of();
        }
        Map<String, EntryChainJoinEvidence.FilterDominance> result = new TreeMap<>();
        for (ServiceEndpoint endpoint : endpoints) {
            EntryChainJoinEvidence.FilterDominance current = filterDominance(endpoint, controls);
            EntryChainJoinEvidence.FilterDominance previous = result.get(endpoint.serviceMethodKey());
            result.put(endpoint.serviceMethodKey(), mergeFilterDominance(previous, current));
        }
        return Map.copyOf(result);
    }

    private static EntryChainJoinEvidence.FilterDominance filterDominance(
            ServiceEndpoint endpoint, List<FilterControl> controls) {
        if (controls == null || controls.isEmpty()) {
            return EntryChainJoinEvidence.FilterDominance.NOT_PRESENT;
        }
        for (FilterControl control : controls) {
            String prefix = canonicalPath(control.pathPrefix());
            String route = routePath(prefix, endpoint.publishPath());
            if (prefix.isBlank() || route.isBlank()
                    || !(route.equals(prefix) || route.startsWith(prefix + "/"))) {
                continue;
            }
            String blockedPath = canonicalPath(control.blockedPath());
            if (blockedPath.equals(route)) {
                return EntryChainJoinEvidence.FilterDominance.DOMINATES;
            }
            if (!blockedPath.equals(prefix) || !control.passThrough()) {
                continue;
            }
            String blockedMethod = control.blockedMethod();
            if (blockedMethod.isBlank()) {
                return EntryChainJoinEvidence.FilterDominance.DOES_NOT_DOMINATE;
            }
            if ("SOAP/CXF".equals(endpoint.protocol())
                    && "GET".equalsIgnoreCase(blockedMethod)) {
                return EntryChainJoinEvidence.FilterDominance.DOES_NOT_DOMINATE;
            }
            if ("SOAP/CXF".equals(endpoint.protocol())
                    && "POST".equalsIgnoreCase(blockedMethod)) {
                return EntryChainJoinEvidence.FilterDominance.DOMINATES;
            }
        }
        return EntryChainJoinEvidence.FilterDominance.UNKNOWN;
    }

    private static EntryChainJoinEvidence.FilterDominance mergeFilterDominance(
            EntryChainJoinEvidence.FilterDominance first,
            EntryChainJoinEvidence.FilterDominance second) {
        if (first == null) {
            return second;
        }
        if (first == EntryChainJoinEvidence.FilterDominance.DOMINATES
                || second == EntryChainJoinEvidence.FilterDominance.DOMINATES) {
            return EntryChainJoinEvidence.FilterDominance.DOMINATES;
        }
        if (first == EntryChainJoinEvidence.FilterDominance.DOES_NOT_DOMINATE
                || second == EntryChainJoinEvidence.FilterDominance.DOES_NOT_DOMINATE) {
            return EntryChainJoinEvidence.FilterDominance.DOES_NOT_DOMINATE;
        }
        if (first == EntryChainJoinEvidence.FilterDominance.UNKNOWN
                || second == EntryChainJoinEvidence.FilterDominance.UNKNOWN) {
            return EntryChainJoinEvidence.FilterDominance.UNKNOWN;
        }
        return EntryChainJoinEvidence.FilterDominance.NOT_PRESENT;
    }

    private static String routePath(String prefix, String publishPath) {
        if (prefix == null || prefix.isBlank() || publishPath == null
                || publishPath.isBlank() || !publishPath.startsWith("/")) {
            return "";
        }
        String base = canonicalPath(prefix);
        if (base.isBlank() || "/".equals(base)) {
            return canonicalPath(publishPath);
        }
        return canonicalPath(base + publishPath);
    }

    private static String canonicalPath(String value) {
        if (value == null || value.isBlank() || !value.trim().startsWith("/")) {
            return "";
        }
        String path = value.trim().replaceAll("/+$", "");
        return path.isBlank() ? "/" : path;
    }

    /**
     * Build a deterministic index.  {@code applicationOwners} contains internal class names
     * from the first (target) artifact, not dependency/JDK classes.
     */
    public static ApplicationEntryIndex build(Graph graph, RuleEngine rules,
                                               Set<String> applicationOwners,
                                               boolean applicationScopeKnown) {
        return build(graph, rules, applicationOwners, applicationScopeKnown,
                ApplicationResourceFacts.empty());
    }

    /** Build with bounded deployment/configuration facts recovered by the static frontend. */
    public static ApplicationEntryIndex build(Graph graph, RuleEngine rules,
                                               Set<String> applicationOwners,
                                               boolean applicationScopeKnown,
                                               ApplicationResourceFacts resourceFacts) {
        return buildInternal(graph, rules, applicationOwners, applicationScopeKnown,
                resourceFacts);
    }

    private static ApplicationEntryIndex buildInternal(Graph graph, RuleEngine rules,
                                                        Set<String> applicationOwners,
                                                        boolean applicationScopeKnown,
                                                        ApplicationResourceFacts resourceFacts) {
        Objects.requireNonNull(graph, "graph");
        Objects.requireNonNull(rules, "rules");
        ApplicationResourceFacts resources = resourceFacts == null
                ? ApplicationResourceFacts.empty() : resourceFacts;
        Set<String> owners = normalizeOwners(applicationOwners);
        List<String> reasons = new ArrayList<>();
        if (!applicationScopeKnown) {
            reasons.add("APPLICATION_SCOPE_UNKNOWN");
        }
        reasons.addAll(resources.completenessReasons());

        Map<String, Node> methods = new HashMap<>();
        Map<String, Set<String>> methodAnnotations = new HashMap<>();
        Map<String, Set<String>> classAnnotations = new HashMap<>();
        Map<String, Set<String>> classSupertypes = new HashMap<>();
        for (Node method : graph.nodesOfType(NodeType.METHOD)) {
            String key = methodKey(method.owner(), method.name(), method.descriptor());
            methods.put(key, method);
            methodAnnotations.put(key, annotationDescriptors(method,
                    "methodAnnotationDescriptors"));
            classAnnotations.computeIfAbsent(method.owner(), ignored -> new TreeSet<>())
                    .addAll(annotationDescriptors(method, "classAnnotationDescriptors"));
            Set<String> supertypes = classSupertypes.computeIfAbsent(method.owner(),
                    ignored -> new TreeSet<>());
            Object superName = method.note("classSuperName");
            if (superName != null && !superName.toString().isBlank()) {
                supertypes.add(superName.toString());
            }
            Object interfaces = method.note("classInterfaces");
            if (interfaces instanceof Iterable<?> values) {
                for (Object value : values) {
                    if (value != null && !value.toString().isBlank()) {
                        supertypes.add(value.toString());
                    }
                }
            }
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
                    classAnnotations, classSupertypes);
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

        // Endpoint registration and route filters are application facts, not entry-name
        // heuristics.  Discover them once beside the entry index so the joiner can consume a
        // stable projection instead of rescanning CXF/Servlet calls for every candidate.
        List<ServiceEndpoint> serviceEndpoints = discoverServiceEndpoints(graph, entries,
                owners, applicationScopeKnown);
        List<HttpContextRegistration> httpContextRegistrations =
                discoverHttpContextRegistrations(graph, owners, applicationScopeKnown);
        List<HttpExternalSource> httpExternalSources = discoverHttpExternalSources(
                graph, owners, applicationScopeKnown, rules);
        List<HttpSite> httpSites = discoverHttpSites(graph, owners, applicationScopeKnown,
                entries, httpContextRegistrations, httpExternalSources);
        List<FilterControl> filterControls = discoverFilterControls(graph, owners,
                applicationScopeKnown);
        if (applicationScopeKnown) {
            for (ApplicationResourceFacts.RouteBinding binding : resources.routeBindings()) {
                if (!binding.externalControlProven()
                        || !owners.contains(binding.handlerClass())) {
                    continue;
                }
                String key = binding.handlerMemberKey();
                if (key.isBlank()) {
                    continue;
                }
                List<Node> handlerMethods = methods.values().stream()
                        .filter(candidate -> binding.handlerClass().equals(candidate.owner())
                                && binding.handlerMethod().equals(candidate.name()))
                        .sorted(Comparator.comparing(Node::descriptor))
                        .toList();
                if (handlerMethods.size() != 1) {
                    continue;
                }
                Node method = handlerMethods.get(0);
                entries.add(new ExecutionEntry(methodKey(method.owner(), method.name(),
                        method.descriptor()), method.owner(), method.name(),
                        method.descriptor(), "builtin:resource-route", "resource-route",
                        FindingState.EntryStatus.EXTERNAL_ENTRY, true, true));
            }
        }

        List<DeserializeSite> sites = new ArrayList<>();
        Map<String, Boolean> sourceHosts = new HashMap<>();
        Map<String, DeserializeHost> deserializeHosts = new TreeMap<>();
        Set<String> bindingSiteHosts = new TreeSet<>();
        List<String> boundarySliceReasons = new ArrayList<>();
        Set<String> externalBoundaryRoots = entries.stream()
                .filter(ExecutionEntry::externalControlProven)
                .map(ExecutionEntry::methodKey)
                .collect(java.util.stream.Collectors.toCollection(TreeSet::new));
        Set<String> externalBoundaryForward = new TreeSet<>(forwardSlice(graph, methods,
                externalBoundaryRoots, boundarySliceReasons));
        boolean externalBoundaryForwardUnknown = boundarySliceReasons.stream()
                .anyMatch(reason -> reason.contains("CAP"));
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
            // A source helper is application-reachable when the typed external boundary can
            // reach that exact host. Requiring the source method itself to be a framework entry
            // loses real servlet/service flows that delegate through ordinary application code.
            // If the bounded pre-slice is incomplete, retain the source rather than turning an
            // analysis budget into negative evidence.
            boolean reachableFromExternalBoundary = externalInput && owned
                    && (externalBoundaryForwardUnknown || externalBoundaryForward.contains(host));
            boolean boundaryExternal = explicitExecutionBoundary || reachableFromExternalBoundary;
            if (externalInput && owned && boundaryExternal) {
                sourceHosts.put(host, true);
                if (publicDeserializeBoundary && hostNode != null) {
                    entries.add(new ExecutionEntry(host, hostNode.owner(), hostNode.name(),
                            hostNode.descriptor(), ruleId, "public-deserialize-source",
                            FindingState.EntryStatus.EXTERNAL_ENTRY, true, true));
                }
                if (explicitExecutionBoundary && hostNode != null) {
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
                    classAnnotations, classSupertypes);
            if (framework == null || !framework.bindingCapable()
                    || !applicationScopeKnown || !owners.contains(method.owner())) {
                continue;
            }
            String host = methodKey(method.owner(), method.name(), method.descriptor());
            if (!bindingSiteHosts.add(host)) {
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
                    call.owner(), call.name(), call.descriptor(), sink.id(),
                    RuleSchemaV2.sinkRoleFor(sink),
                    applicationScopeKnown && owners.contains(call.methodOwner()),
                    RuleSchemaV2.isTerminalSink(sink)));
        }

        sortEntries(entries);
        sites.sort(Comparator.comparingLong(DeserializeSite::callId));
        impacts.sort(Comparator.comparingLong(TerminalImpact::callId));

        Set<String> siteRoots = new TreeSet<>();
        if (applicationScopeKnown) {
            httpSites.stream().map(HttpSite::handlerMethodKey).forEach(siteRoots::add);
        }
        Set<String> roots = new TreeSet<>();
        if (applicationScopeKnown) {
            entries.stream().filter(entry -> entry.status() != FindingState.EntryStatus.NO_APPLICATION_ENTRY)
                    .map(ExecutionEntry::methodKey).forEach(roots::add);
            sourceHosts.keySet().forEach(roots::add);
            roots.addAll(siteRoots);
        }
        List<String> forward = forwardSlice(graph, methods, roots, reasons);

        Set<String> sinkHosts = new TreeSet<>();
        for (TerminalImpact impact : impacts) {
            if (impact.terminal()) {
                sinkHosts.add(impact.hostMethodKey());
            }
        }
        // A known application with no verified entry/site has no application demand boundary.
        // Do not build the global sink-reverse caller index for that negative result; component
        // and unknown-scope indexes retain the compatibility reverse slice below.
        List<String> reverse = applicationScopeKnown && roots.isEmpty()
                ? List.of() : reverseSlice(graph, sinkHosts, reasons);
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
                List.copyOf(deserializeHosts.values()), serviceEndpoints, filterControls, resources,
                httpContextRegistrations,
                httpExternalSources,
                httpSites,
                siteRoots,
                impacts,
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

    /** Immutable application-owned CXF endpoint registrations. */
    public List<ServiceEndpoint> serviceEndpoints() {
        return serviceEndpoints;
    }

    /** Immutable endpoint registrations for one exact service operation. */
    public List<ServiceEndpoint> serviceEndpointsFor(String serviceMethodKey) {
        if (serviceMethodKey == null || serviceMethodKey.isBlank()) {
            return List.of();
        }
        return serviceEndpointsByMethod.getOrDefault(serviceMethodKey, List.of());
    }

    /** Whether the exact method is a typed JAX-WS/CXF application service operation. */
    public boolean isFrameworkServiceMethod(String methodKey) {
        return executionEntries.stream().anyMatch(entry -> entry.applicationOwned()
                && "framework-service".equals(entry.entryKind())
                && entry.methodKey().equals(methodKey));
    }

    /** Whether a typed service operation is backed by a concrete EndpointImpl.publish call. */
    public boolean isRegisteredServiceMethod(String methodKey) {
        return !serviceEndpointsFor(methodKey).isEmpty();
    }

    /** Immutable exact application-owned HttpServer context registrations. */
    public List<HttpContextRegistration> httpContextRegistrations() {
        return httpContextRegistrations;
    }

    /** Context registrations for one exact application host method. */
    public List<HttpContextRegistration> httpContextRegistrationsFor(String hostMethodKey) {
        if (hostMethodKey == null || hostMethodKey.isBlank()) {
            return List.of();
        }
        return httpContextRegistrationsByMethod.getOrDefault(hostMethodKey, List.of());
    }

    /** Immutable typed HTTP request-source facts; this list does not imply a verified site. */
    public List<HttpExternalSource> httpExternalSources() {
        return httpExternalSources;
    }

    /** Typed HTTP request-source facts for one exact application host method. */
    public List<HttpExternalSource> httpExternalSourcesFor(String hostMethodKey) {
        if (hostMethodKey == null || hostMethodKey.isBlank()) {
            return List.of();
        }
        return httpExternalSourcesByMethod.getOrDefault(hostMethodKey, List.of());
    }

    /** Immutable verified HTTP application sites; registration alone never appears here. */
    public List<HttpSite> httpSites() {
        return httpSites;
    }

    /** Verified HTTP sites for one exact registration host method. */
    public List<HttpSite> httpSitesFor(String hostMethodKey) {
        if (hostMethodKey == null || hostMethodKey.isBlank()) {
            return List.of();
        }
        return httpSitesByMethod.getOrDefault(hostMethodKey, List.of());
    }

    /** Immutable callback methods that begin a verified application site flow. */
    public Set<String> applicationSiteRoots() {
        return applicationSiteRoots;
    }

    /** Whether an exact method is the callback root of a verified application site. */
    public boolean isApplicationSiteRoot(String methodKey) {
        return methodKey != null && applicationSiteRoots.contains(methodKey);
    }

    /** Whether the immutable entry/site projection contains at least one verified root. */
    public boolean hasVerifiedApplicationRoot() {
        return applicationScopeKnown && !entryForwardMethods.isEmpty();
    }

    /** Whether an exact method is a concrete application-owned HttpHandler callback. */
    public boolean isHttpHandlerMethod(String methodKey) {
        return executionEntries.stream().anyMatch(entry -> entry.applicationOwned()
                && "http-handler".equals(entry.entryKind())
                && entry.methodKey().equals(methodKey));
    }

    /** Immutable application-owned route filters discovered from Filter#doFilter. */
    public List<FilterControl> filterControls() {
        return filterControls;
    }

    /** Immutable deployment/configuration routes recovered from the application artifact. */
    public List<ApplicationResourceFacts.RouteBinding> routeBindings() {
        return routeBindings;
    }

    /** Resource routes for one exact handler member. */
    public List<ApplicationResourceFacts.RouteBinding> routeBindingsFor(String methodKey) {
        if (methodKey == null || methodKey.isBlank()) {
            return List.of();
        }
        return routeBindingsByMember.getOrDefault(memberOfMethodKey(methodKey), List.of());
    }

    /** Closed filter result for a registered service operation; unknown remains explicit. */
    public EntryChainJoinEvidence.FilterDominance filterDominanceFor(String serviceMethodKey) {
        if (serviceMethodKey == null || serviceMethodKey.isBlank()) {
            return EntryChainJoinEvidence.FilterDominance.UNKNOWN;
        }
        EntryChainJoinEvidence.FilterDominance result = filterDominanceByService.get(
                serviceMethodKey);
        if (result != null) {
            return result;
        }
        return filterControls.isEmpty() ? EntryChainJoinEvidence.FilterDominance.NOT_PRESENT
                : EntryChainJoinEvidence.FilterDominance.UNKNOWN;
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

    /** Immutable secondary deserialization sources with an explicit tainted input argument. */
    public List<DeserializeSite> secondaryDeserializeSites() {
        return secondaryDeserializeSites;
    }

    /** Whether an application-owned method contains the first ObjectInputStream boundary. */
    public boolean hasApplicationObjectInputStreamSite(String methodKey) {
        return methodKey != null && applicationObjectInputHosts.contains(methodKey);
    }

    /** Whether a chain carries a typed non-OIS deserialization source hop. */
    public boolean hasSecondaryDeserializationHop(List<ChainHop> hops) {
        if (hops == null || secondaryDeserializeSites.isEmpty()) {
            return false;
        }
        for (ChainHop hop : hops) {
            if (hop == null) {
                continue;
            }
            if (isSecondaryDeserializeMember(hop.fromOwner(), hop.fromName())
                    || isSecondaryDeserializeMember(hop.toOwner(), hop.toName())) {
                return true;
            }
        }
        return false;
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
        return applicationScopeKnown
                && (!applicationExecutionEntries.isEmpty() || !applicationSiteRoots.isEmpty())
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
                terminalName, terminalDescriptor, continuationEvidence, null, false, false);
    }

    /**
     * Candidate admission for a declarative continuation whose terminal is a rule-owned
     * boundary rather than an observed call site.  The fragment producer owns the declaration
     * and supplies the typed boolean; this index only owns application-scope and reachability
     * admission.
     */
    public CandidateAdmissionDecision candidateAdmission(String entryOwner, String entryName,
                                                         String entryDescriptor,
                                                         String terminalOwner,
                                                         String terminalName,
                                                         String terminalDescriptor,
                                                         boolean continuationEvidence,
                                                         boolean declaredFragmentContinuation) {
        return candidateAdmission(entryOwner, entryName, entryDescriptor, terminalOwner,
                terminalName, terminalDescriptor, continuationEvidence, null, false,
                declaredFragmentContinuation);
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
                terminalName, terminalDescriptor, continuationEvidence, resolvedTerminal, false,
                false);
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
        return candidateAdmission(entryOwner, entryName, entryDescriptor, terminalOwner,
                terminalName, terminalDescriptor, continuationEvidence, resolvedTerminal,
                serializedTriggerContinuation, false);
    }

    /** Internal admission path for the bounded declaration-backed continuation axis. */
    private CandidateAdmissionDecision candidateAdmission(String entryOwner, String entryName,
                                                          String entryDescriptor,
                                                          String terminalOwner,
                                                          String terminalName,
                                                          String terminalDescriptor,
                                                          boolean continuationEvidence,
                                                          TerminalDecision resolvedTerminal,
                                                          boolean serializedTriggerContinuation,
                                                          boolean declaredFragmentContinuation) {
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
        TerminalDecision terminal = resolvedTerminal == null
                ? terminalAdmission(sinkOwner, sinkName, sinkDescriptor) : resolvedTerminal;
        if (!applicationScopeKnown) {
            return new CandidateAdmissionDecision(CandidateAdmissionStatus.APPLICATION_SCOPE_UNKNOWN,
                    entryKey, sinkOwner, sinkName, sinkDescriptor, entryForward, false,
                    continuationEvidence);
        }
        if (declaredFragmentContinuation && continuationEvidence
                && terminal.status() == TerminalStatus.NOT_INDEXED
                && (!isApplicationOwner(owner)
                || applicationEntryMethods.contains(entryKey) || entryForward
                || bindingTarget)) {
            return new CandidateAdmissionDecision(
                    CandidateAdmissionStatus.DECLARED_FRAGMENT_CONTINUATION, entryKey,
                    sinkOwner, sinkName, sinkDescriptor, entryForward, false, true);
        }
        if (!isApplicationOwner(owner) && !bindingTarget) {
            // A dependency fragment that ends at a typed capability is not an application
            // root, but it is still a legitimate continuation participant.  Preserve the
            // intermediate classification so producerAdmission can route it to the bridge
            // store; otherwise a SignedObject/ObjectInput or equivalent nested boundary is
            // rejected before composition ever sees its immutable endpoint.
            if (continuationEvidence
                    && terminal.status() == TerminalStatus.INTERMEDIATE_ONLY) {
                return new CandidateAdmissionDecision(
                        CandidateAdmissionStatus.TERMINAL_IMPACT_IS_INTERMEDIATE, entryKey,
                        sinkOwner, sinkName, sinkDescriptor, entryForward, false,
                        true);
            }
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
        boolean declaredFragmentContinuation = candidate.declaredFragmentContinuation()
                || candidate.declaredApplicationContinuation();
        CandidateAdmissionDecision admission = candidateAdmission(candidate.entryOwner(),
                candidate.entryName(), candidate.entryDescriptor(), candidate.terminalOwner(),
                candidate.terminalName(), candidate.terminalDescriptor(),
                candidate.continuationEvidence(), terminal, serializedTriggerContinuation,
                declaredFragmentContinuation);
        if (!applicationScopeKnown) {
            return new ProducerAdmissionDecision(ProducerAdmissionStatus.KERNEL_ONLY,
                    admission, terminal, candidate.continuationEvidence());
        }
        if (admission.admitted() && serializedTriggerContinuation) {
            return new ProducerAdmissionDecision(ProducerAdmissionStatus.BRIDGE_CONTINUATION,
                    admission, terminal, true);
        }
        if (admission.status() == CandidateAdmissionStatus.DECLARED_FRAGMENT_CONTINUATION) {
            ProducerAdmissionStatus route = candidate.declaredApplicationContinuation()
                    ? ProducerAdmissionStatus.APPLICATION_CHAIN
                    : ProducerAdmissionStatus.BRIDGE_CONTINUATION;
            return new ProducerAdmissionDecision(route,
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

    /**
     * Return a descriptor only when the graph contains exactly one overload for the owner/name
     * pair.  A name-only lookup is not a method fact: overloaded framework constructors and
     * callbacks must remain unresolved until a rule or an ENTRY hop supplies the signature.
     */
    public static String uniqueMethodDescriptor(Graph graph, String owner, String name) {
        if (graph == null || owner == null || owner.isBlank()
                || name == null || name.isBlank()) {
            return "";
        }
        Set<String> descriptors = new TreeSet<>();
        for (Node method : graph.nodesOfType(NodeType.METHOD)) {
            if (method != null && owner.equals(method.owner()) && name.equals(method.name())
                    && method.descriptor() != null && !method.descriptor().isBlank()) {
                descriptors.add(method.descriptor());
            }
        }
        return descriptors.size() == 1 ? descriptors.iterator().next() : "";
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

    private static boolean isObjectInputStreamSite(DeserializeSite site) {
        return site != null && ("builtin:ois-read".equals(site.ruleId())
                || "java/io/ObjectInputStream".equals(site.owner()));
    }

    private static boolean isSecondaryDeserializeSite(DeserializeSite site) {
        return site != null && !site.externalInput()
                && "deserialize".equalsIgnoreCase(site.bridge())
                && !isObjectInputStreamSite(site);
    }

    private boolean isSecondaryDeserializeMember(String owner, String name) {
        if (owner == null || owner.isBlank() || name == null || name.isBlank()) {
            return false;
        }
        return secondaryDeserializeSites.stream().anyMatch(site -> owner.equals(site.owner())
                && name.equals(site.name()));
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
                                                 Map<String, Set<String>> classAnnotationByOwner,
                                                 Map<String, Set<String>> classSupertypes) {
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
        boolean servlet = servletType(method, classSupertypes);

        if ("main".equals(method.name()) && "([Ljava/lang/String;)V".equals(method.descriptor())
                && Modifier.isPublic(access) && Modifier.isStatic(access)) {
            return new FrameworkEntry("lifecycle-main", false, false);
        }
        if (isHttpHandlerImplementation(method.owner(), classSupertypes, new TreeSet<>())
                && HTTP_HANDLER_HANDLE_NAME.equals(method.name())
                && HTTP_HANDLER_HANDLE_DESCRIPTOR.equals(method.descriptor())
                && Modifier.isPublic(access)) {
            return new FrameworkEntry("http-handler", true, true);
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

    private static boolean servletType(Node method, Map<String, Set<String>> classSupertypes) {
        return method != null && isServletType(method.owner(), classSupertypes, new TreeSet<>());
    }

    private static boolean isHttpHandlerImplementation(String owner,
                                                        Map<String, Set<String>> classSupertypes,
                                                        Set<String> visited) {
        if (owner == null || owner.isBlank() || HTTP_HANDLER_OWNER.equals(owner)
                || !visited.add(owner)) {
            return false;
        }
        for (String type : classSupertypes.getOrDefault(owner, Set.of())) {
            if (HTTP_HANDLER_OWNER.equals(type)
                    || isHttpHandlerImplementation(type, classSupertypes, visited)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isServletType(String owner, Map<String, Set<String>> classSupertypes,
                                         Set<String> visited) {
        if (owner == null || owner.isBlank() || !visited.add(owner)) {
            return false;
        }
        for (String type : classSupertypes.getOrDefault(owner, Set.of())) {
            if (SERVLET_TYPES.contains(type) || type.endsWith("/Servlet")
                    || type.endsWith("/Filter")
                    || isServletType(type, classSupertypes, visited)) {
                return true;
            }
        }
        return false;
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
            serviceEndpoints.forEach(value -> update(digest, "service=" + value));
            httpContextRegistrations.forEach(value -> update(digest, "http-context=" + value));
            httpExternalSources.forEach(value -> update(digest, "http-source=" + value));
            httpSites.forEach(value -> update(digest, "http-site=" + value));
            applicationSiteRoots.forEach(value -> update(digest, "site-root=" + value));
            filterControls.forEach(value -> update(digest, "filter=" + value));
            routeBindings.forEach(value -> update(digest, "route=" + value));
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
