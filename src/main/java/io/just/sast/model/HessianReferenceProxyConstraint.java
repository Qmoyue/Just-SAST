package io.just.sast.model;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Typed bridge from a JNDI Reference to the Hessian proxy-factory creation path.
 *
 * <p>The Hessian implementation consumes exactly one {@code StringRefAddr} whose type is
 * {@code type} and one whose type is {@code url}.  Their content is declared by that factory
 * contract to feed the exact {@code Class.forName(String)} and
 * {@code HessianProxyFactory.create(Class,String)} slots.  This owner also requires the
 * implementation method and the later {@code Proxy.newProxyInstance} call to be in the exact
 * Hessian factory methods.  It never parses a URL, loads a class, creates a proxy, invokes a
 * handler, performs network I/O, or executes target code.</p>
 */
public record HessianReferenceProxyConstraint(
        JndiReferenceFact reference,
        List<JndiReferenceFact.RefAddrFact> typeAddresses,
        List<JndiReferenceFact.RefAddrFact> urlAddresses,
        ClassForNameCallSite classForName,
        TypedBridgeFact.Endpoint typeContentEndpoint,
        TypedBridgeFact.Endpoint classNameEndpoint,
        TypedBridgeFact.Endpoint classResultEndpoint,
        HessianProxyFactoryCallSite createCallSite,
        TypedBridgeFact.Endpoint createApiEndpoint,
        TypedBridgeFact.Endpoint urlContentEndpoint,
        TypedBridgeFact.Endpoint createUrlEndpoint,
        ProxyCreationCallSite proxyCreation,
        Optional<TypedBridgeFact> typeBridge,
        Optional<TypedBridgeFact> classBridge,
        Optional<TypedBridgeFact> urlBridge,
        Status status,
        Reason reason) {

    public static final String GRAPH_NOTE_KEY = "hessianReferenceProxyConstraint";
    public static final String FACTORY_OWNER = HessianProxyFactoryCallSite.OWNER;
    public static final String GET_OBJECT_INSTANCE_NAME = "getObjectInstance";
    public static final String GET_OBJECT_INSTANCE_DESCRIPTOR =
            "(Ljava/lang/Object;Ljavax/naming/Name;Ljavax/naming/Context;"
                    + "Ljava/util/Hashtable;)Ljava/lang/Object;";
    public static final String PROXY_CREATE_DESCRIPTOR =
            "(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/ClassLoader;)Ljava/lang/Object;";

    public enum Status {
        PROVED,
        PARTIAL,
        UNKNOWN
    }

    public enum Reason {
        NONE,
        FACTORY_CLASS_UNKNOWN,
        FACTORY_CLASS_MISMATCH,
        TYPE_ADDRESS_MISSING,
        TYPE_ADDRESS_AMBIGUOUS,
        TYPE_ADDRESS_UNKNOWN,
        URL_ADDRESS_MISSING,
        URL_ADDRESS_AMBIGUOUS,
        URL_ADDRESS_UNKNOWN,
        TYPE_VALUE_UNKNOWN,
        URL_VALUE_UNKNOWN,
        TYPE_CONTENT_ENDPOINT_NOT_EXACT,
        URL_CONTENT_ENDPOINT_NOT_EXACT,
        CLASS_NAME_ENDPOINT_NOT_EXACT,
        CLASS_RESULT_ENDPOINT_NOT_EXACT,
        CREATE_API_ENDPOINT_NOT_EXACT,
        CREATE_URL_ENDPOINT_NOT_EXACT,
        FACTORY_METHOD_NOT_EXACT,
        PROXY_METHOD_NOT_EXACT,
        TYPE_BRIDGE_PARTIAL,
        TYPE_BRIDGE_UNKNOWN,
        CLASS_BRIDGE_PARTIAL,
        CLASS_BRIDGE_UNKNOWN,
        URL_BRIDGE_PARTIAL,
        URL_BRIDGE_UNKNOWN,
        PROXY_CREATION_INCOMPLETE
    }

    public HessianReferenceProxyConstraint {
        reference = Objects.requireNonNull(reference, "Hessian Reference fact");
        typeAddresses = List.copyOf(Objects.requireNonNull(typeAddresses,
                "Hessian type addresses"));
        urlAddresses = List.copyOf(Objects.requireNonNull(urlAddresses,
                "Hessian URL addresses"));
        classForName = Objects.requireNonNull(classForName, "Hessian Class.forName fact");
        typeContentEndpoint = Objects.requireNonNull(typeContentEndpoint,
                "Hessian type content endpoint");
        classNameEndpoint = Objects.requireNonNull(classNameEndpoint,
                "Hessian Class.forName argument endpoint");
        classResultEndpoint = Objects.requireNonNull(classResultEndpoint,
                "Hessian Class.forName result endpoint");
        createCallSite = Objects.requireNonNull(createCallSite, "Hessian create call site");
        createApiEndpoint = Objects.requireNonNull(createApiEndpoint,
                "Hessian create API endpoint");
        urlContentEndpoint = Objects.requireNonNull(urlContentEndpoint,
                "Hessian URL content endpoint");
        createUrlEndpoint = Objects.requireNonNull(createUrlEndpoint,
                "Hessian create URL endpoint");
        proxyCreation = Objects.requireNonNull(proxyCreation, "Hessian proxy creation fact");
        typeBridge = Objects.requireNonNull(typeBridge, "Hessian type bridge");
        classBridge = Objects.requireNonNull(classBridge, "Hessian class bridge");
        urlBridge = Objects.requireNonNull(urlBridge, "Hessian URL bridge");
        status = Objects.requireNonNull(status, "Hessian constraint status");
        reason = Objects.requireNonNull(reason, "Hessian constraint reason");
        validateAddresses(reference, typeAddresses, urlAddresses);
        validateClassForNameEndpoints(classForName, classNameEndpoint, classResultEndpoint);
        validateCreateEndpoints(createCallSite, createApiEndpoint, createUrlEndpoint);
        Decision expected = decide(reference, typeAddresses, urlAddresses, classForName,
                typeContentEndpoint, classNameEndpoint, classResultEndpoint, createCallSite,
                createApiEndpoint, urlContentEndpoint, createUrlEndpoint, proxyCreation,
                typeBridge, classBridge, urlBridge);
        if (status != expected.status() || reason != expected.reason()) {
            throw new IllegalArgumentException(
                    "Hessian Reference/proxy status does not match typed constraints");
        }
    }

    /**
     * Connect the exact Reference fields and Hessian call-sites.  Address selection is exact and
     * preserves duplicate/unknown candidates instead of choosing one silently.
     */
    public static HessianReferenceProxyConstraint connect(
            JndiReferenceFact reference,
            ClassForNameCallSite classForName,
            TypedBridgeFact.Endpoint typeContentEndpoint,
            TypedBridgeFact.Endpoint classNameEndpoint,
            TypedBridgeFact.Endpoint classResultEndpoint,
            HessianProxyFactoryCallSite createCallSite,
            TypedBridgeFact.Endpoint createApiEndpoint,
            TypedBridgeFact.Endpoint urlContentEndpoint,
            TypedBridgeFact.Endpoint createUrlEndpoint,
            ProxyCreationCallSite proxyCreation) {
        Objects.requireNonNull(reference, "Hessian Reference fact");
        Objects.requireNonNull(classForName, "Hessian Class.forName fact");
        Objects.requireNonNull(typeContentEndpoint, "Hessian type content endpoint");
        Objects.requireNonNull(classNameEndpoint, "Hessian Class.forName argument endpoint");
        Objects.requireNonNull(classResultEndpoint, "Hessian Class.forName result endpoint");
        Objects.requireNonNull(createCallSite, "Hessian create call site");
        Objects.requireNonNull(createApiEndpoint, "Hessian create API endpoint");
        Objects.requireNonNull(urlContentEndpoint, "Hessian URL content endpoint");
        Objects.requireNonNull(createUrlEndpoint, "Hessian create URL endpoint");
        Objects.requireNonNull(proxyCreation, "Hessian proxy creation fact");

        List<JndiReferenceFact.RefAddrFact> typeAddresses = addressesOf(reference, "type");
        List<JndiReferenceFact.RefAddrFact> urlAddresses = addressesOf(reference, "url");
        Optional<TypedBridgeFact> typeBridge = typeAddresses.size() == 1
                && typeAddresses.get(0).content().isKnown()
                && exactRefAddrContentEndpoint(typeAddresses.get(0), typeContentEndpoint)
                ? Optional.of(derivedBridge(typeContentEndpoint, classNameEndpoint))
                : Optional.empty();
        Optional<TypedBridgeFact> classBridge = exactClassNameEndpoints(classForName,
                classNameEndpoint, classResultEndpoint)
                && exactCreateEndpoint(createCallSite, createApiEndpoint,
                HessianProxyFactoryCallSite.API_SLOT)
                ? Optional.of(TypedBridgeFact.connect(TypedBridgeFact.Relation.VALUE_FLOW,
                classResultEndpoint, createApiEndpoint, TypedBridgeFact.IdentityRelation.SAME,
                artifactRelation(classResultEndpoint, createApiEndpoint)))
                : Optional.empty();
        Optional<TypedBridgeFact> urlBridge = urlAddresses.size() == 1
                && urlAddresses.get(0).content().isKnown()
                && exactRefAddrContentEndpoint(urlAddresses.get(0), urlContentEndpoint)
                && exactCreateEndpoint(createCallSite, createUrlEndpoint,
                HessianProxyFactoryCallSite.URL_SLOT)
                ? Optional.of(derivedBridge(urlContentEndpoint, createUrlEndpoint))
                : Optional.empty();
        Decision decision = decide(reference, typeAddresses, urlAddresses, classForName,
                typeContentEndpoint, classNameEndpoint, classResultEndpoint, createCallSite,
                createApiEndpoint, urlContentEndpoint, createUrlEndpoint, proxyCreation,
                typeBridge, classBridge, urlBridge);
        return new HessianReferenceProxyConstraint(reference, typeAddresses, urlAddresses,
                classForName, typeContentEndpoint, classNameEndpoint, classResultEndpoint,
                createCallSite, createApiEndpoint, urlContentEndpoint, createUrlEndpoint,
                proxyCreation, typeBridge, classBridge, urlBridge,
                decision.status(), decision.reason());
    }

    public boolean proved() {
        return status == Status.PROVED;
    }

    public Optional<JndiReferenceFact.RefAddrFact> typeAddress() {
        return typeAddresses.size() == 1 ? Optional.of(typeAddresses.get(0)) : Optional.empty();
    }

    public Optional<JndiReferenceFact.RefAddrFact> urlAddress() {
        return urlAddresses.size() == 1 ? Optional.of(urlAddresses.get(0)) : Optional.empty();
    }

    public String identity() {
        return "hessian-reference-proxy-v1|" + reference.identity().identity() + "|type="
                + addressesIdentity(typeAddresses) + "|url=" + addressesIdentity(urlAddresses)
                + "|" + classForName.identity() + "|" + createCallSite.identity() + "|proxy="
                + proxyCreation.identity() + "|typeBridge=" + bridgeIdentity(typeBridge)
                + "|classBridge=" + bridgeIdentity(classBridge) + "|urlBridge="
                + bridgeIdentity(urlBridge) + "|" + status + "|" + reason;
    }

    private static Decision decide(
            JndiReferenceFact reference,
            List<JndiReferenceFact.RefAddrFact> typeAddresses,
            List<JndiReferenceFact.RefAddrFact> urlAddresses,
            ClassForNameCallSite classForName,
            TypedBridgeFact.Endpoint typeContentEndpoint,
            TypedBridgeFact.Endpoint classNameEndpoint,
            TypedBridgeFact.Endpoint classResultEndpoint,
            HessianProxyFactoryCallSite createCallSite,
            TypedBridgeFact.Endpoint createApiEndpoint,
            TypedBridgeFact.Endpoint urlContentEndpoint,
            TypedBridgeFact.Endpoint createUrlEndpoint,
            ProxyCreationCallSite proxyCreation,
            Optional<TypedBridgeFact> typeBridge,
            Optional<TypedBridgeFact> classBridge,
            Optional<TypedBridgeFact> urlBridge) {
        if (!reference.factoryClass().isKnown()) {
            return new Decision(Status.PARTIAL, Reason.FACTORY_CLASS_UNKNOWN);
        }
        if (!FACTORY_OWNER.equals(TypeId.of(reference.factoryClass().value()).internalName())) {
            return new Decision(Status.UNKNOWN, Reason.FACTORY_CLASS_MISMATCH);
        }
        Reason typeAddressReason = addressReason(typeAddresses, reference, "type");
        if (typeAddressReason != null) {
            return decisionForAddress(typeAddressReason);
        }
        Reason urlAddressReason = addressReason(urlAddresses, reference, "url");
        if (urlAddressReason != null) {
            return decisionForAddress(urlAddressReason);
        }
        JndiReferenceFact.RefAddrFact typeAddress = typeAddresses.get(0);
        JndiReferenceFact.RefAddrFact urlAddress = urlAddresses.get(0);
        if (!typeAddress.content().isKnown()) {
            return new Decision(Status.PARTIAL, Reason.TYPE_VALUE_UNKNOWN);
        }
        if (!urlAddress.content().isKnown()) {
            return new Decision(Status.PARTIAL, Reason.URL_VALUE_UNKNOWN);
        }
        if (!exactClassNameEndpoints(classForName, classNameEndpoint, classResultEndpoint)) {
            return new Decision(Status.UNKNOWN, Reason.CLASS_NAME_ENDPOINT_NOT_EXACT);
        }
        if (!exactCreateEndpoint(createCallSite, createApiEndpoint,
                HessianProxyFactoryCallSite.API_SLOT)) {
            return new Decision(Status.UNKNOWN, Reason.CREATE_API_ENDPOINT_NOT_EXACT);
        }
        if (!exactRefAddrContentEndpoint(typeAddress, typeContentEndpoint)) {
            return new Decision(Status.UNKNOWN, Reason.TYPE_CONTENT_ENDPOINT_NOT_EXACT);
        }
        if (!exactRefAddrContentEndpoint(urlAddress, urlContentEndpoint)) {
            return new Decision(Status.UNKNOWN, Reason.URL_CONTENT_ENDPOINT_NOT_EXACT);
        }
        if (!exactCreateEndpoint(createCallSite, createUrlEndpoint,
                HessianProxyFactoryCallSite.URL_SLOT)) {
            return new Decision(Status.UNKNOWN, Reason.CREATE_URL_ENDPOINT_NOT_EXACT);
        }
        if (!factoryImplementationMethods(classForName, createCallSite)) {
            return new Decision(Status.UNKNOWN, Reason.FACTORY_METHOD_NOT_EXACT);
        }
        if (!proxyCreationMethod(proxyCreation)) {
            return new Decision(Status.UNKNOWN, Reason.PROXY_METHOD_NOT_EXACT);
        }
        Decision typeDecision = bridgeDecision(typeBridge, Reason.TYPE_BRIDGE_PARTIAL,
                Reason.TYPE_BRIDGE_UNKNOWN);
        if (typeDecision != null) {
            return typeDecision;
        }
        Decision classDecision = bridgeDecision(classBridge, Reason.CLASS_BRIDGE_PARTIAL,
                Reason.CLASS_BRIDGE_UNKNOWN);
        if (classDecision != null) {
            return classDecision;
        }
        Decision urlDecision = bridgeDecision(urlBridge, Reason.URL_BRIDGE_PARTIAL,
                Reason.URL_BRIDGE_UNKNOWN);
        if (urlDecision != null) {
            return urlDecision;
        }
        if (proxyCreation.status() != ProxyCreationCallSite.Status.PROVED) {
            return new Decision(Status.PARTIAL, Reason.PROXY_CREATION_INCOMPLETE);
        }
        return new Decision(Status.PROVED, Reason.NONE);
    }

    private static Decision decisionForAddress(Reason reason) {
        return switch (reason) {
            case TYPE_ADDRESS_AMBIGUOUS, URL_ADDRESS_AMBIGUOUS ->
                    new Decision(Status.UNKNOWN, reason);
            case TYPE_ADDRESS_UNKNOWN, URL_ADDRESS_UNKNOWN, TYPE_ADDRESS_MISSING,
                    URL_ADDRESS_MISSING -> new Decision(Status.PARTIAL, reason);
            default -> throw new IllegalArgumentException("unsupported address reason: " + reason);
        };
    }

    private static Reason addressReason(List<JndiReferenceFact.RefAddrFact> addresses,
                                        JndiReferenceFact reference, String key) {
        if (addresses.size() > 1) {
            return "type".equals(key) ? Reason.TYPE_ADDRESS_AMBIGUOUS
                    : Reason.URL_ADDRESS_AMBIGUOUS;
        }
        if (addresses.size() == 1) {
            return null;
        }
        boolean unresolved = reference.addresses().stream()
                .anyMatch(address -> address.type().state()
                        == JndiReferenceFact.FieldValue.State.UNKNOWN);
        if (unresolved) {
            return "type".equals(key) ? Reason.TYPE_ADDRESS_UNKNOWN
                    : Reason.URL_ADDRESS_UNKNOWN;
        }
        return "type".equals(key) ? Reason.TYPE_ADDRESS_MISSING : Reason.URL_ADDRESS_MISSING;
    }

    private static Decision bridgeDecision(Optional<TypedBridgeFact> bridge,
                                           Reason partialReason, Reason unknownReason) {
        if (bridge.isEmpty()) {
            return new Decision(Status.PARTIAL, partialReason);
        }
        return switch (bridge.get().status()) {
            case PROVED -> null;
            case PARTIAL -> new Decision(Status.PARTIAL, partialReason);
            case UNKNOWN -> new Decision(Status.UNKNOWN, unknownReason);
        };
    }

    private static TypedBridgeFact derivedBridge(TypedBridgeFact.Endpoint producer,
                                                  TypedBridgeFact.Endpoint consumer) {
        return TypedBridgeFact.connect(TypedBridgeFact.Relation.VALUE_FLOW, producer, consumer,
                TypedBridgeFact.IdentityRelation.DECLARED_DERIVATION,
                artifactRelation(producer, consumer));
    }

    private static TypedBridgeFact.ArtifactRelation artifactRelation(
            TypedBridgeFact.Endpoint producer, TypedBridgeFact.Endpoint consumer) {
        return producer.artifact().identity().equals(consumer.artifact().identity())
                ? TypedBridgeFact.ArtifactRelation.SAME_ARTIFACT
                : TypedBridgeFact.ArtifactRelation.EXPLICIT_CROSS_ARTIFACT;
    }

    private static boolean factoryImplementationMethods(ClassForNameCallSite classForName,
                                                        HessianProxyFactoryCallSite create) {
        return exactMethod(classForName.callSite().hostMethod(), GET_OBJECT_INSTANCE_NAME,
                GET_OBJECT_INSTANCE_DESCRIPTOR)
                && exactMethod(create.callSite().hostMethod(), GET_OBJECT_INSTANCE_NAME,
                GET_OBJECT_INSTANCE_DESCRIPTOR)
                && classForName.callSite().hostMethod().equals(create.callSite().hostMethod());
    }

    private static boolean proxyCreationMethod(ProxyCreationCallSite proxyCreation) {
        MethodId method = proxyCreation.callSite().hostMethod();
        return FACTORY_OWNER.equals(method.owner().internalName())
                && HessianProxyFactoryCallSite.CREATE_NAME.equals(method.name())
                && PROXY_CREATE_DESCRIPTOR.equals(method.descriptor());
    }

    private static boolean exactMethod(MethodId method, String name, String descriptor) {
        return FACTORY_OWNER.equals(method.owner().internalName())
                && name.equals(method.name()) && descriptor.equals(method.descriptor());
    }

    private static boolean exactClassNameEndpoints(ClassForNameCallSite classForName,
                                                   TypedBridgeFact.Endpoint argument,
                                                   TypedBridgeFact.Endpoint result) {
        return classForName.callSite().equals(argument.callSite())
                && ClassForNameCallSite.ARGUMENT_SLOT.equals(argument.slot())
                && TypeId.of("java/lang/String").equals(argument.type())
                && classForName.callSite().equals(result.callSite())
                && ClassForNameCallSite.RESULT_SLOT.equals(result.slot())
                && TypeId.of("java/lang/Class").equals(result.type());
    }

    private static boolean exactCreateEndpoint(HessianProxyFactoryCallSite create,
                                                TypedBridgeFact.Endpoint endpoint,
                                                TypedBridgeFact.Slot slot) {
        return create.callSite().equals(endpoint.callSite()) && slot.equals(endpoint.slot())
                && ((HessianProxyFactoryCallSite.API_SLOT.equals(slot)
                && TypeId.of("java/lang/Class").equals(endpoint.type()))
                || (HessianProxyFactoryCallSite.URL_SLOT.equals(slot)
                && TypeId.of("java/lang/String").equals(endpoint.type())));
    }

    private static boolean exactRefAddrContentEndpoint(
            JndiReferenceFact.RefAddrFact address, TypedBridgeFact.Endpoint endpoint) {
        TypedBridgeFact.CallSite call = endpoint.callSite();
        return JndiReferenceFact.STRING_REF_ADDR_OWNER.equals(call.calleeOwner())
                && "<init>".equals(call.calleeName())
                && JndiReferenceFact.STRING_REF_ADDR_CONSTRUCTOR_DESCRIPTOR
                .equals(call.calleeDescriptor())
                && call.invokeKind() == TypedBridgeFact.InvokeKind.SPECIAL
                && call.callId() == address.identity().constructionCallId()
                && call.callOffset() == address.identity().constructionOffset()
                && hostMethodKey(call.hostMethod()).equals(address.identity().hostMethodKey())
                && TypedBridgeFact.Slot.argument(1, "Ljava/lang/String;").equals(endpoint.slot())
                && TypeId.of("java/lang/String").equals(endpoint.type());
    }

    private static void validateAddresses(JndiReferenceFact reference,
                                           List<JndiReferenceFact.RefAddrFact> typeAddresses,
                                           List<JndiReferenceFact.RefAddrFact> urlAddresses) {
        for (JndiReferenceFact.RefAddrFact address : typeAddresses) {
            validateAddressMembership(reference, address);
        }
        for (JndiReferenceFact.RefAddrFact address : urlAddresses) {
            validateAddressMembership(reference, address);
        }
    }

    private static void validateAddressMembership(JndiReferenceFact reference,
                                                   JndiReferenceFact.RefAddrFact address) {
        if (!reference.addresses().contains(address)) {
            throw new IllegalArgumentException("Hessian address is not owned by Reference");
        }
    }

    private static void validateClassForNameEndpoints(ClassForNameCallSite classForName,
                                                      TypedBridgeFact.Endpoint argument,
                                                      TypedBridgeFact.Endpoint result) {
        if (classForName == null || argument == null || result == null) {
            throw new IllegalArgumentException("Hessian Class.forName endpoints are required");
        }
    }

    private static void validateCreateEndpoints(HessianProxyFactoryCallSite create,
                                                TypedBridgeFact.Endpoint api,
                                                TypedBridgeFact.Endpoint url) {
        if (create == null || api == null || url == null) {
            throw new IllegalArgumentException("Hessian create endpoints are required");
        }
    }

    private static List<JndiReferenceFact.RefAddrFact> addressesOf(JndiReferenceFact reference,
                                                                    String type) {
        return reference.addresses().stream()
                .filter(address -> address.type().isKnown() && type.equals(address.type().value()))
                .toList();
    }

    private static String hostMethodKey(MethodId method) {
        return method.owner().internalName() + "#" + method.name() + method.descriptor();
    }

    private static String addressesIdentity(List<JndiReferenceFact.RefAddrFact> addresses) {
        return addresses.stream().map(address -> address.identity().identity()).sorted().toList()
                .toString();
    }

    private static String bridgeIdentity(Optional<TypedBridgeFact> bridge) {
        return bridge.map(TypedBridgeFact::identity).orElse("ABSENT");
    }

    private record Decision(Status status, Reason reason) {
    }
}
