package io.just.sast.model;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Immutable fact for the exact static JDK proxy factory boundary.
 *
 * <p>The four physical slots are retained independently: class loader, interface array,
 * invocation handler and returned proxy.  Interface names are published only when the array
 * contents are proved from class literals in the same value flow.  Unknown values remain
 * explicit facts; this model never loads an interface, creates a proxy, invokes a handler, or
 * expands implementers.</p>
 */
public record ProxyCreationCallSite(
        TypedBridgeFact.CallSite callSite,
        TypedBridgeFact.Slot classLoaderSlot,
        TypedBridgeFact.Slot interfaceSetSlot,
        TypedBridgeFact.Slot handlerSlot,
        TypedBridgeFact.Slot resultSlot,
        ValueIdentity classLoader,
        InterfaceSet interfaceSet,
        ValueIdentity handler,
        ValueIdentity proxy,
        Status status,
        Reason reason) {

    public static final String GRAPH_NOTE_KEY = "proxyCreationCallSite";
    public static final String OWNER = "java/lang/reflect/Proxy";
    public static final String NAME = "newProxyInstance";
    public static final String DESCRIPTOR =
            "(Ljava/lang/ClassLoader;[Ljava/lang/Class;"
                    + "Ljava/lang/reflect/InvocationHandler;)Ljava/lang/reflect/Proxy;";
    public static final String CLASS_LOADER_DESCRIPTOR = "Ljava/lang/ClassLoader;";
    public static final String INTERFACE_SET_DESCRIPTOR = "[Ljava/lang/Class;";
    public static final String HANDLER_DESCRIPTOR = "Ljava/lang/reflect/InvocationHandler;";
    public static final String RESULT_DESCRIPTOR = "Ljava/lang/reflect/Proxy;";

    public static final TypedBridgeFact.Slot CLASS_LOADER_SLOT =
            TypedBridgeFact.Slot.argument(0, CLASS_LOADER_DESCRIPTOR);
    public static final TypedBridgeFact.Slot INTERFACE_SET_SLOT =
            TypedBridgeFact.Slot.argument(1, INTERFACE_SET_DESCRIPTOR);
    public static final TypedBridgeFact.Slot HANDLER_SLOT =
            TypedBridgeFact.Slot.argument(2, HANDLER_DESCRIPTOR);
    public static final TypedBridgeFact.Slot RESULT_SLOT =
            TypedBridgeFact.Slot.returnValue(RESULT_DESCRIPTOR);

    public enum ValueState {
        KNOWN,
        NULL,
        UNKNOWN
    }

    public enum Status {
        PROVED,
        PARTIAL,
        UNKNOWN
    }

    public enum Reason {
        NONE,
        VALUE_FLOW_INCOMPLETE,
        INTERFACE_SET_UNKNOWN,
        NULL_INTERFACE_SET,
        NULL_HANDLER
    }

    /** Physical identity at one proxy factory slot; text/name inference is intentionally absent. */
    public record ValueIdentity(ValueState state, TypedBridgeFact.FlowIdentity identity,
                                String descriptor, int producerOffset) {
        public ValueIdentity {
            state = Objects.requireNonNull(state, "proxy value state");
            identity = Objects.requireNonNull(identity, "proxy value identity");
            descriptor = requireText(descriptor, "proxy value descriptor");
            if (producerOffset < -1) {
                throw new IllegalArgumentException("proxy value producer offset must be -1 or greater");
            }
        }

        public static ValueIdentity known(TypedBridgeFact.FlowIdentity identity,
                                          String descriptor, int producerOffset) {
            return new ValueIdentity(ValueState.KNOWN, identity, descriptor, producerOffset);
        }

        public static ValueIdentity nullValue(TypedBridgeFact.FlowIdentity identity,
                                              String descriptor, int producerOffset) {
            return new ValueIdentity(ValueState.NULL, identity, descriptor, producerOffset);
        }

        public static ValueIdentity unknown(TypedBridgeFact.FlowIdentity identity,
                                            String descriptor, int producerOffset) {
            return new ValueIdentity(ValueState.UNKNOWN, identity, descriptor, producerOffset);
        }

        public boolean known() {
            return state == ValueState.KNOWN;
        }

        public String token() {
            return identity.value();
        }
    }

    /**
     * The interface-array value and its statically observed class-literal members.  The array
     * identity remains available even when one member or the whole array is unresolved.
     */
    public record InterfaceSet(ValueState state, TypedBridgeFact.FlowIdentity identity,
                               String descriptor, int producerOffset,
                               List<String> interfaceTypes) {
        public InterfaceSet {
            state = Objects.requireNonNull(state, "proxy interface-set state");
            identity = Objects.requireNonNull(identity, "proxy interface-set identity");
            descriptor = requireText(descriptor, "proxy interface-set descriptor");
            if (!INTERFACE_SET_DESCRIPTOR.equals(descriptor)) {
                throw new IllegalArgumentException("proxy interface-set descriptor is not exact");
            }
            if (producerOffset < -1) {
                throw new IllegalArgumentException(
                        "proxy interface-set producer offset must be -1 or greater");
            }
            interfaceTypes = List.copyOf(Objects.requireNonNull(interfaceTypes,
                    "proxy interface types"));
            if (state != ValueState.KNOWN && !interfaceTypes.isEmpty()) {
                throw new IllegalArgumentException(
                        "unresolved proxy interface-set cannot carry interface types");
            }
            interfaceTypes = interfaceTypes.stream()
                    .map(type -> requireInternalName(type, "proxy interface type"))
                    .toList();
        }

        public static InterfaceSet known(TypedBridgeFact.FlowIdentity identity,
                                         int producerOffset, List<String> interfaceTypes) {
            return new InterfaceSet(ValueState.KNOWN, identity, INTERFACE_SET_DESCRIPTOR,
                    producerOffset, interfaceTypes);
        }

        public static InterfaceSet nullValue(TypedBridgeFact.FlowIdentity identity,
                                             int producerOffset) {
            return new InterfaceSet(ValueState.NULL, identity, INTERFACE_SET_DESCRIPTOR,
                    producerOffset, List.of());
        }

        public static InterfaceSet unknown(TypedBridgeFact.FlowIdentity identity,
                                           int producerOffset) {
            return new InterfaceSet(ValueState.UNKNOWN, identity, INTERFACE_SET_DESCRIPTOR,
                    producerOffset, List.of());
        }

        public boolean known() {
            return state == ValueState.KNOWN;
        }
    }

    public ProxyCreationCallSite {
        callSite = Objects.requireNonNull(callSite, "proxy creation call site");
        classLoaderSlot = Objects.requireNonNull(classLoaderSlot, "proxy class-loader slot");
        interfaceSetSlot = Objects.requireNonNull(interfaceSetSlot, "proxy interface-set slot");
        handlerSlot = Objects.requireNonNull(handlerSlot, "proxy handler slot");
        resultSlot = Objects.requireNonNull(resultSlot, "proxy result slot");
        classLoader = Objects.requireNonNull(classLoader, "proxy class-loader identity");
        interfaceSet = Objects.requireNonNull(interfaceSet, "proxy interface-set");
        handler = Objects.requireNonNull(handler, "proxy handler identity");
        proxy = Objects.requireNonNull(proxy, "proxy identity");
        status = Objects.requireNonNull(status, "proxy creation status");
        reason = Objects.requireNonNull(reason, "proxy creation reason");
        if (!matches(callSite.calleeOwner(), callSite.calleeName(),
                callSite.calleeDescriptor(), callSite.invokeKind().name())) {
            throw new IllegalArgumentException("proxy creation call site is not exact");
        }
        if (!CLASS_LOADER_SLOT.equals(classLoaderSlot)
                || !INTERFACE_SET_SLOT.equals(interfaceSetSlot)
                || !HANDLER_SLOT.equals(handlerSlot)
                || !RESULT_SLOT.equals(resultSlot)) {
            throw new IllegalArgumentException("proxy creation slot contract is invalid");
        }
        Decision expected = decide(classLoader, interfaceSet, handler, proxy);
        if (status != expected.status() || reason != expected.reason()) {
            throw new IllegalArgumentException("proxy creation status does not match value facts");
        }
    }

    /** Match only the exact static JDK proxy factory; overloads and name-only calls are excluded. */
    public static boolean matches(String owner, String name, String descriptor,
                                  String invokeKind) {
        return OWNER.equals(owner) && NAME.equals(name) && DESCRIPTOR.equals(descriptor)
                && "STATIC".equals(invokeKind);
    }

    /** Build an explicit incomplete fact when the exact factory is known but value flow is not. */
    public static Optional<ProxyCreationCallSite> fromCall(
            long callId, MethodId hostMethod, int callOffset, String owner, String name,
            String descriptor, String invokeKind) {
        if (!matches(owner, name, descriptor, invokeKind) || hostMethod == null) {
            return Optional.empty();
        }
        TypedBridgeFact.CallSite callSite = new TypedBridgeFact.CallSite(callId, hostMethod,
                callOffset, owner, name, descriptor, TypedBridgeFact.InvokeKind.STATIC);
        ValueIdentity loader = unknownValue(callSite, "class-loader", CLASS_LOADER_DESCRIPTOR);
        InterfaceSet interfaces = InterfaceSet.unknown(
                new TypedBridgeFact.FlowIdentity("proxy-unknown-interface-set:" + callSite.identity()),
                -1);
        ValueIdentity handler = unknownValue(callSite, "handler", HANDLER_DESCRIPTOR);
        ValueIdentity proxy = unknownValue(callSite, "result", RESULT_DESCRIPTOR);
        return Optional.of(new ProxyCreationCallSite(callSite, CLASS_LOADER_SLOT,
                INTERFACE_SET_SLOT, HANDLER_SLOT, RESULT_SLOT, loader, interfaces, handler, proxy,
                Status.PARTIAL, Reason.VALUE_FLOW_INCOMPLETE));
    }

    public static ProxyCreationCallSite withValues(TypedBridgeFact.CallSite callSite,
                                                    ValueIdentity classLoader,
                                                    InterfaceSet interfaceSet,
                                                    ValueIdentity handler,
                                                    ValueIdentity proxy) {
        Decision decision = decide(classLoader, interfaceSet, handler, proxy);
        return new ProxyCreationCallSite(callSite, CLASS_LOADER_SLOT, INTERFACE_SET_SLOT,
                HANDLER_SLOT, RESULT_SLOT, classLoader, interfaceSet, handler, proxy,
                decision.status(), decision.reason());
    }

    public String identity() {
        return "proxy-creation-v1|" + callSite.identity() + "|"
                + classLoader.identity().canonical() + "|" + interfaceSet.identity().canonical()
                + "|" + handler.identity().canonical() + "|" + proxy.identity().canonical()
                + "|" + status + "|" + reason;
    }

    public ValueIdentity handlerReceiver() {
        return handler;
    }

    public ValueIdentity proxyIdentity() {
        return proxy;
    }

    private static ValueIdentity unknownValue(TypedBridgeFact.CallSite callSite, String slot,
                                              String descriptor) {
        return ValueIdentity.unknown(new TypedBridgeFact.FlowIdentity(
                "proxy-unknown-" + slot + ":" + callSite.identity()), descriptor, -1);
    }

    private static Decision decide(ValueIdentity classLoader, InterfaceSet interfaceSet,
                                   ValueIdentity handler, ValueIdentity proxy) {
        Objects.requireNonNull(classLoader, "proxy class-loader identity");
        Objects.requireNonNull(interfaceSet, "proxy interface-set");
        Objects.requireNonNull(handler, "proxy handler identity");
        Objects.requireNonNull(proxy, "proxy identity");
        boolean allSlotsUnknown = classLoader.producerOffset() < 0
                && interfaceSet.producerOffset() < 0
                && handler.producerOffset() < 0
                && proxy.producerOffset() < 0;
        if (allSlotsUnknown) {
            return new Decision(Status.PARTIAL, Reason.VALUE_FLOW_INCOMPLETE);
        }
        if (interfaceSet.state() == ValueState.NULL) {
            return new Decision(Status.PARTIAL, Reason.NULL_INTERFACE_SET);
        }
        if (interfaceSet.state() == ValueState.UNKNOWN) {
            return new Decision(Status.PARTIAL, Reason.INTERFACE_SET_UNKNOWN);
        }
        if (classLoader.producerOffset() < 0 || interfaceSet.producerOffset() < 0
                || handler.producerOffset() < 0 || proxy.producerOffset() < 0) {
            return new Decision(Status.PARTIAL, Reason.VALUE_FLOW_INCOMPLETE);
        }
        if (handler.state() == ValueState.NULL) {
            return new Decision(Status.PARTIAL, Reason.NULL_HANDLER);
        }
        return new Decision(Status.PROVED, Reason.NONE);
    }

    private record Decision(Status status, Reason reason) {
    }

    private static String requireText(String value, String label) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(label + " must not be blank");
        }
        if (value.indexOf('\r') >= 0 || value.indexOf('\n') >= 0) {
            throw new IllegalArgumentException(label + " must not contain a line break");
        }
        return value.trim();
    }

    private static String requireInternalName(String value, String label) {
        String normalized = requireText(value, label).replace('.', '/');
        if (normalized.startsWith("L") && normalized.endsWith(";")) {
            normalized = normalized.substring(1, normalized.length() - 1);
        }
        if (normalized.isBlank() || normalized.startsWith("[")
                || normalized.indexOf('\u0000') >= 0) {
            throw new IllegalArgumentException(label + " is not an object internal name");
        }
        return normalized;
    }
}
