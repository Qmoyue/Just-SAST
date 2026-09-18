package io.just.sast.model;

import java.util.Objects;
import java.util.Optional;

/**
 * Immutable fact for the exact Hessian factory overload used by its JNDI object-factory path.
 *
 * <p>This is only the physical JVM call-site contract.  It does not inspect a URL, load an API
 * class, create a proxy, invoke a handler, or make a network request.  The
 * {@link HessianReferenceProxyConstraint} owner connects its typed slots to Reference facts.</p>
 */
public record HessianProxyFactoryCallSite(
        TypedBridgeFact.CallSite callSite,
        TypedBridgeFact.Slot receiverSlot,
        TypedBridgeFact.Slot apiSlot,
        TypedBridgeFact.Slot urlSlot,
        TypedBridgeFact.Slot resultSlot) {

    public static final String GRAPH_NOTE_KEY = "hessianProxyFactoryCallSite";
    public static final String OWNER = "com/caucho/hessian/client/HessianProxyFactory";
    public static final String CREATE_NAME = "create";
    public static final String CREATE_DESCRIPTOR =
            "(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Object;";
    public static final String RECEIVER_DESCRIPTOR = "L" + OWNER + ";";
    public static final String API_DESCRIPTOR = "Ljava/lang/Class;";
    public static final String URL_DESCRIPTOR = "Ljava/lang/String;";
    public static final String RESULT_DESCRIPTOR = "Ljava/lang/Object;";

    public static final TypedBridgeFact.Slot RECEIVER_SLOT =
            TypedBridgeFact.Slot.receiver(RECEIVER_DESCRIPTOR);
    public static final TypedBridgeFact.Slot API_SLOT =
            TypedBridgeFact.Slot.argument(0, API_DESCRIPTOR);
    public static final TypedBridgeFact.Slot URL_SLOT =
            TypedBridgeFact.Slot.argument(1, URL_DESCRIPTOR);
    public static final TypedBridgeFact.Slot RESULT_SLOT =
            TypedBridgeFact.Slot.returnValue(RESULT_DESCRIPTOR);

    public HessianProxyFactoryCallSite {
        callSite = Objects.requireNonNull(callSite, "Hessian factory call site");
        receiverSlot = Objects.requireNonNull(receiverSlot, "Hessian factory receiver slot");
        apiSlot = Objects.requireNonNull(apiSlot, "Hessian factory API slot");
        urlSlot = Objects.requireNonNull(urlSlot, "Hessian factory URL slot");
        resultSlot = Objects.requireNonNull(resultSlot, "Hessian factory result slot");
        if (!matches(callSite.calleeOwner(), callSite.calleeName(),
                callSite.calleeDescriptor(), callSite.invokeKind().name())) {
            throw new IllegalArgumentException("Hessian factory call site is not exact");
        }
        if (!RECEIVER_SLOT.equals(receiverSlot) || !API_SLOT.equals(apiSlot)
                || !URL_SLOT.equals(urlSlot) || !RESULT_SLOT.equals(resultSlot)) {
            throw new IllegalArgumentException("Hessian factory slot contract is invalid");
        }
    }

    /** Match only the exact two-argument Hessian factory overload. */
    public static boolean matches(String owner, String name, String descriptor,
                                  String invokeKind) {
        return OWNER.equals(owner) && CREATE_NAME.equals(name)
                && CREATE_DESCRIPTOR.equals(descriptor) && "VIRTUAL".equals(invokeKind);
    }

    /** Build a fact for one physical call when the exact overload is present. */
    public static Optional<HessianProxyFactoryCallSite> fromCall(
            long callId, MethodId hostMethod, int callOffset, String owner, String name,
            String descriptor, String invokeKind) {
        if (!matches(owner, name, descriptor, invokeKind) || hostMethod == null) {
            return Optional.empty();
        }
        TypedBridgeFact.CallSite callSite = new TypedBridgeFact.CallSite(callId, hostMethod,
                callOffset, owner, name, descriptor, TypedBridgeFact.InvokeKind.VIRTUAL);
        return Optional.of(new HessianProxyFactoryCallSite(callSite, RECEIVER_SLOT, API_SLOT,
                URL_SLOT, RESULT_SLOT));
    }

    public String identity() {
        return "hessian-factory-create-v1:" + callSite.identity();
    }
}
