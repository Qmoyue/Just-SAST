package io.just.sast.model;

import java.util.Objects;
import java.util.Optional;

/**
 * Immutable fact for one interface invocation whose receiver is the exact result of a
 * {@link ProxyCreationCallSite}.  This is the value-flow seam only: class-hierarchy resolution
 * and default-method selection belong to {@link ProxyInterfaceDispatch}.
 *
 * <p>The fact never treats a method name or an equal display value as an identity.  A receiver
 * is associated with a proxy only when the same straight-line flow token produced by the
 * factory reaches this physical {@code invokeinterface} call.</p>
 */
public record ProxyInterfaceCallSite(
        TypedBridgeFact.CallSite callSite,
        TypedBridgeFact.Slot receiverSlot,
        ProxyCreationCallSite.ValueIdentity receiver,
        ProxyCreationCallSite creation,
        Status status,
        Reason reason) {

    public static final String GRAPH_NOTE_KEY = "proxyInterfaceCallSite";
    public static final String DISPATCH_NOTE_KEY = "proxyInterfaceDispatch";

    public enum Status {
        PROVED,
        PARTIAL,
        UNKNOWN
    }

    public enum Reason {
        NONE,
        VALUE_FLOW_INCOMPLETE,
        PROXY_CREATION_INCOMPLETE,
        INTERFACE_SET_UNKNOWN,
        NULL_RECEIVER,
        RECEIVER_DESCRIPTOR_MISMATCH
    }

    public ProxyInterfaceCallSite {
        callSite = Objects.requireNonNull(callSite, "proxy interface call site");
        receiverSlot = Objects.requireNonNull(receiverSlot, "proxy interface receiver slot");
        receiver = Objects.requireNonNull(receiver, "proxy interface receiver identity");
        creation = Objects.requireNonNull(creation, "proxy interface proxy creation");
        status = Objects.requireNonNull(status, "proxy interface relation status");
        reason = Objects.requireNonNull(reason, "proxy interface relation reason");
        if (callSite.invokeKind() != TypedBridgeFact.InvokeKind.INTERFACE) {
            throw new IllegalArgumentException("proxy interface call requires INVOKEINTERFACE");
        }
        if (!validInternalName(callSite.calleeOwner())) {
            throw new IllegalArgumentException("proxy interface owner is not an internal name");
        }
        if (!validMethodDescriptor(callSite.calleeDescriptor())) {
            throw new IllegalArgumentException("proxy interface descriptor is not exact");
        }
        TypedBridgeFact.Slot expectedReceiver = TypedBridgeFact.Slot.receiver(
                "L" + callSite.calleeOwner() + ";");
        if (!expectedReceiver.equals(receiverSlot)) {
            throw new IllegalArgumentException("proxy interface receiver slot is not exact");
        }
        if (!callSite.hostMethod().equals(creation.callSite().hostMethod())) {
            throw new IllegalArgumentException("proxy interface and factory hosts differ");
        }
        if (!receiver.identity().equals(creation.proxy().identity())) {
            throw new IllegalArgumentException("proxy interface receiver identity is not factory result");
        }
        Decision expected = decide(receiver, receiverSlot, creation);
        if (status != expected.status() || reason != expected.reason()) {
            throw new IllegalArgumentException("proxy interface relation status is inconsistent");
        }
    }

    /** Match only a physical JVM interface invocation; method resolution is deliberately later. */
    public static boolean matches(String owner, String name, String descriptor,
                                  String invokeKind) {
        return validInternalName(owner) && name != null && !name.isBlank()
                && validMethodDescriptor(descriptor) && "INTERFACE".equals(invokeKind);
    }

    /**
     * Build a relation fact only after the value-flow owner has found the same factory-result
     * identity.  An ordinary interface call therefore does not enter the proxy dispatch path.
     */
    public static Optional<ProxyInterfaceCallSite> fromValues(
            TypedBridgeFact.CallSite callSite,
            ProxyCreationCallSite.ValueIdentity receiver,
            ProxyCreationCallSite creation) {
        if (callSite == null || receiver == null || creation == null
                || callSite.invokeKind() != TypedBridgeFact.InvokeKind.INTERFACE
                || !callSite.hostMethod().equals(creation.callSite().hostMethod())
                || !receiver.identity().equals(creation.proxy().identity())) {
            return Optional.empty();
        }
        TypedBridgeFact.Slot receiverSlot = TypedBridgeFact.Slot.receiver(
                "L" + callSite.calleeOwner() + ";");
        Decision decision = decide(receiver, receiverSlot, creation);
        return Optional.of(new ProxyInterfaceCallSite(callSite, receiverSlot, receiver, creation,
                decision.status(), decision.reason()));
    }

    public String identity() {
        return "proxy-interface-call-v1:" + callSite.identity() + "|receiver="
                + receiver.identity().canonical() + "|factory=" + creation.identity();
    }

    private static Decision decide(ProxyCreationCallSite.ValueIdentity receiver,
                                   TypedBridgeFact.Slot receiverSlot,
                                   ProxyCreationCallSite creation) {
        if (receiver.state() == ProxyCreationCallSite.ValueState.NULL) {
            return new Decision(Status.PARTIAL, Reason.NULL_RECEIVER);
        }
        if (receiver.producerOffset() < 0) {
            return new Decision(Status.PARTIAL, Reason.VALUE_FLOW_INCOMPLETE);
        }
        if (!receiverSlot.descriptor().equals(receiver.descriptor())) {
            return new Decision(Status.UNKNOWN, Reason.RECEIVER_DESCRIPTOR_MISMATCH);
        }
        if (creation.status() != ProxyCreationCallSite.Status.PROVED) {
            return new Decision(Status.PARTIAL, Reason.PROXY_CREATION_INCOMPLETE);
        }
        if (!creation.interfaceSet().known()) {
            return new Decision(Status.PARTIAL, Reason.INTERFACE_SET_UNKNOWN);
        }
        return new Decision(Status.PROVED, Reason.NONE);
    }

    private static boolean validInternalName(String value) {
        return value != null && !value.isBlank() && !value.startsWith("[")
                && value.indexOf('.') < 0 && value.indexOf(';') < 0
                && value.indexOf('(') < 0 && value.indexOf(')') < 0;
    }

    private static boolean validMethodDescriptor(String descriptor) {
        if (descriptor == null || !descriptor.startsWith("(")
                || descriptor.indexOf(')') <= 0
                || descriptor.indexOf(')') >= descriptor.length() - 1) {
            return false;
        }
        try {
            Descriptor.paramCount(descriptor);
            Descriptor.returnType(descriptor);
            return true;
        } catch (RuntimeException invalid) {
            return false;
        }
    }

    private record Decision(Status status, Reason reason) {
    }
}
