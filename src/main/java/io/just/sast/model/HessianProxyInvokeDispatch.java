package io.just.sast.model;

import java.util.Objects;

/**
 * Typed dispatch evidence from a proved proxy interface call to Hessian's invocation handler.
 *
 * <p>The relation is deliberately narrower than ordinary interface dispatch: only an abstract
 * proxy declaration which still requires its handler can reach the exact Hessian
 * {@code invoke(Object, Method, Object[])} method.  The handler is matched by the physical value
 * identity produced at the {@link ProxyCreationCallSite} slot, not by a class name or display
 * value.  This model never loads, initializes, constructs, reflects, or executes Hessian code.</p>
 */
public record HessianProxyInvokeDispatch(
        ProxyInterfaceDispatch interfaceDispatch,
        ProxyCreationCallSite.ValueIdentity handler,
        MethodId target,
        Status status,
        Reason reason) {

    public static final String GRAPH_NOTE_KEY = "hessianProxyInvokeDispatch";
    public static final String OWNER = "com/caucho/hessian/client/HessianProxy";
    public static final String NAME = "invoke";
    public static final String DESCRIPTOR =
            "(Ljava/lang/Object;Ljava/lang/reflect/Method;[Ljava/lang/Object;)Ljava/lang/Object;";
    public static final String HANDLER_DESCRIPTOR = "L" + OWNER + ";";
    public static final String RESULT_DESCRIPTOR = "Ljava/lang/Object;";

    public static final TypedBridgeFact.Slot RECEIVER_SLOT =
            TypedBridgeFact.Slot.receiver(HANDLER_DESCRIPTOR);
    public static final TypedBridgeFact.Slot PROXY_ARGUMENT_SLOT =
            TypedBridgeFact.Slot.argument(0, "Ljava/lang/Object;");
    public static final TypedBridgeFact.Slot METHOD_ARGUMENT_SLOT =
            TypedBridgeFact.Slot.argument(1, "Ljava/lang/reflect/Method;");
    public static final TypedBridgeFact.Slot ARGUMENTS_ARGUMENT_SLOT =
            TypedBridgeFact.Slot.argument(2, "[Ljava/lang/Object;");
    public static final TypedBridgeFact.Slot RESULT_SLOT =
            TypedBridgeFact.Slot.returnValue(RESULT_DESCRIPTOR);

    public enum Status {
        PROVED,
        PARTIAL,
        UNKNOWN
    }

    public enum Reason {
        NONE,
        INTERFACE_DISPATCH_INCOMPLETE,
        INTERFACE_DISPATCH_UNKNOWN,
        INTERFACE_DISPATCH_NOT_HANDLER,
        HANDLER_UNKNOWN,
        HANDLER_NULL,
        HANDLER_DESCRIPTOR_MISMATCH,
        HESSIAN_INVOKE_NOT_EXACT
    }

    public HessianProxyInvokeDispatch {
        interfaceDispatch = Objects.requireNonNull(interfaceDispatch,
                "Hessian interface dispatch");
        handler = Objects.requireNonNull(handler, "Hessian handler identity");
        status = Objects.requireNonNull(status, "Hessian invoke dispatch status");
        reason = Objects.requireNonNull(reason, "Hessian invoke dispatch reason");
        ProxyCreationCallSite.ValueIdentity expected = interfaceDispatch.callSite()
                .creation().handler();
        if (!expected.identity().equals(handler.identity())) {
            throw new IllegalArgumentException(
                    "Hessian handler identity is not the proxy factory handler");
        }
        if (status == Status.PROVED) {
            if (target == null || !matchesTarget(target)) {
                throw new IllegalArgumentException("proved Hessian invoke lacks exact target");
            }
        } else if (target != null) {
            throw new IllegalArgumentException("unresolved Hessian invoke has target");
        }
        Decision expectedDecision = decide(interfaceDispatch, handler, target);
        if (status != expectedDecision.status() || reason != expectedDecision.reason()) {
            throw new IllegalArgumentException(
                    "Hessian invoke dispatch status does not match typed constraints");
        }
    }

    /** Match only the exact Hessian handler method; overloads and name-only matches are excluded. */
    public static boolean matchesTarget(MethodId method) {
        return method != null && OWNER.equals(method.owner().internalName())
                && NAME.equals(method.name()) && DESCRIPTOR.equals(method.descriptor());
    }

    /** Connect one hierarchy result to the exact input method, retaining the same handler token. */
    public static HessianProxyInvokeDispatch connect(ProxyInterfaceDispatch dispatch,
                                                       MethodId target) {
        Objects.requireNonNull(dispatch, "Hessian interface dispatch");
        ProxyCreationCallSite.ValueIdentity handler = dispatch.callSite().creation().handler();
        Decision decision = decide(dispatch, handler, target);
        return new HessianProxyInvokeDispatch(dispatch, handler, target, decision.status(),
                decision.reason());
    }

    public boolean resolved() {
        return status == Status.PROVED;
    }

    public String identity() {
        return "hessian-proxy-invoke-v1|interface="
                + interfaceDispatch.callSite().identity()
                + "|handler=" + handler.identity().canonical() + "|target="
                + (target == null ? "ABSENT" : target.canonical()) + "|" + status + "|"
                + reason;
    }

    private static Decision decide(ProxyInterfaceDispatch dispatch,
                                   ProxyCreationCallSite.ValueIdentity handler,
                                   MethodId target) {
        return switch (dispatch.status()) {
            case PARTIAL -> new Decision(Status.PARTIAL,
                    Reason.INTERFACE_DISPATCH_INCOMPLETE);
            case UNKNOWN -> new Decision(Status.UNKNOWN,
                    Reason.INTERFACE_DISPATCH_UNKNOWN);
            case DEFAULT_RESOLVED -> new Decision(Status.UNKNOWN,
                    Reason.INTERFACE_DISPATCH_NOT_HANDLER);
            case HANDLER_REQUIRED -> decideHandler(handler, target);
        };
    }

    private static Decision decideHandler(ProxyCreationCallSite.ValueIdentity handler,
                                          MethodId target) {
        if (handler.state() == ProxyCreationCallSite.ValueState.NULL) {
            return new Decision(Status.PARTIAL, Reason.HANDLER_NULL);
        }
        if (handler.state() != ProxyCreationCallSite.ValueState.KNOWN
                || handler.producerOffset() < 0) {
            return new Decision(Status.PARTIAL, Reason.HANDLER_UNKNOWN);
        }
        if (!HANDLER_DESCRIPTOR.equals(handler.descriptor())) {
            return new Decision(Status.UNKNOWN, Reason.HANDLER_DESCRIPTOR_MISMATCH);
        }
        if (!matchesTarget(target)) {
            return new Decision(Status.UNKNOWN, Reason.HESSIAN_INVOKE_NOT_EXACT);
        }
        return new Decision(Status.PROVED, Reason.NONE);
    }

    private record Decision(Status status, Reason reason) {
    }
}
