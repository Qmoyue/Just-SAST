package io.just.sast.model;

import java.util.Objects;
import java.util.Optional;

/** Immutable fact for the exact one-argument {@code Class.forName} contract. */
public record ClassForNameCallSite(TypedBridgeFact.CallSite callSite,
                                   TypedBridgeFact.Slot argument,
                                   TypedBridgeFact.Slot result) {

    public static final String OWNER = "java/lang/Class";
    public static final String NAME = "forName";
    public static final String DESCRIPTOR = "(Ljava/lang/String;)Ljava/lang/Class;";
    public static final String GRAPH_NOTE_KEY = "classForNameCallSite";
    public static final TypedBridgeFact.Slot ARGUMENT_SLOT =
            TypedBridgeFact.Slot.argument(0, "Ljava/lang/String;");
    public static final TypedBridgeFact.Slot RESULT_SLOT =
            TypedBridgeFact.Slot.returnValue("Ljava/lang/Class;");

    public ClassForNameCallSite {
        callSite = Objects.requireNonNull(callSite, "Class.forName call site");
        if (!OWNER.equals(callSite.calleeOwner()) || !NAME.equals(callSite.calleeName())
                || !DESCRIPTOR.equals(callSite.calleeDescriptor())
                || callSite.invokeKind() != TypedBridgeFact.InvokeKind.STATIC) {
            throw new IllegalArgumentException("Class.forName call site is not exact");
        }
        if (!ARGUMENT_SLOT.equals(argument)) {
            throw new IllegalArgumentException("Class.forName argument slot is not exact");
        }
        if (!RESULT_SLOT.equals(result)) {
            throw new IllegalArgumentException("Class.forName result slot is not exact");
        }
    }

    /** Match only the exact static JDK method; overloads and name-only calls are excluded. */
    public static boolean matches(String owner, String name, String descriptor,
                                  String invokeKind) {
        return OWNER.equals(owner) && NAME.equals(name) && DESCRIPTOR.equals(descriptor)
                && "STATIC".equals(invokeKind);
    }

    /** Build a fact for an exact physical call, retaining the caller and bytecode position. */
    public static Optional<ClassForNameCallSite> fromCall(long callId, MethodId hostMethod,
                                                           int callOffset, String owner,
                                                           String name, String descriptor,
                                                           String invokeKind) {
        if (!matches(owner, name, descriptor, invokeKind)
                || hostMethod == null) {
            return Optional.empty();
        }
        TypedBridgeFact.CallSite callSite = new TypedBridgeFact.CallSite(callId, hostMethod,
                callOffset, owner, name, descriptor, TypedBridgeFact.InvokeKind.STATIC);
        return Optional.of(new ClassForNameCallSite(callSite, ARGUMENT_SLOT, RESULT_SLOT));
    }

    public String identity() {
        return "class-for-name-v1:" + callSite.identity();
    }
}
