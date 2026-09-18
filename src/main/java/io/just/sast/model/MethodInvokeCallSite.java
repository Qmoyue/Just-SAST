package io.just.sast.model;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Immutable fact for the exact reflective {@code Method.invoke} boundary.
 *
 * <p>The JVM method name and descriptor are retained by {@link #callSite()}; the Method object,
 * reflected target receiver, and packed argument array keep separate physical identities.  The
 * argument array is never expanded into an arbitrary target call: only elements proved by the
 * same local value flow are retained as parameter constraints.</p>
 */
public record MethodInvokeCallSite(
        TypedBridgeFact.CallSite callSite,
        TypedBridgeFact.Slot methodSlot,
        TypedBridgeFact.Slot targetSlot,
        TypedBridgeFact.Slot argumentsSlot,
        TypedBridgeFact.Slot returnSlot,
        ValueIdentity method,
        ValueIdentity target,
        ArgumentArray arguments,
        ValueIdentity result,
        Status status,
        Reason reason) {

    public static final String GRAPH_NOTE_KEY = "methodInvokeCallSite";
    public static final String OWNER = "java/lang/reflect/Method";
    public static final String NAME = "invoke";
    public static final String DESCRIPTOR =
            "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;";
    public static final String METHOD_DESCRIPTOR = "L" + OWNER + ";";
    public static final String TARGET_DESCRIPTOR = "Ljava/lang/Object;";
    public static final String ARGUMENTS_DESCRIPTOR = "[Ljava/lang/Object;";
    public static final String RETURN_DESCRIPTOR = "Ljava/lang/Object;";

    public static final TypedBridgeFact.Slot METHOD_SLOT =
            TypedBridgeFact.Slot.receiver(METHOD_DESCRIPTOR);
    public static final TypedBridgeFact.Slot TARGET_SLOT =
            TypedBridgeFact.Slot.argument(0, TARGET_DESCRIPTOR);
    public static final TypedBridgeFact.Slot ARGUMENTS_SLOT =
            TypedBridgeFact.Slot.argument(1, ARGUMENTS_DESCRIPTOR);
    public static final TypedBridgeFact.Slot RETURN_SLOT =
            TypedBridgeFact.Slot.returnValue(RETURN_DESCRIPTOR);

    public enum Status {
        PROVED,
        PARTIAL,
        UNKNOWN
    }

    public enum Reason {
        NONE,
        VALUE_FLOW_INCOMPLETE,
        METHOD_RECEIVER_NULL,
        METHOD_RECEIVER_DESCRIPTOR_MISMATCH,
        ARGUMENT_ARRAY_NULL,
        ARGUMENT_ARRAY_UNKNOWN,
        ARGUMENT_ARRAY_INCOMPLETE,
        ARGUMENT_ELEMENT_UNKNOWN
    }

    public enum ValueState {
        KNOWN,
        NULL,
        UNKNOWN
    }

    /** Physical identity for one Method or reflected target value. */
    public record ValueIdentity(ValueState state, TypedBridgeFact.FlowIdentity identity,
                                String descriptor, int producerOffset) {
        public ValueIdentity {
            state = Objects.requireNonNull(state, "Method.invoke value state");
            identity = Objects.requireNonNull(identity, "Method.invoke value identity");
            descriptor = requireText(descriptor, "Method.invoke value descriptor");
            if (producerOffset < -1) {
                throw new IllegalArgumentException(
                        "Method.invoke value producer offset must be -1 or greater");
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
    }

    /** A packed reflective argument array with only physically observed element constraints. */
    public record ArgumentArray(State state, TypedBridgeFact.FlowIdentity identity,
                                String descriptor, int producerOffset, List<Element> elements) {
        public enum State {
            KNOWN,
            NULL,
            UNKNOWN,
            PARTIAL
        }

        public record Element(int ordinal, ValueIdentity value) {
            public Element {
                if (ordinal < 0) {
                    throw new IllegalArgumentException(
                            "Method.invoke argument ordinal must be non-negative");
                }
                value = Objects.requireNonNull(value, "Method.invoke argument value");
            }
        }

        public ArgumentArray {
            state = Objects.requireNonNull(state, "Method.invoke argument-array state");
            identity = Objects.requireNonNull(identity, "Method.invoke argument-array identity");
            descriptor = requireText(descriptor, "Method.invoke argument-array descriptor");
            if (producerOffset < -1) {
                throw new IllegalArgumentException(
                        "Method.invoke argument-array producer offset must be -1 or greater");
            }
            List<Element> ordered = new ArrayList<>(Objects.requireNonNull(elements,
                    "Method.invoke argument elements"));
            ordered.replaceAll(value -> Objects.requireNonNull(value,
                    "Method.invoke argument element"));
            ordered.sort(Comparator.comparingInt(Element::ordinal));
            for (int index = 0; index < ordered.size(); index++) {
                if (ordered.get(index).ordinal() != index) {
                    throw new IllegalArgumentException(
                            "Method.invoke argument elements are not contiguous");
                }
            }
            if (state != State.KNOWN && !ordered.isEmpty()) {
                throw new IllegalArgumentException(
                        "unresolved Method.invoke argument array cannot carry elements");
            }
            elements = List.copyOf(ordered);
        }

        public static ArgumentArray known(TypedBridgeFact.FlowIdentity identity,
                                          int producerOffset, List<Element> elements) {
            return new ArgumentArray(State.KNOWN, identity, ARGUMENTS_DESCRIPTOR,
                    producerOffset, elements);
        }

        public static ArgumentArray nullValue(TypedBridgeFact.FlowIdentity identity,
                                              int producerOffset) {
            return new ArgumentArray(State.NULL, identity, ARGUMENTS_DESCRIPTOR,
                    producerOffset, List.of());
        }

        public static ArgumentArray unknown(TypedBridgeFact.FlowIdentity identity,
                                            String descriptor, int producerOffset) {
            return new ArgumentArray(State.UNKNOWN, identity, descriptor, producerOffset,
                    List.of());
        }

        public static ArgumentArray partial(TypedBridgeFact.FlowIdentity identity,
                                            String descriptor, int producerOffset) {
            return new ArgumentArray(State.PARTIAL, identity, descriptor, producerOffset,
                    List.of());
        }
    }

    public MethodInvokeCallSite {
        callSite = Objects.requireNonNull(callSite, "Method.invoke call site");
        methodSlot = Objects.requireNonNull(methodSlot, "Method.invoke Method slot");
        targetSlot = Objects.requireNonNull(targetSlot, "Method.invoke target slot");
        argumentsSlot = Objects.requireNonNull(argumentsSlot, "Method.invoke arguments slot");
        returnSlot = Objects.requireNonNull(returnSlot, "Method.invoke return slot");
        method = Objects.requireNonNull(method, "Method.invoke Method identity");
        target = Objects.requireNonNull(target, "Method.invoke target identity");
        arguments = Objects.requireNonNull(arguments, "Method.invoke argument array");
        result = Objects.requireNonNull(result, "Method.invoke result identity");
        status = Objects.requireNonNull(status, "Method.invoke status");
        reason = Objects.requireNonNull(reason, "Method.invoke reason");
        if (!matches(callSite.calleeOwner(), callSite.calleeName(),
                callSite.calleeDescriptor(), callSite.invokeKind().name())) {
            throw new IllegalArgumentException("Method.invoke call site is not exact");
        }
        if (!METHOD_SLOT.equals(methodSlot) || !TARGET_SLOT.equals(targetSlot)
                || !ARGUMENTS_SLOT.equals(argumentsSlot) || !RETURN_SLOT.equals(returnSlot)) {
            throw new IllegalArgumentException("Method.invoke slot contract is invalid");
        }
        Decision expected = decide(method, arguments, result);
        if (status != expected.status() || reason != expected.reason()) {
            throw new IllegalArgumentException("Method.invoke status does not match constraints");
        }
    }

    /** Match only the exact two-argument reflective Method.invoke API. */
    public static boolean matches(String owner, String name, String descriptor,
                                  String invokeKind) {
        return OWNER.equals(owner) && NAME.equals(name) && DESCRIPTOR.equals(descriptor)
                && "VIRTUAL".equals(invokeKind);
    }

    /** Build an explicit incomplete fact when the exact call is known but value flow is not. */
    public static Optional<MethodInvokeCallSite> fromCall(
            long callId, MethodId hostMethod, int callOffset, String owner, String name,
            String descriptor, String invokeKind) {
        if (!matches(owner, name, descriptor, invokeKind) || hostMethod == null) {
            return Optional.empty();
        }
        TypedBridgeFact.CallSite callSite = new TypedBridgeFact.CallSite(callId, hostMethod,
                callOffset, owner, name, descriptor, TypedBridgeFact.InvokeKind.VIRTUAL);
        ValueIdentity method = ValueIdentity.unknown(unknownIdentity(callSite, "method"),
                METHOD_DESCRIPTOR, -1);
        ValueIdentity target = ValueIdentity.unknown(unknownIdentity(callSite, "target"),
                TARGET_DESCRIPTOR, -1);
        ArgumentArray arguments = ArgumentArray.unknown(
                unknownIdentity(callSite, "arguments"), ARGUMENTS_DESCRIPTOR, -1);
        ValueIdentity result = ValueIdentity.unknown(unknownIdentity(callSite, "result"),
                RETURN_DESCRIPTOR, -1);
        return Optional.of(withValues(callSite, method, target, arguments, result));
    }

    public static MethodInvokeCallSite withValues(TypedBridgeFact.CallSite callSite,
                                                  ValueIdentity method, ValueIdentity target,
                                                  ArgumentArray arguments, ValueIdentity result) {
        Decision decision = decide(method, arguments, result);
        return new MethodInvokeCallSite(callSite, METHOD_SLOT, TARGET_SLOT, ARGUMENTS_SLOT,
                RETURN_SLOT, method, target, arguments, result, decision.status(),
                decision.reason());
    }

    public String identity() {
        return "method-invoke-v1:" + callSite.identity() + "|method="
                + method.identity().canonical() + "|target=" + target.identity().canonical()
                + "|arguments=" + arguments.identity().canonical() + "|result="
                + result.identity().canonical() + "|" + status + "|" + reason;
    }

    public String apiMethodName() {
        return callSite.calleeName();
    }

    public String apiDescriptor() {
        return callSite.calleeDescriptor();
    }

    private static Decision decide(ValueIdentity method, ArgumentArray arguments,
                                   ValueIdentity result) {
        if (!METHOD_DESCRIPTOR.equals(method.descriptor())) {
            if (method.state() == ValueState.UNKNOWN && method.producerOffset() >= 0) {
                return new Decision(Status.PARTIAL, Reason.VALUE_FLOW_INCOMPLETE);
            }
            return new Decision(Status.UNKNOWN, Reason.METHOD_RECEIVER_DESCRIPTOR_MISMATCH);
        }
        if (method.state() == ValueState.NULL) {
            return new Decision(Status.PARTIAL, Reason.METHOD_RECEIVER_NULL);
        }
        if (method.producerOffset() < 0) {
            return new Decision(Status.PARTIAL, Reason.VALUE_FLOW_INCOMPLETE);
        }
        if (arguments.state() == ArgumentArray.State.NULL) {
            return new Decision(Status.PARTIAL, Reason.ARGUMENT_ARRAY_NULL);
        }
        if (arguments.state() == ArgumentArray.State.UNKNOWN) {
            return new Decision(Status.PARTIAL, Reason.ARGUMENT_ARRAY_UNKNOWN);
        }
        if (arguments.state() == ArgumentArray.State.PARTIAL
                || arguments.producerOffset() < 0) {
            return new Decision(Status.PARTIAL, Reason.ARGUMENT_ARRAY_INCOMPLETE);
        }
        if (arguments.elements().stream().anyMatch(element ->
                element.value().state() == ValueState.UNKNOWN
                        || element.value().producerOffset() < 0)) {
            return new Decision(Status.PARTIAL, Reason.ARGUMENT_ELEMENT_UNKNOWN);
        }
        if (!RETURN_DESCRIPTOR.equals(result.descriptor()) || result.producerOffset() < 0) {
            return new Decision(Status.PARTIAL, Reason.VALUE_FLOW_INCOMPLETE);
        }
        return new Decision(Status.PROVED, Reason.NONE);
    }

    private static TypedBridgeFact.FlowIdentity unknownIdentity(
            TypedBridgeFact.CallSite callSite, String slot) {
        return new TypedBridgeFact.FlowIdentity("method-invoke-unknown-" + slot + ":"
                + callSite.identity());
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
}
