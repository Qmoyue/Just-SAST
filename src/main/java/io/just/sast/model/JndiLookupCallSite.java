package io.just.sast.model;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Immutable facts for the exact JNDI lookup/search value boundary.
 *
 * <p>The lookup result is retained as a physical value identity so a later
 * {@code DirContext.search} receiver can be connected only through the same
 * JVM value flow.  This model records API slots and does not perform a JNDI
 * lookup, load a provider, construct a context, or execute target code.</p>
 */
public record JndiLookupCallSite(
        TypedBridgeFact.CallSite callSite,
        Kind kind,
        List<SlotValue> values) {

    public static final String GRAPH_NOTE_KEY = "jndiLookupCallSite";
    public static final String INITIAL_CONTEXT_OWNER = "javax/naming/InitialContext";
    public static final String DIR_CONTEXT_OWNER = "javax/naming/directory/DirContext";
    public static final String LOOKUP_NAME = "lookup";
    public static final String LOOKUP_DESCRIPTOR = "(Ljava/lang/String;)Ljava/lang/Object;";
    public static final String LOOKUP_RECEIVER_DESCRIPTOR = "L" + INITIAL_CONTEXT_OWNER + ";";
    public static final String LOOKUP_RESULT_DESCRIPTOR = "Ljava/lang/Object;";
    public static final String SEARCH_NAME = "search";
    public static final String SEARCH_RETURN_DESCRIPTOR = "Ljavax/naming/NamingEnumeration;";
    public static final String SEARCH_RECEIVER_DESCRIPTOR = "L" + DIR_CONTEXT_OWNER + ";";

    /** All exact Java {@code DirContext.search} erasures, in declaration-independent order. */
    public static final List<String> SEARCH_DESCRIPTORS = List.of(
            "(Ljavax/naming/Name;Ljavax/naming/directory/Attributes;[Ljava/lang/String;)"
                    + SEARCH_RETURN_DESCRIPTOR,
            "(Ljava/lang/String;Ljavax/naming/directory/Attributes;[Ljava/lang/String;)"
                    + SEARCH_RETURN_DESCRIPTOR,
            "(Ljavax/naming/Name;Ljavax/naming/directory/Attributes;)"
                    + SEARCH_RETURN_DESCRIPTOR,
            "(Ljava/lang/String;Ljavax/naming/directory/Attributes;)"
                    + SEARCH_RETURN_DESCRIPTOR,
            "(Ljavax/naming/Name;Ljava/lang/String;Ljavax/naming/directory/SearchControls;)"
                    + SEARCH_RETURN_DESCRIPTOR,
            "(Ljava/lang/String;Ljava/lang/String;Ljavax/naming/directory/SearchControls;)"
                    + SEARCH_RETURN_DESCRIPTOR,
            "(Ljavax/naming/Name;Ljava/lang/String;[Ljava/lang/Object;"
                    + "Ljavax/naming/directory/SearchControls;)" + SEARCH_RETURN_DESCRIPTOR,
            "(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;"
                    + "Ljavax/naming/directory/SearchControls;)" + SEARCH_RETURN_DESCRIPTOR);

    public enum Kind {
        INITIAL_CONTEXT_LOOKUP,
        DIR_CONTEXT_SEARCH
    }

    public enum ValueState {
        KNOWN,
        NULL,
        UNKNOWN
    }

    /** Value identity is physical-flow data; display text is never a join condition. */
    public record ValueIdentity(ValueState state, TypedBridgeFact.FlowIdentity identity,
                                String displayValue, String descriptor, int producerOffset) {
        public ValueIdentity {
            state = Objects.requireNonNull(state, "JNDI value state");
            identity = Objects.requireNonNull(identity, "JNDI value identity");
            descriptor = requireText(descriptor, "JNDI value descriptor");
            if (producerOffset < -1) {
                throw new IllegalArgumentException(
                        "JNDI value producer offset must be -1 or greater");
            }
            if (state == ValueState.KNOWN && displayValue == null) {
                displayValue = "";
            }
            if (state != ValueState.KNOWN && displayValue != null) {
                throw new IllegalArgumentException(
                        "non-known JNDI value cannot carry display text");
            }
        }

        public static ValueIdentity known(TypedBridgeFact.FlowIdentity identity,
                                          String descriptor, int producerOffset,
                                          String displayValue) {
            return new ValueIdentity(ValueState.KNOWN, identity, displayValue, descriptor,
                    producerOffset);
        }

        public static ValueIdentity nullValue(TypedBridgeFact.FlowIdentity identity,
                                              String descriptor, int producerOffset) {
            return new ValueIdentity(ValueState.NULL, identity, null, descriptor, producerOffset);
        }

        public static ValueIdentity unknown(TypedBridgeFact.FlowIdentity identity,
                                            String descriptor, int producerOffset) {
            return new ValueIdentity(ValueState.UNKNOWN, identity, null, descriptor,
                    producerOffset);
        }

        public boolean known() {
            return state == ValueState.KNOWN;
        }

        public String token() {
            return identity.value();
        }
    }

    /** One declared receiver, argument, or return slot paired with its physical identity. */
    public record SlotValue(TypedBridgeFact.Slot slot, ValueIdentity value) {
        public SlotValue {
            slot = Objects.requireNonNull(slot, "JNDI slot");
            value = Objects.requireNonNull(value, "JNDI slot value");
        }
    }

    public JndiLookupCallSite {
        callSite = Objects.requireNonNull(callSite, "JNDI call site");
        kind = Objects.requireNonNull(kind, "JNDI call kind");
        values = List.copyOf(Objects.requireNonNull(values, "JNDI slot values"));
        validateCall(callSite, kind);
        List<TypedBridgeFact.Slot> expected = expectedSlots(kind, callSite.calleeDescriptor());
        if (values.size() != expected.size()) {
            throw new IllegalArgumentException("JNDI slot count is invalid");
        }
        List<SlotValue> ordered = new ArrayList<>(values);
        ordered.sort(Comparator.comparingInt(value -> slotOrder(value.slot())));
        for (int index = 0; index < expected.size(); index++) {
            if (!expected.get(index).equals(ordered.get(index).slot())) {
                throw new IllegalArgumentException("JNDI slot contract is invalid");
            }
        }
        values = List.copyOf(ordered);
    }

    /** Match only the exact InitialContext String lookup and DirContext search APIs. */
    public static Optional<Kind> matchKind(String owner, String name, String descriptor,
                                           String invokeKind) {
        if (INITIAL_CONTEXT_OWNER.equals(owner) && LOOKUP_NAME.equals(name)
                && LOOKUP_DESCRIPTOR.equals(descriptor) && "VIRTUAL".equals(invokeKind)) {
            return Optional.of(Kind.INITIAL_CONTEXT_LOOKUP);
        }
        if (DIR_CONTEXT_OWNER.equals(owner) && SEARCH_NAME.equals(name)
                && SEARCH_DESCRIPTORS.contains(descriptor) && "INTERFACE".equals(invokeKind)) {
            return Optional.of(Kind.DIR_CONTEXT_SEARCH);
        }
        return Optional.empty();
    }

    /** Build an explicit unknown fact for an exact API when local value flow is incomplete. */
    public static Optional<JndiLookupCallSite> fromCall(
            long callId, MethodId hostMethod, int callOffset, String owner, String name,
            String descriptor, String invokeKind) {
        Optional<Kind> kind = matchKind(owner, name, descriptor, invokeKind);
        if (kind.isEmpty() || hostMethod == null) {
            return Optional.empty();
        }
        TypedBridgeFact.CallSite callSite = new TypedBridgeFact.CallSite(callId, hostMethod,
                callOffset, owner, name, descriptor, invokeKind(invokeKind));
        List<SlotValue> values = expectedSlots(kind.get(), descriptor).stream()
                .map(slot -> new SlotValue(slot, ValueIdentity.unknown(
                        new TypedBridgeFact.FlowIdentity("jndi-unknown:" + callSite.identity()
                                + ":" + slot.identity()), slot.descriptor(), -1)))
                .toList();
        return Optional.of(new JndiLookupCallSite(callSite, kind.get(), values));
    }

    public static JndiLookupCallSite withValues(TypedBridgeFact.CallSite callSite, Kind kind,
                                                 List<SlotValue> values) {
        return new JndiLookupCallSite(callSite, kind, values);
    }

    public SlotValue value(TypedBridgeFact.Slot.Position position, int ordinal) {
        return values.stream().filter(value -> value.slot().position() == position
                && value.slot().ordinal() == ordinal).findFirst().orElseThrow(
                () -> new IllegalArgumentException("JNDI slot is not part of this call site"));
    }

    public SlotValue receiver() {
        return value(TypedBridgeFact.Slot.Position.RECEIVER, -1);
    }

    public SlotValue argument(int ordinal) {
        return value(TypedBridgeFact.Slot.Position.ARGUMENT, ordinal);
    }

    public Optional<SlotValue> returnValue() {
        return values.stream().filter(value ->
                value.slot().position() == TypedBridgeFact.Slot.Position.RETURN).findFirst();
    }

    public String identity() {
        return "jndi-call-v1:" + callSite.identity() + ":" + kind;
    }

    private static List<TypedBridgeFact.Slot> expectedSlots(Kind kind, String descriptor) {
        String receiver = kind == Kind.INITIAL_CONTEXT_LOOKUP
                ? LOOKUP_RECEIVER_DESCRIPTOR : SEARCH_RECEIVER_DESCRIPTOR;
        List<TypedBridgeFact.Slot> result = new ArrayList<>();
        result.add(TypedBridgeFact.Slot.receiver(receiver));
        int count = Descriptor.paramCount(descriptor);
        for (int index = 0; index < count; index++) {
            result.add(TypedBridgeFact.Slot.argument(index, Descriptor.paramType(descriptor, index)));
        }
        result.add(TypedBridgeFact.Slot.returnValue(Descriptor.returnType(descriptor)));
        return List.copyOf(result);
    }

    private static int slotOrder(TypedBridgeFact.Slot slot) {
        return switch (slot.position()) {
            case RECEIVER -> 0;
            case ARGUMENT -> slot.ordinal() + 1;
            case RETURN -> 1000;
        };
    }

    private static void validateCall(TypedBridgeFact.CallSite callSite, Kind kind) {
        Optional<Kind> matched = matchKind(callSite.calleeOwner(), callSite.calleeName(),
                callSite.calleeDescriptor(), callSite.invokeKind().name());
        if (matched.isEmpty() || matched.get() != kind) {
            throw new IllegalArgumentException("JNDI call site is not exact");
        }
    }

    private static TypedBridgeFact.InvokeKind invokeKind(String value) {
        return switch (value) {
            case "STATIC" -> TypedBridgeFact.InvokeKind.STATIC;
            case "SPECIAL" -> TypedBridgeFact.InvokeKind.SPECIAL;
            case "VIRTUAL" -> TypedBridgeFact.InvokeKind.VIRTUAL;
            case "INTERFACE" -> TypedBridgeFact.InvokeKind.INTERFACE;
            case "DYNAMIC" -> TypedBridgeFact.InvokeKind.DYNAMIC;
            default -> throw new IllegalArgumentException("unknown JVM invoke kind: " + value);
        };
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
