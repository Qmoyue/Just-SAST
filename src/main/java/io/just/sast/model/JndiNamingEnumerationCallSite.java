package io.just.sast.model;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Immutable facts for the exact JNDI enumeration consumer boundary.
 *
 * <p>The fact records only the JVM contract and the physical receiver/result values.  It does
 * not inspect an enumeration, call a provider, or execute a returned object.  The
 * {@link JndiSearchReturnFlow} owner decides whether a consumer is connected to one exact
 * {@code DirContext.search} result.</p>
 */
public record JndiNamingEnumerationCallSite(
        TypedBridgeFact.CallSite callSite,
        Kind kind,
        List<SlotValue> values) {

    public static final String GRAPH_NOTE_KEY = "jndiNamingEnumerationCallSite";
    public static final String NAMING_ENUMERATION_OWNER = "javax/naming/NamingEnumeration";
    public static final String JAVA_ENUMERATION_OWNER = "java/util/Enumeration";
    public static final String HAS_MORE_NAME = "hasMore";
    public static final String HAS_MORE_ELEMENTS_NAME = "hasMoreElements";
    public static final String NEXT_NAME = "next";
    public static final String NEXT_ELEMENT_NAME = "nextElement";
    public static final String BOOLEAN_DESCRIPTOR = "()Z";
    public static final String ELEMENT_DESCRIPTOR = "()Ljava/lang/Object;";
    public static final String NAMING_ENUMERATION_DESCRIPTOR =
            "L" + NAMING_ENUMERATION_OWNER + ";";
    public static final String JAVA_ENUMERATION_DESCRIPTOR =
            "L" + JAVA_ENUMERATION_OWNER + ";";

    public enum Kind {
        HAS_MORE,
        HAS_MORE_ELEMENTS,
        NEXT,
        NEXT_ELEMENT
    }

    /** One declared receiver or return slot paired with its physical value identity. */
    public record SlotValue(TypedBridgeFact.Slot slot, JndiLookupCallSite.ValueIdentity value) {
        public SlotValue {
            slot = Objects.requireNonNull(slot, "JNDI enumeration slot");
            value = Objects.requireNonNull(value, "JNDI enumeration slot value");
        }
    }

    public JndiNamingEnumerationCallSite {
        callSite = Objects.requireNonNull(callSite, "JNDI enumeration call site");
        kind = Objects.requireNonNull(kind, "JNDI enumeration call kind");
        values = List.copyOf(Objects.requireNonNull(values, "JNDI enumeration slot values"));
        validateCall(callSite, kind);
        List<TypedBridgeFact.Slot> expected = expectedSlots(callSite, kind);
        if (values.size() != expected.size()) {
            throw new IllegalArgumentException("JNDI enumeration slot count is invalid");
        }
        List<SlotValue> ordered = new ArrayList<>(values);
        ordered.sort(Comparator.comparingInt(value -> slotOrder(value.slot())));
        for (int index = 0; index < expected.size(); index++) {
            if (!expected.get(index).equals(ordered.get(index).slot())) {
                throw new IllegalArgumentException("JNDI enumeration slot contract is invalid");
            }
        }
        values = List.copyOf(ordered);
    }

    /** Match only exact NamingEnumeration/Enumeration consumer contracts. */
    public static Optional<Kind> matchKind(String owner, String name, String descriptor,
                                           String invokeKind) {
        if (!"INTERFACE".equals(invokeKind) || name == null || descriptor == null) {
            return Optional.empty();
        }
        if (NAMING_ENUMERATION_OWNER.equals(owner)
                && HAS_MORE_NAME.equals(name) && BOOLEAN_DESCRIPTOR.equals(descriptor)) {
            return Optional.of(Kind.HAS_MORE);
        }
        if (isEnumerationOwner(owner)
                && HAS_MORE_ELEMENTS_NAME.equals(name) && BOOLEAN_DESCRIPTOR.equals(descriptor)) {
            return Optional.of(Kind.HAS_MORE_ELEMENTS);
        }
        if (NAMING_ENUMERATION_OWNER.equals(owner)
                && NEXT_NAME.equals(name) && ELEMENT_DESCRIPTOR.equals(descriptor)) {
            return Optional.of(Kind.NEXT);
        }
        if (isEnumerationOwner(owner)
                && NEXT_ELEMENT_NAME.equals(name) && ELEMENT_DESCRIPTOR.equals(descriptor)) {
            return Optional.of(Kind.NEXT_ELEMENT);
        }
        return Optional.empty();
    }

    /** Build an explicit unknown consumer fact when local value flow is incomplete. */
    public static Optional<JndiNamingEnumerationCallSite> fromCall(
            long callId, MethodId hostMethod, int callOffset, String owner, String name,
            String descriptor, String invokeKind) {
        Optional<Kind> kind = matchKind(owner, name, descriptor, invokeKind);
        if (kind.isEmpty() || hostMethod == null) {
            return Optional.empty();
        }
        TypedBridgeFact.CallSite callSite = new TypedBridgeFact.CallSite(callId, hostMethod,
                callOffset, owner, name, descriptor, invokeKind(invokeKind));
        List<SlotValue> values = expectedSlots(callSite, kind.get()).stream()
                .map(slot -> new SlotValue(slot, JndiLookupCallSite.ValueIdentity.unknown(
                        new TypedBridgeFact.FlowIdentity("jndi-enumeration-unknown:"
                                + callSite.identity() + ":" + slot.identity()),
                        slot.descriptor(), -1)))
                .toList();
        return Optional.of(new JndiNamingEnumerationCallSite(callSite, kind.get(), values));
    }

    public static JndiNamingEnumerationCallSite withValues(
            TypedBridgeFact.CallSite callSite, Kind kind, List<SlotValue> values) {
        return new JndiNamingEnumerationCallSite(callSite, kind, values);
    }

    public SlotValue value(TypedBridgeFact.Slot.Position position, int ordinal) {
        return values.stream().filter(value -> value.slot().position() == position
                && value.slot().ordinal() == ordinal).findFirst().orElseThrow(
                () -> new IllegalArgumentException(
                        "JNDI enumeration slot is not part of this call site"));
    }

    public SlotValue receiver() {
        return value(TypedBridgeFact.Slot.Position.RECEIVER, -1);
    }

    public SlotValue returnValue() {
        return value(TypedBridgeFact.Slot.Position.RETURN, -1);
    }

    public String identity() {
        return "jndi-enumeration-call-v1:" + callSite.identity() + ":" + kind;
    }

    public boolean returnsElement() {
        return kind == Kind.NEXT || kind == Kind.NEXT_ELEMENT;
    }

    private static List<TypedBridgeFact.Slot> expectedSlots(
            TypedBridgeFact.CallSite callSite, Kind kind) {
        String receiver = receiverDescriptor(callSite.calleeOwner(), kind);
        return List.of(TypedBridgeFact.Slot.receiver(receiver),
                TypedBridgeFact.Slot.returnValue(returnDescriptor(kind)));
    }

    private static String receiverDescriptor(String owner, Kind kind) {
        if (kind == Kind.HAS_MORE) {
            return NAMING_ENUMERATION_DESCRIPTOR;
        }
        return NAMING_ENUMERATION_OWNER.equals(owner)
                ? NAMING_ENUMERATION_DESCRIPTOR : JAVA_ENUMERATION_DESCRIPTOR;
    }

    private static String returnDescriptor(Kind kind) {
        return kind == Kind.HAS_MORE || kind == Kind.HAS_MORE_ELEMENTS ? "Z" :
                "Ljava/lang/Object;";
    }

    private static int slotOrder(TypedBridgeFact.Slot slot) {
        return slot.position() == TypedBridgeFact.Slot.Position.RECEIVER ? 0 : 1000;
    }

    private static void validateCall(TypedBridgeFact.CallSite callSite, Kind kind) {
        Optional<Kind> matched = matchKind(callSite.calleeOwner(), callSite.calleeName(),
                callSite.calleeDescriptor(), callSite.invokeKind().name());
        if (matched.isEmpty() || matched.get() != kind) {
            throw new IllegalArgumentException("JNDI enumeration call site is not exact");
        }
    }

    private static boolean isEnumerationOwner(String owner) {
        return NAMING_ENUMERATION_OWNER.equals(owner) || JAVA_ENUMERATION_OWNER.equals(owner);
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
}
