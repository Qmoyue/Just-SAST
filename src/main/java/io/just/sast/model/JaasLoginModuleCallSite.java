package io.just.sast.model;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Immutable facts for the exact JAAS options and {@code LoginModule} lifecycle contracts.
 *
 * <p>The model keeps the physical invocation and every value slot separate from displayed
 * text.  It therefore records an options map copied through a local alias without treating two
 * equal literals as the same object.  This is a data-only boundary: it never loads a login
 * module, parses a JAAS file, creates a subject, or calls {@code initialize}/{@code login}.</p>
 */
public record JaasLoginModuleCallSite(
        TypedBridgeFact.CallSite callSite,
        Kind kind,
        List<SlotValue> values) {

    public static final String GRAPH_NOTE_KEY = "jaasLoginModuleCallSite";

    public static final String APP_CONFIGURATION_ENTRY_OWNER =
            "javax/security/auth/login/AppConfigurationEntry";
    public static final String APP_CONFIGURATION_ENTRY_CONSTRUCTOR_NAME = "<init>";
    public static final String APP_CONFIGURATION_ENTRY_CONSTRUCTOR_DESCRIPTOR =
            "(Ljava/lang/String;Ljavax/security/auth/login/AppConfigurationEntry$LoginModuleControlFlag;"
                    + "Ljava/util/Map;)V";
    public static final String APP_CONFIGURATION_ENTRY_DESCRIPTOR =
            "L" + APP_CONFIGURATION_ENTRY_OWNER + ";";
    public static final List<String> APP_CONFIGURATION_ENTRY_ARGUMENT_DESCRIPTORS = List.of(
            "Ljava/lang/String;",
            "Ljavax/security/auth/login/AppConfigurationEntry$LoginModuleControlFlag;",
            "Ljava/util/Map;");

    public static final String LOGIN_MODULE_OWNER = "javax/security/auth/spi/LoginModule";
    public static final String INITIALIZE_NAME = "initialize";
    public static final String INITIALIZE_DESCRIPTOR =
            "(Ljavax/security/auth/Subject;Ljavax/security/auth/callback/CallbackHandler;"
                    + "Ljava/util/Map;Ljava/util/Map;)V";
    public static final String LOGIN_NAME = "login";
    public static final String LOGIN_DESCRIPTOR = "()Z";
    public static final String LOGIN_MODULE_DESCRIPTOR = "L" + LOGIN_MODULE_OWNER + ";";
    public static final List<String> INITIALIZE_ARGUMENT_DESCRIPTORS = List.of(
            "Ljavax/security/auth/Subject;",
            "Ljavax/security/auth/callback/CallbackHandler;",
            "Ljava/util/Map;",
            "Ljava/util/Map;");

    public static final String MAP_OWNER = "java/util/Map";
    public static final String MAP_PUT_NAME = "put";
    public static final String MAP_PUT_DESCRIPTOR =
            "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;";
    public static final String MAP_DESCRIPTOR = "L" + MAP_OWNER + ";";

    public enum Kind {
        APP_CONFIGURATION_ENTRY,
        OPTIONS_MAP_PUT,
        LOGIN_MODULE_INITIALIZE,
        LOGIN_MODULE_LOGIN
    }

    /** Explicit value state; UNKNOWN never becomes a guessed option or module name. */
    public enum ValueState {
        KNOWN,
        NULL,
        UNKNOWN
    }

    /** Value identity carried by one exact JAAS slot. */
    public record ValueIdentity(ValueState state, TypedBridgeFact.FlowIdentity identity,
                                String displayValue, String descriptor, int producerOffset) {
        public ValueIdentity {
            state = Objects.requireNonNull(state, "JAAS value state");
            identity = Objects.requireNonNull(identity, "JAAS value identity");
            descriptor = requireText(descriptor, "JAAS value descriptor");
            if (producerOffset < -1) {
                throw new IllegalArgumentException(
                        "JAAS value producer offset must be -1 or greater");
            }
            if (state == ValueState.KNOWN && displayValue == null) {
                displayValue = "";
            }
            if (state != ValueState.KNOWN && displayValue != null) {
                throw new IllegalArgumentException(
                        "non-known JAAS value cannot carry display text");
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

    /** One receiver, argument or return slot paired with its physical value identity. */
    public record SlotValue(TypedBridgeFact.Slot slot, ValueIdentity value) {
        public SlotValue {
            slot = Objects.requireNonNull(slot, "JAAS slot");
            value = Objects.requireNonNull(value, "JAAS slot value");
        }
    }

    public JaasLoginModuleCallSite {
        callSite = Objects.requireNonNull(callSite, "JAAS call site");
        kind = Objects.requireNonNull(kind, "JAAS call kind");
        values = List.copyOf(Objects.requireNonNull(values, "JAAS slot values"));
        validateCall(callSite, kind);
        List<TypedBridgeFact.Slot> expected = expectedSlots(kind);
        if (values.size() != expected.size()) {
            throw new IllegalArgumentException("JAAS slot count is invalid");
        }
        List<SlotValue> ordered = new ArrayList<>(values);
        ordered.sort(Comparator.comparingInt(value -> slotOrder(value.slot())));
        for (int index = 0; index < expected.size(); index++) {
            if (!expected.get(index).equals(ordered.get(index).slot())) {
                throw new IllegalArgumentException("JAAS slot contract is invalid");
            }
        }
        values = List.copyOf(ordered);
    }

    /** Recognize only exact API owner/name/descriptor/invocation-kind combinations. */
    public static Optional<Kind> matchKind(String owner, String name, String descriptor,
                                           String invokeKind) {
        if (APP_CONFIGURATION_ENTRY_OWNER.equals(owner)
                && APP_CONFIGURATION_ENTRY_CONSTRUCTOR_NAME.equals(name)
                && APP_CONFIGURATION_ENTRY_CONSTRUCTOR_DESCRIPTOR.equals(descriptor)
                && "SPECIAL".equals(invokeKind)) {
            return Optional.of(Kind.APP_CONFIGURATION_ENTRY);
        }
        if (MAP_OWNER.equals(owner) && MAP_PUT_NAME.equals(name)
                && MAP_PUT_DESCRIPTOR.equals(descriptor) && "INTERFACE".equals(invokeKind)) {
            return Optional.of(Kind.OPTIONS_MAP_PUT);
        }
        if (LOGIN_MODULE_OWNER.equals(owner) && INITIALIZE_NAME.equals(name)
                && INITIALIZE_DESCRIPTOR.equals(descriptor) && "INTERFACE".equals(invokeKind)) {
            return Optional.of(Kind.LOGIN_MODULE_INITIALIZE);
        }
        if (LOGIN_MODULE_OWNER.equals(owner) && LOGIN_NAME.equals(name)
                && LOGIN_DESCRIPTOR.equals(descriptor) && "INTERFACE".equals(invokeKind)) {
            return Optional.of(Kind.LOGIN_MODULE_LOGIN);
        }
        return Optional.empty();
    }

    /** Build an explicit unknown fact for an exact call whose value transfer is incomplete. */
    public static Optional<JaasLoginModuleCallSite> fromCall(
            long callId, MethodId hostMethod, int callOffset, String owner, String name,
            String descriptor, String invokeKind) {
        Optional<Kind> kind = matchKind(owner, name, descriptor, invokeKind);
        if (kind.isEmpty() || hostMethod == null) {
            return Optional.empty();
        }
        TypedBridgeFact.CallSite callSite = new TypedBridgeFact.CallSite(callId, hostMethod,
                callOffset, owner, name, descriptor, invokeKind(invokeKind));
        List<SlotValue> values = expectedSlots(kind.get()).stream()
                .map(slot -> new SlotValue(slot, ValueIdentity.unknown(
                        new TypedBridgeFact.FlowIdentity("jaas-unknown:" + callSite.identity()
                                + ":" + slot.identity()), slot.descriptor(), -1)))
                .toList();
        return Optional.of(new JaasLoginModuleCallSite(callSite, kind.get(), values));
    }

    public static JaasLoginModuleCallSite withValues(TypedBridgeFact.CallSite callSite,
                                                     Kind kind, List<SlotValue> values) {
        return new JaasLoginModuleCallSite(callSite, kind, values);
    }

    public SlotValue value(TypedBridgeFact.Slot.Position position, int ordinal) {
        for (SlotValue value : values) {
            TypedBridgeFact.Slot slot = value.slot();
            if (slot.position() == position && slot.ordinal() == ordinal) {
                return value;
            }
        }
        throw new IllegalArgumentException("JAAS slot is not part of this call site");
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
        return "jaas-call-v1:" + callSite.identity() + ":" + kind;
    }

    private static List<TypedBridgeFact.Slot> expectedSlots(Kind kind) {
        return switch (kind) {
            case APP_CONFIGURATION_ENTRY -> slots(APP_CONFIGURATION_ENTRY_DESCRIPTOR,
                    APP_CONFIGURATION_ENTRY_ARGUMENT_DESCRIPTORS, "V");
            case OPTIONS_MAP_PUT -> slots(MAP_DESCRIPTOR,
                    List.of("Ljava/lang/Object;", "Ljava/lang/Object;"),
                    "Ljava/lang/Object;");
            case LOGIN_MODULE_INITIALIZE -> slots(LOGIN_MODULE_DESCRIPTOR,
                    INITIALIZE_ARGUMENT_DESCRIPTORS, "V");
            case LOGIN_MODULE_LOGIN -> slots(LOGIN_MODULE_DESCRIPTOR, List.of(), "Z");
        };
    }

    private static List<TypedBridgeFact.Slot> slots(String receiverDescriptor,
                                                     List<String> arguments,
                                                     String returnDescriptor) {
        List<TypedBridgeFact.Slot> result = new ArrayList<>(arguments.size() + 2);
        result.add(TypedBridgeFact.Slot.receiver(receiverDescriptor));
        for (int index = 0; index < arguments.size(); index++) {
            result.add(TypedBridgeFact.Slot.argument(index, arguments.get(index)));
        }
        if (!"V".equals(returnDescriptor)) {
            result.add(TypedBridgeFact.Slot.returnValue(returnDescriptor));
        }
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
            throw new IllegalArgumentException("JAAS call site is not exact");
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
