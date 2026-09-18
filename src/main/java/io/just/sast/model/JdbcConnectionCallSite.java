package io.just.sast.model;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Immutable fact for the exact JDBC URL/Properties connection boundary.
 *
 * <p>This model records the JVM consumer contract first and keeps value identity separate from
 * display text.  A literal URL or property value is therefore not a global string join: its
 * identity includes the producing method and bytecode offset, while aliases retain that same
 * token.  The model is data-only and does not load a driver or invoke JDBC code.</p>
 */
public record JdbcConnectionCallSite(
        TypedBridgeFact.CallSite callSite,
        Kind kind,
        TypedBridgeFact.Slot urlSlot,
        TypedBridgeFact.Slot propertiesSlot,
        TypedBridgeFact.Slot returnSlot,
        ValueIdentity url,
        ValueIdentity properties,
        List<PropertyEntry> propertyEntries) {

    public static final String GRAPH_NOTE_KEY = "jdbcConnectionCallSite";
    public static final String DRIVER_MANAGER_OWNER = "java/sql/DriverManager";
    public static final String DRIVER_OWNER = "java/sql/Driver";
    public static final String GET_CONNECTION_NAME = "getConnection";
    public static final String CONNECT_NAME = "connect";
    public static final String CONNECTION_DESCRIPTOR =
            "(Ljava/lang/String;Ljava/util/Properties;)Ljava/sql/Connection;";
    public static final String URL_DESCRIPTOR = "Ljava/lang/String;";
    public static final String PROPERTIES_DESCRIPTOR = "Ljava/util/Properties;";
    public static final String CONNECTION_DESCRIPTOR_TYPE = "Ljava/sql/Connection;";

    public enum Kind {
        DRIVER_MANAGER_GET_CONNECTION,
        DRIVER_CONNECT
    }

    /** Explicit value state; UNKNOWN never becomes a guessed literal. */
    public enum ValueState {
        KNOWN,
        NULL,
        UNKNOWN
    }

    /**
     * Value identity at a producer or consumer slot.  {@code token} is a physical-flow token,
     * not the displayed string; equal text at different offsets is intentionally different.
     */
    public record ValueIdentity(ValueState state, String token, String displayValue,
                                 String descriptor, int producerOffset) {
        public ValueIdentity {
            state = Objects.requireNonNull(state, "JDBC value state");
            token = requireText(token, "JDBC value identity token");
            descriptor = requireText(descriptor, "JDBC value descriptor");
            if (producerOffset < -1) {
                throw new IllegalArgumentException("JDBC value producer offset must be -1 or greater");
            }
            if (state == ValueState.KNOWN && displayValue == null) {
                // Objects such as Properties are known by allocation identity but have no text.
                displayValue = "";
            }
            if (state != ValueState.KNOWN && displayValue != null) {
                throw new IllegalArgumentException("non-known JDBC value cannot carry display text");
            }
        }

        public static ValueIdentity known(String token, String descriptor, int producerOffset,
                                          String displayValue) {
            return new ValueIdentity(ValueState.KNOWN, token, displayValue, descriptor,
                    producerOffset);
        }

        public static ValueIdentity nullValue(String token, String descriptor, int producerOffset) {
            return new ValueIdentity(ValueState.NULL, token, null, descriptor, producerOffset);
        }

        public static ValueIdentity unknown(String token, String descriptor, int producerOffset) {
            return new ValueIdentity(ValueState.UNKNOWN, token, null, descriptor, producerOffset);
        }

        public boolean known() {
            return state == ValueState.KNOWN;
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

    /** Exact Properties mutation with receiver, key and value slots preserved. */
    public record PropertyEntry(TypedBridgeFact.CallSite callSite,
                                TypedBridgeFact.Slot receiverSlot,
                                TypedBridgeFact.Slot keySlot,
                                TypedBridgeFact.Slot valueSlot,
                                ValueIdentity receiver,
                                ValueIdentity key,
                                ValueIdentity value) {
        public static final String PROPERTIES_OWNER = "java/util/Properties";
        public static final String SET_PROPERTY_NAME = "setProperty";
        public static final String SET_PROPERTY_DESCRIPTOR =
                "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/Object;";
        public static final String PUT_NAME = "put";
        public static final String PUT_DESCRIPTOR =
                "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;";

        public PropertyEntry {
            callSite = Objects.requireNonNull(callSite, "JDBC Properties call site");
            receiverSlot = Objects.requireNonNull(receiverSlot, "JDBC Properties receiver slot");
            keySlot = Objects.requireNonNull(keySlot, "JDBC Properties key slot");
            valueSlot = Objects.requireNonNull(valueSlot, "JDBC Properties value slot");
            receiver = Objects.requireNonNull(receiver, "JDBC Properties receiver identity");
            key = Objects.requireNonNull(key, "JDBC Properties key identity");
            value = Objects.requireNonNull(value, "JDBC Properties value identity");
            if (!PROPERTIES_OWNER.equals(callSite.calleeOwner())
                    || callSite.invokeKind() != TypedBridgeFact.InvokeKind.VIRTUAL
                    || !(SET_PROPERTY_NAME.equals(callSite.calleeName())
                    || PUT_NAME.equals(callSite.calleeName()))) {
                throw new IllegalArgumentException("JDBC Properties mutation is not exact");
            }
            String descriptor = callSite.calleeDescriptor();
            String keyDescriptor;
            String valueDescriptor;
            if (SET_PROPERTY_NAME.equals(callSite.calleeName())) {
                if (!SET_PROPERTY_DESCRIPTOR.equals(descriptor)) {
                    throw new IllegalArgumentException("JDBC setProperty descriptor is not exact");
                }
                keyDescriptor = URL_DESCRIPTOR;
                valueDescriptor = URL_DESCRIPTOR;
            } else {
                if (!PUT_DESCRIPTOR.equals(descriptor)) {
                    throw new IllegalArgumentException("JDBC Properties.put descriptor is not exact");
                }
                keyDescriptor = "Ljava/lang/Object;";
                valueDescriptor = "Ljava/lang/Object;";
            }
            if (!new TypedBridgeFact.Slot(TypedBridgeFact.Slot.Position.RECEIVER, -1,
                    "L" + PROPERTIES_OWNER + ";").equals(receiverSlot)
                    || !keyDescriptor.equals(keySlot.descriptor())
                    || !valueDescriptor.equals(valueSlot.descriptor())
                    || keySlot.position() != TypedBridgeFact.Slot.Position.ARGUMENT
                    || keySlot.ordinal() != 0
                    || valueSlot.position() != TypedBridgeFact.Slot.Position.ARGUMENT
                    || valueSlot.ordinal() != 1) {
                throw new IllegalArgumentException("JDBC Properties slot contract is invalid");
            }
        }

        public boolean keyAndValueKnown() {
            return key.known() && value.known();
        }
    }

    public JdbcConnectionCallSite {
        callSite = Objects.requireNonNull(callSite, "JDBC connection call site");
        kind = Objects.requireNonNull(kind, "JDBC connection kind");
        urlSlot = Objects.requireNonNull(urlSlot, "JDBC URL slot");
        propertiesSlot = Objects.requireNonNull(propertiesSlot, "JDBC Properties slot");
        returnSlot = Objects.requireNonNull(returnSlot, "JDBC return slot");
        url = Objects.requireNonNull(url, "JDBC URL identity");
        properties = Objects.requireNonNull(properties, "JDBC Properties identity");
        propertyEntries = List.copyOf(Objects.requireNonNull(propertyEntries,
                "JDBC Properties entries"));
        validateCall(callSite, kind);
        if (!new TypedBridgeFact.Slot(TypedBridgeFact.Slot.Position.ARGUMENT, 0,
                URL_DESCRIPTOR).equals(urlSlot)
                || !new TypedBridgeFact.Slot(TypedBridgeFact.Slot.Position.ARGUMENT, 1,
                PROPERTIES_DESCRIPTOR).equals(propertiesSlot)
                || !new TypedBridgeFact.Slot(TypedBridgeFact.Slot.Position.RETURN, -1,
                CONNECTION_DESCRIPTOR_TYPE).equals(returnSlot)) {
            throw new IllegalArgumentException("JDBC connection slot contract is invalid");
        }
        for (PropertyEntry entry : propertyEntries) {
            if (!properties.token().equals(entry.receiver().token())) {
                throw new IllegalArgumentException(
                        "JDBC Properties entry does not share the connection object identity");
            }
        }
    }

    /** Match only the exact URL + Properties overloads; user/password overloads are excluded. */
    public static boolean matches(String owner, String name, String descriptor, String invokeKind) {
        return CONNECTION_DESCRIPTOR.equals(descriptor)
                && ((DRIVER_MANAGER_OWNER.equals(owner)
                && GET_CONNECTION_NAME.equals(name) && "STATIC".equals(invokeKind))
                || (DRIVER_OWNER.equals(owner)
                && CONNECT_NAME.equals(name) && "INTERFACE".equals(invokeKind)));
    }

    /** Build an explicit unknown-value fact when the exact consumer is known but flow is not. */
    public static Optional<JdbcConnectionCallSite> fromCall(long callId, MethodId hostMethod,
                                                              int callOffset, String owner,
                                                              String name, String descriptor,
                                                              String invokeKind) {
        if (!matches(owner, name, descriptor, invokeKind) || hostMethod == null) {
            return Optional.empty();
        }
        Kind kind = DRIVER_MANAGER_OWNER.equals(owner)
                ? Kind.DRIVER_MANAGER_GET_CONNECTION : Kind.DRIVER_CONNECT;
        TypedBridgeFact.CallSite callSite = new TypedBridgeFact.CallSite(callId, hostMethod,
                callOffset, owner, name, descriptor, invokeKind(invokeKind));
        return Optional.of(withValues(callSite, kind,
                ValueIdentity.unknown("jdbc-unknown-url:" + callSite.identity(), URL_DESCRIPTOR, -1),
                ValueIdentity.unknown("jdbc-unknown-properties:" + callSite.identity(),
                        PROPERTIES_DESCRIPTOR, -1), List.of()));
    }

    public static JdbcConnectionCallSite withValues(TypedBridgeFact.CallSite callSite, Kind kind,
                                                     ValueIdentity url, ValueIdentity properties,
                                                     List<PropertyEntry> entries) {
        return new JdbcConnectionCallSite(callSite, kind,
                new TypedBridgeFact.Slot(TypedBridgeFact.Slot.Position.ARGUMENT, 0, URL_DESCRIPTOR),
                new TypedBridgeFact.Slot(TypedBridgeFact.Slot.Position.ARGUMENT, 1,
                        PROPERTIES_DESCRIPTOR),
                new TypedBridgeFact.Slot(TypedBridgeFact.Slot.Position.RETURN, -1,
                        CONNECTION_DESCRIPTOR_TYPE), url, properties, entries);
    }

    public String identity() {
        return "jdbc-connection-v1:" + callSite.identity();
    }

    private static void validateCall(TypedBridgeFact.CallSite callSite, Kind kind) {
        boolean manager = kind == Kind.DRIVER_MANAGER_GET_CONNECTION;
        String owner = manager ? DRIVER_MANAGER_OWNER : DRIVER_OWNER;
        String name = manager ? GET_CONNECTION_NAME : CONNECT_NAME;
        TypedBridgeFact.InvokeKind invokeKind = manager
                ? TypedBridgeFact.InvokeKind.STATIC : TypedBridgeFact.InvokeKind.INTERFACE;
        if (!owner.equals(callSite.calleeOwner()) || !name.equals(callSite.calleeName())
                || !CONNECTION_DESCRIPTOR.equals(callSite.calleeDescriptor())
                || invokeKind != callSite.invokeKind()) {
            throw new IllegalArgumentException("JDBC connection call site is not exact");
        }
    }

    private static TypedBridgeFact.InvokeKind invokeKind(String value) {
        return switch (value) {
            case "STATIC" -> TypedBridgeFact.InvokeKind.STATIC;
            case "INTERFACE" -> TypedBridgeFact.InvokeKind.INTERFACE;
            case "VIRTUAL" -> TypedBridgeFact.InvokeKind.VIRTUAL;
            case "SPECIAL" -> TypedBridgeFact.InvokeKind.SPECIAL;
            case "DYNAMIC" -> TypedBridgeFact.InvokeKind.DYNAMIC;
            default -> throw new IllegalArgumentException("unknown JVM invoke kind: " + value);
        };
    }
}
