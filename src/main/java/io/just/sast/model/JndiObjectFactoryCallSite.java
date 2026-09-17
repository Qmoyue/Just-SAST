package io.just.sast.model;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Immutable fact for one exact JNDI {@code ObjectFactory#getObjectInstance} call site.
 *
 * <p>The fact is created from the CPG call node, after ASM has crossed the frontend seam.  It
 * records the JVM contract and physical caller position; it does not load a factory or execute
 * any factory code.  Concrete implementation targets are attached by the call-graph owner in
 * {@link JndiObjectFactoryDispatch}.</p>
 */
public record JndiObjectFactoryCallSite(long callId, String hostMethodKey, int callOffset,
                                        String invokeKind, Slot receiver,
                                        List<Slot> arguments, String returnDescriptor) {

    public static final String GRAPH_NOTE_KEY = "jndiObjectFactoryCallSite";
    public static final String DISPATCH_NOTE_KEY = "jndiObjectFactoryDispatch";
    public static final String OBJECT_FACTORY_OWNER = "javax/naming/spi/ObjectFactory";
    public static final String GET_OBJECT_INSTANCE_NAME = "getObjectInstance";
    public static final String GET_OBJECT_INSTANCE_DESCRIPTOR =
            "(Ljava/lang/Object;Ljavax/naming/Name;Ljavax/naming/Context;"
                    + "Ljava/util/Hashtable;)Ljava/lang/Object;";
    public static final String RECEIVER_DESCRIPTOR = "L" + OBJECT_FACTORY_OWNER + ";";
    public static final List<String> ARGUMENT_DESCRIPTORS = List.of(
            "Ljava/lang/Object;", "Ljavax/naming/Name;", "Ljavax/naming/Context;",
            "Ljava/util/Hashtable;");
    public static final String RETURN_DESCRIPTOR = "Ljava/lang/Object;";

    /** One exact JVM value position at the call site; -1 denotes the receiver. */
    public record Slot(int ordinal, String descriptor) {
        public Slot {
            if (ordinal < -1) {
                throw new IllegalArgumentException("ObjectFactory slot ordinal must be -1 or greater");
            }
            descriptor = requireText(descriptor, "ObjectFactory slot descriptor");
        }
    }

    public JndiObjectFactoryCallSite {
        if (callId < 0) {
            throw new IllegalArgumentException("ObjectFactory call id must be non-negative");
        }
        hostMethodKey = requireText(hostMethodKey, "ObjectFactory host method key");
        if (callOffset < 0) {
            throw new IllegalArgumentException("ObjectFactory call offset must be non-negative");
        }
        if (!"INTERFACE".equals(invokeKind)) {
            throw new IllegalArgumentException("ObjectFactory contract requires INVOKEINTERFACE");
        }
        receiver = Objects.requireNonNull(receiver, "ObjectFactory receiver");
        if (receiver.ordinal() != -1 || !RECEIVER_DESCRIPTOR.equals(receiver.descriptor())) {
            throw new IllegalArgumentException("ObjectFactory receiver contract is invalid");
        }
        arguments = List.copyOf(Objects.requireNonNull(arguments, "ObjectFactory arguments"));
        if (arguments.size() != ARGUMENT_DESCRIPTORS.size()) {
            throw new IllegalArgumentException("ObjectFactory argument count is invalid");
        }
        for (int index = 0; index < arguments.size(); index++) {
            Slot argument = Objects.requireNonNull(arguments.get(index), "ObjectFactory argument");
            if (argument.ordinal() != index
                    || !ARGUMENT_DESCRIPTORS.get(index).equals(argument.descriptor())) {
                throw new IllegalArgumentException("ObjectFactory argument contract is invalid");
            }
        }
        if (!RETURN_DESCRIPTOR.equals(returnDescriptor)) {
            throw new IllegalArgumentException("ObjectFactory return contract is invalid");
        }
    }

    /** Recognize only the exact JVM interface invocation, never a name-only factory method. */
    public static boolean matches(String owner, String name, String descriptor,
                                  String invokeKind) {
        return OBJECT_FACTORY_OWNER.equals(owner)
                && GET_OBJECT_INSTANCE_NAME.equals(name)
                && GET_OBJECT_INSTANCE_DESCRIPTOR.equals(descriptor)
                && "INTERFACE".equals(invokeKind);
    }

    /** Build the typed fact from a physical CPG call position when the exact contract matches. */
    public static Optional<JndiObjectFactoryCallSite> fromCall(long callId, String hostMethodKey,
                                                                int callOffset, String owner,
                                                                String name, String descriptor,
                                                                String invokeKind) {
        if (!matches(owner, name, descriptor, invokeKind)
                || hostMethodKey == null || hostMethodKey.isBlank()) {
            return Optional.empty();
        }
        List<Slot> arguments = java.util.stream.IntStream.range(0, ARGUMENT_DESCRIPTORS.size())
                .mapToObj(index -> new Slot(index, ARGUMENT_DESCRIPTORS.get(index)))
                .toList();
        return Optional.of(new JndiObjectFactoryCallSite(callId, hostMethodKey, callOffset,
                invokeKind, new Slot(-1, RECEIVER_DESCRIPTOR), arguments, RETURN_DESCRIPTOR));
    }

    /** Stable identity for this exact caller and bytecode call offset. */
    public String identity() {
        return "jndi-object-factory-call:call:" + callId + "@" + hostMethodKey
                + ":" + callOffset;
    }

    public String contractMethodKey() {
        return OBJECT_FACTORY_OWNER + "#" + GET_OBJECT_INSTANCE_NAME
                + GET_OBJECT_INSTANCE_DESCRIPTOR;
    }

    private static String requireText(String value, String label) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(label + " must not be blank");
        }
        return value;
    }
}
