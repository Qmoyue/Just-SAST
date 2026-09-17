package io.just.sast.model;

import java.util.Objects;

/**
 * Immutable bridge from a Reference factory-class field through {@code Class.forName} to the
 * typed ObjectFactory receiver.  The bridge consumes only facts already produced by the CPG,
 * call-graph and artifact owners; it never loads or invokes a target class.
 */
public record JndiReferenceFactoryClassConstraint(
        JndiReferenceFact reference,
        ClassForNameCallSite classForName,
        JndiReferenceFact.FieldValue classForNameArgument,
        TypedBridgeFact.Endpoint classNameEndpoint,
        TypedBridgeFact.Endpoint referenceFactoryEndpoint,
        TypedBridgeFact.Endpoint factoryReceiver,
        TypeId loadedFactoryType,
        TypedBridgeFact.IdentityRelation identityRelation,
        TypedBridgeFact.ArtifactRelation artifactRelation,
        TypedBridgeFact nameBridge,
        Status status,
        Reason reason) {

    private static final String OBJECT_FACTORY_OWNER = "javax/naming/spi/ObjectFactory";
    private static final String OBJECT_FACTORY_NAME = "getObjectInstance";
    private static final String OBJECT_FACTORY_DESCRIPTOR =
            "(Ljava/lang/Object;Ljavax/naming/Name;Ljavax/naming/Context;"
                    + "Ljava/util/Hashtable;)Ljava/lang/Object;";
    private static final String OBJECT_FACTORY_RECEIVER_DESCRIPTOR =
            "L" + OBJECT_FACTORY_OWNER + ";";

    public enum Status {
        PROVED,
        PARTIAL,
        UNKNOWN
    }

    public enum Reason {
        NONE,
        IDENTITY_UNKNOWN,
        IDENTITY_MISMATCH,
        IDENTITY_RELATION_MISMATCH,
        DESCRIPTOR_MISMATCH,
        TYPE_MISMATCH,
        ARTIFACT_PROVENANCE_UNKNOWN,
        ARTIFACT_RELATION_MISMATCH,
        REFERENCE_FACTORY_CLASS_UNKNOWN,
        CLASS_FOR_NAME_ARGUMENT_UNKNOWN,
        FACTORY_CLASS_NAME_MISMATCH,
        LOADED_FACTORY_TYPE_MISMATCH,
        FACTORY_RECEIVER_TYPE_MISMATCH
    }

    public JndiReferenceFactoryClassConstraint {
        reference = Objects.requireNonNull(reference, "Reference fact");
        classForName = Objects.requireNonNull(classForName, "Class.forName fact");
        classForNameArgument = Objects.requireNonNull(classForNameArgument,
                "Class.forName argument value");
        classNameEndpoint = Objects.requireNonNull(classNameEndpoint,
                "Class.forName argument endpoint");
        referenceFactoryEndpoint = Objects.requireNonNull(referenceFactoryEndpoint,
                "Reference factory-class endpoint");
        factoryReceiver = Objects.requireNonNull(factoryReceiver, "factory receiver endpoint");
        loadedFactoryType = Objects.requireNonNull(loadedFactoryType, "loaded factory type");
        identityRelation = Objects.requireNonNull(identityRelation, "identity relation");
        artifactRelation = Objects.requireNonNull(artifactRelation, "artifact relation");
        nameBridge = Objects.requireNonNull(nameBridge, "factory-class name bridge");
        validateClassNameEndpoint(classForName, classNameEndpoint);
        validateReferenceEndpoint(reference, referenceFactoryEndpoint);
        validateFactoryReceiver(factoryReceiver);
        TypedBridgeFact expectedNameBridge = buildNameBridge(classNameEndpoint,
                referenceFactoryEndpoint, identityRelation, artifactRelation);
        if (!expectedNameBridge.equals(nameBridge)) {
            throw new IllegalArgumentException("factory-class name bridge does not match endpoints");
        }
        Decision expected = decide(reference, classForNameArgument, factoryReceiver,
                loadedFactoryType, nameBridge);
        if (status != expected.status() || reason != expected.reason()) {
            throw new IllegalArgumentException("factory-class constraint status is inconsistent");
        }
    }

    /** Evaluate the complete Reference → Class.forName → factory receiver contract once. */
    public static JndiReferenceFactoryClassConstraint connect(
            JndiReferenceFact reference,
            ClassForNameCallSite classForName,
            JndiReferenceFact.FieldValue classForNameArgument,
            TypedBridgeFact.Endpoint classNameEndpoint,
            TypedBridgeFact.Endpoint referenceFactoryEndpoint,
            TypedBridgeFact.Endpoint factoryReceiver,
            TypeId loadedFactoryType,
            TypedBridgeFact.IdentityRelation identityRelation,
            TypedBridgeFact.ArtifactRelation artifactRelation) {
        Objects.requireNonNull(reference, "Reference fact");
        Objects.requireNonNull(classForName, "Class.forName fact");
        Objects.requireNonNull(classForNameArgument, "Class.forName argument value");
        Objects.requireNonNull(classNameEndpoint, "Class.forName argument endpoint");
        Objects.requireNonNull(referenceFactoryEndpoint, "Reference factory-class endpoint");
        Objects.requireNonNull(factoryReceiver, "factory receiver endpoint");
        Objects.requireNonNull(loadedFactoryType, "loaded factory type");
        Objects.requireNonNull(identityRelation, "identity relation");
        Objects.requireNonNull(artifactRelation, "artifact relation");
        TypedBridgeFact nameBridge = buildNameBridge(classNameEndpoint, referenceFactoryEndpoint,
                identityRelation, artifactRelation);
        Decision decision = decide(reference, classForNameArgument, factoryReceiver,
                loadedFactoryType, nameBridge);
        return new JndiReferenceFactoryClassConstraint(reference, classForName,
                classForNameArgument, classNameEndpoint, referenceFactoryEndpoint, factoryReceiver,
                loadedFactoryType, identityRelation, artifactRelation, nameBridge,
                decision.status(), decision.reason());
    }

    public boolean proved() {
        return status == Status.PROVED;
    }

    /** Stable identity retains Reference identity, all physical endpoints and every decision axis. */
    public String identity() {
        return "jndi-reference-factory-v1|" + reference.identity().identity() + "|"
                + classForName.identity() + "|" + classNameEndpoint.canonical() + "|"
                + referenceFactoryEndpoint.canonical() + "|" + factoryReceiver.canonical() + "|"
                + loadedFactoryType.canonical() + "|" + identityRelation + "|"
                + artifactRelation + "|" + status + "|" + reason;
    }

    private static TypedBridgeFact buildNameBridge(TypedBridgeFact.Endpoint classNameEndpoint,
                                                     TypedBridgeFact.Endpoint referenceEndpoint,
                                                     TypedBridgeFact.IdentityRelation identityRelation,
                                                     TypedBridgeFact.ArtifactRelation artifactRelation) {
        return TypedBridgeFact.connect(TypedBridgeFact.Relation.VALUE_FLOW, classNameEndpoint,
                referenceEndpoint, identityRelation, artifactRelation);
    }

    private static Decision decide(JndiReferenceFact reference,
                                   JndiReferenceFact.FieldValue classForNameArgument,
                                   TypedBridgeFact.Endpoint factoryReceiver,
                                   TypeId loadedFactoryType,
                                   TypedBridgeFact nameBridge) {
        if (!reference.factoryClass().isKnown()) {
            return new Decision(Status.PARTIAL, Reason.REFERENCE_FACTORY_CLASS_UNKNOWN);
        }
        if (!classForNameArgument.isKnown()) {
            return new Decision(Status.PARTIAL, Reason.CLASS_FOR_NAME_ARGUMENT_UNKNOWN);
        }
        if (nameBridge.status() != TypedBridgeFact.Status.PROVED) {
            return new Decision(statusOf(nameBridge.status()), reasonOf(nameBridge.reason()));
        }
        String referenceType = TypeId.of(reference.factoryClass().value()).internalName();
        String loadedType = TypeId.of(classForNameArgument.value()).internalName();
        if (!referenceType.equals(loadedType)) {
            return new Decision(Status.UNKNOWN, Reason.FACTORY_CLASS_NAME_MISMATCH);
        }
        if (!loadedFactoryType.internalName().equals(loadedType)) {
            return new Decision(Status.UNKNOWN, Reason.LOADED_FACTORY_TYPE_MISMATCH);
        }
        if (!factoryReceiver.type().equals(loadedFactoryType)) {
            return new Decision(Status.UNKNOWN, Reason.FACTORY_RECEIVER_TYPE_MISMATCH);
        }
        if (!factoryReceiver.artifact().hasContentDigest()) {
            return new Decision(Status.PARTIAL, Reason.ARTIFACT_PROVENANCE_UNKNOWN);
        }
        return new Decision(Status.PROVED, Reason.NONE);
    }

    private static Status statusOf(TypedBridgeFact.Status status) {
        return switch (status) {
            case PROVED -> Status.PROVED;
            case PARTIAL -> Status.PARTIAL;
            case UNKNOWN -> Status.UNKNOWN;
        };
    }

    private static Reason reasonOf(TypedBridgeFact.Reason reason) {
        return switch (reason) {
            case NONE -> Reason.NONE;
            case IDENTITY_UNKNOWN -> Reason.IDENTITY_UNKNOWN;
            case IDENTITY_MISMATCH -> Reason.IDENTITY_MISMATCH;
            case IDENTITY_RELATION_MISMATCH -> Reason.IDENTITY_RELATION_MISMATCH;
            case DESCRIPTOR_MISMATCH -> Reason.DESCRIPTOR_MISMATCH;
            case TYPE_MISMATCH -> Reason.TYPE_MISMATCH;
            case ARTIFACT_PROVENANCE_UNKNOWN -> Reason.ARTIFACT_PROVENANCE_UNKNOWN;
            case ARTIFACT_RELATION_MISMATCH -> Reason.ARTIFACT_RELATION_MISMATCH;
        };
    }

    private static void validateClassNameEndpoint(ClassForNameCallSite classForName,
                                                   TypedBridgeFact.Endpoint endpoint) {
        if (!classForName.callSite().equals(endpoint.callSite())
                || !classForName.argument().equals(endpoint.slot())) {
            throw new IllegalArgumentException("Class.forName endpoint is not its argument slot");
        }
    }

    private static void validateReferenceEndpoint(JndiReferenceFact reference,
                                                   TypedBridgeFact.Endpoint endpoint) {
        TypedBridgeFact.CallSite call = endpoint.callSite();
        if (!JndiReferenceFact.REFERENCE_OWNER.equals(call.calleeOwner())
                || !"<init>".equals(call.calleeName())
                || call.invokeKind() != TypedBridgeFact.InvokeKind.SPECIAL
                || call.callId() != reference.identity().constructionCallId()
                || call.callOffset() != reference.identity().constructionOffset()
                || !hostMethodKey(call.hostMethod()).equals(reference.identity().hostMethodKey())) {
            throw new IllegalArgumentException("Reference factory endpoint is not its constructor");
        }
        int factoryOrdinal;
        if (JndiReferenceFact.REFERENCE_CONSTRUCTOR_FACTORY_DESCRIPTOR
                .equals(call.calleeDescriptor())) {
            factoryOrdinal = 1;
        } else if (JndiReferenceFact.REFERENCE_CONSTRUCTOR_FULL_DESCRIPTOR
                .equals(call.calleeDescriptor())) {
            factoryOrdinal = 2;
        } else {
            throw new IllegalArgumentException("Reference constructor has no factory-class slot");
        }
        if (!TypedBridgeFact.Slot.argument(factoryOrdinal, "Ljava/lang/String;")
                .equals(endpoint.slot())) {
            throw new IllegalArgumentException("Reference factory-class slot is not exact");
        }
    }

    private static void validateFactoryReceiver(TypedBridgeFact.Endpoint endpoint) {
        TypedBridgeFact.CallSite call = endpoint.callSite();
        if (!OBJECT_FACTORY_OWNER.equals(call.calleeOwner())
                || !OBJECT_FACTORY_NAME.equals(call.calleeName())
                || !OBJECT_FACTORY_DESCRIPTOR.equals(call.calleeDescriptor())
                || call.invokeKind() != TypedBridgeFact.InvokeKind.INTERFACE
                || !TypedBridgeFact.Slot.receiver(OBJECT_FACTORY_RECEIVER_DESCRIPTOR)
                .equals(endpoint.slot())) {
            throw new IllegalArgumentException("factory receiver endpoint is not exact ObjectFactory");
        }
    }

    private static String hostMethodKey(MethodId method) {
        return method.owner().internalName() + "#" + method.name() + method.descriptor();
    }

    private record Decision(Status status, Reason reason) {
    }
}
