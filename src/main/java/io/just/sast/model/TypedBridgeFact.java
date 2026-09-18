package io.just.sast.model;

import java.util.Objects;

/**
 * Immutable contract for one typed producer-to-consumer bridge.
 *
 * <p>A bridge is a relation between two physical call-site positions.  The model keeps the
 * value/object identity separate from the endpoint identity, so equal names or equal display
 * text can never create a flow on their own.  Every endpoint also carries its declared slot
 * descriptor, resolved type and artifact provenance.  Future protocol owners (JNDI, JDBC,
 * JAAS, proxy and Hessian) use this same contract instead of inventing string joins.</p>
 *
 * <p>This is a data-only model.  It does not load a type, invoke a method or evaluate target
 * code.  A failed connection is an explicit fact with a status and reason; it is never
 * represented by a missing value.</p>
 */
public record TypedBridgeFact(
        Relation relation,
        Endpoint producer,
        Endpoint consumer,
        IdentityRelation identityRelation,
        ArtifactRelation artifactRelation,
        Status status,
        Reason reason) {

    public static final int MODEL_VERSION = 1;

    /** Semantic owner of the connection; protocol-specific rules select the relation. */
    public enum Relation {
        VALUE_FLOW,
        OBJECT_FLOW,
        FIELD_FLOW,
        CALLBACK,
        CAPABILITY
    }

    /** How the producer and consumer identities were established. */
    public enum IdentityRelation {
        SAME,
        DECLARED_DERIVATION,
        UNKNOWN
    }

    /** Provenance relation supplied by the artifact/closure owner. */
    public enum ArtifactRelation {
        SAME_ARTIFACT,
        EXPLICIT_CROSS_ARTIFACT,
        UNKNOWN
    }

    public enum Status {
        PROVED,
        PARTIAL,
        UNKNOWN
    }

    /** Closed reason axis for an unproved connection. */
    public enum Reason {
        NONE,
        IDENTITY_UNKNOWN,
        IDENTITY_MISMATCH,
        IDENTITY_RELATION_MISMATCH,
        DESCRIPTOR_MISMATCH,
        TYPE_MISMATCH,
        ARTIFACT_PROVENANCE_UNKNOWN,
        ARTIFACT_RELATION_MISMATCH
    }

    /** Closed JVM invocation-kind axis used by every physical call-site endpoint. */
    public enum InvokeKind {
        STATIC,
        SPECIAL,
        VIRTUAL,
        INTERFACE,
        DYNAMIC
    }

    /** One receiver, argument or return position at a physical call site. */
    public record Slot(Position position, int ordinal, String descriptor) {
        public enum Position {
            RECEIVER,
            ARGUMENT,
            RETURN
        }

        public Slot {
            position = Objects.requireNonNull(position, "bridge slot position");
            descriptor = requireText(descriptor, "bridge slot descriptor");
            if (position == Position.ARGUMENT && ordinal < 0) {
                throw new IllegalArgumentException("bridge argument ordinal must be non-negative");
            }
            if (position != Position.ARGUMENT && ordinal != -1) {
                throw new IllegalArgumentException(
                        "bridge receiver/return ordinal must be -1");
            }
        }

        public static Slot receiver(String descriptor) {
            return new Slot(Position.RECEIVER, -1, descriptor);
        }

        public static Slot argument(int ordinal, String descriptor) {
            return new Slot(Position.ARGUMENT, ordinal, descriptor);
        }

        public static Slot returnValue(String descriptor) {
            return new Slot(Position.RETURN, -1, descriptor);
        }

        public String identity() {
            return position.name() + ":" + ordinal + ":" + descriptor;
        }
    }

    /** Exact physical call-site contract; the descriptor is the callee JVM descriptor. */
    public record CallSite(long callId, MethodId hostMethod, int callOffset,
                           String calleeOwner, String calleeName, String calleeDescriptor,
                           InvokeKind invokeKind) {
        public CallSite {
            if (callId < 0) {
                throw new IllegalArgumentException("bridge call id must be non-negative");
            }
            hostMethod = Objects.requireNonNull(hostMethod, "bridge host method");
            if (callOffset < 0) {
                throw new IllegalArgumentException("bridge call offset must be non-negative");
            }
            calleeOwner = requireText(calleeOwner, "bridge callee owner");
            calleeName = requireText(calleeName, "bridge callee name");
            calleeDescriptor = requireText(calleeDescriptor, "bridge callee descriptor");
            invokeKind = Objects.requireNonNull(invokeKind, "bridge invoke kind");
        }

        public String identity() {
            return "bridge-call-v1:" + callId + "@" + hostMethod.canonical() + ":"
                    + callOffset + "->" + calleeOwner + "#" + calleeName
                    + calleeDescriptor + ":" + invokeKind;
        }
    }

    /** A value/object endpoint with no implicit provenance or identity inference. */
    public record Endpoint(FlowIdentity identity, CallSite callSite, Slot slot, TypeId type,
                            ArtifactProvenance artifact) {
        public Endpoint {
            identity = Objects.requireNonNull(identity, "bridge endpoint identity");
            callSite = Objects.requireNonNull(callSite, "bridge endpoint call site");
            slot = Objects.requireNonNull(slot, "bridge endpoint slot");
            type = Objects.requireNonNull(type, "bridge endpoint type");
            artifact = Objects.requireNonNull(artifact, "bridge endpoint artifact provenance");
            validateSlot(callSite, slot);
        }

        public String canonical() {
            return identity.canonical() + "|" + callSite.identity() + "|"
                    + slot.identity() + "|" + type.canonical() + "|" + artifact.identity();
        }

        private static void validateSlot(CallSite callSite, Slot slot) {
            String expected;
            switch (slot.position()) {
                case RECEIVER -> {
                    if (callSite.invokeKind() == InvokeKind.STATIC
                            || callSite.invokeKind() == InvokeKind.DYNAMIC) {
                        throw new IllegalArgumentException(
                                "bridge receiver slot is invalid for static/dynamic call");
                    }
                    expected = "L" + callSite.calleeOwner() + ";";
                }
                case ARGUMENT -> expected = parameterDescriptor(callSite.calleeDescriptor(),
                        slot.ordinal());
                case RETURN -> expected = returnDescriptor(callSite.calleeDescriptor());
                default -> throw new IllegalArgumentException("unsupported bridge slot position");
            }
            if (!expected.equals(slot.descriptor())) {
                throw new IllegalArgumentException("bridge slot descriptor does not match call site");
            }
        }

        private static String parameterDescriptor(String descriptor, int ordinal) {
            int count = Descriptor.paramCount(descriptor);
            if (ordinal >= count) {
                throw new IllegalArgumentException("bridge argument ordinal is outside descriptor");
            }
            String value = Descriptor.paramType(descriptor, ordinal);
            if (value == null || value.isBlank()) {
                throw new IllegalArgumentException("bridge argument descriptor is unavailable");
            }
            return value;
        }

        private static String returnDescriptor(String descriptor) {
            int close = descriptor.indexOf(')');
            if (close < 0 || close == descriptor.length() - 1) {
                throw new IllegalArgumentException("bridge return descriptor is invalid");
            }
            return Descriptor.returnType(descriptor);
        }
    }

    /** Explicit identity token; its value is never inferred from type, name or display text. */
    public record FlowIdentity(String value) {
        public FlowIdentity {
            value = requireText(value, "bridge flow identity");
        }

        public String canonical() {
            return "flow-v1:" + value;
        }
    }

    public TypedBridgeFact {
        relation = Objects.requireNonNull(relation, "bridge relation");
        producer = Objects.requireNonNull(producer, "bridge producer");
        consumer = Objects.requireNonNull(consumer, "bridge consumer");
        identityRelation = Objects.requireNonNull(identityRelation, "bridge identity relation");
        artifactRelation = Objects.requireNonNull(artifactRelation, "bridge artifact relation");
        status = Objects.requireNonNull(status, "bridge status");
        reason = Objects.requireNonNull(reason, "bridge reason");
        Decision expected = decide(producer, consumer, identityRelation, artifactRelation);
        if (status != expected.status() || reason != expected.reason()) {
            throw new IllegalArgumentException("bridge status does not match typed constraints");
        }
    }

    /** Evaluate all bridge constraints in one owner and retain the result as an immutable fact. */
    public static TypedBridgeFact connect(Relation relation, Endpoint producer, Endpoint consumer,
                                          IdentityRelation identityRelation,
                                          ArtifactRelation artifactRelation) {
        Objects.requireNonNull(relation, "bridge relation");
        Objects.requireNonNull(producer, "bridge producer");
        Objects.requireNonNull(consumer, "bridge consumer");
        Objects.requireNonNull(identityRelation, "bridge identity relation");
        Objects.requireNonNull(artifactRelation, "bridge artifact relation");
        Decision decision = decide(producer, consumer, identityRelation, artifactRelation);
        return new TypedBridgeFact(relation, producer, consumer, identityRelation,
                artifactRelation, decision.status(), decision.reason());
    }

    /**
     * Connect endpoints whose artifacts are explicitly known to be different.
     *
     * <p>The relation is deliberately fixed here instead of asking each protocol owner to
     * repeat the cross-artifact enum choice.  Missing digests and identity/type/descriptor
     * conflicts still remain the normal explicit PARTIAL/UNKNOWN result of {@link #connect};
     * this helper never turns an unproved relation into a proved edge.</p>
     */
    public static TypedBridgeFact connectCrossArtifact(Relation relation, Endpoint producer,
                                                       Endpoint consumer,
                                                       IdentityRelation identityRelation) {
        return connect(relation, producer, consumer, identityRelation,
                ArtifactRelation.EXPLICIT_CROSS_ARTIFACT);
    }

    public boolean proved() {
        return status == Status.PROVED;
    }

    /** The exact callee owner at the producer endpoint; no display-name inference is involved. */
    public String producerOwner() {
        return producer.callSite().calleeOwner();
    }

    /** The exact callee owner at the consumer endpoint; no display-name inference is involved. */
    public String consumerOwner() {
        return consumer.callSite().calleeOwner();
    }

    /** The producer endpoint's declared slot ordinal, or -1 for receiver/return slots. */
    public int producerOrdinal() {
        return producer.slot().ordinal();
    }

    /** The consumer endpoint's declared slot ordinal, or -1 for receiver/return slots. */
    public int consumerOrdinal() {
        return consumer.slot().ordinal();
    }

    public String producerDescriptor() {
        return producer.slot().descriptor();
    }

    public String consumerDescriptor() {
        return consumer.slot().descriptor();
    }

    public ArtifactProvenance producerArtifact() {
        return producer.artifact();
    }

    public ArtifactProvenance consumerArtifact() {
        return consumer.artifact();
    }

    /** Stable semantic identity includes both endpoint positions and every constraint axis. */
    public String identity() {
        return "typed-bridge-v1|" + relation + "|" + producer.canonical() + "|"
                + consumer.canonical() + "|" + identityRelation + "|" + artifactRelation
                + "|" + status + "|" + reason;
    }

    private static Decision decide(Endpoint producer, Endpoint consumer,
                                   IdentityRelation identityRelation,
                                   ArtifactRelation artifactRelation) {
        if (identityRelation == IdentityRelation.UNKNOWN) {
            return new Decision(Status.UNKNOWN, Reason.IDENTITY_UNKNOWN);
        }
        boolean sameIdentity = producer.identity().equals(consumer.identity());
        if (identityRelation == IdentityRelation.SAME && !sameIdentity) {
            return new Decision(Status.UNKNOWN, Reason.IDENTITY_MISMATCH);
        }
        if (identityRelation == IdentityRelation.DECLARED_DERIVATION && sameIdentity) {
            return new Decision(Status.UNKNOWN, Reason.IDENTITY_RELATION_MISMATCH);
        }
        if (!producer.slot().descriptor().equals(consumer.slot().descriptor())) {
            return new Decision(Status.UNKNOWN, Reason.DESCRIPTOR_MISMATCH);
        }
        if (!producer.type().equals(consumer.type())) {
            return new Decision(Status.UNKNOWN, Reason.TYPE_MISMATCH);
        }
        if (!producer.artifact().hasContentDigest() || !consumer.artifact().hasContentDigest()) {
            return new Decision(Status.PARTIAL, Reason.ARTIFACT_PROVENANCE_UNKNOWN);
        }
        if (artifactRelation == ArtifactRelation.UNKNOWN) {
            return new Decision(Status.PARTIAL, Reason.ARTIFACT_PROVENANCE_UNKNOWN);
        }
        boolean sameArtifact = producer.artifact().identity()
                .equals(consumer.artifact().identity());
        if (artifactRelation == ArtifactRelation.SAME_ARTIFACT && !sameArtifact) {
            return new Decision(Status.UNKNOWN, Reason.ARTIFACT_RELATION_MISMATCH);
        }
        if (artifactRelation == ArtifactRelation.EXPLICIT_CROSS_ARTIFACT && sameArtifact) {
            return new Decision(Status.UNKNOWN, Reason.ARTIFACT_RELATION_MISMATCH);
        }
        return new Decision(Status.PROVED, Reason.NONE);
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
