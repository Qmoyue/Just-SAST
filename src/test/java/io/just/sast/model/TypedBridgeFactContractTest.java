package io.just.sast.model;

import io.just.sast.cpg.build.CpgBuilder;
import io.just.sast.cpg.graph.Graph;
import io.just.sast.cpg.graph.Node;
import io.just.sast.frontend.asm.FactsExtractor;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TypedBridgeFactContractTest {

    @Test
    void actualCpgCallSitesCarryAllTypedConnectionConditions() {
        ClassInfo info = extract(callSiteBytes());
        LoadResult load = new LoadResult(Map.of(info.internalName(), info), List.of(), 1, 61);
        ArtifactProvenance artifact = new ArtifactProvenance("typed-bridge.jar",
                ArtifactProvenance.Role.APPLICATION, "A".repeat(64), 128L);
        ProgramUniverse universe = ProgramUniverse.of(load,
                Map.of(info.internalName(), artifact), List.of(artifact));
        Graph graph = new CpgBuilder().build(universe).graph();
        String hostKey = info.internalName() + "#wire()V";
        List<Node> calls = graph.callsOfMethod(hostKey);
        Node producerCall = calls.stream().filter(node -> "produce".equals(node.name()))
                .findFirst().orElseThrow();
        Node consumerCall = calls.stream().filter(node -> "accept".equals(node.name()))
                .findFirst().orElseThrow();
        MethodId host = MethodId.of(info.internalName(), "wire", "()V");
        ArtifactProvenance resolved = universe.artifactFor(TypeId.of(info.internalName()))
                .orElseThrow();

        TypedBridgeFact.Endpoint producer = endpoint(host, producerCall,
                TypedBridgeFact.Slot.returnValue("Ljava/lang/String;"),
                "request-value", "java/lang/String", resolved);
        TypedBridgeFact.Endpoint consumer = endpoint(host, consumerCall,
                TypedBridgeFact.Slot.argument(0, "Ljava/lang/String;"),
                "request-value", "java/lang/String", resolved);

        TypedBridgeFact bridge = TypedBridgeFact.connect(TypedBridgeFact.Relation.VALUE_FLOW,
                producer, consumer, TypedBridgeFact.IdentityRelation.SAME,
                TypedBridgeFact.ArtifactRelation.SAME_ARTIFACT);

        assertTrue(bridge.proved());
        assertEquals(TypedBridgeFact.Status.PROVED, bridge.status());
        assertEquals(TypedBridgeFact.Reason.NONE, bridge.reason());
        assertEquals(TypedBridgeFact.Slot.Position.RETURN, bridge.producer().slot().position());
        assertEquals(TypedBridgeFact.Slot.Position.ARGUMENT, bridge.consumer().slot().position());
        assertEquals("java/lang/String", bridge.producer().type().internalName());
        assertEquals(resolved.identity(), bridge.consumer().artifact().identity());
        assertTrue(bridge.identity().contains("typed-bridge-v1|VALUE_FLOW"));
    }

    @Test
    void sameDisplayTextWithDifferentIdentityCannotBecomeAFlow() {
        TypedBridgeFact.Endpoint producer = endpoint("produce", 1L, 3,
                "fixture/Host", "produce", "()Ljava/lang/String;",
                "request-value", "java/lang/String", applicationArtifact());
        TypedBridgeFact.Endpoint consumer = endpoint("consume", 2L, 7,
                "fixture/Host", "accept", "(Ljava/lang/String;)V",
                "request-value-other", "java/lang/String", applicationArtifact());

        TypedBridgeFact bridge = TypedBridgeFact.connect(TypedBridgeFact.Relation.VALUE_FLOW,
                producer, consumer, TypedBridgeFact.IdentityRelation.SAME,
                TypedBridgeFact.ArtifactRelation.SAME_ARTIFACT);

        assertEquals(TypedBridgeFact.Status.UNKNOWN, bridge.status());
        assertEquals(TypedBridgeFact.Reason.IDENTITY_MISMATCH, bridge.reason());
        assertFalse(bridge.proved());
        assertNotEquals(producer.identity(), consumer.identity());
    }

    @Test
    void descriptorAndTypeMismatchesRemainUnknown() {
        TypedBridgeFact.Endpoint producer = endpoint("produce", 1L, 3,
                "fixture/Host", "produce", "()Ljava/lang/String;",
                "value", "java/lang/String", applicationArtifact());
        TypedBridgeFact.Endpoint objectConsumer = endpoint("consume-object", 2L, 7,
                "fixture/Host", "accept", "(Ljava/lang/Object;)V",
                "value", "java/lang/String", applicationArtifact());
        TypedBridgeFact.Endpoint integerConsumer = endpoint("consume-int", 3L, 9,
                "fixture/Host", "acceptInt", "(Ljava/lang/String;)V",
                "value", "java/lang/Integer", applicationArtifact());

        TypedBridgeFact descriptorMismatch = TypedBridgeFact.connect(
                TypedBridgeFact.Relation.VALUE_FLOW, producer, objectConsumer,
                TypedBridgeFact.IdentityRelation.SAME,
                TypedBridgeFact.ArtifactRelation.SAME_ARTIFACT);
        TypedBridgeFact typeMismatch = TypedBridgeFact.connect(
                TypedBridgeFact.Relation.VALUE_FLOW, producer, integerConsumer,
                TypedBridgeFact.IdentityRelation.SAME,
                TypedBridgeFact.ArtifactRelation.SAME_ARTIFACT);

        assertEquals(TypedBridgeFact.Status.UNKNOWN, descriptorMismatch.status());
        assertEquals(TypedBridgeFact.Reason.DESCRIPTOR_MISMATCH, descriptorMismatch.reason());
        assertEquals(TypedBridgeFact.Status.UNKNOWN, typeMismatch.status());
        assertEquals(TypedBridgeFact.Reason.TYPE_MISMATCH, typeMismatch.reason());
    }

    @Test
    void missingArtifactDigestIsExplicitPartialAndCrossArtifactNeedsTypedRelation() {
        ArtifactProvenance unknown = ArtifactProvenance.unknown("unknown.jar",
                ArtifactProvenance.Role.DEPENDENCY);
        TypedBridgeFact.Endpoint unknownProducer = endpoint("producer", 1L, 3,
                "fixture/Host", "produce", "()Ljava/lang/String;",
                "value", "java/lang/String", unknown);
        TypedBridgeFact.Endpoint knownConsumer = endpoint("consumer", 2L, 7,
                "fixture/Host", "accept", "(Ljava/lang/String;)V",
                "value", "java/lang/String", applicationArtifact());

        TypedBridgeFact partial = TypedBridgeFact.connect(TypedBridgeFact.Relation.VALUE_FLOW,
                unknownProducer, knownConsumer, TypedBridgeFact.IdentityRelation.SAME,
                TypedBridgeFact.ArtifactRelation.SAME_ARTIFACT);
        assertEquals(TypedBridgeFact.Status.PARTIAL, partial.status());
        assertEquals(TypedBridgeFact.Reason.ARTIFACT_PROVENANCE_UNKNOWN, partial.reason());

        ArtifactProvenance dependency = new ArtifactProvenance("dependency.jar",
                ArtifactProvenance.Role.DEPENDENCY, "B".repeat(64), 256L);
        TypedBridgeFact.Endpoint crossConsumer = endpoint("consumer-cross", 4L, 11,
                "fixture/Consumer", "accept", "(Ljava/lang/String;)V",
                "value-derived", "java/lang/String", dependency);
        TypedBridgeFact unprovedCross = TypedBridgeFact.connect(
                TypedBridgeFact.Relation.CALLBACK, knownConsumer, crossConsumer,
                TypedBridgeFact.IdentityRelation.DECLARED_DERIVATION,
                TypedBridgeFact.ArtifactRelation.UNKNOWN);
        TypedBridgeFact provedCross = TypedBridgeFact.connect(
                TypedBridgeFact.Relation.CALLBACK, knownConsumer, crossConsumer,
                TypedBridgeFact.IdentityRelation.DECLARED_DERIVATION,
                TypedBridgeFact.ArtifactRelation.EXPLICIT_CROSS_ARTIFACT);

        assertEquals(TypedBridgeFact.Status.PARTIAL, unprovedCross.status());
        assertEquals(TypedBridgeFact.Status.PROVED, provedCross.status());
    }

    @Test
    void explicitCrossArtifactEdgeRetainsEndpointOwnersOrdinalsDescriptorsAndProvenance() {
        ArtifactProvenance application = applicationArtifact();
        ArtifactProvenance dependency = new ArtifactProvenance("dependency.jar",
                ArtifactProvenance.Role.DEPENDENCY, "D".repeat(64), 256L);
        TypedBridgeFact.Endpoint producer = endpoint("producer", 11L, 4,
                "fixture/Producer", "produce", "()Ljava/lang/String;",
                "url-value", "java/lang/String", application,
                TypedBridgeFact.Slot.returnValue("Ljava/lang/String;"));
        TypedBridgeFact.Endpoint consumer = endpoint("consumer", 19L, 8,
                "fixture/Consumer", "accept", "(Ljava/lang/String;)V",
                "url-value", "java/lang/String", dependency,
                TypedBridgeFact.Slot.argument(0, "Ljava/lang/String;"));

        TypedBridgeFact edge = TypedBridgeFact.connectCrossArtifact(
                TypedBridgeFact.Relation.VALUE_FLOW, producer, consumer,
                TypedBridgeFact.IdentityRelation.SAME);

        assertTrue(edge.proved());
        assertEquals(TypedBridgeFact.ArtifactRelation.EXPLICIT_CROSS_ARTIFACT,
                edge.artifactRelation());
        assertEquals("fixture/Producer", edge.producerOwner());
        assertEquals("fixture/Consumer", edge.consumerOwner());
        assertEquals(-1, edge.producerOrdinal());
        assertEquals(0, edge.consumerOrdinal());
        assertEquals("Ljava/lang/String;", edge.producerDescriptor());
        assertEquals("Ljava/lang/String;", edge.consumerDescriptor());
        assertEquals(application.identity(), edge.producerArtifact().identity());
        assertEquals(dependency.identity(), edge.consumerArtifact().identity());
    }

    @Test
    void crossArtifactHelperKeepsUnknownAndSameArtifactBoundariesExplicit() {
        ArtifactProvenance application = applicationArtifact();
        TypedBridgeFact.Endpoint producer = endpoint("producer", 21L, 4,
                "fixture/Producer", "produce", "()Ljava/lang/String;",
                "url-value", "java/lang/String", application,
                TypedBridgeFact.Slot.returnValue("Ljava/lang/String;"));
        TypedBridgeFact.Endpoint consumer = endpoint("consumer", 29L, 8,
                "fixture/Consumer", "accept", "(Ljava/lang/String;)V",
                "url-value", "java/lang/String", application,
                TypedBridgeFact.Slot.argument(0, "Ljava/lang/String;"));

        TypedBridgeFact sameArtifact = TypedBridgeFact.connectCrossArtifact(
                TypedBridgeFact.Relation.VALUE_FLOW, producer, consumer,
                TypedBridgeFact.IdentityRelation.SAME);
        TypedBridgeFact unknownRelation = TypedBridgeFact.connect(
                TypedBridgeFact.Relation.VALUE_FLOW, producer, consumer,
                TypedBridgeFact.IdentityRelation.SAME,
                TypedBridgeFact.ArtifactRelation.UNKNOWN);

        assertEquals(TypedBridgeFact.Status.UNKNOWN, sameArtifact.status());
        assertEquals(TypedBridgeFact.Reason.ARTIFACT_RELATION_MISMATCH, sameArtifact.reason());
        assertEquals(TypedBridgeFact.Status.PARTIAL, unknownRelation.status());
        assertEquals(TypedBridgeFact.Reason.ARTIFACT_PROVENANCE_UNKNOWN,
                unknownRelation.reason());
    }

    @Test
    void slotAndForgedStatusContractsFailClosed() {
        assertThrows(IllegalArgumentException.class,
                () -> TypedBridgeFact.Slot.argument(-1, "Ljava/lang/String;"));
        assertThrows(IllegalArgumentException.class,
                () -> endpoint("bad", 1L, 3, "fixture/Host", "accept",
                        "(Ljava/lang/String;)V", "value", "java/lang/String",
                        applicationArtifact(),
                        TypedBridgeFact.Slot.argument(0, "Ljava/lang/Object;")));

        TypedBridgeFact.Endpoint producer = endpoint("same", 1L, 3,
                "fixture/Host", "produce", "()Ljava/lang/String;", "same",
                "java/lang/String", applicationArtifact());
        TypedBridgeFact.Endpoint consumer = endpoint("same", 2L, 7,
                "fixture/Host", "accept", "(Ljava/lang/String;)V", "same",
                "java/lang/String", applicationArtifact());
        assertThrows(IllegalArgumentException.class, () -> new TypedBridgeFact(
                TypedBridgeFact.Relation.VALUE_FLOW, producer, consumer,
                TypedBridgeFact.IdentityRelation.SAME,
                TypedBridgeFact.ArtifactRelation.SAME_ARTIFACT,
                TypedBridgeFact.Status.UNKNOWN, TypedBridgeFact.Reason.NONE));
    }

    private static TypedBridgeFact.Endpoint endpoint(MethodId host, Node call,
                                                      TypedBridgeFact.Slot slot,
                                                      String identity, String type,
                                                      ArtifactProvenance artifact) {
        return new TypedBridgeFact.Endpoint(new TypedBridgeFact.FlowIdentity(identity),
                new TypedBridgeFact.CallSite(call.id(), host, call.offset(), call.owner(),
                        call.name(), call.descriptor(), TypedBridgeFact.InvokeKind.STATIC), slot,
                TypeId.of(type), artifact);
    }

    private static TypedBridgeFact.Endpoint endpoint(String identity, long callId, int offset,
                                                      String owner, String name, String descriptor,
                                                      String flowIdentity, String type,
                                                      ArtifactProvenance artifact) {
        return endpoint(identity, callId, offset, owner, name, descriptor, flowIdentity, type,
                artifact, defaultSlot(descriptor));
    }

    private static TypedBridgeFact.Endpoint endpoint(String identity, long callId, int offset,
                                                      String owner, String name, String descriptor,
                                                      String flowIdentity, String type,
                                                      ArtifactProvenance artifact,
                                                      TypedBridgeFact.Slot slot) {
        return new TypedBridgeFact.Endpoint(new TypedBridgeFact.FlowIdentity(flowIdentity),
                new TypedBridgeFact.CallSite(callId,
                        MethodId.of("fixture/Host", "wire", "()V"), offset, owner, name,
                        descriptor, TypedBridgeFact.InvokeKind.STATIC), slot, TypeId.of(type), artifact);
    }

    private static TypedBridgeFact.Slot defaultSlot(String descriptor) {
        return descriptor.endsWith("V")
                ? TypedBridgeFact.Slot.argument(0, Descriptor.paramType(descriptor, 0))
                : TypedBridgeFact.Slot.returnValue(Descriptor.returnType(descriptor));
    }

    private static ArtifactProvenance applicationArtifact() {
        return new ArtifactProvenance("application.jar", ArtifactProvenance.Role.APPLICATION,
                "C".repeat(64), 512L);
    }

    private static ClassInfo extract(byte[] bytes) {
        org.objectweb.asm.tree.ClassNode node = new org.objectweb.asm.tree.ClassNode();
        new ClassReader(bytes).accept(node, 0);
        return new FactsExtractor().extract(node);
    }

    private static byte[] callSiteBytes() {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "fixture/TypedBridgeHost", null,
                "java/lang/Object", null);
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "wire", "()V", null, null);
        method.visitCode();
        method.visitMethodInsn(Opcodes.INVOKESTATIC, "fixture/Producer", "produce",
                "()Ljava/lang/String;", false);
        method.visitMethodInsn(Opcodes.INVOKESTATIC, "fixture/Consumer", "accept",
                "(Ljava/lang/String;)V", false);
        method.visitInsn(Opcodes.RETURN);
        method.visitMaxs(1, 0);
        method.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }
}
