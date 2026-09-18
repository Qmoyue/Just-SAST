package io.just.sast.cpg.build;

import io.just.sast.model.ArtifactProvenance;
import io.just.sast.model.ClassForNameCallSite;
import io.just.sast.model.ClassInfo;
import io.just.sast.model.JndiObjectFactoryCallSite;
import io.just.sast.model.JndiReferenceFact;
import io.just.sast.model.JndiReferenceFactoryClassConstraint;
import io.just.sast.model.LoadResult;
import io.just.sast.model.MethodId;
import io.just.sast.model.ProgramUniverse;
import io.just.sast.model.TypeId;
import io.just.sast.model.TypedBridgeFact;
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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JndiReferenceFactoryClassConstraintTest {

    @Test
    void exactCpgFactsJoinReferenceFactoryClassToClassForNameAndReceiverType() {
        Fixture fixture = fixture();
        ClassForNameCallSite classForName = fixture.classForName();
        assertNotNull(classForName);
        assertEquals(ClassForNameCallSite.DESCRIPTOR,
                classForName.callSite().calleeDescriptor());

        JndiReferenceFactoryClassConstraint constraint = connect(fixture,
                new TypedBridgeFact.FlowIdentity("factory-name"),
                new TypedBridgeFact.FlowIdentity("factory-name"),
                TypeId.of("fixture/Factory"), TypeId.of("fixture/Factory"),
                JndiReferenceFact.FieldValue.known("fixture.Factory"));

        assertTrue(constraint.proved());
        assertEquals(JndiReferenceFactoryClassConstraint.Status.PROVED, constraint.status());
        assertEquals(JndiReferenceFactoryClassConstraint.Reason.NONE, constraint.reason());
        assertTrue(constraint.nameBridge().proved());
        assertEquals(TypeId.of("fixture/Factory"), constraint.loadedFactoryType());
        assertEquals(TypeId.of("fixture/Factory"), constraint.factoryReceiver().type());
        assertEquals(TypedBridgeFact.Slot.Position.ARGUMENT,
                constraint.classNameEndpoint().slot().position());
        assertEquals(TypedBridgeFact.Slot.Position.ARGUMENT,
                constraint.referenceFactoryEndpoint().slot().position());
        assertEquals(TypedBridgeFact.Slot.Position.RECEIVER,
                constraint.factoryReceiver().slot().position());
    }

    @Test
    void sameClassNameWithDifferentValueIdentityRemainsUnknown() {
        Fixture fixture = fixture();
        JndiReferenceFactoryClassConstraint constraint = connect(fixture,
                new TypedBridgeFact.FlowIdentity("class-name-source"),
                new TypedBridgeFact.FlowIdentity("reference-name-source"),
                TypeId.of("fixture/Factory"), TypeId.of("fixture/Factory"),
                JndiReferenceFact.FieldValue.known("fixture.Factory"));

        assertEquals(JndiReferenceFactoryClassConstraint.Status.UNKNOWN, constraint.status());
        assertEquals(JndiReferenceFactoryClassConstraint.Reason.IDENTITY_MISMATCH,
                constraint.reason());
        assertFalse(constraint.proved());
        assertEquals(TypedBridgeFact.Reason.IDENTITY_MISMATCH,
                constraint.nameBridge().reason());
    }

    @Test
    void loadedClassAndFactoryReceiverMustHaveTheSameType() {
        Fixture fixture = fixture();
        JndiReferenceFactoryClassConstraint constraint = connect(fixture,
                new TypedBridgeFact.FlowIdentity("factory-name"),
                new TypedBridgeFact.FlowIdentity("factory-name"),
                TypeId.of("fixture/OtherFactory"), TypeId.of("fixture/Factory"),
                JndiReferenceFact.FieldValue.known("fixture.Factory"));

        assertEquals(JndiReferenceFactoryClassConstraint.Status.UNKNOWN, constraint.status());
        assertEquals(JndiReferenceFactoryClassConstraint.Reason.FACTORY_RECEIVER_TYPE_MISMATCH,
                constraint.reason());
    }

    @Test
    void missingClassForNameArgumentIsPartialAndOverloadsAreNotExact() {
        Fixture fixture = fixture();
        JndiReferenceFactoryClassConstraint constraint = connect(fixture,
                new TypedBridgeFact.FlowIdentity("factory-name"),
                new TypedBridgeFact.FlowIdentity("factory-name"),
                TypeId.of("fixture/Factory"), TypeId.of("fixture/Factory"),
                JndiReferenceFact.FieldValue.unknown());

        assertEquals(JndiReferenceFactoryClassConstraint.Status.PARTIAL, constraint.status());
        assertEquals(JndiReferenceFactoryClassConstraint.Reason.CLASS_FOR_NAME_ARGUMENT_UNKNOWN,
                constraint.reason());
        assertTrue(ClassForNameCallSite.fromCall(fixture.forName().id(), fixture.host(),
                fixture.forName().offset(), ClassForNameCallSite.OWNER,
                ClassForNameCallSite.NAME, "(Ljava/lang/String;Z)Ljava/lang/Class;", "STATIC")
                .isEmpty());
    }

    @Test
    void missingReferenceFactoryClassRemainsPartialWithoutGuessing() {
        Fixture fixture = fixture();
        JndiReferenceFact missingFactory = new JndiReferenceFact(fixture.reference().identity(),
                fixture.reference().type(), JndiReferenceFact.FieldValue.absent(),
                fixture.reference().factoryLocation(), fixture.reference().properties());

        JndiReferenceFactoryClassConstraint constraint = connect(missingFactory, fixture,
                new TypedBridgeFact.FlowIdentity("factory-name"),
                new TypedBridgeFact.FlowIdentity("factory-name"),
                TypeId.of("fixture/Factory"), TypeId.of("fixture/Factory"),
                JndiReferenceFact.FieldValue.known("fixture.Factory"));

        assertEquals(JndiReferenceFactoryClassConstraint.Status.PARTIAL, constraint.status());
        assertEquals(JndiReferenceFactoryClassConstraint.Reason.REFERENCE_FACTORY_CLASS_UNKNOWN,
                constraint.reason());
        assertFalse(constraint.proved());
    }

    private static JndiReferenceFactoryClassConstraint connect(
            Fixture fixture,
            TypedBridgeFact.FlowIdentity classNameIdentity,
            TypedBridgeFact.FlowIdentity referenceIdentity,
            TypeId receiverType,
            TypeId loadedType,
            JndiReferenceFact.FieldValue classForNameArgument) {
        return connect(fixture.reference(), fixture, classNameIdentity, referenceIdentity,
                receiverType, loadedType, classForNameArgument);
    }

    private static JndiReferenceFactoryClassConstraint connect(
            JndiReferenceFact reference,
            Fixture fixture,
            TypedBridgeFact.FlowIdentity classNameIdentity,
            TypedBridgeFact.FlowIdentity referenceIdentity,
            TypeId receiverType,
            TypeId loadedType,
            JndiReferenceFact.FieldValue classForNameArgument) {
        ArtifactProvenance artifact = fixture.artifact();
        TypedBridgeFact.Endpoint classNameEndpoint = new TypedBridgeFact.Endpoint(
                classNameIdentity, fixture.classForName().callSite(),
                ClassForNameCallSite.ARGUMENT_SLOT, TypeId.of("java/lang/String"), artifact);
        TypedBridgeFact.CallSite referenceCall = new TypedBridgeFact.CallSite(
                fixture.constructor().id(), fixture.host(), fixture.constructor().offset(),
                fixture.constructor().owner(), fixture.constructor().name(),
                fixture.constructor().descriptor(), TypedBridgeFact.InvokeKind.SPECIAL);
        TypedBridgeFact.Endpoint referenceFactoryEndpoint = new TypedBridgeFact.Endpoint(
                referenceIdentity, referenceCall, TypedBridgeFact.Slot.argument(1,
                "Ljava/lang/String;"), TypeId.of("java/lang/String"), artifact);
        TypedBridgeFact.CallSite receiverCall = new TypedBridgeFact.CallSite(
                fixture.factoryCall().id(), fixture.host(), fixture.factoryCall().offset(),
                fixture.factoryCall().owner(), fixture.factoryCall().name(),
                fixture.factoryCall().descriptor(), TypedBridgeFact.InvokeKind.INTERFACE);
        TypedBridgeFact.Endpoint factoryReceiver = new TypedBridgeFact.Endpoint(
                new TypedBridgeFact.FlowIdentity("factory-object"), receiverCall,
                TypedBridgeFact.Slot.receiver(JndiObjectFactoryCallSite.RECEIVER_DESCRIPTOR),
                receiverType, artifact);
        return JndiReferenceFactoryClassConstraint.connect(reference,
                fixture.classForName(), classForNameArgument, classNameEndpoint,
                referenceFactoryEndpoint, factoryReceiver, loadedType,
                TypedBridgeFact.IdentityRelation.SAME,
                TypedBridgeFact.ArtifactRelation.SAME_ARTIFACT);
    }

    private static Fixture fixture() {
        ClassInfo info = extract(fixtureBytes());
        LoadResult load = new LoadResult(Map.of(info.internalName(), info), List.of(), 1, 61);
        ArtifactProvenance artifact = new ArtifactProvenance("reference-factory.jar",
                ArtifactProvenance.Role.APPLICATION, "D".repeat(64), 1024L);
        ProgramUniverse universe = ProgramUniverse.of(load,
                Map.of(info.internalName(), artifact), List.of(artifact));
        Graph graph = new CpgBuilder().build(universe).graph();
        String hostKey = info.internalName() + "#build()Ljavax/naming/Reference;";
        Node forName = graph.callsOfMethod(hostKey).stream()
                .filter(node -> ClassForNameCallSite.OWNER.equals(node.owner())
                        && ClassForNameCallSite.NAME.equals(node.name()))
                .findFirst().orElseThrow();
        Node constructor = graph.callsOfMethod(hostKey).stream()
                .filter(node -> JndiReferenceFact.REFERENCE_OWNER.equals(node.owner())
                        && "<init>".equals(node.name())
                        && JndiReferenceFact.REFERENCE_CONSTRUCTOR_FACTORY_DESCRIPTOR
                        .equals(node.descriptor()))
                .findFirst().orElseThrow();
        Node factoryCall = graph.callsOfMethod(hostKey).stream()
                .filter(node -> JndiObjectFactoryCallSite.OBJECT_FACTORY_OWNER.equals(node.owner())
                        && JndiObjectFactoryCallSite.GET_OBJECT_INSTANCE_NAME.equals(node.name())
                        && JndiObjectFactoryCallSite.GET_OBJECT_INSTANCE_DESCRIPTOR
                        .equals(node.descriptor()))
                .findFirst().orElseThrow();
        JndiReferenceFact reference = (JndiReferenceFact) constructor.note(
                JndiReferenceFact.GRAPH_NOTE_KEY);
        ClassForNameCallSite classForName = (ClassForNameCallSite) forName.note(
                ClassForNameCallSite.GRAPH_NOTE_KEY);
        assertNotNull(reference);
        assertNotNull(classForName);
        return new Fixture(info, graph, MethodId.of(info.internalName(), "build",
                "()Ljavax/naming/Reference;"), forName, constructor, factoryCall,
                reference, classForName, artifact);
    }

    private static ClassInfo extract(byte[] bytes) {
        org.objectweb.asm.tree.ClassNode node = new org.objectweb.asm.tree.ClassNode();
        new ClassReader(bytes).accept(node, 0);
        return new FactsExtractor().extract(node);
    }

    private static byte[] fixtureBytes() {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "fixture/ReferenceFactoryHost", null,
                "java/lang/Object", null);
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "build", "()Ljavax/naming/Reference;", null, null);
        method.visitCode();
        method.visitLdcInsn("fixture.Factory");
        method.visitVarInsn(Opcodes.ASTORE, 0);
        method.visitVarInsn(Opcodes.ALOAD, 0);
        method.visitMethodInsn(Opcodes.INVOKESTATIC, ClassForNameCallSite.OWNER,
                ClassForNameCallSite.NAME, ClassForNameCallSite.DESCRIPTOR, false);
        method.visitVarInsn(Opcodes.ASTORE, 1);

        method.visitTypeInsn(Opcodes.NEW, JndiReferenceFact.REFERENCE_OWNER);
        method.visitInsn(Opcodes.DUP);
        method.visitLdcInsn("fixture.Type");
        method.visitVarInsn(Opcodes.ALOAD, 0);
        method.visitInsn(Opcodes.ACONST_NULL);
        method.visitMethodInsn(Opcodes.INVOKESPECIAL, JndiReferenceFact.REFERENCE_OWNER,
                "<init>", JndiReferenceFact.REFERENCE_CONSTRUCTOR_FACTORY_DESCRIPTOR, false);
        method.visitVarInsn(Opcodes.ASTORE, 2);

        method.visitTypeInsn(Opcodes.NEW, "fixture/Factory");
        method.visitInsn(Opcodes.DUP);
        method.visitMethodInsn(Opcodes.INVOKESPECIAL, "fixture/Factory", "<init>", "()V",
                false);
        method.visitInsn(Opcodes.ACONST_NULL);
        method.visitInsn(Opcodes.ACONST_NULL);
        method.visitInsn(Opcodes.ACONST_NULL);
        method.visitInsn(Opcodes.ACONST_NULL);
        method.visitMethodInsn(Opcodes.INVOKEINTERFACE, JndiObjectFactoryCallSite.OBJECT_FACTORY_OWNER,
                JndiObjectFactoryCallSite.GET_OBJECT_INSTANCE_NAME,
                JndiObjectFactoryCallSite.GET_OBJECT_INSTANCE_DESCRIPTOR, true);
        method.visitInsn(Opcodes.POP);
        method.visitVarInsn(Opcodes.ALOAD, 2);
        method.visitInsn(Opcodes.ARETURN);
        method.visitMaxs(6, 3);
        method.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private record Fixture(ClassInfo info, Graph graph, MethodId host, Node forName,
                           Node constructor, Node factoryCall, JndiReferenceFact reference,
                           ClassForNameCallSite classForName, ArtifactProvenance artifact) {
    }
}
