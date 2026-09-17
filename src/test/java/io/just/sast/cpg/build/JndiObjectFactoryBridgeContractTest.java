package io.just.sast.cpg.build;

import io.just.sast.analysis.callgraph.CallGraphBuilder;
import io.just.sast.analysis.hierarchy.ClassHierarchy;
import io.just.sast.cpg.graph.EdgeType;
import io.just.sast.cpg.graph.Graph;
import io.just.sast.cpg.graph.NodeType;
import io.just.sast.frontend.asm.FactsExtractor;
import io.just.sast.model.ClassInfo;
import io.just.sast.model.JndiObjectFactoryCallSite;
import io.just.sast.model.JndiObjectFactoryDispatch;
import io.just.sast.model.LoadResult;
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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JndiObjectFactoryBridgeContractTest {

    @Test
    void exactInterfaceCallConnectsPhysicalCallSiteToConcreteImplementation() {
        ClassInfo host = extract(hostBytes(JndiObjectFactoryCallSite.GET_OBJECT_INSTANCE_DESCRIPTOR));
        ClassInfo factory = extract(factoryBytes());
        LoadResult load = new LoadResult(Map.of(host.internalName(), host,
                factory.internalName(), factory), List.of(), 1, 61);

        Graph graph = new CpgBuilder().build(load).graph();
        var call = graph.callsOfMethod(host.internalName() + "#call"
                        + host.method("call", hostMethodDescriptor()).descriptor())
                .stream().filter(node -> node.type() == NodeType.CALL).findFirst().orElseThrow();
        int edges = new CallGraphBuilder(new ClassHierarchy(load.classes(), null)).build(graph);

        assertEquals(1, edges);
        JndiObjectFactoryCallSite site =
                (JndiObjectFactoryCallSite) call.note(JndiObjectFactoryCallSite.GRAPH_NOTE_KEY);
        assertNotNull(site);
        assertEquals(JndiObjectFactoryCallSite.OBJECT_FACTORY_OWNER + "#"
                        + JndiObjectFactoryCallSite.GET_OBJECT_INSTANCE_NAME
                        + JndiObjectFactoryCallSite.GET_OBJECT_INSTANCE_DESCRIPTOR,
                site.contractMethodKey());
        assertEquals("INTERFACE", site.invokeKind());
        assertEquals(-1, site.receiver().ordinal());
        assertEquals(JndiObjectFactoryCallSite.RECEIVER_DESCRIPTOR, site.receiver().descriptor());
        assertEquals(List.of(0, 1, 2, 3), site.arguments().stream()
                .map(JndiObjectFactoryCallSite.Slot::ordinal).toList());
        assertEquals(JndiObjectFactoryCallSite.RETURN_DESCRIPTOR, site.returnDescriptor());

        JndiObjectFactoryDispatch dispatch =
                (JndiObjectFactoryDispatch) call.note(JndiObjectFactoryCallSite.DISPATCH_NOTE_KEY);
        assertEquals(JndiObjectFactoryDispatch.Status.RESOLVED, dispatch.status());
        assertEquals(List.of("fixture/Factory#getObjectInstance"
                        + JndiObjectFactoryCallSite.GET_OBJECT_INSTANCE_DESCRIPTOR),
                dispatch.implementations().stream()
                        .map(JndiObjectFactoryDispatch.Implementation::methodKey).toList());
        assertEquals(EdgeType.DISPATCHES, call.out().get(0).type());
        assertEquals("fixture/Factory", call.out().get(0).to().owner());
        assertEquals(site.identity(), dispatch.callSite().identity());
    }

    @Test
    void wrongDescriptorAndNonContractOwnerDoNotCreateTypedFactoryFacts() {
        ClassInfo wrongDescriptor = extract(hostBytes("(Ljava/lang/Object;)Ljava/lang/Object;"));
        LoadResult wrongLoad = new LoadResult(Map.of(wrongDescriptor.internalName(), wrongDescriptor),
                List.of(), 1, 61);
        Graph wrongGraph = new CpgBuilder().build(wrongLoad).graph();
        var wrongCall = wrongGraph.callsOfMethod(wrongDescriptor.internalName() + "#call"
                        + wrongDescriptor.method("call", hostMethodDescriptor()).descriptor())
                .stream().findFirst().orElseThrow();
        new CallGraphBuilder(new ClassHierarchy(wrongLoad.classes(), null)).build(wrongGraph);
        assertNull(wrongCall.note(JndiObjectFactoryCallSite.GRAPH_NOTE_KEY));
        assertNull(wrongCall.note(JndiObjectFactoryCallSite.DISPATCH_NOTE_KEY));

        ClassInfo unrelated = extract(unrelatedOwnerBytes());
        LoadResult unrelatedLoad = new LoadResult(Map.of(unrelated.internalName(), unrelated),
                List.of(), 1, 61);
        Graph unrelatedGraph = new CpgBuilder().build(unrelatedLoad).graph();
        var unrelatedCall = unrelatedGraph.callsOfMethod(unrelated.internalName() + "#call"
                        + unrelated.method("call", hostMethodDescriptor()).descriptor())
                .stream().findFirst().orElseThrow();
        new CallGraphBuilder(new ClassHierarchy(unrelatedLoad.classes(), null)).build(unrelatedGraph);
        assertFalse(unrelatedCall.notes().containsKey(JndiObjectFactoryCallSite.GRAPH_NOTE_KEY));
    }

    @Test
    void interfaceOnlyFactoryRemainsCapabilityWithoutImplementationExpansion() {
        ClassInfo host = extract(hostBytes(JndiObjectFactoryCallSite.GET_OBJECT_INSTANCE_DESCRIPTOR));
        LoadResult load = new LoadResult(Map.of(host.internalName(), host), List.of(), 1, 61);
        Graph graph = new CpgBuilder().build(load).graph();
        var call = graph.callsOfMethod(host.internalName() + "#call"
                        + host.method("call", hostMethodDescriptor()).descriptor())
                .stream().findFirst().orElseThrow();

        assertEquals(1, new CallGraphBuilder(new ClassHierarchy(load.classes(), null)).build(graph));
        JndiObjectFactoryDispatch dispatch =
                (JndiObjectFactoryDispatch) call.note(JndiObjectFactoryCallSite.DISPATCH_NOTE_KEY);
        assertEquals(JndiObjectFactoryDispatch.Status.INTERFACE_ONLY, dispatch.status());
        assertTrue(dispatch.implementations().isEmpty());
        assertFalse(dispatch.resolved());
        assertTrue(call.out().stream().noneMatch(edge -> edge.type() == EdgeType.DISPATCHES));
    }

    @Test
    void abstractFactoryRemainsCapabilityWithoutTreatingDeclarationAsImplementation() {
        ClassInfo host = extract(hostBytes(JndiObjectFactoryCallSite.GET_OBJECT_INSTANCE_DESCRIPTOR));
        ClassInfo abstractFactory = extract(abstractFactoryBytes());
        LoadResult load = new LoadResult(Map.of(host.internalName(), host,
                abstractFactory.internalName(), abstractFactory), List.of(), 1, 61);
        Graph graph = new CpgBuilder().build(load).graph();
        var call = graph.callsOfMethod(host.internalName() + "#call"
                        + host.method("call", hostMethodDescriptor()).descriptor())
                .stream().findFirst().orElseThrow();

        assertEquals(1, new CallGraphBuilder(new ClassHierarchy(load.classes(), null)).build(graph));
        JndiObjectFactoryDispatch dispatch =
                (JndiObjectFactoryDispatch) call.note(JndiObjectFactoryCallSite.DISPATCH_NOTE_KEY);
        assertEquals(JndiObjectFactoryDispatch.Status.ABSTRACT_ONLY, dispatch.status());
        assertTrue(dispatch.implementations().isEmpty());
        assertFalse(dispatch.resolved());
        assertTrue(call.out().stream().allMatch(edge -> edge.to().owner().equals("fixture/AbstractFactory")));
    }

    @Test
    void factoryBytecodeIsNeverInitializedOrInvokedDuringStaticBridgeModeling() {
        ClassInfo host = extract(hostBytes(JndiObjectFactoryCallSite.GET_OBJECT_INSTANCE_DESCRIPTOR));
        ClassInfo factory = extract(throwingFactoryBytes());
        LoadResult load = new LoadResult(Map.of(host.internalName(), host,
                factory.internalName(), factory), List.of(), 1, 61);
        Graph graph = new CpgBuilder().build(load).graph();
        var call = graph.callsOfMethod(host.internalName() + "#call"
                        + host.method("call", hostMethodDescriptor()).descriptor())
                .stream().findFirst().orElseThrow();

        new CallGraphBuilder(new ClassHierarchy(load.classes(), null)).build(graph);
        JndiObjectFactoryDispatch dispatch =
                (JndiObjectFactoryDispatch) call.note(JndiObjectFactoryCallSite.DISPATCH_NOTE_KEY);
        assertEquals(JndiObjectFactoryDispatch.Status.RESOLVED, dispatch.status());
        assertEquals(List.of("fixture/ThrowingFactory#getObjectInstance"
                        + JndiObjectFactoryCallSite.GET_OBJECT_INSTANCE_DESCRIPTOR),
                dispatch.implementations().stream()
                        .map(JndiObjectFactoryDispatch.Implementation::methodKey).toList());
    }

    private static String hostMethodDescriptor() {
        return "(Ljavax/naming/spi/ObjectFactory;Ljava/lang/Object;Ljavax/naming/Name;"
                + "Ljavax/naming/Context;Ljava/util/Hashtable;)Ljava/lang/Object;";
    }

    private static ClassInfo extract(byte[] bytes) {
        org.objectweb.asm.tree.ClassNode node = new org.objectweb.asm.tree.ClassNode();
        new ClassReader(bytes).accept(node, 0);
        return new FactsExtractor().extract(node);
    }

    private static byte[] hostBytes(String descriptor) {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "fixture/FactoryHost", null,
                "java/lang/Object", null);
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "call",
                hostMethodDescriptor(), null, null);
        method.visitCode();
        method.visitVarInsn(Opcodes.ALOAD, 0);
        method.visitVarInsn(Opcodes.ALOAD, 1);
        method.visitVarInsn(Opcodes.ALOAD, 2);
        method.visitVarInsn(Opcodes.ALOAD, 3);
        method.visitVarInsn(Opcodes.ALOAD, 4);
        method.visitMethodInsn(Opcodes.INVOKEINTERFACE, JndiObjectFactoryCallSite.OBJECT_FACTORY_OWNER,
                JndiObjectFactoryCallSite.GET_OBJECT_INSTANCE_NAME, descriptor, true);
        method.visitInsn(Opcodes.ARETURN);
        method.visitMaxs(5, 5);
        method.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] factoryBytes() {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "fixture/Factory", null,
                "java/lang/Object", new String[] {JndiObjectFactoryCallSite.OBJECT_FACTORY_OWNER});
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC,
                JndiObjectFactoryCallSite.GET_OBJECT_INSTANCE_NAME,
                JndiObjectFactoryCallSite.GET_OBJECT_INSTANCE_DESCRIPTOR, null, null);
        method.visitCode();
        method.visitVarInsn(Opcodes.ALOAD, 1);
        method.visitInsn(Opcodes.ARETURN);
        method.visitMaxs(1, 5);
        method.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] abstractFactoryBytes() {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC | Opcodes.ACC_ABSTRACT,
                "fixture/AbstractFactory", null, "java/lang/Object",
                new String[] {JndiObjectFactoryCallSite.OBJECT_FACTORY_OWNER});
        writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_ABSTRACT,
                JndiObjectFactoryCallSite.GET_OBJECT_INSTANCE_NAME,
                JndiObjectFactoryCallSite.GET_OBJECT_INSTANCE_DESCRIPTOR, null, null).visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] throwingFactoryBytes() {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "fixture/ThrowingFactory", null,
                "java/lang/Object", new String[] {JndiObjectFactoryCallSite.OBJECT_FACTORY_OWNER});
        MethodVisitor initializer = writer.visitMethod(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        initializer.visitCode();
        emitAssertionError(initializer);
        initializer.visitMaxs(3, 0);
        initializer.visitEnd();
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC,
                JndiObjectFactoryCallSite.GET_OBJECT_INSTANCE_NAME,
                JndiObjectFactoryCallSite.GET_OBJECT_INSTANCE_DESCRIPTOR, null, null);
        method.visitCode();
        emitAssertionError(method);
        method.visitMaxs(3, 5);
        method.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static void emitAssertionError(MethodVisitor method) {
        method.visitTypeInsn(Opcodes.NEW, "java/lang/AssertionError");
        method.visitInsn(Opcodes.DUP);
        method.visitLdcInsn("ObjectFactory target code must not execute");
        method.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/AssertionError", "<init>",
                "(Ljava/lang/Object;)V", false);
        method.visitInsn(Opcodes.ATHROW);
    }

    private static byte[] unrelatedOwnerBytes() {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "fixture/UnrelatedFactory", null,
                "java/lang/Object", null);
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "call",
                hostMethodDescriptor(), null, null);
        method.visitCode();
        method.visitVarInsn(Opcodes.ALOAD, 0);
        method.visitInsn(Opcodes.ACONST_NULL);
        method.visitInsn(Opcodes.ACONST_NULL);
        method.visitInsn(Opcodes.ACONST_NULL);
        method.visitInsn(Opcodes.ACONST_NULL);
        method.visitMethodInsn(Opcodes.INVOKEINTERFACE, "fixture/OtherFactory",
                JndiObjectFactoryCallSite.GET_OBJECT_INSTANCE_NAME,
                JndiObjectFactoryCallSite.GET_OBJECT_INSTANCE_DESCRIPTOR, true);
        method.visitInsn(Opcodes.ARETURN);
        method.visitMaxs(5, 5);
        method.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }
}
