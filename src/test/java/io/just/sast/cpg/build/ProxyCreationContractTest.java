package io.just.sast.cpg.build;

import io.just.sast.cpg.graph.Graph;
import io.just.sast.cpg.graph.Node;
import io.just.sast.frontend.asm.FactsExtractor;
import io.just.sast.model.ClassInfo;
import io.just.sast.model.LoadResult;
import io.just.sast.model.ProxyCreationCallSite;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

class ProxyCreationContractTest {

    @Test
    void exactFactoryRetainsLoaderInterfaceSetHandlerAndProxyIdentity() {
        Fixture fixture = fixture(knownProxyBytes());
        ProxyCreationCallSite fact = fact(fixture.call(
                ProxyCreationCallSite.OWNER, ProxyCreationCallSite.NAME,
                ProxyCreationCallSite.DESCRIPTOR));

        assertEquals(ProxyCreationCallSite.Status.PROVED, fact.status());
        assertEquals(ProxyCreationCallSite.Reason.NONE, fact.reason());
        assertEquals(ProxyCreationCallSite.ValueState.UNKNOWN, fact.classLoader().state());
        assertEquals(ProxyCreationCallSite.ValueState.KNOWN, fact.interfaceSet().state());
        assertEquals(List.of("fixture/First", "fixture/Second"),
                fact.interfaceSet().interfaceTypes());
        assertEquals(ProxyCreationCallSite.ValueState.KNOWN, fact.handler().state());
        assertEquals(ProxyCreationCallSite.ValueState.UNKNOWN, fact.proxy().state());
        assertNotEquals(fact.interfaceSet().identity(), fact.handler().identity());
        assertNotEquals(fact.interfaceSet().identity(), fact.proxy().identity());
        assertEquals(ProxyCreationCallSite.DESCRIPTOR, fact.callSite().calleeDescriptor());
        assertEquals(0, fact.classLoaderSlot().ordinal());
        assertEquals(1, fact.interfaceSetSlot().ordinal());
        assertEquals(2, fact.handlerSlot().ordinal());
        assertEquals(-1, fact.resultSlot().ordinal());
    }

    @Test
    void equalInterfaceNamesFromDifferentArraysDoNotMergePhysicalIdentity() {
        Fixture fixture = fixture(twoProxyBytes());
        List<Node> calls = fixture.graph().callsOfMethod(fixture.hostKey()).stream()
                .filter(node -> ProxyCreationCallSite.OWNER.equals(node.owner())
                        && ProxyCreationCallSite.NAME.equals(node.name()))
                .toList();

        assertEquals(2, calls.size());
        ProxyCreationCallSite first = fact(calls.get(0));
        ProxyCreationCallSite second = fact(calls.get(1));
        assertEquals(List.of("fixture/First"), first.interfaceSet().interfaceTypes());
        assertEquals(List.of("fixture/First"), second.interfaceSet().interfaceTypes());
        assertNotEquals(first.interfaceSet().identity(), second.interfaceSet().identity());
        assertNotEquals(first.proxyIdentity().identity(), second.proxyIdentity().identity());
    }

    @Test
    void unknownInterfaceArrayIsPartialWithoutDroppingTheFactoryFact() {
        Fixture fixture = fixture(unknownInterfaceBytes());
        ProxyCreationCallSite fact = fact(fixture.call(
                ProxyCreationCallSite.OWNER, ProxyCreationCallSite.NAME,
                ProxyCreationCallSite.DESCRIPTOR));

        assertEquals(ProxyCreationCallSite.Status.PARTIAL, fact.status());
        assertEquals(ProxyCreationCallSite.Reason.INTERFACE_SET_UNKNOWN, fact.reason());
        assertEquals(ProxyCreationCallSite.ValueState.UNKNOWN, fact.interfaceSet().state());
        assertEquals(1, fact.interfaceSet().producerOffset());
    }

    @Test
    void unknownArrayIndexCannotBecomeKnownAfterOtherWrites() {
        Fixture fixture = fixture(unknownArrayIndexBytes());
        ProxyCreationCallSite fact = fact(fixture.call(
                ProxyCreationCallSite.OWNER, ProxyCreationCallSite.NAME,
                ProxyCreationCallSite.DESCRIPTOR));

        assertEquals(ProxyCreationCallSite.Status.PARTIAL, fact.status());
        assertEquals(ProxyCreationCallSite.Reason.INTERFACE_SET_UNKNOWN, fact.reason());
        assertEquals(ProxyCreationCallSite.ValueState.UNKNOWN, fact.interfaceSet().state());
    }

    @Test
    void controlFlowBoundaryIsExplicitlyPartial() {
        Fixture fixture = fixture(branchProxyBytes());
        ProxyCreationCallSite fact = fact(fixture.call(
                ProxyCreationCallSite.OWNER, ProxyCreationCallSite.NAME,
                ProxyCreationCallSite.DESCRIPTOR));

        assertEquals(ProxyCreationCallSite.Status.PARTIAL, fact.status());
        assertEquals(ProxyCreationCallSite.Reason.VALUE_FLOW_INCOMPLETE, fact.reason());
        assertEquals(-1, fact.proxy().producerOffset());
    }

    @Test
    void overloadsAndWrongOwnersDoNotCreateProxyFacts() {
        Fixture fixture = fixture(wrongProxyBytes());
        assertNull(fixture.call("fixture/OtherProxy", ProxyCreationCallSite.NAME,
                ProxyCreationCallSite.DESCRIPTOR).note(ProxyCreationCallSite.GRAPH_NOTE_KEY));
        assertNull(fixture.call(ProxyCreationCallSite.OWNER, ProxyCreationCallSite.NAME,
                "(Ljava/lang/ClassLoader;[Ljava/lang/Class;)Ljava/lang/reflect/Proxy;")
                .note(ProxyCreationCallSite.GRAPH_NOTE_KEY));
    }

    private static ProxyCreationCallSite fact(Node node) {
        ProxyCreationCallSite fact = (ProxyCreationCallSite) node.note(
                ProxyCreationCallSite.GRAPH_NOTE_KEY);
        assertNotNull(fact);
        return fact;
    }

    private static Fixture fixture(byte[] bytes) {
        ClassInfo info = extract(bytes);
        LoadResult load = new LoadResult(Map.of(info.internalName(), info), List.of(), 1, 61);
        Graph graph = new CpgBuilder().build(load).graph();
        var method = info.methods().stream().filter(candidate -> "flow".equals(candidate.name()))
                .findFirst().orElseThrow();
        return new Fixture(graph, info.internalName() + "#" + method.name() + method.descriptor());
    }

    private static ClassInfo extract(byte[] bytes) {
        org.objectweb.asm.tree.ClassNode node = new org.objectweb.asm.tree.ClassNode();
        new ClassReader(bytes).accept(node, 0);
        return new FactsExtractor().extract(node);
    }

    private static byte[] knownProxyBytes() {
        ClassWriter writer = hostWriter("fixture/ProxyHost");
        MethodVisitor method = flowMethod(writer);
        emitKnownProxy(method, "fixture/First", "fixture/Second");
        method.visitInsn(Opcodes.POP);
        method.visitInsn(Opcodes.RETURN);
        finish(method, 8, 0);
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] twoProxyBytes() {
        ClassWriter writer = hostWriter("fixture/TwoProxyHost");
        MethodVisitor method = flowMethod(writer);
        emitKnownProxy(method, "fixture/First");
        method.visitInsn(Opcodes.POP);
        emitKnownProxy(method, "fixture/First");
        method.visitInsn(Opcodes.POP);
        method.visitInsn(Opcodes.RETURN);
        finish(method, 8, 0);
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] unknownInterfaceBytes() {
        ClassWriter writer = hostWriter("fixture/UnknownProxyHost");
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "flow", "([Ljava/lang/Class;)V", null, null);
        method.visitCode();
        method.visitInsn(Opcodes.ACONST_NULL);
        method.visitVarInsn(Opcodes.ALOAD, 0);
        method.visitInsn(Opcodes.ACONST_NULL);
        method.visitMethodInsn(Opcodes.INVOKESTATIC, ProxyCreationCallSite.OWNER,
                ProxyCreationCallSite.NAME, ProxyCreationCallSite.DESCRIPTOR, false);
        method.visitInsn(Opcodes.POP);
        method.visitInsn(Opcodes.RETURN);
        finish(method, 3, 1);
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] branchProxyBytes() {
        ClassWriter writer = hostWriter("fixture/BranchProxyHost");
        MethodVisitor method = flowMethod(writer);
        Label alternate = new Label();
        method.visitInsn(Opcodes.ACONST_NULL);
        method.visitJumpInsn(Opcodes.IFNULL, alternate);
        emitKnownProxy(method, "fixture/First");
        method.visitInsn(Opcodes.POP);
        method.visitLabel(alternate);
        method.visitInsn(Opcodes.RETURN);
        finish(method, 8, 0);
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] unknownArrayIndexBytes() {
        ClassWriter writer = hostWriter("fixture/UnknownIndexProxyHost");
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "flow", "(I)V", null, null);
        method.visitCode();
        method.visitLdcInsn(Type.getObjectType("fixture/ProxyHost"));
        method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Class", "getClassLoader",
                "()Ljava/lang/ClassLoader;", false);
        pushInt(method, 2);
        method.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Class");
        method.visitInsn(Opcodes.DUP);
        method.visitVarInsn(Opcodes.ILOAD, 0);
        method.visitLdcInsn(Type.getObjectType("fixture/First"));
        method.visitInsn(Opcodes.AASTORE);
        method.visitInsn(Opcodes.DUP);
        pushInt(method, 0);
        method.visitLdcInsn(Type.getObjectType("fixture/First"));
        method.visitInsn(Opcodes.AASTORE);
        method.visitInsn(Opcodes.DUP);
        pushInt(method, 1);
        method.visitLdcInsn(Type.getObjectType("fixture/Second"));
        method.visitInsn(Opcodes.AASTORE);
        method.visitTypeInsn(Opcodes.NEW, "fixture/Handler");
        method.visitInsn(Opcodes.DUP);
        method.visitMethodInsn(Opcodes.INVOKESPECIAL, "fixture/Handler", "<init>", "()V", false);
        method.visitMethodInsn(Opcodes.INVOKESTATIC, ProxyCreationCallSite.OWNER,
                ProxyCreationCallSite.NAME, ProxyCreationCallSite.DESCRIPTOR, false);
        method.visitInsn(Opcodes.POP);
        method.visitInsn(Opcodes.RETURN);
        finish(method, 8, 1);
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] wrongProxyBytes() {
        ClassWriter writer = hostWriter("fixture/WrongProxyHost");
        MethodVisitor method = flowMethod(writer);
        method.visitInsn(Opcodes.ACONST_NULL);
        method.visitInsn(Opcodes.ACONST_NULL);
        method.visitInsn(Opcodes.ACONST_NULL);
        method.visitMethodInsn(Opcodes.INVOKESTATIC, "fixture/OtherProxy",
                ProxyCreationCallSite.NAME, ProxyCreationCallSite.DESCRIPTOR, false);
        method.visitInsn(Opcodes.POP);
        method.visitInsn(Opcodes.ACONST_NULL);
        method.visitInsn(Opcodes.ACONST_NULL);
        method.visitMethodInsn(Opcodes.INVOKESTATIC, ProxyCreationCallSite.OWNER,
                ProxyCreationCallSite.NAME,
                "(Ljava/lang/ClassLoader;[Ljava/lang/Class;)Ljava/lang/reflect/Proxy;", false);
        method.visitInsn(Opcodes.POP);
        method.visitInsn(Opcodes.RETURN);
        finish(method, 3, 0);
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static void emitKnownProxy(MethodVisitor method, String... interfaces) {
        method.visitLdcInsn(Type.getObjectType("fixture/ProxyHost"));
        method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Class", "getClassLoader",
                "()Ljava/lang/ClassLoader;", false);
        pushInt(method, interfaces.length);
        method.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Class");
        for (int index = 0; index < interfaces.length; index++) {
            method.visitInsn(Opcodes.DUP);
            pushInt(method, index);
            method.visitLdcInsn(Type.getObjectType(interfaces[index]));
            method.visitInsn(Opcodes.AASTORE);
        }
        method.visitTypeInsn(Opcodes.NEW, "fixture/Handler");
        method.visitInsn(Opcodes.DUP);
        method.visitMethodInsn(Opcodes.INVOKESPECIAL, "fixture/Handler", "<init>", "()V", false);
        method.visitMethodInsn(Opcodes.INVOKESTATIC, ProxyCreationCallSite.OWNER,
                ProxyCreationCallSite.NAME, ProxyCreationCallSite.DESCRIPTOR, false);
    }

    private static void pushInt(MethodVisitor method, int value) {
        switch (value) {
            case 0 -> method.visitInsn(Opcodes.ICONST_0);
            case 1 -> method.visitInsn(Opcodes.ICONST_1);
            case 2 -> method.visitInsn(Opcodes.ICONST_2);
            case 3 -> method.visitInsn(Opcodes.ICONST_3);
            case 4 -> method.visitInsn(Opcodes.ICONST_4);
            case 5 -> method.visitInsn(Opcodes.ICONST_5);
            default -> method.visitIntInsn(Opcodes.BIPUSH, value);
        }
    }

    private static ClassWriter hostWriter(String name) {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, name, null, "java/lang/Object", null);
        return writer;
    }

    private static MethodVisitor flowMethod(ClassWriter writer) {
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "flow", "()V", null, null);
        method.visitCode();
        return method;
    }

    private static void finish(MethodVisitor method, int maxStack, int maxLocals) {
        method.visitMaxs(maxStack, maxLocals);
        method.visitEnd();
    }

    private record Fixture(Graph graph, String hostKey) {
        private Node call(String owner, String name, String descriptor) {
            return graph.callsOfMethod(hostKey).stream()
                    .filter(node -> owner.equals(node.owner()) && name.equals(node.name())
                            && descriptor.equals(node.descriptor()))
                    .findFirst().orElseThrow();
        }
    }
}
