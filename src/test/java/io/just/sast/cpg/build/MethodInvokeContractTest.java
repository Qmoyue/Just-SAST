package io.just.sast.cpg.build;

import io.just.sast.cpg.graph.Graph;
import io.just.sast.cpg.graph.Node;
import io.just.sast.frontend.asm.FactsExtractor;
import io.just.sast.model.ClassInfo;
import io.just.sast.model.LoadResult;
import io.just.sast.model.MethodInvokeCallSite;
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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MethodInvokeContractTest {

    private static final String OWNER = "java/lang/reflect/Method";
    private static final String INVOKE_DESCRIPTOR =
            "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;";
    private static final String GET_METHOD_DESCRIPTOR =
            "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;";

    @Test
    void exactLookupAndEmptyArgumentsRetainApiAndPhysicalSlots() {
        Fixture fixture = fixture(knownLookupHost(false));
        Node call = fixture.call(OWNER, "invoke", INVOKE_DESCRIPTOR);

        MethodInvokeCallSite fact = fact(call);
        assertEquals(MethodInvokeCallSite.Status.PROVED, fact.status());
        assertEquals(MethodInvokeCallSite.Reason.NONE, fact.reason());
        assertEquals("invoke", fact.apiMethodName());
        assertEquals(INVOKE_DESCRIPTOR, fact.apiDescriptor());
        assertEquals(MethodInvokeCallSite.METHOD_SLOT, fact.methodSlot());
        assertEquals(MethodInvokeCallSite.TARGET_SLOT, fact.targetSlot());
        assertEquals(MethodInvokeCallSite.ARGUMENTS_SLOT, fact.argumentsSlot());
        assertEquals(MethodInvokeCallSite.RETURN_SLOT, fact.returnSlot());
        assertEquals("L" + OWNER + ";", fact.method().descriptor());
        assertEquals(MethodInvokeCallSite.ArgumentArray.State.KNOWN,
                fact.arguments().state());
        assertEquals(List.of(), fact.arguments().elements());
        assertEquals("Ljava/lang/Object;", fact.result().descriptor());
    }

    @Test
    void populatedObjectArrayRetainsOrdinalAndElementIdentity() {
        Fixture fixture = fixture(knownLookupHost(true));
        Node call = fixture.call(OWNER, "invoke", INVOKE_DESCRIPTOR);

        MethodInvokeCallSite fact = fact(call);
        assertEquals(MethodInvokeCallSite.Status.PROVED, fact.status());
        assertEquals(1, fact.arguments().elements().size());
        MethodInvokeCallSite.ArgumentArray.Element element = fact.arguments().elements().get(0);
        assertEquals(0, element.ordinal());
        assertEquals(MethodInvokeCallSite.ValueState.KNOWN, element.value().state());
        assertEquals("Ljava/lang/String;", element.value().descriptor());
        assertTrue(element.value().producerOffset() > 0);
    }

    @Test
    void parameterBackedMethodAndArgumentsRemainTypedButIncomplete() {
        Fixture fixture = fixture(parameterHost());
        Node call = fixture.call(OWNER, "invoke", INVOKE_DESCRIPTOR);

        MethodInvokeCallSite fact = fact(call);
        assertEquals(MethodInvokeCallSite.Status.PARTIAL, fact.status());
        assertEquals(MethodInvokeCallSite.Reason.VALUE_FLOW_INCOMPLETE, fact.reason());
        assertEquals(MethodInvokeCallSite.METHOD_DESCRIPTOR, fact.methodSlot().descriptor());
        assertEquals("Ljava/lang/Object;", fact.method().descriptor());
        assertEquals("Ljava/lang/Object;", fact.target().descriptor());
        assertEquals(MethodInvokeCallSite.ArgumentArray.State.KNOWN,
                fact.arguments().state());
        assertEquals(1, fact.arguments().elements().size());
        assertEquals("Ljava/lang/Object;",
                fact.arguments().elements().get(0).value().descriptor());
        assertEquals(0, fact.method().producerOffset());
    }

    @Test
    void incompleteControlFlowKeepsExactCallAsExplicitPartial() {
        Fixture fixture = fixture(incompleteHost());
        Node call = fixture.call(OWNER, "invoke", INVOKE_DESCRIPTOR);

        MethodInvokeCallSite fact = fact(call);
        assertEquals(MethodInvokeCallSite.Status.PARTIAL, fact.status());
        assertEquals(MethodInvokeCallSite.Reason.VALUE_FLOW_INCOMPLETE, fact.reason());
        assertEquals(-1, fact.arguments().producerOffset());
    }

    @Test
    void wrongOverloadAndOwnerDoNotEnterMethodInvokeContract() {
        Fixture overload = fixture(wrongOverloadHost());
        assertNull(overload.graph().nodesOfType(io.just.sast.cpg.graph.NodeType.CALL).stream()
                .filter(node -> OWNER.equals(node.owner()) && "invoke".equals(node.name()))
                .findFirst().orElseThrow().note(MethodInvokeCallSite.GRAPH_NOTE_KEY));

        Fixture owner = fixture(wrongOwnerHost());
        Node call = owner.graph().nodesOfType(io.just.sast.cpg.graph.NodeType.CALL).stream()
                .filter(node -> "java/lang/reflect/Constructor".equals(node.owner()))
                .findFirst().orElseThrow();
        assertNull(call.note(MethodInvokeCallSite.GRAPH_NOTE_KEY));
    }

    private static MethodInvokeCallSite fact(Node call) {
        MethodInvokeCallSite fact = (MethodInvokeCallSite) call.note(
                MethodInvokeCallSite.GRAPH_NOTE_KEY);
        assertNotNull(fact);
        return fact;
    }

    private static Fixture fixture(byte[] bytes) {
        ClassInfo host = extract(bytes);
        LoadResult load = new LoadResult(Map.of(host.internalName(), host), List.of(), 1, 61);
        Graph graph = new CpgBuilder().build(load).graph();
        return new Fixture(graph, host.internalName() + "#flow" + host.methods().get(0).descriptor());
    }

    private static ClassInfo extract(byte[] bytes) {
        org.objectweb.asm.tree.ClassNode node = new org.objectweb.asm.tree.ClassNode();
        new ClassReader(bytes).accept(node, 0);
        return new FactsExtractor().extract(node);
    }

    private static byte[] knownLookupHost(boolean populatedArguments) {
        ClassWriter writer = hostWriter("fixture/LookupHost");
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "flow", "()V", null, null);
        method.visitCode();
        emitMethodLookup(method);
        method.visitInsn(Opcodes.ACONST_NULL);
        if (populatedArguments) {
            method.visitInsn(Opcodes.ICONST_1);
            method.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Object");
            method.visitInsn(Opcodes.DUP);
            method.visitInsn(Opcodes.ICONST_0);
            method.visitLdcInsn("value");
            method.visitInsn(Opcodes.AASTORE);
        } else {
            method.visitInsn(Opcodes.ICONST_0);
            method.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Object");
        }
        method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, OWNER, "invoke", INVOKE_DESCRIPTOR, false);
        method.visitInsn(Opcodes.POP);
        method.visitInsn(Opcodes.RETURN);
        method.visitMaxs(8, 0);
        method.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] parameterHost() {
        ClassWriter writer = hostWriter("fixture/ParameterHost");
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "flow", "(Ljava/lang/reflect/Method;Ljava/lang/Object;Ljava/lang/Object;)V",
                null, null);
        method.visitCode();
        method.visitVarInsn(Opcodes.ALOAD, 0);
        method.visitVarInsn(Opcodes.ALOAD, 1);
        method.visitInsn(Opcodes.ICONST_1);
        method.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Object");
        method.visitInsn(Opcodes.DUP);
        method.visitInsn(Opcodes.ICONST_0);
        method.visitVarInsn(Opcodes.ALOAD, 2);
        method.visitInsn(Opcodes.AASTORE);
        method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, OWNER, "invoke", INVOKE_DESCRIPTOR, false);
        method.visitInsn(Opcodes.POP);
        method.visitInsn(Opcodes.RETURN);
        method.visitMaxs(5, 3);
        method.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] incompleteHost() {
        ClassWriter writer = hostWriter("fixture/IncompleteHost");
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "flow", "()V", null, null);
        method.visitCode();
        Label done = new Label();
        method.visitInsn(Opcodes.ICONST_0);
        method.visitJumpInsn(Opcodes.IFEQ, done);
        method.visitInsn(Opcodes.ACONST_NULL);
        method.visitInsn(Opcodes.ACONST_NULL);
        method.visitInsn(Opcodes.ACONST_NULL);
        method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, OWNER, "invoke", INVOKE_DESCRIPTOR, false);
        method.visitInsn(Opcodes.POP);
        method.visitLabel(done);
        method.visitInsn(Opcodes.RETURN);
        method.visitMaxs(3, 0);
        method.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] wrongOverloadHost() {
        ClassWriter writer = hostWriter("fixture/WrongOverloadHost");
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "flow", "()V", null, null);
        method.visitCode();
        method.visitInsn(Opcodes.ACONST_NULL);
        method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, OWNER, "invoke",
                "(Ljava/lang/Object;)Ljava/lang/Object;", false);
        method.visitInsn(Opcodes.POP);
        method.visitInsn(Opcodes.RETURN);
        method.visitMaxs(1, 0);
        method.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] wrongOwnerHost() {
        ClassWriter writer = hostWriter("fixture/WrongOwnerHost");
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "flow", "()V", null, null);
        method.visitCode();
        method.visitInsn(Opcodes.ACONST_NULL);
        method.visitInsn(Opcodes.ACONST_NULL);
        method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/reflect/Constructor",
                "invoke", "(Ljava/lang/Object;)Ljava/lang/Object;", false);
        method.visitInsn(Opcodes.POP);
        method.visitInsn(Opcodes.RETURN);
        method.visitMaxs(2, 0);
        method.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static void emitMethodLookup(MethodVisitor method) {
        method.visitLdcInsn(Type.getObjectType("fixture/Target"));
        method.visitLdcInsn("run");
        method.visitInsn(Opcodes.ICONST_0);
        method.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Class");
        method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Class", "getMethod",
                GET_METHOD_DESCRIPTOR, false);
    }

    private static ClassWriter hostWriter(String name) {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, name, null, "java/lang/Object", null);
        return writer;
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
