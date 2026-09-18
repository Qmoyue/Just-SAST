package io.just.sast.cpg.build;

import io.just.sast.cpg.graph.Graph;
import io.just.sast.cpg.graph.Node;
import io.just.sast.frontend.asm.FactsExtractor;
import io.just.sast.model.ClassInfo;
import io.just.sast.model.JdbcConnectionCallSite;
import io.just.sast.model.LoadResult;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JdbcConnectionBridgeContractTest {

    @Test
    void driverManagerKeepsExactUrlPropertiesSlotsAndMutationIdentities() {
        Fixture fixture = fixture(driverManagerBytes());
        Node call = fixture.call(JdbcConnectionCallSite.DRIVER_MANAGER_OWNER,
                JdbcConnectionCallSite.GET_CONNECTION_NAME,
                JdbcConnectionCallSite.CONNECTION_DESCRIPTOR);

        JdbcConnectionCallSite site = (JdbcConnectionCallSite) call.note(
                JdbcConnectionCallSite.GRAPH_NOTE_KEY);
        assertNotNull(site);
        assertEquals(JdbcConnectionCallSite.Kind.DRIVER_MANAGER_GET_CONNECTION, site.kind());
        assertEquals("STATIC", call.invokeKind());
        assertEquals(JdbcConnectionCallSite.URL_DESCRIPTOR, site.urlSlot().descriptor());
        assertEquals(JdbcConnectionCallSite.PROPERTIES_DESCRIPTOR,
                site.propertiesSlot().descriptor());
        assertEquals(JdbcConnectionCallSite.CONNECTION_DESCRIPTOR_TYPE,
                site.returnSlot().descriptor());
        assertEquals(JdbcConnectionCallSite.ValueState.KNOWN, site.url().state());
        assertEquals("jdbc:fixture:one", site.url().displayValue());
        assertEquals(JdbcConnectionCallSite.ValueState.KNOWN, site.properties().state());
        assertEquals(2, site.propertyEntries().size());

        JdbcConnectionCallSite.PropertyEntry first = site.propertyEntries().get(0);
        JdbcConnectionCallSite.PropertyEntry second = site.propertyEntries().get(1);
        assertEquals(JdbcConnectionCallSite.PropertyEntry.SET_PROPERTY_NAME,
                first.callSite().calleeName());
        assertEquals(JdbcConnectionCallSite.PropertyEntry.PUT_NAME,
                second.callSite().calleeName());
        assertEquals("user", first.key().displayValue());
        assertEquals("alice", first.value().displayValue());
        assertEquals("user", second.key().displayValue());
        assertEquals("alice", second.value().displayValue());
        assertNotEquals(first.key().token(), second.key().token());
        assertNotEquals(first.value().token(), second.value().token());
        assertEquals(site.properties().token(), first.receiver().token());
        assertEquals(site.properties().token(), second.receiver().token());
        assertEquals(0, first.keySlot().ordinal());
        assertEquals(1, first.valueSlot().ordinal());
        assertEquals("Ljava/lang/String;", first.keySlot().descriptor());
        assertEquals("Ljava/lang/Object;", second.keySlot().descriptor());
    }

    @Test
    void driverInterfaceConnectUsesTheSameExactConsumerContract() {
        Fixture fixture = fixture(driverConnectBytes());
        Node call = fixture.call(JdbcConnectionCallSite.DRIVER_OWNER,
                JdbcConnectionCallSite.CONNECT_NAME,
                JdbcConnectionCallSite.CONNECTION_DESCRIPTOR);

        JdbcConnectionCallSite site = (JdbcConnectionCallSite) call.note(
                JdbcConnectionCallSite.GRAPH_NOTE_KEY);
        assertNotNull(site);
        assertEquals(JdbcConnectionCallSite.Kind.DRIVER_CONNECT, site.kind());
        assertEquals("INTERFACE", call.invokeKind());
        assertEquals("jdbc:fixture:driver", site.url().displayValue());
        assertEquals(2, site.propertyEntries().size());
        assertEquals("user", site.propertyEntries().get(0).key().displayValue());
    }

    @Test
    void unknownUrlRemainsExplicitAndDoesNotGuessFromCallName() {
        Fixture fixture = fixture(unknownUrlBytes());
        Node call = fixture.call(JdbcConnectionCallSite.DRIVER_MANAGER_OWNER,
                JdbcConnectionCallSite.GET_CONNECTION_NAME,
                JdbcConnectionCallSite.CONNECTION_DESCRIPTOR);

        JdbcConnectionCallSite site = (JdbcConnectionCallSite) call.note(
                JdbcConnectionCallSite.GRAPH_NOTE_KEY);
        assertNotNull(site);
        assertEquals(JdbcConnectionCallSite.ValueState.UNKNOWN, site.url().state());
        assertNull(site.url().displayValue());
        assertEquals(JdbcConnectionCallSite.ValueState.KNOWN, site.properties().state());
        assertEquals("user", site.propertyEntries().get(0).key().displayValue());
        assertFalse(site.url().token().contains("fixture/Config"));
    }

    @Test
    void wrongOverloadAndWrongOwnerDoNotCreateTypedConnectionFacts() {
        Fixture overload = fixture(wrongOverloadBytes());
        Node overloadCall = overload.call(JdbcConnectionCallSite.DRIVER_MANAGER_OWNER,
                JdbcConnectionCallSite.GET_CONNECTION_NAME,
                "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/sql/Connection;");
        assertNull(overloadCall.note(JdbcConnectionCallSite.GRAPH_NOTE_KEY));

        Fixture owner = fixture(wrongOwnerBytes());
        Node ownerCall = owner.call("fixture/DriverManager",
                JdbcConnectionCallSite.GET_CONNECTION_NAME,
                JdbcConnectionCallSite.CONNECTION_DESCRIPTOR);
        assertFalse(ownerCall.notes().containsKey(JdbcConnectionCallSite.GRAPH_NOTE_KEY));
    }

    @Test
    void unsupportedControlFlowPublishesUnknownInsteadOfDroppingExactConsumer() {
        Fixture fixture = fixture(branchUrlBytes());
        Node call = fixture.call(JdbcConnectionCallSite.DRIVER_MANAGER_OWNER,
                JdbcConnectionCallSite.GET_CONNECTION_NAME,
                JdbcConnectionCallSite.CONNECTION_DESCRIPTOR);

        JdbcConnectionCallSite site = (JdbcConnectionCallSite) call.note(
                JdbcConnectionCallSite.GRAPH_NOTE_KEY);
        assertNotNull(site);
        assertEquals(JdbcConnectionCallSite.ValueState.UNKNOWN, site.url().state());
        assertEquals(JdbcConnectionCallSite.ValueState.UNKNOWN, site.properties().state());
        assertTrue(site.propertyEntries().isEmpty());
    }

    @Test
    void modelFromCallExcludesNonExactInvocations() {
        Fixture fixture = fixture(driverManagerBytes());
        Node call = fixture.call(JdbcConnectionCallSite.DRIVER_MANAGER_OWNER,
                JdbcConnectionCallSite.GET_CONNECTION_NAME,
                JdbcConnectionCallSite.CONNECTION_DESCRIPTOR);

        assertTrue(JdbcConnectionCallSite.fromCall(call.id(), fixture.hostMethod(), call.offset(),
                JdbcConnectionCallSite.DRIVER_MANAGER_OWNER,
                JdbcConnectionCallSite.GET_CONNECTION_NAME,
                JdbcConnectionCallSite.CONNECTION_DESCRIPTOR, "STATIC").isPresent());
        assertTrue(JdbcConnectionCallSite.fromCall(call.id(), fixture.hostMethod(), call.offset(),
                JdbcConnectionCallSite.DRIVER_MANAGER_OWNER,
                JdbcConnectionCallSite.GET_CONNECTION_NAME,
                "(Ljava/lang/String;)Ljava/sql/Connection;", "STATIC").isEmpty());
        assertTrue(JdbcConnectionCallSite.fromCall(call.id(), fixture.hostMethod(), call.offset(),
                "fixture/DriverManager", JdbcConnectionCallSite.GET_CONNECTION_NAME,
                JdbcConnectionCallSite.CONNECTION_DESCRIPTOR, "STATIC").isEmpty());
    }

    private static Fixture fixture(byte[] bytes) {
        ClassInfo info = extract(bytes);
        LoadResult load = new LoadResult(Map.of(info.internalName(), info), List.of(), 1, 61);
        Graph graph = new CpgBuilder().build(load).graph();
        String host = info.internalName() + "#build"
                + info.method("build", info.methods().get(0).descriptor()).descriptor();
        return new Fixture(info, graph, host,
                io.just.sast.model.MethodId.of(info.internalName(), "build",
                        info.methods().get(0).descriptor()));
    }

    private static ClassInfo extract(byte[] bytes) {
        org.objectweb.asm.tree.ClassNode node = new org.objectweb.asm.tree.ClassNode();
        new ClassReader(bytes).accept(node, 0);
        return new FactsExtractor().extract(node);
    }

    private static byte[] driverManagerBytes() {
        ClassWriter writer = hostWriter("fixture/JdbcManagerHost");
        MethodVisitor method = buildMethod(writer, "()Ljava/sql/Connection;");
        properties(method);
        method.visitLdcInsn("jdbc:fixture:one");
        method.visitVarInsn(Opcodes.ALOAD, 0);
        method.visitMethodInsn(Opcodes.INVOKESTATIC, JdbcConnectionCallSite.DRIVER_MANAGER_OWNER,
                JdbcConnectionCallSite.GET_CONNECTION_NAME,
                JdbcConnectionCallSite.CONNECTION_DESCRIPTOR, false);
        method.visitInsn(Opcodes.ARETURN);
        finish(method, 4, 1);
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] driverConnectBytes() {
        ClassWriter writer = hostWriter("fixture/JdbcDriverHost");
        MethodVisitor method = buildMethod(writer, "()Ljava/sql/Connection;");
        properties(method);
        method.visitTypeInsn(Opcodes.NEW, "fixture/Driver");
        method.visitInsn(Opcodes.DUP);
        method.visitMethodInsn(Opcodes.INVOKESPECIAL, "fixture/Driver", "<init>", "()V", false);
        method.visitVarInsn(Opcodes.ASTORE, 1);
        method.visitVarInsn(Opcodes.ALOAD, 1);
        method.visitLdcInsn("jdbc:fixture:driver");
        method.visitVarInsn(Opcodes.ALOAD, 0);
        method.visitMethodInsn(Opcodes.INVOKEINTERFACE, JdbcConnectionCallSite.DRIVER_OWNER,
                JdbcConnectionCallSite.CONNECT_NAME,
                JdbcConnectionCallSite.CONNECTION_DESCRIPTOR, true);
        method.visitInsn(Opcodes.ARETURN);
        finish(method, 4, 2);
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] unknownUrlBytes() {
        ClassWriter writer = hostWriter("fixture/JdbcUnknownUrlHost");
        MethodVisitor method = buildMethod(writer, "()Ljava/sql/Connection;");
        properties(method);
        method.visitMethodInsn(Opcodes.INVOKESTATIC, "fixture/Config", "url",
                "()Ljava/lang/String;", false);
        method.visitVarInsn(Opcodes.ALOAD, 0);
        method.visitMethodInsn(Opcodes.INVOKESTATIC, JdbcConnectionCallSite.DRIVER_MANAGER_OWNER,
                JdbcConnectionCallSite.GET_CONNECTION_NAME,
                JdbcConnectionCallSite.CONNECTION_DESCRIPTOR, false);
        method.visitInsn(Opcodes.ARETURN);
        finish(method, 4, 1);
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] wrongOverloadBytes() {
        ClassWriter writer = hostWriter("fixture/JdbcWrongOverloadHost");
        MethodVisitor method = buildMethod(writer, "()Ljava/sql/Connection;");
        method.visitLdcInsn("jdbc:fixture:wrong");
        method.visitLdcInsn("user");
        method.visitLdcInsn("secret");
        method.visitMethodInsn(Opcodes.INVOKESTATIC, JdbcConnectionCallSite.DRIVER_MANAGER_OWNER,
                JdbcConnectionCallSite.GET_CONNECTION_NAME,
                "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/sql/Connection;",
                false);
        method.visitInsn(Opcodes.ARETURN);
        finish(method, 3, 0);
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] wrongOwnerBytes() {
        ClassWriter writer = hostWriter("fixture/JdbcWrongOwnerHost");
        MethodVisitor method = buildMethod(writer, "()Ljava/sql/Connection;");
        properties(method);
        method.visitLdcInsn("jdbc:fixture:wrong-owner");
        method.visitVarInsn(Opcodes.ALOAD, 0);
        method.visitMethodInsn(Opcodes.INVOKESTATIC, "fixture/DriverManager",
                JdbcConnectionCallSite.GET_CONNECTION_NAME,
                JdbcConnectionCallSite.CONNECTION_DESCRIPTOR, false);
        method.visitInsn(Opcodes.ARETURN);
        finish(method, 4, 1);
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] branchUrlBytes() {
        ClassWriter writer = hostWriter("fixture/JdbcBranchHost");
        MethodVisitor method = buildMethod(writer, "()Ljava/sql/Connection;");
        properties(method);
        Label alternate = new Label();
        Label join = new Label();
        method.visitVarInsn(Opcodes.ALOAD, 0);
        method.visitJumpInsn(Opcodes.IFNULL, alternate);
        method.visitLdcInsn("jdbc:fixture:branch-one");
        method.visitJumpInsn(Opcodes.GOTO, join);
        method.visitLabel(alternate);
        method.visitLdcInsn("jdbc:fixture:branch-two");
        method.visitLabel(join);
        method.visitVarInsn(Opcodes.ALOAD, 0);
        method.visitMethodInsn(Opcodes.INVOKESTATIC, JdbcConnectionCallSite.DRIVER_MANAGER_OWNER,
                JdbcConnectionCallSite.GET_CONNECTION_NAME,
                JdbcConnectionCallSite.CONNECTION_DESCRIPTOR, false);
        method.visitInsn(Opcodes.ARETURN);
        finish(method, 4, 1);
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static void properties(MethodVisitor method) {
        method.visitTypeInsn(Opcodes.NEW, "java/util/Properties");
        method.visitInsn(Opcodes.DUP);
        method.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/util/Properties", "<init>",
                "()V", false);
        method.visitVarInsn(Opcodes.ASTORE, 0);

        method.visitVarInsn(Opcodes.ALOAD, 0);
        method.visitLdcInsn("user");
        method.visitLdcInsn("alice");
        method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/util/Properties",
                JdbcConnectionCallSite.PropertyEntry.SET_PROPERTY_NAME,
                JdbcConnectionCallSite.PropertyEntry.SET_PROPERTY_DESCRIPTOR, false);
        method.visitInsn(Opcodes.POP);

        method.visitVarInsn(Opcodes.ALOAD, 0);
        method.visitLdcInsn("user");
        method.visitLdcInsn("alice");
        method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/util/Properties",
                JdbcConnectionCallSite.PropertyEntry.PUT_NAME,
                JdbcConnectionCallSite.PropertyEntry.PUT_DESCRIPTOR, false);
        method.visitInsn(Opcodes.POP);
    }

    private static ClassWriter hostWriter(String name) {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, name, null, "java/lang/Object", null);
        return writer;
    }

    private static MethodVisitor buildMethod(ClassWriter writer, String descriptor) {
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "build", descriptor, null, null);
        method.visitCode();
        return method;
    }

    private static void finish(MethodVisitor method, int maxStack, int maxLocals) {
        method.visitMaxs(maxStack, maxLocals);
        method.visitEnd();
    }

    private record Fixture(ClassInfo info, Graph graph, String hostKey,
                           io.just.sast.model.MethodId hostMethod) {
        private Node call(String owner, String name, String descriptor) {
            return graph.callsOfMethod(hostKey).stream()
                    .filter(node -> owner.equals(node.owner()) && name.equals(node.name())
                            && descriptor.equals(node.descriptor()))
                    .findFirst().orElseThrow();
        }

    }
}
