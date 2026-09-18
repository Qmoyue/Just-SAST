package io.just.sast.cpg.build;

import io.just.sast.cpg.graph.Graph;
import io.just.sast.frontend.asm.FactsExtractor;
import io.just.sast.model.ClassInfo;
import io.just.sast.model.JaasLoginModuleCallSite;
import io.just.sast.model.JaasLoginModuleFlow;
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
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JaasLoginModuleBridgeContractTest {

    @Test
    void jdbcPropertiesOptionsAndLoginModuleLifecycleRetainOnePhysicalIdentity() {
        Fixture fixture = fixture(chainBytes());

        var jdbc = fixture.call(JdbcConnectionCallSite.DRIVER_MANAGER_OWNER,
                JdbcConnectionCallSite.GET_CONNECTION_NAME,
                JdbcConnectionCallSite.CONNECTION_DESCRIPTOR);
        JdbcConnectionCallSite jdbcFact = (JdbcConnectionCallSite) jdbc.note(
                JdbcConnectionCallSite.GRAPH_NOTE_KEY);
        assertNotNull(jdbcFact);
        assertEquals(1, jdbcFact.propertyEntries().size());

        var mapPut = fixture.call(JaasLoginModuleCallSite.MAP_OWNER,
                JaasLoginModuleCallSite.MAP_PUT_NAME,
                JaasLoginModuleCallSite.MAP_PUT_DESCRIPTOR);
        JaasLoginModuleCallSite mapFact = fact(mapPut);
        assertEquals(JaasLoginModuleCallSite.Kind.OPTIONS_MAP_PUT, mapFact.kind());

        var entry = fixture.call(JaasLoginModuleCallSite.APP_CONFIGURATION_ENTRY_OWNER,
                JaasLoginModuleCallSite.APP_CONFIGURATION_ENTRY_CONSTRUCTOR_NAME,
                JaasLoginModuleCallSite.APP_CONFIGURATION_ENTRY_CONSTRUCTOR_DESCRIPTOR);
        JaasLoginModuleCallSite entryFact = fact(entry);
        assertEquals(JaasLoginModuleCallSite.Kind.APP_CONFIGURATION_ENTRY, entryFact.kind());
        assertEquals(entryFact.argument(2).value().identity(), mapFact.receiver().value().identity());
        assertEquals(jdbcFact.propertyEntries().get(0).key().token(),
                mapFact.argument(0).value().token());
        assertEquals(jdbcFact.propertyEntries().get(0).value().token(),
                mapFact.argument(1).value().token());

        var initialize = fixture.call(JaasLoginModuleCallSite.LOGIN_MODULE_OWNER,
                JaasLoginModuleCallSite.INITIALIZE_NAME,
                JaasLoginModuleCallSite.INITIALIZE_DESCRIPTOR);
        JaasLoginModuleCallSite initializeFact = fact(initialize);
        assertEquals(JaasLoginModuleCallSite.Kind.LOGIN_MODULE_INITIALIZE,
                initializeFact.kind());
        assertEquals(entryFact.argument(2).value().identity(),
                initializeFact.argument(3).value().identity());

        var login = fixture.call(JaasLoginModuleCallSite.LOGIN_MODULE_OWNER,
                JaasLoginModuleCallSite.LOGIN_NAME,
                JaasLoginModuleCallSite.LOGIN_DESCRIPTOR);
        JaasLoginModuleCallSite loginFact = fact(login);
        assertEquals(JaasLoginModuleCallSite.Kind.LOGIN_MODULE_LOGIN, loginFact.kind());
        assertEquals(initializeFact.receiver().value().identity(),
                loginFact.receiver().value().identity());
        assertEquals("INTERFACE", initialize.invokeKind());
        assertEquals("INTERFACE", login.invokeKind());
        assertEquals("Ljava/util/Map;", initializeFact.argument(3).slot().descriptor());
        Object flowNote = login.note(JaasLoginModuleFlow.GRAPH_NOTE_KEY);
        assertTrue(flowNote instanceof List<?>);
        List<?> flows = (List<?>) flowNote;
        assertEquals(1, flows.size());
        JaasLoginModuleFlow flow = (JaasLoginModuleFlow) flows.get(0);
        assertTrue(flow.proved());
        assertEquals(JaasLoginModuleFlow.Reason.NONE, flow.reason());
        assertEquals(1, flow.propertyOptionBridges().size());
        assertTrue(flow.propertyOptionBridges().get(0).proved());
    }

    @Test
    void unsupportedControlFlowKeepsExactJaasConsumersAsUnknownFacts() {
        Fixture fixture = fixture(branchBytes());

        JaasLoginModuleCallSite mapFact = fact(fixture.call(JaasLoginModuleCallSite.MAP_OWNER,
                JaasLoginModuleCallSite.MAP_PUT_NAME,
                JaasLoginModuleCallSite.MAP_PUT_DESCRIPTOR));
        JaasLoginModuleCallSite initializeFact = fact(fixture.call(
                JaasLoginModuleCallSite.LOGIN_MODULE_OWNER,
                JaasLoginModuleCallSite.INITIALIZE_NAME,
                JaasLoginModuleCallSite.INITIALIZE_DESCRIPTOR));

        assertEquals(JaasLoginModuleCallSite.ValueState.UNKNOWN,
                mapFact.receiver().value().state());
        assertEquals(JaasLoginModuleCallSite.ValueState.UNKNOWN,
                initializeFact.argument(3).value().state());
        assertTrue(mapFact.identity().contains("jaas-call-v1:"));
    }

    @Test
    void unknownJdbcUrlRemainsPartialAndCannotProveTheContinuousFlow() {
        Fixture fixture = fixture(chainBytes(true, false, false));
        var login = fixture.call(JaasLoginModuleCallSite.LOGIN_MODULE_OWNER,
                JaasLoginModuleCallSite.LOGIN_NAME,
                JaasLoginModuleCallSite.LOGIN_DESCRIPTOR);
        List<?> flows = (List<?>) login.note(JaasLoginModuleFlow.GRAPH_NOTE_KEY);

        assertEquals(1, flows.size());
        JaasLoginModuleFlow flow = (JaasLoginModuleFlow) flows.get(0);
        assertEquals(JaasLoginModuleFlow.Status.PARTIAL, flow.status());
        assertEquals(JaasLoginModuleFlow.Reason.JDBC_URL_NOT_KNOWN, flow.reason());
        assertTrue(!flow.proved());
    }

    @Test
    void optionsOrLoginReceiverIdentityMismatchCannotBecomeACompleteFlow() {
        Fixture optionsMismatch = fixture(chainBytes(false, true, false));
        List<?> optionsFlows = (List<?>) optionsMismatch.call(
                JaasLoginModuleCallSite.LOGIN_MODULE_OWNER,
                JaasLoginModuleCallSite.LOGIN_NAME,
                JaasLoginModuleCallSite.LOGIN_DESCRIPTOR)
                .note(JaasLoginModuleFlow.GRAPH_NOTE_KEY);
        JaasLoginModuleFlow optionsFlow = (JaasLoginModuleFlow) optionsFlows.get(0);
        assertEquals(JaasLoginModuleFlow.Status.UNKNOWN, optionsFlow.status());
        assertEquals(JaasLoginModuleFlow.Reason.OPTIONS_IDENTITY_MISMATCH,
                optionsFlow.reason());

        Fixture receiverMismatch = fixture(chainBytes(false, false, true));
        List<?> receiverFlows = (List<?>) receiverMismatch.call(
                JaasLoginModuleCallSite.LOGIN_MODULE_OWNER,
                JaasLoginModuleCallSite.LOGIN_NAME,
                JaasLoginModuleCallSite.LOGIN_DESCRIPTOR)
                .note(JaasLoginModuleFlow.GRAPH_NOTE_KEY);
        JaasLoginModuleFlow receiverFlow = (JaasLoginModuleFlow) receiverFlows.get(0);
        assertEquals(JaasLoginModuleFlow.Status.UNKNOWN, receiverFlow.status());
        assertEquals(JaasLoginModuleFlow.Reason.LOGIN_RECEIVER_IDENTITY_MISMATCH,
                receiverFlow.reason());
    }

    @Test
    void equalOptionTextAtDifferentCallSitesDoesNotMergeIdentity() {
        Fixture fixture = fixture(equalTextBytes());
        List<io.just.sast.cpg.graph.Node> puts = fixture.graph().callsOfMethod(fixture.hostKey())
                .stream().filter(node -> JaasLoginModuleCallSite.MAP_OWNER.equals(node.owner())
                        && JaasLoginModuleCallSite.MAP_PUT_NAME.equals(node.name()))
                .toList();

        assertEquals(2, puts.size());
        JaasLoginModuleCallSite first = fact(puts.get(0));
        JaasLoginModuleCallSite second = fact(puts.get(1));
        assertEquals("same", first.argument(0).value().displayValue());
        assertEquals("same", second.argument(0).value().displayValue());
        assertNotEquals(first.argument(0).value().identity(),
                second.argument(0).value().identity());
        assertNotEquals(first.argument(1).value().identity(),
                second.argument(1).value().identity());
    }

    @Test
    void nonContractOwnersAndDescriptorsDoNotCreateJaasFacts() {
        Fixture fixture = fixture(wrongApiBytes());
        assertNull(fixture.callOrNull("fixture/OtherMap", JaasLoginModuleCallSite.MAP_PUT_NAME,
                JaasLoginModuleCallSite.MAP_PUT_DESCRIPTOR)
                .note(JaasLoginModuleCallSite.GRAPH_NOTE_KEY));
        assertNull(fixture.callOrNull(JaasLoginModuleCallSite.LOGIN_MODULE_OWNER,
                JaasLoginModuleCallSite.LOGIN_NAME, "(I)Z")
                .note(JaasLoginModuleCallSite.GRAPH_NOTE_KEY));
    }

    private static JaasLoginModuleCallSite fact(io.just.sast.cpg.graph.Node node) {
        JaasLoginModuleCallSite fact = (JaasLoginModuleCallSite) node.note(
                JaasLoginModuleCallSite.GRAPH_NOTE_KEY);
        assertNotNull(fact);
        return fact;
    }

    private static Fixture fixture(byte[] bytes) {
        ClassInfo info = extract(bytes);
        LoadResult load = new LoadResult(Map.of(info.internalName(), info), List.of(), 1, 61);
        Graph graph = new CpgBuilder().build(load).graph();
        String descriptor = info.method("flow", "()Z") == null ? "()V" : "()Z";
        return new Fixture(graph, info.internalName() + "#flow" + descriptor);
    }

    private static ClassInfo extract(byte[] bytes) {
        org.objectweb.asm.tree.ClassNode node = new org.objectweb.asm.tree.ClassNode();
        new ClassReader(bytes).accept(node, 0);
        return new FactsExtractor().extract(node);
    }

    private static byte[] chainBytes() {
        return chainBytes(false, false, false);
    }

    private static byte[] chainBytes(boolean unknownUrl, boolean optionsMismatch,
                                     boolean receiverMismatch) {
        ClassWriter writer = hostWriter("fixture/JaasChainHost");
        MethodVisitor method = flowMethod(writer, "()Z");

        method.visitTypeInsn(Opcodes.NEW, "java/util/Properties");
        method.visitInsn(Opcodes.DUP);
        method.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/util/Properties", "<init>",
                "()V", false);
        method.visitVarInsn(Opcodes.ASTORE, 0);
        method.visitLdcInsn("jaas-key");
        method.visitVarInsn(Opcodes.ASTORE, 1);
        method.visitLdcInsn("module-value");
        method.visitVarInsn(Opcodes.ASTORE, 2);
        method.visitVarInsn(Opcodes.ALOAD, 0);
        method.visitVarInsn(Opcodes.ALOAD, 1);
        method.visitVarInsn(Opcodes.ALOAD, 2);
        method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/util/Properties", "setProperty",
                JdbcConnectionCallSite.PropertyEntry.SET_PROPERTY_DESCRIPTOR, false);
        method.visitInsn(Opcodes.POP);
        if (unknownUrl) {
            method.visitMethodInsn(Opcodes.INVOKESTATIC, "fixture/Config", "url",
                    "()Ljava/lang/String;", false);
        } else {
            method.visitLdcInsn("jdbc:fixture:jaas");
        }
        method.visitVarInsn(Opcodes.ALOAD, 0);
        method.visitMethodInsn(Opcodes.INVOKESTATIC, JdbcConnectionCallSite.DRIVER_MANAGER_OWNER,
                JdbcConnectionCallSite.GET_CONNECTION_NAME,
                JdbcConnectionCallSite.CONNECTION_DESCRIPTOR, false);
        method.visitInsn(Opcodes.POP);

        method.visitTypeInsn(Opcodes.NEW, "java/util/HashMap");
        method.visitInsn(Opcodes.DUP);
        method.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/util/HashMap", "<init>",
                "()V", false);
        method.visitVarInsn(Opcodes.ASTORE, 3);
        method.visitVarInsn(Opcodes.ALOAD, 3);
        method.visitVarInsn(Opcodes.ALOAD, 1);
        method.visitVarInsn(Opcodes.ALOAD, 2);
        method.visitMethodInsn(Opcodes.INVOKEINTERFACE, JaasLoginModuleCallSite.MAP_OWNER,
                JaasLoginModuleCallSite.MAP_PUT_NAME,
                JaasLoginModuleCallSite.MAP_PUT_DESCRIPTOR, true);
        method.visitInsn(Opcodes.POP);

        method.visitTypeInsn(Opcodes.NEW, JaasLoginModuleCallSite.APP_CONFIGURATION_ENTRY_OWNER);
        method.visitInsn(Opcodes.DUP);
        method.visitVarInsn(Opcodes.ALOAD, 2);
        method.visitFieldInsn(Opcodes.GETSTATIC,
                JaasLoginModuleCallSite.APP_CONFIGURATION_ENTRY_OWNER
                        + "$LoginModuleControlFlag", "REQUIRED",
                "L" + JaasLoginModuleCallSite.APP_CONFIGURATION_ENTRY_OWNER
                        + "$LoginModuleControlFlag;");
        method.visitVarInsn(Opcodes.ALOAD, 3);
        method.visitMethodInsn(Opcodes.INVOKESPECIAL,
                JaasLoginModuleCallSite.APP_CONFIGURATION_ENTRY_OWNER,
                JaasLoginModuleCallSite.APP_CONFIGURATION_ENTRY_CONSTRUCTOR_NAME,
                JaasLoginModuleCallSite.APP_CONFIGURATION_ENTRY_CONSTRUCTOR_DESCRIPTOR, false);
        method.visitVarInsn(Opcodes.ASTORE, 4);

        method.visitTypeInsn(Opcodes.NEW, "fixture/LoginModule");
        method.visitInsn(Opcodes.DUP);
        method.visitMethodInsn(Opcodes.INVOKESPECIAL, "fixture/LoginModule", "<init>",
                "()V", false);
        method.visitVarInsn(Opcodes.ASTORE, 5);
        int loginModuleLocal = 5;
        if (receiverMismatch) {
            method.visitTypeInsn(Opcodes.NEW, "fixture/OtherLoginModule");
            method.visitInsn(Opcodes.DUP);
            method.visitMethodInsn(Opcodes.INVOKESPECIAL, "fixture/OtherLoginModule", "<init>",
                    "()V", false);
            method.visitVarInsn(Opcodes.ASTORE, 7);
            loginModuleLocal = 7;
        }
        int optionsLocal = 3;
        if (optionsMismatch) {
            method.visitTypeInsn(Opcodes.NEW, "java/util/HashMap");
            method.visitInsn(Opcodes.DUP);
            method.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/util/HashMap", "<init>",
                    "()V", false);
            method.visitVarInsn(Opcodes.ASTORE, 6);
            optionsLocal = 6;
        }
        method.visitVarInsn(Opcodes.ALOAD, 5);
        method.visitInsn(Opcodes.ACONST_NULL);
        method.visitInsn(Opcodes.ACONST_NULL);
        method.visitVarInsn(Opcodes.ALOAD, optionsLocal);
        method.visitVarInsn(Opcodes.ALOAD, optionsLocal);
        method.visitMethodInsn(Opcodes.INVOKEINTERFACE, JaasLoginModuleCallSite.LOGIN_MODULE_OWNER,
                JaasLoginModuleCallSite.INITIALIZE_NAME,
                JaasLoginModuleCallSite.INITIALIZE_DESCRIPTOR, true);
        method.visitVarInsn(Opcodes.ALOAD, loginModuleLocal);
        method.visitMethodInsn(Opcodes.INVOKEINTERFACE, JaasLoginModuleCallSite.LOGIN_MODULE_OWNER,
                JaasLoginModuleCallSite.LOGIN_NAME,
                JaasLoginModuleCallSite.LOGIN_DESCRIPTOR, true);
        method.visitInsn(Opcodes.IRETURN);
        finish(method, 6, 8);
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] branchBytes() {
        ClassWriter writer = hostWriter("fixture/JaasBranchHost");
        MethodVisitor method = flowMethod(writer, "()V");
        Label alternate = new Label();
        method.visitInsn(Opcodes.ACONST_NULL);
        method.visitJumpInsn(Opcodes.IFNULL, alternate);
        emitUnknownMapPut(method);
        method.visitLabel(alternate);
        emitUnknownInitialize(method);
        method.visitInsn(Opcodes.RETURN);
        finish(method, 6, 0);
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] equalTextBytes() {
        ClassWriter writer = hostWriter("fixture/JaasEqualTextHost");
        MethodVisitor method = flowMethod(writer, "()V");
        method.visitTypeInsn(Opcodes.NEW, "java/util/HashMap");
        method.visitInsn(Opcodes.DUP);
        method.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/util/HashMap", "<init>",
                "()V", false);
        method.visitVarInsn(Opcodes.ASTORE, 0);
        emitMapPut(method, 0, "same", "value");
        emitMapPut(method, 0, "same", "value");
        method.visitInsn(Opcodes.RETURN);
        finish(method, 3, 1);
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] wrongApiBytes() {
        ClassWriter writer = hostWriter("fixture/JaasWrongApiHost");
        MethodVisitor method = flowMethod(writer, "()V");
        method.visitInsn(Opcodes.ACONST_NULL);
        method.visitInsn(Opcodes.ACONST_NULL);
        method.visitInsn(Opcodes.ACONST_NULL);
        method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "fixture/OtherMap",
                JaasLoginModuleCallSite.MAP_PUT_NAME,
                JaasLoginModuleCallSite.MAP_PUT_DESCRIPTOR, false);
        method.visitInsn(Opcodes.POP);
        method.visitInsn(Opcodes.ACONST_NULL);
        method.visitMethodInsn(Opcodes.INVOKEINTERFACE, JaasLoginModuleCallSite.LOGIN_MODULE_OWNER,
                JaasLoginModuleCallSite.LOGIN_NAME, "(I)Z", true);
        method.visitInsn(Opcodes.POP);
        method.visitInsn(Opcodes.RETURN);
        finish(method, 3, 0);
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static void emitMapPut(MethodVisitor method, int local, String key, String value) {
        method.visitVarInsn(Opcodes.ALOAD, local);
        method.visitLdcInsn(key);
        method.visitLdcInsn(value);
        method.visitMethodInsn(Opcodes.INVOKEINTERFACE, JaasLoginModuleCallSite.MAP_OWNER,
                JaasLoginModuleCallSite.MAP_PUT_NAME,
                JaasLoginModuleCallSite.MAP_PUT_DESCRIPTOR, true);
        method.visitInsn(Opcodes.POP);
    }

    private static void emitUnknownMapPut(MethodVisitor method) {
        method.visitInsn(Opcodes.ACONST_NULL);
        method.visitInsn(Opcodes.ACONST_NULL);
        method.visitInsn(Opcodes.ACONST_NULL);
        method.visitMethodInsn(Opcodes.INVOKEINTERFACE, JaasLoginModuleCallSite.MAP_OWNER,
                JaasLoginModuleCallSite.MAP_PUT_NAME,
                JaasLoginModuleCallSite.MAP_PUT_DESCRIPTOR, true);
        method.visitInsn(Opcodes.POP);
    }

    private static void emitUnknownInitialize(MethodVisitor method) {
        for (int i = 0; i < 5; i++) {
            method.visitInsn(Opcodes.ACONST_NULL);
        }
        method.visitMethodInsn(Opcodes.INVOKEINTERFACE, JaasLoginModuleCallSite.LOGIN_MODULE_OWNER,
                JaasLoginModuleCallSite.INITIALIZE_NAME,
                JaasLoginModuleCallSite.INITIALIZE_DESCRIPTOR, true);
    }

    private static ClassWriter hostWriter(String name) {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, name, null, "java/lang/Object", null);
        return writer;
    }

    private static MethodVisitor flowMethod(ClassWriter writer, String descriptor) {
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "flow", descriptor, null, null);
        method.visitCode();
        return method;
    }

    private static void finish(MethodVisitor method, int maxStack, int maxLocals) {
        method.visitMaxs(maxStack, maxLocals);
        method.visitEnd();
    }

    private record Fixture(Graph graph, String hostKey) {
        private io.just.sast.cpg.graph.Node call(String owner, String name, String descriptor) {
            return callOrNull(owner, name, descriptor);
        }

        private io.just.sast.cpg.graph.Node callOrNull(String owner, String name,
                                                        String descriptor) {
            return graph.callsOfMethod(hostKey).stream()
                    .filter(node -> owner.equals(node.owner()) && name.equals(node.name())
                            && descriptor.equals(node.descriptor()))
                    .findFirst().orElseThrow();
        }
    }
}
