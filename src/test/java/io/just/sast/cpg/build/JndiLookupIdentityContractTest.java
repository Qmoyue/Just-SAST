package io.just.sast.cpg.build;

import io.just.sast.cpg.graph.Graph;
import io.just.sast.cpg.graph.Node;
import io.just.sast.frontend.asm.FactsExtractor;
import io.just.sast.model.ClassInfo;
import io.just.sast.model.JndiLookupCallSite;
import io.just.sast.model.JndiLookupIdentityFlow;
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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JndiLookupIdentityContractTest {

    @Test
    void lookupResultRetainsIdentityThroughCastAndDirContextSearchReceiver() {
        Fixture fixture = fixture(chainBytes());
        Node lookup = fixture.call(JndiLookupCallSite.INITIAL_CONTEXT_OWNER,
                JndiLookupCallSite.LOOKUP_NAME, JndiLookupCallSite.LOOKUP_DESCRIPTOR);
        Node search = fixture.call(JndiLookupCallSite.DIR_CONTEXT_OWNER,
                JndiLookupCallSite.SEARCH_NAME,
                "(Ljava/lang/String;Ljavax/naming/directory/Attributes;)"
                        + JndiLookupCallSite.SEARCH_RETURN_DESCRIPTOR);

        JndiLookupCallSite lookupFact = fact(lookup);
        JndiLookupCallSite searchFact = fact(search);
        assertEquals(JndiLookupCallSite.Kind.INITIAL_CONTEXT_LOOKUP, lookupFact.kind());
        assertEquals(JndiLookupCallSite.Kind.DIR_CONTEXT_SEARCH, searchFact.kind());
        assertEquals("ldap://fixture/entry", lookupFact.argument(0).value().displayValue());
        assertEquals(lookupFact.returnValue().orElseThrow().value().identity(),
                searchFact.receiver().value().identity());
        assertEquals("Ljavax/naming/directory/DirContext;",
                searchFact.receiver().slot().descriptor());
        assertEquals("Ljava/lang/Object;",
                lookupFact.returnValue().orElseThrow().value().descriptor());

        List<JndiLookupIdentityFlow> flows = flows(search);
        assertEquals(1, flows.size());
        assertTrue(flows.get(0).proved());
        assertEquals(JndiLookupIdentityFlow.Status.PROVED, flows.get(0).status());
        assertEquals(JndiLookupIdentityFlow.Reason.NONE, flows.get(0).reason());
    }

    @Test
    void unknownLookupNameDoesNotEraseProvenObjectIdentity() {
        Fixture fixture = fixture(chainBytes(true));
        Node lookup = fixture.call(JndiLookupCallSite.INITIAL_CONTEXT_OWNER,
                JndiLookupCallSite.LOOKUP_NAME, JndiLookupCallSite.LOOKUP_DESCRIPTOR);
        Node search = fixture.call(JndiLookupCallSite.DIR_CONTEXT_OWNER,
                JndiLookupCallSite.SEARCH_NAME,
                "(Ljava/lang/String;Ljavax/naming/directory/Attributes;)"
                        + JndiLookupCallSite.SEARCH_RETURN_DESCRIPTOR);

        assertEquals(JndiLookupCallSite.ValueState.UNKNOWN,
                fact(lookup).argument(0).value().state());
        assertEquals(1, flows(search).size());
        assertTrue(flows(search).get(0).proved());
    }

    @Test
    void equalDisplayTextFromDifferentLookupObjectsDoesNotMergeIdentity() {
        Fixture fixture = fixture(twoLookupBytes());
        List<Node> lookups = fixture.graph().callsOfMethod(fixture.hostKey()).stream()
                .filter(node -> JndiLookupCallSite.INITIAL_CONTEXT_OWNER.equals(node.owner())
                        && JndiLookupCallSite.LOOKUP_NAME.equals(node.name()))
                .toList();
        Node search = fixture.call(JndiLookupCallSite.DIR_CONTEXT_OWNER,
                JndiLookupCallSite.SEARCH_NAME,
                "(Ljava/lang/String;Ljavax/naming/directory/Attributes;)"
                        + JndiLookupCallSite.SEARCH_RETURN_DESCRIPTOR);

        assertEquals(2, lookups.size());
        assertEquals("same", fact(lookups.get(0)).argument(0).value().displayValue());
        assertEquals("same", fact(lookups.get(1)).argument(0).value().displayValue());
        assertNotEquals(fact(lookups.get(0)).returnValue().orElseThrow().value().identity(),
                fact(lookups.get(1)).returnValue().orElseThrow().value().identity());

        List<JndiLookupIdentityFlow> flows = flows(search);
        assertEquals(2, flows.size());
        assertEquals(1, flows.stream().filter(JndiLookupIdentityFlow::proved).count());
        assertEquals(1, flows.stream().filter(flow ->
                flow.reason() == JndiLookupIdentityFlow.Reason.LOOKUP_SEARCH_IDENTITY_MISMATCH)
                .count());
    }

    @Test
    void unsupportedOwnersAndOverloadsDoNotCreateLookupIdentityFacts() {
        Fixture fixture = fixture(wrongApiBytes());
        assertNull(fixture.callOrNull(JndiLookupCallSite.INITIAL_CONTEXT_OWNER,
                JndiLookupCallSite.LOOKUP_NAME,
                "(Ljavax/naming/Name;)Ljava/lang/Object;")
                .note(JndiLookupCallSite.GRAPH_NOTE_KEY));
        assertNull(fixture.callOrNull("fixture/OtherDirContext", JndiLookupCallSite.SEARCH_NAME,
                "(Ljava/lang/String;Ljavax/naming/directory/Attributes;)"
                        + JndiLookupCallSite.SEARCH_RETURN_DESCRIPTOR)
                .note(JndiLookupCallSite.GRAPH_NOTE_KEY));
        assertNull(fixture.callOrNull(JndiLookupCallSite.DIR_CONTEXT_OWNER,
                JndiLookupCallSite.SEARCH_NAME, "(Ljava/lang/String;)"
                        + JndiLookupCallSite.SEARCH_RETURN_DESCRIPTOR)
                .note(JndiLookupCallSite.GRAPH_NOTE_KEY));
    }

    @Test
    void incompleteControlFlowKeepsExactLookupAndSearchSlotsUnknown() {
        Fixture fixture = fixture(branchBytes());
        Node lookup = fixture.call(JndiLookupCallSite.INITIAL_CONTEXT_OWNER,
                JndiLookupCallSite.LOOKUP_NAME, JndiLookupCallSite.LOOKUP_DESCRIPTOR);
        Node search = fixture.call(JndiLookupCallSite.DIR_CONTEXT_OWNER,
                JndiLookupCallSite.SEARCH_NAME,
                "(Ljava/lang/String;Ljavax/naming/directory/Attributes;)"
                        + JndiLookupCallSite.SEARCH_RETURN_DESCRIPTOR);

        JndiLookupCallSite lookupFact = fact(lookup);
        JndiLookupCallSite searchFact = fact(search);
        assertEquals(JndiLookupCallSite.ValueState.UNKNOWN,
                lookupFact.returnValue().orElseThrow().value().state());
        assertEquals(JndiLookupCallSite.ValueState.UNKNOWN,
                searchFact.receiver().value().state());
        assertTrue(flows(search).isEmpty());
    }

    private static JndiLookupCallSite fact(Node node) {
        JndiLookupCallSite fact = (JndiLookupCallSite) node.note(
                JndiLookupCallSite.GRAPH_NOTE_KEY);
        assertNotNull(fact);
        return fact;
    }

    @SuppressWarnings("unchecked")
    private static List<JndiLookupIdentityFlow> flows(Node node) {
        Object note = node.note(JndiLookupIdentityFlow.GRAPH_NOTE_KEY);
        if (note == null) {
            return List.of();
        }
        return (List<JndiLookupIdentityFlow>) note;
    }

    private static Fixture fixture(byte[] bytes) {
        ClassInfo info = extract(bytes);
        LoadResult load = new LoadResult(Map.of(info.internalName(), info), List.of(), 1, 61);
        Graph graph = new CpgBuilder().build(load).graph();
        return new Fixture(graph, info.internalName() + "#flow()V");
    }

    private static ClassInfo extract(byte[] bytes) {
        org.objectweb.asm.tree.ClassNode node = new org.objectweb.asm.tree.ClassNode();
        new ClassReader(bytes).accept(node, 0);
        return new FactsExtractor().extract(node);
    }

    private static byte[] chainBytes() {
        return chainBytes(false);
    }

    private static byte[] chainBytes(boolean unknownLookupName) {
        ClassWriter writer = hostWriter("fixture/JndiLookupHost");
        MethodVisitor method = flowMethod(writer);
        emitContext(method, 0);
        method.visitVarInsn(Opcodes.ALOAD, 0);
        if (unknownLookupName) {
            method.visitMethodInsn(Opcodes.INVOKESTATIC, "fixture/Config", "url",
                    "()Ljava/lang/String;", false);
        } else {
            method.visitLdcInsn("ldap://fixture/entry");
        }
        method.visitMethodInsn(Opcodes.INVOKEVIRTUAL,
                JndiLookupCallSite.INITIAL_CONTEXT_OWNER, JndiLookupCallSite.LOOKUP_NAME,
                JndiLookupCallSite.LOOKUP_DESCRIPTOR, false);
        method.visitTypeInsn(Opcodes.CHECKCAST, JndiLookupCallSite.DIR_CONTEXT_OWNER);
        method.visitVarInsn(Opcodes.ASTORE, 1);
        emitSearch(method, 1, "");
        method.visitInsn(Opcodes.POP);
        method.visitInsn(Opcodes.RETURN);
        finish(method, 3, 2);
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] twoLookupBytes() {
        ClassWriter writer = hostWriter("fixture/JndiLookupIdentityHost");
        MethodVisitor method = flowMethod(writer);
        emitContext(method, 0);
        emitLookup(method, 0, "same");
        method.visitTypeInsn(Opcodes.CHECKCAST, JndiLookupCallSite.DIR_CONTEXT_OWNER);
        method.visitVarInsn(Opcodes.ASTORE, 1);
        emitLookup(method, 0, "same");
        method.visitTypeInsn(Opcodes.CHECKCAST, JndiLookupCallSite.DIR_CONTEXT_OWNER);
        method.visitVarInsn(Opcodes.ASTORE, 2);
        emitSearch(method, 1, "");
        method.visitInsn(Opcodes.POP);
        method.visitInsn(Opcodes.RETURN);
        finish(method, 3, 3);
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] wrongApiBytes() {
        ClassWriter writer = hostWriter("fixture/JndiWrongApiHost");
        MethodVisitor method = flowMethod(writer);
        emitContext(method, 0);
        method.visitVarInsn(Opcodes.ALOAD, 0);
        method.visitInsn(Opcodes.ACONST_NULL);
        method.visitMethodInsn(Opcodes.INVOKEVIRTUAL,
                JndiLookupCallSite.INITIAL_CONTEXT_OWNER, JndiLookupCallSite.LOOKUP_NAME,
                "(Ljavax/naming/Name;)Ljava/lang/Object;", false);
        method.visitInsn(Opcodes.POP);
        method.visitInsn(Opcodes.ACONST_NULL);
        method.visitLdcInsn("");
        method.visitInsn(Opcodes.ACONST_NULL);
        method.visitMethodInsn(Opcodes.INVOKEINTERFACE, "fixture/OtherDirContext",
                JndiLookupCallSite.SEARCH_NAME,
                "(Ljava/lang/String;Ljavax/naming/directory/Attributes;)"
                        + JndiLookupCallSite.SEARCH_RETURN_DESCRIPTOR, true);
        method.visitInsn(Opcodes.POP);
        method.visitInsn(Opcodes.ACONST_NULL);
        method.visitLdcInsn("");
        method.visitMethodInsn(Opcodes.INVOKEINTERFACE, JndiLookupCallSite.DIR_CONTEXT_OWNER,
                JndiLookupCallSite.SEARCH_NAME, "(Ljava/lang/String;)"
                        + JndiLookupCallSite.SEARCH_RETURN_DESCRIPTOR, true);
        method.visitInsn(Opcodes.POP);
        method.visitInsn(Opcodes.RETURN);
        finish(method, 3, 1);
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] branchBytes() {
        ClassWriter writer = hostWriter("fixture/JndiBranchHost");
        MethodVisitor method = flowMethod(writer);
        emitContext(method, 0);
        Label alternate = new Label();
        method.visitInsn(Opcodes.ACONST_NULL);
        method.visitJumpInsn(Opcodes.IFNULL, alternate);
        emitLookup(method, 0, "branch");
        method.visitTypeInsn(Opcodes.CHECKCAST, JndiLookupCallSite.DIR_CONTEXT_OWNER);
        method.visitVarInsn(Opcodes.ASTORE, 1);
        emitSearch(method, 1, "");
        method.visitInsn(Opcodes.POP);
        method.visitLabel(alternate);
        method.visitInsn(Opcodes.RETURN);
        finish(method, 3, 2);
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static void emitContext(MethodVisitor method, int local) {
        method.visitTypeInsn(Opcodes.NEW, JndiLookupCallSite.INITIAL_CONTEXT_OWNER);
        method.visitInsn(Opcodes.DUP);
        method.visitMethodInsn(Opcodes.INVOKESPECIAL, JndiLookupCallSite.INITIAL_CONTEXT_OWNER,
                "<init>", "()V", false);
        method.visitVarInsn(Opcodes.ASTORE, local);
    }

    private static void emitLookup(MethodVisitor method, int contextLocal, String value) {
        method.visitVarInsn(Opcodes.ALOAD, contextLocal);
        method.visitLdcInsn(value);
        method.visitMethodInsn(Opcodes.INVOKEVIRTUAL,
                JndiLookupCallSite.INITIAL_CONTEXT_OWNER, JndiLookupCallSite.LOOKUP_NAME,
                JndiLookupCallSite.LOOKUP_DESCRIPTOR, false);
    }

    private static void emitSearch(MethodVisitor method, int contextLocal, String name) {
        method.visitVarInsn(Opcodes.ALOAD, contextLocal);
        method.visitLdcInsn(name);
        method.visitInsn(Opcodes.ACONST_NULL);
        method.visitMethodInsn(Opcodes.INVOKEINTERFACE, JndiLookupCallSite.DIR_CONTEXT_OWNER,
                JndiLookupCallSite.SEARCH_NAME,
                "(Ljava/lang/String;Ljavax/naming/directory/Attributes;)"
                        + JndiLookupCallSite.SEARCH_RETURN_DESCRIPTOR, true);
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
            return callOrNull(owner, name, descriptor);
        }

        private Node callOrNull(String owner, String name, String descriptor) {
            return graph.callsOfMethod(hostKey).stream()
                    .filter(node -> owner.equals(node.owner()) && name.equals(node.name())
                            && descriptor.equals(node.descriptor()))
                    .findFirst().orElseThrow();
        }
    }
}
