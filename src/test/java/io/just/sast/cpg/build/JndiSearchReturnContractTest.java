package io.just.sast.cpg.build;

import io.just.sast.cpg.graph.Graph;
import io.just.sast.cpg.graph.Node;
import io.just.sast.frontend.asm.FactsExtractor;
import io.just.sast.model.ClassInfo;
import io.just.sast.model.JndiLookupCallSite;
import io.just.sast.model.JndiNamingEnumerationCallSite;
import io.just.sast.model.JndiSearchReturnFlow;
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

class JndiSearchReturnContractTest {

    private static final String SEARCH_DESCRIPTOR =
            "(Ljava/lang/String;Ljavax/naming/directory/Attributes;)"
                    + JndiLookupCallSite.SEARCH_RETURN_DESCRIPTOR;

    @Test
    void searchResultUsesSameEnumerationIdentityAndDeclaredElementContract() {
        Fixture fixture = fixture(searchAndConsumersBytes());
        Node search = fixture.call(JndiLookupCallSite.DIR_CONTEXT_OWNER,
                JndiLookupCallSite.SEARCH_NAME, SEARCH_DESCRIPTOR);
        Node hasMore = fixture.call(JndiNamingEnumerationCallSite.NAMING_ENUMERATION_OWNER,
                JndiNamingEnumerationCallSite.HAS_MORE_NAME,
                JndiNamingEnumerationCallSite.BOOLEAN_DESCRIPTOR);
        Node next = fixture.call(JndiNamingEnumerationCallSite.NAMING_ENUMERATION_OWNER,
                JndiNamingEnumerationCallSite.NEXT_NAME,
                JndiNamingEnumerationCallSite.ELEMENT_DESCRIPTOR);

        JndiLookupCallSite searchFact = searchFact(search);
        JndiNamingEnumerationCallSite hasMoreFact = consumerFact(hasMore);
        JndiNamingEnumerationCallSite nextFact = consumerFact(next);
        assertEquals(searchFact.returnValue().orElseThrow().value().identity(),
                hasMoreFact.receiver().value().identity());
        assertEquals(searchFact.returnValue().orElseThrow().value().identity(),
                nextFact.receiver().value().identity());
        assertNotEquals(nextFact.receiver().value().identity(),
                nextFact.returnValue().value().identity());

        List<JndiSearchReturnFlow> hasMoreFlows = flows(hasMore);
        assertEquals(1, hasMoreFlows.size());
        assertEquals(JndiSearchReturnFlow.Relation.SAME_IDENTITY,
                hasMoreFlows.get(0).relation());
        assertEquals(JndiSearchReturnFlow.Status.PROVED, hasMoreFlows.get(0).status());

        List<JndiSearchReturnFlow> nextFlows = flows(next);
        assertEquals(1, nextFlows.size());
        assertEquals(JndiSearchReturnFlow.Relation.DECLARED_CONTRACT,
                nextFlows.get(0).relation());
        assertTrue(nextFlows.get(0).declaredContract());
        assertEquals(JndiSearchReturnFlow.Reason.NONE, nextFlows.get(0).reason());
    }

    @Test
    void equalContractTextDoesNotMergeDifferentSearchResultIdentities() {
        Fixture fixture = fixture(twoSearchesBytes());
        List<Node> searches = fixture.calls(JndiLookupCallSite.DIR_CONTEXT_OWNER,
                JndiLookupCallSite.SEARCH_NAME, SEARCH_DESCRIPTOR);
        Node next = fixture.call(JndiNamingEnumerationCallSite.NAMING_ENUMERATION_OWNER,
                JndiNamingEnumerationCallSite.NEXT_NAME,
                JndiNamingEnumerationCallSite.ELEMENT_DESCRIPTOR);

        assertEquals(2, searches.size());
        assertNotEquals(searchFact(searches.get(0)).returnValue().orElseThrow().value().identity(),
                searchFact(searches.get(1)).returnValue().orElseThrow().value().identity());
        List<JndiSearchReturnFlow> flows = flows(next);
        assertEquals(2, flows.size());
        assertEquals(1, flows.stream().filter(JndiSearchReturnFlow::proved).count());
        assertEquals(1, flows.stream().filter(flow ->
                flow.reason() == JndiSearchReturnFlow.Reason.SEARCH_CONSUMER_IDENTITY_MISMATCH)
                .count());
    }

    @Test
    void inheritedEnumerationContractCanUseTheSameIdentityAfterCast() {
        Fixture fixture = fixture(enumerationSupertypeBytes());
        Node search = fixture.call(JndiLookupCallSite.DIR_CONTEXT_OWNER,
                JndiLookupCallSite.SEARCH_NAME, SEARCH_DESCRIPTOR);
        Node hasMoreElements = fixture.call(
                JndiNamingEnumerationCallSite.JAVA_ENUMERATION_OWNER,
                JndiNamingEnumerationCallSite.HAS_MORE_ELEMENTS_NAME,
                JndiNamingEnumerationCallSite.BOOLEAN_DESCRIPTOR);
        Node nextElement = fixture.call(JndiNamingEnumerationCallSite.JAVA_ENUMERATION_OWNER,
                JndiNamingEnumerationCallSite.NEXT_ELEMENT_NAME,
                JndiNamingEnumerationCallSite.ELEMENT_DESCRIPTOR);

        JndiNamingEnumerationCallSite consumer = consumerFact(nextElement);
        assertEquals(JndiNamingEnumerationCallSite.JAVA_ENUMERATION_DESCRIPTOR,
                consumer.receiver().slot().descriptor());
        assertEquals(JndiSearchReturnFlow.Relation.DECLARED_CONTRACT,
                flows(nextElement).get(0).relation());
        assertEquals(JndiSearchReturnFlow.Status.PROVED, flows(nextElement).get(0).status());
        assertEquals(JndiSearchReturnFlow.Relation.DECLARED_CONTRACT,
                flows(hasMoreElements).get(0).relation());
        assertEquals(JndiSearchReturnFlow.Status.PROVED, flows(hasMoreElements).get(0).status());
        assertEquals(searchFact(search).returnValue().orElseThrow().value().identity(),
                consumer.receiver().value().identity());
    }

    @Test
    void wrongEnumerationOwnerAndDescriptorDoNotEnterTheContract() {
        Fixture fixture = fixture(wrongConsumerBytes());
        for (Node call : fixture.graph().callsOfMethod(fixture.hostKey())) {
            if ("next".equals(call.name()) || "nextElement".equals(call.name())) {
                assertNull(call.note(JndiNamingEnumerationCallSite.GRAPH_NOTE_KEY));
                assertNull(call.note(JndiSearchReturnFlow.GRAPH_NOTE_KEY));
            }
        }
    }

    @Test
    void incompleteControlFlowKeepsSearchAndConsumerPropagationPartial() {
        Fixture fixture = fixture(branchBytes());
        Node search = fixture.call(JndiLookupCallSite.DIR_CONTEXT_OWNER,
                JndiLookupCallSite.SEARCH_NAME, SEARCH_DESCRIPTOR);
        Node next = fixture.call(JndiNamingEnumerationCallSite.NAMING_ENUMERATION_OWNER,
                JndiNamingEnumerationCallSite.NEXT_NAME,
                JndiNamingEnumerationCallSite.ELEMENT_DESCRIPTOR);

        assertNotNull(searchFact(search));
        JndiNamingEnumerationCallSite consumer = consumerFact(next);
        assertEquals(-1, consumer.receiver().value().producerOffset());
        List<JndiSearchReturnFlow> flows = flows(next);
        assertEquals(1, flows.size());
        assertEquals(JndiSearchReturnFlow.Status.PARTIAL, flows.get(0).status());
        assertEquals(JndiSearchReturnFlow.Reason.VALUE_FLOW_INCOMPLETE,
                flows.get(0).reason());
    }

    private static JndiLookupCallSite searchFact(Node node) {
        JndiLookupCallSite fact = (JndiLookupCallSite) node.note(
                JndiLookupCallSite.GRAPH_NOTE_KEY);
        assertNotNull(fact);
        return fact;
    }

    private static JndiNamingEnumerationCallSite consumerFact(Node node) {
        JndiNamingEnumerationCallSite fact = (JndiNamingEnumerationCallSite) node.note(
                JndiNamingEnumerationCallSite.GRAPH_NOTE_KEY);
        assertNotNull(fact);
        return fact;
    }

    @SuppressWarnings("unchecked")
    private static List<JndiSearchReturnFlow> flows(Node node) {
        Object note = node.note(JndiSearchReturnFlow.GRAPH_NOTE_KEY);
        assertNotNull(note);
        return (List<JndiSearchReturnFlow>) note;
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

    private static byte[] searchAndConsumersBytes() {
        ClassWriter writer = hostWriter("fixture/JndiSearchReturnHost");
        MethodVisitor method = flowMethod(writer);
        emitSearch(method);
        method.visitVarInsn(Opcodes.ASTORE, 0);
        method.visitVarInsn(Opcodes.ALOAD, 0);
        method.visitMethodInsn(Opcodes.INVOKEINTERFACE,
                JndiNamingEnumerationCallSite.NAMING_ENUMERATION_OWNER,
                JndiNamingEnumerationCallSite.HAS_MORE_NAME,
                JndiNamingEnumerationCallSite.BOOLEAN_DESCRIPTOR, true);
        method.visitInsn(Opcodes.POP);
        method.visitVarInsn(Opcodes.ALOAD, 0);
        method.visitMethodInsn(Opcodes.INVOKEINTERFACE,
                JndiNamingEnumerationCallSite.NAMING_ENUMERATION_OWNER,
                JndiNamingEnumerationCallSite.NEXT_NAME,
                JndiNamingEnumerationCallSite.ELEMENT_DESCRIPTOR, true);
        method.visitInsn(Opcodes.POP);
        method.visitInsn(Opcodes.RETURN);
        finish(method, 4, 1);
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] twoSearchesBytes() {
        ClassWriter writer = hostWriter("fixture/JndiSearchIdentityHost");
        MethodVisitor method = flowMethod(writer);
        emitSearch(method);
        method.visitVarInsn(Opcodes.ASTORE, 0);
        emitSearch(method);
        method.visitVarInsn(Opcodes.ASTORE, 1);
        method.visitVarInsn(Opcodes.ALOAD, 1);
        method.visitMethodInsn(Opcodes.INVOKEINTERFACE,
                JndiNamingEnumerationCallSite.NAMING_ENUMERATION_OWNER,
                JndiNamingEnumerationCallSite.NEXT_NAME,
                JndiNamingEnumerationCallSite.ELEMENT_DESCRIPTOR, true);
        method.visitInsn(Opcodes.POP);
        method.visitInsn(Opcodes.RETURN);
        finish(method, 4, 2);
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] enumerationSupertypeBytes() {
        ClassWriter writer = hostWriter("fixture/JndiEnumerationSupertypeHost");
        MethodVisitor method = flowMethod(writer);
        emitSearch(method);
        method.visitVarInsn(Opcodes.ASTORE, 0);
        method.visitVarInsn(Opcodes.ALOAD, 0);
        method.visitTypeInsn(Opcodes.CHECKCAST,
                JndiNamingEnumerationCallSite.JAVA_ENUMERATION_OWNER);
        method.visitMethodInsn(Opcodes.INVOKEINTERFACE,
                JndiNamingEnumerationCallSite.JAVA_ENUMERATION_OWNER,
                JndiNamingEnumerationCallSite.HAS_MORE_ELEMENTS_NAME,
                JndiNamingEnumerationCallSite.BOOLEAN_DESCRIPTOR, true);
        method.visitInsn(Opcodes.POP);
        method.visitVarInsn(Opcodes.ALOAD, 0);
        method.visitTypeInsn(Opcodes.CHECKCAST,
                JndiNamingEnumerationCallSite.JAVA_ENUMERATION_OWNER);
        method.visitMethodInsn(Opcodes.INVOKEINTERFACE,
                JndiNamingEnumerationCallSite.JAVA_ENUMERATION_OWNER,
                JndiNamingEnumerationCallSite.NEXT_ELEMENT_NAME,
                JndiNamingEnumerationCallSite.ELEMENT_DESCRIPTOR, true);
        method.visitInsn(Opcodes.POP);
        method.visitInsn(Opcodes.RETURN);
        finish(method, 4, 1);
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] wrongConsumerBytes() {
        ClassWriter writer = hostWriter("fixture/JndiWrongEnumerationHost");
        MethodVisitor method = flowMethod(writer);
        method.visitInsn(Opcodes.ACONST_NULL);
        method.visitMethodInsn(Opcodes.INVOKEINTERFACE, "fixture/OtherEnumeration", "next",
                JndiNamingEnumerationCallSite.ELEMENT_DESCRIPTOR, true);
        method.visitInsn(Opcodes.POP);
        method.visitInsn(Opcodes.ACONST_NULL);
        method.visitMethodInsn(Opcodes.INVOKEINTERFACE, "java/util/Iterator", "next",
                JndiNamingEnumerationCallSite.ELEMENT_DESCRIPTOR, true);
        method.visitInsn(Opcodes.POP);
        method.visitInsn(Opcodes.ACONST_NULL);
        method.visitMethodInsn(Opcodes.INVOKEINTERFACE,
                JndiNamingEnumerationCallSite.NAMING_ENUMERATION_OWNER,
                JndiNamingEnumerationCallSite.NEXT_NAME, "()Ljava/lang/String;", true);
        method.visitInsn(Opcodes.POP);
        method.visitInsn(Opcodes.RETURN);
        finish(method, 2, 0);
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] branchBytes() {
        ClassWriter writer = hostWriter("fixture/JndiSearchBranchHost");
        MethodVisitor method = flowMethod(writer);
        Label done = new Label();
        method.visitInsn(Opcodes.ICONST_0);
        method.visitJumpInsn(Opcodes.IFEQ, done);
        emitSearch(method);
        method.visitVarInsn(Opcodes.ASTORE, 0);
        method.visitVarInsn(Opcodes.ALOAD, 0);
        method.visitMethodInsn(Opcodes.INVOKEINTERFACE,
                JndiNamingEnumerationCallSite.NAMING_ENUMERATION_OWNER,
                JndiNamingEnumerationCallSite.NEXT_NAME,
                JndiNamingEnumerationCallSite.ELEMENT_DESCRIPTOR, true);
        method.visitInsn(Opcodes.POP);
        method.visitLabel(done);
        method.visitInsn(Opcodes.RETURN);
        finish(method, 4, 1);
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static void emitSearch(MethodVisitor method) {
        method.visitInsn(Opcodes.ACONST_NULL);
        method.visitLdcInsn("");
        method.visitInsn(Opcodes.ACONST_NULL);
        method.visitMethodInsn(Opcodes.INVOKEINTERFACE, JndiLookupCallSite.DIR_CONTEXT_OWNER,
                JndiLookupCallSite.SEARCH_NAME, SEARCH_DESCRIPTOR, true);
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
            return calls(owner, name, descriptor).stream().findFirst().orElseThrow();
        }

        private List<Node> calls(String owner, String name, String descriptor) {
            return graph.callsOfMethod(hostKey).stream()
                    .filter(node -> owner.equals(node.owner()) && name.equals(node.name())
                            && descriptor.equals(node.descriptor()))
                    .toList();
        }
    }
}
