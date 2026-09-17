package io.just.sast.cpg.build;

import io.just.sast.cpg.graph.Graph;
import io.just.sast.cpg.graph.Node;
import io.just.sast.frontend.asm.FactsExtractor;
import io.just.sast.model.ClassInfo;
import io.just.sast.model.JndiReferenceFact;
import io.just.sast.model.LoadResult;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JndiReferenceBridgeContractTest {

    @Test
    void exactReferenceConstructorAndRefAddrKeepIdentityAndFieldValues() {
        ClassInfo info = extract(referenceWithAddressBytes());
        LoadResult load = new LoadResult(Map.of(info.internalName(), info), List.of(), 1, 61);
        Graph graph = new CpgBuilder().build(load).graph();
        String host = info.internalName() + "#build"
                + info.method("build", referenceMethodDescriptor()).descriptor();

        Node constructor = graph.callsOfMethod(host).stream()
                .filter(node -> JndiReferenceFact.REFERENCE_OWNER.equals(node.owner())
                        && "<init>".equals(node.name())
                        && JndiReferenceFact.REFERENCE_CONSTRUCTOR_FACTORY_DESCRIPTOR.equals(
                        node.descriptor()))
                .findFirst().orElseThrow();
        JndiReferenceFact fact = (JndiReferenceFact) constructor.note(
                JndiReferenceFact.GRAPH_NOTE_KEY);

        assertTrue(fact.identity().identity().contains("@" + host + ":"));
        assertEquals(constructor.id(), fact.identity().constructionCallId());
        assertEquals(constructor.offset(), fact.identity().constructionOffset());
        assertEquals("javax.sql.DataSource", fact.type().value());
        assertEquals(JndiReferenceFact.FieldValue.State.KNOWN, fact.type().state());
        assertEquals("org.vibur.dbcp.ViburDBCPObjectFactory", fact.factoryClass().value());
        assertEquals(JndiReferenceFact.FieldValue.State.NULL, fact.factoryLocation().state());
        assertEquals(2, fact.properties().size());

        JndiReferenceFact.RefAddrFact driver = fact.properties().get(0);
        assertEquals("driverClassName", driver.type().value());
        assertEquals(JndiReferenceFact.FieldValue.State.UNKNOWN, driver.content().state());
        assertEquals("javax/naming/StringRefAddr", driver.identity().owner());

        JndiReferenceFact.RefAddrFact url = fact.properties().get(1);
        assertEquals("url", url.type().value());
        assertEquals("http://example.invalid/provider", url.content().value());
        assertEquals(JndiReferenceFact.FieldValue.State.KNOWN, url.content().state());
        assertNotEquals(fact.identity().identity(), url.identity().identity());
        assertThrows(UnsupportedOperationException.class, () -> fact.properties().clear());
    }

    @Test
    void fullReferenceConstructorRetainsInitialAddressAndFactoryLocation() {
        ClassInfo info = extract(fullReferenceConstructorBytes());
        LoadResult load = new LoadResult(Map.of(info.internalName(), info), List.of(), 1, 61);
        Graph graph = new CpgBuilder().build(load).graph();
        String host = info.internalName() + "#build()Ljavax/naming/Reference;";
        Node constructor = graph.callsOfMethod(host).stream()
                .filter(node -> JndiReferenceFact.REFERENCE_OWNER.equals(node.owner())
                        && "<init>".equals(node.name())
                        && JndiReferenceFact.REFERENCE_CONSTRUCTOR_FULL_DESCRIPTOR.equals(
                        node.descriptor()))
                .findFirst().orElseThrow();
        JndiReferenceFact fact = (JndiReferenceFact) constructor.note(
                JndiReferenceFact.GRAPH_NOTE_KEY);

        assertEquals("test", fact.type().value());
        assertEquals("fixture.Factory", fact.factoryClass().value());
        assertEquals("https://example.invalid/factory", fact.factoryLocation().value());
        assertEquals(1, fact.properties().size());
        assertEquals("type", fact.properties().get(0).type().value());
        assertEquals("java.util.Map", fact.properties().get(0).content().value());
    }

    @Test
    void equalFieldValuesFromDifferentReferenceAllocationsDoNotMerge() {
        ClassInfo info = extract(twoReferenceAllocationsBytes());
        LoadResult load = new LoadResult(Map.of(info.internalName(), info), List.of(), 1, 61);
        Graph graph = new CpgBuilder().build(load).graph();
        String host = info.internalName() + "#build()Ljavax/naming/Reference;";
        List<Node> constructors = graph.callsOfMethod(host).stream()
                .filter(node -> JndiReferenceFact.REFERENCE_OWNER.equals(node.owner())
                        && "<init>".equals(node.name())
                        && JndiReferenceFact.REFERENCE_CONSTRUCTOR_ONE_DESCRIPTOR.equals(
                        node.descriptor()))
                .toList();

        assertEquals(2, constructors.size());
        JndiReferenceFact first = (JndiReferenceFact) constructors.get(0).note(
                JndiReferenceFact.GRAPH_NOTE_KEY);
        JndiReferenceFact second = (JndiReferenceFact) constructors.get(1).note(
                JndiReferenceFact.GRAPH_NOTE_KEY);
        assertEquals("same", first.type().value());
        assertEquals("same", second.type().value());
        assertNotEquals(first.identity().identity(), second.identity().identity());
        assertNotEquals(first.identity().allocationOffset(), second.identity().allocationOffset());
        assertEquals(JndiReferenceFact.FieldValue.State.ABSENT, first.factoryClass().state());
        assertEquals(JndiReferenceFact.FieldValue.State.ABSENT, first.factoryLocation().state());
    }

    @Test
    void unmodeledReferenceMutationDoesNotPublishStaleProperties() {
        ClassInfo info = extract(referenceClearBytes());
        LoadResult load = new LoadResult(Map.of(info.internalName(), info), List.of(), 1, 61);
        Graph graph = new CpgBuilder().build(load).graph();
        String host = info.internalName() + "#build()Ljavax/naming/Reference;";
        Node constructor = graph.callsOfMethod(host).stream()
                .filter(node -> JndiReferenceFact.REFERENCE_OWNER.equals(node.owner())
                        && "<init>".equals(node.name())
                        && JndiReferenceFact.REFERENCE_CONSTRUCTOR_ONE_DESCRIPTOR.equals(
                        node.descriptor()))
                .findFirst().orElseThrow();

        assertNull(constructor.note(JndiReferenceFact.GRAPH_NOTE_KEY));
    }

    private static String referenceMethodDescriptor() {
        return "(Ljava/util/Properties;)Ljavax/naming/Reference;";
    }

    private static ClassInfo extract(byte[] bytes) {
        org.objectweb.asm.tree.ClassNode node = new org.objectweb.asm.tree.ClassNode();
        new ClassReader(bytes).accept(node, 0);
        return new FactsExtractor().extract(node);
    }

    private static byte[] referenceWithAddressBytes() {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "fixture/ReferenceHost", null,
                "java/lang/Object", null);
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "build",
                referenceMethodDescriptor(), null, null);
        method.visitCode();
        method.visitTypeInsn(Opcodes.NEW, JndiReferenceFact.REFERENCE_OWNER);
        method.visitInsn(Opcodes.DUP);
        method.visitLdcInsn("javax.sql.DataSource");
        method.visitLdcInsn("org.vibur.dbcp.ViburDBCPObjectFactory");
        method.visitInsn(Opcodes.ACONST_NULL);
        method.visitMethodInsn(Opcodes.INVOKESPECIAL, JndiReferenceFact.REFERENCE_OWNER,
                "<init>", JndiReferenceFact.REFERENCE_CONSTRUCTOR_FACTORY_DESCRIPTOR, false);
        method.visitVarInsn(Opcodes.ASTORE, 1);

        method.visitVarInsn(Opcodes.ALOAD, 1);
        method.visitTypeInsn(Opcodes.NEW, JndiReferenceFact.STRING_REF_ADDR_OWNER);
        method.visitInsn(Opcodes.DUP);
        method.visitLdcInsn("driverClassName");
        method.visitVarInsn(Opcodes.ALOAD, 0);
        method.visitLdcInsn("driver");
        method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/util/Properties", "getProperty",
                "(Ljava/lang/String;)Ljava/lang/String;", false);
        method.visitMethodInsn(Opcodes.INVOKESPECIAL, JndiReferenceFact.STRING_REF_ADDR_OWNER,
                "<init>", JndiReferenceFact.STRING_REF_ADDR_CONSTRUCTOR_DESCRIPTOR, false);
        method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, JndiReferenceFact.REFERENCE_OWNER, "add",
                "(L" + JndiReferenceFact.REF_ADDR_OWNER + ";)V", false);

        method.visitVarInsn(Opcodes.ALOAD, 1);
        method.visitTypeInsn(Opcodes.NEW, JndiReferenceFact.STRING_REF_ADDR_OWNER);
        method.visitInsn(Opcodes.DUP);
        method.visitLdcInsn("url");
        method.visitLdcInsn("http://example.invalid/provider");
        method.visitMethodInsn(Opcodes.INVOKESPECIAL, JndiReferenceFact.STRING_REF_ADDR_OWNER,
                "<init>", JndiReferenceFact.STRING_REF_ADDR_CONSTRUCTOR_DESCRIPTOR, false);
        method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, JndiReferenceFact.REFERENCE_OWNER, "add",
                "(L" + JndiReferenceFact.REF_ADDR_OWNER + ";)V", false);

        method.visitVarInsn(Opcodes.ALOAD, 1);
        method.visitInsn(Opcodes.ARETURN);
        method.visitMaxs(6, 2);
        method.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] twoReferenceAllocationsBytes() {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "fixture/TwoReferenceHost", null,
                "java/lang/Object", null);
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "build",
                "()Ljavax/naming/Reference;", null, null);
        method.visitCode();
        method.visitTypeInsn(Opcodes.NEW, JndiReferenceFact.REFERENCE_OWNER);
        method.visitInsn(Opcodes.DUP);
        method.visitLdcInsn("same");
        method.visitMethodInsn(Opcodes.INVOKESPECIAL, JndiReferenceFact.REFERENCE_OWNER,
                "<init>", JndiReferenceFact.REFERENCE_CONSTRUCTOR_ONE_DESCRIPTOR, false);
        method.visitVarInsn(Opcodes.ASTORE, 0);

        method.visitTypeInsn(Opcodes.NEW, JndiReferenceFact.REFERENCE_OWNER);
        method.visitInsn(Opcodes.DUP);
        method.visitLdcInsn("same");
        method.visitMethodInsn(Opcodes.INVOKESPECIAL, JndiReferenceFact.REFERENCE_OWNER,
                "<init>", JndiReferenceFact.REFERENCE_CONSTRUCTOR_ONE_DESCRIPTOR, false);
        method.visitVarInsn(Opcodes.ASTORE, 1);
        method.visitVarInsn(Opcodes.ALOAD, 1);
        method.visitInsn(Opcodes.ARETURN);
        method.visitMaxs(2, 2);
        method.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] fullReferenceConstructorBytes() {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "fixture/FullReferenceHost", null,
                "java/lang/Object", null);
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "build",
                "()Ljavax/naming/Reference;", null, null);
        method.visitCode();
        method.visitTypeInsn(Opcodes.NEW, JndiReferenceFact.REFERENCE_OWNER);
        method.visitInsn(Opcodes.DUP);
        method.visitLdcInsn("test");
        method.visitTypeInsn(Opcodes.NEW, JndiReferenceFact.STRING_REF_ADDR_OWNER);
        method.visitInsn(Opcodes.DUP);
        method.visitLdcInsn("type");
        method.visitLdcInsn("java.util.Map");
        method.visitMethodInsn(Opcodes.INVOKESPECIAL, JndiReferenceFact.STRING_REF_ADDR_OWNER,
                "<init>", JndiReferenceFact.STRING_REF_ADDR_CONSTRUCTOR_DESCRIPTOR, false);
        method.visitLdcInsn("fixture.Factory");
        method.visitLdcInsn("https://example.invalid/factory");
        method.visitMethodInsn(Opcodes.INVOKESPECIAL, JndiReferenceFact.REFERENCE_OWNER,
                "<init>", JndiReferenceFact.REFERENCE_CONSTRUCTOR_FULL_DESCRIPTOR, false);
        method.visitInsn(Opcodes.ARETURN);
        method.visitMaxs(6, 0);
        method.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] referenceClearBytes() {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "fixture/ClearedReferenceHost", null,
                "java/lang/Object", null);
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "build",
                "()Ljavax/naming/Reference;", null, null);
        method.visitCode();
        method.visitTypeInsn(Opcodes.NEW, JndiReferenceFact.REFERENCE_OWNER);
        method.visitInsn(Opcodes.DUP);
        method.visitLdcInsn("test");
        method.visitMethodInsn(Opcodes.INVOKESPECIAL, JndiReferenceFact.REFERENCE_OWNER,
                "<init>", JndiReferenceFact.REFERENCE_CONSTRUCTOR_ONE_DESCRIPTOR, false);
        method.visitVarInsn(Opcodes.ASTORE, 0);
        method.visitVarInsn(Opcodes.ALOAD, 0);
        method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, JndiReferenceFact.REFERENCE_OWNER,
                "clear", JndiReferenceFact.REFERENCE_CLEAR_DESCRIPTOR, false);
        method.visitVarInsn(Opcodes.ALOAD, 0);
        method.visitInsn(Opcodes.ARETURN);
        method.visitMaxs(2, 1);
        method.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }
}
