package io.just.sast.cpg.build;

import io.just.sast.cpg.graph.Graph;
import io.just.sast.frontend.asm.FactsExtractor;
import io.just.sast.model.ClassInfo;
import io.just.sast.model.LoadResult;
import io.just.sast.model.MethodInfo;
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
import static org.junit.jupiter.api.Assertions.assertTrue;

class StaticValueFlowContractTest {

    @Test
    void arbitraryOwnersUsePhysicalSlotsAndDoNotJoinEqualDisplayText() {
        Fixture fixture = fixture(equalTextBytes());
        StaticValueFlow.Result result = StaticValueFlow.analyze(fixture.graph(), fixture.method());

        assertTrue(result.complete());
        assertEquals(2, result.invocations().size());
        StaticValueFlow.Invocation producer = result.invocations().get(0);
        StaticValueFlow.Invocation consumer = result.invocations().get(1);
        assertEquals("fixture/vendor/Producer", producer.owner());
        assertEquals("fixture/vendor/Consumer", consumer.owner());
        assertEquals("(Ljava/lang/String;)Ljava/lang/String;", producer.descriptor());
        assertEquals("(Ljava/lang/String;)V", consumer.descriptor());
        assertEquals(1, producer.arguments().size());
        assertEquals(1, consumer.arguments().size());
        assertEquals(StaticValueFlow.ValueState.KNOWN, producer.arguments().get(0).state());
        assertEquals(StaticValueFlow.ValueState.KNOWN, consumer.arguments().get(0).state());
        assertEquals("same", producer.arguments().get(0).displayValue());
        assertEquals("same", consumer.arguments().get(0).displayValue());
        assertNotEquals(producer.arguments().get(0).identity(),
                consumer.arguments().get(0).identity());
    }

    @Test
    void localAliasRetainsOneIdentityAcrossProducerAndConsumer() {
        Fixture fixture = fixture(aliasBytes());
        StaticValueFlow.Result result = StaticValueFlow.analyze(fixture.graph(), fixture.method());

        assertTrue(result.complete());
        assertEquals(2, result.invocations().size());
        StaticValueFlow.Value produced = result.invocations().get(0).result();
        StaticValueFlow.Value consumed = result.invocations().get(1).arguments().get(0);
        assertTrue(produced != null);
        assertEquals(StaticValueFlow.ValueState.UNKNOWN, produced.state());
        assertEquals(produced.identity(), consumed.identity());
        assertEquals(produced.descriptor(), consumed.descriptor());
    }

    @Test
    void controlFlowDoesNotBecomeAChimericValueFlow() {
        Fixture fixture = fixture(branchBytes());
        StaticValueFlow.Result result = StaticValueFlow.analyze(fixture.graph(), fixture.method());

        assertFalse(result.complete());
        assertTrue(result.invocations().isEmpty());
    }

    private static Fixture fixture(byte[] bytes) {
        ClassInfo info = extract(bytes);
        LoadResult load = new LoadResult(Map.of(info.internalName(), info), List.of(), 1, 61);
        Graph graph = new CpgBuilder().build(load).graph();
        MethodInfo method = info.methods().stream()
                .filter(candidate -> "wire".equals(candidate.name())
                        && "()V".equals(candidate.descriptor()))
                .findFirst().orElseThrow();
        return new Fixture(graph, method);
    }

    private static ClassInfo extract(byte[] bytes) {
        org.objectweb.asm.tree.ClassNode node = new org.objectweb.asm.tree.ClassNode();
        new ClassReader(bytes).accept(node, 0);
        return new FactsExtractor().extract(node);
    }

    private static byte[] equalTextBytes() {
        ClassWriter writer = hostWriter("fixture/GenericFlowTextHost");
        MethodVisitor method = wireMethod(writer);
        method.visitLdcInsn("same");
        method.visitMethodInsn(Opcodes.INVOKESTATIC, "fixture/vendor/Producer", "read",
                "(Ljava/lang/String;)Ljava/lang/String;", false);
        method.visitInsn(Opcodes.POP);
        method.visitLdcInsn("same");
        method.visitMethodInsn(Opcodes.INVOKESTATIC, "fixture/vendor/Consumer", "accept",
                "(Ljava/lang/String;)V", false);
        method.visitInsn(Opcodes.RETURN);
        finish(method, 1, 0);
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] aliasBytes() {
        ClassWriter writer = hostWriter("fixture/GenericFlowAliasHost");
        MethodVisitor method = wireMethod(writer);
        method.visitLdcInsn("alias");
        method.visitVarInsn(Opcodes.ASTORE, 0);
        method.visitVarInsn(Opcodes.ALOAD, 0);
        method.visitMethodInsn(Opcodes.INVOKESTATIC, "fixture/vendor/Producer", "read",
                "(Ljava/lang/String;)Ljava/lang/String;", false);
        method.visitVarInsn(Opcodes.ASTORE, 1);
        method.visitVarInsn(Opcodes.ALOAD, 1);
        method.visitMethodInsn(Opcodes.INVOKESTATIC, "fixture/vendor/Consumer", "accept",
                "(Ljava/lang/String;)V", false);
        method.visitInsn(Opcodes.RETURN);
        finish(method, 1, 2);
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] branchBytes() {
        ClassWriter writer = hostWriter("fixture/GenericFlowBranchHost");
        MethodVisitor method = wireMethod(writer);
        Label alternate = new Label();
        Label join = new Label();
        method.visitInsn(Opcodes.ACONST_NULL);
        method.visitJumpInsn(Opcodes.IFNULL, alternate);
        method.visitLdcInsn("one");
        method.visitJumpInsn(Opcodes.GOTO, join);
        method.visitLabel(alternate);
        method.visitLdcInsn("two");
        method.visitLabel(join);
        method.visitMethodInsn(Opcodes.INVOKESTATIC, "fixture/vendor/Consumer", "accept",
                "(Ljava/lang/String;)V", false);
        method.visitInsn(Opcodes.RETURN);
        finish(method, 1, 0);
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static ClassWriter hostWriter(String name) {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, name, null, "java/lang/Object", null);
        return writer;
    }

    private static MethodVisitor wireMethod(ClassWriter writer) {
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "wire", "()V", null, null);
        method.visitCode();
        return method;
    }

    private static void finish(MethodVisitor method, int maxStack, int maxLocals) {
        method.visitMaxs(maxStack, maxLocals);
        method.visitEnd();
    }

    private record Fixture(Graph graph, MethodInfo method) {
    }
}
