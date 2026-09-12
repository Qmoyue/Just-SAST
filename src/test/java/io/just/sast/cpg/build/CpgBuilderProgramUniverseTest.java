package io.just.sast.cpg.build;

import io.just.sast.cpg.graph.Graph;
import io.just.sast.frontend.asm.FactsExtractor;
import io.just.sast.model.ClassInfo;
import io.just.sast.model.LoadResult;
import io.just.sast.model.MethodInfo;
import io.just.sast.model.Op;
import io.just.sast.model.ProgramUniverse;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CpgBuilderProgramUniverseTest {

    @Test
    void typedUniverseBuildMatchesLoadResultCompatibilityPath() {
        MethodNode node = new MethodNode(Opcodes.ACC_PUBLIC, "run", "()V", null, null);
        node.instructions.add(new InsnNode(Opcodes.RETURN));
        ClassNode classNode = new ClassNode();
        classNode.name = "fixture/Entry";
        classNode.superName = "java/lang/Object";
        classNode.methods.add(node);
        MethodInfo method = new FactsExtractor().extract(classNode).methods().get(0);
        ClassInfo info = new ClassInfo(classNode.name, classNode.superName, List.of(), classNode.access,
                List.of(method), List.of());
        LoadResult load = new LoadResult(Map.of(info.internalName(), info), List.of(), 1, 61);
        CpgBuilder builder = new CpgBuilder();

        BuiltCpg legacy = builder.build(load);
        BuiltCpg typed = builder.build(ProgramUniverse.from(load));
        assertEquals(legacy.graph().nodeCount(), typed.graph().nodeCount());
        assertEquals(legacy.graph().edgeCount(), typed.graph().edgeCount());
        assertEquals(legacy.index().methodCount(), typed.index().methodCount());
        assertEquals(legacy.fieldWriters().fieldCount(), typed.fieldWriters().fieldCount());
    }

    @Test
    void bindingCallRetainsOnlyNearbyClassLiteralHints() {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "fixture/app/Ingress", null,
                "java/lang/Object", null);
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC, "decode",
                "(Ljava/lang/String;)Ljava/lang/Object;", null, null);
        method.visitCode();
        method.visitVarInsn(Opcodes.ALOAD, 1);
        method.visitLdcInsn(Type.getObjectType("fixture/model/User"));
        method.visitMethodInsn(Opcodes.INVOKESTATIC, "fixture/Mapper", "readValue",
                "(Ljava/lang/String;Ljava/lang/Class;)Ljava/lang/Object;", false);
        method.visitInsn(Opcodes.ARETURN);
        method.visitMaxs(2, 2);
        method.visitEnd();
        writer.visitEnd();

        ClassNode node = new ClassNode();
        new org.objectweb.asm.ClassReader(writer.toByteArray()).accept(node, 0);
        ClassInfo info = new FactsExtractor().extract(node);
        LoadResult load = new LoadResult(Map.of(info.internalName(), info), List.of(), 1, 61);

        Graph graph = new CpgBuilder().build(load).graph();
        var call = graph.callsOfMethod("fixture/app/Ingress#decode(Ljava/lang/String;)Ljava/lang/Object;")
                .stream().findFirst().orElseThrow();
        assertEquals(List.of("fixture/model/User"), call.note("classLiteralHints"));
        assertTrue(call.notes().containsKey("classLiteralHints"));
    }

    @Test
    void configurationCallRetainsOnlyNearbyStringHints() {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "fixture/app/Config", null,
                "java/lang/Object", null);
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC, "configure",
                "()V", null, null);
        method.visitCode();
        method.visitLdcInsn("fixture.app.");
        method.visitMethodInsn(Opcodes.INVOKEVIRTUAL,
                "com/alibaba/fastjson/parser/ParserConfig", "addAccept",
                "(Ljava/lang/String;)V", false);
        method.visitInsn(Opcodes.RETURN);
        method.visitMaxs(2, 1);
        method.visitEnd();
        writer.visitEnd();

        ClassNode node = new ClassNode();
        new org.objectweb.asm.ClassReader(writer.toByteArray()).accept(node, 0);
        ClassInfo info = new FactsExtractor().extract(node);
        LoadResult load = new LoadResult(Map.of(info.internalName(), info), List.of(), 1, 61);

        Graph graph = new CpgBuilder().build(load).graph();
        var call = graph.callsOfMethod("fixture/app/Config#configure()V")
                .stream().findFirst().orElseThrow();
        assertEquals(List.of("fixture.app."), call.note("stringLiteralHints"));
        assertTrue(call.notes().containsKey("stringLiteralHints"));
    }
}
