package io.just.sast.frontend.asm;

import io.just.sast.model.ClassInfo;
import io.just.sast.model.MethodInfo;
import io.just.sast.model.Op;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LineNumberNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TryCatchBlockNode;

import java.lang.reflect.Modifier;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 字节码事实抽取契约：偏移/异常表/调试信息；label 引用缺失即失败（不静默生成假边）。 */
class FactsExtractorTest {

    private static ClassNode classNodeWith(MethodNode method) {
        ClassNode node = new ClassNode();
        node.name = "T";
        node.superName = "java/lang/Object";
        node.methods.add(method);
        return node;
    }

    @Test
    void lineNumbersNotCountedAsOffsetsButMarkDebugInfo() {
        MethodNode m = new MethodNode(0, "run", "()V", null, null);
        LabelNode l1 = new LabelNode();
        m.instructions.add(l1);
        m.instructions.add(new LineNumberNode(5, l1));
        m.instructions.add(new org.objectweb.asm.tree.InsnNode(Op.RETURN.code()));
        ClassInfo info = new FactsExtractor().extract(classNodeWith(m));
        MethodInfo method = info.methods().get(0);
        assertEquals(1, method.instructions().size(), "LINE 不计入指令偏移");
        assertTrue(method.hasDebugInfo(), "含 LineNumberNode 的方法应标记 hasDebugInfo");
        assertEquals(Op.RETURN, method.instructions().get(0).op());
    }

    @Test
    void methodWithoutDebugInfoIsNotMarked() {
        MethodNode m = new MethodNode(0, "run", "()V", null, null);
        m.instructions.add(new org.objectweb.asm.tree.InsnNode(Op.RETURN.code()));
        MethodInfo method = new FactsExtractor().extract(classNodeWith(m)).methods().get(0);
        assertFalse(method.hasDebugInfo());
    }

    @Test
    void tryCatchLabelsResolveToOffsets() {
        MethodNode m = new MethodNode(0, "run", "()V", null, null);
        LabelNode start = new LabelNode();
        LabelNode end = new LabelNode();
        LabelNode handler = new LabelNode();
        m.instructions.add(start);
        m.instructions.add(new org.objectweb.asm.tree.VarInsnNode(Op.ALOAD.code(), 0));
        m.instructions.add(new org.objectweb.asm.tree.VarInsnNode(Op.ASTORE.code(), 1));
        m.instructions.add(end);
        m.instructions.add(handler);
        m.instructions.add(new org.objectweb.asm.tree.InsnNode(Op.RETURN.code()));
        m.tryCatchBlocks.add(new TryCatchBlockNode(start, end, handler, "java/lang/Exception"));
        MethodInfo method = new FactsExtractor().extract(classNodeWith(m)).methods().get(0);
        // 非 LINE/FRAME 指令：aload(0), astore(1), return(2)——start=0, end=2, handler=2
        assertEquals(1, method.tryCatch().size());
        assertEquals(0, method.tryCatch().get(0).start());
        assertEquals(2, method.tryCatch().get(0).end());
        assertEquals(2, method.tryCatch().get(0).handler());
        assertEquals("java/lang/Exception", method.tryCatch().get(0).type());
    }

    @Test
    void missingLabelReferenceFailsLoudly() {
        MethodNode m = new MethodNode(0, "run", "()V", null, null);
        LabelNode registered = new LabelNode();
        LabelNode unregistered = new LabelNode();
        m.instructions.add(registered);
        m.instructions.add(new org.objectweb.asm.tree.VarInsnNode(Op.ALOAD.code(), 0));
        // 跳转目标 unregistered 从未注册（模拟异常指令序列）
        m.instructions.add(new org.objectweb.asm.tree.JumpInsnNode(Op.IFNULL.code(), unregistered));
        assertThrows(Exception.class, () -> new FactsExtractor().extract(classNodeWith(m)),
                "label 缺失应解析失败计入诊断，绝不静默指向 offset 0");
    }

    @Test
    void accessFlagsPreserved() {
        MethodNode m = new MethodNode(Modifier.PRIVATE | Modifier.STATIC, "secret", "()V", null, null);
        m.instructions.add(new org.objectweb.asm.tree.InsnNode(Op.RETURN.code()));
        MethodInfo method = new FactsExtractor().extract(classNodeWith(m)).methods().get(0);
        assertTrue(Modifier.isPrivate(method.access()));
        assertTrue(method.isStatic());
        assertEquals(List.of(), method.tryCatch());
    }
}
