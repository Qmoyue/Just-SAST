package io.just.sast.verify;

import io.just.sast.verify.boot.SinkCanaryGate;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * sink canary 契约：插桩在 sink 入口注入门卫调用；门卫仅在调用栈存在链入口帧时抛标记。
 * 回归背景：无条件抛出会击杀探针 JVM——Constructor#newInstance / URL#openConnection 被
 * lambda metafactory 与启动器自身调用，插桩即崩；且 gadget 的 catch(Exception) 会吞掉
 * Exception 语义的标记，故标记必须为 Error。
 */
class SinkCanaryAgentTest {

    /** 用 ASM 生成一个极小测试类：public static 目标方法体为空返回。 */
    private byte[] simpleClass(String internalName, String methodName) {
        ClassWriter cw = new ClassWriter(0);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, internalName, null,
                "java/lang/Object", null);
        var mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, methodName,
                "()V", null, null);
        mv.visitCode();
        mv.visitInsn(Opcodes.RETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }

    /** 用 ASM 生成一个真实的 invokevirtual sink 调用点，覆盖应用类加载期插桩。 */
    private byte[] callSiteClass(String internalName) {
        ClassWriter cw = new ClassWriter(0);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, internalName, null,
                "java/lang/Object", null);
        var mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "caller",
                "()V", null, null);
        mv.visitCode();
        mv.visitTypeInsn(Opcodes.NEW, "javax/naming/InitialContext");
        mv.visitInsn(Opcodes.DUP);
        mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "javax/naming/InitialContext", "<init>",
                "()V", false);
        mv.visitLdcInsn("CHAIN_OK");
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "javax/naming/InitialContext", "lookup",
                "(Ljava/lang/String;)Ljava/lang/Object;", false);
        mv.visitInsn(Opcodes.POP);
        mv.visitInsn(Opcodes.RETURN);
        mv.visitMaxs(2, 0);
        mv.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }

    /** 统计字节码中对 SinkCanaryGate.hit 的调用次数。 */
    private int gateCallCount(byte[] bytes) {
        AtomicBoolean found = new AtomicBoolean(false);
        new ClassReader(bytes).accept(new ClassVisitor(Opcodes.ASM9) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String desc,
                                             String sig, String[] exceptions) {
                return new MethodVisitor(Opcodes.ASM9) {
                    @Override
                    public void visitMethodInsn(int opcode, String owner, String name2,
                                                String desc2, boolean itf) {
                        if ("io/just/sast/verify/boot/SinkCanaryGate".equals(owner)
                                && "hit".equals(name2)) {
                            found.set(true);
                        }
                    }
                };
            }
        }, 0);
        return found.get() ? 1 : 0;
    }

    @Test
    void transformerInjectsGateCallIntoNamedMethodOnly() throws Exception {
        var transformer = new SinkCanaryAgent.CanaryTransformer(
                Map.of("t/Sink", Set.of("exec")), "test-token");
        byte[] injected = transformer.transform(null, "t/Sink", null, null,
                simpleClass("t/Sink", "exec"));

        assertNotNull(injected, "命中 sink 类必须返回插桩字节码");
        assertEquals(1, gateCallCount(injected), "exec 方法入口应有门卫调用");
        // 插桩后字节码合法可读（COMPUTE_MAXS 重算有效）
        new ClassReader(injected).accept(new ClassVisitor(Opcodes.ASM9) {
        }, 0);
    }

    @Test
    void transformerIgnoresNonSinkClassesAndMethods() throws Exception {
        var transformer = new SinkCanaryAgent.CanaryTransformer(
                Map.of("t/Sink", Set.of("exec")), "test-token");
        // 类名未命中 → null（不插桩，目标类原样加载）
        assertNull(transformer.transform(null, "other/Clean", null, null,
                simpleClass("other/Clean", "exec")));
        // 类命中但方法未命中 → 重写但不得注入门卫
        byte[] rewritten = transformer.transform(null, "t/Sink", null, null,
                simpleClass("t/Sink", "clean"));
        assertNotNull(rewritten);
        assertEquals(0, gateCallCount(rewritten), "非 sink 方法不得注入门卫调用");
    }

    @Test
    void transformerInjectsGateAtApplicationCallSite() {
        var transformer = new SinkCanaryAgent.CanaryTransformer(
                Map.of("javax/naming/InitialContext",
                        Set.of("lookup#(Ljava/lang/String;)Ljava/lang/Object;")), "test-token");
        byte[] injected = transformer.transform(null, "t/Caller", null, null,
                callSiteClass("t/Caller"));

        assertNotNull(injected, "应用类中的 sink 调用点应被插桩");
        assertEquals(1, gateCallCount(injected), "InitialContext.lookup 调用点应有门卫调用");
    }

    @Test
    void gateThrowsMarkerOnlyWhenEntryFrameOnStack() {
        String selfClass = SinkCanaryAgentTest.class.getName();
        // 入口注册为本测试方法自身——hit() 的真实调用栈上必然存在该帧
        SinkCanaryGate.setEntry(selfClass, "gateThrowsMarkerOnlyWhenEntryFrameOnStack", "test-token");
        var err = assertThrows(io.just.sast.verify.boot.SinkReachedError.class,
                () -> SinkCanaryGate.hit("java/lang/reflect/Method#invoke", "test-token"));
        assertEquals("java/lang/reflect/Method#invoke", err.getMessage());
        // Wrong/missing token is diagnostic-only and cannot manufacture a positive result.
        SinkCanaryGate.hit("java/lang/reflect/Method#invoke", "wrong-token");
    }

    @Test
    void markerIsErrorSoGadgetCatchExceptionCannotSwallow() {
        // gadget 常见形态：catch (Exception e) { e.printStackTrace(); }
        try {
            throw new io.just.sast.verify.boot.SinkReachedError("t/Sink#exec");
        } catch (Exception e) {
            throw new AssertionError("SinkReachedError 不得是 Exception——会被 gadget 吞掉");
        } catch (io.just.sast.verify.boot.SinkReachedError err) {
            assertEquals("t/Sink#exec", err.getMessage());
        }
    }

    @Test
    void probeVerdictHelpersJudgeMarkerCorrectly() {
        io.just.sast.verify.boot.SinkReachedError marker =
                new io.just.sast.verify.boot.SinkReachedError("java/lang/reflect/Method#invoke");
        // 包装一层 InvocationTargetException（反射调用场景）——cause 链也要能识别
        var wrapped = new java.lang.reflect.InvocationTargetException(marker);

        assertEquals("java/lang/reflect/Method#invoke", ChainVerifyProbe.markerSpec(marker));
        assertEquals("java/lang/reflect/Method#invoke", ChainVerifyProbe.markerSpec(wrapped));
        assertNull(ChainVerifyProbe.markerSpec(new RuntimeException("plain")));

        assertTrue(ChainVerifyProbe.sameSink("java/lang/reflect/Method#invoke",
                "java.lang.reflect.Method", "invoke"));
        assertFalse(ChainVerifyProbe.sameSink("java/lang/Runtime#exec",
                "java.lang.reflect.Method", "invoke"));

        // 入口帧在场判定
        var withEntry = new Exception();
        withEntry.setStackTrace(new StackTraceElement[]{
                new StackTraceElement("java.lang.reflect.Method", "invoke", "M.java", 1),
                new StackTraceElement("com.example.Dog", "hashCode", "D.java", 48)});
        assertTrue(ChainVerifyProbe.entryReached(withEntry, "com.example.Dog", "hashCode"));
        assertFalse(ChainVerifyProbe.entryReached(withEntry, "com.example.Other", "hashCode"));
    }
}
