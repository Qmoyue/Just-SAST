package io.just.sast.verify;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * sink canary 插桩代理（与扫描器同一 shaded jar，经 -javaagent 自挂载）：
 * 在链 sink 方法入口注入 {@code SinkCanaryGate.hit("内部类名#方法名")}——
 * 门卫按调用栈判定：存在链入口帧才抛 {@code SinkReachedError}（见 SinkCanaryGate）。
 * 判定从"异常栈帧被动检测"升级为"主动命中检测"；Error 语义穿透 gadget 的 catch(Exception)；
 * 命中的 sink 真实方法体不再执行，exec / defineClass / connect 类危险副作用被天然解除。
 *
 * premain 参数格式：{@code <bootstrapJarPath>|<入口点分类名>#<入口方法>|<spec1>,<spec2>…}
 * spec = 内部类名#方法名。
 * bootstrapJar 仅含 boot 包两个类——插桩 java.base 类（如 Method.invoke）时其引用
 * 必须对 bootstrap 可见，经 appendToBootstrapClassLoaderSearch 挂载。
 *
 * 核心类（java.lang.reflect.Method 等）先于 premain 加载，需 retransformClasses 补插桩；
 * JVM 不支持时该 sink 退化为原有的异常栈帧被动判定。
 */
public final class SinkCanaryAgent {

    static final String GATE_INTERNAL = "io/just/sast/verify/boot/SinkCanaryGate";

    public static void premain(String args, Instrumentation inst) {
        if (args == null) {
            return;
        }
        String[] parts = args.split("\\|", 3);
        if (parts.length < 3) {
            return;
        }
        String bootJar = parts[0];
        int h = parts[1].indexOf('#');
        Map<String, Set<String>> sinks = new HashMap<>();
        for (String spec : parts[2].split(",")) {
            int p = spec.indexOf('#');
            if (p > 0) {
                sinks.computeIfAbsent(spec.substring(0, p), k -> new HashSet<>())
                        .add(spec.substring(p + 1));
            }
        }
        if (sinks.isEmpty()) {
            return;
        }
        try {
            inst.appendToBootstrapClassLoaderSearch(new java.util.jar.JarFile(bootJar));
        } catch (Exception ignored) {
            // bootstrap 挂载失败：仅 java.base 类 sink 不可插桩，其余照常
        }
        try {
            Class<?> gate = Class.forName(GATE_INTERNAL.replace('/', '.'), true,
                    SinkCanaryAgent.class.getClassLoader());
            gate.getDeclaredMethod("setEntry", String.class, String.class)
                    .invoke(null, parts[1].substring(0, h), parts[1].substring(h + 1));
        } catch (Throwable ignored) {
            return; // 门卫不可用：插桩无判定依据，直接放弃
        }
        inst.addTransformer(new CanaryTransformer(sinks), true);
        for (String name : sinks.keySet()) {
            try {
                Class<?> c = Class.forName(name.replace('/', '.'), false,
                        SinkCanaryAgent.class.getClassLoader());
                if (inst.isModifiableClass(c)) {
                    inst.retransformClasses(c);
                }
            } catch (Throwable ignored) {
                // 重转换不支持/类不存在：该 sink 退化为被动判定
            }
        }
    }

    /** sink 插桩变换器：命中类名 → 所有同名方法入口注入门卫调用。 */
    static final class CanaryTransformer implements ClassFileTransformer {

        private final Map<String, Set<String>> sinks;

        CanaryTransformer(Map<String, Set<String>> sinks) {
            this.sinks = sinks;
        }

        @Override
        public byte[] transform(ClassLoader loader, String className, Class<?> beingDefined,
                                ProtectionDomain pd, byte[] bytes) {
            Set<String> methods = className == null ? null : sinks.get(className);
            if (methods == null || bytes == null) {
                return null;
            }
            try {
                ClassReader cr = new ClassReader(bytes);
                ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_MAXS);
                cr.accept(new ClassVisitor(Opcodes.ASM9, cw) {
                    @Override
                    public MethodVisitor visitMethod(int access, String name, String desc,
                                                     String sig, String[] exceptions) {
                        MethodVisitor mv = super.visitMethod(access, name, desc, sig, exceptions);
                        boolean injectable = methods.contains(name)
                                && (access & Opcodes.ACC_ABSTRACT) == 0
                                && (access & Opcodes.ACC_NATIVE) == 0;
                        if (!injectable) {
                            return mv;
                        }
                        return new MethodVisitor(Opcodes.ASM9, mv) {
                            @Override
                            public void visitCode() {
                                super.visitCode();
                                visitLdcInsn(className + "#" + name);
                                visitMethodInsn(Opcodes.INVOKESTATIC, GATE_INTERNAL,
                                        "hit", "(Ljava/lang/String;)V", false);
                            }
                        };
                    }
                }, 0);
                return cw.toByteArray();
            } catch (Throwable t) {
                return null; // 插桩失败不阻断目标类加载
            }
        }
    }
}
