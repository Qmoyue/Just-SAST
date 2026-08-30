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
 * 在链 sink 方法入口注入带本次子进程 token 的 {@code SinkCanaryGate.hit(..., token)}——
 * 门卫按调用栈判定：存在链入口帧才抛 {@code SinkReachedError}（见 SinkCanaryGate）。
 * 判定从"异常栈帧被动检测"升级为"主动命中检测"；Error 语义穿透 gadget 的 catch(Exception)；
 * 命中的 sink 真实方法体不再执行，exec / defineClass / connect 类危险副作用被天然解除。
 * 子 JVM 的 exec/网络/文件/线程限制由 SandboxSecurityManager 负责；代理只改写明确的 sink
 * 方法，不对目标工件做全量方法级重写，避免改变类加载/初始化语义并降低验证开销。
 *
 * premain 参数格式：{@code <bootstrapJarPath>|<入口点分类名>#<入口方法>|<spec1>,<spec2>…}
 * spec = 内部类名#方法名[#描述符]；没有描述符时兼容旧的按方法名匹配。
 * bootstrapJar 仅含 boot 包两个类——插桩 java.base 类（如 Method.invoke）时其引用
 * 必须对 bootstrap 可见，经 appendToBootstrapClassLoaderSearch 挂载。
 *
 * 核心类（java.lang.reflect.Method 等）先于 premain 加载，需 retransformClasses 补插桩；
 * 无法插桩时不产生 sink-boundary 确认，探针仍由权限门阻断并报告为不可验证/部分结果。
 */
public final class SinkCanaryAgent {

    static final String GATE_INTERNAL = "io/just/sast/verify/boot/SinkCanaryGate";

    public static void premain(String args, Instrumentation inst) {
        if (args == null) {
            return;
        }
        String[] parts = args.split("\\|", 4);
        if (parts.length < 4 || parts[3].isEmpty()) {
            return;
        }
        String bootJar = parts[0];
        String token = parts[3];
        int h = parts[1].indexOf('#');
        Map<String, Set<String>> sinks = new HashMap<>();
        for (String spec : parts[2].split(",")) {
            int p = spec.indexOf('#');
            if (p > 0) {
                sinks.computeIfAbsent(spec.substring(0, p), k -> new HashSet<>())
                        .add(spec.substring(p + 1));
            }
        }
        try {
            inst.appendToBootstrapClassLoaderSearch(new java.util.jar.JarFile(bootJar));
        } catch (Exception ignored) {
            // bootstrap 挂载失败：仅 java.base 类 sink 不可插桩，其余照常
        }
        try {
            // The transformed java.base method resolves the gate through the bootstrap
            // loader. Configure that same class identity; using the agent/application loader
            // here creates a second gate whose latch is invisible to the transformed method.
            Class<?> gate = Class.forName(GATE_INTERNAL.replace('/', '.'), true, null);
            gate.getDeclaredMethod("setEntry", String.class, String.class, String.class)
                    .invoke(null, parts[1].substring(0, h), parts[1].substring(h + 1), token);
        } catch (Throwable ignored) {
            // canary 不可用时仍保留子 JVM 权限门；安全失败不能降级成任意执行。
        }
        inst.addTransformer(new CanaryTransformer(sinks, token), true);
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

    /**
     * Sink canary transformer.  Ordinary sinks are guarded at their method entry.  Native
     * sinks (notably Method.invoke and several Class/VM entry points) have no bytecode entry
     * to rewrite, so matching call sites are guarded immediately before the invocation.  The
     * latter is also safer for constructors: the canary throws before the target body or native
     * capability is entered.  The matcher remains descriptor-aware and is driven only by the
     * current chain's sink specification.
     */
    static final class CanaryTransformer implements ClassFileTransformer {

        private final Map<String, Set<String>> sinks;
        private final String token;

        /** Compatibility constructor for direct transformer tests and callers that only want canaries. */
        CanaryTransformer(Map<String, Set<String>> sinks) {
            this(sinks, "");
        }

        CanaryTransformer(Map<String, Set<String>> sinks, String token) {
            this.sinks = sinks;
            this.token = token == null ? "" : token;
        }

        @Override
        public byte[] transform(ClassLoader loader, String className, Class<?> beingDefined,
                                ProtectionDomain pd, byte[] bytes) {
            if (bytes == null || className == null || token.isEmpty()) {
                return null;
            }
            Set<String> entryMethods = sinks.get(className);
            boolean[] changed = {false};
            try {
                ClassReader cr = new ClassReader(bytes);
                ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_MAXS);
                cr.accept(new ClassVisitor(Opcodes.ASM9, cw) {
                    @Override
                    public MethodVisitor visitMethod(int access, String name, String desc,
                                                     String sig, String[] exceptions) {
                        MethodVisitor mv = super.visitMethod(access, name, desc, sig, exceptions);
                        boolean injectable = entryMethods != null
                                && (entryMethods.contains(name)
                                || entryMethods.contains(name + "#" + desc))
                                && (access & Opcodes.ACC_ABSTRACT) == 0
                                && (access & Opcodes.ACC_NATIVE) == 0;
                        if (!injectable && entryMethods == null && sinks.isEmpty()) {
                            return mv;
                        }
                        return new MethodVisitor(Opcodes.ASM9, mv) {
                            @Override
                            public void visitCode() {
                                super.visitCode();
                                if (injectable) {
                                    visitLdcInsn(className + "#" + name + "#" + desc);
                                    visitLdcInsn(token);
                                    visitMethodInsn(Opcodes.INVOKESTATIC, GATE_INTERNAL,
                                            "hit", "(Ljava/lang/String;Ljava/lang/String;)V", false);
                                    changed[0] = true;
                                }
                            }

                            @Override
                            public void visitMethodInsn(int opcode, String owner, String calledName,
                                                        String calledDesc, boolean isInterface) {
                                Set<String> callMethods = sinks.get(owner);
                                if (callMethods != null
                                        && (callMethods.contains(calledName)
                                        || callMethods.contains(calledName + "#" + calledDesc))) {
                                    visitLdcInsn(owner + "#" + calledName + "#" + calledDesc);
                                    visitLdcInsn(token);
                                    visitMethodInsn(Opcodes.INVOKESTATIC, GATE_INTERNAL,
                                            "hit", "(Ljava/lang/String;Ljava/lang/String;)V", false);
                                    changed[0] = true;
                                }
                                super.visitMethodInsn(opcode, owner, calledName, calledDesc,
                                        isInterface);
                            }
                        };
                    }
                }, 0);
                // Preserve the old direct-transformer contract for a sink class, even if the
                // selected overload is absent.  For all other classes avoid rewriting bytes
                // when no matching call site exists.
                return changed[0] || entryMethods != null ? cw.toByteArray() : null;
            } catch (Throwable t) {
                return null; // 插桩失败不阻断目标类加载
            }
        }

    }
}
