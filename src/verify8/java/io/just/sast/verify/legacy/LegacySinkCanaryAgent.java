package io.just.sast.verify.legacy;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.io.File;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.net.URISyntaxException;
import java.security.ProtectionDomain;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarFile;

/** Java 8-compatible sink-entry canary agent used when the target JDK is older than 17. */
public final class LegacySinkCanaryAgent {

    private static final String GATE = "io/just/sast/verify/legacy/LegacySinkCanaryGate";
    private static final String MARKER = "io/just/sast/verify/legacy/LegacySinkReachedError";

    private LegacySinkCanaryAgent() {
    }

    public static void premain(String args, Instrumentation inst) {
        if (args == null) {
            return;
        }
        String[] parts = args.split("\\|", 3);
        if (parts.length < 2) {
            return;
        }
        String bootJar = parts.length == 3 ? parts[0] : null;
        String entrySpec = parts.length == 3 ? parts[1] : parts[0];
        String sinkSpec = parts.length == 3 ? parts[2] : parts[1];
        int entryHash = entrySpec.indexOf('#');
        if (entryHash <= 0) {
            return;
        }
        Map<String, Set<String>> sinks = parseSinks(sinkSpec);
        if (sinks.isEmpty()) {
            return;
        }
        appendCanaryToBootstrap(inst, bootJar);
        try {
            // The transformed JDK class resolves the gate from the bootstrap loader. Calling
            // the class through the system loader would configure a different copy and lose
            // the canary signal across the loader boundary.
            Class<?> gate = Class.forName(
                    "io.just.sast.verify.legacy.LegacySinkCanaryGate", true, null);
            gate.getDeclaredMethod("setEntry", String.class, String.class)
                    .invoke(null, entrySpec.substring(0, entryHash),
                            entrySpec.substring(entryHash + 1));
        } catch (Throwable ignored) {
            // A missing gate must not turn a canary into an unbounded execution path.
            return;
        }
        inst.addTransformer(new CanaryTransformer(sinks), true);
        for (String name : sinks.keySet()) {
            try {
                Class<?> type = Class.forName(name.replace('/', '.'), false,
                        LegacySinkCanaryAgent.class.getClassLoader());
                if (inst.isModifiableClass(type)) {
                    inst.retransformClasses(type);
                }
            } catch (Throwable ignored) {
                // Load-time transformation remains available for classes not yet loaded.
            }
        }
    }

    private static Map<String, Set<String>> parseSinks(String encoded) {
        Map<String, Set<String>> result = new HashMap<String, Set<String>>();
        String[] specs = encoded.split(",");
        for (String spec : specs) {
            int hash = spec.indexOf('#');
            if (hash <= 0) {
                continue;
            }
            Set<String> methods = result.get(spec.substring(0, hash));
            if (methods == null) {
                methods = new HashSet<String>();
                result.put(spec.substring(0, hash), methods);
            }
            methods.add(spec.substring(hash + 1));
        }
        return result;
    }

    private static void appendCanaryToBootstrap(Instrumentation inst, String bootJar) {
        try {
            File file;
            if (bootJar != null && bootJar.length() > 0) {
                file = new File(bootJar);
            } else {
                // Compatibility for manually launched old agents. Production verifier calls
                // with a minimal canary jar; never prefer the full agent jar in that path.
                file = new File(LegacySinkCanaryAgent.class.getProtectionDomain()
                        .getCodeSource().getLocation().toURI());
            }
            inst.appendToBootstrapClassLoaderSearch(new JarFile(file));
        } catch (Exception ignored) {
            // If bootstrap visibility fails, transformed application sinks can still be useful;
            // java.base sinks will fail closed in the parent verifier when no marker appears.
        }
    }

    static final class CanaryTransformer implements ClassFileTransformer {

        private final Map<String, Set<String>> sinks;

        CanaryTransformer(Map<String, Set<String>> sinks) {
            this.sinks = sinks;
        }

        @Override
        public byte[] transform(ClassLoader loader, String className, Class<?> beingDefined,
                                ProtectionDomain protectionDomain, byte[] bytes) {
            if (className == null || bytes == null) {
                return null;
            }
            Set<String> entryMethods = sinks.get(className);
            final boolean[] changed = new boolean[]{false};
            try {
                ClassReader reader = new ClassReader(bytes);
                ClassWriter writer = new ClassWriter(reader, ClassWriter.COMPUTE_MAXS);
                reader.accept(new ClassVisitor(Opcodes.ASM7, writer) {
                    @Override
                    public MethodVisitor visitMethod(int access, String name, String desc,
                                                     String signature, String[] exceptions) {
                        MethodVisitor visitor = super.visitMethod(access, name, desc,
                                signature, exceptions);
                        boolean injectable = entryMethods != null
                                && (entryMethods.contains(name)
                                || entryMethods.contains(name + "#" + desc))
                                && (access & Opcodes.ACC_ABSTRACT) == 0
                                && (access & Opcodes.ACC_NATIVE) == 0;
                        if (!injectable && entryMethods == null && sinks.isEmpty()) {
                            return visitor;
                        }
                        return new MethodVisitor(Opcodes.ASM7, visitor) {
                            @Override
                            public void visitCode() {
                                super.visitCode();
                                if (injectable) {
                                    visitLdcInsn(className + "#" + name + "#" + desc);
                                    visitMethodInsn(Opcodes.INVOKESTATIC, GATE, "hit",
                                            "(Ljava/lang/String;)V", false);
                                    changed[0] = true;
                                }
                            }

                            @Override
                            public void visitMethodInsn(int opcode, String owner,
                                                        String calledName, String calledDesc,
                                                        boolean isInterface) {
                                Set<String> callMethods = sinks.get(owner);
                                if (callMethods != null
                                        && (callMethods.contains(calledName)
                                        || callMethods.contains(calledName + "#" + calledDesc))) {
                                    visitLdcInsn(owner + "#" + calledName + "#" + calledDesc);
                                    visitMethodInsn(Opcodes.INVOKESTATIC, GATE, "hit",
                                            "(Ljava/lang/String;)V", false);
                                    changed[0] = true;
                                }
                                super.visitMethodInsn(opcode, owner, calledName, calledDesc,
                                        isInterface);
                            }
                        };
                    }
                }, 0);
                return changed[0] || entryMethods != null ? writer.toByteArray() : null;
            } catch (Throwable ignored) {
                return null;
            }
        }
    }
}
