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
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.jar.JarFile;

/** Java 8-compatible sink-entry canary agent used when the target JDK is older than 17. */
public final class LegacySinkCanaryAgent {

    private static final String GATE = "io/just/sast/verify/boot/SinkCanaryGate";
    private static final String MARKER = "io/just/sast/verify/boot/SinkReachedError";
    private static final AtomicInteger TRANSFORMED_CLASSES = new AtomicInteger();
    private static final AtomicInteger INJECTED_GATES = new AtomicInteger();
    private static final Set<String> TRANSFORMED_NAMES =
            java.util.Collections.synchronizedSet(new LinkedHashSet<String>());
    private static final int MAX_DIAGNOSTIC_NAMES = 12;

    private LegacySinkCanaryAgent() {
    }

    /** Bounded diagnostic for a positive entry return that did not hit the requested sink. */
    static String instrumentationSummary() {
        StringBuilder names = new StringBuilder();
        int count = 0;
        synchronized (TRANSFORMED_NAMES) {
            for (String name : TRANSFORMED_NAMES) {
                if (count++ > 0) {
                    names.append(',');
                }
                names.append(name);
            }
        }
        return "classes=" + TRANSFORMED_CLASSES.get() + ",gates=" + INJECTED_GATES.get()
                + (names.length() == 0 ? "" : ",targets=" + names);
    }

    public static void premain(String args, Instrumentation inst) {
        if (args == null) {
            return;
        }
        // Keep the legacy first four fields, then carry the launcher-owned attempt binding.
        String[] parts = args.split("\\|", -1);
        // Production verifier arguments are always bootJar|entry|sink|token. The previous
        // length==3 compatibility branch treated a four-part request as if the bootstrap
        // path were the entry spec, so every Java 8--16 child silently skipped agent setup
        // and the probe reported CANARY_AGENT_NOT_READY after an otherwise valid sandbox
        // handshake. Keep the parser strict for the authenticated protocol; old manual
        // launches without a token cannot produce dynamic evidence and must fail closed.
        if (parts.length < 4) {
            return;
        }
        String bootJar = parts[0];
        String entrySpec = parts[1];
        String sinkSpec = parts[2];
        String token = parts[3];
        if (token.length() == 0) {
            return;
        }
        int entryHash = entrySpec.indexOf('#');
        if (entryHash <= 0) {
            return;
        }
        Map<String, Set<String>> sinks = parseSinks(sinkSpec);
        if (sinks.isEmpty()) {
            return;
        }
        appendCanaryToBootstrap(inst, bootJar);
        boolean gateReady = false;
        try {
            // The transformed JDK class resolves the gate from the bootstrap loader. Calling
            // the class through the system loader would configure a different copy and lose
            // the canary signal across the loader boundary.
            Class<?> gate = Class.forName(
                    "io.just.sast.verify.boot.SinkCanaryGate", true, null);
            gate.getDeclaredMethod("setEntry", String.class, String.class, String.class)
                    .invoke(null, entrySpec.substring(0, entryHash),
                            entrySpec.substring(entryHash + 1), token);
            if (parts.length < 9) {
                return;
            }
            gate.getDeclaredMethod("setProtocolBinding", String.class, String.class,
                            String.class, String.class, String.class)
                    .invoke(null, parts[4], parts[5], parts[6], parts[7], parts[8]);
            gateReady = Boolean.TRUE.equals(gate.getDeclaredMethod("configured").invoke(null));
        } catch (Throwable ignored) {
            // A missing gate must not turn a canary into an unbounded execution path.
            return;
        }
        if (!gateReady) {
            return;
        }
        try {
            inst.addTransformer(new CanaryTransformer(sinks, token), true);
        } catch (Throwable ignored) {
            return;
        }
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
        try {
            System.setProperty("just.verify.canary-token", token);
        } catch (SecurityException ignored) {
            // The child reports an untestable result when the readiness attestation is absent.
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
        private final String token;

        CanaryTransformer(Map<String, Set<String>> sinks) {
            this(sinks, "");
        }

        CanaryTransformer(Map<String, Set<String>> sinks, String token) {
            this.sinks = sinks;
            this.token = token == null ? "" : token;
        }

        @Override
        public byte[] transform(ClassLoader loader, String className, Class<?> beingDefined,
                                ProtectionDomain protectionDomain, byte[] bytes) {
            if (className == null || bytes == null || token.length() == 0) {
                return null;
            }
            Set<String> entryMethods = sinks.get(className);
            final boolean[] changed = new boolean[]{false};
            final int[] injections = new int[]{0};
            try {
                ClassReader reader = new ClassReader(bytes);
                ClassWriter writer = new ClassWriter(reader, ClassWriter.COMPUTE_MAXS);
                reader.accept(new ClassVisitor(Opcodes.ASM9, writer) {
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
                        return new MethodVisitor(Opcodes.ASM9, visitor) {
                            @Override
                            public void visitCode() {
                                super.visitCode();
                                if (injectable) {
                                    visitLdcInsn(className + "#" + name + "#" + desc);
                                    visitLdcInsn(token);
                                    visitMethodInsn(Opcodes.INVOKESTATIC, GATE, "hit",
                                            "(Ljava/lang/String;Ljava/lang/String;)V", false);
                                    changed[0] = true;
                                    injections[0]++;
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
                                    visitLdcInsn(token);
                                    visitMethodInsn(Opcodes.INVOKESTATIC, GATE, "hit",
                                            "(Ljava/lang/String;Ljava/lang/String;)V", false);
                                    changed[0] = true;
                                    injections[0]++;
                                }
                                super.visitMethodInsn(opcode, owner, calledName, calledDesc,
                                        isInterface);
                            }
                        };
                    }
                }, 0);
                if (changed[0]) {
                    TRANSFORMED_CLASSES.incrementAndGet();
                    synchronized (TRANSFORMED_NAMES) {
                        if (TRANSFORMED_NAMES.size() < MAX_DIAGNOSTIC_NAMES) {
                            TRANSFORMED_NAMES.add(className);
                        }
                    }
                    INJECTED_GATES.addAndGet(injections[0]);
                }
                return changed[0] || entryMethods != null ? writer.toByteArray() : null;
            } catch (Throwable ignored) {
                return null;
            }
        }
    }
}
