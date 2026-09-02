package io.just.sast.verify.legacy;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.AdviceAdapter;

import java.io.File;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.jar.JarFile;

/** Java 8-compatible sink agent used when the target JDK is older than 17. */
public final class LegacySinkCanaryAgent {

    private static final String GATE = "io/just/sast/verify/boot/SinkCanaryGate";
    private static final String EXEC = "io/just/sast/verify/boot/SinkExecutionGate";
    private static final String REAL_MODE = "REAL_SANITIZED";
    private static final AtomicInteger TRANSFORMED_CLASSES = new AtomicInteger();
    private static final AtomicInteger INJECTED_GATES = new AtomicInteger();

    private LegacySinkCanaryAgent() { }

    static String instrumentationSummary() {
        return "classes=" + TRANSFORMED_CLASSES.get() + ",gates=" + INJECTED_GATES.get();
    }

    public static void premain(String args, Instrumentation inst) {
        if (args == null) return;
        String[] parts = args.split("\\|", -1);
        if (parts.length < 9 || parts[3].length() == 0) return;
        String entrySpec = parts[1];
        int entryHash = entrySpec.indexOf('#');
        if (entryHash <= 0 || entryHash == entrySpec.length() - 1) return;
        Map<String, Set<String>> sinks = parseSinks(parts[2]);
        if (sinks.isEmpty()) return;
        String token = parts[3];
        appendCanaryToBootstrap(inst, parts[0]);
        if (!configureCanary(parts, entryHash, token)) return;
        boolean real = parts.length > 9 && REAL_MODE.equals(parts[9]);
        String realKind = parts.length > 10 ? parts[10] : "";
        Map<String, Set<String>> nativeIndex = parseNativeIndex(parts.length > 13 ? parts[13] : "");
        String executionToken = real ? newExecutionToken() : token;
        if (real && !configureExecution(parts, entryHash, executionToken)) return;
        String entryClass = entrySpec.substring(0, entryHash);
        String entryTail = entrySpec.substring(entryHash + 1);
        int descriptorHash = entryTail.indexOf('#');
        String entryMethod = descriptorHash < 0 ? entryTail : entryTail.substring(0, descriptorHash);
        String entryDescriptor = descriptorHash < 0 ? "" : entryTail.substring(descriptorHash + 1);
        try {
            inst.addTransformer(new CanaryTransformer(sinks, real ? executionToken : token,
                    real, realKind,
                    entryClass, entryMethod, entryDescriptor, nativeIndex), true);
        } catch (Throwable ignored) {
            return;
        }
        for (String name : sinks.keySet()) {
            // REAL_SANITIZED observes the target call site. Do not retransform the JDK sink
            // implementation itself: its private plumbing is part of the API under test and
            // would otherwise be mistaken for a nested target effect.
            if (real && platformClass(name)) continue;
            try {
                Class<?> type = Class.forName(name.replace('/', '.'), false,
                        LegacySinkCanaryAgent.class.getClassLoader());
                if (inst.isModifiableClass(type)) inst.retransformClasses(type);
            } catch (Throwable ignored) {
                // Load-time transformation handles classes not loaded during premain.
            }
        }
        try {
            System.setProperty("just.verify.canary-token", token);
        } catch (SecurityException ignored) {
            // The probe reports missing readiness rather than accepting an unarmed agent.
        }
    }

    private static String newExecutionToken() {
        return java.util.UUID.randomUUID().toString().replace("-", "")
                + java.util.UUID.randomUUID().toString().replace("-", "");
    }

    private static boolean configureCanary(String[] parts, int entryHash, String token) {
        try {
            String entryTail = parts[1].substring(entryHash + 1);
            int descriptorHash = entryTail.indexOf('#');
            Class<?> gate = Class.forName("io.just.sast.verify.boot.SinkCanaryGate", true, null);
            gate.getDeclaredMethod("setEntry", String.class, String.class, String.class)
                    .invoke(null, parts[1].substring(0, entryHash),
                            descriptorHash < 0 ? entryTail : entryTail.substring(0, descriptorHash), token);
            gate.getDeclaredMethod("setProtocolBinding", String.class, String.class,
                            String.class, String.class, String.class)
                    .invoke(null, parts[4], parts[5], parts[6], parts[7], parts[8]);
            return Boolean.TRUE.equals(gate.getDeclaredMethod("configured").invoke(null));
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static boolean platformClass(String value) {
        return value != null && (value.startsWith("java/") || value.startsWith("javax/")
                || value.startsWith("jdk/") || value.startsWith("sun/")
                || value.startsWith("com/sun/"));
    }

    private static boolean configureExecution(String[] parts, int entryHash, String token) {
        try {
            String entryTail = parts[1].substring(entryHash + 1);
            int descriptorHash = entryTail.indexOf('#');
            String entryMethod = descriptorHash < 0 ? entryTail : entryTail.substring(0, descriptorHash);
            String scratch = parts.length > 11 ? parts[11]
                    : System.getProperty("just.verify.safe-scratch", "");
            String nativeRoot = parts.length > 12 ? parts[12] : "";
            String safeJava = System.getProperty("just.verify.safe-java", "");
            Class<?> gate = Class.forName(EXEC.replace('/', '.'), true, null);
            gate.getDeclaredMethod("setExecution", String.class, String.class, String.class,
                            String.class, String.class, String.class, String.class, String.class)
                    .invoke(null, REAL_MODE, parts[1].substring(0, entryHash),
                            entryMethod, parts[2], token, scratch, nativeRoot, safeJava);
            return Boolean.TRUE.equals(gate.getDeclaredMethod("configured").invoke(null));
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static Map<String, Set<String>> parseSinks(String encoded) {
        Map<String, Set<String>> result = new HashMap<String, Set<String>>();
        if (encoded == null) return result;
        String[] values = encoded.split(",", -1);
        for (String spec : values) {
            int hash = spec.indexOf('#');
            if (hash <= 0 || hash == spec.length() - 1) continue;
            Set<String> methods = result.get(spec.substring(0, hash));
            if (methods == null) {
                methods = new HashSet<String>();
                result.put(spec.substring(0, hash), methods);
            }
            methods.add(spec.substring(hash + 1));
        }
        return result;
    }

    private static Map<String, Set<String>> parseNativeIndex(String encoded) {
        Map<String, Set<String>> result = new HashMap<String, Set<String>>();
        if (encoded == null || encoded.length() == 0 || encoded.length() > 64 * 1024) {
            return result;
        }
        for (String spec : encoded.split(",", -1)) {
            int first = spec.indexOf('#');
            int second = first < 0 ? -1 : spec.indexOf('#', first + 1);
            if (first <= 0 || second <= first + 1 || second == spec.length() - 1
                    || !spec.substring(0, first).matches("[A-Za-z0-9_$\\/]+")) continue;
            Set<String> methods = result.get(spec.substring(0, first));
            if (methods == null) {
                methods = new HashSet<String>();
                result.put(spec.substring(0, first), methods);
            }
            methods.add(spec.substring(first + 1));
            if (result.size() > 256) break;
        }
        return result;
    }

    private static void appendCanaryToBootstrap(Instrumentation inst, String bootJar) {
        try {
            inst.appendToBootstrapClassLoaderSearch(new JarFile(new File(bootJar)));
        } catch (Exception ignored) {
            // Probe-side identity/readiness checks fail closed if bootstrap visibility is lost.
        }
    }

    static final class CanaryTransformer implements ClassFileTransformer {
        private final Map<String, Set<String>> sinks;
        private final String token;
        private final boolean real;
        private final String realKind;
        private final String entryClass;
        private final String entryMethod;
        private final String entryDescriptor;
        private final Map<String, Set<String>> nativeMethodIndex;

        CanaryTransformer(Map<String, Set<String>> sinks) { this(sinks, "", false, ""); }
        CanaryTransformer(Map<String, Set<String>> sinks, String token) {
            this(sinks, token, false, "");
        }
        CanaryTransformer(Map<String, Set<String>> sinks, String token,
                          boolean real, String realKind) {
            this(sinks, token, real, realKind, "", "");
        }
        CanaryTransformer(Map<String, Set<String>> sinks, String token,
                          boolean real, String realKind,
                          String entryClass, String entryMethod) {
            this(sinks, token, real, realKind, entryClass, entryMethod, "");
        }

        CanaryTransformer(Map<String, Set<String>> sinks, String token,
                          boolean real, String realKind,
                          String entryClass, String entryMethod, String entryDescriptor) {
            this(sinks, token, real, realKind, entryClass, entryMethod, entryDescriptor,
                    Collections.<String, Set<String>>emptyMap());
        }

        CanaryTransformer(Map<String, Set<String>> sinks, String token,
                          boolean real, String realKind,
                          String entryClass, String entryMethod, String entryDescriptor,
                          Map<String, Set<String>> nativeIndex) {
            this.sinks = sinks;
            this.token = token == null ? "" : token;
            this.real = real;
            this.realKind = realKind == null ? "" : realKind;
            this.entryClass = internalName(entryClass);
            this.entryMethod = entryMethod == null ? "" : entryMethod;
            this.entryDescriptor = entryDescriptor == null ? "" : entryDescriptor;
            this.nativeMethodIndex = new java.util.concurrent.ConcurrentHashMap<String, Set<String>>();
            if (nativeIndex != null) {
                for (Map.Entry<String, Set<String>> entry : nativeIndex.entrySet()) {
                    if (entry.getKey() != null && entry.getValue() != null
                            && !entry.getValue().isEmpty()) {
                        Set<String> methods = java.util.concurrent.ConcurrentHashMap.newKeySet();
                        methods.addAll(entry.getValue());
                        this.nativeMethodIndex.put(entry.getKey(), methods);
                    }
                }
            }
        }

        @Override
        public byte[] transform(ClassLoader loader, String className, Class<?> beingDefined,
                                ProtectionDomain protectionDomain, byte[] bytes) {
            if (className == null || bytes == null || token.length() == 0) return null;
            if (real && !className.equals(entryClass) && !sinks.containsKey(className)
                    && (loader == null || className.startsWith("io/just/sast/"))) {
                return null;
            }
            Set<String> entryMethods = sinks.get(className);
            return real ? realTransform(className, bytes, entryMethods)
                    : boundaryTransform(className, bytes, entryMethods);
        }

        private byte[] boundaryTransform(final String className, byte[] bytes,
                                         final Set<String> entryMethods) {
            final boolean[] changed = new boolean[]{false};
            try {
                ClassReader reader = new ClassReader(bytes);
                ClassWriter writer = new ClassWriter(reader, ClassWriter.COMPUTE_MAXS);
                reader.accept(new ClassVisitor(Opcodes.ASM9, writer) {
                    @Override
                    public MethodVisitor visitMethod(int access, String name, String desc,
                                                      String sig, String[] exceptions) {
                        MethodVisitor visitor = super.visitMethod(access, name, desc, sig, exceptions);
                        final boolean injectable = entryMethods != null && matches(entryMethods, name, desc)
                                && (access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) == 0;
                        return new MethodVisitor(Opcodes.ASM9, visitor) {
                            @Override public void visitCode() {
                                super.visitCode();
                                if (injectable) { emitCanary(this, className + "#" + name + "#" + desc); changed[0] = true; }
                            }
                            @Override public void visitMethodInsn(int opcode, String owner, String calledName,
                                                                  String calledDesc, boolean isInterface) {
                                Set<String> calls = sinks.get(owner);
                                if (calls != null && matches(calls, calledName, calledDesc)) {
                                    emitCanary(this, owner + "#" + calledName + "#" + calledDesc);
                                    changed[0] = true;
                                }
                                super.visitMethodInsn(opcode, owner, calledName, calledDesc, isInterface);
                            }
                        };
                    }
                }, 0);
                return changed[0] || entryMethods != null ? writer.toByteArray() : null;
            } catch (Throwable ignored) { return null; }
        }

        private byte[] realTransform(final String className, byte[] bytes,
                                     final Set<String> entryMethods) {
            final boolean[] changed = new boolean[]{false};
            try {
                ClassReader reader = new ClassReader(bytes);
                ClassWriter writer = new ClassWriter(reader, ClassWriter.COMPUTE_FRAMES);
                reader.accept(new ClassVisitor(Opcodes.ASM9, writer) {
                    @Override
                    public MethodVisitor visitMethod(int access, String name, String desc,
                                                      String signature, String[] exceptions) {
                        MethodVisitor visitor = super.visitMethod(access, name, desc,
                                signature, exceptions);
                        if ((access & Opcodes.ACC_NATIVE) != 0) {
                            Set<String> methods = nativeMethodIndex.get(className);
                            if (methods == null) {
                                methods = java.util.concurrent.ConcurrentHashMap.newKeySet();
                                Set<String> existing = nativeMethodIndex.putIfAbsent(className, methods);
                                if (existing != null) methods = existing;
                            }
                            methods.add(name + "#" + desc);
                        }
                        boolean exact = entryMethods != null && matches(entryMethods, name, desc)
                                && (access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) == 0;
                        boolean entry = className.equals(CanaryTransformer.this.entryClass)
                                && CanaryTransformer.this.entryMethod.equals(name)
                                && (CanaryTransformer.this.entryDescriptor.length() == 0
                                || CanaryTransformer.this.entryDescriptor.equals(desc))
                                && (access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) == 0;
                        return new RealMethodVisitor(visitor, access, className, name, desc,
                                exact, entry, changed);
                    }
                }, ClassReader.EXPAND_FRAMES);
                return changed[0] ? writer.toByteArray() : null;
            } catch (Throwable ignored) { return null; }
        }

        private final class RealMethodVisitor extends AdviceAdapter {
            private final String className;
            private final String methodName;
            private final String methodDesc;
            private final boolean exact;
            private final boolean entry;
            private final boolean[] changed;

            RealMethodVisitor(MethodVisitor delegate, int access, String className,
                              String methodName, String methodDesc, boolean exact,
                              boolean entry, boolean[] changed) {
                super(Opcodes.ASM9, delegate, access, methodName, methodDesc);
                this.className = className; this.methodName = methodName; this.methodDesc = methodDesc;
                this.exact = exact; this.entry = entry;
                this.changed = changed;
            }

            @Override protected void onMethodEnter() {
                if (entry) { emitExecution("entryStart", null); changed[0] = true; }
                if (exact) {
                    emitExecution("enter", className + "#" + methodName + "#" + methodDesc);
                    sanitizeEntryArguments(); changed[0] = true;
                }
            }

            @Override protected void onMethodExit(int opcode) {
                if (exact && opcode != Opcodes.ATHROW) {
                    emitExecution("bodyExit", className + "#" + methodName + "#" + methodDesc);
                    changed[0] = true;
                }
                if (entry) { emitExecution("entryEnd", null); changed[0] = true; }
                super.onMethodExit(opcode);
            }

            @Override public void visitTypeInsn(int opcode, String type) {
                // Guard constructor capabilities before NEW; an uninitialized receiver may
                // not be kept on the operand stack for a static guard call.
                if (opcode == Opcodes.NEW && nestedConstructorType(type)
                        && !exactConstructorOwner(type)) {
                    emitExecution("blockNested", "NESTED");
                    changed[0] = true;
                }
                super.visitTypeInsn(opcode, type);
            }

            @Override public void visitMethodInsn(int opcode, String owner, String name,
                                                  String desc, boolean isInterface) {
                boolean exactCall = matches(sinks.get(owner), name, desc);
                // Only the selected sink may cross into a real API.  Any other dangerous
                // operation in the target body is a nested effect and is stopped before it
                // can execute target-controlled side effects.
                String kind = exactCall ? realKind : nestedKind(owner, name, desc);
                if (!exactCall && "NESTED_BLOCK".equals(kind)
                        && opcode == Opcodes.INVOKESPECIAL && "<init>".equals(name)) {
                    super.visitMethodInsn(opcode, owner, name, desc, isInterface);
                    return;
                }
                if (kind != null && kind.length() > 0) {
                    rewriteCall(opcode, owner, name, desc, isInterface, kind, exactCall);
                    changed[0] = true; return;
                }
                if (nativeMethod(owner, name, desc)) {
                    super.visitMethodInsn(opcode, owner, name, desc, isInterface);
                    emitExecution("nativeCall", owner + "#" + name + "#" + desc); changed[0] = true;
                    return;
                }
                super.visitMethodInsn(opcode, owner, name, desc, isInterface);
            }

            private void sanitizeEntryArguments() {
                if ("APPLICATION_BODY".equals(realKind)) {
                    Type[] args = Type.getArgumentTypes(methodDesc);
                    for (int i = 0; i < args.length; i++) sanitizeApplicationArgument(args[i], i);
                } else if ("RUNTIME_EXEC".equals(realKind)) {
                    Type[] args = Type.getArgumentTypes(methodDesc);
                    if (args.length > 0) { loadArg(0); emitSanitizer(args[0].getSort() == Type.ARRAY ? "safeCommandArray" : "safeCommand",
                            args[0].getSort() == Type.ARRAY ? "([Ljava/lang/String;Ljava/lang/String;)[Ljava/lang/String;" : "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;"); storeArg(0); }
                    for (int i = 1; i < args.length; i++) {
                        if (args[i].getSort() == Type.ARRAY && isString(args[i].getElementType())) { loadArg(i); emitSanitizer("safeEnvironment", "([Ljava/lang/String;Ljava/lang/String;)[Ljava/lang/String;"); storeArg(i); }
                        else if (isType(args[i], "java/io/File")) { loadArg(i); emitSanitizer("safeWorkingDirectory", "(Ljava/io/File;Ljava/lang/String;)Ljava/io/File;"); storeArg(i); }
                    }
                } else if ("PROCESS_BUILDER_START".equals(realKind)) {
                    loadThis(); emitSanitizer("safeProcessBuilder", "(Ljava/lang/ProcessBuilder;Ljava/lang/String;)Ljava/lang/ProcessBuilder;"); pop();
                }
            }

            private void rewriteCall(int opcode, String owner, String name, String desc,
                                     boolean isInterface, String kind, boolean exactCall) {
                Type[] args = Type.getArgumentTypes(desc);
                boolean constructor = opcode == Opcodes.INVOKESPECIAL && "<init>".equals(name);
                int[] locals = new int[args.length];
                for (int i = args.length - 1; i >= 0; i--) { locals[i] = newLocal(args[i]); storeLocal(locals[i]); }
                int receiver = -1;
                if (opcode != Opcodes.INVOKESTATIC && !constructor) { receiver = newLocal(Type.getObjectType(owner)); storeLocal(receiver); }
                sanitizeCallArguments(kind, name, args, locals);
                if ("NESTED_BLOCK".equals(kind)) emitExecution("blockNested", "NESTED");
                if (receiver >= 0) {
                    loadLocal(receiver); sanitizeReceiver(kind);
                    if ("URL_LOOPBACK".equals(kind) || "SOCKET_LOOPBACK".equals(kind)) { storeLocal(receiver); loadLocal(receiver); }
                }
                if (exactCall && !constructor) emitExecution("beforeCall", owner + "#" + name + "#" + desc);
                for (int i = 0; i < args.length; i++) loadLocal(locals[i]);
                super.visitMethodInsn(opcode, owner, name, desc, isInterface);
                if (exactCall) emitExecution("afterCall", owner + "#" + name + "#" + desc);
                if ("NATIVE_FIXTURE".equals(kind)) emitExecution("nativeLoadSucceeded", null);
            }

            private void sanitizeApplicationArgument(Type type, int index) {
                String helper;
                String descriptor;
                if (isString(type)) {
                    helper = "safeString";
                    descriptor = "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;";
                } else {
                    switch (type.getSort()) {
                        case Type.BOOLEAN: helper = "safeBoolean"; descriptor = "(ZLjava/lang/String;)Z"; break;
                        case Type.BYTE: helper = "safeByte"; descriptor = "(BLjava/lang/String;)B"; break;
                        case Type.SHORT: helper = "safeShort"; descriptor = "(SLjava/lang/String;)S"; break;
                        case Type.CHAR: helper = "safeChar"; descriptor = "(CLjava/lang/String;)C"; break;
                        case Type.INT: helper = "safeInt"; descriptor = "(ILjava/lang/String;)I"; break;
                        case Type.FLOAT: helper = "safeFloat"; descriptor = "(FLjava/lang/String;)F"; break;
                        case Type.LONG: helper = "safeLong"; descriptor = "(JLjava/lang/String;)J"; break;
                        case Type.DOUBLE: helper = "safeDouble"; descriptor = "(DLjava/lang/String;)D"; break;
                        default: throw new IllegalStateException("unsupported-application-argument");
                    }
                }
                loadArg(index); emitSanitizer(helper, descriptor); storeArg(index);
            }

            private void sanitizeCallArguments(String kind, String name, Type[] args, int[] locals) {
                if ("RUNTIME_EXEC".equals(kind) && args.length > 0) {
                    loadLocal(locals[0]); emitSanitizer(args[0].getSort() == Type.ARRAY ? "safeCommandArray" : "safeCommand",
                            args[0].getSort() == Type.ARRAY ? "([Ljava/lang/String;Ljava/lang/String;)[Ljava/lang/String;" : "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;"); storeLocal(locals[0]);
                } else if ("CLASS_FOR_NAME".equals(kind) && args.length > 0) {
                    loadLocal(locals[0]); emitSanitizer("safeClassName", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;"); storeLocal(locals[0]);
                    if (args.length == 3) {
                        loadLocal(locals[1]); emitSanitizer("safeBoolean", "(ZLjava/lang/String;)Z"); storeLocal(locals[1]);
                        loadLocal(locals[2]); emitSanitizer("safeClassLoader", "(Ljava/lang/ClassLoader;Ljava/lang/String;)Ljava/lang/ClassLoader;"); storeLocal(locals[2]);
                    }
                } else if ("METHOD_INVOKE".equals(kind) && args.length == 2) {
                    loadLocal(locals[0]); emitSanitizer("safeInvocationTarget", "(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;"); storeLocal(locals[0]);
                    loadLocal(locals[1]); emitSanitizer("safeArguments", "([Ljava/lang/Object;Ljava/lang/String;)[Ljava/lang/Object;"); storeLocal(locals[1]);
                } else if ("CONSTRUCTOR_NEW_INSTANCE".equals(kind) && args.length == 1) {
                    loadLocal(locals[0]); emitSanitizer("safeArguments", "([Ljava/lang/Object;Ljava/lang/String;)[Ljava/lang/Object;"); storeLocal(locals[0]);
                } else if ("FILE_OUTPUT".equals(kind) && args.length > 0) {
                    loadLocal(locals[0]);
                    if (isType(args[0], "java/nio/file/Path")) emitSanitizer("safePath", "(Ljava/nio/file/Path;Ljava/lang/String;)Ljava/nio/file/Path;");
                    else if (isType(args[0], "java/io/File")) emitSanitizer("safeFile", "(Ljava/io/File;Ljava/lang/String;)Ljava/io/File;");
                    else emitSanitizer("safeFilePath", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;");
                    storeLocal(locals[0]);
                    for (int i = 1; i < args.length; i++) if (args[i].getSort() == Type.BOOLEAN) { push(false); storeLocal(locals[i]); }
                } else if ("SOCKET_LOOPBACK".equals(kind) && args.length > 0) {
                    loadLocal(locals[0]); emitSanitizer("safeSocketAddress", "(Ljava/lang/Object;Ljava/lang/String;)Ljava/net/InetSocketAddress;"); storeLocal(locals[0]);
                    if (args.length > 1 && args[1].getSort() == Type.INT) { push(50); storeLocal(locals[1]); }
                }
                if ("NATIVE_FIXTURE".equals(kind) && args.length == 1) {
                    loadLocal(locals[0]);
                    emitSanitizer("loadLibrary".equals(name) ? "safeNativeLibraryName" : "rewriteNativeLoad",
                            "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;");
                    storeLocal(locals[0]);
                }
            }

            private void sanitizeReceiver(String kind) {
                if ("PROCESS_BUILDER_START".equals(kind)) emitSanitizer("safeProcessBuilder", "(Ljava/lang/ProcessBuilder;Ljava/lang/String;)Ljava/lang/ProcessBuilder;");
                else if ("CLASS_NEW_INSTANCE".equals(kind)) emitSanitizer("safeClass", "(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Class;");
                else if ("METHOD_INVOKE".equals(kind)) emitSanitizer("safeMethod", "(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/reflect/Method;");
                else if ("CONSTRUCTOR_NEW_INSTANCE".equals(kind)) emitSanitizer("safeConstructor", "(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/reflect/Constructor;");
                else if ("URL_LOOPBACK".equals(kind)) emitSanitizer("safeUrl", "(Ljava/lang/Object;Ljava/lang/String;)Ljava/net/URL;");
                else if ("SOCKET_LOOPBACK".equals(kind)) emitSanitizer("safeSocket", "(Ljava/lang/Object;Ljava/lang/String;)Ljava/net/Socket;");
            }

            private void emitExecution(String name, String spec) {
                if (spec == null) { visitLdcInsn(token); super.visitMethodInsn(Opcodes.INVOKESTATIC, EXEC, name, "(Ljava/lang/String;)V", false); }
                else { visitLdcInsn(spec); visitLdcInsn(token); super.visitMethodInsn(Opcodes.INVOKESTATIC, EXEC, name, "(Ljava/lang/String;Ljava/lang/String;)V", false); }
            }
            private void emitSanitizer(String name, String desc) { visitLdcInsn(token); super.visitMethodInsn(Opcodes.INVOKESTATIC, EXEC, name, desc, false); }
        }

        private boolean isString(Type type) { return isType(type, "java/lang/String"); }
        private boolean isType(Type type, String internal) { return type.getSort() == Type.OBJECT && internal.equals(type.getInternalName()); }
        private static boolean matches(Set<String> methods, String name, String desc) { return methods != null && (methods.contains(name) || methods.contains(name + "#" + desc)); }
        private boolean nativeMethod(String owner, String name, String desc) {
            Set<String> methods = nativeMethodIndex.get(owner);
            return methods != null && methods.contains(name + "#" + desc);
        }

        private static String internalName(String value) {
            return value == null ? "" : value.replace('.', '/');
        }
        private void emitCanary(MethodVisitor visitor, String spec) { visitor.visitLdcInsn(spec); visitor.visitLdcInsn(token); visitor.visitMethodInsn(Opcodes.INVOKESTATIC, GATE, "hit", "(Ljava/lang/String;Ljava/lang/String;)V", false); }
        private static String nestedKind(String owner, String name, String desc) {
            if (owner.equals("java/lang/System") && (name.equals("load") || name.equals("loadLibrary")) && "(Ljava/lang/String;)V".equals(desc)) return "NESTED_BLOCK";
            if (owner.equals("java/lang/Runtime") && name.equals("exec") && commandDescriptor(desc)) return "NESTED_BLOCK";
            if (owner.equals("java/lang/ProcessBuilder") && name.equals("start") && "()Ljava/lang/Process;".equals(desc)) return "NESTED_BLOCK";
            if (owner.equals("java/lang/Class") && name.equals("forName") && ("(Ljava/lang/String;)Ljava/lang/Class;".equals(desc) || "(Ljava/lang/String;ZLjava/lang/ClassLoader;)Ljava/lang/Class;".equals(desc))) return "NESTED_BLOCK";
            if (owner.equals("java/lang/Class") && name.equals("newInstance") && "()Ljava/lang/Object;".equals(desc)) return "NESTED_BLOCK";
            if (owner.equals("java/lang/reflect/Method") && name.equals("invoke") && "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;".equals(desc)) return "NESTED_BLOCK";
            if (owner.equals("java/lang/reflect/Constructor") && name.equals("newInstance") && "([Ljava/lang/Object;)Ljava/lang/Object;".equals(desc)) return "NESTED_BLOCK";
            if ((owner.equals("java/nio/file/Files") && name.equals("newOutputStream") && "(Ljava/nio/file/Path;[Ljava/nio/file/OpenOption;)Ljava/io/OutputStream;".equals(desc)) || ((owner.equals("java/io/FileOutputStream") || owner.equals("java/io/FileWriter")) && name.equals("<init>") && fileConstructorDescriptor(desc))) return "NESTED_BLOCK";
            if (owner.equals("java/net/URL") && (name.equals("openConnection") || name.equals("openStream")) && ("()Ljava/net/URLConnection;".equals(desc) || "()Ljava/io/InputStream;".equals(desc))) return "NESTED_BLOCK";
            if (owner.equals("java/net/Socket") && name.equals("connect") && ("(Ljava/net/SocketAddress;)V".equals(desc) || "(Ljava/net/SocketAddress;I)V".equals(desc))) return "NESTED_BLOCK";
            if (owner.equals("java/lang/System") && (name.equals("exit") || name.equals("halt") || name.equals("setSecurityManager"))) return "NESTED_BLOCK";
            if (owner.equals("java/lang/Runtime") && (name.equals("exec") || name.equals("load") || name.equals("loadLibrary") || name.equals("halt"))) return "NESTED_BLOCK";
            if (owner.equals("java/lang/ClassLoader") && (name.equals("defineClass") || name.equals("loadClass"))) return "NESTED_BLOCK";
            if (owner.startsWith("javax/naming/") || owner.startsWith("java/rmi/")) return (name.equals("lookup") || name.equals("list") || name.equals("bind") || name.equals("connect") || name.equals("accept")) ? "NESTED_BLOCK" : "";
            if (owner.startsWith("javax/script/") && (name.equals("eval") || name.equals("getEngineByName"))) return "NESTED_BLOCK";
            if (owner.startsWith("java/lang/invoke/") && name.startsWith("invoke")) return "NESTED_BLOCK";
            if (owner.equals("java/sql/Statement") || owner.equals("java/sql/Connection") || owner.equals("java/net/URLClassLoader")) return "NESTED_BLOCK";
            if (owner.equals("java/nio/file/Files")) return (name.startsWith("write") || name.startsWith("delete") || name.startsWith("move") || name.startsWith("copy") || name.startsWith("create") || name.startsWith("set") || name.equals("newByteChannel")) ? "NESTED_BLOCK" : "";
            if (owner.equals("java/io/File") && (name.equals("delete") || name.equals("deleteOnExit") || name.equals("createNewFile") || name.equals("mkdir") || name.equals("mkdirs") || name.equals("renameTo"))) return "NESTED_BLOCK";
            if (owner.equals("java/io/RandomAccessFile") && name.equals("<init>")) return "NESTED_BLOCK";
            if (owner.equals("java/net/URLConnection") || owner.equals("java/net/HttpURLConnection")) return (name.equals("connect") || name.equals("getInputStream") || name.equals("getOutputStream") || name.equals("getResponseCode")) ? "NESTED_BLOCK" : "";
            if (owner.equals("java/net/Socket") && (name.equals("connect") || name.equals("getInputStream") || name.equals("getOutputStream"))) return "NESTED_BLOCK";
            if (owner.equals("java/net/ServerSocket") || owner.equals("java/net/DatagramSocket")) return (name.equals("<init>") || name.equals("bind") || name.equals("accept") || name.equals("connect") || name.equals("send")) ? "NESTED_BLOCK" : "";
            if (owner.equals("java/net/InetAddress") && name.startsWith("getBy")) return "NESTED_BLOCK";
            if (owner.startsWith("java/net/http/") && (name.equals("send") || name.equals("sendAsync"))) return "NESTED_BLOCK";
            if (owner.startsWith("javax/xml/transform/") || owner.startsWith("javax/el/") || owner.startsWith("org/apache/commons/jexl/") || owner.startsWith("groovy/")) return "NESTED_BLOCK";
            return "";
        }
        private boolean exactConstructorOwner(String owner) {
            Set<String> methods = sinks.get(owner);
            if (methods == null) return false;
            for (String method : methods) {
                if (method.equals("<init>") || method.startsWith("<init>#")) return true;
            }
            return false;
        }
        private static boolean nestedConstructorType(String owner) {
            return owner.equals("java/io/FileOutputStream")
                    || owner.equals("java/io/FileWriter")
                    || owner.equals("java/io/RandomAccessFile")
                    || owner.equals("java/net/ServerSocket")
                    || owner.equals("java/net/DatagramSocket");
        }
        private static boolean commandDescriptor(String desc) { return desc.endsWith(")Ljava/lang/Process;") && (desc.startsWith("(Ljava/lang/String;") || desc.startsWith("([Ljava/lang/String;")); }
        private static boolean fileConstructorDescriptor(String desc) { return "(Ljava/lang/String;)V".equals(desc) || "(Ljava/io/File;)V".equals(desc) || "(Ljava/lang/String;Z)V".equals(desc) || "(Ljava/io/File;Z)V".equals(desc); }
    }
}
