package io.just.sast.verify;

import io.just.sast.blackboard.Chain;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * 动态验证 sink 判定契约：栈帧级全等匹配（类名+方法名）。
 * 历史缺陷：子串匹配把 java.lang.RuntimeException 的栈帧误判为 java.lang.Runtime.exec 命中。
 */
class VerifyJudgmentTest {

    @TempDir
    Path temp;

    private static StackTraceElement frame(String cls, String method) {
        return new StackTraceElement(cls, method, "X.java", 1);
    }

    @Test
    void runtimeExceptionStackDoesNotMatchRuntimeExecSink() {
        Exception e = new RuntimeException("boom");
        e.setStackTrace(new StackTraceElement[]{
                frame("app.Gadget", "readObject"),
                frame("java.lang.RuntimeException", "<init>"),
        });
        // RuntimeException 是 java.lang.Runtime 的子串——全等匹配必须排除
        assertFalse(ChainVerifyProbe.reachesSink(e, "java.lang.Runtime", "exec"),
                "java.lang.RuntimeException 栈帧不得命中 java.lang.Runtime.exec sink");
    }

    @Test
    void exactFrameMatchesSink() {
        Exception e = new RuntimeException("boom");
        e.setStackTrace(new StackTraceElement[]{
                frame("java.lang.ProcessImpl", "start"),
                frame("java.lang.Runtime", "exec"),
                frame("app.Gadget", "readObject"),
        });
        assertTrue(ChainVerifyProbe.reachesSink(e, "java.lang.Runtime", "exec"));
        // 同类不同方法不算命中
        assertFalse(ChainVerifyProbe.reachesSink(e, "java.lang.Runtime", "availableProcessors"));
    }

    @Test
    void causeChainFramesMatch() {
        Exception root = new Exception("root");
        root.setStackTrace(new StackTraceElement[]{
                frame("javax.naming.InitialContext", "lookup"),
        });
        Exception wrapper = new Exception("wrap", root);
        wrapper.setStackTrace(new StackTraceElement[]{frame("app.Caller", "run")});
        assertTrue(ChainVerifyProbe.reachesSink(wrapper, "javax.naming.InitialContext", "lookup"),
                "cause 链中的 sink 帧应命中");
        assertFalse(ChainVerifyProbe.reachesSink(wrapper, "app.Caller", "missing"));
    }

    @Test
    void modeOfMapsEntryKindsToTriggerFaithfulModes() {
        assertEquals("TRIGGER_HASH", ParallelVerifier.modeOf("hashCode"));
        assertEquals("TRIGGER_COMPARETO", ParallelVerifier.modeOf("compareTo"));
        assertEquals("TRIGGER_COMPARATOR", ParallelVerifier.modeOf("compare"));
        assertEquals("TRIGGER_CONTAINS", ParallelVerifier.modeOf("equals"));
        assertEquals("SERIAL", ParallelVerifier.modeOf("readObject"));
        assertEquals("PROXY", ParallelVerifier.modeOf("proxyInvoke"));
        assertEquals("DIRECT", ParallelVerifier.modeOf("toString"));
        assertEquals("SERIAL", ParallelVerifier.modeOf("readResolve"));
        assertEquals("SERIAL", ParallelVerifier.modeOf("readExternal"));
        assertEquals("SOURCE", ParallelVerifier.modeOf("source"));
        assertEquals("SOURCE", ParallelVerifier.modeOf("deserialize"));
    }

    @Test
    void collectionInstantiationMatchesDeclaredType() {
        assertTrue(ChainVerifyProbe.newCollection(java.util.HashMap.class) instanceof java.util.HashMap);
        assertTrue(ChainVerifyProbe.newCollection(java.util.TreeSet.class) instanceof java.util.TreeSet);
        assertTrue(ChainVerifyProbe.newCollection(java.util.ArrayList.class) instanceof java.util.ArrayList);
        // 接口/抽象取默认实现
        assertTrue(ChainVerifyProbe.newCollection(java.util.Map.class) instanceof java.util.HashMap);
        assertTrue(ChainVerifyProbe.newCollection(java.util.SortedSet.class) instanceof java.util.TreeSet);
        assertTrue(ChainVerifyProbe.newCollection(java.util.List.class) instanceof java.util.ArrayList);
        assertNull(ChainVerifyProbe.newCollection(String.class));
    }

    @Test
    void canaryDescriptorDistinguishesOverloadedSinks() {
        assertTrue(ChainVerifyProbe.sameSink("t/Sink#exec#(Ljava/lang/String;)V",
                "t.Sink", "exec", "(Ljava/lang/String;)V"));
        assertFalse(ChainVerifyProbe.sameSink("t/Sink#exec#(I)V",
                "t.Sink", "exec", "(Ljava/lang/String;)V"),
                "不同重载不得被动态 canary 误判为同一 sink");
        assertTrue(ChainVerifyProbe.sameSink("t/Sink#exec", "t.Sink", "exec", "()V"),
                "旧的无 descriptor spec 仍应可兼容");
    }

    @Test
    void verifierMatchesOverloadedEntryByDescriptorAndSupportsPrimitiveConstructors() throws Exception {
        assertEquals("(I)V", descriptorOf(ChainVerifyProbe.findMethod(
                OverloadedEntry.class, "run", "(I)V")));
        assertEquals("(Ljava/lang/String;I)V", descriptorOf(ChainVerifyProbe.findMethod(
                OverloadedEntry.class, "run", "(Ljava/lang/String;I)V")));
        assertTrue(ChainVerifyProbe.newInstance(PrimitiveEntry.class, false) instanceof PrimitiveEntry);
    }

    private static String descriptorOf(java.lang.reflect.Method method) {
        StringBuilder result = new StringBuilder("(");
        for (Class<?> parameter : method.getParameterTypes()) {
            result.append(typeDescriptor(parameter));
        }
        return result.append(')').append(typeDescriptor(method.getReturnType())).toString();
    }

    private static String typeDescriptor(Class<?> type) {
        if (type == String.class) return "Ljava/lang/String;";
        if (type == void.class) return "V";
        if (type == int.class) return "I";
        throw new AssertionError("test descriptor type missing: " + type);
    }

    private static final class OverloadedEntry {
        private void run(int value) { }
        private void run(String value, int flag) { }
    }

    private static final class PrimitiveEntry {
        private PrimitiveEntry(short s, byte b, float f, double d, char c) { }
    }

    @Test
    void emptyVerificationBatchIsAValidNoOp() {
        ParallelVerifier verifier = new ParallelVerifier(java.nio.file.Path.of("."), java.util.List.of(), null);
        assertEquals(java.util.List.of(), verifier.selectChains(java.util.List.of(), 20));
        assertEquals(java.util.List.of(), verifier.verifyAll(java.util.List.of()));
    }

    @Test
    void constructibleChainsGetBudgetPreferenceWithoutChangingCandidates() {
        Chain weak = new Chain("rule", "gadget", "HIGH", "a/Entry", "run", "source",
                "java/lang/Runtime", "exec", java.util.List.of(), 0);
        Chain constructible = new Chain("rule", "gadget", "HIGH", "b/Entry", "run", "source",
                "java/lang/Runtime", "exec", java.util.List.of(), 0);
        ParallelVerifier verifier = new ParallelVerifier(java.nio.file.Path.of("."),
                java.util.List.of(), null);

        assertEquals(java.util.List.of(constructible), verifier.selectChains(
                java.util.List.of(weak, constructible), 1,
                java.util.Set.of(constructible.key())));
    }

    @Test
    void primaryArtifactEntryGetsCoveragePreferenceWithoutNameSpecialCases() throws IOException {
        Path target = temp.resolve("target.jar");
        try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(target))) {
            output.putNextEntry(new JarEntry("app/Entry.class"));
            output.write(new byte[]{0});
            output.closeEntry();
        }
        Chain applicationEntry = new Chain("rule", "gadget", "HIGH", "app/Entry", "hashCode",
                "hashCode", "java/lang/reflect/Method", "invoke", java.util.List.of(), 0);
        Chain dependencyEntry = new Chain("rule", "gadget", "HIGH", "dep/Entry", "hashCode",
                "hashCode", "java/lang/reflect/Method", "invoke", java.util.List.of(), 0);
        ParallelVerifier verifier = new ParallelVerifier(target, java.util.List.of(), null);

        assertEquals(applicationEntry,
                verifier.selectChains(java.util.List.of(dependencyEntry, applicationEntry), 1).get(0));
    }

    @Test
    void finiteProbeBudgetPrefersCompactDangerousSinkOverGenericPlumbing() {
        java.util.List<io.just.sast.blackboard.ChainHop> longPath = new java.util.ArrayList<>();
        for (int i = 0; i < 12; i++) {
            longPath.add(new io.just.sast.blackboard.ChainHop("lib/Layer" + i, "run",
                    "lib/Layer" + (i + 1), "run",
                    io.just.sast.blackboard.HopKind.DIRECT_CALL, null, "call", "()V", null));
        }
        Chain plumbing = new Chain("rule", "gadget", "MEDIUM", "app/Entry", "run",
                "source", "java/util/concurrent/Executor", "execute", longPath, 0);
        Chain compact = new Chain("rule", "gadget", "HIGH", "app/Other", "readObject",
                "readObject", "java/lang/reflect/Method", "invoke",
                java.util.List.of(new io.just.sast.blackboard.ChainHop("app/Other", "readObject",
                        "java/lang/reflect/Method", "invoke", io.just.sast.blackboard.HopKind.DIRECT_CALL,
                        null, "call", "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;", null)), 0);
        ParallelVerifier verifier = new ParallelVerifier(java.nio.file.Path.of("."),
                java.util.List.of(), null);

        assertEquals(compact, verifier.selectChains(java.util.List.of(plumbing, compact), 1).get(0));
    }

    @Test
    void verificationQuotaKeepsDifferentSinkFamiliesForOneEntry() {
        Chain executor = new Chain("rule", "gadget", "MEDIUM", "app/Entry", "read",
                "readObject", "java/util/concurrent/Executor", "execute",
                java.util.List.of(), 0);
        Chain reflection = new Chain("rule", "gadget", "HIGH", "app/Entry", "read",
                "readObject", "java/lang/reflect/Method", "invoke",
                java.util.List.of(), 0);
        Chain secondExecutor = new Chain("rule", "gadget", "MEDIUM", "app/Entry", "read",
                "readObject", "java/util/concurrent/ScheduledExecutorService", "execute",
                java.util.List.of(), 0);
        ParallelVerifier verifier = new ParallelVerifier(java.nio.file.Path.of("."),
                java.util.List.of(), null);

        java.util.List<Chain> selected = verifier.selectChains(
                java.util.List.of(executor, reflection, secondExecutor), 3);
        assertTrue(selected.contains(reflection));
        assertEquals(3, selected.size());
        assertEquals("reflection", ParallelVerifier.sinkRiskFamily(reflection.sinkClass()));
        assertEquals("other", ParallelVerifier.sinkRiskFamily(executor.sinkClass()));
    }

    @Test
    void sourceTriggerSpecCarriesSemanticCallbackAndSourceBoundary() {
        Chain chain = new Chain("rule", "gadget", "HIGH", "app/Host", "read",
                "source", "java/lang/reflect/Method", "invoke",
                java.util.List.of(
                        new io.just.sast.blackboard.ChainHop("app/Host", "read",
                                "java/io/ObjectInputStream", "readObject",
                                io.just.sast.blackboard.HopKind.DIRECT_CALL, null,
                                "bridge-source-deserialize", "()Ljava/lang/Object;", null),
                        new io.just.sast.blackboard.ChainHop("java/io/ObjectInputStream", "readObject",
                                "app/Gadget", "hashCode", io.just.sast.blackboard.HopKind.VIRTUAL_DISPATCH,
                                null, "bridge-trigger-src", "()I", null),
                        new io.just.sast.blackboard.ChainHop("app/Host", "read", "app/Host", "read",
                                io.just.sast.blackboard.HopKind.ENTRY, null, "source", "()V", null)),
                0);
        assertEquals("app/Gadget|hashCode|hashCode|java/io/ObjectInputStream|readObject|()Ljava/lang/Object;||",
                ParallelVerifier.sourceTriggerSpec(chain));
    }

    @Test
    void directKryoSourceGetsBoundedSerializedInputWithoutTargetNames() {
        Chain chain = new Chain("rule", "gadget", "HIGH", "app/Host", "readPayload",
                "deserialize", "java/lang/reflect/Method", "invoke",
                java.util.List.of(
                        new io.just.sast.blackboard.ChainHop("app/Host", "readPayload",
                                "com/esotericsoftware/kryo/Kryo", "readClassAndObject",
                                io.just.sast.blackboard.HopKind.DIRECT_CALL, null,
                                "call", "(Lcom/esotericsoftware/kryo/io/Input;)Ljava/lang/Object;", null),
                        new io.just.sast.blackboard.ChainHop("app/Host", "readPayload",
                                "app/Host", "readPayload", io.just.sast.blackboard.HopKind.ENTRY,
                                null, "deserialize", "(Ljava/lang/String;)Ljava/lang/Object;", null)),
                0);

        assertEquals("java/util/ArrayList|toString|toString|com/esotericsoftware/kryo/Kryo|"
                        + "readClassAndObject|(Lcom/esotericsoftware/kryo/io/Input;)Ljava/lang/Object;||",
                ParallelVerifier.sourceTriggerSpec(chain));
    }

    @Test
    void directObjectInputSourceUsesTheNearestGenericCallbackShape() {
        Chain chain = new Chain("rule", "gadget", "HIGH", "app/Host", "readPayload",
                "source", "java/lang/reflect/Method", "invoke", java.util.List.of(
                new io.just.sast.blackboard.ChainHop("app/Gadget", "equals",
                        "java/lang/reflect/Method", "invoke",
                        io.just.sast.blackboard.HopKind.DIRECT_CALL, null, "call",
                        "(Ljava/lang/Object;)Ljava/lang/Object;", null),
                new io.just.sast.blackboard.ChainHop("java/io/ObjectInputStream", "readObject",
                        "app/Gadget", "equals", io.just.sast.blackboard.HopKind.NATIVE_CALLBACK,
                        null, "callback", "(Ljava/lang/Object;)Z", null),
                new io.just.sast.blackboard.ChainHop("app/Host", "readPayload",
                        "java/io/ObjectInputStream", "readObject",
                        io.just.sast.blackboard.HopKind.DIRECT_CALL, null, "call",
                        "()Ljava/lang/Object;", null),
                new io.just.sast.blackboard.ChainHop("app/Host", "readPayload",
                        "app/Host", "readPayload", io.just.sast.blackboard.HopKind.ENTRY,
                        null, "source", "([B)Ljava/lang/Object;", null)), 0);
        assertEquals("app/Gadget|equals|equals|java/io/ObjectInputStream|readObject|"
                        + "()Ljava/lang/Object;||", ParallelVerifier.sourceTriggerSpec(chain));
    }
}
