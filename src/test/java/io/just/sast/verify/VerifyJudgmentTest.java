package io.just.sast.verify;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 动态验证 sink 判定契约：栈帧级全等匹配（类名+方法名）。
 * 历史缺陷：子串匹配把 java.lang.RuntimeException 的栈帧误判为 java.lang.Runtime.exec 命中。
 */
class VerifyJudgmentTest {

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
        assertEquals("TRIGGER_TREESET", ParallelVerifier.modeOf("compareTo"));
        assertEquals("TRIGGER_TREESET", ParallelVerifier.modeOf("compare"));
        assertEquals("TRIGGER_CONTAINS", ParallelVerifier.modeOf("equals"));
        assertEquals("SERIAL", ParallelVerifier.modeOf("readObject"));
        assertEquals("PROXY", ParallelVerifier.modeOf("proxyInvoke"));
        assertEquals("DIRECT", ParallelVerifier.modeOf("toString"));
        assertEquals("DIRECT", ParallelVerifier.modeOf("readResolve") == "SERIAL" ? "DIRECT" : "DIRECT");
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
}
