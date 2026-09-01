package io.just.sast.verify.boot;

/**
 * sink canary 门卫（bootstrap classloader，无任何依赖）：
 * 插桩后的 sink 方法入口统一调用 {@link #hit(String, String)}——仅当调用栈上存在本链入口类#入口方法帧
 * 时抛出 {@link SinkReachedError}，否则静默放行。
 *
 * 必须设门卫的原因：java.lang.reflect.Constructor#newInstance、java.net.URL#openConnection、
 * java.lang.Class#forName 等通用 sink 被 JVM 自身机制（lambda metafactory、launcher 类路径
 * 处理）大量调用——无条件抛出会在探针 JVM 启动阶段即崩溃；探针自身的基础设施调用同理。
 * 入口帧在场 = sink 真实经由 gadget 路径到达，才构成链命中。
 */
public final class SinkCanaryGate {

    private static volatile String entryClass;
    private static volatile String entryMethod;
    private static volatile String entryToken;
    private static volatile String protocolRunId;
    private static volatile String protocolChainFingerprint;
    private static volatile String protocolSinkFingerprint;
    private static volatile String protocolNonce;
    private static volatile String protocolArtifactFingerprint;
    private static volatile boolean reached;
    private static boolean configured;
    private static boolean protocolConfigured;

    private SinkCanaryGate() {
    }

    /** Agent premain registers the one-shot entry and per-child canary token. */
    public static synchronized void setEntry(String dottedClass, String method, String token) {
        // The gate is bootstrap-visible, so an input class could otherwise reset it after
        // premain and manufacture a positive result. Each verifier child handles exactly one
        // chain; one-shot arming removes that mutation surface without a second dependency.
        if (configured || dottedClass == null || method == null || token == null
                || dottedClass.isEmpty() || method.isEmpty() || token.isEmpty()) {
            return;
        }
        entryClass = dottedClass;
        entryMethod = method;
        entryToken = token;
        reached = false;
        configured = true;
    }

    /** Bind the bootstrap canary to the launcher-owned attempt identity exactly once. */
    public static synchronized void setProtocolBinding(String runId, String chainFingerprint,
                                                        String sinkFingerprint, String nonce,
                                                        String artifactFingerprint) {
        if (!configured || protocolConfigured || blank(runId) || blank(chainFingerprint)
                || blank(sinkFingerprint) || blank(nonce) || blank(artifactFingerprint)) {
            return;
        }
        protocolRunId = runId;
        protocolChainFingerprint = chainFingerprint;
        protocolSinkFingerprint = sinkFingerprint;
        protocolNonce = nonce;
        protocolArtifactFingerprint = artifactFingerprint;
        protocolConfigured = true;
    }

    /** Probe-side check that the agent configured this exact bootstrap gate instance. */
    public static boolean protocolBound(String runId, String chainFingerprint,
                                        String sinkFingerprint, String nonce,
                                        String artifactFingerprint) {
        return protocolConfigured && same(protocolRunId, runId)
                && same(protocolChainFingerprint, chainFingerprint)
                && same(protocolSinkFingerprint, sinkFingerprint)
                && same(protocolNonce, nonce)
                && same(protocolArtifactFingerprint, artifactFingerprint);
    }

    /** Sink entry call: an authenticated token plus the entry frame is required. */
    public static void hit(String spec, String token) {
        String ec = entryClass;
        String em = entryMethod;
        if (ec == null || em == null || entryToken == null || !entryToken.equals(token)) {
            return;
        }
        StackTraceElement[] stack = new Throwable().getStackTrace();
        // frame[0] = hit() 自身；从 1 起找入口帧
        for (int i = 1; i < stack.length; i++) {
            StackTraceElement frame = stack[i];
            if (ec.equals(frame.getClassName()) && em.equals(frame.getMethodName())) {
                reached = true;
                throw new SinkReachedError(spec);
            }
        }
    }

    /**
     * Reflection wraps Errors thrown by an instrumented sink in InvocationTargetException;
     * a gadget may then catch that checked wrapper and hide the marker from the probe. Keep a
     * one-bit bootstrap-visible latch so the child can classify an already reached sink after
     * the target's own catch block returns. The bit is reset for every forked chain.
     */
    public static boolean wasReached() {
        return reached;
    }

    /** Agent readiness check used before a target class is loaded. */
    public static boolean configured() {
        return configured && entryClass != null && entryMethod != null && entryToken != null;
    }

    /** JDK 24+ 无 SecurityManager 时的第二道 Java 级能力门；目标代码调用危险 API 时直接失败。 */
    public static void deny(String capability) {
        throw new SecurityException("dynamic sandbox denied: " + capability);
    }

    private static boolean blank(String value) {
        return value == null || value.isEmpty();
    }

    private static boolean same(String left, String right) {
        return left != null && left.equals(right);
    }
}
