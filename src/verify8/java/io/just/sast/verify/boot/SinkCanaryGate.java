package io.just.sast.verify.boot;

/**
 * Dependency-free, one-shot canary gate shared by legacy verifier children.
 * The class is appended to the bootstrap search path before target code loads.
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

    public static synchronized void setEntry(String dottedClass, String method, String token) {
        if (configured || dottedClass == null || method == null || token == null
                || dottedClass.length() == 0 || method.length() == 0 || token.length() == 0) {
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

    public static boolean protocolBound(String runId, String chainFingerprint,
                                        String sinkFingerprint, String nonce,
                                        String artifactFingerprint) {
        return protocolConfigured && same(protocolRunId, runId)
                && same(protocolChainFingerprint, chainFingerprint)
                && same(protocolSinkFingerprint, sinkFingerprint)
                && same(protocolNonce, nonce)
                && same(protocolArtifactFingerprint, artifactFingerprint);
    }

    public static void hit(String spec, String token) {
        String expectedClass = entryClass;
        String expectedMethod = entryMethod;
        String expectedToken = entryToken;
        if (expectedClass == null || expectedMethod == null || expectedToken == null
                || !expectedToken.equals(token)) {
            return;
        }
        StackTraceElement[] stack = new Throwable().getStackTrace();
        for (int i = 1; i < stack.length; i++) {
            StackTraceElement frame = stack[i];
            if (expectedClass.equals(frame.getClassName())
                    && expectedMethod.equals(frame.getMethodName())) {
                reached = true;
                throw new SinkReachedError(spec);
            }
        }
    }

    public static boolean wasReached() {
        return reached;
    }

    public static boolean configured() {
        return configured && entryClass != null && entryMethod != null && entryToken != null;
    }

    private static boolean blank(String value) {
        return value == null || value.length() == 0;
    }

    private static boolean same(String left, String right) {
        return left != null && left.equals(right);
    }
}
