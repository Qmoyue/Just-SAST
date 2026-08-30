package io.just.sast.verify.legacy;

/**
 * Dependency-free gate used by the Java 8 canary agent. The class is appended to
 * the bootstrap search path so transformed JDK classes can resolve it.
 */
public final class LegacySinkCanaryGate {

    private static volatile String entryClass;
    private static volatile String entryMethod;
    private static volatile String entryToken;
    private static volatile boolean reached;
    private static boolean configured;

    private LegacySinkCanaryGate() {
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

    public static void hit(String spec, String token) {
        String ec = entryClass;
        String em = entryMethod;
        if (ec == null || em == null || entryToken == null || !entryToken.equals(token)) {
            return;
        }
        StackTraceElement[] stack = new Throwable().getStackTrace();
        for (int i = 1; i < stack.length; i++) {
            StackTraceElement frame = stack[i];
            if (ec.equals(frame.getClassName()) && em.equals(frame.getMethodName())) {
                reached = true;
                throw new LegacySinkReachedError(spec);
            }
        }
    }

    public static boolean wasReached() {
        return reached;
    }
}
