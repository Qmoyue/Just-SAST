package io.just.sast.verify.legacy;

/**
 * Dependency-free gate used by the Java 8 canary agent. The class is appended to
 * the bootstrap search path so transformed JDK classes can resolve it.
 */
public final class LegacySinkCanaryGate {

    private static volatile String entryClass;
    private static volatile String entryMethod;
    private static volatile boolean reached;

    private LegacySinkCanaryGate() {
    }

    public static void setEntry(String dottedClass, String method) {
        entryClass = dottedClass;
        entryMethod = method;
        reached = false;
    }

    public static void hit(String spec) {
        String ec = entryClass;
        String em = entryMethod;
        if (ec == null || em == null) {
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
