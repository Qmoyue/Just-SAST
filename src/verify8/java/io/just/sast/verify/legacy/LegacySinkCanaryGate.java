package io.just.sast.verify.legacy;

/**
 * Dependency-free gate used by the Java 8 canary agent. The class is appended to
 * the bootstrap search path so transformed JDK classes can resolve it.
 */
public final class LegacySinkCanaryGate {

    private static volatile String entryClass;
    private static volatile String entryMethod;

    private LegacySinkCanaryGate() {
    }

    public static void setEntry(String dottedClass, String method) {
        entryClass = dottedClass;
        entryMethod = method;
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
                throw new LegacySinkReachedError(spec);
            }
        }
    }
}
