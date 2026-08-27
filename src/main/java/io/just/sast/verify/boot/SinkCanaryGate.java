package io.just.sast.verify.boot;

/**
 * sink canary 门卫（bootstrap classloader，无任何依赖）：
 * 插桩后的 sink 方法入口统一调用 {@link #hit(String)}——仅当调用栈上存在本链入口类#入口方法帧
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

    private SinkCanaryGate() {
    }

    /** agent premain 注册本链入口（点分类名 + 方法名）。 */
    public static void setEntry(String dottedClass, String method) {
        entryClass = dottedClass;
        entryMethod = method;
    }

    /** sink 入口调用：栈上存在入口帧 → 抛标记；否则放行。 */
    public static void hit(String spec) {
        String ec = entryClass;
        String em = entryMethod;
        if (ec == null || em == null) {
            return;
        }
        StackTraceElement[] stack = new Throwable().getStackTrace();
        // frame[0] = hit() 自身；从 1 起找入口帧
        for (int i = 1; i < stack.length; i++) {
            StackTraceElement frame = stack[i];
            if (ec.equals(frame.getClassName()) && em.equals(frame.getMethodName())) {
                throw new SinkReachedError(spec);
            }
        }
    }
}
