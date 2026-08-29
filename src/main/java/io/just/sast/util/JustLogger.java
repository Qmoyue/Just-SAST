package io.just.sast.util;

/** 轻量日志：全部走 stderr，与 CSV 结果输出隔离。 */
public final class JustLogger {

    public enum Level { DEBUG, INFO, WARN, ERROR }

    private static volatile Level level = Level.INFO;

    static {
        String p = System.getProperty("just.log.level");
        if (p != null) {
            try {
                level = Level.valueOf(p.trim().toUpperCase());
            } catch (IllegalArgumentException ignore) {
                // 非法级别保持 INFO
            }
        }
    }

    private JustLogger() {}

    public static void debug(String msg, Object... args) {
        log(Level.DEBUG, msg, args);
    }

    public static void info(String msg, Object... args) {
        log(Level.INFO, msg, args);
    }

    public static void warn(String msg, Object... args) {
        log(Level.WARN, msg, args);
    }

    public static void error(String msg, Object... args) {
        log(Level.ERROR, msg, args);
    }

    private static void log(Level lv, String msg, Object... args) {
        if (lv.ordinal() < level.ordinal()) {
            return;
        }
        System.err.println("[just:" + lv.name().toLowerCase() + "] " + format(msg, args));
    }

    private static String format(String msg, Object... args) {
        if (args == null || args.length == 0) {
            return msg;
        }
        StringBuilder sb = new StringBuilder(msg.length() + 32);
        int i = 0;
        int argIdx = 0;
        while (i < msg.length()) {
            char c = msg.charAt(i);
            if (c == '{' && i + 1 < msg.length() && msg.charAt(i + 1) == '}' && argIdx < args.length) {
                sb.append(args[argIdx++]);
                i += 2;
            } else {
                sb.append(c);
                i++;
            }
        }
        return sb.toString();
    }
}
