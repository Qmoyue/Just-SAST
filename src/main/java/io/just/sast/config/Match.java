package io.just.sast.config;

import java.util.regex.Pattern;

/** 匹配器：精确字符串，或以 "~" 前缀表示锚定正则（构造时预编译，匹配零编译开销）。 */
public final class Match {

    private final String pattern;
    private final boolean regex;
    private final Pattern compiled;

    public Match(String raw) {
        String p = raw == null ? "" : raw.strip();
        // YAML 中 ~"a|b" 的引号会进入标量，剥掉以防备选被引号拆散（"a / b"）
        if (p.startsWith("~")) {
            String rest = p.substring(1).strip();
            if (rest.length() >= 2 && rest.startsWith("\"") && rest.endsWith("\"")) {
                p = "~" + rest.substring(1, rest.length() - 1);
            }
        }
        this.pattern = p;
        this.regex = p.startsWith("~");
        this.compiled = regex ? Pattern.compile("^(?:" + p.substring(1) + ")$") : null;
    }

    public static Match of(String raw) {
        return new Match(raw);
    }

    public String pattern() {
        return pattern;
    }

    public boolean isRegex() {
        return regex;
    }

    public boolean matches(String value) {
        if (value == null) {
            return false;
        }
        if (regex) {
            return compiled.matcher(value).matches();
        }
        return pattern.equals(value);
    }

    @Override
    public String toString() {
        return pattern;
    }
}
