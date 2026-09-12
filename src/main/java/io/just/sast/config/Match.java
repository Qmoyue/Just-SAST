package io.just.sast.config;

import java.util.regex.Pattern;

/** 匹配器：精确字符串，或以 "~" 前缀表示锚定正则（构造时预编译，匹配零编译开销）。 */
public final class Match {

    private static final int MAX_PATTERN_CHARS = 4_096;
    private static final int MAX_INPUT_CHARS = 16_384;
    private static final int MAX_QUANTIFIERS = 128;
    private static final int MAX_ALTERNATIONS = 256;
    private static final long MAX_MATCH_WORK = 4_000_000L;

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
        if (regex) {
            String expression = p.substring(1);
            validateRegex(expression);
            this.compiled = Pattern.compile("^(?:" + expression + ")$");
        } else {
            this.compiled = null;
        }
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
            if (value.length() > MAX_INPUT_CHARS) {
                return false;
            }
            if ((long) pattern.length() * Math.max(1, value.length()) > MAX_MATCH_WORK) {
                return false;
            }
            return compiled.matcher(value).matches();
        }
        return pattern.equals(value);
    }

    @Override
    public String toString() {
        return pattern;
    }

    /**
     * Reject regex constructs for which java.util.regex can backtrack exponentially.  Rule
     * files are data, so this validation is deliberately conservative and deterministic: the
     * matcher remains allocation-free on the hot path and never accepts a potentially hostile
     * back-reference/look-around or nested repetition.  The input length cap bounds the other
     * linear cases without a worker-thread timeout on every call site.
     */
    private static void validateRegex(String expression) {
        if (expression.length() > MAX_PATTERN_CHARS) {
            throw new IllegalArgumentException("MATCH_REGEX_LENGTH_LIMIT:" + MAX_PATTERN_CHARS);
        }
        int groups = 0;
        int quantifiers = 0;
        int alternations = 0;
        boolean escaped = false;
        boolean inClass = false;
        boolean lastAtom = false;
        boolean lastAtomQuantified = false;
        boolean lastAtomHasAlternation = false;
        boolean previousAtomQuantified = false;
        java.util.ArrayDeque<GroupState> groupStates = new java.util.ArrayDeque<>();
        for (int i = 0; i < expression.length(); i++) {
            char ch = expression.charAt(i);
            if (escaped) {
                if (Character.isDigit(ch) || ch == 'k' || ch == 'g') {
                    throw new IllegalArgumentException("MATCH_REGEX_BACKREFERENCE");
                }
                escaped = false;
                previousAtomQuantified = lastAtomQuantified;
                lastAtom = true;
                lastAtomQuantified = false;
                lastAtomHasAlternation = false;
                continue;
            }
            if (ch == '\\') {
                escaped = true;
                continue;
            }
            if (inClass) {
                if (ch == ']') {
                    inClass = false;
                    previousAtomQuantified = lastAtomQuantified;
                    lastAtom = true;
                    lastAtomQuantified = false;
                    lastAtomHasAlternation = false;
                }
                continue;
            }
            if (ch == '[') {
                inClass = true;
                lastAtom = false;
                lastAtomQuantified = false;
                lastAtomHasAlternation = false;
                continue;
            }
            if (ch == '(') {
                groups++;
                if (groups > MAX_ALTERNATIONS) {
                    throw new IllegalArgumentException("MATCH_REGEX_GROUP_LIMIT:" + MAX_ALTERNATIONS);
                }
                boolean nonCapturing = i + 2 < expression.length()
                        && expression.charAt(i + 1) == '?' && expression.charAt(i + 2) == ':';
                if (i + 1 < expression.length() && expression.charAt(i + 1) == '?'
                        && !nonCapturing) {
                    throw new IllegalArgumentException("MATCH_REGEX_UNSUPPORTED_GROUP");
                }
                groupStates.push(new GroupState());
                lastAtom = false;
                lastAtomQuantified = false;
                lastAtomHasAlternation = false;
                previousAtomQuantified = false;
                if (nonCapturing) {
                    // The `?:` marker is syntax, not a quantifier or an input atom.
                    i += 2;
                }
                continue;
            }
            if (ch == ')') {
                if (groupStates.isEmpty()) {
                    throw new IllegalArgumentException("MATCH_REGEX_UNBALANCED_GROUP");
                }
                GroupState state = groupStates.pop();
                if (state.hasAlternation && state.hasQuantifier) {
                    throw new IllegalArgumentException("MATCH_REGEX_AMBIGUOUS_GROUP");
                }
                previousAtomQuantified = lastAtomQuantified;
                lastAtom = true;
                lastAtomQuantified = state.hasQuantifier;
                lastAtomHasAlternation = state.hasAlternation;
                if (!groupStates.isEmpty()) {
                    GroupState parent = groupStates.peek();
                    parent.hasQuantifier |= state.hasQuantifier;
                    parent.hasAlternation |= state.hasAlternation;
                }
                continue;
            }
            if (ch == '|') {
                if (++alternations > MAX_ALTERNATIONS) {
                    throw new IllegalArgumentException("MATCH_REGEX_ALTERNATION_LIMIT:" + MAX_ALTERNATIONS);
                }
                if (!groupStates.isEmpty()) {
                    groupStates.peek().hasAlternation = true;
                }
                lastAtom = false;
                lastAtomQuantified = false;
                lastAtomHasAlternation = false;
                previousAtomQuantified = false;
                continue;
            }
            if (isQuantifierStart(ch)) {
                if (!lastAtom) {
                    throw new IllegalArgumentException("MATCH_REGEX_QUANTIFIER_WITHOUT_ATOM");
                }
                if (lastAtomQuantified) {
                    throw new IllegalArgumentException("MATCH_REGEX_NESTED_QUANTIFIER");
                }
                if (lastAtomHasAlternation) {
                    throw new IllegalArgumentException("MATCH_REGEX_AMBIGUOUS_REPETITION");
                }
                if (previousAtomQuantified) {
                    throw new IllegalArgumentException("MATCH_REGEX_ADJACENT_REPETITION");
                }
                if (++quantifiers > MAX_QUANTIFIERS) {
                    throw new IllegalArgumentException("MATCH_REGEX_QUANTIFIER_LIMIT:" + MAX_QUANTIFIERS);
                }
                if (ch == '{') {
                    int close = expression.indexOf('}', i + 1);
                    if (close < 0) {
                        throw new IllegalArgumentException("MATCH_REGEX_UNBALANCED_QUANTIFIER");
                    }
                    String body = expression.substring(i + 1, close);
                    String[] bounds = body.split(",", -1);
                    try {
                        int upper = Integer.parseInt(bounds[bounds.length - 1].trim());
                        if (upper > 4_096) {
                            throw new IllegalArgumentException("MATCH_REGEX_REPEAT_LIMIT:4096");
                        }
                    } catch (NumberFormatException invalid) {
                        if (!body.isBlank() && !body.endsWith(",")) {
                            throw new IllegalArgumentException("MATCH_REGEX_INVALID_QUANTIFIER");
                        }
                    }
                    i = close;
                }
                if (!groupStates.isEmpty()) {
                    groupStates.peek().hasQuantifier = true;
                }
                lastAtom = true;
                lastAtomQuantified = true;
                lastAtomHasAlternation = false;
                continue;
            }
            if (!Character.isWhitespace(ch)) {
                previousAtomQuantified = lastAtomQuantified;
                lastAtom = true;
                lastAtomQuantified = false;
                lastAtomHasAlternation = false;
            }
        }
        if (escaped || inClass || !groupStates.isEmpty()) {
            throw new IllegalArgumentException("MATCH_REGEX_UNBALANCED");
        }
    }

    private static final class GroupState {
        private boolean hasQuantifier;
        private boolean hasAlternation;
    }

    private static boolean isQuantifierStart(char ch) {
        return ch == '*' || ch == '+' || ch == '?' || ch == '{';
    }
}
