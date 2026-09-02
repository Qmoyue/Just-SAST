package io.just.sast.config;

/**
 * Parsed source selector used by declarative model rules.
 *
 * <p>The grammar is intentionally small: {@code this}, {@code argN}, and the explicit
 * finite-container selectors {@code element(this)} / {@code element(argN)}.  Keeping the
 * grammar in one place prevents the forward engine, backward engine, loader, and lint pass
 * from silently accepting different rule languages.</p>
 */
public record ModelSource(boolean element, String base, Integer argumentOrdinal) {

    public ModelSource {
        if (base == null || base.isBlank()) {
            throw new IllegalArgumentException("model source base is required");
        }
        if ("this".equals(base) && argumentOrdinal != null) {
            throw new IllegalArgumentException("receiver model source cannot have an argument ordinal");
        }
        if (!"this".equals(base)
                && (argumentOrdinal == null || argumentOrdinal < 0)) {
            throw new IllegalArgumentException("argument model source needs a non-negative ordinal");
        }
    }

    public boolean receiver() {
        return "this".equals(base);
    }

    /** Parse the complete grammar; malformed or overflowing ordinals return {@code null}. */
    public static ModelSource parse(String source) {
        if (source == null || source.isEmpty()) {
            return null;
        }
        boolean element = source.startsWith("element(") && source.endsWith(")");
        String base = element
                ? source.substring("element(".length(), source.length() - 1)
                : source;
        if ("this".equals(base)) {
            return new ModelSource(element, base, null);
        }
        if (base.length() <= 3 || !base.startsWith("arg")) {
            return null;
        }
        for (int i = 3; i < base.length(); i++) {
            if (base.charAt(i) < '0' || base.charAt(i) > '9') {
                return null;
            }
        }
        try {
            int ordinal = Integer.parseInt(base.substring(3));
            return ordinal < 0 ? null : new ModelSource(element, base, ordinal);
        } catch (NumberFormatException ignored) {
            return null;
        }
    }

    public static boolean isValid(String source) {
        return parse(source) != null;
    }
}
