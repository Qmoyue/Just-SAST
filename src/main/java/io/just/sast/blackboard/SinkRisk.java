package io.just.sast.blackboard;

import java.util.Locale;

/**
 * Data-only terminal risk metadata shared by rules, chains and reports.
 *
 * <p>The verifier may execute only a completely controlled effect.  Everything else stays at
 * the authenticated pre-sink boundary.  The inference helper is deliberately conservative and
 * has no project, package, version or benchmark-specific branches.</p>
 */
public enum SinkRisk {
    SAFE_CALLABLE,
    CONTROLLED_EFFECT,
    HIGH_RISK_TERMINAL;

    public static SinkRisk parse(String value) {
        if (value == null || value.isBlank()) {
            return HIGH_RISK_TERMINAL;
        }
        return switch (value.trim().toUpperCase(Locale.ROOT).replace('-', '_')) {
            case "SAFE", "SAFE_CALLABLE", "CALLABLE" -> SAFE_CALLABLE;
            case "CONTROLLED", "CONTROLLED_EFFECT", "SAFE_EFFECT" -> CONTROLLED_EFFECT;
            case "HIGH", "HIGH_RISK", "HIGH_RISK_TERMINAL", "DANGEROUS" ->
                    HIGH_RISK_TERMINAL;
            default -> throw new IllegalArgumentException(
                    "sink_risk must be SAFE_CALLABLE, CONTROLLED_EFFECT or HIGH_RISK_TERMINAL: "
                            + value);
        };
    }

    /** Conservative default for rules that predate explicit sink_risk metadata. */
    public static SinkRisk infer(String category, String owner, String method) {
        String c = lower(category);
        String o = lower(owner).replace('.', '/');
        String m = lower(method);
        if (containsAny(c, "native", "jni", "code", "template", "script", "spel",
                "expression", "reflect", "classload", "deserialize", "jndi", "ldap",
                "rmi", "jrmp", "remote", "ssrf", "network", "xxe", "sqli", "sql")) {
            return HIGH_RISK_TERMINAL;
        }
        if (isNativeApi(o, m) || o.startsWith("java/rmi/") || o.contains("/jndi/")
                || o.contains("jrmp") || o.contains("naming")) {
            return HIGH_RISK_TERMINAL;
        }
        if (containsAny(c, "command", "process", "exec", "file_write", "filesystem_write",
                "application_body", "controlled")) {
            return CONTROLLED_EFFECT;
        }
        if (o.equals("java/lang/runtime") && m.equals("exec")
                || o.equals("java/lang/processbuilder") && m.equals("start")) {
            return CONTROLLED_EFFECT;
        }
        return HIGH_RISK_TERMINAL;
    }

    /**
     * Apply an optional rule declaration without allowing a broad declaration to downgrade a
     * mechanically recognizable dangerous endpoint.  Explicit metadata may refine a generic
     * endpoint, but native loading, code loading, lookup and remote boundaries always retain the
     * conservative terminal classification.
     */
    public static SinkRisk resolve(SinkRisk declared, String category, String owner,
                                   String method) {
        SinkRisk inferred = infer(category, owner, method);
        if (inferred == HIGH_RISK_TERMINAL) {
            return HIGH_RISK_TERMINAL;
        }
        return declared == null ? inferred : declared;
    }

    private static boolean isNativeApi(String owner, String method) {
        return (owner.equals("java/lang/system") || owner.equals("java/lang/runtime")
                || owner.endsWith("/runtime"))
                && (method.equals("load") || method.equals("loadlibrary"));
    }

    private static boolean containsAny(String value, String... needles) {
        for (String needle : needles) {
            if (value.contains(needle)) {
                return true;
            }
        }
        return false;
    }

    private static String lower(String value) {
        return value == null ? "" : value.toLowerCase(Locale.ROOT);
    }
}
