package io.just.sast.analysis.taint;

import java.util.Locale;
import java.util.Objects;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Closed result vocabulary for local path/filter refinements.
 *
 * <p>A filter may reject a path only on a proof.  Missing facts, unsupported bytecode and a
 * consumed budget remain explicit unknowns; they are never represented by a false boolean
 * that callers could accidentally interpret as a contradiction.</p>
 */
public final class FilterAnalysis {

    /** Semantic version is part of every finite-filter cache/evidence identity. */
    public static final String SEMANTICS_VERSION = "bounded-static-filter-v2";
    public static final String SEMANTICS_DIGEST = digest(SEMANTICS_VERSION);

    public enum Kind {
        CFG_PATH,
        EXCEPTION_HANDLER,
        REFLECTIVE_INVOCATION,
        COLLECTION_GUARD
    }

    public enum Status {
        PROVABLY_UNREACHABLE,
        PROVEN_RETAINED,
        UNKNOWN,
        BUDGET_EXCEEDED
    }

    public record Decision(Kind kind, Status status, String reasonCode) {
        public Decision {
            kind = kind == null ? Kind.CFG_PATH : kind;
            status = status == null ? Status.UNKNOWN : status;
            reasonCode = normalize(reasonCode);
        }

        public boolean rejectsPath() {
            return status == Status.PROVABLY_UNREACHABLE;
        }

        public boolean preservesPath() {
            return status != Status.PROVABLY_UNREACHABLE;
        }

        public boolean isUnknown() {
            return status == Status.UNKNOWN || status == Status.BUDGET_EXCEEDED;
        }
    }

    /**
     * One deterministic hotspot observation.  Counts describe only the bounded local proof;
     * they are never a claim about the complete chain.  {@code filterCostNanos} is additive
     * analysis time, not a wall-clock measurement of the whole scan.
     */
    public record Evidence(Kind kind, String location, Status status, String reasonCode,
                           String domainDigest, String semanticDigest, int budget,
                           long evaluated, long retained, long rejected, long expanded,
                           long filterCostNanos) {
        public Evidence {
            kind = Objects.requireNonNull(kind, "filter evidence kind");
            status = Objects.requireNonNull(status, "filter evidence status");
            location = text(location);
            reasonCode = normalize(reasonCode);
            domainDigest = text(domainDigest);
            semanticDigest = text(semanticDigest);
            if (budget < 0 || evaluated < 0L || retained < 0L || rejected < 0L
                    || expanded < 0L || filterCostNanos < 0L) {
                throw new IllegalArgumentException("filter evidence counts must be non-negative");
            }
        }

        private static String text(String value) {
            return value == null || value.isBlank()
                    ? "UNKNOWN" : value.trim();
        }

        private static String normalize(String value) {
            return text(value).toUpperCase(Locale.ROOT);
        }
    }

    private FilterAnalysis() {
    }

    public static Decision cfgPath(boolean unreachable, boolean budgetExceeded) {
        return cfgPath(unreachable, budgetExceeded, true);
    }

    /** Build a CFG decision when the caller can state whether a finite proof completed. */
    public static Decision cfgPath(boolean unreachable, boolean budgetExceeded,
                                   boolean proofCompleted) {
        if (unreachable) {
            return new Decision(Kind.CFG_PATH, Status.PROVABLY_UNREACHABLE,
                    "CFG_EXACT_PATH_UNREACHABLE");
        }
        if (budgetExceeded) {
            return new Decision(Kind.CFG_PATH, Status.BUDGET_EXCEEDED,
                    "CFG_PROOF_BUDGET_EXCEEDED");
        }
        return proofCompleted
                ? new Decision(Kind.CFG_PATH, Status.PROVEN_RETAINED, "CFG_PATH_PRESERVED")
                : new Decision(Kind.CFG_PATH, Status.UNKNOWN, "CFG_PROOF_NOT_APPLICABLE");
    }

    public static Decision exceptionHandler(boolean unreachable) {
        return unreachable
                ? new Decision(Kind.EXCEPTION_HANDLER, Status.PROVABLY_UNREACHABLE,
                "EXCEPTION_HANDLER_UNREACHABLE")
                : new Decision(Kind.EXCEPTION_HANDLER, Status.PROVEN_RETAINED,
                "EXCEPTION_HANDLER_PRESERVED");
    }

    public static Decision reflectiveInvocation(boolean mayReach) {
        return mayReach
                ? new Decision(Kind.REFLECTIVE_INVOCATION, Status.UNKNOWN,
                "REFLECTIVE_PRECONDITION_UNKNOWN_OR_SAT")
                : new Decision(Kind.REFLECTIVE_INVOCATION, Status.PROVABLY_UNREACHABLE,
                "REFLECTIVE_PRECONDITION_UNSAT");
    }

    public static Decision unknown(Kind kind, String reasonCode) {
        return new Decision(kind, Status.UNKNOWN, reasonCode);
    }

    /** Stable identity for the finite domain owned by one local hotspot. */
    public static String domainDigest(Kind kind, String location, String operation) {
        String value = SEMANTICS_VERSION + "|" + (kind == null ? "UNKNOWN" : kind.name())
                + "|" + normalize(location) + "|" + normalize(operation);
        return digest(value);
    }

    private static String digest(String value) {
        try {
            byte[] bytes = MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder result = new StringBuilder(bytes.length * 2);
            for (byte item : bytes) {
                result.append(String.format(Locale.ROOT, "%02x", item & 0xff));
            }
            return result.toString();
        } catch (NoSuchAlgorithmException error) {
            throw new IllegalStateException("SHA-256 is required for filter identity", error);
        }
    }

    private static String normalize(String value) {
        if (value == null || value.isBlank()) {
            return "UNKNOWN_FILTER_REASON";
        }
        return value.trim().toUpperCase(Locale.ROOT);
    }
}
