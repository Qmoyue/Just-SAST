package io.just.sast.analysis.taint;

import java.util.Locale;

/**
 * Closed result vocabulary for local path/filter refinements.
 *
 * <p>A filter may reject a path only on a proof.  Missing facts, unsupported bytecode and a
 * consumed budget remain explicit unknowns; they are never represented by a false boolean
 * that callers could accidentally interpret as a contradiction.</p>
 */
public final class FilterAnalysis {

    public enum Kind {
        CFG_PATH,
        EXCEPTION_HANDLER,
        REFLECTIVE_INVOCATION,
        COLLECTION_GUARD
    }

    public enum Status {
        KEEP,
        PROVABLY_UNREACHABLE,
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

    private FilterAnalysis() {
    }

    public static Decision cfgPath(boolean unreachable, boolean budgetExceeded) {
        if (unreachable) {
            return new Decision(Kind.CFG_PATH, Status.PROVABLY_UNREACHABLE,
                    "CFG_EXACT_PATH_UNREACHABLE");
        }
        if (budgetExceeded) {
            return new Decision(Kind.CFG_PATH, Status.BUDGET_EXCEEDED,
                    "CFG_PROOF_BUDGET_EXCEEDED");
        }
        return new Decision(Kind.CFG_PATH, Status.KEEP, "CFG_PATH_PRESERVED");
    }

    public static Decision exceptionHandler(boolean unreachable) {
        return unreachable
                ? new Decision(Kind.EXCEPTION_HANDLER, Status.PROVABLY_UNREACHABLE,
                "EXCEPTION_HANDLER_UNREACHABLE")
                : new Decision(Kind.EXCEPTION_HANDLER, Status.KEEP,
                "EXCEPTION_HANDLER_PRESERVED");
    }

    public static Decision reflectiveInvocation(boolean mayReach) {
        return mayReach
                ? new Decision(Kind.REFLECTIVE_INVOCATION, Status.KEEP,
                "REFLECTIVE_PRECONDITION_UNKNOWN_OR_SAT")
                : new Decision(Kind.REFLECTIVE_INVOCATION, Status.PROVABLY_UNREACHABLE,
                "REFLECTIVE_PRECONDITION_UNSAT");
    }

    public static Decision unknown(Kind kind, String reasonCode) {
        return new Decision(kind, Status.UNKNOWN, reasonCode);
    }

    private static String normalize(String value) {
        if (value == null || value.isBlank()) {
            return "UNKNOWN_FILTER_REASON";
        }
        return value.trim().toUpperCase(Locale.ROOT);
    }
}
