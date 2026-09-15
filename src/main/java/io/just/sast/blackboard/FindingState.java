package io.just.sast.blackboard;

import java.util.List;
import java.util.Locale;
import java.util.Objects;

/**
 * The six independent axes of a product finding.
 *
 * <p>This is the typed seam for the static finding contract. It is deliberately not
 * derived from report prose or free-form notes.</p>
 */
public record FindingState(
        EntryStatus entryStatus,
        ChainProgress chainProgress,
        Feasibility feasibility,
        Completeness completeness,
        Risk risk) {

    /** Whether an execution root belongs to the target application and has external control. */
    public enum EntryStatus {
        NO_APPLICATION_ENTRY,
        APPLICATION_ENTRY,
        EXTERNAL_ENTRY;

        public static EntryStatus parse(String value) {
            return parse(value, false);
        }

        static EntryStatus parse(String value, boolean unknownAsNoEntry) {
            if (value == null || value.isBlank()) {
                return unknownAsNoEntry ? NO_APPLICATION_ENTRY :
                        throwUnknown("entry_status", value);
            }
            try {
                return valueOf(normalize(value));
            } catch (IllegalArgumentException ex) {
                if (unknownAsNoEntry) {
                    return NO_APPLICATION_ENTRY;
                }
                throw new IllegalArgumentException("unknown entry_status: " + value, ex);
            }
        }
    }

    /** Monotonic static chain progress; intermediate capabilities are not terminal impact. */
    public enum ChainProgress {
        ENTRY_IDENTIFIED,
        BOUNDARY_REACHED,
        DEPENDENCY_JOINED,
        IMPACT_CHAIN_COMPLETE;

        public boolean atLeast(ChainProgress other) {
            return ordinal() >= Objects.requireNonNull(other, "other").ordinal();
        }

        public static ChainProgress parse(String value) {
            return parseEnum("chain_progress", value, ChainProgress.class);
        }
    }

    /** Constraint result is independent from completeness. */
    public enum Feasibility {
        SAT,
        UNSAT,
        UNKNOWN;

        public static Feasibility parse(String value) {
            return parseEnum("feasibility", value, Feasibility.class);
        }
    }

    /** Whether all required static evidence for the requested chain has been accounted for. */
    public enum Completeness {
        COMPLETE,
        PARTIAL,
        UNKNOWN;

        public static Completeness parse(String value) {
            return parseEnum("completeness", value, Completeness.class);
        }
    }

    /** Risk is a presentation-independent axis; it is not a proxy for chain progress. */
    public enum Risk {
        NONE,
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL,
        UNKNOWN;

        public static Risk parse(String value) {
            return parseEnum("risk", value, Risk.class);
        }
    }

    /** Closed reason for default product export policy. */
    public enum Eligibility {
        ELIGIBLE_APPLICATION_CHAIN,
        NO_APPLICATION_ENTRY,
        APPLICATION_ENTRY_NOT_EXTERNAL,
        CHAIN_NOT_IMPACT_COMPLETE,
        CONSTRAINTS_UNSAT,
        CONSTRAINTS_UNKNOWN,
        ANALYSIS_INCOMPLETE,
        RISK_UNKNOWN,
        RISK_NOT_ACTIONABLE
    }

    public FindingState {
        entryStatus = Objects.requireNonNull(entryStatus, "entryStatus");
        chainProgress = Objects.requireNonNull(chainProgress, "chainProgress");
        feasibility = Objects.requireNonNull(feasibility, "feasibility");
        completeness = Objects.requireNonNull(completeness, "completeness");
        risk = Objects.requireNonNull(risk, "risk");
    }

    /** The only default export decision; ranking must not infer it from a score or note. */
    public Eligibility eligibility() {
        if (entryStatus == EntryStatus.NO_APPLICATION_ENTRY) {
            return Eligibility.NO_APPLICATION_ENTRY;
        }
        if (entryStatus != EntryStatus.EXTERNAL_ENTRY) {
            return Eligibility.APPLICATION_ENTRY_NOT_EXTERNAL;
        }
        if (feasibility == Feasibility.UNSAT) {
            return Eligibility.CONSTRAINTS_UNSAT;
        }
        if (feasibility != Feasibility.SAT) {
            return Eligibility.CONSTRAINTS_UNKNOWN;
        }
        if (chainProgress != ChainProgress.IMPACT_CHAIN_COMPLETE) {
            return Eligibility.CHAIN_NOT_IMPACT_COMPLETE;
        }
        if (completeness != Completeness.COMPLETE) {
            return Eligibility.ANALYSIS_INCOMPLETE;
        }
        if (risk == Risk.UNKNOWN) {
            return Eligibility.RISK_UNKNOWN;
        }
        if (risk == Risk.NONE) {
            return Eligibility.RISK_NOT_ACTIONABLE;
        }
        return Eligibility.ELIGIBLE_APPLICATION_CHAIN;
    }

    public boolean defaultFindingEligible() {
        return eligibility() == Eligibility.ELIGIBLE_APPLICATION_CHAIN;
    }

    public boolean applicationAnchored() {
        return entryStatus != EntryStatus.NO_APPLICATION_ENTRY;
    }

    public boolean dependencyJoined() {
        return chainProgress.atLeast(ChainProgress.DEPENDENCY_JOINED);
    }

    public boolean impactComplete() {
        return chainProgress == ChainProgress.IMPACT_CHAIN_COMPLETE;
    }

    /**
     * Validate the stricter default product export contract without rejecting
     * useful intermediate/kernel evidence at construction time.
     */
    public List<String> defaultFindingViolations() {
        java.util.ArrayList<String> errors = new java.util.ArrayList<>();
        if (entryStatus == EntryStatus.NO_APPLICATION_ENTRY) {
            errors.add("NO_APPLICATION_ENTRY");
        } else if (entryStatus != EntryStatus.EXTERNAL_ENTRY) {
            errors.add("EXTERNAL_CONTROL_UNPROVEN");
        }
        if (chainProgress != ChainProgress.IMPACT_CHAIN_COMPLETE) {
            errors.add("IMPACT_CHAIN_INCOMPLETE");
        }
        if (feasibility == Feasibility.UNSAT) {
            errors.add("CONSTRAINTS_UNSAT");
        } else if (feasibility != Feasibility.SAT) {
            errors.add("CONSTRAINTS_UNKNOWN");
        }
        if (completeness != Completeness.COMPLETE) {
            errors.add("ANALYSIS_INCOMPLETE");
        }
        if (risk == Risk.UNKNOWN) {
            errors.add("RISK_UNKNOWN");
        } else if (risk == Risk.NONE) {
            errors.add("RISK_NOT_ACTIONABLE");
        }
        return List.copyOf(errors);
    }

    /** Fail closed when a caller explicitly asks to publish a default finding. */
    public FindingState requireDefaultFinding() {
        List<String> violations = defaultFindingViolations();
        if (!violations.isEmpty()) {
            throw new IllegalStateException("default finding rejected: "
                    + String.join(",", violations));
        }
        return this;
    }

    /**
     * A strict adapter for old string producers.  It is intentionally explicit
     * and local; future producers must construct FindingState directly.
     */
    public static FindingState fromLegacy(String entry, String progress, String feasible,
                                           String complete, String risk) {
        return new FindingState(
                EntryStatus.parse(entry),
                ChainProgress.parse(progress),
                Feasibility.parse(feasible),
                Completeness.parse(complete),
                Risk.parse(risk));
    }

    private static String normalize(String value) {
        return value.trim().toUpperCase(Locale.ROOT).replace('-', '_');
    }

    private static <E extends Enum<E>> E parseEnum(String axis, String value, Class<E> type) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("missing " + axis);
        }
        try {
            return Enum.valueOf(type, normalize(value));
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException("unknown " + axis + ": " + value, ex);
        }
    }

    private static <E> E throwUnknown(String axis, String value) {
        throw new IllegalArgumentException("missing " + axis + ": " + value);
    }
}
