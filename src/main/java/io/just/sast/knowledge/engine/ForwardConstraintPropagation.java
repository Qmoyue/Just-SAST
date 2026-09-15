package io.just.sast.knowledge.engine;

import io.just.sast.analysis.taint.FilterAnalysis;

/**
 * Converts a typed local feasibility decision into the forward solver's propagation outcome.
 * Unknown and budget-exhausted filters preserve a conservative candidate; only an independently
 * proven unreachable path blocks propagation.  This prevents a diagnostic string or a verifier
 * boundary from silently becoming a false negative.
 */
public final class ForwardConstraintPropagation {
    public enum Status {
        PROPAGATE,
        BLOCKED,
        UNKNOWN
    }

    public record Decision(Status status, FilterAnalysis.Decision filterDecision,
                           String reasonCode) {
        public Decision {
            status = status == null ? Status.UNKNOWN : status;
            reasonCode = reasonCode == null || reasonCode.isBlank()
                    ? "FORWARD_CONSTRAINT_UNKNOWN" : reasonCode;
        }

        public boolean blocksPath() {
            return status == Status.BLOCKED;
        }

        public boolean preservesCandidate() {
            return status != Status.BLOCKED;
        }
    }

    private ForwardConstraintPropagation() {
    }

    public static Decision from(FilterAnalysis.Decision decision) {
        if (decision == null) {
            return new Decision(Status.UNKNOWN, null, "FORWARD_CONSTRAINT_UNKNOWN");
        }
        if (decision.status() == FilterAnalysis.Status.PROVABLY_UNREACHABLE) {
            return new Decision(Status.BLOCKED, decision, decision.reasonCode());
        }
        if (decision.status() == FilterAnalysis.Status.PROVEN_RETAINED) {
            return new Decision(Status.PROPAGATE, decision, decision.reasonCode());
        }
        return new Decision(Status.UNKNOWN, decision, decision.reasonCode());
    }
}
