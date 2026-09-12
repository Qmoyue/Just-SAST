package io.just.sast.blackboard;

import java.util.Objects;

/** Immutable identity and resource envelope for one dynamic verification attempt. */
public record VerificationAttempt(
        AttemptId id,
        String chainKey,
        int attempt,
        long durationMs,
        VerificationOutcome outcome) implements BlackboardFact {

    public VerificationAttempt {
        chainKey = requireText("chainKey", chainKey);
        if (attempt < 1) {
            throw new IllegalArgumentException("attempt must be positive");
        }
        if (durationMs < 0L) {
            throw new IllegalArgumentException("durationMs must not be negative");
        }
        outcome = Objects.requireNonNull(outcome, "outcome");
        AttemptId expected = AttemptId.fromCanonical(chainKey, Integer.toString(attempt));
        id = id == null ? expected : Objects.requireNonNull(id, "id");
        if (!expected.equals(id)) {
            throw new IllegalArgumentException("attempt id does not match chain and ordinal");
        }
    }

    public static VerificationAttempt fromLegacy(String chainKey, int attempt, long durationMs,
                                                 String status, String detail, String evidence) {
        return new VerificationAttempt(null, chainKey, attempt, durationMs,
                VerificationOutcome.fromLegacy(status, detail, evidence));
    }

    private static String requireText(String field, String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
        return value;
    }
}
