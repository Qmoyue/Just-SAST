package io.just.sast.run;

import java.util.Locale;

/** Closed result for input/verification budget accounting. */
public record InputBudgetResult(State state, long limit, long consumed, String reasonCode) {

    public enum State {
        NOT_REQUESTED,
        WITHIN_LIMIT,
        EXHAUSTED,
        INVALID,
        UNKNOWN
    }

    public InputBudgetResult {
        state = state == null ? State.UNKNOWN : state;
        limit = limit < 0L ? -1L : limit;
        consumed = consumed < 0L ? -1L : consumed;
        reasonCode = normalize(reasonCode);
        if (state == State.WITHIN_LIMIT && limit >= 0L && consumed >= 0L && consumed > limit) {
            state = State.EXHAUSTED;
            reasonCode = "CONSUMED_EXCEEDS_LIMIT";
        }
        if (state == State.NOT_REQUESTED) {
            limit = -1L;
            consumed = 0L;
        }
    }

    public static InputBudgetResult notRequested() {
        return new InputBudgetResult(State.NOT_REQUESTED, -1L, 0L, "NOT_REQUESTED");
    }

    public static InputBudgetResult within(long limit, long consumed) {
        if (limit < 0L || consumed < 0L) {
            return invalid("NEGATIVE_BUDGET");
        }
        return consumed > limit
                ? exhausted(limit, consumed, "CONSUMED_EXCEEDS_LIMIT")
                : new InputBudgetResult(State.WITHIN_LIMIT, limit, consumed, "WITHIN_LIMIT");
    }

    public static InputBudgetResult exhausted(long limit, long consumed, String reasonCode) {
        return new InputBudgetResult(State.EXHAUSTED, limit, consumed,
                reasonCode == null ? "BUDGET_EXHAUSTED" : reasonCode);
    }

    public static InputBudgetResult invalid(String reasonCode) {
        return new InputBudgetResult(State.INVALID, -1L, -1L,
                reasonCode == null ? "INVALID_BUDGET" : reasonCode);
    }

    public static InputBudgetResult unknown(String reasonCode) {
        return new InputBudgetResult(State.UNKNOWN, -1L, -1L,
                reasonCode == null ? "UNKNOWN_BUDGET" : reasonCode);
    }

    /** Only these states are safe to reuse for a cache/report gate. */
    public boolean reusable() {
        return state == State.NOT_REQUESTED || state == State.WITHIN_LIMIT;
    }

    public String toCanonicalJson() {
        return "{\"state\":\"" + state.name() + "\",\"limit\":" + limit
                + ",\"consumed\":" + consumed + ",\"reason_code\":\""
                + escape(reasonCode) + "\"}";
    }

    private static String normalize(String value) {
        if (value == null || value.isBlank()) {
            return "UNKNOWN";
        }
        return value.trim().toUpperCase(Locale.ROOT);
    }

    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\r", "\\r").replace("\n", "\\n");
    }
}
