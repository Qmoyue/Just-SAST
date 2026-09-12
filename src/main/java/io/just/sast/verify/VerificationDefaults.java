package io.just.sast.verify;

/**
 * Product defaults for the lightweight second-pass verifier.
 *
 * <p>The value is deliberately owned in one place so the scan CLI, performance command and
 * compatibility callers cannot silently drift.  It is still only a finite upper bound: an
 * explicit {@code --verify-budget} remains authoritative, and static analysis never depends on
 * the dynamic budget.</p>
 */
public final class VerificationDefaults {

    /** Default number of normalized application finding groups eligible for dynamic attempts. */
    public static final int VERIFY_BUDGET = 32;

    /** Picocli annotation-safe representation of {@link #VERIFY_BUDGET}. */
    public static final String VERIFY_BUDGET_TEXT = "32";

    private VerificationDefaults() {
    }
}
