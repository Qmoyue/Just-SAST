package io.just.sast.knowledge.engine;

/**
 * Typed owner for forward run counters, version clocks and the method worklist.
 *
 * <p>The store deliberately does not own taint facts or evidence.  Those migrations have
 * separate characterization seams; this first state extraction only makes scheduling and
 * budget accounting observable without changing solver truth.  Version clocks are monotonic
 * across repeated engine runs, while per-run counters are reset by {@link #beginRun()}.</p>
 */
public final class ForwardStateStore {
    public record Budget(int stepLimit, int methodPassLimit, int roundLimit) {
        public Budget {
            if (stepLimit <= 0 || methodPassLimit <= 0 || roundLimit <= 0) {
                throw new IllegalArgumentException("forward budget limits must be positive");
            }
        }
    }

    public record Snapshot(Budget budget, long factVersion, long primaryFactVersion,
                           long candidateFactVersion, long steps, long methodPasses,
                           long rounds, long factCount, long primaryFactUpdates,
                           long alternativeFactUpdates,
                           ForwardWorklist.Snapshot worklist) {
        public Snapshot {
            if (budget == null || worklist == null) {
                throw new IllegalArgumentException("missing forward state snapshot component");
            }
            if (factVersion < 0 || primaryFactVersion < 0 || candidateFactVersion < 0
                    || steps < 0 || methodPasses < 0 || rounds < 0 || factCount < 0
                    || primaryFactUpdates < 0 || alternativeFactUpdates < 0) {
                throw new IllegalArgumentException("negative forward state counter");
            }
        }
    }

    private static final Budget DEFAULT_BUDGET = new Budget(20_000_000, 1_000_000, 32);
    private final ForwardWorklist worklist = new ForwardWorklist();
    private Budget budget = DEFAULT_BUDGET;
    private long factVersion;
    private long primaryFactVersion;
    private long candidateFactVersion;
    private long steps;
    private long methodPasses;
    private long rounds;
    private long factCount;
    private long primaryFactUpdates;
    private long alternativeFactUpdates;

    /** Reset per-run work counters without invalidating monotonic fact versions. */
    public void beginRun() {
        steps = 0;
        methodPasses = 0;
        rounds = 0;
        factCount = 0;
        primaryFactUpdates = 0;
        alternativeFactUpdates = 0;
    }

    public void configureBudget(int stepLimit, int methodPassLimit, int roundLimit) {
        budget = new Budget(stepLimit, methodPassLimit, roundLimit);
    }

    public ForwardWorklist worklist() {
        return worklist;
    }

    public void recordStep() {
        steps++;
    }

    public void recordMethodPass() {
        methodPasses++;
    }

    public void recordRound() {
        rounds++;
    }

    public void recordPrimaryFact() {
        factVersion++;
        primaryFactVersion++;
        primaryFactUpdates++;
        factCount++;
    }

    public void recordAlternativeFact() {
        factVersion++;
        candidateFactVersion++;
        alternativeFactUpdates++;
        factCount++;
    }

    /** Whether another fixed-point round is allowed under the configured limits. */
    public boolean withinBudget(int rounds) {
        return rounds >= 0 && steps < budget.stepLimit() && methodPasses < budget.methodPassLimit()
                && rounds < budget.roundLimit();
    }

    public boolean stepLimitReached() {
        return steps >= budget.stepLimit();
    }

    public boolean methodPassLimitReached() {
        return methodPasses >= budget.methodPassLimit();
    }

    public Budget budget() {
        return budget;
    }

    public long factVersion() {
        return factVersion;
    }

    public long primaryFactVersion() {
        return primaryFactVersion;
    }

    public long candidateFactVersion() {
        return candidateFactVersion;
    }

    public long steps() {
        return steps;
    }

    public long methodPasses() {
        return methodPasses;
    }

    public long rounds() {
        return rounds;
    }

    public long factCount() {
        return factCount;
    }

    public long primaryFactUpdates() {
        return primaryFactUpdates;
    }

    public long alternativeFactUpdates() {
        return alternativeFactUpdates;
    }

    public Snapshot snapshot() {
        return new Snapshot(budget, factVersion, primaryFactVersion, candidateFactVersion,
                steps, methodPasses, rounds, factCount, primaryFactUpdates,
                alternativeFactUpdates, worklist.snapshot());
    }
}
