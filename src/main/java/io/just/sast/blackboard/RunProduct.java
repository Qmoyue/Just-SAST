package io.just.sast.blackboard;

/**
 * Closed vocabulary of products exchanged during one scan run.
 *
 * <p>Products describe phase boundaries, not individual implementation classes.  The
 * chain products are append-only because several independent knowledge sources contribute
 * facts to the single {@link ChainStore} owner.  Other products have one producer and are
 * rejected when a second producer is declared.</p>
 */
public enum RunProduct {
    /** The immutable graph, hierarchy, rules and scan inputs supplied before analysis. */
    PROGRAM_MODEL(false, true),
    /** Sink/entry analysis candidates emitted by analysis knowledge sources. */
    ANALYSIS_CHAINS(true, false),
    /** Object-graph and dependency fragments assembled after analysis. */
    COMPOSED_CHAINS(true, false),
    /** Constraint, trigger and configuration calibration results. */
    CALIBRATED_CHAINS(true, false),
    /** The one typed dynamic-verification result stream for this run. */
    VERIFICATION_RESULTS(false, false);

    private final boolean appendOnly;
    private final boolean initiallyAvailable;

    RunProduct(boolean appendOnly, boolean initiallyAvailable) {
        this.appendOnly = appendOnly;
        this.initiallyAvailable = initiallyAvailable;
    }

    /** Whether multiple source contributions may be merged by the single product owner. */
    public boolean appendOnly() {
        return appendOnly;
    }

    /** Whether the product exists before any knowledge source is initialized. */
    public boolean initiallyAvailable() {
        return initiallyAvailable;
    }
}
