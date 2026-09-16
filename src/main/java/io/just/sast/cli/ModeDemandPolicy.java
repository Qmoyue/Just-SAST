package io.just.sast.cli;

import java.util.Objects;
import java.util.Set;

/**
 * Immutable policy for the two product scan modes.
 *
 * <p>The mode owns the demand boundary and application export requirement together. It does not
 * change the solver: it tells the pipeline which already-parsed classes represent an application
 * execution scope and which finding boundary is requested.</p>
 */
public record ModeDemandPolicy(ScanMode mode) {

    public ModeDemandPolicy {
        mode = Objects.requireNonNull(mode, "mode");
    }

    public static ModeDemandPolicy forMode(ScanMode mode) {
        return new ModeDemandPolicy(mode);
    }

    /** Whether the target artifact is an application-owned execution scope. */
    public boolean applicationScopeKnown() {
        return mode == ScanMode.APPLICATION;
    }

    /** Application reports use the typed entry/site/join/terminal export contract. */
    public boolean requireApplicationJoin() {
        return mode == ScanMode.APPLICATION;
    }

    /**
     * Select graph demand roots without changing artifact ownership.  Component roots are still
     * retained by the frontend for mechanism analysis, but are not advertised as application
     * entries to the application joiner.
     */
    public Set<String> demandRootClasses(Set<String> targetClasses) {
        if (targetClasses == null || targetClasses.isEmpty()) {
            return Set.of();
        }
        return Set.copyOf(targetClasses);
    }

    /**
     * Preserve target ownership for the shared solver in both modes.  The separate
     * {@link #applicationScopeKnown()} bit is what prevents component roots from becoming
     * application-entry evidence at the join/export boundary.
     */
    public Set<String> applicationClassNames(Set<String> targetClasses) {
        return demandRootClasses(targetClasses);
    }

    public String wireName() {
        return mode.name().toLowerCase(java.util.Locale.ROOT);
    }
}
