package io.just.sast.cli;

import java.util.Objects;
import java.util.Set;

/**
 * Immutable policy for the two product scan modes.
 *
 * <p>The mode owns the demand boundary and export rule together.  Keeping these decisions in
 * one value prevents a caller from accidentally combining component demand with application
 * export (or the reverse), which was the source of several compatibility seams during the
 * migration.  It does not change the solver: it only tells the pipeline which already-parsed
 * classes represent an application execution scope and which finding boundary is requested.</p>
 */
public record ModeDemandPolicy(ScanMode mode) {

    public ModeDemandPolicy {
        mode = Objects.requireNonNull(mode, "mode");
    }

    public static ModeDemandPolicy forMode(ScanMode mode) {
        return new ModeDemandPolicy(mode);
    }

    /** Compatibility mapping for library callers that still pass the old export enum. */
    public static ModeDemandPolicy fromExportPolicy(ScanPipeline.ExportPolicy policy) {
        Objects.requireNonNull(policy, "policy");
        return new ModeDemandPolicy(policy == ScanPipeline.ExportPolicy.STRICT_PRODUCT
                ? ScanMode.APPLICATION : ScanMode.COMPONENT);
    }

    /** Component mode keeps kernel candidates; application mode requires a real join to export. */
    public boolean retainKernelCandidates() {
        return mode == ScanMode.COMPONENT;
    }

    /** Whether the target artifact is an application-owned execution scope. */
    public boolean applicationScopeKnown() {
        return mode == ScanMode.APPLICATION;
    }

    /**
     * The shared static solver knows which classes belong to the scanned target in both modes.
     * Application provenance is gated separately by {@link #applicationScopeKnown()} and
     * {@link #requireApplicationJoin()} so component roots can seed mechanism analysis without
     * being rendered as application findings.
     */
    public boolean solverScopeKnown() {
        return true;
    }

    /** Application reports use the typed entry/site/join/terminal export contract. */
    public boolean requireApplicationJoin() {
        return mode == ScanMode.APPLICATION;
    }

    public ScanPipeline.ExportPolicy exportPolicy() {
        return requireApplicationJoin() ? ScanPipeline.ExportPolicy.STRICT_PRODUCT
                : ScanPipeline.ExportPolicy.AUDIT_COMPATIBILITY;
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
