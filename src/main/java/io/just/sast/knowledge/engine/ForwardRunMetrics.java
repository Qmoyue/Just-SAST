package io.just.sast.knowledge.engine;

import io.just.sast.blackboard.BlackboardFact;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Immutable, report-facing telemetry for one forward fixed-point pass.
 *
 * <p>The record is a blackboard fact rather than a mutable field on {@code Blackboard}; this
 * keeps the solver's counters owned by {@link ForwardStateStore} while giving report consumers
 * a stable typed boundary.  Byte counts are explicitly structural estimates, never process
 * RSS or a claim about JVM retained size.</p>
 */
public record ForwardRunMetrics(
        Pass pass,
        boolean interrupted,
        int stepLimit,
        int methodPassLimit,
        int roundLimit,
        long factVersion,
        long primaryFactVersion,
        long candidateFactVersion,
        long steps,
        long methodPasses,
        long rounds,
        long factCount,
        long primaryFactUpdates,
        long alternativeFactUpdates,
        int pendingWorkItems,
        long acceptedWorkItems,
        long duplicateWorkItems,
        long consumedWorkItems,
        int peakPendingWorkItems,
        long peakPendingKeyChars,
        long estimatedStateBytes
) implements BlackboardFact {

    public enum Pass {
        COARSE,
        REFINED,
        UNKNOWN
    }

    public ForwardRunMetrics {
        pass = pass == null ? Pass.UNKNOWN : pass;
        if (stepLimit <= 0 || methodPassLimit <= 0 || roundLimit <= 0) {
            throw new IllegalArgumentException("forward metric budgets must be positive");
        }
        requireNonNegative(factVersion, "factVersion");
        requireNonNegative(primaryFactVersion, "primaryFactVersion");
        requireNonNegative(candidateFactVersion, "candidateFactVersion");
        requireNonNegative(steps, "steps");
        requireNonNegative(methodPasses, "methodPasses");
        requireNonNegative(rounds, "rounds");
        requireNonNegative(factCount, "factCount");
        requireNonNegative(primaryFactUpdates, "primaryFactUpdates");
        requireNonNegative(alternativeFactUpdates, "alternativeFactUpdates");
        if (pendingWorkItems < 0 || peakPendingWorkItems < pendingWorkItems) {
            throw new IllegalArgumentException("invalid forward work item counts");
        }
        requireNonNegative(acceptedWorkItems, "acceptedWorkItems");
        requireNonNegative(duplicateWorkItems, "duplicateWorkItems");
        requireNonNegative(consumedWorkItems, "consumedWorkItems");
        requireNonNegative(peakPendingKeyChars, "peakPendingKeyChars");
        requireNonNegative(estimatedStateBytes, "estimatedStateBytes");
    }

    /** Convert one immutable state snapshot without exposing engine internals to reports. */
    public static ForwardRunMetrics from(ForwardStateStore.Snapshot snapshot, Pass pass,
                                         boolean interrupted) {
        if (snapshot == null) {
            throw new IllegalArgumentException("forward state snapshot is required");
        }
        ForwardWorklist.Snapshot worklist = snapshot.worklist();
        return new ForwardRunMetrics(pass, interrupted,
                snapshot.budget().stepLimit(), snapshot.budget().methodPassLimit(),
                snapshot.budget().roundLimit(), snapshot.factVersion(),
                snapshot.primaryFactVersion(), snapshot.candidateFactVersion(), snapshot.steps(),
                snapshot.methodPasses(), snapshot.rounds(), snapshot.factCount(),
                snapshot.primaryFactUpdates(), snapshot.alternativeFactUpdates(),
                worklist.pendingCount(), worklist.acceptedOffers(), worklist.duplicateOffers(),
                worklist.consumedItems(), worklist.peakPending(), worklist.peakPendingKeyChars(),
                estimateStateBytes(snapshot));
    }

    /** Flat metric aliases used by ScanStatistics; availability is supplied separately. */
    public Map<String, Long> asMetrics() {
        Map<String, Long> metrics = new LinkedHashMap<>();
        metrics.put("forward_fact_version", factVersion);
        metrics.put("forward_primary_fact_version", primaryFactVersion);
        metrics.put("forward_candidate_fact_version", candidateFactVersion);
        metrics.put("forward_steps", steps);
        metrics.put("forward_method_passes", methodPasses);
        metrics.put("forward_rounds", rounds);
        metrics.put("forward_fact_count", factCount);
        metrics.put("forward_primary_fact_updates", primaryFactUpdates);
        metrics.put("forward_alternative_fact_updates", alternativeFactUpdates);
        metrics.put("forward_worklist_pending", (long) pendingWorkItems);
        metrics.put("forward_worklist_accepted", acceptedWorkItems);
        metrics.put("forward_worklist_duplicates", duplicateWorkItems);
        metrics.put("forward_worklist_consumed", consumedWorkItems);
        metrics.put("forward_worklist_peak_pending", (long) peakPendingWorkItems);
        metrics.put("forward_worklist_peak_key_chars", peakPendingKeyChars);
        metrics.put("forward_state_bytes_estimate", estimatedStateBytes);
        metrics.put("forward_step_limit", (long) stepLimit);
        metrics.put("forward_method_pass_limit", (long) methodPassLimit);
        metrics.put("forward_round_limit", (long) roundLimit);
        return Map.copyOf(metrics);
    }

    public static List<String> metricNames() {
        return List.of("forward_fact_version", "forward_primary_fact_version",
                "forward_candidate_fact_version", "forward_steps", "forward_method_passes",
                "forward_rounds", "forward_fact_count", "forward_primary_fact_updates",
                "forward_alternative_fact_updates", "forward_worklist_pending",
                "forward_worklist_accepted", "forward_worklist_duplicates",
                "forward_worklist_consumed", "forward_worklist_peak_pending",
                "forward_worklist_peak_key_chars", "forward_state_bytes_estimate",
                "forward_step_limit", "forward_method_pass_limit", "forward_round_limit");
    }

    private static long estimateStateBytes(ForwardStateStore.Snapshot snapshot) {
        ForwardWorklist.Snapshot worklist = snapshot.worklist();
        long counters = 16L + 12L + 13L * Long.BYTES;
        long queue = 24L + 8L * worklist.peakPending()
                + 24L * worklist.peakPending() + 2L * worklist.peakPendingKeyChars();
        return safeAdd(counters, queue);
    }

    private static long safeAdd(long left, long right) {
        if (right > 0L && left > Long.MAX_VALUE - right) {
            return Long.MAX_VALUE;
        }
        return left + right;
    }

    private static void requireNonNegative(long value, String name) {
        if (value < 0L) {
            throw new IllegalArgumentException(name + " must be non-negative");
        }
    }
}
