package io.just.sast.verify;

import io.just.sast.blackboard.BlackboardFact;
import io.just.sast.blackboard.Chain;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

/**
 * Immutable plan produced before a dynamic verifier opens a target classpath.
 *
 * <p>The plan is intentionally a selection snapshot, not a verification result.  It records
 * how many candidates entered/deduplicated the bounded planner and the exact ordered candidates
 * that the scheduler may attempt.  Dynamic status, safety and terminal evidence remain owned by
 * {@link io.just.sast.blackboard.VerificationOutcome} and are never inferred from this record.</p>
 */
public record VerificationPlan(
        int requestedBudget,
        int inputCount,
        int uniqueCount,
        List<Chain> selectedChains,
        Map<String, Integer> selectedQuotaCounts,
        String reasonCode,
        String digest) implements BlackboardFact {

    public VerificationPlan {
        if (requestedBudget < 0) {
            throw new IllegalArgumentException("requestedBudget must not be negative");
        }
        if (inputCount < 0 || uniqueCount < 0 || uniqueCount > inputCount) {
            throw new IllegalArgumentException("invalid candidate counts");
        }
        selectedChains = selectedChains == null ? List.of() : List.copyOf(selectedChains);
        if (selectedChains.size() > requestedBudget || selectedChains.size() > uniqueCount) {
            throw new IllegalArgumentException("selected candidates exceed plan bounds");
        }
        Map<String, Integer> quotas = new TreeMap<>();
        if (selectedQuotaCounts != null) {
            selectedQuotaCounts.forEach((key, value) -> {
                if (key != null && !key.isBlank() && value != null && value > 0) {
                    quotas.put(key, value);
                }
            });
        }
        selectedQuotaCounts = Collections.unmodifiableMap(quotas);
        reasonCode = normalize(reasonCode, selectedChains.isEmpty() ? "EMPTY" : "SELECTED");
        digest = normalize(digest, "EMPTY");
    }

    public int selectedCount() {
        return selectedChains.size();
    }

    /** Ordered keys are the scheduler identity and preserve deterministic selection order. */
    public List<String> selectedKeys() {
        List<String> keys = new ArrayList<>(selectedChains.size());
        for (Chain chain : selectedChains) {
            if (chain != null) {
                keys.add(chain.key());
            }
        }
        return List.copyOf(keys);
    }

    public boolean isEmpty() {
        return selectedChains.isEmpty();
    }

    public static VerificationPlan empty(int requestedBudget) {
        return new VerificationPlan(Math.max(0, requestedBudget), 0, 0,
                List.of(), Map.of(), "EMPTY", "EMPTY");
    }

    private static String normalize(String value, String fallback) {
        return value == null || value.isBlank() ? Objects.requireNonNull(fallback) : value;
    }
}
