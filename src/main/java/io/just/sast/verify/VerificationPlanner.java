package io.just.sast.verify;

import io.just.sast.blackboard.Chain;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.function.ToIntFunction;

/**
 * Deterministic bounded dynamic-plan builder.  The verifier supplies only policy predicates and
 * scoring functions; candidate de-duplication, quota accounting and immutable plan construction
 * have one owner here so a future shared VerificationPlan cannot drift from legacy selection.
 */
public final class VerificationPlanner {

    private final int maxPerQuota;
    private final int primaryBudgetDivisor;

    public VerificationPlanner() {
        this(2, 4);
    }

    VerificationPlanner(int maxPerQuota, int primaryBudgetDivisor) {
        if (maxPerQuota < 1 || primaryBudgetDivisor < 1) {
            throw new IllegalArgumentException("planner limits must be positive");
        }
        this.maxPerQuota = maxPerQuota;
        this.primaryBudgetDivisor = primaryBudgetDivisor;
    }

    /**
     * Build one bounded plan.  Null/invalid input is an explicit empty plan and never a reason to
     * remove static findings.  All callbacks are invoked only after basic bounds are validated.
     */
    public VerificationPlan plan(List<Chain> candidates,
                                 int maxTotal,
                                 Set<String> constructibleKeys,
                                 Predicate<Chain> primaryPredicate,
                                 ToIntFunction<Chain> priority,
                                 Comparator<Chain> ranking,
                                 Function<Chain, String> quotaKey) {
        if (candidates == null || candidates.isEmpty() || maxTotal <= 0) {
            return VerificationPlan.empty(maxTotal);
        }
        if (primaryPredicate == null || priority == null || ranking == null || quotaKey == null) {
            throw new IllegalArgumentException("planner policy callbacks must not be null");
        }
        Set<String> constructible = constructibleKeys == null ? Set.of()
                : constructibleKeys.stream().filter(value -> value != null && !value.isBlank())
                .collect(java.util.stream.Collectors.toUnmodifiableSet());

        // A knowledge source may publish equivalent candidates from concurrent workers. Keep the
        // least-unresolved deterministic representative before applying the finite budget.
        Map<String, Chain> unique = new TreeMap<>();
        for (Chain candidate : candidates) {
            if (candidate == null) {
                continue;
            }
            String key = candidate.key();
            Chain previous = unique.get(key);
            if (previous == null || equivalentCandidateOrder(candidate, previous) < 0) {
                unique.put(key, candidate);
            }
        }
        if (unique.isEmpty()) {
            return new VerificationPlan(maxTotal, candidates.size(), 0,
                    List.of(), Map.of(), "NO_VALID_CANDIDATE", digest(maxTotal, candidates.size(), 0,
                    List.of(), constructible));
        }

        List<Chain> sorted = new ArrayList<>(unique.values());
        Map<Chain, Integer> priorities = new java.util.IdentityHashMap<>();
        for (Chain chain : sorted) {
            priorities.put(chain, priority.applyAsInt(chain));
        }
        sorted.sort(ranking
                .thenComparingInt(chain -> -priorities.getOrDefault(chain, 0))
                .thenComparing(chain -> chain.key() == null ? "" : chain.key()));

        // When the caller has already normalized the work queue (for example one representative
        // per application finding group), quotas must not discard work that fits inside the
        // explicit budget.  Applying the per-family cap in this case would make coverage depend
        // on incidental entry-class distribution rather than on the requested bound.
        if (sorted.size() <= maxTotal) {
            Map<String, Integer> allQuotas = new TreeMap<>();
            for (Chain chain : sorted) {
                String key = quotaKey.apply(chain);
                if (key == null || key.isBlank()) key = "<unknown>";
                allQuotas.merge(key, 1, Integer::sum);
            }
            return new VerificationPlan(maxTotal, candidates.size(), unique.size(), sorted,
                    allQuotas, "SELECTED_ALL_WITHIN_BUDGET",
                    digest(maxTotal, candidates.size(), unique.size(), sorted, constructible));
        }

        Map<String, Integer> quotaCounts = new HashMap<>();
        List<Chain> selected = new ArrayList<>();
        Set<String> selectedKeys = new HashSet<>();
        int primaryBudget = Math.min(maxTotal,
                Math.max(1, maxTotal / primaryBudgetDivisor));
        for (Chain chain : sorted) {
            if (selected.size() >= primaryBudget || !primaryPredicate.test(chain)) {
                continue;
            }
            if (!take(chain, quotaCounts, quotaKey)) {
                continue;
            }
            selected.add(chain);
            selectedKeys.add(chain.key());
        }
        for (Chain chain : sorted) {
            if (selectedKeys.contains(chain.key()) || selected.size() >= maxTotal) {
                continue;
            }
            if (!take(chain, quotaCounts, quotaKey)) {
                continue;
            }
            selected.add(chain);
            selectedKeys.add(chain.key());
        }

        Map<String, Integer> stableQuotas = new TreeMap<>(quotaCounts);
        String reason = selected.isEmpty() ? "NO_ELIGIBLE_CANDIDATE" : "SELECTED";
        return new VerificationPlan(maxTotal, candidates.size(), unique.size(), selected,
                stableQuotas, reason, digest(maxTotal, candidates.size(), unique.size(),
                selected, constructible));
    }

    private boolean take(Chain chain, Map<String, Integer> quotaCounts,
                         Function<Chain, String> quotaKey) {
        String key = quotaKey.apply(chain);
        if (key == null || key.isBlank()) {
            key = "<unknown>";
        }
        int count = quotaCounts.getOrDefault(key, 0);
        if (count >= maxPerQuota) {
            return false;
        }
        quotaCounts.put(key, count + 1);
        return true;
    }

    private static int equivalentCandidateOrder(Chain left, Chain right) {
        int unresolved = Integer.compare(left.unresolvedHops(), right.unresolvedHops());
        if (unresolved != 0) {
            return unresolved;
        }
        return candidateTieKey(left).compareTo(candidateTieKey(right));
    }

    private static String candidateTieKey(Chain chain) {
        return String.valueOf(chain.entryClass()) + "|" + String.valueOf(chain.entryMethod())
                + "|" + String.valueOf(chain.sinkClass()) + "|" + String.valueOf(chain.sinkMethod())
                + "|" + chain.hops().size();
    }

    private static String digest(int budget, int inputCount, int uniqueCount,
                                 List<Chain> selected, Set<String> constructible) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            update(digest, Integer.toString(Math.max(0, budget)));
            update(digest, Integer.toString(Math.max(0, inputCount)));
            update(digest, Integer.toString(Math.max(0, uniqueCount)));
            List<String> keys = new ArrayList<>();
            if (selected != null) {
                for (Chain chain : selected) {
                    if (chain != null) {
                        keys.add(chain.key());
                    }
                }
            }
            for (String key : keys) {
                update(digest, key);
            }
            if (constructible != null && !constructible.isEmpty()) {
                constructible.stream().filter(value -> value != null && !value.isBlank())
                        .sorted().forEach(value -> update(digest, "constructible:" + value));
            }
            byte[] bytes = digest.digest();
            StringBuilder result = new StringBuilder(bytes.length * 2);
            for (byte value : bytes) {
                result.append(String.format(java.util.Locale.ROOT, "%02x", value & 0xff));
            }
            return result.toString();
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("required SHA-256 digest unavailable", impossible);
        }
    }

    private static void update(MessageDigest digest, String value) {
        digest.update((value == null ? "" : value).getBytes(StandardCharsets.UTF_8));
        digest.update((byte) 0);
    }
}
