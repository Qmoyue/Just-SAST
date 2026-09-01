package io.just.sast.chain;

import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.VerificationSummary;

import java.util.Comparator;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * One deterministic ranking contract shared by verification selection and reporters.
 *
 * <p>The order is deliberately a tuple rather than a pile of unrelated bonuses.  This makes
 * the reason a candidate moves visible and prevents a long list of static points from
 * accidentally outranking an exact dynamic boundary.  The comparator has no knowledge of
 * benchmark names or WP signatures.</p>
 */
public final class ChainRanking {

    /** Stable, reportable ranking factors. Lower values are preferred except staticScore. */
    public record Evidence(int dynamicRank, int sinkRoleRank, int constructionRank,
                           int sinkPrecisionRank, int entryRank, int unresolvedHops,
                           int incompleteness, int pathLength, int staticScore,
                           int precisionRank,
                           String explanation) {
        /** Compatibility constructor for consumers compiled against the previous tuple. */
        public Evidence(int dynamicRank, int sinkRoleRank, int constructionRank,
                        int sinkPrecisionRank, int entryRank, int unresolvedHops,
                        int incompleteness, int pathLength, int staticScore,
                        String explanation) {
            this(dynamicRank, sinkRoleRank, constructionRank, sinkPrecisionRank, entryRank,
                    unresolvedHops, incompleteness, pathLength, staticScore, 99, explanation);
        }

        public Evidence {
            explanation = explanation == null ? "" : explanation;
            precisionRank = Math.max(0, precisionRank);
        }
    }

    private ChainRanking() {
    }

    public static Comparator<Chain> comparator(Map<String, List<String>> notes,
                                              Map<String, VerificationSummary.ChainResult> verification,
                                              Set<String> constructible) {
        Map<String, List<String>> stableNotes = notes == null ? Map.of() : notes;
        Map<String, VerificationSummary.ChainResult> stableVerification =
                verification == null ? Map.of() : verification;
        Set<String> stableConstructible = constructible == null ? Set.of() : constructible;
        // TimSort may compare the same candidate O(log n) times.  Precision assessment walks
        // every hop and note, so recomputing it from the comparator made large closures pay a
        // hidden O(n log n * chain-size) cost.  Candidates are immutable for one phase; an
        // identity cache keeps this optimization local to the sort and cannot leak stale notes
        // across phases.
        Map<Chain, Evidence> memo = new IdentityHashMap<>();
        return (left, right) -> compareEvidence(left, right,
                memo.computeIfAbsent(left, candidate -> evidence(candidate, stableNotes,
                        stableVerification, stableConstructible)),
                memo.computeIfAbsent(right, candidate -> evidence(candidate, stableNotes,
                        stableVerification, stableConstructible)));
    }

    public static int compare(Chain left, Chain right,
                              Map<String, List<String>> notes,
                              Map<String, VerificationSummary.ChainResult> verification,
                              Set<String> constructible) {
        return compareEvidence(left, right, evidence(left, notes, verification, constructible),
                evidence(right, notes, verification, constructible));
    }

    private static int compareEvidence(Chain left, Chain right, Evidence a, Evidence b) {
        int result = Integer.compare(a.dynamicRank(), b.dynamicRank());
        if (result != 0) return result;
        result = Integer.compare(a.sinkRoleRank(), b.sinkRoleRank());
        if (result != 0) return result;
        result = Integer.compare(a.constructionRank(), b.constructionRank());
        if (result != 0) return result;
        result = Integer.compare(a.sinkPrecisionRank(), b.sinkPrecisionRank());
        if (result != 0) return result;
        result = Integer.compare(a.entryRank(), b.entryRank());
        if (result != 0) return result;
        result = Integer.compare(a.unresolvedHops(), b.unresolvedHops());
        if (result != 0) return result;
        result = Integer.compare(a.incompleteness(), b.incompleteness());
        if (result != 0) return result;
        result = Integer.compare(b.staticScore(), a.staticScore());
        if (result != 0) return result;
        // Precision is a confidence tie-break after semantic risk/entry coverage.  A
        // declared reflective sink must not make a compact high-severity deserialization
        // candidate lose its finite verification slot to a long generic plumbing path merely
        // because the latter has no reflection obligation.
        result = Integer.compare(a.precisionRank(), b.precisionRank());
        if (result != 0) return result;
        result = Integer.compare(a.pathLength(), b.pathLength());
        if (result != 0) return result;
        return safeKey(left).compareTo(safeKey(right));
    }

    public static Evidence evidence(Chain chain, Map<String, List<String>> notes,
                                    Map<String, VerificationSummary.ChainResult> verification,
                                    Set<String> constructible) {
        if (chain == null) {
            return new Evidence(9, 9, 9, 9, 9, Integer.MAX_VALUE, Integer.MAX_VALUE,
                    Integer.MAX_VALUE, Integer.MIN_VALUE, 99, "null-candidate");
        }
        List<String> chainNotes = notes == null ? List.of()
                : notes.getOrDefault(chain.key(), List.of());
        if (chainNotes == null) {
            chainNotes = List.of();
        }
        VerificationSummary.ChainResult result = verification == null ? null
                : verification.get(chain.key());
        String status = result == null ? "" : result.status();
        if (status.isBlank()) {
            status = ConfidenceScorer.statusFromNotes(chainNotes);
        }
        int dynamic = ConfidenceScorer.dynamicRank(status, chainNotes);
        // A terminal-looking frame without the authenticated readiness bit is not dynamic
        // evidence. Keep the candidate visible, but place it with untestable results.
        if (result != null && !result.sandboxReady()) {
            dynamic = Math.max(dynamic, ConfidenceScorer.DYNAMIC_NEGATIVE_OR_UNTESTABLE);
        }
        int sinkRole = chain.terminalSink() ? 0 : 1;
        boolean isConstructible = constructible != null && constructible.contains(chain.key())
                || chainNotes.stream().anyMatch("verify:constructible"::equals);
        boolean hasDeclaredPlan = chain.constructionPlan() != null
                && !chain.constructionPlan().isEmpty();
        boolean declaredPlanValid = hasDeclaredPlan
                && chain.constructionPlan().shapeSummary().valid();
        boolean partialConstruction = chainNotes.stream().anyMatch(n -> n != null
                && n.startsWith("degrade:partial-construct"));
        int construction = isConstructible ? 0
                : declaredPlanValid ? 1
                : hasDeclaredPlan ? 2
                : partialConstruction ? 2 : 3;
        int sinkPrecision = chain.sinkDescriptor() == null || chain.sinkDescriptor().isBlank() ? 1 : 0;
        int entry = switch (chain.entryKind() == null ? "" : chain.entryKind()) {
            case "readObject", "readObjectNoData", "readExternal", "readResolve" -> 0;
            case "deserialize", "source" -> 1;
            case "hashCode", "equals", "compareTo", "compare", "toString", "proxyInvoke" -> 2;
            default -> 3;
        };
        int incomplete = 0;
        for (String note : chainNotes) {
            if (note != null && (note.startsWith("degrade:") || note.contains("CAP")
                    || note.contains("UNKNOWN"))) {
                incomplete++;
            }
        }
        if (hasDeclaredPlan && !declaredPlanValid) {
            incomplete++;
        }
        ChainPrecision.Assessment precision = ChainPrecision.assess(chain, chainNotes, result);
        String explanation = "dynamic=" + (status.isBlank() ? "NOT_SELECTED" : status)
                + ";sink_role=" + chain.sinkRole()
                + ";construction=" + (isConstructible ? "CONSTRUCTIBLE"
                : declaredPlanValid ? "DECLARED_PLAN"
                : hasDeclaredPlan ? "PLAN_PARTIAL"
                : partialConstruction ? "PARTIAL" : "UNKNOWN")
                + ";sink_precision=" + (sinkPrecision == 0 ? "EXACT_DESCRIPTOR" : "NAME_ONLY")
                + ";entry_direction=" + (entry == 0 ? "DESERIALIZE_CALLBACK" : chain.entryKind())
                + ";unresolved=" + chain.unresolvedHops()
                + ";incompleteness=" + incomplete
                + ";path_length=" + chain.hops().size()
                + ";precision=" + precision.compact();
        return new Evidence(dynamic, sinkRole, construction, sinkPrecision, entry,
                chain.unresolvedHops(), incomplete, chain.hops().size(),
                ConfidenceScorer.evidenceScore(chain, chainNotes), precision.rank(), explanation);
    }

    private static String safeKey(Chain chain) {
        return chain == null || chain.key() == null ? "" : chain.key();
    }
}
