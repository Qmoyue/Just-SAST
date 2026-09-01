package io.just.sast.chain;

import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.VerificationSummary;

import java.util.Comparator;
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
                           String explanation) {
        public Evidence {
            explanation = explanation == null ? "" : explanation;
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
        return (left, right) -> compare(left, right, stableNotes, stableVerification,
                stableConstructible);
    }

    public static int compare(Chain left, Chain right,
                              Map<String, List<String>> notes,
                              Map<String, VerificationSummary.ChainResult> verification,
                              Set<String> constructible) {
        Evidence a = evidence(left, notes, verification, constructible);
        Evidence b = evidence(right, notes, verification, constructible);
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
        result = Integer.compare(a.pathLength(), b.pathLength());
        if (result != 0) return result;
        return safeKey(left).compareTo(safeKey(right));
    }

    public static Evidence evidence(Chain chain, Map<String, List<String>> notes,
                                    Map<String, VerificationSummary.ChainResult> verification,
                                    Set<String> constructible) {
        if (chain == null) {
            return new Evidence(9, 9, 9, 9, 9, Integer.MAX_VALUE, Integer.MAX_VALUE,
                    Integer.MAX_VALUE, Integer.MIN_VALUE, "null-candidate");
        }
        List<String> chainNotes = notes == null ? List.of()
                : notes.getOrDefault(chain.key(), List.of());
        VerificationSummary.ChainResult result = verification == null ? null
                : verification.get(chain.key());
        String status = result == null ? "" : result.status();
        if (status.isBlank()) {
            status = statusFromNotes(chainNotes);
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
        int construction = isConstructible ? 0
                : declaredPlanValid ? 1
                : hasDeclaredPlan ? 2
                : chainNotes.stream().anyMatch(n -> n.startsWith("degrade:partial-construct")) ? 2 : 3;
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
        String explanation = "dynamic=" + (status.isBlank() ? "NOT_SELECTED" : status)
                + ";sink_role=" + chain.sinkRole()
                + ";construction=" + (isConstructible ? "CONSTRUCTIBLE"
                : declaredPlanValid ? "DECLARED_PLAN"
                : hasDeclaredPlan ? "PLAN_PARTIAL" : "UNKNOWN")
                + ";sink_precision=" + (sinkPrecision == 0 ? "EXACT_DESCRIPTOR" : "NAME_ONLY")
                + ";entry_direction=" + (entry == 0 ? "DESERIALIZE_CALLBACK" : chain.entryKind())
                + ";unresolved=" + chain.unresolvedHops()
                + ";incompleteness=" + incomplete
                + ";path_length=" + chain.hops().size();
        return new Evidence(dynamic, sinkRole, construction, sinkPrecision, entry,
                chain.unresolvedHops(), incomplete, chain.hops().size(),
                ConfidenceScorer.evidenceScore(chain, chainNotes), explanation);
    }

    private static String statusFromNotes(List<String> notes) {
        if (notes == null) return "";
        if (notes.stream().anyMatch(n -> "verify:sink-blocked".equals(n))) return "SINK_BLOCKED";
        if (notes.stream().anyMatch(n -> "verify:safe-effect-observed".equals(n))) {
            return "SAFE_EFFECT_OBSERVED";
        }
        if (notes.stream().anyMatch(n -> "verify:concrete-reached".equals(n)
                || "verify:executed".equals(n))) return "CONCRETE_REACHED";
        if (notes.stream().anyMatch(n -> n != null && n.startsWith("degrade:partial-path"))) {
            return "PARTIAL";
        }
        return "";
    }

    private static String safeKey(Chain chain) {
        return chain == null || chain.key() == null ? "" : chain.key();
    }
}
