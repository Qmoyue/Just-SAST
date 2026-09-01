package io.just.sast.blackboard;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * Semantic identity and preference rules for concurrent chain publication.
 *
 * <p>Hop reasons and construction plans are evidence attached to a path, not a new path.  The
 * merge key therefore excludes those two fields while retaining rule, overload, field identity
 * and hop order.  This removes order-dependent duplicates without collapsing distinct chains.</p>
 */
public final class ChainMerge {

    private ChainMerge() {
    }

    public static String semanticKey(Chain chain) {
        if (chain == null) {
            return "<null>";
        }
        StringBuilder value = new StringBuilder();
        append(value, chain.ruleId());
        append(value, chain.category());
        append(value, chain.severity());
        append(value, chain.entryClass());
        append(value, chain.entryMethod());
        append(value, chain.entryKind());
        append(value, chain.sinkClass());
        append(value, chain.sinkMethod());
        append(value, chain.sinkDescriptor());
        append(value, chain.sinkRole());
        for (ChainHop hop : chain.hops()) {
            if (hop == null) {
                append(value, "<null-hop>");
                continue;
            }
            append(value, hop.fromOwner());
            append(value, hop.fromName());
            append(value, hop.toOwner());
            append(value, hop.toName());
            append(value, hop.kind());
            append(value, hop.field());
            append(value, hop.desc());
            append(value, hop.argOrdinal());
            append(value, hop.fieldOwner());
        }
        return value.toString();
    }

    /** Return the chain with the strongest structural evidence, with a stable final tie-break. */
    public static Chain preferred(Chain first, Chain second) {
        if (first == null) {
            return second;
        }
        if (second == null) {
            return first;
        }
        Comparator<Chain> order = Comparator
                .comparingInt(Chain::unresolvedHops)
                .thenComparingInt(ChainMerge::missingEvidence)
                .thenComparingInt(ChainMerge::planRank)
                .thenComparingInt(chain -> -chain.hops().size())
                .thenComparing(chain -> chain.key() == null ? "" : chain.key());
        return order.compare(first, second) <= 0 ? first : second;
    }

    /** Stable reason set used by Blackboard when two producers describe one semantic path. */
    public static List<String> reasons(Chain chain) {
        if (chain == null) {
            return List.of();
        }
        List<String> reasons = new ArrayList<>();
        for (ChainHop hop : chain.hops()) {
            if (hop != null && hop.reason() != null && !hop.reason().isBlank()) {
                reasons.add(hop.reason());
            }
        }
        return reasons.stream().distinct().sorted().toList();
    }

    private static int missingEvidence(Chain chain) {
        int missing = 0;
        if (chain.sinkDescriptor() == null || chain.sinkDescriptor().isBlank()) {
            missing++;
        }
        for (ChainHop hop : chain.hops()) {
            if (hop == null) {
                missing++;
                continue;
            }
            if (hop.desc() == null || hop.desc().isBlank()) {
                missing++;
            }
            if (hop.kind() == HopKind.FIELD_FLOW
                    && (hop.field() == null || hop.field().isBlank()
                    || hop.fieldOwner() == null || hop.fieldOwner().isBlank())) {
                missing++;
            }
        }
        return missing;
    }

    private static int planRank(Chain chain) {
        if (chain.constructionPlan() == null || chain.constructionPlan().isEmpty()) {
            return 1;
        }
        return chain.constructionPlan().shapeSummary().valid() ? 0 : 2;
    }

    private static void append(StringBuilder value, Object item) {
        value.append(item == null ? "<null>" : item).append('|');
    }
}
