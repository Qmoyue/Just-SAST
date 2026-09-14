package io.just.sast.chain;

import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.HopKind;
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
    public record Evidence(int dynamicRank, int sinkRoleRank, int semanticRank,
                           int constructionRank,
                           int sinkPrecisionRank, int entryRank, int unresolvedHops,
                           int incompleteness, int compactTerminalRank, int pathPreferenceRank,
                           int pathLength, int staticScore,
                           int precisionRank,
                           String explanation) {
        /** Compatibility constructor for consumers compiled against the previous tuple. */
        public Evidence(int dynamicRank, int sinkRoleRank, int constructionRank,
                        int sinkPrecisionRank, int entryRank, int unresolvedHops,
                        int incompleteness, int pathLength, int staticScore,
                        String explanation) {
            this(dynamicRank, sinkRoleRank, 2, constructionRank, sinkPrecisionRank, entryRank,
                    unresolvedHops, incompleteness, 1, 1, pathLength, staticScore, 99,
                    explanation);
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

    /** Compare two already-materialized evidence tuples using the product ordering. */
    public static int compareEvidence(Evidence a, String leftKey, Evidence b, String rightKey) {
        if (a == null || b == null) {
            throw new IllegalArgumentException("ranking evidence must not be null");
        }
        int result = Integer.compare(a.dynamicRank(), b.dynamicRank());
        if (result != 0) return result;
        result = Integer.compare(a.sinkRoleRank(), b.sinkRoleRank());
        if (result != 0) return result;
        // Evidence completeness is a hard boundary: a semantically attractive but partial
        // chain must not outrank a complete chain merely because it carries a bridge marker.
        result = Integer.compare(a.incompleteness(), b.incompleteness());
        if (result != 0) return result;
        result = Integer.compare(a.semanticRank(), b.semanticRank());
        if (result != 0) return result;
        result = Integer.compare(a.constructionRank(), b.constructionRank());
        if (result != 0) return result;
        result = Integer.compare(a.sinkPrecisionRank(), b.sinkPrecisionRank());
        if (result != 0) return result;
        result = Integer.compare(a.entryRank(), b.entryRank());
        if (result != 0) return result;
        result = Integer.compare(a.unresolvedHops(), b.unresolvedHops());
        if (result != 0) return result;
        // A declaration-backed one-hop terminal is an exact usable endpoint.  It outranks a
        // longer generic suffix without knowing a class, package, rule id, or benchmark name.
        result = Integer.compare(a.compactTerminalRank(), b.compactTerminalRank());
        if (result != 0) return result;
        // A semantic bridge or an obviously disconnected component is where static search most
        // often appends decorative suffixes.  Prefer the shorter representative for that pair,
        // while keeping the historical static-evidence ordering for ordinary connected paths.
        boolean shortestFirst = a.pathPreferenceRank() == 0 || b.pathPreferenceRank() == 0;
        if (shortestFirst) {
            result = Integer.compare(a.precisionRank(), b.precisionRank());
            if (result != 0) return result;
            result = Integer.compare(a.pathLength(), b.pathLength());
            if (result != 0) return result;
            result = Integer.compare(b.staticScore(), a.staticScore());
            if (result != 0) return result;
        } else {
            result = Integer.compare(b.staticScore(), a.staticScore());
            if (result != 0) return result;
            result = Integer.compare(a.precisionRank(), b.precisionRank());
            if (result != 0) return result;
            result = Integer.compare(a.pathLength(), b.pathLength());
            if (result != 0) return result;
        }
        return (leftKey == null ? "" : leftKey).compareTo(rightKey == null ? "" : rightKey);
    }

    private static int compareEvidence(Chain left, Chain right, Evidence a, Evidence b) {
        return compareEvidence(a, safeKey(left), b, safeKey(right));
    }

    public static Evidence evidence(Chain chain, Map<String, List<String>> notes,
                                    Map<String, VerificationSummary.ChainResult> verification,
                                    Set<String> constructible) {
        if (chain == null) {
            return new Evidence(9, 9, 9, 9, 9, 9, Integer.MAX_VALUE, Integer.MAX_VALUE,
                    1, 1, Integer.MAX_VALUE, Integer.MIN_VALUE, 99, "null-candidate");
        }
        List<String> chainNotes = notes == null ? List.of()
                : notes.getOrDefault(chain.key(), List.of());
        if (chainNotes == null) {
            chainNotes = List.of();
        }
        VerificationSummary.ChainResult result = verification == null ? null
                : verification.get(chain.key());
        String status = result == null ? "" : result.outcomeStatus().name();
        if (status.isBlank()) {
            status = ConfidenceScorer.statusFromNotes(chainNotes);
        }
        ConfidenceScorer.RankFeatures rankFeatures =
                ConfidenceScorer.rankFeatures(chain, chainNotes);
        int dynamic = rankFeatures.dynamicRank();
        // A terminal-looking frame without the authenticated readiness bit is not dynamic
        // evidence. Keep the candidate visible, but place it with untestable results.
        if (result != null && !result.sandboxReady()) {
            dynamic = Math.max(dynamic, ConfidenceScorer.DYNAMIC_NEGATIVE_OR_UNTESTABLE);
        }
        int sinkRole = chain.terminalSink() ? 0 : 1;
        int semantic = semanticRank(chain);
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
        ChainPrecision.Assessment precision = ChainPrecision.assess(chain, chainNotes, result);
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
        if (!"COMPLETE".equals(precision.completeness())) {
            incomplete++;
        }
        int compactTerminal = isCompactDeclaredTerminal(chain) ? 0 : 1;
        int disconnectedHops = disconnectedEvidenceHops(chain);
        int pathPreference = disconnectedHops > 0 || hasSemanticContinuation(chain) ? 0 : 1;
        String explanation = "dynamic=" + (status.isBlank() ? "NOT_SELECTED" : status)
                + ";sink_role=" + chain.sinkRole()
                + ";semantic=" + semanticLabel(semantic)
                + ";construction=" + (isConstructible ? "CONSTRUCTIBLE"
                : declaredPlanValid ? "DECLARED_PLAN"
                : hasDeclaredPlan ? "PLAN_PARTIAL"
                : partialConstruction ? "PARTIAL" : "UNKNOWN")
                + ";sink_precision=" + (sinkPrecision == 0 ? "EXACT_DESCRIPTOR" : "NAME_ONLY")
                + ";entry_direction=" + (entry == 0 ? "DESERIALIZE_CALLBACK" : chain.entryKind())
                + ";unresolved=" + chain.unresolvedHops()
                + ";incompleteness=" + incomplete
                + ";compact_terminal="
                + (compactTerminal == 0 ? "DECLARED_MINIMAL" : "NO")
                + ";path_preference="
                + (pathPreference == 0 ? "SHORTEST_BRIDGE_OR_DISCONNECT" : "STATIC_EVIDENCE")
                + ";disconnected_hops=" + disconnectedHops
                + ";path_length=" + chain.hops().size()
                + ";precision=" + precision.compact();
        return new Evidence(dynamic, sinkRole, semantic, construction, sinkPrecision, entry,
                chain.unresolvedHops(), incomplete, compactTerminal, pathPreference,
                chain.hops().size(), rankFeatures.totalScore(), precision.rank(), explanation);
    }

    /**
     * A direct declared fragment has no unresolved gadget suffix: its construction plan, sink,
     * entry and single ENTRY hop all describe the same callable endpoint.  This is a structural
     * rank, not a class-name exception, so every rule can benefit from the same minimal-chain
     * policy.
     */
    private static boolean isCompactDeclaredTerminal(Chain chain) {
        if (chain == null || !chain.terminalSink()
                || !"reflectiveTarget".equals(chain.entryKind())
                || chain.constructionPlan() == null
                || !chain.constructionPlan().shapeSummary().valid()
                || chain.hops().size() != 1) {
            return false;
        }
        ChainHop hop = chain.hops().get(0);
        return hop != null && hop.kind() == HopKind.ENTRY
                && sameText(chain.entryClass(), chain.sinkClass())
                && sameText(chain.entryMethod(), chain.sinkMethod())
                && !chain.sinkDescriptor().isBlank()
                && sameText(hop.desc(), chain.sinkDescriptor())
                && hop.reason() != null
                && hop.reason().startsWith("fragment-activation-invoke");
    }

    private static boolean hasSemanticContinuation(Chain chain) {
        return chain != null && chain.hops().stream().anyMatch(hop -> hop != null
                && hop.reason() != null
                && (hop.reason().startsWith("bridge-")
                || hop.reason().equals("fragment")
                || hop.reason().startsWith("fragment-activation-")));
    }

    /**
     * Do not reward an isolated direct/field component that is not connected to the declared
     * application entry.  UNKNOWN/disconnected evidence remains visible in the candidate, but
     * it cannot inflate the score used to select the representative chain.
     */
    private static int disconnectedEvidenceHops(Chain chain) {
        if (chain == null || chain.hops().size() < 2
                || isBlank(chain.entryClass()) || isBlank(chain.entryMethod())) {
            return 0;
        }
        List<ChainHop> hops = chain.hops();
        boolean[] connected = new boolean[hops.size()];
        boolean seeded = false;
        for (int i = 0; i < hops.size(); i++) {
            ChainHop hop = hops.get(i);
            if (hop == null || hop.kind() == HopKind.ENTRY) {
                continue;
            }
            if (sameMethod(hop.fromOwner(), hop.fromName(), chain.entryClass(), chain.entryMethod())
                    || sameMethod(hop.toOwner(), hop.toName(), chain.entryClass(),
                    chain.entryMethod())) {
                connected[i] = true;
                seeded = true;
            }
        }
        if (!seeded) {
            return 0;
        }
        boolean changed;
        do {
            changed = false;
            for (int i = 0; i + 1 < hops.size(); i++) {
                ChainHop left = hops.get(i);
                ChainHop right = hops.get(i + 1);
                if (left == null || right == null || left.kind() == HopKind.ENTRY
                        || right.kind() == HopKind.ENTRY
                        || !adjacentMethods(left, right)) {
                    continue;
                }
                if (connected[i] != connected[i + 1]) {
                    connected[i] = true;
                    connected[i + 1] = true;
                    changed = true;
                }
            }
        } while (changed);
        int disconnected = 0;
        for (int i = 0; i < hops.size(); i++) {
            ChainHop hop = hops.get(i);
            if (hop != null && !connected[i]
                    && (hop.kind() == HopKind.DIRECT_CALL || hop.kind() == HopKind.FIELD_FLOW)) {
                disconnected++;
            }
        }
        return disconnected;
    }

    private static boolean adjacentMethods(ChainHop left, ChainHop right) {
        return sameMethod(left.toOwner(), left.toName(), right.fromOwner(), right.fromName())
                || sameMethod(left.fromOwner(), left.fromName(), right.toOwner(), right.toName());
    }

    private static boolean sameMethod(String leftOwner, String leftName,
                                      String rightOwner, String rightName) {
        return sameText(leftOwner, rightOwner) && sameText(leftName, rightName);
    }

    private static boolean sameText(String left, String right) {
        return left != null && right != null && left.equals(right);
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    /**
     * Prefer a complete, typed nested-deserialization bridge over an otherwise more convenient
     * generic construction variant.  The evidence is intentionally made only from immutable
     * hop reasons: it does not know a benchmark, a package, a rule id, or a gadget name.
     */
    private static int semanticRank(Chain chain) {
        boolean invokeActivation = false;
        boolean deserializeActivation = false;
        boolean nestedBridge = false;
        for (var hop : chain.hops()) {
            if (hop == null || hop.reason() == null) {
                continue;
            }
            String reason = hop.reason();
            if ("fragment-activation-invoke".equals(reason)) {
                invokeActivation = true;
            } else if ("fragment-activation-deserialize".equals(reason)) {
                deserializeActivation = true;
            } else if ("bridge-deser".equals(reason)
                    || reason.startsWith("bridge-second-deserialization")) {
                nestedBridge = true;
            }
        }
        if (invokeActivation && deserializeActivation && nestedBridge) {
            return 0;
        }
        if (invokeActivation && nestedBridge) {
            return 1;
        }
        return 2;
    }

    private static String semanticLabel(int rank) {
        return switch (rank) {
            case 0 -> "TYPED_NESTED_DESERIALIZATION";
            case 1 -> "NESTED_DESERIALIZATION_PARTIAL";
            default -> "ORDINARY_CHAIN";
        };
    }

    private static String safeKey(Chain chain) {
        return chain == null || chain.key() == null ? "" : chain.key();
    }
}
