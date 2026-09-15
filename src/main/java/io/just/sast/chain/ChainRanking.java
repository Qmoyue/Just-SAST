package io.just.sast.chain;

import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.HopKind;

import java.util.Comparator;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** One deterministic ranking contract shared by all static report renderers. */
public final class ChainRanking {

    /** Stable, reportable static ranking factors. Lower values are preferred. */
    public record Evidence(int sinkRoleRank, int semanticRank, int constructionRank,
                           int sinkPrecisionRank, int entryRank, int unresolvedHops,
                           int incompleteness, int compactTerminalRank, int pathPreferenceRank,
                           int pathLength, int staticScore, int precisionRank,
                           String explanation) {
        public Evidence {
            explanation = explanation == null ? "" : explanation;
            precisionRank = Math.max(0, precisionRank);
        }
    }

    private ChainRanking() {
    }

    public static Comparator<Chain> comparator(Map<String, List<String>> notes,
                                              Set<String> constructible) {
        Map<String, List<String>> stableNotes = notes == null ? Map.of() : notes;
        Set<String> stableConstructible = constructible == null ? Set.of() : constructible;
        Map<Chain, Evidence> memo = new IdentityHashMap<>();
        return (left, right) -> compareEvidence(left, right,
                memo.computeIfAbsent(left, candidate -> evidence(candidate, stableNotes,
                        stableConstructible)),
                memo.computeIfAbsent(right, candidate -> evidence(candidate, stableNotes,
                        stableConstructible)));
    }

    public static int compare(Chain left, Chain right,
                              Map<String, List<String>> notes,
                              Set<String> constructible) {
        return compareEvidence(left, right, evidence(left, notes, constructible),
                evidence(right, notes, constructible));
    }

    /** Compare two materialized evidence tuples using the static product ordering. */
    public static int compareEvidence(Evidence a, String leftKey, Evidence b, String rightKey) {
        if (a == null || b == null) {
            throw new IllegalArgumentException("ranking evidence must not be null");
        }
        int result = Integer.compare(a.sinkRoleRank(), b.sinkRoleRank());
        if (result != 0) return result;
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
        result = Integer.compare(a.compactTerminalRank(), b.compactTerminalRank());
        if (result != 0) return result;
        result = Integer.compare(a.pathPreferenceRank(), b.pathPreferenceRank());
        if (result != 0) return result;
        if (a.pathPreferenceRank() == 0 || a.pathPreferenceRank() == 2) {
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
                                    Set<String> constructible) {
        if (chain == null) {
            return new Evidence(9, 9, 9, 9, 9, Integer.MAX_VALUE, Integer.MAX_VALUE,
                    1, 1, Integer.MAX_VALUE, Integer.MIN_VALUE, 99, "null-candidate");
        }
        List<String> chainNotes = notes == null ? List.of()
                : notes.getOrDefault(chain.key(), List.of());
        if (chainNotes == null) {
            chainNotes = List.of();
        }
        ConfidenceScorer.RankFeatures rankFeatures =
                ConfidenceScorer.rankFeatures(chain, chainNotes);
        int sinkRole = chain.terminalSink() ? 0 : 1;
        int semantic = semanticRank(chain);
        boolean isConstructible = constructible != null && constructible.contains(chain.key())
                || chainNotes.stream().anyMatch("static:constructible"::equals);
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
        ChainPrecision.Assessment precision = ChainPrecision.assess(chain, chainNotes);
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
        boolean semanticContinuation = hasSemanticContinuation(chain);
        int pathPreference = semanticContinuation ? 0 : disconnectedHops > 0 ? 2 : 1;
        String explanation = "sink_role=" + chain.sinkRole()
                + ";semantic=" + semanticLabel(semantic)
                + ";construction=" + (isConstructible ? "CONSTRUCTIBLE"
                : declaredPlanValid ? "DECLARED_PLAN"
                : hasDeclaredPlan ? "PLAN_PARTIAL"
                : partialConstruction ? "PARTIAL" : "UNKNOWN")
                + ";sink_precision=" + (sinkPrecision == 0 ? "EXACT_DESCRIPTOR" : "NAME_ONLY")
                + ";entry_direction=" + (entry == 0 ? "DESERIALIZE_CALLBACK" : chain.entryKind())
                + ";unresolved=" + chain.unresolvedHops()
                + ";incompleteness=" + incomplete
                + ";compact_terminal=" + (compactTerminal == 0 ? "DECLARED_MINIMAL" : "NO")
                + ";path_preference=" + switch (pathPreference) {
                    case 0 -> "SEMANTIC_CONTINUATION";
                    case 2 -> "DISCONNECTED_SUFFIX";
                    default -> "STATIC_EVIDENCE";
                }
                + ";disconnected_hops=" + disconnectedHops
                + ";path_length=" + chain.hops().size()
                + ";precision=" + precision.compact();
        return new Evidence(sinkRole, semantic, construction, sinkPrecision, entry,
                chain.unresolvedHops(), incomplete, compactTerminal, pathPreference,
                chain.hops().size(), rankFeatures.totalScore(), precision.rank(), explanation);
    }

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
                    || sameMethod(hop.toOwner(), hop.toName(), chain.entryClass(), chain.entryMethod())) {
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
                        || right.kind() == HopKind.ENTRY || !adjacentMethods(left, right)) {
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
