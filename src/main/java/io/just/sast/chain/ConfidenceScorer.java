package io.just.sast.chain;

import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.HopKind;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/** Deterministic confidence scoring from static chain evidence only. */
public final class ConfidenceScorer {

    public static final int PATTERN_BONUS = 2;
    public static final int FRAMEWORK_BEAN_INPUT_BONUS = 2;

    private ConfidenceScorer() {
    }

    /** Immutable static score vector consumed by ranking and report renderers. */
    public record RankFeatures(int staticScore, int totalScore, int staticRank,
                               int unresolvedPenalty, int degradationCount,
                               boolean staticFeasible, List<String> reasons) {
        public RankFeatures {
            staticRank = Math.max(0, staticRank);
            unresolvedPenalty = Math.max(0, unresolvedPenalty);
            degradationCount = Math.max(0, degradationCount);
            reasons = reasons == null ? List.of() : List.copyOf(reasons);
        }
    }

    /** Typed static confidence projection. */
    public record ConfidenceTransition(String bucket, String reasonCode,
                                       boolean staticFeasible, RankFeatures features,
                                       List<String> reasons) {
        public ConfidenceTransition {
            bucket = bucket == null || bucket.isBlank() ? "UNKNOWN" : bucket;
            reasonCode = reasonCode == null || reasonCode.isBlank() ? "UNKNOWN" : reasonCode;
            features = features == null ? new RankFeatures(0, 0, 2, 0, 0,
                    false, List.of()) : features;
            reasons = reasons == null ? List.of() : List.copyOf(reasons);
        }

        public boolean isFeasible() {
            return "FEASIBLE".equals(bucket);
        }
    }

    public static ConfidenceTransition transition(Chain chain, List<String> notes) {
        List<String> stableNotes = stableNotes(notes);
        RankFeatures features = rankFeatures(chain, stableNotes);
        if (chain == null) {
            return new ConfidenceTransition("UNKNOWN", "NULL_CHAIN", false, features,
                    features.reasons());
        }
        if (!features.staticFeasible()) {
            return new ConfidenceTransition("NOT_FEASIBLE", "STATIC_INFEASIBLE", false,
                    features, features.reasons());
        }
        String degradation = firstDegradation(stableNotes);
        if (degradation != null) {
            return new ConfidenceTransition(degradedBucket(degradation), "STATIC_DEGRADATION",
                    true, features, features.reasons());
        }
        return new ConfidenceTransition("FEASIBLE", "STATIC_FEASIBLE", true, features,
                features.reasons());
    }

    public static RankFeatures rankFeatures(Chain chain, List<String> notes) {
        List<String> stableNotes = stableNotes(notes);
        int staticScore = staticEvidenceScore(chain, stableNotes);
        int unresolvedPenalty = chain == null ? 0 : chain.unresolvedHops() * 2;
        int staticRank = rankFromScore(staticScore);
        int degradationCount = (int) stableNotes.stream()
                .filter(note -> note.startsWith("degrade:")).count();
        boolean staticFeasible = chain != null && staticRank < 2
                && unresolvedPenalty <= Math.max(0, staticScore);
        List<String> reasons = new ArrayList<>();
        if (chain == null) {
            reasons.add("NULL_CHAIN");
        }
        if (staticRank >= 2) {
            reasons.add("STATIC_SCORE_LOW");
        }
        if (unresolvedPenalty > Math.max(0, staticScore)) {
            reasons.add("UNRESOLVED_STATIC_EVIDENCE");
        }
        if (degradationCount > 0) {
            reasons.add("STATIC_DEGRADATION_PRESENT");
        }
        reasons.sort(Comparator.naturalOrder());
        return new RankFeatures(staticScore, staticScore, staticRank, unresolvedPenalty,
                degradationCount, staticFeasible, reasons);
    }

    public static String score(Chain chain, List<String> notes) {
        return transition(chain, notes).bucket();
    }

    /** Static evidence score used for ranking and bounded candidate admission. */
    public static int evidenceScore(Chain chain, List<String> notes) {
        return rankFeatures(chain, notes).totalScore();
    }

    /** Compact score decomposition suitable for human review. */
    public static String evidenceDecomposition(Chain chain, List<String> notes) {
        if (chain == null) {
            return "chain:null";
        }
        int direct = 0;
        int virtual = 0;
        int nativeCallbacks = 0;
        int fieldFlows = 0;
        StringBuilder fields = new StringBuilder();
        for (ChainHop hop : chain.hops()) {
            if (hop.kind() == HopKind.DIRECT_CALL) {
                direct++;
            } else if (hop.kind() == HopKind.VIRTUAL_DISPATCH) {
                virtual++;
            } else if (hop.kind() == HopKind.NATIVE_CALLBACK) {
                nativeCallbacks++;
            } else if (hop.kind() == HopKind.FIELD_FLOW) {
                fieldFlows++;
                if (hop.field() != null) {
                    fields.append(hop.field()).append(',');
                }
            }
        }
        String fieldNames = fields.length() > 0
                ? fields.substring(0, fields.length() - 1) : "";
        StringBuilder out = new StringBuilder();
        out.append("hops:direct=").append(direct).append('+').append(direct)
                .append(",virtual=").append(virtual).append("+0")
                .append(",native=").append(nativeCallbacks).append("+0")
                .append(",field=").append(fieldFlows).append('+').append(fieldFlows);
        if (!fieldNames.isEmpty()) {
            out.append('(').append(fieldNames).append(')');
        }
        out.append(";entry:").append(chain.entryKind() == null ? "?" : chain.entryKind())
                .append('+').append(entryWeight(chain.entryKind()));
        if ("HIGH".equals(chain.severity())) {
            out.append(";sev:HIGH+1");
        }
        if (hasFrameworkBeanInput(chain)) {
            out.append(";source-boundary:framework-bean-input+")
                    .append(FRAMEWORK_BEAN_INPUT_BONUS);
        }
        if (chain.unresolvedHops() > 0) {
            out.append(";unresolved:").append(chain.unresolvedHops())
                    .append('-').append(chain.unresolvedHops() * 2);
        }
        if (notes != null) {
            for (String note : notes) {
                if (note != null && note.startsWith("pattern:")) {
                    out.append(";pattern:").append(note.substring("pattern:".length()))
                            .append('+').append(PATTERN_BONUS);
                }
            }
        }
        return out.toString();
    }

    /** Static rank: lower is stronger, with no runtime or isolation axis. */
    public static int rank(Chain chain, List<String> notes) {
        return rankFeatures(chain, notes).staticRank();
    }

    private static int staticEvidenceScore(Chain chain, List<String> notes) {
        if (chain == null) {
            return 0;
        }
        int points = 0;
        for (ChainHop hop : chain.hops()) {
            points += switch (hop.kind()) {
                case DIRECT_CALL, FIELD_FLOW -> 1;
                case VIRTUAL_DISPATCH, LAMBDA, NATIVE_CALLBACK, ENTRY -> 0;
            };
        }
        points += entryWeight(chain.entryKind());
        if ("HIGH".equals(chain.severity())) {
            points++;
        }
        if (hasFrameworkBeanInput(chain)) {
            points += FRAMEWORK_BEAN_INPUT_BONUS;
        }
        points -= chain.unresolvedHops() * 2;
        if (notes != null) {
            points += notes.stream().filter(note -> note != null && note.startsWith("pattern:"))
                    .count() * PATTERN_BONUS;
        }
        return points;
    }

    private static int rankFromScore(int score) {
        return score >= 5 ? 0 : score >= 3 ? 1 : 2;
    }

    private static List<String> stableNotes(List<String> notes) {
        if (notes == null || notes.isEmpty()) {
            return List.of();
        }
        return notes.stream().filter(java.util.Objects::nonNull).toList();
    }

    private static String firstDegradation(List<String> notes) {
        return notes.stream().filter(note -> note.startsWith("degrade:"))
                .map(note -> note.substring("degrade:".length()))
                .filter(value -> !value.isBlank()).sorted().findFirst().orElse(null);
    }

    private static String degradedBucket(String reason) {
        return "DEGRADED(" + reason + ")";
    }

    private static int entryWeight(String entryKind) {
        if (entryKind == null) {
            return 0;
        }
        return switch (entryKind) {
            case "readObject", "readResolve", "readObjectNoData", "readExternal",
                    "writeReplace", "hashCode", "proxyInvoke" -> 2;
            case "equals", "compareTo", "compare", "toString", "finalize" -> 1;
            default -> 1;
        };
    }

    private static boolean hasFrameworkBeanInput(Chain chain) {
        return chain != null && chain.hops().stream()
                .anyMatch(hop -> hop.kind() == HopKind.ENTRY
                        && "framework-bean-input".equals(hop.reason()));
    }
}
