package io.just.sast.chain;

import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.HopKind;
import io.just.sast.blackboard.VerificationOutcome;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * 证据化置信度评分：逐跳证据 + 入口权重 + 严重度加成 + 模式加分，产出可复核的分值与分桶。
 * 分值依据（findings.csv 的 evidence 列逐项分解，可人工核对）：
 * 逐跳：DIRECT_CALL +1；FIELD_FLOW +1（带字段名）；VIRTUAL_DISPATCH 0（保守）；LAMBDA 0
 * 入口：readObject/readResolve/readObjectNoData/readExternal/writeReplace/hashCode/proxyInvoke +2；
 *       equals/compareTo/compare/toString/finalize +1；deserialization/serialize（框架源）+1
 * 严重度：HIGH +1
 * 框架对象绑定边界：ENTRY reason=framework-bean-input +2
 * 模式：每个命中的 gadget 模式 +2（notes 中 "pattern:" 前缀计数的实现侧约定）
 * 惩罚：unresolved × 2
 * 动态证据是分层的：SINK_BLOCKED +4；真实安全参数下的目标 sink +3；
 * CONCRETE_REACHED +2；EXECUTED/SAFE_EFFECT_OBSERVED +1。真实安全参数仍带失真标记，
 * 证明可调用性而不是恶意参数可利用性。
 * 分桶：FEASIBLE 必须先通过静态可行性门；真实 canary 边界只能作为静态可行链的附加证据。
 * 安全 adapter、具体前缀、入口返回和静态退化都显式标记为 DEGRADED(reason)，不可验证不会
 * 被当成负向证明。
 */
public final class ConfidenceScorer {

    /** 供排序器复用的动态证据层级；数值越小越强。 */
    public static final int DYNAMIC_REAL_SAFE = 0;
    public static final int DYNAMIC_PREFIX_CONFIRMED = 1;
    public static final int DYNAMIC_SINK_BOUNDARY = 2;
    public static final int DYNAMIC_CONCRETE_TRIGGER = 3;
    public static final int DYNAMIC_SAFE_ADAPTER = 4;
    public static final int DYNAMIC_ENTRY_RETURN = 5;
    public static final int DYNAMIC_NEGATIVE_OR_UNTESTABLE = 5;
    public static final int DYNAMIC_NOT_SELECTED = 6;

    /** 每命中一个 gadget 模式的证据加分（GadgetPattern 经链注释 "pattern:*" 声明）。 */
    public static final int PATTERN_BONUS = 2;
    /** 动态验证证据加分：sink 边界真实到达并被 canary 阻断。 */
    public static final int SINK_BLOCKED_BONUS = 4;
    /** 旧注记常量保留给外部扩展的源兼容性。 */
    public static final int CONFIRMED_BONUS = SINK_BLOCKED_BONUS;
    /** 段归因确认（完整链的内段被子进程证实）加分。 */
    public static final int SEGMENT_CONFIRMED_BONUS = 2;
    /** bridge=deserialize 对 JavaBean setter 参数的外部输入边界证据。 */
    public static final int FRAMEWORK_BEAN_INPUT_BONUS = 2;

    private ConfidenceScorer() {}

    /**
     * Stable, inspectable inputs to both the confidence transition and chain ranking.
     *
     * <p>The static and dynamic dimensions are deliberately disjoint.  In particular,
     * {@code dynamicScore} is never used to decide {@code staticFeasible}; a canary boundary
     * cannot repair an unresolved or otherwise statically incomplete path.</p>
     */
    public record RankFeatures(int staticScore, int dynamicScore, int totalScore,
                               int staticRank, int dynamicRank, int unresolvedPenalty,
                               int degradationCount, boolean staticFeasible,
                               String runtimeStatus, List<String> reasons) {
        public RankFeatures {
            runtimeStatus = runtimeStatus == null ? "" : runtimeStatus;
            reasons = reasons == null ? List.of() : List.copyOf(reasons);
            staticScore = staticScore;
            dynamicScore = dynamicScore;
            totalScore = totalScore;
            staticRank = Math.max(0, staticRank);
            dynamicRank = Math.max(0, dynamicRank);
            unresolvedPenalty = Math.max(0, unresolvedPenalty);
            degradationCount = Math.max(0, degradationCount);
        }
    }

    /**
     * Typed explanation of the legacy confidence bucket.  The bucket remains a string for
     * report compatibility; {@code reasonCode} and {@code features} are the semantic source
     * for new consumers.
     */
    public record ConfidenceTransition(String bucket, String reasonCode,
                                       String runtimeStatus, boolean staticFeasible,
                                       RankFeatures features, List<String> reasons) {
        public ConfidenceTransition {
            bucket = bucket == null || bucket.isBlank() ? "UNKNOWN" : bucket;
            reasonCode = reasonCode == null || reasonCode.isBlank() ? "UNKNOWN" : reasonCode;
            runtimeStatus = runtimeStatus == null ? "" : runtimeStatus;
            features = features == null ? new RankFeatures(0, 0, 0, 2, 6, 0, 0,
                    false, runtimeStatus, List.of()) : features;
            reasons = reasons == null ? List.of() : List.copyOf(reasons);
        }

        public boolean isFeasible() {
            return "FEASIBLE".equals(bucket);
        }
    }

    /**
     * Produce the single confidence transition used by the compatibility score API and new
     * typed readers.  Static admissibility is evaluated before runtime evidence, so a
     * {@code SINK_BLOCKED} observation can confirm a boundary but cannot promote an unresolved
     * chain to {@code FEASIBLE}.
     */
    public static ConfidenceTransition transition(Chain chain, List<String> notes) {
        List<String> stableNotes = stableNotes(notes);
        RankFeatures features = rankFeatures(chain, stableNotes);
        String runtimeStatus = features.runtimeStatus();
        if (chain == null) {
            return new ConfidenceTransition("UNKNOWN", "NULL_CHAIN", runtimeStatus,
                    false, features, features.reasons());
        }
        if (!features.staticFeasible()) {
            return new ConfidenceTransition("NOT_FEASIBLE", "STATIC_INFEASIBLE", runtimeStatus,
                    false, features, features.reasons());
        }

        // A construction/analysis degradation is not erased by a dynamic boundary.  Keep the
        // first reason deterministic so parallel knowledge sources cannot change report order.
        String degradation = firstDegradation(stableNotes);
        if ("SINK_BLOCKED".equals(runtimeStatus) && degradation != null) {
            return new ConfidenceTransition(degradedBucket(degradation), "STATIC_DEGRADATION",
                    runtimeStatus, true, features, features.reasons());
        }
        return switch (runtimeStatus) {
            case "SINK_BLOCKED" -> new ConfidenceTransition("FEASIBLE",
                    "SINK_BOUNDARY_STATIC_FEASIBLE", runtimeStatus, true, features,
                    features.reasons());
            case "PRE_SINK_CONFIRMED" -> new ConfidenceTransition(
                    "DEGRADED(PRE_SINK_HIGH_RISK)", "PRE_SINK_HIGH_RISK", runtimeStatus,
                    true, features, features.reasons());
            case "SINK_EXECUTED_SAFE" -> new ConfidenceTransition(
                    "DEGRADED(REAL_SINK_SAFE_ARGUMENTS)", "REAL_SINK_SAFE_ARGUMENTS",
                    runtimeStatus, true, features, features.reasons());
            case "JNI_EXECUTED_SAFE" -> new ConfidenceTransition(
                    "DEGRADED(JNI_SAFE_FIXTURE)", "JNI_SAFE_FIXTURE", runtimeStatus, true,
                    features, features.reasons());
            case "SAFE_EFFECT_OBSERVED" -> new ConfidenceTransition(
                    "DEGRADED(SAFE_EFFECT_DISTORTED)", "SAFE_EFFECT_DISTORTED", runtimeStatus,
                    true, features, features.reasons());
            case "CONCRETE_REACHED" -> new ConfidenceTransition(
                    "DEGRADED(CONCRETE_TRIGGER_ONLY)", "CONCRETE_TRIGGER_ONLY", runtimeStatus,
                    true, features, features.reasons());
            case "EXECUTED" -> new ConfidenceTransition("DEGRADED(ENTRY_RETURN_ONLY)",
                    "ENTRY_RETURN_ONLY", runtimeStatus, true, features, features.reasons());
            default -> degradation == null
                    ? new ConfidenceTransition("FEASIBLE", "STATIC_FEASIBLE", runtimeStatus,
                    true, features, features.reasons())
                    : new ConfidenceTransition(degradedBucket(degradation), "STATIC_DEGRADATION",
                    runtimeStatus, true, features, features.reasons());
        };
    }

    /** Compute deterministic static/dynamic rank features without mutating chain or notes. */
    public static RankFeatures rankFeatures(Chain chain, List<String> notes) {
        List<String> stableNotes = stableNotes(notes);
        String runtimeStatus = statusFromNotes(stableNotes);
        int staticScore = staticEvidenceScore(chain, stableNotes);
        int dynamicScore = dynamicEvidenceScore(runtimeStatus);
        int unresolvedPenalty = chain == null ? 0 : chain.unresolvedHops() * 2;
        int staticRank = rankFromScore(staticScore);
        int dynamicRank = dynamicRank(runtimeStatus, stableNotes);
        int degradationCount = (int) stableNotes.stream()
                .filter(note -> note.startsWith("degrade:")).count();
        boolean staticFeasible = chain != null && staticRank < 2
                && unresolvedPenalty <= staticScore;
        List<String> reasons = new ArrayList<>();
        if (chain == null) {
            reasons.add("NULL_CHAIN");
        }
        if (staticRank >= 2) {
            reasons.add("STATIC_SCORE_LOW");
        }
        if (unresolvedPenalty > staticScore) {
            reasons.add("UNRESOLVED_STATIC_EVIDENCE");
        }
        if (degradationCount > 0) {
            reasons.add("STATIC_DEGRADATION_PRESENT");
        }
        if (runtimeStatus.isBlank()) {
            reasons.add("DYNAMIC_NOT_SELECTED");
        } else {
            reasons.add("DYNAMIC_" + runtimeStatus);
        }
        reasons.sort(Comparator.naturalOrder());
        return new RankFeatures(staticScore, dynamicScore, staticScore + dynamicScore,
                staticRank, dynamicRank, unresolvedPenalty, degradationCount, staticFeasible,
                runtimeStatus, reasons);
    }

    /** Compatibility bucket projection retained for existing report writers. */
    public static String score(Chain chain, List<String> notes) {
        return transition(chain, notes).bucket();
    }

    /** 证据分值（越大越可信，供排序与分桶）。notes 为链级注释（pattern 加分来源）。 */
    public static int evidenceScore(Chain chain, List<String> notes) {
        RankFeatures features = rankFeatures(chain, notes);
        return features.totalScore();
    }

    /** Stable dynamic order shared by selection, grouped findings and all report renderers. */
    public static int dynamicRank(String status, List<String> notes) {
        String value = status == null ? "" : status;
        if (value.isBlank()) {
            value = statusFromNotes(notes);
        }
        return switch (value) {
            case "SINK_EXECUTED_SAFE", "JNI_EXECUTED_SAFE" -> DYNAMIC_REAL_SAFE;
            case "PRE_SINK_CONFIRMED" -> DYNAMIC_PREFIX_CONFIRMED;
            case "SINK_BLOCKED" -> DYNAMIC_SINK_BOUNDARY;
            case "CONCRETE_REACHED" -> DYNAMIC_CONCRETE_TRIGGER;
            // SAFE_SINK_EXECUTED is a pre-2.0 compatibility label.  It described an
            // adapter-owned operation, never entry into the target sink body, so old reports
            // must not be allowed to outrank the authenticated canary boundary.
            case "SAFE_EFFECT_OBSERVED", "SAFE_SINK_EXECUTED" -> DYNAMIC_SAFE_ADAPTER;
            case "EXECUTED" -> DYNAMIC_ENTRY_RETURN;
            case "PARTIAL", "FAILED", "TIMEOUT", "UNTESTABLE" -> DYNAMIC_NEGATIVE_OR_UNTESTABLE;
            default -> DYNAMIC_NOT_SELECTED;
        };
    }

    /**
     * Typed policy entry point. Wire strings remain accepted only by the compatibility overload
     * above; callers that already hold a closed verification outcome must not round-trip it
     * through free text just to rank a finding.
     */
    public static int dynamicRank(VerificationOutcome.Status status, List<String> notes) {
        return dynamicRank(status == null ? null : status.name(), notes);
    }

    /** True only for the authenticated canary boundary; compatibility labels are weaker. */
    public static boolean isSinkBoundaryStatus(String status) {
        return "SINK_BLOCKED".equals(status);
    }

    /** Safe adapter labels are explicitly distorted and never mean target sink execution. */
    public static boolean isSafeAdapterStatus(String status) {
        return "SAFE_EFFECT_OBSERVED".equals(status)
                || "SAFE_SINK_EXECUTED".equals(status);
    }

    /** Real target execution with fixed safe arguments is useful, but intentionally distorted. */
    public static boolean isSafeRealStatus(String status) {
        return "SINK_EXECUTED_SAFE".equals(status)
                || "JNI_EXECUTED_SAFE".equals(status);
    }

    /**
     * Normalize legacy chain notes into the same closed dynamic status used by reports and
     * ranking.  Notes are an extension compatibility input, so null and unknown values are
     * ignored; precedence follows the evidence contract rather than lexical note order.
     */
    public static String statusFromNotes(List<String> notes) {
        return io.just.sast.blackboard.VerificationDetailAdapter.statusFromLegacyNotes(notes);
    }

    /** Compact evidence vector for callers that need an auditable reason, not just a label. */
    public record EvidenceVector(int staticScore, int constructionScore, int runtimeScore,
                                  int isolationScore, int completenessPenalty,
                                  String runtimeEvidence, String confidence) {
        /** Compatibility constructor for consumers of the pre-isolation vector shape. */
        public EvidenceVector(int staticScore, int constructionScore, int runtimeScore,
                              int uncertaintyPenalty, String runtimeEvidence,
                              String confidence) {
            this(staticScore, constructionScore, runtimeScore, 0, uncertaintyPenalty,
                    runtimeEvidence, confidence);
        }

        public EvidenceVector {
            staticScore = Math.max(0, staticScore);
            constructionScore = Math.max(0, constructionScore);
            runtimeScore = Math.max(0, runtimeScore);
            isolationScore = Math.max(0, isolationScore);
            completenessPenalty = Math.max(0, completenessPenalty);
            runtimeEvidence = runtimeEvidence == null ? "NONE" : runtimeEvidence;
            confidence = confidence == null ? "UNKNOWN" : confidence;
        }

        /** Old name retained as an alias; the penalty is the completeness dimension. */
        public int uncertaintyPenalty() {
            return completenessPenalty;
        }

        public int totalScore() {
            return staticScore + constructionScore + runtimeScore + isolationScore
                    - completenessPenalty;
        }
    }

    public static EvidenceVector vector(Chain chain, List<String> notes) {
        return vector(chain, notes, "NONE", false);
    }

    /** Include the authenticated OS capability separately from runtime/canary evidence. */
    public static EvidenceVector vector(Chain chain, List<String> notes,
                                        String isolationLevel, boolean sandboxReady) {
        List<String> stableNotes = notes == null ? List.of() : notes;
        int construction = stableNotes.stream().anyMatch("verify:constructible"::equals) ? 2
                : stableNotes.stream().anyMatch("degrade:partial-construct"::equals) ? 1 : 0;
        int unresolvedPenalty = chain == null ? 0 : chain.unresolvedHops() * 2;
        int completenessPenalty = unresolvedPenalty + (int) stableNotes.stream()
                .filter(note -> note != null && note.startsWith("degrade:"))
                .count();
        List<String> staticNotes = stableNotes.stream()
                .filter(note -> note != null && !note.startsWith("verify:"))
                .toList();
        // evidenceScore historically includes the unresolved penalty and dynamic points. Add
        // the penalty back after removing runtime notes so this vector has disjoint dimensions:
        // static positives, construction, runtime, and uncertainty.
        int staticScore = Math.max(0, evidenceScore(chain, staticNotes) + unresolvedPenalty);
        String runtime = switch (statusFromNotes(stableNotes)) {
            case "SINK_BLOCKED" -> "SINK_CANARY_BOUNDARY";
            case "PRE_SINK_CONFIRMED" -> "PREFIX_CHAIN_CONFIRMED";
            case "SINK_EXECUTED_SAFE" -> "REAL_SINK_SAFE_ARGUMENTS";
            case "JNI_EXECUTED_SAFE" -> "JNI_SAFE_FIXTURE";
            case "CONCRETE_REACHED" -> "CONCRETE_TRIGGER";
            case "SAFE_EFFECT_OBSERVED" -> "SAFE_EFFECT_DISTORTED";
            case "EXECUTED" -> "ENTRY_RETURN";
            default -> "NONE";
        };
        int runtimeScore = switch (runtime) {
            case "SINK_CANARY_BOUNDARY" -> SINK_BLOCKED_BONUS;
            case "PREFIX_CHAIN_CONFIRMED" -> SINK_BLOCKED_BONUS;
            case "REAL_SINK_SAFE_ARGUMENTS", "JNI_SAFE_FIXTURE" -> 5;
            case "CONCRETE_TRIGGER" -> 2;
            case "SAFE_EFFECT_DISTORTED" -> 1;
            case "ENTRY_RETURN" -> 1;
            default -> 0;
        };
        int isolationScore = !sandboxReady ? 0 : switch (isolationLevel == null
                ? "" : isolationLevel) {
            case "PROCESS_RESOURCE" -> 1;
            default -> 0;
        };
        return new EvidenceVector(staticScore,
                construction, runtimeScore, isolationScore, completenessPenalty, runtime,
                score(chain, stableNotes));
    }

    /** 置信度等级（数字越小越高），仅由静态证据决定。 */
    public static int rank(Chain chain, List<String> notes) {
        return rankFeatures(chain, notes).staticRank();
    }

    /** evidence 列的因子分解串：逐项列出各加分来源，可人工核对总分。 */
    public static String evidenceDecomposition(Chain chain, List<String> notes) {
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
        StringBuilder sb = new StringBuilder();
        sb.append("hops:direct=").append(direct).append("+").append(direct)
                .append(",virtual=").append(virtual).append("+0")
                .append(",native=").append(nativeCallbacks).append("+0")
                .append(",field=").append(fieldFlows).append("+").append(fieldFlows);
        if (!fieldNames.isEmpty()) {
            sb.append("(").append(fieldNames).append(")");
        }
        sb.append(";entry:").append(chain.entryKind() == null ? "?" : chain.entryKind())
                .append("+").append(entryWeight(chain.entryKind()));
        if ("HIGH".equals(chain.severity())) {
            sb.append(";sev:HIGH+1");
        }
        if (hasFrameworkBeanInput(chain)) {
            sb.append(";source-boundary:framework-bean-input+")
                    .append(FRAMEWORK_BEAN_INPUT_BONUS);
        }
        if (chain.unresolvedHops() > 0) {
            sb.append(";unresolved:").append(chain.unresolvedHops())
                    .append("-").append(chain.unresolvedHops() * 2);
        }
        if (notes != null) {
            for (String note : notes) {
                if (note != null && note.startsWith("pattern:")) {
                    sb.append(";pattern:").append(note.substring("pattern:".length()))
                            .append("+").append(PATTERN_BONUS);
                }
            }
            switch (statusFromNotes(notes)) {
                case "SINK_BLOCKED" -> sb.append(";dynamic:SINK_BLOCKED+")
                        .append(SINK_BLOCKED_BONUS);
                case "SINK_EXECUTED_SAFE" -> sb.append(";dynamic:SINK_EXECUTED_SAFE+3");
                case "JNI_EXECUTED_SAFE" -> sb.append(";dynamic:JNI_EXECUTED_SAFE+3");
                case "CONCRETE_REACHED" -> sb.append(";dynamic:CONCRETE_REACHED+2");
                case "SAFE_EFFECT_OBSERVED", "EXECUTED" -> sb.append(";dynamic:")
                        .append(statusFromNotes(notes)).append("+1");
                default -> { }
            }
        }
        return sb.toString();
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
            points += 1;
        }
        if (hasFrameworkBeanInput(chain)) {
            points += FRAMEWORK_BEAN_INPUT_BONUS;
        }
        points -= chain.unresolvedHops() * 2;
        if (notes != null) {
            points += notes.stream().filter(n -> n != null && n.startsWith("pattern:"))
                    .count() * PATTERN_BONUS;
        }
        return points;
    }

    private static int dynamicEvidenceScore(String status) {
        return switch (status == null ? "" : status) {
            case "SINK_BLOCKED", "PRE_SINK_CONFIRMED" -> SINK_BLOCKED_BONUS;
            case "SINK_EXECUTED_SAFE", "JNI_EXECUTED_SAFE" -> 5;
            case "CONCRETE_REACHED" -> 2;
            case "SAFE_EFFECT_OBSERVED", "EXECUTED" -> 1;
            default -> 0;
        };
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
                .filter(value -> !value.isBlank())
                .sorted()
                .findFirst()
                .orElse(null);
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
            default -> 1; // deserialization / serialize（框架桥源）
        };
    }

    private static boolean hasFrameworkBeanInput(Chain chain) {
        if (chain == null) {
            return false;
        }
        return chain.hops().stream()
                .anyMatch(hop -> hop.kind() == HopKind.ENTRY
                        && "framework-bean-input".equals(hop.reason()));
    }

}
