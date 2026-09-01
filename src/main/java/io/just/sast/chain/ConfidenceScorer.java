package io.just.sast.chain;

import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.HopKind;

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
 * 动态证据是分层的：SINK_BLOCKED +4；CONCRETE_REACHED +2；EXECUTED +1；
 * SAFE_EFFECT_OBSERVED +1（这是失真 adapter 的效果，不能与 canary 边界同级）。
 * 分桶：FEASIBLE 只保留静态可行或真实 canary 边界；安全 adapter、具体前缀和入口返回
 * 都显式标记为 DEGRADED(reason)，不可验证不会被当成负向证明。
 */
public final class ConfidenceScorer {

    /** 供排序器复用的动态证据层级；数值越小越强。 */
    public static final int DYNAMIC_SINK_BOUNDARY = 0;
    public static final int DYNAMIC_CONCRETE_TRIGGER = 1;
    public static final int DYNAMIC_SAFE_ADAPTER = 2;
    public static final int DYNAMIC_ENTRY_RETURN = 3;
    public static final int DYNAMIC_NEGATIVE_OR_UNTESTABLE = 4;
    public static final int DYNAMIC_NOT_SELECTED = 5;

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

    public static String score(Chain chain, List<String> notes) {
        if (chain == null) {
            return "UNKNOWN";
        }
        // An authenticated exact canary boundary is direct runtime evidence. It must not be
        // demoted by a static unresolved-hop penalty or a probe-side construction warning;
        // those limitations remain visible in the evidence vector and notes.
        if (hasNote(notes, "verify:sink-blocked") || hasNote(notes, "verify:confirmed")) {
            return hasNote(notes, "degrade:sink-canary-non-strict-os")
                    ? "DEGRADED(SINK_CANARY_NON_STRICT_OS)" : "FEASIBLE";
        }
        int r = rank(chain, notes);
        List<String> degradations = notes == null ? List.of() : notes.stream()
                .filter(n -> n != null && n.startsWith("degrade:")).toList();
        if (r == 2 || chain.unresolvedHops() * 2 > evidenceScore(chain, notes)) {
            return "NOT_FEASIBLE";
        }
        // Safe adapter effects deliberately remain degraded because they are not target
        // effects. Concrete and entry-return observations are weaker prefix evidence.
        if (hasNote(notes, "verify:safe-effect-observed")) {
            return "DEGRADED(SAFE_EFFECT_DISTORTED)";
        }
        if (hasNote(notes, "verify:concrete-reached")) {
            return "DEGRADED(CONCRETE_TRIGGER_ONLY)";
        }
        if (hasNote(notes, "verify:executed")) {
            return "DEGRADED(ENTRY_RETURN_ONLY)";
        }
        if (!degradations.isEmpty()) {
            return "DEGRADED(" + degradations.get(0).substring("degrade:".length()) + ")";
        }
        return r == 0 ? "FEASIBLE" : "FEASIBLE";
    }

    /** 证据分值（越大越可信，供排序与分桶）。notes 为链级注释（pattern 加分来源）。 */
    public static int evidenceScore(Chain chain, List<String> notes) {
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
            points += notes.stream().filter(n -> n != null && n.startsWith("pattern:")).count()
                    * PATTERN_BONUS;
            // 动态验证证据：真实边界 > 具体触发前缀 > 段归因 > 安全 adapter > 入口返回。
            if (notes.stream().anyMatch(n -> n.equals("verify:sink-blocked")
                    || n.equals("verify:confirmed"))) {
                points += SINK_BLOCKED_BONUS;
            } else if (notes.stream().anyMatch(n -> n.equals("verify:segment-confirmed"))) {
                points += SEGMENT_CONFIRMED_BONUS;
            } else if (notes.stream().anyMatch(n -> n.equals("verify:concrete-reached"))) {
                points += 2;
            } else if (notes.stream().anyMatch(n -> n.equals("verify:safe-effect-observed"))) {
                points += 1;
            }
        }
        return points;
    }

    /** Stable dynamic order shared by selection, grouped findings and all report renderers. */
    public static int dynamicRank(String status, List<String> notes) {
        String value = status == null ? "" : status;
        if (value.isBlank()) {
            if (hasNote(notes, "verify:sink-blocked") || hasNote(notes, "verify:confirmed")) {
                return DYNAMIC_SINK_BOUNDARY;
            }
            if (hasNote(notes, "verify:concrete-reached")) {
                return DYNAMIC_CONCRETE_TRIGGER;
            }
            if (hasNote(notes, "verify:safe-effect-observed")) {
                return DYNAMIC_SAFE_ADAPTER;
            }
            if (hasNote(notes, "verify:executed")) {
                return DYNAMIC_ENTRY_RETURN;
            }
            return DYNAMIC_NOT_SELECTED;
        }
        return switch (value) {
            case "SINK_BLOCKED", "SAFE_SINK_EXECUTED" -> DYNAMIC_SINK_BOUNDARY;
            case "CONCRETE_REACHED" -> DYNAMIC_CONCRETE_TRIGGER;
            case "SAFE_EFFECT_OBSERVED" -> DYNAMIC_SAFE_ADAPTER;
            case "EXECUTED" -> DYNAMIC_ENTRY_RETURN;
            case "PARTIAL", "FAILED", "TIMEOUT", "UNTESTABLE" -> DYNAMIC_NEGATIVE_OR_UNTESTABLE;
            default -> DYNAMIC_NOT_SELECTED;
        };
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
        String runtime = stableNotes.stream().anyMatch("verify:sink-blocked"::equals)
                || stableNotes.stream().anyMatch("verify:confirmed"::equals)
                ? "SINK_CANARY_BOUNDARY"
                : stableNotes.stream().anyMatch("verify:concrete-reached"::equals)
                ? "CONCRETE_TRIGGER"
                : stableNotes.stream().anyMatch("verify:safe-effect-observed"::equals)
                ? "SAFE_EFFECT_DISTORTED"
                : stableNotes.stream().anyMatch("verify:executed"::equals)
                ? "ENTRY_RETURN"
                : "NONE";
        int runtimeScore = switch (runtime) {
            case "SINK_CANARY_BOUNDARY" -> SINK_BLOCKED_BONUS;
            case "CONCRETE_TRIGGER" -> 2;
            case "SAFE_EFFECT_DISTORTED" -> 1;
            case "ENTRY_RETURN" -> 1;
            default -> 0;
        };
        int isolationScore = !sandboxReady ? 0 : switch (isolationLevel == null
                ? "" : isolationLevel) {
            case "OS_STRICT" -> 2;
            case "OS_NAMESPACE" -> 1;
            default -> 0;
        };
        return new EvidenceVector(staticScore,
                construction, runtimeScore, isolationScore, completenessPenalty, runtime,
                score(chain, stableNotes));
    }

    /** 置信度等级（数字越小越高）。 */
    public static int rank(Chain chain, List<String> notes) {
        int score = evidenceScore(chain, notes);
        return score >= 5 ? 0 : score >= 3 ? 1 : 2;
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
        }
        return sb.toString();
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

    private static boolean hasNote(List<String> notes, String expected) {
        return notes != null && notes.stream().anyMatch(expected::equals);
    }
}
