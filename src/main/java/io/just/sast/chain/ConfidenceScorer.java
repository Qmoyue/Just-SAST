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
 * 分桶（V2 四级判定，GadgetHunter schema）：
 * FEASIBLE = 证据充分无降级信号；DEGRADED(reason) = 有降级信号但非可证不可能；
 * NOT_FEASIBLE = 被校准拒绝或证据极弱
 */
public final class ConfidenceScorer {

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
        int r = rank(chain, notes);
        List<String> degradations = notes == null ? List.of() : notes.stream()
                .filter(n -> n.startsWith("degrade:")).toList();
        if (r == 2 || chain.unresolvedHops() * 2 > evidenceScore(chain, notes)) {
            return "NOT_FEASIBLE";
        }
        // A sink canary is stronger evidence than a probe-side construction warning:
        // the target method actually reached the modeled sink in the isolated child JVM.
        // Keep the construction limitation in the verification summary/notes, but do not
        // let it demote a directly confirmed path in the primary finding ranking.
        if (notes != null && notes.stream().anyMatch(n -> "verify:sink-blocked".equals(n)
                || "verify:confirmed".equals(n))) {
            return "FEASIBLE";
        }
        if (!degradations.isEmpty()) {
            return "DEGRADED(" + degradations.get(0).substring("degrade:".length()) + ")";
        }
        return r == 0 ? "FEASIBLE" : "FEASIBLE";
    }

    /** 证据分值（越大越可信，供排序与分桶）。notes 为链级注释（pattern 加分来源）。 */
    public static int evidenceScore(Chain chain, List<String> notes) {
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
            points += notes.stream().filter(n -> n.startsWith("pattern:")).count() * PATTERN_BONUS;
            // 动态验证证据：确认 > 段归因确认 > 执行
            if (notes.stream().anyMatch(n -> n.equals("verify:sink-blocked")
                    || n.equals("verify:confirmed"))) {
                points += SINK_BLOCKED_BONUS;
            } else if (notes.stream().anyMatch(n -> n.equals("verify:segment-confirmed"))) {
                points += SEGMENT_CONFIRMED_BONUS;
            } else if (notes.stream().anyMatch(n -> n.equals("verify:concrete-reached")
                    || n.equals("verify:executed"))) {
                points += 1;
            }
        }
        return points;
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
                if (note.startsWith("pattern:")) {
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
        return chain.hops().stream()
                .anyMatch(hop -> hop.kind() == HopKind.ENTRY
                        && "framework-bean-input".equals(hop.reason()));
    }
}
