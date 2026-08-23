package io.just.sast.blackboard;

import java.util.List;

/**
 * 候选 gadget 链（分析知识源产物）。
 * hops 顺序：sink → entry（反向搜索的自然顺序），报告时翻转。
 */
public record Chain(
        String ruleId, String category, String severity,
        String entryClass, String entryMethod, String entryKind,
        String sinkClass, String sinkMethod,
        List<ChainHop> hops,
        int unresolvedHops) {

    public String key() {
        StringBuilder sb = new StringBuilder();
        sb.append(entryClass).append('.').append(entryMethod)
                .append(" -> ").append(sinkClass).append('.').append(sinkMethod)
                .append(" | ");
        for (ChainHop hop : hops) {
            sb.append(hop.toOwner()).append('.').append(hop.toName()).append(hop.kind()).append(';');
        }
        return sb.toString();
    }
}
