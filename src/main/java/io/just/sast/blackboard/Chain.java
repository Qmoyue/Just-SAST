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
        int unresolvedHops,
        String sinkDescriptor) {

    public Chain {
        hops = hops == null ? List.of() : List.copyOf(hops);
        sinkDescriptor = sinkDescriptor == null ? "" : sinkDescriptor;
    }

    /** 兼容扩展点与测试构造：旧调用方未提供 sink 描述符时保持未知。 */
    public Chain(String ruleId, String category, String severity,
                 String entryClass, String entryMethod, String entryKind,
                 String sinkClass, String sinkMethod,
                 List<ChainHop> hops, int unresolvedHops) {
        this(ruleId, category, severity, entryClass, entryMethod, entryKind,
                sinkClass, sinkMethod, hops, unresolvedHops, "");
    }

    public String key() {
        StringBuilder sb = new StringBuilder();
        // 身份键必须区分规则、入口种类、重载和字段/参数流；只拼接目标方法名
        // 会把不同 rule_id 或不同字段路径折叠成一条链，破坏黑板去重与报告追踪。
        append(sb, ruleId);
        append(sb, category);
        append(sb, severity);
        append(sb, entryKind);
        append(sb, entryClass);
        append(sb, entryMethod);
        append(sb, sinkClass);
        append(sb, sinkMethod);
        append(sb, sinkDescriptor);
        for (ChainHop hop : hops) {
            append(sb, hop.fromOwner());
            append(sb, hop.fromName());
            append(sb, hop.toOwner());
            append(sb, hop.toName());
            append(sb, hop.kind());
            append(sb, hop.field());
            append(sb, hop.desc());
            append(sb, hop.argOrdinal());
        }
        return sb.toString();
    }

    private static void append(StringBuilder sb, Object value) {
        sb.append(value == null ? "<null>" : value).append('|');
    }
}
