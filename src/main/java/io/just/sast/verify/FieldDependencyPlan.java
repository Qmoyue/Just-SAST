package io.just.sast.verify;

import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.HopKind;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * 链的不可变字段依赖计划：把分析产出的 FIELD_FLOW 统一提供给探针、报告和未来 payload writer。
 * 这是 JDD IOCD 思想的轻量落地，不引入第二套 IR，也不把计划当作 sink 已执行证据。
 */
public record FieldDependencyPlan(
        String entryClass, String entryMethod, String triggerMode,
        String sinkClass, String sinkMethod, String sinkDescriptor,
        List<FieldLink> fields) {

    public record FieldLink(String fromOwner, String field, String toOwner) {
        public FieldLink {
            fromOwner = fromOwner == null ? "" : fromOwner;
            field = field == null ? "" : field;
            toOwner = toOwner == null ? "" : toOwner;
        }
    }

    public FieldDependencyPlan {
        if (fields == null || fields.isEmpty()) {
            fields = List.of();
        } else {
            Set<FieldLink> unique = new LinkedHashSet<>();
            for (FieldLink field : fields) {
                if (field != null) {
                    unique.add(field);
                }
            }
            fields = List.copyOf(unique);
        }
        sinkDescriptor = sinkDescriptor == null ? "" : sinkDescriptor;
    }

    public static FieldDependencyPlan from(Chain chain, String triggerMode) {
        List<FieldLink> links = new ArrayList<>();
        List<ChainHop> hops = chain.hops();
        for (int i = 0; i < hops.size(); i++) {
            ChainHop hop = hops.get(i);
            if (hop.kind() == HopKind.FIELD_FLOW && hop.field() != null) {
                String target = hop.toOwner();
                if (target == null || target.isBlank() || target.equals(hop.fromOwner())
                        || isGenericType(target)) {
                    target = inferredTarget(hops, i, chain.entryClass());
                }
                links.add(new FieldLink(hop.fromOwner(), hop.field(), target));
            }
        }
        return new FieldDependencyPlan(chain.entryClass(), chain.entryMethod(), triggerMode,
                chain.sinkClass(), chain.sinkMethod(), chain.sinkDescriptor(), links);
    }

    /** 探针的稳定字段链接编码；只编码数据，不执行目标代码。 */
    public String encodedFields() {
        StringBuilder result = new StringBuilder();
        for (FieldLink link : fields) {
            if (result.length() > 0) {
                result.append(',');
            }
            result.append(link.fromOwner()).append('.').append(link.field())
                    .append('=').append(link.toOwner());
        }
        return result.toString();
    }

    /**
     * Delimiter-safe internal encoding for the child probe. JVM field names normally avoid
     * separators, but class files are not limited to Java source identifiers. Length-prefixing
     * keeps a malformed or unusual artifact from changing the object-plan parse shape.
     * The human/report form remains encodedFields().
     */
    public String encodedFieldsForProbe() {
        StringBuilder result = new StringBuilder("v2;");
        for (FieldLink link : fields) {
            appendLengthPrefixed(result, link.fromOwner());
            appendLengthPrefixed(result, link.field());
            appendLengthPrefixed(result, link.toOwner());
        }
        return result.toString();
    }

    private static void appendLengthPrefixed(StringBuilder out, String value) {
        String safe = value == null ? "" : value;
        out.append(safe.length()).append(':').append(safe);
    }

    /** 反向链中的字段跳没有单独的 points-to 类型；向入口方向取最近的具体对象类型。 */
    private static String inferredTarget(List<ChainHop> hops, int fieldIndex, String fallback) {
        String owner = hops.get(fieldIndex).fromOwner();
        for (int i = fieldIndex + 1; i < hops.size(); i++) {
            ChainHop next = hops.get(i);
            if (next.kind() == HopKind.ENTRY) {
                return fallback;
            }
            String candidate = next.toOwner();
            if (candidate != null && !candidate.isBlank() && !candidate.equals(owner)
                    && !isGenericType(candidate)) {
                return candidate;
            }
            candidate = next.fromOwner();
            if (candidate != null && !candidate.isBlank() && !candidate.equals(owner)
                    && !isGenericType(candidate)) {
                return candidate;
            }
        }
        return fallback == null ? owner : fallback;
    }

    private static boolean isGenericType(String owner) {
        return "java/lang/Object".equals(owner)
                || "java/io/Serializable".equals(owner)
                || "java/lang/Comparable".equals(owner);
    }
}
