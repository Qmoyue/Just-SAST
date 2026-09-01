package io.just.sast.blackboard;

/**
 * 链上的一跳。desc 为目标方法描述符（entry/字段跳为空），供 PASM 校验；
 * argOrdinal 为被传播值在目标方法形参中的序数（0 基，receiver/未知为 null），供类型流校准。
 * fieldOwner 保留 FIELD_FLOW 的真实声明类；旧扩展点可省略它，校准器随后使用 toOwner 兼容。
 */
public record ChainHop(
        String fromOwner, String fromName,
        String toOwner, String toName,
        HopKind kind, String field, String reason, String desc,
        Integer argOrdinal, String fieldOwner) {

    /** Compatibility constructor for extensions written before precise field identity. */
    public ChainHop(String fromOwner, String fromName,
                    String toOwner, String toName,
                    HopKind kind, String field, String reason, String desc,
                    Integer argOrdinal) {
        this(fromOwner, fromName, toOwner, toName, kind, field, reason, desc,
                argOrdinal, null);
    }
}
