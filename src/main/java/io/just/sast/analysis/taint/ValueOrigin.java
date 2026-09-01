package io.just.sast.analysis.taint;

/** 值来源（正向抽象解释的产物，反向/前向污点的输入）。 */
public sealed interface ValueOrigin
        permits ValueOrigin.Param, ValueOrigin.Insn, ValueOrigin.CallResult,
                ValueOrigin.FieldRead, ValueOrigin.Constant, ValueOrigin.Unknown {

    /** 被分析方法的参数：slot 为局部变量槽（实例方法 this=0；long/double 参数占 2 槽）。 */
    record Param(int slot) implements ValueOrigin {}

    /** 指令产物（NEW/数组读/算术/转换等）。 */
    record Insn(int offset) implements ValueOrigin {}

    /** 调用返回值。 */
    record CallResult(long callNodeId) implements ValueOrigin {}

    /** 字段读取（保留 JVM descriptor，避免字段隐藏/重载近似串线）。 */
    record FieldRead(String owner, String field, String descriptor,
                     boolean isStatic, ValueOrigin receiver) implements ValueOrigin {
        /** Compatibility constructor for extensions created before descriptor tracking. */
        public FieldRead(String owner, String field, boolean isStatic, ValueOrigin receiver) {
            this(owner, field, "", isStatic, receiver);
        }
    }

    /** 常量（回溯死胡同）。 */
    record Constant(Object value) implements ValueOrigin {}

    /** 不可解析（含异常边进入 handler 时压入的异常对象）。 */
    record Unknown() implements ValueOrigin {}
}
