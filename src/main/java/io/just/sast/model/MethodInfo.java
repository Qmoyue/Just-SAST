package io.just.sast.model;

import java.lang.reflect.Modifier;
import java.util.List;

/** 方法事实。 */
public record MethodInfo(
        String owner,
        String name,
        String descriptor,
        int access,
        List<InsnFact> instructions,
        List<TryCatchFact> tryCatch,
        boolean hasDebugInfo,
        int entryLine) {

    /** 兼容构造：无行号信息（entryLine = -1，SARIF 定位缺省不输出 region）。 */
    public MethodInfo(String owner, String name, String descriptor, int access,
                      List<InsnFact> instructions, List<TryCatchFact> tryCatch, boolean hasDebugInfo) {
        this(owner, name, descriptor, access, instructions, tryCatch, hasDebugInfo, -1);
    }

    /** 约定：instructions 按下标稠密排列，instructions.get(offset).offset() == offset。 */
    public InsnFact insnAt(int offset) {
        return instructions.get(offset);
    }

    public boolean isStatic() {
        return Modifier.isStatic(access);
    }

    /** 参数个数（不含 this）。 */
    public int paramCount() {
        return Descriptor.paramCount(descriptor);
    }
}
