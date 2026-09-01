package io.just.sast.model;

import io.just.sast.model.ClassInfo;

/** JDK 类来源（由 frontend 层实现，避免分析层依赖 ASM）。 */
public interface JdkClassSource extends AutoCloseable {

    /** 按内部名加载 JDK 类；不可用返回 null。 */
    ClassInfo load(String internalName);

    /**
     * Return the owning module when the source can prove one. Legacy rt.jar sources return
     * {@code null}; a missing value is an observation limit, not permission to guess a module.
     */
    default String moduleOf(String internalName) {
        return null;
    }

    /**
     * Release resources owned by a target-JDK source.  Runtime-backed sources do not own the
     * process JRT filesystem, so their default implementation is intentionally a no-op.  A
     * default keeps the frontend extension contract source-compatible for third-party sources.
     */
    @Override
    default void close() {
    }
}
