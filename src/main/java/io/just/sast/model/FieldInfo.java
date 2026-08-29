package io.just.sast.model;

import java.lang.reflect.Modifier;

/** 字段事实。 */
public record FieldInfo(String owner, String name, String descriptor, int access,
                        Object constantValue) {

    /** Compatibility constructor for model users that do not carry ConstantValue metadata. */
    public FieldInfo(String owner, String name, String descriptor, int access) {
        this(owner, name, descriptor, access, null);
    }

    public boolean isStatic() {
        return Modifier.isStatic(access);
    }
}
