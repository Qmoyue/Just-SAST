package io.just.sast.frontend.asm;

import io.just.sast.model.ArchiveMemberProvenance;

/** 从输入中读取到的单个 class 字节。 */
public record ClassBytes(String className, byte[] bytes, String origin,
                         ArchiveMemberProvenance provenance) {

    /** Compatibility constructor for extension callers without archive-member facts. */
    public ClassBytes(String className, byte[] bytes, String origin) {
        this(className, bytes, origin, null);
    }

    public ClassBytes withProvenance(ArchiveMemberProvenance value) {
        return new ClassBytes(className, bytes, origin, value);
    }
}
