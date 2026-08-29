package io.just.sast.cpg.build;

import io.just.sast.model.InsnFact;
import io.just.sast.model.MethodInfo;
import io.just.sast.model.MethodRef;
import io.just.sast.model.Op;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Modifier;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/** CPG 语义切片与共享 CFG 的用户可见契约。 */
class CpgIndexTest {

    @Test
    void methodSliceUsesCompactSemanticOffsets() {
        MethodInfo method = new MethodInfo("T", "run", "()V", Modifier.PUBLIC,
                List.of(
                        new InsnFact(0, Op.ALOAD, List.of(0)),
                        new InsnFact(1, Op.INVOKEVIRTUAL,
                                List.of(new MethodRef("T", "call", "()V"))),
                        new InsnFact(2, Op.GETFIELD,
                                List.of(new io.just.sast.model.FieldRef("T", "value", "I"))),
                        new InsnFact(3, Op.IFNULL, List.of(5)),
                        new InsnFact(4, Op.NEW, List.of(new io.just.sast.model.TypeRef("Ljava/lang/Object;"))),
                        new InsnFact(5, Op.RETURN, List.of())),
                List.of(), false);

        CpgIndex.Builder builder = CpgIndex.builder();
        CpgIndex.Builder.MethodSliceBuilder slice = builder.start(method);
        method.instructions().forEach(slice::accept);
        // finish is required before publishing; an unfinished method cannot leak into the index.
        assertNull(builder.build().slice("T#run()V"));

        CpgIndex.Builder publishedBuilder = CpgIndex.builder();
        CpgIndex.Builder.MethodSliceBuilder published = publishedBuilder.start(method);
        method.instructions().forEach(published::accept);
        published.finish();
        CpgIndex index = publishedBuilder.build();

        CpgIndex.MethodSlice result = index.slice("T#run()V");
        assertEquals(6, result.instructionCount());
        assertArrayEquals(new int[]{1}, result.callOffsets());
        assertArrayEquals(new int[]{2}, result.fieldReadOffsets());
        assertArrayEquals(new int[]{3}, result.controlOffsets());
        assertArrayEquals(new int[]{4}, result.allocationOffsets());
        assertArrayEquals(new int[]{1}, result.effectOffsets());
        int[] returned = result.callOffsets();
        returned[0] = 99;
        assertArrayEquals(new int[]{1}, result.callOffsets(), "切片数组不能被外部改写");
        assertNotSame(returned, result.callOffsets());
    }

    @Test
    void cfgIsSharedAcrossReadOnlyConsumers() {
        MethodInfo method = new MethodInfo("T", "run", "()V", Modifier.PUBLIC,
                List.of(new InsnFact(0, Op.NOP, List.of()), new InsnFact(1, Op.RETURN, List.of())),
                List.of(), false);
        CpgIndex.Builder builder = CpgIndex.builder();
        CpgIndex.Builder.MethodSliceBuilder slice = builder.start(method);
        method.instructions().forEach(slice::accept);
        slice.finish();
        CpgIndex index = builder.build();

        assertSame(index.cfg(method), index.cfg(method));
        assertEquals(1, index.cfgCacheSize());
        assertEquals(1, index.cfgBuilds());
        assertEquals(1, index.cfgCacheHits());
        index.clearCfgCache();
        assertEquals(0, index.cfgCacheSize());
    }

    @Test
    void semanticOffsetsCanBeConsumedWithoutExposingBackingArrays() {
        MethodInfo method = new MethodInfo("T", "run", "()V", Modifier.PUBLIC,
                List.of(new InsnFact(0, Op.GETFIELD,
                        List.of(new io.just.sast.model.FieldRef("T", "value", "I")))),
                List.of(), false);
        CpgIndex.Builder builder = CpgIndex.builder();
        CpgIndex.Builder.MethodSliceBuilder slice = builder.start(method);
        method.instructions().forEach(slice::accept);
        slice.finish();
        CpgIndex.MethodSlice result = builder.build().slice("T#run()V");
        java.util.List<Integer> offsets = new java.util.ArrayList<>();
        result.forEachFieldReadOffset(offsets::add);
        assertEquals(List.of(0), offsets);
    }
}
