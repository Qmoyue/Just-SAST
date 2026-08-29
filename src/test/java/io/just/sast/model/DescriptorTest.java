package io.just.sast.model;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

/** 描述符解析的语义契约；重复调用还覆盖缓存返回的不可变结果。 */
class DescriptorTest {

    @Test
    void parsesReferenceAndWideParametersWithoutChangingJvmSlots() {
        String descriptor = "(Ljava/lang/String;JD[[I)V";

        assertEquals(4, Descriptor.paramCount(descriptor));
        assertEquals(List.of(1, 2, 2, 1), Descriptor.argSlots(descriptor, true));
        assertEquals(List.of(1, 1, 2, 2, 1), Descriptor.argSlots(descriptor, false));
        assertEquals(0, Descriptor.paramOrdinal(descriptor, true, 0));
        assertEquals(1, Descriptor.paramOrdinal(descriptor, true, 1));
        assertEquals(-2, Descriptor.paramOrdinal(descriptor, true, 2),
                "long 的第二局部槽不是独立参数");
        assertEquals(2, Descriptor.paramOrdinal(descriptor, false, 4));
        assertEquals("J", Descriptor.paramType(descriptor, 1));
        assertEquals("[[I", Descriptor.paramType(descriptor, 3));
    }
}
