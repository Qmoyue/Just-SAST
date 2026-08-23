package io.just.sast.analysis.hierarchy;

import io.just.sast.model.ClassInfo;
import io.just.sast.model.MethodInfo;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Modifier;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 类层次契约：子类型闭包、方法解析的 JVM 顺序（父类链整体优先于接口）、负缓存。 */
class ClassHierarchyTest {

    private static ClassInfo cls(String name, String superName, String... interfaces) {
        return new ClassInfo(name, superName, List.of(interfaces), Modifier.PUBLIC, List.of(), List.of());
    }

    private static ClassInfo clsWithMethod(String name, String superName, String method, String desc,
                                           String... interfaces) {
        MethodInfo m = new MethodInfo(name, method, desc, Modifier.PUBLIC, List.of(), List.of(), false);
        return new ClassInfo(name, superName, List.of(interfaces), Modifier.PUBLIC, List.of(m), List.of());
    }

    @Test
    void subtypeThroughInterfaceAndSuperclass() {
        ClassHierarchy h = new ClassHierarchy(Map.of(
                "Ser", cls("Ser", "java/lang/Object", "java/io/Serializable"),
                "Mid", cls("Mid", "Ser"),
                "Impl", cls("Impl", "Mid", "java/lang/Runnable")), null);
        assertTrue(h.isSubtypeOf("Impl", "java/io/Serializable"));
        assertTrue(h.isSubtypeOf("Impl", "Mid"));
        assertTrue(h.isSubtypeOf("Impl", "java/lang/Runnable"));
        assertFalse(h.isSubtypeOf("Ser", "Impl"));
        assertFalse(h.isSubtypeOf("Impl", "java/util/List"));
    }

    @Test
    void resolveMethodPrefersSuperclassChainBeforeInterfaceDefault() {
        // JVM 5.4.5：祖父类声明须优先于接口 default method
        ClassHierarchy h = new ClassHierarchy(Map.of(
                "Grand", clsWithMethod("Grand", "java/lang/Object", "run", "()V"),
                "Itf", clsWithMethod("Itf", "java/lang/Object", "run", "()V"),
                "Sub", cls("Sub", "Grand", "Itf")), null);
        assertEquals("Grand", h.resolveMethod("Sub", "run", "()V"));
    }

    @Test
    void resolveMethodFindsOwnThenAncestor() {
        ClassHierarchy h = new ClassHierarchy(Map.of(
                "A", clsWithMethod("A", "java/lang/Object", "toString", "()Ljava/lang/String;"),
                "B", clsWithMethod("B", "A", "toString", "()Ljava/lang/String;"),
                "C", cls("C", "B")), null);
        assertEquals("B", h.resolveMethod("C", "toString", "()Ljava/lang/String;"));
        assertNull(h.resolveMethod("C", "absent", "()V"));
    }

    @Test
    void implementersCapReturnsNullWhenExceeded() {
        java.util.Map<String, ClassInfo> classes = new java.util.HashMap<>();
        for (int i = 0; i < 5; i++) {
            classes.put("Impl" + i, cls("Impl" + i, "java/lang/Object", "Itf"));
        }
        ClassHierarchy h = new ClassHierarchy(classes, null);
        assertEquals(5, h.implementers("Itf", 10).size());
        assertNull(h.implementers("Itf", 3), "超上限应返回 null 表示放弃枚举");
    }
}
