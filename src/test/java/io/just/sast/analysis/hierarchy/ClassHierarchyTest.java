package io.just.sast.analysis.hierarchy;

import io.just.sast.model.ClassInfo;
import io.just.sast.model.JdkClassSource;
import io.just.sast.model.MethodInfo;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Modifier;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

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

    private static ClassInfo clsWithMethodAccess(String name, String superName, int access,
                                                 String method, String desc) {
        MethodInfo m = new MethodInfo(name, method, desc, access, List.of(), List.of(), false);
        return new ClassInfo(name, superName, List.of(), Modifier.PUBLIC, List.of(m), List.of());
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
    void inheritedFinalMethodIsNotAnOverridableDispatchTarget() {
        ClassHierarchy h = new ClassHierarchy(Map.of(
                "Base", clsWithMethodAccess("Base", "java/lang/Object",
                        Modifier.PUBLIC | Modifier.FINAL, "getClass", "()Ljava/lang/Class;"),
                "Sub", cls("Sub", "Base")), null);

        assertFalse(h.isOverridableDispatchTarget("Base", "Sub", "getClass", "()Ljava/lang/Class;"),
                "继承的 final 方法也不得被当成可动态分派目标");
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

    @Test
    void transitiveSubtypesIncludeGrandchildren() {
        // 深继承链（JsonSerializer → StdSerializer → BeanSerializerBase → BeanSerializer 形态）：
        // 传递闭包必须含孙类——调用图与引擎侧展开共用同一来源（历史缺陷：两处直接/传递口径分叉）
        ClassHierarchy h = new ClassHierarchy(Map.of(
                "Base", cls("Base", "java/lang/Object"),
                "Mid", cls("Mid", "Base"),
                "Deep", cls("Deep", "Base"),
                "GrandChild", cls("GrandChild", "Mid"),
                "Unrelated", cls("Unrelated", "java/lang/Object")), null);
        List<String> closure = h.transitiveSubtypes("Base");
        assertTrue(closure.contains("Mid") && closure.contains("Deep") && closure.contains("GrandChild"),
                "闭包须含孙类: " + closure);
        assertFalse(closure.contains("Unrelated"));
        assertEquals(closure, h.transitiveSubtypes("Base"), "闭包记忆化：重复调用结果一致");
        assertTrue(h.transitiveSubtypes("Mid").contains("GrandChild"));
        assertTrue(h.transitiveSubtypes("Unrelated").isEmpty());
    }

    @Test
    void implementersIncludeSubclassesOfConcreteImplementers() {
        ClassHierarchy h = new ClassHierarchy(Map.of(
                "Base", cls("Base", "java/lang/Object", "Itf"),
                "Mid", cls("Mid", "Base"),
                "Deep", cls("Deep", "Mid")), null);
        assertEquals(List.of("Base", "Deep", "Mid"), h.implementers("Itf", 10),
                "接口实现闭包必须穿过实现类继续枚举其覆写子类，并按稳定键排序");
    }

    @Test
    void concurrentJdkLoadDoesNotReturnTransientNull() throws Exception {
        ClassInfo loaded = cls("jdk/Fake", "java/lang/Object");
        CountDownLatch loadStarted = new CountDownLatch(1);
        CountDownLatch releaseLoad = new CountDownLatch(1);
        JdkClassSource source = name -> {
            loadStarted.countDown();
            try {
                releaseLoad.await(2, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return null;
            }
            return loaded;
        };
        ClassHierarchy h = new ClassHierarchy(Map.of(), source);
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            var first = pool.submit(() -> h.classInfo("jdk/Fake"));
            assertTrue(loadStarted.await(1, TimeUnit.SECONDS));
            var second = pool.submit(() -> h.classInfo("jdk/Fake"));
            releaseLoad.countDown();
            assertEquals(loaded, first.get(1, TimeUnit.SECONDS));
            assertEquals(loaded, second.get(1, TimeUnit.SECONDS),
                    "并发懒加载不能把负缓存竞争误报为类不存在");
        } finally {
            releaseLoad.countDown();
            pool.shutdownNow();
        }
    }

    @Test
    void loadingNewImplementerInvalidatesInterfaceCache() {
        ClassInfo late = cls("jdk/Late", "java/lang/Object", "Itf");
        JdkClassSource source = name -> "jdk/Late".equals(name) ? late : null;
        ClassHierarchy h = new ClassHierarchy(Map.of(), source);
        assertTrue(h.implementers("Itf", 10).isEmpty());
        assertEquals(late, h.classInfo("jdk/Late"));
        assertEquals(List.of("jdk/Late"), h.implementers("Itf", 10),
                "懒加载新实现类后，接口实现者缓存必须失效");
    }

    @Test
    void stableNegativeJdkLookupIsCached() {
        AtomicInteger loads = new AtomicInteger();
        JdkClassSource source = name -> {
            loads.incrementAndGet();
            return null;
        };
        ClassHierarchy h = new ClassHierarchy(Map.of(), source);

        assertNull(h.classInfo("jdk/MissingBase"));
        assertNull(h.classInfo("jdk/MissingBase"));
        assertEquals(1, loads.get(), "稳定 JDK 来源的缺失类应走负缓存，避免热路径反复探测");
    }

    @Test
    void transientJdkFailureDoesNotPoisonLaterLookup() {
        ClassInfo loaded = cls("jdk/LateRetry", "java/lang/Object");
        AtomicInteger loads = new AtomicInteger();
        JdkClassSource source = name -> {
            if (loads.incrementAndGet() == 1) {
                throw new IllegalStateException("transient provider failure");
            }
            return loaded;
        };
        ClassHierarchy h = new ClassHierarchy(Map.of(), source);

        assertNull(h.classInfo("jdk/LateRetry"));
        assertEquals(loaded, h.classInfo("jdk/LateRetry"));
        assertEquals(2, loads.get());
    }

    @Test
    void transitiveInterfacesTraverseInterfaceParentsAndInvalidNamesAreSafe() {
        ClassHierarchy h = new ClassHierarchy(Map.of(
                "Parent", cls("Parent", "java/lang/Object"),
                "Child", cls("Child", "java/lang/Object", "Parent"),
                "Impl", cls("Impl", "java/lang/Object", "Child")), null);

        assertEquals(List.of("Child", "Parent"), h.transitiveInterfaces("Impl"));
        assertTrue(h.transitiveSubtypes(null).isEmpty());
        assertTrue(h.transitiveInterfaces("").isEmpty());
        assertTrue(h.implementers(null, 10).isEmpty());
        assertNull(h.resolveMethod(null, "run", "()V"));
        assertFalse(h.isSubtypeOf("", "Parent"));
    }
}
