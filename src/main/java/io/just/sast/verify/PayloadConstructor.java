package io.just.sast.verify;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.*;

/**
 * V8 动态验证：Payload 构造器——对候选链尝试以反射构造入口对象图。
 * 
 * 三层判定：
 * 1. CONSTRUCTIBLE：入口类与可见字段图可检查 → 对象图大概率可构造
 * 2. PARTIALLY_CONSTRUCTIBLE：入口可检查但部分字段不可填充 → 降级
 * 3. SKIP：类不在目标类路径或构造能力不足，不能据此拒绝静态候选
 * 
 * 纯进程内反射（目标 jar 已在 classpath）。
 */
public final class PayloadConstructor {

    public record ConstructionResult(String verdict, String detail) {}

    private static final int MAX_DEPTH = 5;
    private static final int MAX_FIELDS = 20;
    private static final int MAX_RESULT_CACHE = 8192;

    private final ClassLoader loader;
    /** 当前递归路径，而不是整个扫描调用的全局 visited；共享字段类型不能被误判为环。 */
    private final Set<String> active = new HashSet<>();
    /** 构造可行性只依赖类结构；同一入口常对应大量候选链，跨链复用解析和字段遍历。 */
    private final Map<String, Class<?>> classCache = new HashMap<>();
    /** Depth is part of the key: a result computed near the root has more budget than one
     * reached at the depth boundary and must not be reused in the latter context. */
    private record ConstructionKey(String className, int depth) {}
    private final Map<ConstructionKey, ConstructionResult> resultCache = new HashMap<>();
    private final java.util.ArrayDeque<ConstructionKey> resultOrder = new java.util.ArrayDeque<>();

    public PayloadConstructor(ClassLoader loader) {
        this.loader = loader;
    }

    /** 尝试构造链的入口对象。 */
    public ConstructionResult tryConstruct(String entryClassDotted) {
        if (entryClassDotted == null || entryClassDotted.isBlank()) {
            return new ConstructionResult("SKIP", "invalid-entry-class");
        }
        active.clear();
        return tryInstantiate(entryClassDotted, 0);
    }

    private ConstructionResult tryInstantiate(String className, int depth) {
        if (depth > MAX_DEPTH) {
            return new ConstructionResult("PARTIALLY_CONSTRUCTIBLE", "max-depth");
        }
        if (!active.add(className)) {
            return new ConstructionResult("CONSTRUCTIBLE", "cycle-ok");
        }
        try {
            ConstructionKey cacheKey = new ConstructionKey(className, depth);
            ConstructionResult cached = resultCache.get(cacheKey);
            if (cached != null) {
                return cached;
            }
            Class<?> cls;
            try {
                cls = classCache.get(className);
                if (cls == null) {
                    cls = Class.forName(className, false, loader);
                    classCache.put(className, cls);
                }
            } catch (ClassNotFoundException e) {
                // 类不在当前 classpath（在目标 jar 中）——不可判定，跳过不拒
                return new ConstructionResult("SKIP", "not-on-classpath:" + className);
            } catch (LinkageError e) {
                // 目标工件经常只携带部分可选运行时依赖。类链接失败是验证能力边界，
                // 不能让一条缺依赖链中止整个 verify 阶段，也不能把它当成静态否定。
                return new ConstructionResult("SKIP", "linkage:" + className + ":"
                        + e.getClass().getSimpleName());
            }
            if (cls.isInterface() || Modifier.isAbstract(cls.getModifiers())) {
                return new ConstructionResult("SKIP", "abstract:" + className);
            }

            // Java serialization bypasses the serializable class constructor；无参构造器缺失
            // 不是静态链的充分拒绝条件，因此仅作为探针能力边界，不在这里判死。
            int fieldCount = 0;
            List<String> unfillable = new ArrayList<>();
            boolean depthLimited = false;
            for (Class<?> current = cls; current != null && current != Object.class; current = current.getSuperclass()) {
                for (Field f : current.getDeclaredFields()) {
                    if (Modifier.isStatic(f.getModifiers()) || Modifier.isTransient(f.getModifiers())) {
                        continue;
                    }
                    if (++fieldCount > MAX_FIELDS) {
                        break;
                    }
                    Class<?> fieldType = f.getType();
                    if (fieldType.isPrimitive() || fieldType == String.class
                            || fieldType == Object.class || fieldType.isEnum()) {
                        continue; // 可直接赋值
                    }
                    if (!java.io.Serializable.class.isAssignableFrom(fieldType)) {
                        unfillable.add(f.getName() + ":" + fieldType.getSimpleName());
                        continue;
                    }
                    // 递归检查字段类型；任何非 CONSTRUCTIBLE 结果都必须向父图传播，
                    // 否则 SKIP 子节点会被错误地吞掉并把父链标成 CONSTRUCTIBLE。
                    ConstructionResult sub = tryInstantiate(fieldType.getName(), depth + 1);
                    if (!sub.verdict().equals("CONSTRUCTIBLE")) {
                        unfillable.add(f.getName() + ":" + fieldType.getSimpleName());
                        depthLimited |= "max-depth".equals(sub.detail());
                    }
                }
                if (fieldCount > MAX_FIELDS) {
                    break;
                }
            }
            if (unfillable.isEmpty()) {
                ConstructionResult result = new ConstructionResult("CONSTRUCTIBLE", className);
                cacheResult(cacheKey, result);
                return result;
            }
            ConstructionResult result = new ConstructionResult("PARTIALLY_CONSTRUCTIBLE",
                    className + " unfillable:" + String.join(",", unfillable));
            if (!depthLimited) {
                cacheResult(cacheKey, result);
            }
            return result;
        } catch (LinkageError e) {
            // getSuperclass/getDeclaredFields 等反射 API 也可能在解析字段类型时触发链接错误。
            // 与入口 Class.forName 一样，只记录探针不可判定，不污染其他候选链。
            return new ConstructionResult("SKIP", "linkage:" + className + ":"
                    + e.getClass().getSimpleName());
        } finally {
            active.remove(className);
        }
    }

    private void cacheResult(ConstructionKey key, ConstructionResult result) {
        if (key == null || result == null || resultCache.containsKey(key)) {
            return;
        }
        while (resultCache.size() >= MAX_RESULT_CACHE && !resultOrder.isEmpty()) {
            resultCache.remove(resultOrder.removeFirst());
        }
        resultCache.put(key, result);
        resultOrder.addLast(key);
    }
}
