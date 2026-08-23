package io.just.sast.verify;

import io.just.sast.util.JustLogger;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.*;

/**
 * V8 动态验证：Payload 构造器——对候选链尝试以反射构造入口对象图。
 * 
 * 三层判定：
 * 1. CONSTRUCTIBLE：入口类可实例化、链上字段类型可填充 → 对象图可构造
 * 2. PARTIALLY_CONSTRUCTIBLE：入口可实例化但部分字段不可填充 → 降级
 * 3. NOT_CONSTRUCTIBLE：入口类不可实例化（无默认构造器/abstract/interface）→ 拒
 * 
 * 纯进程内反射（目标 jar 已在 classpath），子进程验证见 VerifyRunner。
 */
public final class PayloadConstructor {

    public record ConstructionResult(String verdict, String detail) {}

    private static final int MAX_DEPTH = 5;
    private static final int MAX_FIELDS = 20;

    private final ClassLoader loader;
    private final Set<String> visited = new HashSet<>();

    public PayloadConstructor(ClassLoader loader) {
        this.loader = loader;
    }

    /** 尝试构造链的入口对象。 */
    public ConstructionResult tryConstruct(String entryClassDotted) {
        visited.clear();
        return tryInstantiate(entryClassDotted, 0);
    }

    private ConstructionResult tryInstantiate(String className, int depth) {
        if (depth > MAX_DEPTH) {
            return new ConstructionResult("PARTIALLY_CONSTRUCTIBLE", "max-depth");
        }
        if (!visited.add(className)) {
            return new ConstructionResult("CONSTRUCTIBLE", "cycle-ok");
        }
        Class<?> cls;
        try {
            cls = Class.forName(className, false, loader);
        } catch (ClassNotFoundException e) {
            // 类不在当前 classpath（在目标 jar 中）——不可判定，跳过不拒
            return new ConstructionResult("SKIP", "not-on-classpath:" + className);
        }
        if (cls.isInterface() || Modifier.isAbstract(cls.getModifiers())) {
            return new ConstructionResult("SKIP", "abstract:" + className);
        }
        // 找无参构造器
        Constructor<?> ctor = null;
        for (Constructor<?> c : cls.getDeclaredConstructors()) {
            if (c.getParameterCount() == 0) {
                ctor = c;
                break;
            }
        }
        if (ctor == null) {
            return new ConstructionResult("SKIP", "no-default-ctor:" + className);
        }
        // 递归检查 Serializable 字段可填充性
        int fieldCount = 0;
        List<String> unfillable = new ArrayList<>();
        for (Field f : cls.getDeclaredFields()) {
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
            // 递归检查字段类型
            ConstructionResult sub = tryInstantiate(fieldType.getName(), depth + 1);
            if (sub.verdict().equals("NOT_CONSTRUCTIBLE")) {
                unfillable.add(f.getName() + ":" + fieldType.getSimpleName());
            }
        }
        if (unfillable.isEmpty()) {
            return new ConstructionResult("CONSTRUCTIBLE", className);
        }
        return new ConstructionResult("PARTIALLY_CONSTRUCTIBLE",
                className + " unfillable:" + String.join(",", unfillable));
    }
}
