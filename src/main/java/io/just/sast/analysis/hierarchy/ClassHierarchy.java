package io.just.sast.analysis.hierarchy;

import io.just.sast.model.ClassInfo;
import io.just.sast.model.JdkClassSource;
import io.just.sast.model.MethodInfo;

import java.lang.reflect.Modifier;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * 类层次：子类索引、subtype 判定、Serializable 判定、方法解析（沿父类+接口，支持 default method）。
 * JDK 类按需懒加载。
 */
public final class ClassHierarchy {

    private final Map<String, ClassInfo> classes;
    private final JdkClassSource jdk;
    /** 直接子类型：懒加载时写、ANALYSIS 并行时读——并发结构（写稀少，读密集）。 */
    private final Map<String, List<String>> directSubtypes = new java.util.concurrent.ConcurrentHashMap<>();
    /** 缓存均支持并发读（反向引擎 per-sink 并行）；懒加载失效用 clear()，最坏浪费重算无害。 */
    private final Map<String, Boolean> subtypeCache = new java.util.concurrent.ConcurrentHashMap<>();
    /** Optional 包装：CHM 不容 null 值，empty 表示解析失败。 */
    private final Map<String, Optional<String>> resolveCache = new java.util.concurrent.ConcurrentHashMap<>();
    /** 负缓存：确认不可解析的类名（防未知类名反复触发 JDK 懒加载磁盘探测）。 */
    private final Set<String> unresolvable = java.util.concurrent.ConcurrentHashMap.newKeySet();
    /** implementers 缓存键：接口 + 上限（不同上限结果不同；null 表示该上限下放弃枚举）。 */
    private record IfaceKey(String interfaceName, int cap) {}
    /** Optional 包装：empty 表示该上限下放弃枚举（区别于空列表=无实现者）。 */
    private final Map<IfaceKey, Optional<List<String>>> implementersCache =
            new java.util.concurrent.ConcurrentHashMap<>();

    public ClassHierarchy(Map<String, ClassInfo> initial, JdkClassSource jdk) {
        this.classes = new java.util.concurrent.ConcurrentHashMap<>(initial);
        this.jdk = jdk;
        for (ClassInfo c : initial.values()) {
            indexSubtypes(c);
        }
    }

    private void indexSubtypes(ClassInfo c) {
        if (c.superName() != null) {
            directSubtypes.computeIfAbsent(c.superName(),
                    k -> new java.util.concurrent.CopyOnWriteArrayList<>()).add(c.internalName());
        }
        for (String itf : c.interfaces()) {
            directSubtypes.computeIfAbsent(itf,
                    k -> new java.util.concurrent.CopyOnWriteArrayList<>()).add(c.internalName());
        }
    }

    /** 取类信息，未知类走 JDK 懒加载；确认缺失的类负缓存（来源集合不变，结果稳定）。懒加载段同步（并发下防重复探测/结构破坏）。 */
    public ClassInfo classInfo(String internalName) {
        ClassInfo c = classes.get(internalName);
        if (c != null || jdk == null || !unresolvable.add(internalName)) {
            return c;
        }
        synchronized (this) {
            c = classes.get(internalName);
            if (c != null) {
                return c;
            }
            c = jdk.load(internalName);
            if (c != null) {
                classes.put(internalName, c);
                indexSubtypes(c);
                unresolvable.remove(internalName);
                // B4 增量失效：只清除包含新类名的条目（大语料懒加载时避免全量清缓存 O(n^2)）
                String newName = c.internalName();
                subtypeCache.keySet().removeIf(k -> k.contains(newName));
                resolveCache.keySet().removeIf(k -> k.contains(newName));
                implementersCache.keySet().removeIf(k -> k.interfaceName().contains(newName));
            }
        }
        return c;
    }

    public int classCount() {
        return classes.size();
    }

    /** 已加载类中 name 的直接子类型。 */
    public List<String> loadedSubtypes(String internalName) {
        List<String> list = directSubtypes.get(internalName);
        return list != null ? list : List.of();
    }

    /** 类的传递接口（含父类继承），供接口反向分发使用。 */
    public List<String> transitiveInterfaces(String internalName) {
        List<String> result = new ArrayList<>();
        Deque<String> queue = new ArrayDeque<>();
        Set<String> visited = new HashSet<>();
        queue.add(internalName);
        while (!queue.isEmpty()) {
            String cur = queue.poll();
            if (!visited.add(cur)) {
                continue;
            }
            ClassInfo ci = classInfo(cur);
            if (ci == null) {
                continue;
            }
            for (String itf : ci.interfaces()) {
                if (visited.add(itf)) {
                    result.add(itf);
                    queue.add(itf);
                }
            }
            if (ci.superName() != null) {
                queue.add(ci.superName());
            }
        }
        return result;
    }

    /** a 是否为 b 的子类型（沿父类 + 传递接口）。 */
    public boolean isSubtypeOf(String a, String b) {
        if (a.equals(b)) {
            return true;
        }
        String key = a + "->" + b;
        Boolean cached = subtypeCache.get(key);
        if (cached != null) {
            return cached;
        }
        boolean result = computeSubtype(a, b);
        subtypeCache.put(key, result);
        return result;
    }

    private boolean computeSubtype(String a, String b) {
        Deque<String> queue = new ArrayDeque<>();
        Set<String> visited = new HashSet<>();
        queue.add(a);
        while (!queue.isEmpty()) {
            String cur = queue.poll();
            if (!visited.add(cur)) {
                continue;
            }
            ClassInfo ci = classInfo(cur);
            if (ci == null) {
                continue;
            }
            if (b.equals(ci.superName())) {
                return true;
            }
            if (ci.interfaces().contains(b)) {
                return true;
            }
            if (ci.superName() != null) {
                queue.add(ci.superName());
            }
            queue.addAll(ci.interfaces());
        }
        return false;
    }

    public boolean isSerializable(String internalName) {
        return isSubtypeOf(internalName, "java/io/Serializable");
    }

    /**
     * 解析方法声明位置。按 JVM 方法解析顺序（JLS/JVMS 5.4.5）：先沿父类链逐级查找，
     * 再按接口 BFS（含各接口的父类链）查找第一个声明 (name, desc) 的类——父类链整体优先于
     * 接口 default method，与真实 JVM 分派一致。未找到返回 null。
     */
    public String resolveMethod(String owner, String name, String desc) {
        String key = owner + "#" + name + desc;
        Optional<String> cached = resolveCache.get(key);
        if (cached != null) {
            return cached.orElse(null);
        }
        String result = computeResolve(owner, name, desc);
        resolveCache.put(key, Optional.ofNullable(result));
        return result;
    }

    /** 方法的 access 标志（声明类解析）；不可解析返回 -1。 */
    public int methodAccess(String owner, String name, String desc) {
        ClassInfo ci = classInfo(owner);
        MethodInfo m = ci != null ? ci.method(name, desc) : null;
        return m != null ? m.access() : -1;
    }

    /**
     * candidate 类上的 (name, desc) 是否可作为 declared（被覆写方法的声明类）虚分派的覆写目标
     * （JVMS 5.4.5 覆写条件）：private/static 不可覆写；package-private 仅同包覆写
     * （同包判定以声明类为基准，非调用点静态类型）。FLASH (USENIX'25) 可见性剪枝的 JVM 语义实现。
     */
    public boolean isOverridableDispatchTarget(String declared, String candidate, String name, String desc) {
        int access = methodAccess(candidate, name, desc);
        if (access < 0) {
            return true; // 不可解析：保守视为可
        }
        if (Modifier.isPrivate(access) || Modifier.isStatic(access)) {
            return false;
        }
        if (Modifier.isPublic(access) || Modifier.isProtected(access)) {
            return true;
        }
        return packageOf(candidate).equals(packageOf(declared));
    }

    private static String packageOf(String internalName) {
        int idx = internalName.lastIndexOf('/');
        return idx > 0 ? internalName.substring(0, idx) : "";
    }

    private String computeResolve(String owner, String name, String desc) {
        // 1. 父类链（含自身）优先
        String cur = owner;
        Set<String> seen = new HashSet<>();
        while (cur != null && seen.add(cur)) {
            ClassInfo ci = classInfo(cur);
            if (ci == null) {
                break;
            }
            if (ci.method(name, desc) != null) {
                return cur;
            }
            cur = ci.superName();
        }
        // 2. 接口 BFS（含各接口的父类链）
        Deque<String> queue = new ArrayDeque<>();
        Set<String> visited = new HashSet<>();
        queue.add(owner);
        while (!queue.isEmpty()) {
            String itf = queue.poll();
            if (!visited.add(itf)) {
                continue;
            }
            ClassInfo ci = classInfo(itf);
            if (ci == null) {
                continue;
            }
            if (ci.method(name, desc) != null) {
                return itf;
            }
            if (ci.superName() != null) {
                queue.add(ci.superName()); // 接口的父类链（java.lang.Object 兜底）
            }
            queue.addAll(ci.interfaces());
        }
        return null;
    }

    /** 字段解析：沿父类链找字段声明类；未找到返回 null（父类不可解析时同样返回 null，由调用方保守处理）。 */
    public String resolveField(String owner, String name) {
        String current = owner;
        Set<String> visited = new HashSet<>();
        while (current != null && visited.add(current)) {
            ClassInfo cls = classInfo(current);
            if (cls == null) {
                return null; // 类不可解析：无法证明存在，保守由调用方处理
            }
            if (cls.field(name) != null) {
                return current;
            }
            current = cls.superName();
        }
        return null;
    }

    /** 父类链是否全部可解析（供校准只在可证明时拒绝）。 */
    public boolean superclassChainResolvable(String owner) {
        String current = owner;
        Set<String> visited = new HashSet<>();
        while (current != null && visited.add(current)) {
            ClassInfo cls = classInfo(current);
            if (cls == null) {
                return false;
            }
            current = cls.superName();
        }
        return true;
    }

    /**
     * 接口实现类（传递，非接口类），超上限返回 null 表示放弃枚举。按 (接口, 上限) 缓存。
     */
    public List<String> implementers(String interfaceName, int cap) {
        IfaceKey key = new IfaceKey(interfaceName, cap);
        Optional<List<String>> cached = implementersCache.get(key);
        if (cached != null) {
            return cached.orElse(null);
        }
        List<String> result = new ArrayList<>();
        Deque<String> queue = new ArrayDeque<>();
        Set<String> visited = new HashSet<>();
        queue.add(interfaceName);
        while (!queue.isEmpty()) {
            String cur = queue.poll();
            if (!visited.add(cur)) {
                continue;
            }
            // 快照遍历：classInfo 懒加载可能向 directSubtypes 追加（单线程 CME）
            for (String sub : new ArrayList<>(loadedSubtypes(cur))) {
                ClassInfo ci = classInfo(sub);
                if (ci == null) {
                    continue;
                }
                if (ci.isInterface()) {
                    queue.add(sub);
                } else {
                    result.add(sub);
                    if (result.size() > cap) {
                        implementersCache.put(key, Optional.empty());
                        return null;
                    }
                }
            }
        }
        List<String> frozen = List.copyOf(result);
        implementersCache.put(key, Optional.of(frozen));
        return frozen;
    }
}
