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
    /** 传递子类型闭包缓存（调用图与引擎侧展开共用同一来源，避免直接/传递口径分叉）。 */
    private final Map<String, List<String>> transitiveSubtypesCache = new java.util.concurrent.ConcurrentHashMap<>();
    private record SubtypeKey(String internalName, int cap) {}
    private final Map<SubtypeKey, SubtypeResult> boundedSubtypeCache =
            new java.util.concurrent.ConcurrentHashMap<>();
    /** 类的传递接口缓存；同一类的每个方法都会查询一次接口反向分发，必须跨方法复用。 */
    private final Map<String, List<String>> transitiveInterfacesCache =
            new java.util.concurrent.ConcurrentHashMap<>();
    /**
     * 单调层次版本：JDK 懒加载补充一个类型后，调用方缓存的分派候选必须重新验证。
     * 初始目标类集合是冻结的，因而只有成功懒加载时才递增。
     */
    private volatile long revision;

    public ClassHierarchy(Map<String, ClassInfo> initial, JdkClassSource jdk) {
        this.classes = new java.util.concurrent.ConcurrentHashMap<>();
        this.jdk = jdk;
        if (initial != null) {
            initial.forEach((name, info) -> {
                if (name != null && !name.isBlank() && info != null) {
                    this.classes.put(name, info);
                }
            });
        }
        // The input map is often a LinkedHashMap, but tests and extension points are free to
        // provide a HashMap.  Subtype indexing is semantically a set operation; making its
        // seed order explicit prevents HashMap iteration order from leaking into dispatch
        // candidates and, ultimately, finite path budgets.
        (initial == null ? List.<ClassInfo>of() : initial.values()).stream()
                .filter(java.util.Objects::nonNull)
                .sorted(java.util.Comparator.comparing(ClassInfo::internalName))
                .forEach(this::indexSubtypes);
    }

    private void indexSubtypes(ClassInfo c) {
        if (c == null || c.internalName() == null || c.internalName().isBlank()) {
            return;
        }
        if (c.superName() != null && !c.superName().isBlank()) {
            addDirectSubtype(c.superName(), c.internalName());
        }
        for (String itf : c.interfaces()) {
            if (itf != null && !itf.isBlank()) {
                addDirectSubtype(itf, c.internalName());
            }
        }
    }

    /**
     * Initial hierarchy construction is ordered and lazy JDK loading is serialized by the
     * ClassHierarchy monitor.  A synchronized ArrayList therefore gives readers a stable
     * snapshot without CopyOnWriteArrayList's full-array copy on every subtype insertion;
     * the latter created a large transient allocation cliff for generated polymorphism jars.
     */
    private void addDirectSubtype(String parent, String child) {
        if (parent == null || parent.isBlank() || child == null || child.isBlank()) {
            return;
        }
        List<String> children = directSubtypes.computeIfAbsent(parent,
                ignored -> new ArrayList<>());
        synchronized (children) {
            if (!children.contains(child)) {
                children.add(child);
            }
        }
    }

    /** 取类信息，未知类走 JDK 懒加载；确认缺失的类负缓存（来源集合不变，结果稳定）。懒加载段同步（并发下防重复探测/结构破坏）。 */
    public ClassInfo classInfo(String internalName) {
        if (internalName == null || internalName.isBlank()) {
            return null;
        }
        ClassInfo c = classes.get(internalName);
        if (c != null || jdk == null) {
            return c;
        }
        synchronized (this) {
            c = classes.get(internalName);
            if (c != null) {
                return c;
            }
            // 负缓存的检查和 JDK 加载必须在同一临界区内完成。否则第二个并发
            // 调用者会看到 add=false 并直接返回 null，而第一个调用者仍在加载。
            if (!unresolvable.add(internalName)) {
                return null;
            }
            try {
                c = jdk.load(internalName);
            } catch (RuntimeException | LinkageError unavailable) {
                // A provider may fail transiently while the runtime is being probed. Do not
                // poison the negative cache forever; callers still receive null for this
                // attempt and a later hierarchy revision can retry the load.
                unresolvable.remove(internalName);
                return null;
            }
            if (c != null) {
                classes.put(internalName, c);
                indexSubtypes(c);
                unresolvable.remove(internalName);
                // JDK 懒加载会改变整个可解析关系图：新类既可能是已知类型的子类，
                // 也可能补齐一个此前不可解析的父类/接口。仅按 key 字符串做局部失效
                // 会漏掉“已缓存的负 resolve/subtype 结果”（例如 Child -> MissingBase），
                // 进而把合法分派链永久当成不存在。扫描构建阶段只会加载有限的 JDK
                // 切片；这里选择一次性清除所有派生缓存，以完整性优先，避免陈旧快照。
                subtypeCache.clear();
                resolveCache.clear();
                implementersCache.clear();
                transitiveSubtypesCache.clear();
                boundedSubtypeCache.clear();
                transitiveInterfacesCache.clear();
                revision++;
            }
        }
        return c;
    }

    /** 当前类层次快照版本；用于跨调用点复用分派候选而不读取陈旧的懒加载结果。 */
    public long revision() {
        return revision;
    }

    public int classCount() {
        return classes.size();
    }

    /** 已加载类中 name 的直接子类型。 */
    public List<String> loadedSubtypes(String internalName) {
        List<String> list = directSubtypes.get(internalName);
        if (list == null || list.isEmpty()) {
            return List.of();
        }
        List<String> stable;
        synchronized (list) {
            if (list.size() == 1) {
                return List.copyOf(list);
            }
            stable = new ArrayList<>(list);
        }
        stable.sort(String::compareTo);
        return List.copyOf(stable);
    }

    /**
     * 传递子类型闭包（含孙类及更深，BFS 穿过子类链；结果冻结 + 记忆化）。
     * 调用图与引擎侧的分发展开共用本方法——深继承链中的覆写方法两处一致。
     */
    public List<String> transitiveSubtypes(String internalName) {
        if (internalName == null || internalName.isBlank()) {
            return List.of();
        }
        List<String> cached = transitiveSubtypesCache.get(internalName);
        if (cached != null) {
            return cached;
        }
        java.util.Set<String> result = new java.util.LinkedHashSet<>();
        java.util.Set<String> visited = new HashSet<>();
        Deque<String> work = new ArrayDeque<>();
        work.add(internalName);
        while (!work.isEmpty()) {
            String cur = work.poll();
            if (!visited.add(cur)) {
                continue;
            }
            for (String sub : loadedSubtypes(cur)) {
                result.add(sub);
                work.add(sub);
            }
        }
        List<String> frozen = new ArrayList<>(result);
        frozen.sort(String::compareTo);
        frozen = List.copyOf(frozen);
        transitiveSubtypesCache.put(internalName, frozen);
        return frozen;
    }

    /**
     * Bounded lazy subtype traversal.  Unlike the legacy unbounded compatibility method this
     * never materializes the complete closure merely to discover that a caller's cap was
     * exceeded.  {@code complete=false} is an explicit analysis boundary, not an empty result.
     */
    public SubtypeResult transitiveSubtypes(String internalName, int cap) {
        if (internalName == null || internalName.isBlank()) {
            return new SubtypeResult(List.of(), true);
        }
        int effectiveCap = Math.max(0, cap);
        SubtypeKey key = new SubtypeKey(internalName, effectiveCap);
        SubtypeResult cached = boundedSubtypeCache.get(key);
        if (cached != null) {
            return cached;
        }
        java.util.Set<String> result = new java.util.LinkedHashSet<>();
        java.util.Set<String> visited = new HashSet<>();
        Deque<String> work = new ArrayDeque<>();
        work.add(internalName);
        boolean truncated = false;
        while (!work.isEmpty() && !truncated) {
            String cur = work.poll();
            if (!visited.add(cur)) {
                continue;
            }
            for (String sub : loadedSubtypes(cur)) {
                if (result.size() >= effectiveCap) {
                    truncated = true;
                    break;
                }
                if (result.add(sub)) {
                    work.add(sub);
                }
            }
        }
        List<String> values = new ArrayList<>(result);
        values.sort(String::compareTo);
        SubtypeResult output = new SubtypeResult(List.copyOf(values), !truncated);
        boundedSubtypeCache.put(key, output);
        return output;
    }

    /** Result of a capped subtype traversal. */
    public record SubtypeResult(List<String> values, boolean complete) {
        public SubtypeResult {
            values = values == null ? List.of() : List.copyOf(values);
        }
    }

    /** name 的全部祖先类型（父类链 + 传递接口，不含自身）。 */
    private java.util.Set<String> ancestorsOf(String internalName) {
        java.util.Set<String> result = new HashSet<>();
        if (internalName == null || internalName.isBlank()) {
            return result;
        }
        Deque<String> queue = new ArrayDeque<>();
        ClassInfo ci = internalName.equals("") ? null : classInfo(internalName);
        if (ci != null) {
            if (ci.superName() != null) {
                queue.add(ci.superName());
            }
            queue.addAll(ci.interfaces());
        }
        while (!queue.isEmpty()) {
            String cur = queue.poll();
            if (!result.add(cur)) {
                continue;
            }
            ClassInfo c = classInfo(cur);
            if (c == null) {
                continue;
            }
            if (c.superName() != null) {
                queue.add(c.superName());
            }
            queue.addAll(c.interfaces());
        }
        return result;
    }

    /** 类的传递接口（含父类继承），供接口反向分发使用。 */
    public List<String> transitiveInterfaces(String internalName) {
        if (internalName == null || internalName.isBlank()) {
            return List.of();
        }
        List<String> cached = transitiveInterfacesCache.get(internalName);
        if (cached != null) {
            return cached;
        }
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
                if (itf != null && !itf.isBlank() && !visited.contains(itf)) {
                    result.add(itf);
                    queue.add(itf);
                }
            }
            if (ci.superName() != null) {
                queue.add(ci.superName());
            }
        }
        result.sort(String::compareTo);
        List<String> frozen = List.copyOf(result);
        transitiveInterfacesCache.put(internalName, frozen);
        return frozen;
    }

    /** a 是否为 b 的子类型（沿父类 + 传递接口）。 */
    public boolean isSubtypeOf(String a, String b) {
        if (a == null || b == null || a.isBlank() || b.isBlank()) {
            return false;
        }
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
        return internalName != null && isSubtypeOf(internalName, "java/io/Serializable");
    }

    /**
     * 解析方法声明位置。按 JVM 方法解析顺序（JLS/JVMS 5.4.5）：先沿父类链逐级查找，
     * 再按接口 BFS（含各接口的父类链）查找第一个声明 (name, desc) 的类——父类链整体优先于
     * 接口 default method，与真实 JVM 分派一致。未找到返回 null。
     */
    public String resolveMethod(String owner, String name, String desc) {
        if (owner == null || owner.isBlank() || name == null || name.isBlank()
                || desc == null || desc.isBlank()) {
            return null;
        }
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
        if (declared == null || candidate == null || name == null || desc == null) {
            return false;
        }
        // candidate 往往继承 declared 的方法，并不在 candidate.methods() 中直接出现。
        // 先按 JVM 方法解析找到真正的声明类，再读取其 access；否则 final native
        // Object.getClass 等方法会因“候选类未直接声明”被错误地当成可覆写目标。
        String resolvedOwner = resolveMethod(candidate, name, desc);
        int access = resolvedOwner == null ? methodAccess(candidate, name, desc)
                : methodAccess(resolvedOwner, name, desc);
        if (access < 0) {
            return true; // 不可解析：保守视为可
        }
        if (Modifier.isPrivate(access) || Modifier.isStatic(access) || Modifier.isFinal(access)) {
            return false;
        }
        if (Modifier.isPublic(access) || Modifier.isProtected(access)) {
            return true;
        }
        return packageOf(resolvedOwner == null ? candidate : resolvedOwner).equals(packageOf(declared));
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
        if (interfaceName == null || interfaceName.isBlank()) {
            return List.of();
        }
        int effectiveCap = Math.max(0, cap);
        IfaceKey key = new IfaceKey(interfaceName, effectiveCap);
        Optional<List<String>> cached = implementersCache.get(key);
        if (cached != null) {
            return cached.orElse(null);
        }
        Set<String> result = new java.util.LinkedHashSet<>();
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
                    // 具体类也可能还有覆写它的子类；接口实现闭包必须继续穿过
                    // 实现类，而不能只枚举“直接实现者”。
                    queue.add(sub);
                    if (result.size() > effectiveCap) {
                        implementersCache.put(key, Optional.empty());
                        return null;
                    }
                }
            }
        }
        List<String> ordered = new ArrayList<>(result);
        ordered.sort(String::compareTo);
        List<String> frozen = List.copyOf(ordered);
        implementersCache.put(key, Optional.of(frozen));
        return frozen;
    }
}
