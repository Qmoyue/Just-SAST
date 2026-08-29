package io.just.sast.knowledge.objectgraph;

import io.just.sast.blackboard.Blackboard;
import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.Event;
import io.just.sast.blackboard.EventType;
import io.just.sast.blackboard.HopKind;
import io.just.sast.blackboard.KnowledgeSource;
import io.just.sast.blackboard.Phase;
import io.just.sast.cpg.graph.Node;
import io.just.sast.cpg.graph.NodeType;
import io.just.sast.model.ClassInfo;
import io.just.sast.model.FieldInfo;
import io.just.sast.util.JustLogger;

import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 对象图入口扩散（COMPOSITION 阶段）：反序列化机制按对象图递归触发字段类型的反序列化回调。
 * 类 E（含回调入口方法）的非 transient 字段声明类型 T（含 [L..; 数组元素类型）、T 的子类型 F 可序列化
 * → 攻击者可在该字段放置 F 实例 → F 的回调入口在 E 反序列化期间被机制调用。
 * 将 F 入口的既有链重根到 E：E 的入口 → 字段跳 → F 的链，产出新的 entry→sink 覆盖
 * （默认反序列化填充字段，不经显式调用边，前向/反向引擎均不可见——本源补足）。
 * 机制触发的入口类别：readObject/readObjectNoData/readExternal/readResolve
 * （readResolve 在对象图读完后由机制调用，语义同族）；
 * validateObject 仅当该类 readObject 内有 registerValidation 调用时纳入（机制语义核验）；
 * proxyInvoke 为使用期触发（非机制期），不参与重根。
 */
public final class ObjectGraphEntryKnowledgeSource implements KnowledgeSource {

    private static final int MAX_REROOTED = 300;
    private static final int MAX_PER_CHAIN = 20;
    private static final int MAX_HOPS = 16;
    /** 机制期入口类别（E 自身须有其一，重根后的新入口才真实存在）。 */
    private static final Set<String> MECHANISM_ENTRIES = Set.of(
            "readObject", "readObjectNoData", "readExternal", "readResolve", "validateObject");

    /** 万能容器类型：对任意可序列化子类型平凡成立，重根无信号纯噪音，排除。 */
    private static final Set<String> UNIVERSAL_TYPES = Set.of(
            "java/lang/Object", "java/io/Serializable", "java/lang/Cloneable",
            "java/lang/Comparable", "java/io/Externalizable");

    private Blackboard bb;

    @Override
    public String id() {
        return "object-graph";
    }

    @Override
    public Set<EventType> interests() {
        return Set.of(EventType.SCAN_ANALYZED);
    }

    @Override
    public Phase phase() {
        return Phase.COMPOSITION;
    }

    @Override
    public int priority() {
        return 100;
    }

    @Override
    public void init(Blackboard blackboard) {
        this.bb = blackboard;
    }

    @Override
    public void onEvent(Blackboard bb, Event event) {
        if (event.type() != EventType.SCAN_ANALYZED) {
            return;
        }
        JustLogger.info("对象图入口开始：当前链 {}", bb.chains().size());
        // 字段容器索引：声明类型 → (所在类, 字段名)，仅 Serializable 类的非 transient/static 引用字段
        Map<String, List<String[]>> containersByType = new java.util.TreeMap<>();
        Set<String> owners = new java.util.TreeSet<>();
        for (Node m : bb.graph().nodesOfType(NodeType.METHOD)) {
            owners.add(m.strProp("owner"));
        }
        for (String owner : owners) {
            if (!bb.hierarchy().isSerializable(owner)) {
                continue;
            }
            ClassInfo ci = bb.hierarchy().classInfo(owner);
            if (ci == null) {
                continue;
            }
            for (FieldInfo f : ci.fields()) {
                if (Modifier.isTransient(f.access()) || Modifier.isStatic(f.access())) {
                    continue;
                }
                String type = referenceTypeOf(f.descriptor());
                if (type == null || UNIVERSAL_TYPES.contains(type)) {
                    continue; // 非引用类型 / 万能容器类型：重根无信号
                }
                containersByType.computeIfAbsent(type, k -> new ArrayList<>(1))
                        .add(new String[] {owner, f.name()});
            }
        }
        for (List<String[]> containers : containersByType.values()) {
            containers.sort(java.util.Comparator
                    .comparing((String[] container) -> container[0])
                    .thenComparing(container -> container[1]));
        }
        JustLogger.info("对象图字段索引：容器类型 {}，容器字段 {}",
                containersByType.size(), containersByType.values().stream()
                        .mapToInt(List::size).sum());
        // validateObject 注册核验：类 readObject 体内调用 OIS.registerValidation 才会被机制回调
        Set<String> validationRegistered = new HashSet<>();
        for (Node call : bb.graph().nodesOfType(NodeType.CALL)) {
            if ("java/io/ObjectInputStream".equals(call.strProp("owner"))
                    && "registerValidation".equals(call.strProp("name"))) {
                validationRegistered.add(call.strProp("methodOwner"));
            }
        }
        int rerooted = 0;
        List<Chain> chains = new ArrayList<>(bb.chains());
        chains.sort(java.util.Comparator.comparing(Chain::key));
        for (Chain chain : chains) {
            if (rerooted >= MAX_REROOTED) {
                bb.markIncomplete("OBJECT_GRAPH_REROOT_CAP:" + MAX_REROOTED);
                break;
            }
            if (!mechanismInvoked(chain.entryKind(), chain.entryClass(), validationRegistered)) {
                continue;
            }
            int per = 0;
            // 字段声明类型取 F 的祖先闭包（父类链 + 传递接口）：任一祖先类型的容器字段都能容纳 F
            for (String ancestor : ancestors(chain.entryClass())) {
                for (String[] container : containersByType.getOrDefault(ancestor, List.of())) {
                    if (per >= MAX_PER_CHAIN || rerooted >= MAX_REROOTED) {
                        if (rerooted >= MAX_REROOTED) {
                            bb.markIncomplete("OBJECT_GRAPH_REROOT_CAP:" + MAX_REROOTED);
                        }
                        break;
                    }
                    Chain merged = reroot(chain, container[0], container[1]);
                    if (merged != null && bb.addChain(merged)) {
                        rerooted++;
                        per++;
                    }
                }
            }
        }
        JustLogger.info("对象图入口：重根产链 {} 条", rerooted);
    }

    /** 入口类别是否由反序列化机制直接调用（validateObject 需注册核验）。 */
    private static boolean mechanismInvoked(String entryKind, String entryClass, Set<String> validationRegistered) {
        return switch (entryKind) {
            case "readObject", "readObjectNoData", "readExternal", "readResolve" -> true;
            case "validateObject" -> validationRegistered.contains(entryClass);
            default -> false;
        };
    }

    /** 字段描述符 → 引用类型名：L..; 直接取，[L..; 取元素类型；其余（基本类型/基本数组）null。 */
    private static String referenceTypeOf(String desc) {
        if (desc.startsWith("L") && desc.endsWith(";")) {
            return desc.substring(1, desc.length() - 1);
        }
        if (desc.startsWith("[L") && desc.endsWith(";")) {
            return desc.substring(2, desc.length() - 1);
        }
        return null;
    }

    /** F 入口链重根到 E：E 的入口跳 + 字段跳 + F 的链（去 F 入口自跳），sink-first 顺序。 */
    private Chain reroot(Chain chain, String owner, String field) {
        if (owner.equals(chain.entryClass()) || onPath(chain, owner)) {
            return null; // 防环
        }
        // E 须有自己的回调入口方法（保证入口真实存在且可评分）
        String[] entry = callbackEntryOf(owner);
        if (entry == null) {
            return null;
        }
        List<ChainHop> hops = new ArrayList<>(chain.hops().size() + 2);
        for (int i = 0; i < chain.hops().size() - 1; i++) {
            hops.add(chain.hops().get(i)); // F 的跳（末位 ENTRY 自跳去掉）
        }
        hops.add(new ChainHop(entry[0], entry[1], chain.entryClass(), chain.entryMethod(),
                HopKind.FIELD_FLOW, field, "object-graph", "", null));
        hops.add(new ChainHop(entry[0], entry[1], entry[0], entry[1],
                HopKind.ENTRY, null, entry[2], entry[3], null));
        if (hops.size() > MAX_HOPS) {
            return null;
        }
        return new Chain(chain.ruleId(), chain.category(), chain.severity(),
                entry[0], entry[1], entry[2],
                chain.sinkClass(), chain.sinkMethod(), hops, chain.unresolvedHops(), chain.sinkDescriptor());
    }

    /** 类的第一个机制回调入口（owner, method, entryKind）；无则 null。 */
    private String[] callbackEntryOf(String owner) {
        ClassInfo ci = bb.hierarchy().classInfo(owner);
        if (ci == null) {
            return null;
        }
        for (var method : ci.methods()) {
            var rule = bb.ruleEngine().matchingEntry(owner, method.name(), method.descriptor());
            if (rule.isPresent() && rule.get().entryKind() != null
                    && MECHANISM_ENTRIES.contains(rule.get().entryKind())) {
                return new String[] {owner, method.name(), rule.get().entryKind(), method.descriptor()};
            }
        }
        return null;
    }

    private static boolean onPath(Chain chain, String owner) {
        for (ChainHop hop : chain.hops()) {
            if (hop.fromOwner().equals(owner) || hop.toOwner().equals(owner)) {
                return true;
            }
        }
        return false;
    }

    /** 类的祖先闭包：父类链 + 传递接口（含自身，字段声明类型可为自身）。 */
    private List<String> ancestors(String cls) {
        List<String> result = new ArrayList<>();
        Set<String> visited = new HashSet<>();
        List<String> queue = new ArrayList<>();
        queue.add(cls);
        while (!queue.isEmpty()) {
            String cur = queue.remove(queue.size() - 1);
            if (!visited.add(cur)) {
                continue;
            }
            result.add(cur);
            ClassInfo ci = bb.hierarchy().classInfo(cur);
            if (ci == null) {
                continue;
            }
            if (ci.superName() != null) {
                queue.add(ci.superName());
            }
            queue.addAll(ci.interfaces());
        }
        result.sort(String::compareTo);
        return result;
    }
}
