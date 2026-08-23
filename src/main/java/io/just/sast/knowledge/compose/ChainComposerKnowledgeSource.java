package io.just.sast.knowledge.compose;

import io.just.sast.blackboard.Blackboard;
import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.Event;
import io.just.sast.blackboard.EventType;
import io.just.sast.blackboard.HopKind;
import io.just.sast.blackboard.KnowledgeSource;
import io.just.sast.blackboard.Phase;
import io.just.sast.util.JustLogger;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * 语义链组装（COMPOSITION 阶段）。
 * 将不同引擎产出的完整链通过**语义桥接**组装成多级完整攻击路径。
 *
 * 四种桥接（均为语义级，非调用图相邻）：
 * 1. INVOKE 桥：前段链 sink = Method.invoke → 可调用后段链 entry 的任意公共方法
 * 2. TRIGGER 桥：前段链路径含 HashMap/HashSet/Hashtable → 反序列化时调 key.hashCode/toString → 触发后段
 * 3. TEMPLATE 桥：前段链路径含 TemplatesImpl → 后段 entry 触发 getOutputProperties/newTransformer
 * 4. DESER 桥：前段 sink 为二次反序列化（DESERIALIZE 类别，SignedObject.getObject /
 *    SerializationUtils.deserialize 等）→ 前段产物字节流再被反序列化，触发后段机制入口
 *
 * 不在调用图上找相邻方法（结构级），而是验证前段 sink 能否**语义上**触发后段 entry
 * （Method.invoke 可调任意公共方法、HashMap 反序列化调 hashCode、TemplatesImpl 的 getter
 * 加载字节码、SignedObject 模式的嵌套反序列化）。
 */
public final class ChainComposerKnowledgeSource implements KnowledgeSource {

    private static final int MAX_COMPOSED = 100;
    private static final int MAX_HOPS = 16;

    /** 桥接类型。 */
    enum Bridge { INVOKE, TRIGGER, TEMPLATE, DESER }

    private Blackboard bb;

    @Override
    public String id() {
        return "chain-composer";
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
        return 200;
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
        List<Chain> chains = List.copyOf(bb.chains());
        if (chains.size() < 2) {
            return;
        }
        int composed = 0;
        for (Chain front : chains) {
            if (composed >= MAX_COMPOSED) {
                break;
            }
            for (Chain back : chains) {
                if (composed >= MAX_COMPOSED || front == back) {
                    continue;
                }
                Bridge bridge = semanticBridge(front, back);
                if (bridge == null) {
                    continue;
                }
                // 防环：back 的 entry 不在 front 的路径上
                if (onPath(front, back.entryClass())) {
                    continue;
                }
                Chain merged = compose(front, back, bridge);
                if (merged != null && bb.addChain(merged)) {
                    composed++;
                }
            }
        }
        JustLogger.info("链组装：语义桥接产链 {} 条", composed);
    }

    /** 判断前段链的 sink 能否语义上触发后段链的 entry。 */
    private Bridge semanticBridge(Chain front, Chain back) {
        String frontSink = front.sinkClass() + "." + front.sinkMethod();
        String backEntry = back.entryClass() + "." + back.entryMethod();
        String backKind = back.entryKind();

        // 1. INVOKE 桥：前段 sink 是 Method.invoke → 可调任意公共方法
        if ("java/lang/reflect/Method.invoke".equals(frontSink)
                && isPublicEntry(backKind)) {
            return Bridge.INVOKE;
        }

        // 2. TRIGGER 桥：前段路径含 HashMap/HashSet/Hashtable/TreeMap → 调 key.hashCode/equals/compareTo/toString
        if (containsTriggerContainer(front) && isTriggerEntry(backKind)) {
            return Bridge.TRIGGER;
        }

        // 3. TEMPLATE 桥：前段路径含 TemplatesImpl → 后段 entry 触发其 getter
        if (onPath(front, "com/sun/org/apache/xalan/internal/xsltc/trax/TemplatesImpl")
                && isTemplateTrigger(backEntry)) {
            return Bridge.TEMPLATE;
        }

        // 4. DESER 桥：前段 sink 是二次反序列化 → 其产物字节流再被反序列化，触发后段机制入口
        if ("DESERIALIZE".equals(front.category()) && isPublicEntry(backKind)) {
            return Bridge.DESER;
        }

        return null;
    }

    private static boolean isPublicEntry(String entryKind) {
        return Set.of("readObject", "readResolve", "readObjectNoData", "readExternal",
                "hashCode", "equals", "compareTo", "compare", "toString",
                "proxyInvoke", "validateObject").contains(entryKind);
    }

    private static boolean isTriggerEntry(String entryKind) {
        return Set.of("hashCode", "equals", "compareTo", "compare", "toString").contains(entryKind);
    }

    private static boolean isTemplateTrigger(String entryMethod) {
        return entryMethod.contains("getOutputProperties") || entryMethod.contains("newTransformer");
    }

    /** 前段链路径是否经过触发容器（HashMap/HashSet/Hashtable/TreeMap/PriorityQueue）。 */
    private static boolean containsTriggerContainer(Chain chain) {
        for (ChainHop hop : chain.hops()) {
            String owner = hop.toOwner();
            if (owner.startsWith("java/util/HashMap") || owner.startsWith("java/util/HashSet")
                    || owner.startsWith("java/util/Hashtable") || owner.startsWith("java/util/TreeMap")
                    || owner.startsWith("java/util/concurrent/PriorityQueue")) {
                return true;
            }
        }
        return false;
    }

    private static boolean onPath(Chain chain, String className) {
        if (chain.entryClass().startsWith(className)) {
            return true;
        }
        for (ChainHop hop : chain.hops()) {
            if (hop.fromOwner().startsWith(className) || hop.toOwner().startsWith(className)) {
                return true;
            }
        }
        return false;
    }

    /** 组装：front 的跳（截至桥接点）+ 桥接跳 + back 的跳（去 back 的入口自跳）。 */
    private Chain compose(Chain front, Chain back, Bridge bridge) {
        List<ChainHop> hops = new ArrayList<>();
        // back 的跳（sink-first，去末位 ENTRY 自跳）
        for (int i = 0; i < back.hops().size() - 1; i++) {
            hops.add(back.hops().get(i));
        }
        // 桥接跳：front.sink → back.entry
        hops.add(new ChainHop(front.sinkClass(), front.sinkMethod(),
                back.entryClass(), back.entryMethod(),
                HopKind.DIRECT_CALL, null, "bridge-" + bridge.name().toLowerCase(), "", null));
        // front 的跳（含 ENTRY 自跳）
        hops.addAll(front.hops());
        if (hops.size() > MAX_HOPS) {
            return null;
        }
        return new Chain(back.ruleId(), back.category(), back.severity(),
                front.entryClass(), front.entryMethod(), front.entryKind(),
                back.sinkClass(), back.sinkMethod(), hops,
                front.unresolvedHops() + back.unresolvedHops());
    }
}
