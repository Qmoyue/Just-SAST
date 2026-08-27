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
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
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

    private static final int MAX_COMPOSED = 400;
    private static final int MAX_HOPS = 16;
    private static final int MAX_SOURCE_HOSTS = 1000;

    /** 哈希触发容器：其反序列化机制以元素/键回调 hashCode/equals/compareTo。 */
    private static final Set<String> TRIGGER_CONTAINERS = Set.of(
            "java/util/Map", "java/util/Collection", "java/util/Set", "java/util/List",
            "java/util/HashMap", "java/util/HashSet", "java/util/Hashtable",
            "java/util/LinkedHashMap", "java/util/LinkedHashSet",
            "java/util/TreeMap", "java/util/TreeSet", "java/util/concurrent/PriorityQueue");

    /** 桥接类型。 */
    enum Bridge { INVOKE, TRIGGER, TEMPLATE, DESER }

    private Blackboard bb;
    /** 反序列化源宿主：hostKey(methodOwner.#methodName) → 源框架入口 (owner, method)。 */
    private Map<String, String[]> deserHosts;

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
        // 源宿主桥使用含本轮 INVOKE/DESER 合成链的新快照——完整链（多段桥接产物）也能再挂源宿主；
        // 图不可用（最小夹具）时宿主扫描无从进行，跳过该桥
        int sourceComposed = this.bb != null && this.bb.graph() != null
                ? composeSourceHosted(List.copyOf(this.bb.chains())) : 0;
        JustLogger.info("链组装：语义桥接产链 {} 条（源宿主容器触发 {} 条）", composed, sourceComposed);
    }

    /**
     * 源宿主容器触发桥：方法 M 体内含反序列化源调用（OIS 读取或 bridge:deserialize 框架源），
     * 且操作哈希触发容器（Map/Set 的 add/put/iterator）——容器反序列化机制以攻击者数据回调
     * 元素 hashCode/equals/compareTo（如 HashSet.readObject → HashMap.hash → 元素 hashCode）。
     * 此类方法直接作为触发容器桥的前段宿主，与 trigger-entry 后段链组装成完整攻击路径。
     */
    private int composeSourceHosted(List<Chain> chains) {
        if (deserHosts == null) {
            scanHosts();
        }
        int composed = 0;
        // 公开 gadget 片段链（已知触发语义）优先消耗预算，其余按黑板顺序
        List<Chain> ordered = new ArrayList<>();
        List<Chain> rest = new ArrayList<>();
        for (Chain back : chains) {
            boolean fragment = back.hops().stream()
                    .anyMatch(h -> "fragment".equals(h.reason()));
            (fragment ? ordered : rest).add(back);
        }
        ordered.addAll(rest);
        for (Chain back : ordered) {
            if (composed >= MAX_COMPOSED || !isTriggerEntry(back.entryKind())) {
                continue;
            }
            for (Map.Entry<String, String[]> host : deserHosts.entrySet()) {
                if (composed >= MAX_COMPOSED) {
                    break;
                }
                String hostKey = host.getKey();
                int sep = hostKey.lastIndexOf(".#");
                String hostClass = hostKey.substring(0, sep);
                String hostMethod = hostKey.substring(sep + 2);
                // 防环：后段入口类不得就是宿主自身（宿主内自触发无源语义）
                if (back.entryClass().equals(hostClass)) {
                    continue;
                }
                String[] frame = host.getValue();
                List<ChainHop> hops = new ArrayList<>();
                for (int i = 0; i < back.hops().size() - 1; i++) {
                    hops.add(back.hops().get(i));
                }
                // 机制桥接跳：反序列化框架的容器/bean 机制以攻击者数据回调后段入口
                // （OIS: HashSet.readObject→HashMap.hash；Kryo: MapSerializer.read→put；
                //   fastjson: JavaBeanDeserializer→setter——框架管线语义，非调用图相邻）
                hops.add(new ChainHop(frame[0], frame[1],
                        back.entryClass(), back.entryMethod(),
                        HopKind.VIRTUAL_DISPATCH, null, "bridge-trigger-src", "", null));
                hops.add(back.hops().get(back.hops().size() - 1));
                if (hops.size() > MAX_HOPS) {
                    continue;
                }
                Chain merged = new Chain(back.ruleId(), back.category(), back.severity(),
                        hostClass, hostMethod, "source",
                        back.sinkClass(), back.sinkMethod(), hops, back.unresolvedHops());
                if (bb.addChain(merged)) {
                    bb.chainNote(merged.key(), "pattern:src-container-trigger");
                    composed++;
                }
            }
        }
        return composed;
    }

    /** 全图单遍扫描：反序列化源宿主（体内含 OIS 读取或 bridge:deserialize 源调用，
     *  排除 JDK 运行时包——其 readObject 体是容器触发机制本身，以机制桥接跳建模）。 */
    private void scanHosts() {
        Map<String, String[]> hosts = new HashMap<>();
        for (var call : bb.graph().nodesOfType(io.just.sast.cpg.graph.NodeType.CALL)) {
            String callOwner = call.strProp("owner");
            String callName = call.strProp("name");
            String hostOwner = call.strProp("methodOwner");
            String hostName = call.strProp("methodName");
            if (hostOwner == null || hostName == null || isJdkInternal(hostOwner)) {
                continue;
            }
            String frameOwner = null;
            String frameMethod = null;
            if ("java/io/ObjectInputStream".equals(callOwner)
                    && ("readObject".equals(callName) || "readUnshared".equals(callName))) {
                frameOwner = callOwner;
                frameMethod = callName;
            } else if (callName != null) {
                var rule = bb.ruleEngine().matchingSource(callOwner, callName, call.strProp("desc"))
                        .filter(r -> "deserialize".equals(r.bridge())).orElse(null);
                if (rule != null) {
                    frameOwner = callOwner;
                    frameMethod = callName;
                }
            }
            if (frameOwner == null || hosts.size() >= MAX_SOURCE_HOSTS) {
                continue;
            }
            // 框架自身管线内的同名调用（Kryo 序列化器内部再调 readObject 等）是机制 plumbing，
            // 不是攻击面宿主——排除与源框架同包的宿主
            int slash = frameOwner.lastIndexOf('/');
            String framePkg = slash > 0 ? frameOwner.substring(0, slash + 1) : frameOwner;
            if (!hostOwner.startsWith(framePkg)) {
                hosts.putIfAbsent(hostOwner + ".#" + hostName,
                        new String[] {frameOwner, frameMethod});
            }
        }
        deserHosts = hosts;
    }

    /** JDK 运行时包前缀（这些包里的反序列化源宿主是机制本身，不是攻击面宿主）。 */
    private static boolean isJdkInternal(String owner) {
        return owner.startsWith("java/") || owner.startsWith("javax/")
                || owner.startsWith("sun/") || owner.startsWith("com/sun/")
                || owner.startsWith("jdk/") || owner.startsWith("org/w3c/")
                || owner.startsWith("org/xml/") || owner.startsWith("org/omg/");
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

        // 2. TRIGGER 桥：前段路径含触发容器，且后段入口类可放入容器的 key/元素槽
        // （有序容器 TreeMap/PriorityQueue 的槽位要求 Comparable——不可比较的入口类放不进去，
        //   桥不成立；HashMap/HashSet/Hashtable 的 key 槽为 Object 不限）
        String container = triggerContainerOnPath(front);
        if (container != null && isTriggerEntry(backKind)
                && keySlotAccepts(container, back.entryClass())) {
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

    /** 前段链路径经过的触发容器（HashMap/HashSet/Hashtable/TreeMap/TreeSet/PriorityQueue），无则 null。 */
    private static String triggerContainerOnPath(Chain chain) {
        for (ChainHop hop : chain.hops()) {
            String owner = hop.toOwner();
            if (owner.startsWith("java/util/HashMap") || owner.startsWith("java/util/HashSet")
                    || owner.startsWith("java/util/Hashtable") || owner.startsWith("java/util/TreeMap")
                    || owner.startsWith("java/util/TreeSet")
                    || owner.startsWith("java/util/concurrent/PriorityQueue")) {
                return owner;
            }
        }
        return null;
    }

    /** 后段入口类能否放入容器的 key/元素槽：有序容器要求 Comparable。 */
    private boolean keySlotAccepts(String container, String entryClass) {
        if (container.startsWith("java/util/TreeMap") || container.startsWith("java/util/TreeSet")
                || container.startsWith("java/util/concurrent/PriorityQueue")) {
            return bb.hierarchy().isSubtypeOf(entryClass, "java/lang/Comparable");
        }
        return true;
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
