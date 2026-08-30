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

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Enumeration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

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

    /**
     * A source host gets one deterministic candidate per round.  The old nested attempt
     * loop retried the same host/candidate product after every rejected or duplicate pair,
     * which made a large dependency graph spend minutes in an effectively quadratic scan.
     * The bound is deliberately tied to the existing composition budget, not exposed as a
     * target-specific tuning knob.
     */
    private static final int MAX_SOURCE_ROUNDS = MAX_COMPOSED;

    /** 哈希触发容器：其反序列化机制以元素/键回调 hashCode/equals/compareTo。 */
    private static final Set<String> TRIGGER_CONTAINERS = Set.of(
            "java/util/Map", "java/util/Collection", "java/util/Set", "java/util/List",
            "java/util/HashMap", "java/util/HashSet", "java/util/Hashtable",
            "java/util/LinkedHashMap", "java/util/LinkedHashSet",
            "java/util/TreeMap", "java/util/TreeSet", "java/util/concurrent/PriorityQueue");

    /** 桥接类型。 */
    enum Bridge { INVOKE, TRIGGER, TEMPLATE, DESER }

    private Blackboard bb;
    /** 反序列化源宿主：带描述符的宿主方法键 → 源框架入口。 */
    private Map<String, DeserHost> deserHosts;
    /** primary artifact provenance used only to make bounded source-host coverage fair. */
    private Set<String> primaryArtifactClasses;

    private record DeserHost(String owner, String method, String descriptor,
                             String frameOwner, String frameMethod, String frameDescriptor) {
    }

    private record FrontFeatures(boolean invoke, String triggerContainer,
                                 boolean template, boolean deserialize) {
    }

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
        List<Chain> chains = new ArrayList<>(bb.chains());
        chains.sort(java.util.Comparator.comparing(Chain::key));
        if (chains.size() < 2) {
            return;
        }
        List<Chain> publicEntries = chains.stream()
                .filter(ChainComposerKnowledgeSource::isPublicEntry)
                .toList();
        List<Chain> triggerEntries = chains.stream()
                .filter(chain -> isTriggerEntry(chain.entryKind()))
                .toList();
        List<Chain> templateEntries = chains.stream()
                .filter(chain -> isTemplateTrigger(chain.entryMethod()))
                .toList();
        JustLogger.info("链组装候选：链 {}，公共入口 {}，触发入口 {}，模板入口 {}",
                chains.size(), publicEntries.size(), triggerEntries.size(), templateEntries.size());

        int composed = 0;
        for (Chain front : chains) {
            if (composed >= MAX_COMPOSED) {
                bb.markIncomplete("COMPOSITION_CHAIN_CAP:" + MAX_COMPOSED);
                break;
            }
            FrontFeatures features = frontFeatures(front);
            if (!features.invoke() && features.triggerContainer() == null
                    && !features.template() && !features.deserialize()) {
                continue;
            }
            // Only inspect chains that can satisfy at least one bridge precondition.  This
            // preserves the old semanticBridge checks while avoiding the full chain×chain
            // product for ordinary, non-bridgeable candidates.
            List<Chain> candidates = candidateBacks(features, publicEntries,
                    triggerEntries, templateEntries);
            for (Chain back : candidates) {
                if (composed >= MAX_COMPOSED || front == back) {
                    continue;
                }
                Bridge bridge = semanticBridge(features, front, back);
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
        JustLogger.info("链组装语义阶段完成：产链 {}，当前链 {}", composed, bb.chains().size());
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
        ordered.sort(java.util.Comparator.comparing(Chain::key));
        rest.sort(java.util.Comparator.comparing(Chain::key));
        ordered.addAll(rest);
        List<Chain> triggerChains = ordered.stream()
                .filter(chain -> isTriggerEntry(chain.entryKind()))
                .sorted(java.util.Comparator
                        .comparingInt((Chain chain) -> triggerPriority(chain,
                                primaryArtifactClasses())).reversed()
                        .thenComparingInt(Chain::unresolvedHops)
                .thenComparingInt(chain -> chain.hops().size())
                .thenComparing(Chain::key))
                .toList();
        List<Map.Entry<String, DeserHost>> hosts = new ArrayList<>(deserHosts.entrySet());
        Set<String> primaryClasses = primaryArtifactClasses();
        // The source-host product is bounded by design. A lexical host order lets a large
        // dependency surface consume the whole first round before an application-defined
        // deserialization boundary gets a chance to attach a fragment. Put primary-artifact
        // hosts first, then retain stable key order inside each group. This is provenance
        // scheduling, not a class/package special case.
        hosts.sort(java.util.Comparator
                .comparing((Map.Entry<String, DeserHost> entry) ->
                        !primaryClasses.contains(entry.getValue().owner()))
                .thenComparing(Map.Entry::getKey));
        // The old back-chain-first loop let one popular library entry consume the whole
        // source-host budget.  Round-robin scheduling is still deterministic and bounded,
        // but gives each independently discovered deserialization host a chance to attach a
        // semantically valid trigger chain before filling the remaining budget.
        int rounds = 0;
        boolean roundLimitReached = false;
        for (int round = 0; round < MAX_SOURCE_ROUNDS
                && composed < MAX_COMPOSED && !triggerChains.isEmpty(); round++) {
            rounds++;
            boolean emittedInRound = false;
            for (int hostIndex = 0; hostIndex < hosts.size() && composed < MAX_COMPOSED; hostIndex++) {
                Map.Entry<String, DeserHost> host = hosts.get(hostIndex);
                // Advance the trigger frontier by round and host index.  Each host gets one
                // new deterministic pair per round; unlike the former inner retry loop this
                // cannot rescan the whole trigger list for every host in every round.
                int backIndex = Math.floorMod(round + hostIndex, triggerChains.size());
                Chain back = triggerChains.get(backIndex);
                DeserHost hostRef = host.getValue();
                String hostClass = hostRef.owner();
                String hostMethod = hostRef.method();
                // 防环：后段入口类不得就是宿主自身（宿主内自触发无源语义）
                if (back.entryClass().equals(hostClass)) {
                    continue;
                }
                List<ChainHop> hops = new ArrayList<>();
                for (int i = 0; i < back.hops().size() - 1; i++) {
                    hops.add(back.hops().get(i));
                }
                // 机制桥接跳：反序列化框架的容器/bean 机制以攻击者数据回调后段入口
                // （OIS: HashSet.readObject→HashMap.hash；Kryo: MapSerializer.read→put；
                //   fastjson: JavaBeanDeserializer→setter——框架管线语义，非调用图相邻）
                hops.add(new ChainHop(hostRef.frameOwner(), hostRef.frameMethod(),
                        back.entryClass(), back.entryMethod(),
                        HopKind.VIRTUAL_DISPATCH, null, "bridge-trigger-src",
                        entryDescriptor(back), null));
                hops.add(new ChainHop(hostClass, hostMethod, hostRef.frameOwner(), hostRef.frameMethod(),
                        HopKind.DIRECT_CALL, null, "bridge-source-deserialize",
                        hostRef.frameDescriptor(), null));
                hops.add(new ChainHop(hostClass, hostMethod, hostClass, hostMethod,
                        HopKind.ENTRY, null, "source",
                        hostRef.descriptor(), null));
                if (hops.size() > MAX_HOPS) {
                    continue;
                }
                Chain merged = new Chain(back.ruleId(), back.category(), back.severity(),
                        hostClass, hostMethod, "source",
                        back.sinkClass(), back.sinkMethod(), hops, back.unresolvedHops(), back.sinkDescriptor());
                if (bb.addChain(merged)) {
                    bb.chainNote(merged.key(), "pattern:src-container-trigger");
                    composed++;
                    emittedInRound = true;
                }
            }
            if (!emittedInRound) {
                break;
            }
        }
        roundLimitReached = rounds >= MAX_SOURCE_ROUNDS;
        if (composed < MAX_COMPOSED && !triggerChains.isEmpty()
                && !hosts.isEmpty() && roundLimitReached) {
            // If the bounded frontier was exhausted before the normal composition cap,
            // expose the bound in completeness metadata instead of silently dropping pairs.
            bb.markIncomplete("SOURCE_HOST_SCHEDULING_CAP:" + MAX_SOURCE_ROUNDS);
        }
        if (composed >= MAX_COMPOSED) {
            bb.markIncomplete("COMPOSITION_SOURCE_CHAIN_CAP:" + MAX_COMPOSED);
        }
        return composed;
    }

    /**
     * Rank trigger fragments for the bounded source-host product.  Application provenance
     * is a universal signal: when a finite composition budget is unavoidable, a real class
     * from the primary artifact must not be displaced by a dependency's earlier sort key.
     * Callback semantics then prefer the most broadly realizable container trigger, with
     * resolved/short paths as deterministic tie breakers.  No package, class, or benchmark
     * name is consulted.
     */
    private int triggerPriority(Chain chain, Set<String> primaryClasses) {
        int score = 0;
        if (primaryClasses.contains(chain.entryClass())) {
            score += 32;
        }
        score += switch (chain.entryKind()) {
            case "hashCode" -> 12;
            case "equals" -> 10;
            case "compareTo" -> 8;
            case "compare" -> 7;
            case "toString" -> 5;
            default -> 0;
        };
        if (chain.hops().stream().anyMatch(hop -> "fragment".equals(hop.reason()))) {
            score += 8;
        }
        if (chain.unresolvedHops() == 0) {
            score += 4;
        }
        // A bounded source-host frontier should spend its first probes on the most
        // security-relevant continuation, not on whichever library happens to sort first.
        // This is expressed as capability-family risk (the same semantic categories used by
        // rules/reports), never as a package, benchmark, or gadget-name preference.
        score += triggerRiskScore(chain);
        return score;
    }

    private static int triggerRiskScore(Chain chain) {
        String sinkClass = chain.sinkClass() == null ? "" : chain.sinkClass();
        String category = chain.category() == null ? "" : chain.category();
        int score = switch (category) {
            case "JNDI", "REFLECTIVE_INVOKE" -> 12;
            case "CODE_EXEC" -> 8;
            case "DESERIALIZE" -> 6;
            default -> 0;
        };
        if (sinkClass.startsWith("javax/naming/") || sinkClass.contains("/jndi/")) {
            score += 8;
        } else if (sinkClass.startsWith("java/lang/Runtime")
                || sinkClass.startsWith("java/lang/ProcessBuilder")) {
            score += 8;
        } else if (sinkClass.startsWith("java/lang/reflect/")
                || sinkClass.startsWith("com/sun/org/apache/xalan")
                || sinkClass.startsWith("javax/xml/transform")) {
            score += 6;
        } else if (sinkClass.startsWith("java/net/")) {
            score += 3;
        }
        score += switch (chain.severity() == null ? "" : chain.severity()) {
            case "CRITICAL" -> 4;
            case "HIGH" -> 3;
            case "MEDIUM" -> 1;
            default -> 0;
        };
        return score;
    }

    /** Read only primary-artifact class names; nested dependency jars are intentionally excluded. */
    private Set<String> primaryArtifactClasses() {
        if (primaryArtifactClasses != null) {
            return primaryArtifactClasses;
        }
        Set<String> result = new LinkedHashSet<>();
        Path target = bb.scanInputs().target();
        try {
            if (Files.isDirectory(target)) {
                try (var stream = Files.walk(target)) {
                    stream.filter(Files::isRegularFile)
                            .map(target::relativize)
                            .map(Path::toString)
                            .map(value -> value.replace(File.separatorChar, '/'))
                            .map(ChainComposerKnowledgeSource::primaryClassName)
                            .filter(java.util.Objects::nonNull)
                            .forEach(result::add);
                }
            } else if (Files.isRegularFile(target)) {
                String name = target.getFileName().toString().toLowerCase(java.util.Locale.ROOT);
                if (name.endsWith(".class")) {
                    result.add(target.getFileName().toString().replaceFirst("\\.class$", ""));
                } else {
                    try (JarFile jar = new JarFile(target.toFile())) {
                        Enumeration<JarEntry> entries = jar.entries();
                        while (entries.hasMoreElements()) {
                            String className = primaryClassName(entries.nextElement().getName());
                            if (className != null) {
                                result.add(className);
                            }
                        }
                    }
                }
            }
        } catch (IOException e) {
            JustLogger.debug("读取主工件类归属失败，源宿主调度退回稳定排序: {}", e.getMessage());
        }
        primaryArtifactClasses = Set.copyOf(result);
        return primaryArtifactClasses;
    }

    private static String primaryClassName(String entry) {
        if (entry == null || !entry.endsWith(".class") || entry.startsWith("META-INF/")) {
            return null;
        }
        for (String prefix : List.of("BOOT-INF/classes/", "WEB-INF/classes/")) {
            if (entry.startsWith(prefix)) {
                return entry.substring(prefix.length(), entry.length() - 6);
            }
        }
        if (entry.startsWith("BOOT-INF/lib/") || entry.startsWith("WEB-INF/lib/")) {
            return null;
        }
        return entry.substring(0, entry.length() - 6);
    }

    /** 全图单遍扫描：反序列化源宿主（体内含 OIS 读取或 bridge:deserialize 源调用，
     *  排除 JDK 运行时包——其 readObject 体是容器触发机制本身，以机制桥接跳建模）。 */
    private void scanHosts() {
        Map<String, DeserHost> hosts = new java.util.TreeMap<>();
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
            if (isObjectInputRead(callOwner, callName)) {
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
                if (hosts.size() >= MAX_SOURCE_HOSTS) {
                    bb.markIncomplete("SOURCE_HOST_CAP:" + MAX_SOURCE_HOSTS);
                }
                continue;
            }
            // 框架自身管线内的同名调用（Kryo 序列化器内部再调 readObject 等）是机制 plumbing，
            // 不是攻击面宿主——排除与源框架同包的宿主
            int slash = frameOwner.lastIndexOf('/');
            String framePkg = slash > 0 ? frameOwner.substring(0, slash + 1) : frameOwner;
            if (!hostOwner.startsWith(framePkg)) {
                String hostDescriptor = call.strProp("methodDesc");
                String hostKey = hostOwner + ".#" + hostName + hostDescriptor;
                hosts.putIfAbsent(hostKey, new DeserHost(hostOwner, hostName, hostDescriptor,
                        frameOwner, frameMethod, call.strProp("desc")));
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

    /**
     * ObjectInputStream source calls include inherited reads through a custom stream
     * subclass.  The call owner is the bytecode-declared receiver type, so checking only
     * the JDK base class loses application-defined stream boundaries before composition.
     */
    private boolean isObjectInputRead(String owner, String name) {
        if (owner == null || name == null
                || !("readObject".equals(name) || "readUnshared".equals(name)
                || "readFields".equals(name))) {
            return false;
        }
        return "java/io/ObjectInputStream".equals(owner)
                || bb.hierarchy().isSubtypeOf(owner, "java/io/ObjectInputStream");
    }

    private static boolean isPublicEntry(Chain chain) {
        return isPublicEntry(chain.entryKind())
                || ("deserialize".equals(chain.entryKind())
                && chain.hops().stream().anyMatch(hop -> hop.kind() == HopKind.ENTRY
                && "framework-bean-input".equals(hop.reason())));
    }

    private FrontFeatures frontFeatures(Chain front) {
        String frontSink = front.sinkClass() + "." + front.sinkMethod();
        return new FrontFeatures(
                "java/lang/reflect/Method.invoke".equals(frontSink),
                triggerContainerOnPath(front),
                onPath(front, "com/sun/org/apache/xalan/internal/xsltc/trax/TemplatesImpl"),
                "DESERIALIZE".equals(front.category()));
    }

    private List<Chain> candidateBacks(FrontFeatures features, List<Chain> publicEntries,
                                       List<Chain> triggerEntries, List<Chain> templateEntries) {
        if ((features.invoke() || features.deserialize()) && features.triggerContainer() == null
                && !features.template()) {
            return publicEntries;
        }
        Set<Chain> candidates = new LinkedHashSet<>();
        if (features.invoke() || features.deserialize()) {
            candidates.addAll(publicEntries);
        }
        if (features.triggerContainer() != null) {
            candidates.addAll(triggerEntries);
        }
        if (features.template()) {
            candidates.addAll(templateEntries);
        }
        return candidates.isEmpty() ? List.of() : List.copyOf(candidates);
    }

    /** 判断前段链的 sink 能否语义上触发后段链的 entry。 */
    private Bridge semanticBridge(FrontFeatures features, Chain front, Chain back) {
        String backKind = back.entryKind();
        String backEntry = back.entryClass() + "." + back.entryMethod();

        // 1. INVOKE 桥：前段 sink 是 Method.invoke → 可调任意公共方法
        if (features.invoke()
                && isPublicEntry(back)) {
            return Bridge.INVOKE;
        }

        // 2. TRIGGER 桥：前段路径含触发容器，且后段入口类可放入容器的 key/元素槽
        // （有序容器 TreeMap/PriorityQueue 的槽位要求 Comparable——不可比较的入口类放不进去，
        //   桥不成立；HashMap/HashSet/Hashtable 的 key 槽为 Object 不限）
        if (features.triggerContainer() != null && isTriggerEntry(backKind)
                && keySlotAccepts(features.triggerContainer(), back.entryClass())) {
            return Bridge.TRIGGER;
        }

        // 3. TEMPLATE 桥：前段路径含 TemplatesImpl → 后段 entry 触发其 getter
        if (features.template()
                && isTemplateTrigger(backEntry)) {
            return Bridge.TEMPLATE;
        }

        // 4. DESER 桥：前段 sink 是二次反序列化 → 其产物字节流再被反序列化，触发后段机制入口
        if (features.deserialize() && isPublicEntry(back)) {
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

    private static String entryDescriptor(Chain chain) {
        for (ChainHop hop : chain.hops()) {
            if (hop.kind() == HopKind.ENTRY && hop.desc() != null) {
                return hop.desc();
            }
        }
        return "";
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
                front.unresolvedHops() + back.unresolvedHops(), back.sinkDescriptor());
    }
}
