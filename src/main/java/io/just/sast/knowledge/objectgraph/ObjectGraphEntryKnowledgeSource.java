package io.just.sast.knowledge.objectgraph;

import io.just.sast.blackboard.Blackboard;
import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.Event;
import io.just.sast.blackboard.EventType;
import io.just.sast.blackboard.HopKind;
import io.just.sast.blackboard.KnowledgeSource;
import io.just.sast.blackboard.Phase;
import io.just.sast.blackboard.RunProduct;
import io.just.sast.analysis.entry.ApplicationEntryIndex;
import io.just.sast.config.RuleSchemaV2;
import io.just.sast.config.Rule;
import io.just.sast.cpg.graph.Node;
import io.just.sast.cpg.graph.NodeType;
import io.just.sast.model.ClassInfo;
import io.just.sast.model.FieldInfo;
import io.just.sast.util.ChainMaterializer;
import io.just.sast.util.JustLogger;

import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Supplier;

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

    private static final List<String> OBJECT_GRAPH_ENTRY_KINDS = List.of(
            "readObject", "readObjectNoData", "readExternal", "readResolve", "validateObject");

    private static final int MAX_REROOTED = 300;
    private static final int MAX_PER_CHAIN = 20;
    private static final int MAX_HOPS = 16;
    /** 万能容器类型：对任意可序列化子类型平凡成立，重根无信号纯噪音，排除。 */
    private static final Set<String> UNIVERSAL_TYPES = Set.of(
            "java/lang/Object", "java/io/Serializable", "java/lang/Cloneable",
            "java/lang/Comparable", "java/io/Externalizable");
    /** Erased container types need generic element evidence; a raw container is not a direct gadget field. */
    private static final Set<String> GENERIC_CONTAINER_TYPES = Set.of(
            "java/lang/Iterable", "java/util/Collection", "java/util/List", "java/util/Set",
            "java/util/Queue", "java/util/Deque", "java/util/Map", "java/util/SortedMap",
            "java/util/SortedSet", "java/util/Iterator");

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
    public Set<RunProduct> requiresProducts() {
        return Set.of(RunProduct.ANALYSIS_CHAINS);
    }

    @Override
    public Set<RunProduct> providesProducts() {
        return Set.of(RunProduct.COMPOSED_CHAINS);
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
        // Keep dependency suffix endpoints deferred.  Object-graph rerooting only needs a
        // suffix payload when a typed mechanism entry can fit one of the discovered concrete
        // fields; the compatibility composition view would otherwise flush every producer.
        Blackboard.CompositionInputs compositionInputs = bb.compositionInputsLazy();
        JustLogger.info("对象图入口开始：当前组合输入 {}",
                distinctCompositionInputCount(compositionInputs));
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
            boolean serialPersistentApprox = ci.hasSerialPersistentFields();
            for (FieldInfo f : ci.fields()) {
                boolean transientReference = Modifier.isTransient(f.access())
                        && referenceTypeOf(f.descriptor()) != null;
                if ((Modifier.isTransient(f.access()) && !serialPersistentApprox)
                        || Modifier.isStatic(f.access())) {
                    continue;
                }
                String type = referenceTypeOf(f.descriptor());
                List<String> genericTypes = f.genericReferenceTypes();
                boolean genericContainer = type != null
                        && GENERIC_CONTAINER_TYPES.contains(type)
                        && !genericTypes.isEmpty();
                if (transientReference && serialPersistentApprox) {
                    bb.markIncomplete("OBJECT_GRAPH_SERIAL_PERSISTENT_FIELDS_APPROX");
                }
                if (type != null && arrayDepth(f.descriptor()) > 1) {
                    bb.markIncomplete("OBJECT_GRAPH_MULTIDIMENSIONAL_ARRAY_APPROX");
                }
                if (genericContainer) {
                    bb.markIncomplete("OBJECT_GRAPH_GENERIC_CONTAINER_APPROX");
                }
                if (type != null && !genericContainer && !UNIVERSAL_TYPES.contains(type)
                        && !GENERIC_CONTAINER_TYPES.contains(type)) {
                    containersByType.computeIfAbsent(type, k -> new ArrayList<>(1))
                            .add(new String[] {owner, f.name(), "field"});
                }
                for (String genericType : genericTypes) {
                    if (!UNIVERSAL_TYPES.contains(genericType)
                            && !GENERIC_CONTAINER_TYPES.contains(genericType)) {
                        containersByType.computeIfAbsent(genericType, k -> new ArrayList<>(1))
                                .add(new String[] {owner, f.name(), "generic-container"});
                    }
                }
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
        // Object-graph rerooting can only start from a mechanism-invoked chain.  Select that
        // frontier directly from the typed owners so ordinary application products are not
        // copied into a compatibility union and rejected after sorting.
        List<Chain> chains = rerootCandidates(bb, compositionInputs, validationRegistered,
                containersByType);
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
                    RerootedProducer merged = reroot(chain, container[0], container[1], container.length > 2
                            ? container[2] : "field");
                    if (merged != null && bb.addSolverCandidate(merged.candidate(),
                            merged.materializer())) {
                        rerooted++;
                        per++;
                    }
                }
            }
        }
        JustLogger.info("对象图入口：重根产链 {} 条", rerooted);
    }

    private List<Chain> rerootCandidates(Blackboard target,
                                         Blackboard.CompositionInputs inputs,
                                         Set<String> validationRegistered,
                                         Map<String, List<String[]>> containersByType) {
        if (inputs == null) {
            return List.of();
        }
        Map<String, Chain> unique = new java.util.TreeMap<>();
        addRerootCandidates(unique, inputs.applicationChains(), validationRegistered);
        addRerootCandidates(unique, inputs.bridgeContinuations(), validationRegistered);
        addRerootCandidates(unique, inputs.dependencySuffixes(), validationRegistered);
        addDeferredRerootCandidates(unique, target, inputs, validationRegistered,
                containersByType);
        return new ArrayList<>(unique.values());
    }

    private void addDeferredRerootCandidates(Map<String, Chain> unique, Blackboard target,
                                             Blackboard.CompositionInputs inputs,
                                             Set<String> validationRegistered,
                                             Map<String, List<String[]>> containersByType) {
        if (inputs == null) {
            return;
        }
        for (String entryKind : OBJECT_GRAPH_ENTRY_KINDS) {
            addDeferredRerootCandidates(unique, target,
                    inputs.deferredDependencySuffixesForEntryKind(entryKind),
                    validationRegistered, containersByType);
        }
    }

    /** Materialize a deferred suffix only when its mechanism entry has a compatible concrete
     * field type.  The later reroot admission still proves application ownership and terminal
     * demand; this predicate only prevents an object-graph compatibility flush. */
    private void addDeferredRerootCandidates(Map<String, Chain> unique, Blackboard target,
                                             List<Blackboard.DeferredDependencySuffix> candidates,
                                             Set<String> validationRegistered,
                                             Map<String, List<String[]>> containersByType) {
        if (target == null || candidates == null || candidates.isEmpty()
                || containersByType == null || containersByType.isEmpty()) {
            return;
        }
        for (Blackboard.DeferredDependencySuffix deferred : candidates) {
            ApplicationEntryIndex.ProducerCandidate candidate = deferred.candidate();
            if (!mechanismInvoked(candidate.entryKind(), candidate.entryOwner(), validationRegistered)
                    || !hasCompatibleContainer(candidate.entryOwner(), containersByType)) {
                continue;
            }
            ApplicationEntryIndex.ProducerAdmissionDecision demandDecision =
                    target.applicationEntryIndex().producerAdmission(candidate);
            Blackboard.SolverAdmissionResult result =
                    target.materializeDeferredDependencySuffix(deferred, demandDecision);
            if (result.accepted() && mechanismInvoked(result.chain().entryKind(),
                    result.chain().entryClass(), validationRegistered)) {
                unique.putIfAbsent(result.chain().key(), result.chain());
            }
        }
    }

    private boolean hasCompatibleContainer(String entryOwner,
                                           Map<String, List<String[]>> containersByType) {
        for (String ancestor : ancestors(entryOwner)) {
            List<String[]> containers = containersByType.get(ancestor);
            if (containers != null && !containers.isEmpty()) {
                return true;
            }
        }
        return false;
    }

    private void addRerootCandidates(Map<String, Chain> unique, List<Chain> candidates,
                                     Set<String> validationRegistered) {
        if (candidates == null) {
            return;
        }
        for (Chain chain : candidates) {
            if (mechanismInvoked(chain.entryKind(), chain.entryClass(), validationRegistered)) {
                unique.putIfAbsent(chain.key(), chain);
            }
        }
    }

    private int distinctCompositionInputCount(Blackboard.CompositionInputs inputs) {
        if (inputs == null) {
            return 0;
        }
        Set<String> keys = new HashSet<>();
        addCompositionKeys(keys, inputs.applicationChains());
        addCompositionKeys(keys, inputs.bridgeContinuations());
        addCompositionKeys(keys, inputs.dependencySuffixes());
        if (inputs.deferredDependencySuffixes() != null) {
            for (Blackboard.DeferredDependencySuffix deferred :
                    inputs.deferredDependencySuffixes()) {
                ApplicationEntryIndex.ProducerCandidate candidate = deferred.candidate();
                keys.add("<deferred>|" + candidate.entryMethodKey() + "|"
                        + candidate.terminalOwner() + "#" + candidate.terminalName()
                        + candidate.terminalDescriptor());
            }
        }
        return keys.size();
    }

    private void addCompositionKeys(Set<String> keys, List<Chain> candidates) {
        if (candidates == null) {
            return;
        }
        for (Chain chain : candidates) {
            if (chain != null) {
                keys.add(chain.key());
            }
        }
    }

    /** 入口类别是否由反序列化机制直接调用（validateObject 需注册核验）。 */
    private static boolean mechanismInvoked(String entryKind, String entryClass, Set<String> validationRegistered) {
        return switch (entryKind) {
            case "readObject", "readObjectNoData", "readExternal", "readResolve" -> true;
            case "validateObject" -> validationRegistered.contains(entryClass);
            default -> false;
        };
    }

    /** 字段描述符 → 引用类型名：去除任意数组维度后取 L..;，基本类型数组仍为 null。 */
    private static String referenceTypeOf(String desc) {
        if (desc == null || desc.isBlank()) {
            return null;
        }
        int start = 0;
        while (start < desc.length() && desc.charAt(start) == '[') {
            start++;
        }
        return start < desc.length() && desc.charAt(start) == 'L'
                && desc.endsWith(";") ? desc.substring(start + 1, desc.length() - 1) : null;
    }

    private static int arrayDepth(String desc) {
        if (desc == null) {
            return 0;
        }
        int depth = 0;
        while (depth < desc.length() && desc.charAt(depth) == '[') {
            depth++;
        }
        return depth;
    }

    /** F 入口链重根到 E：E 的入口跳 + 字段跳 + F 的链（去 F 入口自跳），sink-first 顺序。 */
    private RerootedProducer reroot(Chain chain, String owner, String field, String relation) {
        if (owner.equals(chain.entryClass()) || onPath(chain, owner)) {
            return null; // 防环
        }
        // E 须有自己的回调入口方法（保证入口真实存在且可评分）
        String[] entry = callbackEntryOf(owner);
        if (entry == null) {
            return null;
        }
        int rerootHopCount = Math.max(0, chain.hops().size() - 1) + 2;
        if (rerootHopCount > MAX_HOPS) {
            return null;
        }
        String entryOwner = entry[0];
        String entryMethod = entry[1];
        String entryKind = entry[2];
        String entryDescriptor = entry[3];
        boolean continuation = bb.applicationEntryIndex().hasSemanticContinuation(chain.hops())
                || typedContinuationSink(chain);
        ApplicationEntryIndex.ProducerCandidate candidate = new ApplicationEntryIndex.ProducerCandidate(
                chain.ruleId(), chain.category(), chain.severity(), entryOwner, entryMethod,
                entryDescriptor, entryKind, chain.sinkClass(), chain.sinkMethod(),
                chain.sinkDescriptor(), chain.sinkRole(), chain.sinkRisk(), continuation);
        Supplier<Chain> materializer = () -> new Chain(candidate.ruleId(), candidate.category(),
                candidate.severity(), candidate.entryOwner(), candidate.entryName(),
                candidate.entryKind(), candidate.terminalOwner(), candidate.terminalName(),
                rerootHops(chain, entryOwner, entryMethod, entryKind, entryDescriptor,
                        owner, field, relation), chain.unresolvedHops(), candidate.terminalDescriptor(),
                candidate.terminalRole(), chain.constructionPlan(), candidate.sinkRisk());
        return new RerootedProducer(candidate, materializer);
    }

    /** Build the reroot field/entry path only after typed admission requests materialization. */
    private static List<ChainHop> rerootHops(Chain chain, String entryOwner, String entryMethod,
                                             String entryKind, String entryDescriptor,
                                             String owner, String field, String relation) {
        List<ChainHop> hops = new ArrayList<>(chain.hops().size() + 2);
        for (int i = 0; i < chain.hops().size() - 1; i++) {
            hops.add(chain.hops().get(i)); // F 的跳（末位 ENTRY 自跳去掉）
        }
        hops.add(new ChainHop(entryOwner, entryMethod, chain.entryClass(), chain.entryMethod(),
                HopKind.FIELD_FLOW, field, "object-graph-" + relation, "", null, owner));
        hops.add(new ChainHop(entryOwner, entryMethod, entryOwner, entryMethod,
                HopKind.ENTRY, null, entryKind, entryDescriptor, null));
        return List.copyOf(hops);
    }

    private boolean typedContinuationSink(Chain chain) {
        if (chain == null || bb == null) {
            return false;
        }
        Rule.SinkRule sink = bb.rules().sinks().stream()
                .filter(rule -> rule != null && rule.id().equals(chain.ruleId()))
                .findFirst()
                .orElseGet(() -> bb.ruleEngine().matchingSink(chain.sinkClass(), chain.sinkMethod(),
                        chain.sinkDescriptor()).orElse(null));
        return sink != null && !RuleSchemaV2.isTerminalSink(sink)
                && !RuleSchemaV2.bridgesFor(sink).isEmpty();
    }

    /** 类的第一个机制回调入口（owner, method, entryKind）；无则 null。 */
    private String[] callbackEntryOf(String owner) {
        if (bb == null || bb.applicationEntryIndex() == null) {
            return null;
        }
        List<ApplicationEntryIndex.ExecutionEntry> entries =
                bb.applicationEntryIndex().mechanismEntriesForOwner(owner);
        if (entries.isEmpty()) {
            return null;
        }
        ApplicationEntryIndex.ExecutionEntry entry = entries.get(0);
        return new String[] {entry.owner(), entry.name(), entry.entryKind(), entry.descriptor()};
    }

    private static boolean onPath(Chain chain, String owner) {
        for (ChainHop hop : chain.hops()) {
            if (hop.fromOwner().equals(owner) || hop.toOwner().equals(owner)) {
                return true;
            }
        }
        return false;
    }

    record RerootedProducer(ApplicationEntryIndex.ProducerCandidate candidate,
                            Supplier<Chain> materializer) {
    RerootedProducer {
            candidate = Objects.requireNonNull(candidate, "candidate");
            materializer = ChainMaterializer.memoize(Objects.requireNonNull(materializer, "materializer"));
        }
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
