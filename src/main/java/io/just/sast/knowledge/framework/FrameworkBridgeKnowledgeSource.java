package io.just.sast.knowledge.framework;

import io.just.sast.analysis.entry.ApplicationEntryIndex;
import io.just.sast.analysis.taint.OriginSupport;
import io.just.sast.blackboard.Blackboard;
import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.Event;
import io.just.sast.blackboard.EventType;
import io.just.sast.blackboard.HopKind;
import io.just.sast.blackboard.KnowledgeSource;
import io.just.sast.blackboard.RunProduct;
import io.just.sast.config.Rule;
import io.just.sast.config.RuleSchemaV2;
import io.just.sast.cpg.graph.Edge;
import io.just.sast.cpg.graph.EdgeType;
import io.just.sast.cpg.graph.Node;
import io.just.sast.cpg.graph.NodeType;
import io.just.sast.model.InsnFact;
import io.just.sast.model.MethodInfo;
import io.just.sast.model.MethodRef;
import io.just.sast.util.ChainMaterializer;
import io.just.sast.util.JustLogger;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

/**
 * 统一框架桥接引擎（ANALYSIS 阶段，自足）。
 * 从 YAML source 规则读取框架清单（bridge=deserialize 的反序列化入口 + bridge=serialize 的序列化入口），
 * 以包前缀剪枝 BFS 桥接到反射 sink（Method.invoke / Constructor.newInstance / Class.forName）。
 *
 * 引擎只做一件事：框架入口 → 框架包内 BFS → 反射 sink 的管线桥接。
 * 哪些框架、哪些方法、哪个方向——全部由规则声明，引擎零硬编码。
 * entry_kind 按桥方向标注（deserialize/serialize）；BFS 中间跳保留在链上（框架内部管线可审计）。
 */
public final class FrameworkBridgeKnowledgeSource implements KnowledgeSource {

    private static final int MAX_DEPTH = 12;
    private static final int MAX_CHAINS = 200;

    private Blackboard bb;
    private OriginSupport support;

    @Override
    public String id() {
        return "framework-bridge";
    }

    @Override
    public Set<EventType> interests() {
        return Set.of(EventType.SCAN_START);
    }

    @Override
    public int priority() {
        return 400;
    }

    @Override
    public Set<RunProduct> requiresProducts() {
        return Set.of(RunProduct.PROGRAM_MODEL);
    }

    @Override
    public Set<RunProduct> providesProducts() {
        return Set.of(RunProduct.ANALYSIS_CHAINS);
    }

    @Override
    public void init(Blackboard blackboard) {
        this.bb = blackboard;
        this.support = blackboard.originSupport();
    }

    @Override
    public void onEvent(Blackboard bb, Event event) {
        if (event.type() != EventType.SCAN_START) {
            return;
        }
        List<Rule.SourceRule> sources = bb.rules().sources();
        if (sources.isEmpty()) {
            return;
        }
        int chains = 0;
        outer:
        for (Node method : bb.graph().nodesOfType(NodeType.METHOD)) {
            MethodInfo info = support.methodOf(method.strProp("owner"),
                    method.strProp("name"), method.strProp("desc"));
            if (info == null) {
                continue;
            }
            String methodKey = OriginSupport.methodKey(info);
            for (InsnFact insn : info.instructions()) {
                if (!insn.op().isInvoke() || insn.operands().isEmpty()) {
                    continue;
                }
                if (!(insn.operands().get(0) instanceof MethodRef ref)) {
                    continue;
                }
                Rule.SourceRule matched = bb.ruleEngine()
                        .matchingSource(ref.owner(), ref.name(), ref.descriptor()).orElse(null);
                if (matched == null || !isUnconditionalDeserializeSource(matched)
                        && !"serialize".equalsIgnoreCase(matched.bridge())) {
                    // A constrained source is a secondary object-graph boundary.  The
                    // framework BFS must not publish it as an independent entry->sink
                    // chain; its input provenance is established by the taint engines.
                    continue;
                }
                Long callId = support.callId(methodKey, insn.offset());
                if (callId == null) {
                    continue;
                }
                Node fwCall = bb.graph().node(callId);
                // 管线 BFS（包前缀剪枝）到反射 sink，保留完整调用点路径
                DeferredFrameworkPath path = findReflectiveSinkPath(fwCall, ref.owner());
                if (path == null) {
                    continue;
                }
                Node sinkCall = path.sinkCaller();
                var sinkRule = bb.ruleEngine().matchingSink(sinkCall);
                if (sinkRule.isEmpty()) {
                    continue;
                }
                Rule.SinkRule rule = sinkRule.get();
                // Preserve the old null result before publishing a candidate.  The endpoint
                // descriptor is cheap; the path-to-Chain assembly remains behind the supplier.
                if (support.enclosingMethod(sinkCall) == null) {
                    continue;
                }
                String bridge = matched.bridge() != null ? matched.bridge() : "deserialize";
                boolean continuation = !RuleSchemaV2.isTerminalSink(rule)
                        && !RuleSchemaV2.bridgesFor(rule).isEmpty();
                ApplicationEntryIndex.ProducerCandidate candidate =
                        new ApplicationEntryIndex.ProducerCandidate(rule.id(), rule.category(),
                                rule.severity(), info.owner(), info.name(), info.descriptor(), bridge,
                                sinkCall.strProp("owner"), sinkCall.strProp("name"),
                                sinkCall.strProp("desc"), rule.role().name(), rule.sinkRisk(),
                                continuation);
                FrameworkProducer producer = new FrameworkProducer(candidate, () -> {
                    List<Node> materializedPath = path.materializer().get();
                    if (materializedPath == null || materializedPath.size() != path.pathSize()) {
                        return null;
                    }
                    return assemble(info, materializedPath, sinkCall, rule, matched);
                });
                if (bb.addSolverCandidate(producer.candidate(), producer.materializer())) {
                    chains++;
                    if (chains >= MAX_CHAINS) {
                        JustLogger.warn("框架桥接：达到链数上限 {}，剩余入口未处理", MAX_CHAINS);
                        bb.markIncomplete("FRAMEWORK_CHAIN_CAP:" + MAX_CHAINS);
                        break outer;
                    }
                }
            }
        }
        JustLogger.info("框架桥接[规则驱动]：产链 {} 条", chains);
    }

    private static boolean isUnconditionalDeserializeSource(Rule.SourceRule source) {
        return source != null && !"serialize".equalsIgnoreCase(source.bridge())
                && (source.tainted() == null || source.tainted().isEmpty());
    }

    /** 包前缀剪枝 BFS：框架入口沿同包方法到反射 sink，返回入口→…→sink 的调用点路径。 */
    private DeferredFrameworkPath findReflectiveSinkPath(Node fwCall, String fwOwner) {
        String fwPrefix = packagePrefix(fwOwner, 3);
        Map<Node, Node> parent = new HashMap<>();
        Deque<Node> work = new ArrayDeque<>();
        Set<Long> visited = new HashSet<>();
        work.add(fwCall);
        visited.add(fwCall.id());
        int depth = 0;
        while (!work.isEmpty() && depth < MAX_DEPTH) {
            int size = work.size();
            for (int i = 0; i < size; i++) {
                Node call = work.poll();
                for (Edge edge : call.out()) {
                    if (edge.type() != EdgeType.INVOKES && edge.type() != EdgeType.DISPATCHES) {
                        continue;
                    }
                    Node callee = edge.to();
                    String owner = callee.strProp("owner");
                    String name = callee.strProp("name");
                    if (isReflectiveSink(owner, name)) {
                        Map<Node, Node> stableParent = Map.copyOf(parent);
                        int pathSize = pathSize(stableParent, call, fwCall);
                        if (pathSize <= 0) {
                            return null;
                        }
                        return new DeferredFrameworkPath(call, pathSize,
                                () -> buildPath(stableParent, call, fwCall));
                    }
                    if (!owner.startsWith(fwPrefix)) {
                        continue;
                    }
                    expandBody(parent, visited, work, owner, name, callee.strProp("desc"), call);
                }
            }
            depth++;
        }
        if (!work.isEmpty()) {
            bb.markIncomplete("FRAMEWORK_DEPTH_CAP:" + MAX_DEPTH);
        }
        return null;
    }

    /** 把 callee 方法体内的调用点入队（父记录为当前调用点）。 */
    private void expandBody(Map<Node, Node> parent, Set<Long> visited, Deque<Node> work,
                            String owner, String name, String desc, Node via) {
        MethodInfo info = support.methodOf(owner, name, desc);
        if (info == null) {
            return;
        }
        String key = OriginSupport.methodKeyOf(owner, name, desc);
        for (InsnFact insn : info.instructions()) {
            if (!insn.op().isInvoke()) {
                continue;
            }
            Long callId = support.callId(key, insn.offset());
            if (callId != null) {
                Node nextCall = bb.graph().node(callId);
                if (visited.add(nextCall.id())) {
                    parent.put(nextCall, via);
                    work.add(nextCall);
                }
            }
        }
    }

    /** 沿 parent 回溯构造路径 [fwCall, …, sinkCaller]。 */
    private static List<Node> buildPath(Map<Node, Node> parent, Node sinkCaller, Node fwCall) {
        List<Node> path = new ArrayList<>();
        for (Node cur = sinkCaller; cur != null; cur = parent.get(cur)) {
            path.add(cur);
            if (cur.id() == fwCall.id()) {
                break;
            }
        }
        java.util.Collections.reverse(path);
        return path;
    }

    /** Count the same bounded caller path as {@link #buildPath} without allocating its list. */
    private static int pathSize(Map<Node, Node> parent, Node sinkCaller, Node fwCall) {
        int size = 0;
        for (Node cur = sinkCaller; cur != null; cur = parent.get(cur)) {
            size++;
            if (cur.id() == fwCall.id()) {
                return size;
            }
        }
        return 0;
    }

    private static boolean isReflectiveSink(String owner, String name) {
        return ("java/lang/reflect/Method".equals(owner) && "invoke".equals(name))
                || ("java/lang/reflect/Constructor".equals(owner) && "newInstance".equals(name))
                || ("java/lang/Class".equals(owner) && ("forName".equals(name) || "newInstance".equals(name)));
    }

    /** 组装链（sink-first）：sink 自跳 + 管线中间跳（保留框架内部路径）+ 入口自跳。 */
    private Chain assemble(MethodInfo entryMethod, List<Node> path, Node sinkCall,
                           Rule.SinkRule rule, Rule.SourceRule source) {
        MethodInfo sinkEnclosing = support.enclosingMethod(sinkCall);
        if (sinkEnclosing == null) {
            return null;
        }
        String bridge = source.bridge() != null ? source.bridge() : "deserialize";
        List<ChainHop> hops = new ArrayList<>();
        hops.add(new ChainHop(sinkEnclosing.owner(), sinkEnclosing.name(),
                sinkCall.strProp("owner"), sinkCall.strProp("name"),
                HopKind.DIRECT_CALL, null, bridge, sinkCall.strProp("desc"), null));
        // 中间跳：路径上相邻调用点 (c_i → c_{i+1})，c_{i+1} 位于 c_i 的目标方法体内；sink-first 反向排列
        for (int i = path.size() - 1; i > 0; i--) {
            Node inner = path.get(i);
            Node outer = path.get(i - 1);
            MethodInfo innerMethod = support.enclosingMethod(inner);
            if (innerMethod == null) {
                continue;
            }
            hops.add(new ChainHop(innerMethod.owner(), innerMethod.name(),
                    outer.strProp("owner"), outer.strProp("name"),
                    HopKind.DIRECT_CALL, null, bridge, outer.strProp("desc"), null));
        }
        hops.add(new ChainHop(entryMethod.owner(), entryMethod.name(),
                entryMethod.owner(), entryMethod.name(),
                HopKind.ENTRY, null, bridge, entryMethod.descriptor(), null));
        return new Chain(rule.id(), rule.category(), rule.severity(),
                entryMethod.owner(), entryMethod.name(), bridge,
                sinkCall.strProp("owner"), sinkCall.strProp("name"), hops, 0, sinkCall.strProp("desc"),
                rule.role().name(), null, rule.sinkRisk());
    }

    private static String packagePrefix(String internalName, int segments) {
        String[] parts = internalName.split("/");
        int n = Math.min(segments, parts.length - 1);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++) {
            if (i > 0) {
                sb.append('/');
            }
            sb.append(parts[i]);
        }
        return sb.toString();
    }

    /**
     * Framework BFS endpoint metadata with a memoized caller-path materializer.  The path is
     * frozen only after an accepted typed producer asks for it; rejected candidates pay only
     * the bounded BFS parent-map bookkeeping and path length count.
     */
    record DeferredFrameworkPath(Node sinkCaller, int pathSize, Supplier<List<Node>> materializer) {
        DeferredFrameworkPath {
            sinkCaller = Objects.requireNonNull(sinkCaller, "sinkCaller");
            if (pathSize <= 0) {
                throw new IllegalArgumentException("framework path size must be positive");
            }
            Supplier<List<Node>> delegate = Objects.requireNonNull(materializer, "materializer");
            AtomicReference<PathMaterializationState> cached = new AtomicReference<>();
            materializer = () -> {
                PathMaterializationState existing = cached.get();
                if (existing != null) {
                    return existing.valueOrThrow();
                }
                synchronized (cached) {
                    existing = cached.get();
                    if (existing == null) {
                        try {
                            List<Node> built = delegate.get();
                            existing = new PathMaterializationState(
                                    built == null ? null : List.copyOf(built), null);
                        } catch (RuntimeException failure) {
                            existing = new PathMaterializationState(null, failure);
                        }
                        cached.set(existing);
                    }
                    return existing.valueOrThrow();
                }
            };
        }

        private record PathMaterializationState(List<Node> path, RuntimeException failure) {
            private List<Node> valueOrThrow() {
                if (failure != null) {
                    throw failure;
                }
                return path;
            }
        }
    }

    /** Typed framework endpoint plus a stable deferred chain payload. */
    record FrameworkProducer(ApplicationEntryIndex.ProducerCandidate candidate,
                             Supplier<Chain> materializer) {
        FrameworkProducer {
            candidate = Objects.requireNonNull(candidate, "candidate");
            materializer = ChainMaterializer.memoize(Objects.requireNonNull(materializer, "materializer"));
        }
    }
}
