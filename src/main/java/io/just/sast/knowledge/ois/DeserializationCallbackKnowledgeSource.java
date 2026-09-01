package io.just.sast.knowledge.ois;

import io.just.sast.analysis.taint.ForwardOrigins;
import io.just.sast.analysis.taint.OriginSupport;
import io.just.sast.analysis.taint.ValueOrigin;
import io.just.sast.blackboard.Blackboard;
import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.Event;
import io.just.sast.blackboard.EventType;
import io.just.sast.blackboard.HopKind;
import io.just.sast.blackboard.KnowledgeSource;
import io.just.sast.config.Rule;
import io.just.sast.cpg.graph.Edge;
import io.just.sast.cpg.graph.EdgeType;
import io.just.sast.cpg.graph.Node;
import io.just.sast.cpg.graph.NodeType;
import io.just.sast.model.Descriptor;
import io.just.sast.model.MethodInfo;
import io.just.sast.util.JustLogger;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 反序列化回调知识源（ANALYSIS 阶段，自足）。
 * 领域语义：readObject/readUnshared 执行期间，OIS 机制以攻击者可控的类描述符
 * 回调流对象的 resolveClass/resolveProxyClass 重写（与"OIS 读结果可控"、proxyInvoke 同族的威胁模型）。
 * 补足值污点模型无法表达的"机制以流内容为参数回调"（见 architecture.md 6.3）。
 */
public final class DeserializationCallbackKnowledgeSource implements KnowledgeSource {

    private static final String OIS = "java/io/ObjectInputStream";
    private static final String RESOLVE_CLASS = "(Ljava/io/ObjectStreamClass;)Ljava/lang/Class;";
    private static final String RESOLVE_PROXY_CLASS = "([Ljava/lang/Class;)Ljava/lang/Class;";
    /** 机制路径（readObject →…→ 重写方法）BFS 跳数上限。 */
    private static final int MAX_MACHINERY_HOPS = 6;
    /** OIS 宿主上溯 magic-entry 祖先的深度上限。 */
    private static final int MAX_ENTRY_ANCESTRY = 3;
    private static final int MAX_HOSTS_PER_RESOLVER = 2_000;
    private static final int MAX_CHAINS = 2_000;
    private static final int SUBTYPE_TRAVERSAL_CAP = 10_000;

    /** 回调重写：方法名 + 描述符（回调参数恒在 slot 1）。 */
    private record Callback(String name, String desc) {}

    private static final List<Callback> CALLBACKS = List.of(
            new Callback("resolveClass", RESOLVE_CLASS),
            new Callback("resolveProxyClass", RESOLVE_PROXY_CLASS));

    private Blackboard bb;
    private OriginSupport support;

    @Override
    public String id() {
        return "ois-callback";
    }

    @Override
    public Set<EventType> interests() {
        return Set.of(EventType.SCAN_START);
    }

    @Override
    public int priority() {
        return 300;
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
        Map<String, List<Node>> callsByMethod = new HashMap<>();
        for (Node call : bb.graph().nodesOfType(NodeType.CALL)) {
            callsByMethod.computeIfAbsent(OriginSupport.methodKey(call), k -> new ArrayList<>(1)).add(call);
        }
        int chains = 0;
        for (Callback callback : CALLBACKS) {
            for (String resolver : overriders(callback)) {
                MethodInfo resolverMethod = support.methodOf(resolver, callback.name(), callback.desc());
                if (resolverMethod == null) {
                    continue;
                }
                List<ChainHop> machinery = machineryTo(resolver, callback, callsByMethod);
                if (machinery == null) {
                    continue;
                }
                for (Node sinkCall : paramDrivenSinks(resolverMethod)) {
                    chains += emitChains(sinkCall, machinery, callsByMethod);
                    if (chains >= MAX_CHAINS) {
                        JustLogger.info("OIS 回调：达到链数上限 {}", MAX_CHAINS);
                        bb.markIncomplete("OIS_CALLBACK_CHAIN_CAP:" + MAX_CHAINS);
                        return;
                    }
                }
            }
        }
        JustLogger.info("OIS 反序列化回调：产链 {} 条", chains);
    }

    /** 重写了回调方法的 OIS 子类（resolveMethod 指向子类自身）。 */
    private List<String> overriders(Callback callback) {
        List<String> result = new ArrayList<>();
        var subtypeResult = bb.hierarchy().transitiveSubtypes(OIS, SUBTYPE_TRAVERSAL_CAP);
        if (!subtypeResult.complete()) {
            bb.markIncomplete("OIS_CALLBACK_SUBTYPE_CAP:" + SUBTYPE_TRAVERSAL_CAP);
        }
        for (String sub : subtypeResult.values()) {
            if (sub.equals(bb.hierarchy().resolveMethod(sub, callback.name(), callback.desc()))) {
                result.add(sub);
            }
        }
        return result;
    }

    /**
     * 重写方法内：规则命中的 sink 调用，且污点位置来源由回调参数（slot 1）直接
     * 或经一层调用派生（如 desc.getName()）。常量参数不报。
     */
    private List<Node> paramDrivenSinks(MethodInfo resolverMethod) {
        List<Node> result = new ArrayList<>();
        String resolverKey = OriginSupport.methodKey(resolverMethod);
        for (io.just.sast.model.InsnFact insn : resolverMethod.instructions()) {
            if (!insn.op().isInvoke()) {
                continue;
            }
            Long callId = support.callId(resolverKey, insn.offset());
            if (callId == null) {
                continue;
            }
            Node call = bb.graph().node(callId);
            if (bb.ruleEngine().matchingSink(call).isPresent() && paramDriven(call, resolverMethod)) {
                result.add(call);
            }
        }
        return result;
    }

    private boolean paramDriven(Node call, MethodInfo in) {
        ForwardOrigins.State state = support.origins().compute(in).stateBefore().get(call.prop("offset"));
        if (state == null) {
            return false;
        }
        Rule.SinkRule rule = bb.ruleEngine().matchingSink(call).orElseThrow();
        int paramCount = Descriptor.paramCount(call.strProp("desc"));
        for (Rule.TaintedPos pos : rule.tainted()) {
            int depth = pos instanceof Rule.TaintedPos.Arg a ? paramCount - 1 - a.index() : paramCount;
            if (depth < 0 || depth >= state.stack().size()) {
                continue;
            }
            for (ValueOrigin origin : state.stack().get(state.stack().size() - 1 - depth).origins()) {
                if (origin instanceof ValueOrigin.Param p && p.slot() == 1) {
                    return true; // 回调参数直接驱动
                }
                if (origin instanceof ValueOrigin.CallResult cr && derivedFromCallbackParam(cr, in)) {
                    return true; // 一层调用派生（desc.getName() 等）
                }
            }
        }
        return false;
    }

    /** 调用结果的 receiver 是否为回调参数（slot 1）。 */
    private boolean derivedFromCallbackParam(ValueOrigin.CallResult cr, MethodInfo in) {
        if (cr.callNodeId() < 0) {
            return false;
        }
        Node producer = bb.graph().node(cr.callNodeId());
        ForwardOrigins.State state = support.origins().compute(in).stateBefore().get(producer.prop("offset"));
        if (state == null || "STATIC".equals(producer.strProp("invokeKind"))) {
            return false;
        }
        int receiverDepth = state.stack().size() - 1 - Descriptor.paramCount(producer.strProp("desc"));
        if (receiverDepth < 0 || receiverDepth >= state.stack().size()) {
            return false;
        }
        return state.stack().get(receiverDepth).origins().stream()
                .anyMatch(o -> o instanceof ValueOrigin.Param p && p.slot() == 1);
    }

    /** 机制路径：调用图上 OIS.readObject/readUnshared →…→ 重写方法的有界 BFS，返回 entry→sink 顺序的跳。 */
    private List<ChainHop> machineryTo(String resolver, Callback callback, Map<String, List<Node>> callsByMethod) {
        Node start = machineryStart();
        if (start == null) {
            return null;
        }
        Map<Node, Node> parentCall = new HashMap<>(); // 方法节点 → 到达它的调用点
        Deque<Node> work = new ArrayDeque<>();
        Set<Node> visited = new HashSet<>();
        visited.add(start);
        work.add(start);
        while (!work.isEmpty()) {
            Node cur = work.poll();
            if (cur.strProp("owner").equals(resolver) && cur.strProp("name").equals(callback.name())) {
                return buildPath(parentCall, cur);
            }
            if (hopCount(parentCall, cur, start) >= MAX_MACHINERY_HOPS) {
                continue;
            }
            List<Node> calls = callsByMethod.get(methodKeyOf(cur));
            if (calls == null) {
                continue;
            }
            for (Node call : calls) {
                for (Edge edge : call.out()) {
                    if (edge.type() != EdgeType.INVOKES && edge.type() != EdgeType.DISPATCHES
                            && edge.type() != EdgeType.LAMBDA) {
                        continue;
                    }
                    if (visited.add(edge.to())) {
                        parentCall.put(edge.to(), call);
                        work.add(edge.to());
                    }
                }
            }
        }
        return null;
    }

    private int hopCount(Map<Node, Node> parentCall, Node target, Node start) {
        int count = 0;
        Node cur = target;
        while (count <= MAX_MACHINERY_HOPS && cur != null && !cur.equals(start)) {
            Node call = parentCall.get(cur);
            if (call == null) {
                break;
            }
            cur = bb.graph().findMethodNode(call.strProp("methodOwner"), call.strProp("methodName"),
                    call.strProp("methodDesc"));
            count++;
        }
        return count;
    }

    /** 沿 parentCall 回溯构造跳列表（entry→sink 顺序：readObject →…→ resolver）。 */
    private List<ChainHop> buildPath(Map<Node, Node> parentCall, Node target) {
        List<ChainHop> hops = new ArrayList<>();
        Node cur = target;
        while (true) {
            Node call = parentCall.get(cur);
            if (call == null) {
                break;
            }
            Node caller = bb.graph().findMethodNode(call.strProp("methodOwner"), call.strProp("methodName"),
                    call.strProp("methodDesc"));
            if (caller == null) {
                break;
            }
            final Node callee = cur;
            final Node via = call;
            hops.add(new ChainHop(caller.strProp("owner"), caller.strProp("name"),
                    callee.strProp("owner"), callee.strProp("name"),
                    via.out().stream().anyMatch(e -> e.to().equals(callee) && e.type() == EdgeType.DISPATCHES)
                            ? HopKind.VIRTUAL_DISPATCH : HopKind.DIRECT_CALL,
                    null, "machinery", callee.strProp("desc"), null));
            cur = caller;
        }
        java.util.Collections.reverse(hops);
        return hops;
    }

    /** 组装链：入口取 OIS 宿主的最近 magic-entry 祖先（无则记 deserialization 源），宿主数有上限。 */
    private int emitChains(Node sinkCall, List<ChainHop> machinery, Map<String, List<Node>> callsByMethod) {
        Rule.SinkRule rule = bb.ruleEngine().matchingSink(sinkCall).orElseThrow();
        Node startNode = machineryStart();
        String readName = startNode.strProp("name");
        String readDesc = startNode.strProp("desc");
        int produced = 0;
        Set<String> hosts = new HashSet<>();
        for (Edge edge : startNode.in()) {
            if (edge.type() != EdgeType.INVOKES && edge.type() != EdgeType.DISPATCHES) {
                continue;
            }
            MethodInfo host = support.enclosingMethod(edge.from());
            if (host == null || !hosts.add(OriginSupport.methodKey(host))) {
                continue;
            }
            if (hosts.size() > MAX_HOSTS_PER_RESOLVER) {
                bb.markIncomplete("OIS_CALLBACK_HOST_CAP:" + MAX_HOSTS_PER_RESOLVER);
                break;
            }
            if (inlinePlainStream(host, edge.from())) {
                continue; // 宿主自建普通 OIS（内联 new ObjectInputStream）：运行时类型恒为基类，重写回调不可能触发
            }
            EntryRef entry = nearestEntry(host);
            // 前向路径：入口 →(host 若非入口) → readObject → 机制 → resolver；链内统一 entry-last
            List<ChainHop> forward = new ArrayList<>(machinery);
            if (!entry.owner().equals(host.owner()) || !entry.name().equals(host.name())) {
                forward.add(0, new ChainHop(entry.owner(), entry.name(), host.owner(), host.name(),
                        HopKind.DIRECT_CALL, null, "call", host.descriptor(), null));
            }
            forward.add(0, new ChainHop(host.owner(), host.name(), OIS, readName,
                    HopKind.DIRECT_CALL, null, "call", readDesc, null));
            List<ChainHop> hops = new ArrayList<>(forward);
            java.util.Collections.reverse(hops);
            hops.add(new ChainHop(entry.owner(), entry.name(), entry.owner(), entry.name(),
                    HopKind.ENTRY, null, entry.kind(), entry.desc(), null));
            Chain chain = new Chain(rule.id(), rule.category(), rule.severity(),
                    entry.owner(), entry.name(), entry.kind(),
                    sinkCall.strProp("owner"), sinkCall.strProp("name"), hops, 0, sinkCall.strProp("desc"),
                    rule.role().name());
            produced += bb.addChain(chain) ? 1 : 0;
        }
        return produced;
    }

    /** 机制起跳点：OIS.readObject（无则退 readUnshared/readFields）。 */
    private Node machineryStart() {
        Node read = bb.graph().findMethodNode(OIS, "readObject", "()Ljava/lang/Object;");
        if (read != null) {
            return read;
        }
        read = bb.graph().findMethodNode(OIS, "readUnshared", "()Ljava/lang/Object;");
        return read != null ? read : bb.graph().findMethodNode(OIS, "readFields",
                "()Ljava/io/ObjectInputStream$GetField;");
    }

    private record EntryRef(String owner, String name, String kind, String desc) {}

    /**
     * 宿主的 OIS 读调用：receiver 来源全部为方法内 `new ObjectInputStream` 的内联构造
     * → 流的运行时类型恒为基类，自定义 resolveClass/resolveProxyClass 重写不可能被回调（可证剪除）。
     */
    private boolean inlinePlainStream(MethodInfo host, Node readCall) {
        ForwardOrigins.State state = support.origins().compute(host)
                .stateBefore().get(readCall.prop("offset"));
        if (state == null || state.stack().isEmpty()) {
            return false; // 状态未知：保守保留
        }
        boolean sawInline = false;
        for (ValueOrigin origin : state.stack().get(state.stack().size() - 1).origins()) {
            if (!(origin instanceof ValueOrigin.Insn insn)) {
                return false; // 参数/字段/调用结果来源：可能是任意子类
            }
            var op = host.insnAt(insn.offset()).op();
            if (op != io.just.sast.model.Op.NEW || !host.insnAt(insn.offset()).typeRef()
                    .descriptor().equals(OIS)) {
                return false;
            }
            sawInline = true;
        }
        return sawInline;
    }

    /** 宿主方法上溯 ≤MAX_ENTRY_ANCESTRY 找 magic entry；找不到则以宿主为 deserialization 源。 */
    private EntryRef nearestEntry(MethodInfo host) {
        Deque<MethodInfo> work = new ArrayDeque<>();
        Set<String> visited = new HashSet<>();
        work.add(host);
        visited.add(OriginSupport.methodKey(host));
        int level = 0;
        while (!work.isEmpty() && level < MAX_ENTRY_ANCESTRY) {
            int size = work.size();
            for (int i = 0; i < size; i++) {
                MethodInfo cur = work.poll();
                var entryRule = bb.ruleEngine().matchingEntry(
                        cur.owner(), cur.name(), cur.descriptor());
                if (entryRule.isPresent()) {
                    return new EntryRef(cur.owner(), cur.name(), entryRule.get().entryKind(), cur.descriptor());
                }
                Node node = bb.graph().findMethodNode(cur.owner(), cur.name(), cur.descriptor());
                if (node == null) {
                    continue;
                }
                for (Edge edge : node.in()) {
                    if (edge.type() != EdgeType.INVOKES && edge.type() != EdgeType.DISPATCHES
                            && edge.type() != EdgeType.LAMBDA) {
                        continue;
                    }
                    MethodInfo caller = support.enclosingMethod(edge.from());
                    if (caller != null && visited.add(OriginSupport.methodKey(caller))) {
                        work.add(caller);
                    }
                }
            }
            level++;
        }
        return new EntryRef(host.owner(), host.name(), "deserialization", host.descriptor());
    }

    private static String methodKeyOf(Node method) {
        return OriginSupport.methodKeyOf(method.strProp("owner"), method.strProp("name"), method.strProp("desc"));
    }
}
