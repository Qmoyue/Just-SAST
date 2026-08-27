package io.just.sast.knowledge.calibrate;

import io.just.sast.blackboard.Blackboard;
import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.Event;
import io.just.sast.blackboard.EventType;
import io.just.sast.blackboard.HopKind;
import io.just.sast.blackboard.KnowledgeSource;
import io.just.sast.blackboard.Phase;
import io.just.sast.chain.ConfidenceScorer;
import io.just.sast.cpg.graph.Edge;
import io.just.sast.cpg.graph.EdgeType;
import io.just.sast.cpg.graph.Node;
import io.just.sast.cpg.graph.NodeType;
import io.just.sast.util.JustLogger;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 链剪枝知识源（CALIBRATION 阶段）。
 * 两层剪枝：
 * 1. 触发上下文：hashCode/equals/compareTo/compare/toString 入口须有反序列化可达触发者
 * 2. 机制去重：同机制尾按入口家族留 ≤5 条代表
 * 依赖：ChainValidator 先执行（priority 100 < 本源 200），被拒绝的链不再参与去重。
 * 入口下游闭包与反向污点引擎共享同一份（黑板 OriginSupport 分发）。
 */
public final class ChainPrunerKnowledgeSource implements KnowledgeSource {

    /** JDK 机制内部实现类前缀：其调用边属框架 machinery 语义，不构成 gadget 路径。 */
    private static final java.util.List<String> MACHINERY_INTERNALS = java.util.List.of(
            "java/util/ServiceLoader$");

    private static final Set<String> TRIGGER_REQUIRED = Set.of(
            "hashCode", "equals", "compareTo", "compare", "toString");
    /** 同机制保留的入口类代表上限。家族 = 入口类本身（不同类即不同发现；同类变体仍被去重）。 */
    private static final int MAX_FAMILIES = 8;

    private Blackboard bb;

    @Override
    public String id() {
        return "chain-pruner";
    }

    @Override
    public Set<EventType> interests() {
        return Set.of(EventType.SCAN_COMPLETE);
    }

    @Override
    public Phase phase() {
        return Phase.CALIBRATION;
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
        if (event.type() != EventType.SCAN_COMPLETE) {
            return;
        }
        // 1. 触发上下文（入口下游闭包与反向引擎共享）
        Set<String> downstream = bb.originSupport().entryDownstream(bb.graph());
        int noTrigger = 0;
        for (Chain chain : bb.chains()) {
            if (!TRIGGER_REQUIRED.contains(chain.entryKind())
                    || bb.calibrationOf(chain.key()) != null) {
                continue;
            }
            if (!hasReachableTrigger(chain, downstream)) {
                bb.calibrateChain(chain.key(), "no-trigger");
                noTrigger++;
            }
        }
        // 1.5 深链结构门：跳数 >14 且字段流占比 <25% —— 无对象图绑定的游走链（噪声形态），
        // 类型传播强化（U3）解锁的深度上限以此门控制洪水
        int deep = 0;
        for (Chain chain : bb.chains()) {
            if (bb.calibrationOf(chain.key()) != null || chain.hops().size() <= 14) {
                continue;
            }
            long fieldFlows = chain.hops().stream()
                    .filter(h -> h.kind() == HopKind.FIELD_FLOW).count();
            if (fieldFlows * 6 < chain.hops().size()) {
                bb.calibrateChain(chain.key(), "deep-incoherent");
                deep++;
            }
        }
        // 1.8 JDK 机制内部类噪音：路径穿过 JDK 机制内部实现类（ServiceLoader$ 迭代器等）
        // 的"链"是框架自身 machinery，非攻击者经反序列化语义可触发的 gadget 路径
        int machinery = 0;
        for (Chain chain : bb.chains()) {
            if (bb.calibrationOf(chain.key()) != null) {
                continue;
            }
            if (chain.hops().stream().anyMatch(h -> MACHINERY_INTERNALS.stream()
                    .anyMatch(p -> h.toOwner().startsWith(p)))) {
                bb.calibrateChain(chain.key(), "machinery-hop");
                machinery++;
            }
        }
        // 2. 机制去重（按家族）
        Map<String, List<Chain>> groups = new LinkedHashMap<>();
        for (Chain chain : bb.chains()) {
            if (bb.calibrationOf(chain.key()) != null) {
                continue; // 已被前面校验拒绝的不再处理
            }
            groups.computeIfAbsent(mechanismKey(chain), k -> new ArrayList<>()).add(chain);
        }
        int dedup = 0;
        for (List<Chain> group : groups.values()) {
            group.sort(Comparator.<Chain>comparingInt(Chain::unresolvedHops)
                    .thenComparingInt(c -> c.hops().size())
                    .thenComparingInt(c -> -ConfidenceScorer.evidenceScore(c, null))
                    .thenComparing(Chain::key));
            // V3 Flash 式多样性预算：前 MAX_FAMILIES 个家族保留；超出的高证据链保留（DEGRADED 标注），
            // 低证据链淘汰——多样性有预算但不硬切
            Set<String> keptFamilies = new LinkedHashSet<>();
            int overflow = 0;
            for (Chain chain : group) {
                String family = entryFamily(chain.entryClass());
                if (keptFamilies.contains(family)) {
                    bb.calibrateChain(chain.key(), "mechanism-duplicate");
                    dedup++;
                } else if (keptFamilies.size() >= MAX_FAMILIES) {
                    // 软预算：高证据链保留但降级
                    if (ConfidenceScorer.evidenceScore(chain, null) >= 4 && overflow < 3) {
                        overflow++;
                        bb.chainNote(chain.key(), "degrade:overflow");
                    } else {
                        bb.calibrateChain(chain.key(), "mechanism-duplicate");
                        dedup++;
                    }
                } else {
                    keptFamilies.add(family);
                }
            }
        }
        JustLogger.info("链剪枝：无触发拒绝 {}，机制内部类 {}，机制去重 {}（共 {} 条）",
                noTrigger, machinery, dedup, bb.chains().size());
    }

    // ---- 触发上下文 ----

    private boolean hasReachableTrigger(Chain chain, Set<String> downstream) {
        var support = bb.originSupport();
        for (Node m : bb.graph().nodesOfType(NodeType.METHOD)) {
            if (!m.strProp("owner").equals(chain.entryClass())
                    || !m.strProp("name").equals(chain.entryMethod())) {
                continue;
            }
            Set<Node> callSites = new HashSet<>();
            collectCallSites(m, callSites);
            if (callSites.isEmpty()) {
                for (String ancestor : ancestors(chain.entryClass())) {
                    Node anc = bb.graph().findMethodNode(ancestor, chain.entryMethod(), m.strProp("desc"));
                    if (anc != null) {
                        collectCallSites(anc, callSites);
                    }
                }
            }
            for (Node call : callSites) {
                String caller = call.strProp("methodOwner") + "#"
                        + call.strProp("methodName") + call.strProp("methodDesc");
                if (downstream.contains(caller)) {
                    return true;
                }
            }
        }
        return false;
    }

    private void collectCallSites(Node methodNode, Set<Node> out) {
        for (Edge edge : methodNode.in()) {
            if (edge.type() == EdgeType.INVOKES || edge.type() == EdgeType.DISPATCHES
                    || edge.type() == EdgeType.LAMBDA) {
                out.add(edge.from());
            }
        }
    }

    private Set<String> ancestors(String owner) {
        Set<String> result = new HashSet<>();
        Set<String> visited = new HashSet<>();
        Deque<String> queue = new ArrayDeque<>();
        var ci = bb.hierarchy().classInfo(owner);
        if (ci != null) {
            if (ci.superName() != null) {
                queue.add(ci.superName());
            }
            queue.addAll(bb.hierarchy().transitiveInterfaces(owner));
        }
        while (!queue.isEmpty()) {
            String cur = queue.poll();
            if (!visited.add(cur) || cur.equals(owner)) {
                continue;
            }
            result.add(cur);
            var c = bb.hierarchy().classInfo(cur);
            if (c == null) {
                continue;
            }
            if (c.superName() != null) {
                queue.add(c.superName());
            }
            queue.addAll(bb.hierarchy().transitiveInterfaces(cur));
        }
        return result;
    }

    // ---- 机制去重 ----

    private static String mechanismKey(Chain chain) {
        StringBuilder sb = new StringBuilder();
        sb.append(chain.sinkClass()).append('.').append(chain.sinkMethod())
                .append('|').append(chain.category()).append('|');
        List<ChainHop> hops = chain.hops();
        for (int i = 1; i < hops.size(); i++) {
            ChainHop hop = hops.get(i);
            if (hop.kind() == HopKind.ENTRY) {
                continue;
            }
            sb.append(hop.toOwner()).append('.').append(hop.toName()).append('.')
                    .append(hop.field() != null ? hop.field() : "").append(';');
        }
        return sb.toString();
    }

    /** 入口家族 = 入口类本身：跨类多样性是不同发现，不应被包级家族折叠（历史 bug：包前两段折叠把
     *  单包语料/单包应用的全部分析发现折叠成 1 条）。 */
    private static String entryFamily(String entryClass) {
        return entryClass;
    }
}
