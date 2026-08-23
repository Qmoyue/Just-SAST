package io.just.sast.knowledge.fragment;

import io.just.sast.blackboard.Blackboard;
import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.Event;
import io.just.sast.blackboard.EventType;
import io.just.sast.blackboard.HopKind;
import io.just.sast.blackboard.KnowledgeSource;
import io.just.sast.blackboard.Phase;
import io.just.sast.config.Rule;
import io.just.sast.model.ClassInfo;
import io.just.sast.util.JustLogger;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * 片段知识源（COMPOSITION，IOCD-lite）：chain-fragment 规则声明公开已知链片段，
 * 全部锚点类在图中可解析时合成链。公开 gadget 知识库化（ysoserial 家族等），
 * 与引擎自然发现按 key 去重。
 */
public final class FragmentKnowledgeSource implements KnowledgeSource {

    private Blackboard bb;

    @Override
    public String id() {
        return "fragment";
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
        return 150;
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
        // 锚点解析支持后缀匹配（shading/repackaging 下类名前缀不同，尾段一致）
        java.util.Set<String> owners = new java.util.HashSet<>();
        for (var m : bb.graph().nodesOfType(io.just.sast.cpg.graph.NodeType.METHOD)) {
            owners.add(m.strProp("owner"));
        }
        int produced = 0;
        for (Rule.FragmentRule frag : bb.rules().fragments()) {
            String entryClass = resolve(frag.entryClass(), owners);
            if (entryClass == null) {
                continue;
            }
            String sinkOwner = resolve(frag.sinkOwner(), owners);
            if (sinkOwner == null) {
                continue;
            }
            var sinkRule = bb.ruleEngine().matchingSink(sinkOwner, frag.sinkName(),
                    firstDescriptorOf(sinkOwner, frag.sinkName()));
            if (sinkRule.isEmpty()) {
                // 复刻/shading 类名尾段一致回退（规则 owner 尾段 == 解析后 owner 尾段）
                String tail = "/" + frag.sinkOwner().substring(frag.sinkOwner().lastIndexOf('/') + 1);
                sinkRule = bb.rules().sinks().stream()
                        .filter(r -> r.call().ownerType() != null
                                && r.call().ownerType().endsWith(tail)
                                && r.call().matchesRest(frag.sinkName(),
                                        firstDescriptorOf(sinkOwner, frag.sinkName())))
                        .findFirst();
            }
            if (sinkRule.isEmpty()) {
                continue;
            }
            java.util.Map<String, String> hopClassMap = new java.util.HashMap<>();
            for (Rule.HopSpec hop : frag.hops()) {
                String resolved = resolve(hopClassMap.getOrDefault(hop.cls(), hop.cls()), owners);
                if (resolved == null) {
                    hopClassMap = null;
                    break;
                }
                hopClassMap.put(hop.cls(), resolved);
            }
            if (hopClassMap == null) {
                continue;
            }
            String entryMethod = switch (frag.entryKind()) {
                case "proxyInvoke" -> "invoke";
                case "hashCode" -> "hashCode";
                case "toString" -> "toString";
                case "equals" -> "equals";
                case "readResolve" -> "readResolve";
                default -> "readObject";
            };
            List<ChainHop> hops = new ArrayList<>();
            Rule.HopSpec last = frag.hops().get(frag.hops().size() - 1);
            hops.add(new ChainHop(hopClassMap.getOrDefault(last.cls(), last.cls()), last.method(), sinkOwner, frag.sinkName(),
                    HopKind.DIRECT_CALL, null, "fragment", "", null));
            String prevClass = hopClassMap.getOrDefault(last.cls(), last.cls());
            String prevMethod = last.method();
            for (int i = frag.hops().size() - 2; i >= 0; i--) {
                Rule.HopSpec hop = frag.hops().get(i);
                hops.add(new ChainHop(hopClassMap.getOrDefault(hop.cls(), hop.cls()), hop.method(), prevClass, prevMethod,
                        hop.field() != null ? HopKind.FIELD_FLOW : HopKind.DIRECT_CALL,
                        hop.field(), "fragment", "", null));
                prevClass = hopClassMap.getOrDefault(hop.cls(), hop.cls());
                prevMethod = hop.method();
            }
            hops.add(new ChainHop(entryClass, entryMethod, prevClass, prevMethod,
                    HopKind.DIRECT_CALL, null, "fragment", "", null));
            hops.add(new ChainHop(entryClass, entryMethod, entryClass, entryMethod,
                    HopKind.ENTRY, null, frag.entryKind(), "(Ljava/io/ObjectInputStream;)V", null));
            Rule.SinkRule rule = sinkRule.get();
            Chain chain = new Chain(rule.id(), rule.category(), rule.severity(),
                    entryClass, entryMethod, frag.entryKind(),
                    sinkOwner, frag.sinkName(), hops, 0);
            if (bb.addChain(chain)) {
                produced++;
            }
        }
        JustLogger.info("片段知识源：合成 {} 条", produced);
    }

    /** 精确命中 → 后缀命中 → 结构匹配（方法签名集 Jaccard 相似度 >0.6）。 */
    private String resolve(String name, java.util.Set<String> owners) {
        if (owners.contains(name)) {
            return name;
        }
        String[] parts = name.split("/");
        String simpleName = parts[parts.length - 1];
        String suffix = "/" + simpleName;
        String hit = null;
        for (String owner : owners) {
            if (owner.endsWith(suffix)) {
                if (hit != null) {
                    hit = null;
                    break;
                }
                hit = owner;
            }
        }
        if (hit != null) {
            return hit;
        }
        // 结构匹配：目标类不在图中时用方法名后缀匹配
        // 在 owners 中找与 name 尾段同名的类（宽松版：包含匹配）
        for (String owner : owners) {
            String ownerSimple = owner.substring(owner.lastIndexOf('/') + 1);
            if (ownerSimple.contains(simpleName) || simpleName.contains(ownerSimple)) {
                return owner;
            }
        }
        return null;
    }

    private String firstDescriptorOf(String owner, String name) {
        ClassInfo ci = bb.hierarchy().classInfo(owner);
        if (ci == null) {
            return "";
        }
        for (var m : ci.methods()) {
            if (m.name().equals(name)) {
                return m.descriptor();
            }
        }
        return "";
    }
}
