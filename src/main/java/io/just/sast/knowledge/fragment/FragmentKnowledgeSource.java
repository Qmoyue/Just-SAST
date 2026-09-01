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
            String sinkDescriptor = frag.sinkDescriptor();
            var sinkRule = sinkRuleFor(sinkOwner, frag.sinkName(), sinkDescriptor);
            if (sinkRule.isPresent() && (sinkDescriptor == null || sinkDescriptor.isEmpty())) {
                sinkDescriptor = firstMatchingDescriptor(sinkOwner, frag.sinkName(), sinkRule.get());
            }
            if (sinkRule.isEmpty()) {
                // 复刻/shading 类名尾段一致回退（规则 owner 尾段 == 解析后 owner 尾段）
                String tail = "/" + frag.sinkOwner().substring(frag.sinkOwner().lastIndexOf('/') + 1);
                String descriptorForMatch = sinkDescriptor == null ? "" : sinkDescriptor;
                sinkRule = bb.rules().sinks().stream()
                        .filter(r -> r.call().ownerType() != null
                                && r.call().ownerType().endsWith(tail)
                                && r.call().matchesRest(frag.sinkName(),
                                        descriptorForMatch))
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
                    HopKind.DIRECT_CALL, null, "fragment", sinkDescriptor == null ? "" : sinkDescriptor, null));
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
                    HopKind.ENTRY, null, frag.entryKind(), entryDescriptor(entryClass, entryMethod), null));
            Rule.SinkRule rule = sinkRule.get();
            Chain chain = new Chain(rule.id(), rule.category(), rule.severity(),
                    entryClass, entryMethod, frag.entryKind(),
                    sinkOwner, frag.sinkName(), hops, 0, sinkDescriptor == null ? "" : sinkDescriptor,
                    rule.role().name(), frag.constructionPlan());
            if (bb.addChain(chain)) {
                produced++;
            }
        }
        JustLogger.info("片段知识源：合成 {} 条", produced);
    }

    /** 精确命中 → 唯一后缀命中。结构相似而非同名的类不能作为片段锚点，避免误合成。 */
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
        return null;
    }

    private java.util.Optional<Rule.SinkRule> sinkRuleFor(String owner, String name, String descriptor) {
        if (descriptor != null && !descriptor.isEmpty()) {
            return bb.ruleEngine().matchingSink(owner, name, descriptor);
        }
        ClassInfo ci = bb.hierarchy().classInfo(owner);
        if (ci != null) {
            for (var method : ci.methods()) {
                if (method.name().equals(name)) {
                    var match = bb.ruleEngine().matchingSink(owner, name, method.descriptor());
                    if (match.isPresent()) {
                        return match;
                    }
                }
            }
        }
        return java.util.Optional.empty();
    }

    private String firstMatchingDescriptor(String owner, String name, Rule.SinkRule rule) {
        ClassInfo ci = bb.hierarchy().classInfo(owner);
        if (ci == null) {
            return "";
        }
        for (var m : ci.methods()) {
            if (m.name().equals(name)
                    && bb.ruleEngine().matchingSink(owner, name, m.descriptor())
                    .filter(hit -> hit.id().equals(rule.id())).isPresent()) {
                return m.descriptor();
            }
        }
        return "";
    }

    private String entryDescriptor(String owner, String name) {
        ClassInfo ci = bb.hierarchy().classInfo(owner);
        if (ci != null) {
            for (var method : ci.methods()) {
                if (method.name().equals(name)) {
                    return method.descriptor();
                }
            }
        }
        return switch (name) {
            case "hashCode" -> "()I";
            case "toString" -> "()Ljava/lang/String;";
            case "equals" -> "(Ljava/lang/Object;)Z";
            case "invoke" -> "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;";
            case "readObject" -> "(Ljava/io/ObjectInputStream;)V";
            default -> "";
        };
    }
}
