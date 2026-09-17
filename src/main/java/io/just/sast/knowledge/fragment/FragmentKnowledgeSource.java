package io.just.sast.knowledge.fragment;

import io.just.sast.analysis.entry.ApplicationEntryIndex;
import io.just.sast.blackboard.Blackboard;
import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.Event;
import io.just.sast.blackboard.EventType;
import io.just.sast.blackboard.HopKind;
import io.just.sast.blackboard.KnowledgeSource;
import io.just.sast.blackboard.Phase;
import io.just.sast.blackboard.RunProduct;
import io.just.sast.config.Rule;
import io.just.sast.config.RuleSchemaV2;
import io.just.sast.model.ClassInfo;
import io.just.sast.model.InsnFact;
import io.just.sast.model.MethodInfo;
import io.just.sast.model.MethodRef;
import io.just.sast.model.Op;
import io.just.sast.model.TypeRef;
import io.just.sast.util.ChainMaterializer;
import io.just.sast.util.JustLogger;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;

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
            String entryMethod = declaredEntryMethod(frag);
            String materializedEntryDescriptor = declaredEntryDescriptor(frag, entryClass,
                    entryMethod);
            if (!entryEndpointIsAdmissible(frag, entryClass, entryMethod,
                    materializedEntryDescriptor)) {
                continue;
            }
            Rule.SinkRule rule = sinkRule.get();
            String materializedSinkDescriptor = sinkDescriptor == null ? "" : sinkDescriptor;
            List<Rule.HopSpec> fragmentHops = List.copyOf(frag.hops());
            Map<String, String> resolvedHopClasses = Map.copyOf(hopClassMap);
            int expectedHopCount = frag.directTerminal() ? 1 : fragmentHops.size() + 2;
            boolean continuation = ApplicationEntryIndex.hasTypedContinuationEvidence(frag.entryKind())
                    || (!RuleSchemaV2.isTerminalSink(rule)
                    && !RuleSchemaV2.bridgesFor(rule).isEmpty());
            boolean declaredFragmentContinuation = frag.constructionPlan() != null
                    && frag.constructionPlan().shapeSummary().valid()
                    && RuleSchemaV2.isTerminalSink(rule);
            ApplicationEntryIndex.ProducerCandidate candidate = new ApplicationEntryIndex.ProducerCandidate(
                    rule.id(), rule.category(), rule.severity(), entryClass, entryMethod,
                    materializedEntryDescriptor, frag.entryKind(), sinkOwner, frag.sinkName(),
                    materializedSinkDescriptor, RuleSchemaV2.sinkRoleFor(rule).name(), rule.sinkRisk(),
                    continuation || declaredFragmentContinuation, false,
                    declaredFragmentContinuation);
            Supplier<Chain> materializer = () -> {
                if (fragmentHops.isEmpty() && !frag.directTerminal()) {
                    return null;
                }
                String fragmentReason = "any".equals(frag.activation())
                        ? "fragment" : "fragment-activation-" + frag.activation();
                if (frag.directTerminal()) {
                    List<ChainHop> directHops = List.of(new ChainHop(entryClass, entryMethod,
                            entryClass, entryMethod, HopKind.ENTRY, null, fragmentReason,
                            materializedEntryDescriptor, null));
                    return new Chain(rule.id(), rule.category(), rule.severity(),
                            entryClass, entryMethod, frag.entryKind(), sinkOwner, frag.sinkName(),
                            directHops, 0, materializedSinkDescriptor,
                            RuleSchemaV2.sinkRoleFor(rule).name(),
                            frag.constructionPlan(), rule.sinkRisk());
                }
                Rule.HopSpec last = fragmentHops.get(fragmentHops.size() - 1);
                List<ChainHop> hops = new ArrayList<>(expectedHopCount);
                hops.add(new ChainHop(resolvedHopClasses.getOrDefault(last.cls(), last.cls()),
                        last.method(), sinkOwner, frag.sinkName(), HopKind.DIRECT_CALL, null,
                        fragmentReason, materializedSinkDescriptor, null));
                String prevClass = resolvedHopClasses.getOrDefault(last.cls(), last.cls());
                String prevMethod = last.method();
                for (int i = fragmentHops.size() - 2; i >= 0; i--) {
                    Rule.HopSpec hop = fragmentHops.get(i);
                    hops.add(new ChainHop(resolvedHopClasses.getOrDefault(hop.cls(), hop.cls()),
                            hop.method(), prevClass, prevMethod,
                            hop.field() != null ? HopKind.FIELD_FLOW : HopKind.DIRECT_CALL,
                            hop.field(), fragmentReason, "", null));
                    prevClass = resolvedHopClasses.getOrDefault(hop.cls(), hop.cls());
                    prevMethod = hop.method();
                }
                hops.add(new ChainHop(entryClass, entryMethod, prevClass, prevMethod,
                        HopKind.DIRECT_CALL, null, fragmentReason, "", null));
                hops.add(new ChainHop(entryClass, entryMethod, entryClass, entryMethod,
                        HopKind.ENTRY, null, frag.entryKind(), materializedEntryDescriptor, null));
                if (hops.size() != expectedHopCount) {
                    return null;
                }
                return new Chain(rule.id(), rule.category(), rule.severity(),
                        entryClass, entryMethod, frag.entryKind(), sinkOwner, frag.sinkName(),
                        hops, 0, materializedSinkDescriptor,
                        RuleSchemaV2.sinkRoleFor(rule).name(),
                        frag.constructionPlan(), rule.sinkRisk());
            };
            FragmentProducer producer = new FragmentProducer(candidate, materializer);
            if (bb.addSolverCandidate(producer.candidate(), producer.materializer())) {
                produced++;
            }
        }
        JustLogger.info("片段知识源：合成 {} 条", produced);
    }

    private String declaredEntryMethod(Rule.FragmentRule fragment) {
        if (fragment.entryMethod() != null && !fragment.entryMethod().isBlank()) {
            return fragment.entryMethod();
        }
        return switch (fragment.entryKind()) {
            case "proxyInvoke" -> "invoke";
            case "hashCode" -> "hashCode";
            case "toString" -> "toString";
            case "equals" -> "equals";
            case "readResolve" -> "readResolve";
            default -> "readObject";
        };
    }

    private String declaredEntryDescriptor(Rule.FragmentRule fragment, String owner,
                                            String method) {
        if (fragment.entryDescriptor() != null && !fragment.entryDescriptor().isBlank()) {
            return fragment.entryDescriptor();
        }
        return entryDescriptor(owner, method);
    }

    /**
     * A secondary-deserialization fragment is admitted only from the actual method body.  The
     * rule names the endpoint, but the class model must still prove an ObjectInputStream
     * allocation and an ObjectInput/ObjectInputStream.readObject call.  This keeps a public
     * method with a suggestive name from becoming a nested stream merely by declaration.
     */
    private boolean entryEndpointIsAdmissible(Rule.FragmentRule fragment, String owner,
                                               String methodName, String descriptor) {
        if (!"secondDeserialization".equals(fragment.entryKind())) {
            return true;
        }
        ClassInfo info = bb.hierarchy().classInfo(owner);
        if (info == null || descriptor == null || descriptor.isBlank()) {
            return false;
        }
        MethodInfo method = info.method(methodName, descriptor);
        return method != null && containsNestedObjectInputRead(method);
    }

    private boolean containsNestedObjectInputRead(MethodInfo method) {
        boolean allocatesObjectInputStream = false;
        boolean readsObject = false;
        for (InsnFact instruction : method.instructions()) {
            if (instruction == null) {
                continue;
            }
            if (instruction.op() == Op.NEW && instruction.operands().size() == 1
                    && instruction.operands().get(0) instanceof TypeRef type
                    && isObjectInputStreamType(type.descriptor())) {
                allocatesObjectInputStream = true;
            }
            if (instruction.op().isInvoke() && instruction.operands().size() == 1
                    && instruction.operands().get(0) instanceof MethodRef ref
                    && isObjectInputType(ref.owner()) && "readObject".equals(ref.name())) {
                readsObject = true;
            }
        }
        return allocatesObjectInputStream && readsObject;
    }

    private boolean isObjectInputStreamType(String ownerOrDescriptor) {
        String owner = normalizeType(ownerOrDescriptor);
        return "java/io/ObjectInputStream".equals(owner)
                || bb.hierarchy().isSubtypeOf(owner, "java/io/ObjectInputStream");
    }

    private boolean isObjectInputType(String owner) {
        return "java/io/ObjectInput".equals(owner)
                || "java/io/ObjectInputStream".equals(owner)
                || bb.hierarchy().isSubtypeOf(owner, "java/io/ObjectInput");
    }

    private static String normalizeType(String value) {
        if (value == null) {
            return "";
        }
        if (value.startsWith("L") && value.endsWith(";")) {
            return value.substring(1, value.length() - 1);
        }
        return value;
    }

    /** 精确命中 → 唯一后缀命中。结构相似而非同名的类不能作为片段锚点，避免误合成。 */
    private String resolve(String name, java.util.Set<String> owners) {
        if (owners.contains(name)) {
            return name;
        }
        if (name != null && bb.hierarchy().classInfo(name) != null
                && owners.stream().anyMatch(owner -> owner != null
                && bb.hierarchy().isSubtypeOf(owner, name))) {
            // A declarative fragment may name an inherited API on a concrete anchor type.  The
            // CPG only has method owners for materialized declarations, so the hierarchy is the
            // authoritative existence check for a class such as MLet whose defineClass method is
            // inherited from ClassLoader.  No call is executed or widened from this fact.
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
        String unique = ApplicationEntryIndex.uniqueMethodDescriptor(bb.graph(), owner, name);
        if (!unique.isBlank()) {
            return unique;
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

    /** Typed fragment endpoint plus a stable deferred chain payload. */
    record FragmentProducer(ApplicationEntryIndex.ProducerCandidate candidate,
                            Supplier<Chain> materializer) {
        FragmentProducer {
            candidate = Objects.requireNonNull(candidate, "candidate");
            materializer = ChainMaterializer.memoize(Objects.requireNonNull(materializer, "materializer"));
        }
    }
}
