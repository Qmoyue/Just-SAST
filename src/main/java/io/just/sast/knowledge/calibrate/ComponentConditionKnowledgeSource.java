package io.just.sast.knowledge.calibrate;

import io.just.sast.blackboard.Blackboard;
import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.Event;
import io.just.sast.blackboard.EventType;
import io.just.sast.blackboard.HopKind;
import io.just.sast.blackboard.KnowledgeSource;
import io.just.sast.blackboard.ObjectGraphPlan;
import io.just.sast.blackboard.Phase;
import io.just.sast.blackboard.RunProduct;
import io.just.sast.config.Rule;
import io.just.sast.cpg.graph.NodeType;
import io.just.sast.model.ClassInfo;
import io.just.sast.model.FieldRef;
import io.just.sast.model.InsnFact;
import io.just.sast.model.MethodInfo;
import io.just.sast.model.MethodRef;
import io.just.sast.model.Op;
import io.just.sast.util.JustLogger;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Component-condition calibration.  Conditions are deliberately evaluated after composition:
 * they refine an already materialized path and never manufacture an entry, sink, or object
 * graph.  Unknown class bodies, values, and application state remain candidates.
 */
public final class ComponentConditionKnowledgeSource implements KnowledgeSource {

    private Blackboard bb;

    @Override
    public String id() {
        return "component-condition";
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
        return 150;
    }

    @Override
    public Set<RunProduct> requiresProducts() {
        return Set.of(RunProduct.COMPOSED_CHAINS, RunProduct.CALIBRATED_CHAINS);
    }

    @Override
    public Set<RunProduct> providesProducts() {
        return Set.of(RunProduct.CALIBRATED_CHAINS);
    }

    @Override
    public void init(Blackboard blackboard) {
        this.bb = blackboard;
    }

    @Override
    public void onEvent(Blackboard blackboard, Event event) {
        if (event.type() != EventType.SCAN_COMPLETE) {
            return;
        }
        int rejected = 0;
        int guarded = 0;
        int propertyNotes = 0;
        List<Rule.ConditionRule> conditions = blackboard.rules().conditions();
        if (conditions.isEmpty()) {
            return;
        }
        for (Chain chain : blackboard.reportChains()) {
            if (blackboard.calibrationOf(chain.key()) != null) {
                continue;
            }
            for (Rule.ConditionRule condition : conditions) {
                List<String> targets = matchingPathClasses(chain, condition.targetClass());
                if (targets.isEmpty()) {
                    continue;
                }
                if (condition.spec() instanceof Rule.SerializableRequirement serializable
                        && serializationBoundary(chain)) {
                    String impossible = firstNonSerializable(targets, serializable.interfaceType());
                    if (impossible != null) {
                        blackboard.calibrateChain(chain.key(),
                                "condition-non-serializable:" + condition.id() + ":" + impossible);
                        rejected++;
                        break;
                    }
                    continue;
                }
                if (condition.spec() instanceof Rule.SerializationGuard guard
                        && serializationBoundary(chain)
                        && targets.stream().anyMatch(target -> guardPresent(target, guard.guardCall()))) {
                    blackboard.chainNote(chain.key(), "condition:serialization-guard;property="
                            + guard.propertyKey() + ";required=" + guard.requiredValue()
                            + ";status=CONDITIONAL");
                    guarded++;
                    continue;
                }
                if (condition.spec() instanceof Rule.PropertyFilterDecl filter
                        && propertyFilterInstalled(filter)) {
                    if (explicitBlockedProperty(chain, targets, filter)) {
                        blackboard.calibrateChain(chain.key(),
                                "condition-property-filter:" + condition.id() + ":"
                                        + filter.propertyField() + "=" + filter.blockedValue());
                        rejected++;
                        break;
                    }
                    blackboard.chainNote(chain.key(), "condition:property-filter;field="
                            + filter.propertyField() + ";blocked-value=" + filter.blockedValue()
                            + ";status=CONDITIONAL;other-properties=RETAINED");
                    propertyNotes++;
                }
            }
        }
        JustLogger.info("组件条件校准：拒绝 {}，序列化保护条件 {}，属性过滤条件 {}（规则 {}）",
                rejected, guarded, propertyNotes, conditions.size());
    }

    private String firstNonSerializable(List<String> targets, String interfaceType) {
        for (String target : targets) {
            ClassInfo info = bb.hierarchy().classInfo(target);
            if (info != null && !bb.hierarchy().isSubtypeOf(target, interfaceType)) {
                return target;
            }
        }
        return null;
    }

    private boolean guardPresent(String target, Rule.CallMatcher guard) {
        ClassInfo info = bb.hierarchy().classInfo(target);
        if (info == null) {
            return false;
        }
        for (MethodInfo method : info.methods()) {
            for (InsnFact instruction : method.instructions()) {
                if (!instruction.op().isInvoke() || instruction.operands().isEmpty()
                        || !(instruction.operands().get(0) instanceof MethodRef ref)) {
                    continue;
                }
                if (guard.matches(ref.owner(), ref.name(), ref.descriptor())) {
                    return true;
                }
            }
        }
        return false;
    }

    private boolean propertyFilterInstalled(Rule.PropertyFilterDecl filter) {
        for (var node : bb.graph().nodesOfType(NodeType.METHOD)) {
            String owner = node.owner();
            String name = node.name();
            if (!filter.registrationOwner().matches(owner)
                    || !filter.registrationMethod().matches(name)) {
                continue;
            }
            ClassInfo info = bb.hierarchy().classInfo(owner);
            MethodInfo method = info == null ? null : info.method(name, node.descriptor());
            if (method == null) {
                continue;
            }
            for (InsnFact instruction : method.instructions()) {
                if (instruction.op() != Op.GETSTATIC && instruction.op() != Op.GETFIELD) {
                    continue;
                }
                if (instruction.operands().isEmpty()
                        || !(instruction.operands().get(0) instanceof FieldRef ref)) {
                    continue;
                }
                if (filter.markerClass().matches(ref.owner())) {
                    return true;
                }
            }
        }
        return false;
    }

    private boolean explicitBlockedProperty(Chain chain, List<String> targets,
                                            Rule.PropertyFilterDecl filter) {
        ObjectGraphPlan plan = chain.constructionPlan();
        if (plan == null) {
            return false;
        }
        Set<String> targetSet = Set.copyOf(targets);
        for (ObjectGraphPlan.FieldAssignment assignment : plan.fields()) {
            if (assignment == null || !filter.propertyField().equals(assignment.field())
                    || assignment.values().size() != 1) {
                continue;
            }
            ObjectGraphPlan.Value value = assignment.values().get(0);
            if (value == null || value.kind() != ObjectGraphPlan.ValueKind.STRING
                    || !filter.blockedValue().equals(value.value())) {
                continue;
            }
            if (fieldOwnerTargets(plan, assignment.owner(), chain, targetSet)) {
                return true;
            }
        }
        return false;
    }

    private boolean fieldOwnerTargets(ObjectGraphPlan plan, String owner, Chain chain,
                                      Set<String> targets) {
        if (owner == null || owner.isBlank()) {
            return false;
        }
        if ("entry".equals(owner)) {
            return targets.contains(chain.entryClass());
        }
        for (ObjectGraphPlan.Node node : plan.nodes()) {
            if (node != null && owner.equals(node.id()) && targets.contains(node.type())) {
                return true;
            }
        }
        return targets.contains(owner);
    }

    private static List<String> matchingPathClasses(Chain chain, io.just.sast.config.Match target) {
        Set<String> classes = new LinkedHashSet<>();
        add(classes, chain.entryClass());
        add(classes, chain.sinkClass());
        for (ChainHop hop : chain.hops()) {
            add(classes, hop.fromOwner());
            add(classes, hop.toOwner());
        }
        List<String> result = new ArrayList<>();
        for (String value : classes) {
            if (target.matches(value)) {
                result.add(value);
            }
        }
        result.sort(String::compareTo);
        return List.copyOf(result);
    }

    private static void add(Set<String> values, String value) {
        if (value != null && !value.isBlank()) {
            values.add(value);
        }
    }

    private static boolean serializationBoundary(Chain chain) {
        String kind = chain.entryKind() == null ? "" : chain.entryKind().toLowerCase(Locale.ROOT);
        if (Set.of("readobject", "readobjectnodata", "readresolve", "readexternal",
                "validateobject", "deserialization", "seconddeserialization").contains(kind)) {
            return true;
        }
        if ("readObject".equals(chain.entryMethod()) || "readExternal".equals(chain.entryMethod())) {
            return true;
        }
        return chain.hops().stream().anyMatch(hop -> hop.kind() == HopKind.ENTRY
                && hop.reason() != null
                && Set.of("readObject", "readObjectNoData", "readResolve", "readExternal",
                "validateObject").contains(hop.reason()));
    }
}
