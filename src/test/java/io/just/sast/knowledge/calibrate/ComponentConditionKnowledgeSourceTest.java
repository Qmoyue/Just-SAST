package io.just.sast.knowledge.calibrate;

import io.just.sast.analysis.hierarchy.ClassHierarchy;
import io.just.sast.blackboard.Blackboard;
import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.Event;
import io.just.sast.blackboard.EventType;
import io.just.sast.blackboard.HopKind;
import io.just.sast.blackboard.ObjectGraphPlan;
import io.just.sast.config.Match;
import io.just.sast.config.Rule;
import io.just.sast.config.RuleSet;
import io.just.sast.cpg.build.FieldWriterIndex;
import io.just.sast.cpg.graph.Graph;
import io.just.sast.model.ClassInfo;
import io.just.sast.model.FieldRef;
import io.just.sast.model.InsnFact;
import io.just.sast.model.MethodInfo;
import io.just.sast.model.MethodRef;
import io.just.sast.model.Op;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Modifier;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Semantic contracts for bounded component-condition calibration. */
class ComponentConditionKnowledgeSourceTest {

    @Test
    void knownNonSerializableTargetIsRejectedOnlyAtSerializationBoundary() {
        Rule.ConditionRule condition = new Rule.ConditionRule("SERIALIZABLE",
                Match.of("fixture/Weak"), new Rule.SerializableRequirement("java/io/Serializable"));
        Blackboard blackboard = blackboard(Map.of(
                "fixture/Weak", classInfo("fixture/Weak", List.of(), List.of())),
                List.of(condition));
        Chain chain = chain("fixture/Weak", "readObject", "readObject", null);
        blackboard.addChain(chain);

        calibrate(blackboard);

        assertEquals("condition-non-serializable:SERIALIZABLE:fixture/Weak",
                blackboard.calibrationOf(chain.key()));
    }

    @Test
    void unknownAndSerializableTargetsRemainCandidates() {
        Rule.ConditionRule condition = new Rule.ConditionRule("SERIALIZABLE",
                Match.of("fixture/(Known|Unknown)"),
                new Rule.SerializableRequirement("java/io/Serializable"));
        Blackboard blackboard = blackboard(Map.of(
                "fixture/Known", classInfo("fixture/Known", List.of("java/io/Serializable"), List.of())),
                List.of(condition));
        Chain known = chain("fixture/Known", "readObject", "readObject", null);
        Chain unknown = chain("fixture/Unknown", "readObject", "readObject", null);
        blackboard.addChain(known);
        blackboard.addChain(unknown);

        calibrate(blackboard);

        assertNull(blackboard.calibrationOf(known.key()));
        assertNull(blackboard.calibrationOf(unknown.key()),
                "missing class facts must not deny a static candidate");
    }

    @Test
    void serializationGuardIsReportedAsConditionalAndNeverSilentlyRejected() {
        MethodInfo callback = method("fixture/Guarded", "readObject", List.of(
                new InsnFact(0, Op.INVOKESTATIC,
                        List.of(new MethodRef("guard/FunctorUtils", "check", "()V")))));
        Rule.ConditionRule condition = new Rule.ConditionRule("GUARD",
                Match.of("fixture/Guarded"), new Rule.SerializationGuard(
                        new Rule.CallMatcher(Match.of("guard/FunctorUtils"), Match.of("check"), null),
                        "fixture.flag", "true"));
        Blackboard blackboard = blackboard(Map.of(
                "fixture/Guarded", classInfo("fixture/Guarded", List.of(), List.of(callback))),
                List.of(condition));
        Chain chain = chain("fixture/Guarded", "readObject", "readObject", null);
        blackboard.addChain(chain);

        calibrate(blackboard);

        assertNull(blackboard.calibrationOf(chain.key()));
        assertTrue(blackboard.chainNotesOf(chain.key()).stream()
                .anyMatch(note -> note.contains("condition:serialization-guard")
                        && note.contains("status=CONDITIONAL")));
    }

    @Test
    void serializationClassNameGuardRejectsAnExactBlockedLiteralAtDeserializationBoundary() {
        String owner = "fixture/GuardedOis";
        MethodInfo resolver = method(owner, "resolveClass", List.of(
                new InsnFact(0, Op.LDC, List.of("java.rmi.server")),
                new InsnFact(1, Op.INVOKEVIRTUAL, List.of(new MethodRef(
                        "java/lang/String", "contains", "(Ljava/lang/CharSequence;)Z")))));
        Rule.SerializationClassNameGuard guard = new Rule.SerializationClassNameGuard(
                new Rule.CallMatcher(Match.of("java/lang/String"), Match.of("contains"),
                        Match.of("(Ljava/lang/CharSequence;)Z")),
                "java.rmi.server");
        Rule.ConditionRule condition = new Rule.ConditionRule("RMI-BLOCK",
                Match.of(owner), guard);
        Blackboard blackboard = blackboard(Map.of(owner, classInfo(owner, List.of(), List.of(resolver))),
                List.of(condition));
        Chain chain = chain(owner, "resolveClass", "deserialize", null);
        blackboard.addChain(chain);

        calibrate(blackboard);

        assertEquals("condition-class-name-guard:RMI-BLOCK:java.rmi.server",
                blackboard.calibrationOf(chain.key()));
    }

    @Test
    void serializationClassNameGuardRetainsWhenTheBlockedLiteralIsNotProven() {
        String owner = "fixture/GuardedOis";
        MethodInfo resolver = method(owner, "resolveClass", List.of(
                new InsnFact(0, Op.LDC, List.of("org.apache.commons.fileupload")),
                new InsnFact(1, Op.INVOKEVIRTUAL, List.of(new MethodRef(
                        "java/lang/String", "contains", "(Ljava/lang/CharSequence;)Z")))));
        Rule.ConditionRule condition = new Rule.ConditionRule("RMI-BLOCK",
                Match.of(owner), new Rule.SerializationClassNameGuard(
                        new Rule.CallMatcher(Match.of("java/lang/String"), Match.of("contains"),
                                Match.of("(Ljava/lang/CharSequence;)Z")),
                        "java.rmi.server"));
        Blackboard blackboard = blackboard(Map.of(owner, classInfo(owner, List.of(), List.of(resolver))),
                List.of(condition));
        Chain chain = chain(owner, "resolveClass", "deserialize", null);
        blackboard.addChain(chain);

        calibrate(blackboard);

        assertNull(blackboard.calibrationOf(chain.key()),
                "a different literal must not deny a static candidate");
    }

    @Test
    void packagePolicyRejectsOnlyKnownSerializableTypeOutsideTrustedPrefixes() {
        String policyOwner = "fixture/PolicyOis";
        MethodInfo resolver = new MethodInfo(policyOwner, "resolveClass",
                "(Ljava/lang/Class;)Ljava/lang/Class;", Modifier.PUBLIC,
                List.of(new InsnFact(0, Op.INVOKESPECIAL,
                        List.of(new MethodRef(policyOwner, "checkSecurity",
                                "(Ljava/lang/Class;)V")))), List.of(), false);
        MethodInfo checker = new MethodInfo(policyOwner, "checkSecurity",
                "(Ljava/lang/Class;)V", Modifier.PRIVATE, List.of(), List.of(), false);
        Rule.ConditionRule condition = new Rule.ConditionRule("PACKAGE",
                Match.of("javax/jms/ObjectMessage"),
                new Rule.SerializationPackagePolicy(
                        new Rule.CallMatcher(Match.of(policyOwner), Match.of("checkSecurity"), null),
                        List.of("java.lang")));
        Map<String, ClassInfo> classes = new HashMap<>();
        classes.put(policyOwner, classInfo(policyOwner, List.of(), List.of(resolver, checker)));
        classes.put("fixture/Blocked", classInfo("fixture/Blocked",
                List.of("java/io/Serializable"), List.of()));
        Blackboard blackboard = blackboard(classes, List.of(condition));
        Chain chain = new Chain("fixture-condition", "CODE_EXEC", "HIGH", "fixture/App", "write",
                "source", "fixture/Blocked", "run", List.of(
                new ChainHop("fixture/App", "write", "javax/jms/ObjectMessage", "getObject",
                        HopKind.DIRECT_CALL, null, null, "()Ljava/lang/Object;", null, null),
                new ChainHop("javax/jms/ObjectMessage", "getObject", "fixture/Blocked", "equals",
                        HopKind.DIRECT_CALL, null, null, "()Z", null, null)), 0,
                "()V", "TERMINAL", null);
        blackboard.addChain(chain);

        calibrate(blackboard);

        assertEquals("condition-package-policy:PACKAGE:fixture/Blocked",
                blackboard.calibrationOf(chain.key()));
    }

    @Test
    void propertyFilterRetainsOtherPropertiesButRejectsExplicitBlockedValue() {
        String registrationOwner = "fixture/PropertyUtilsBean";
        MethodInfo registration = method(registrationOwner, "resetBeanIntrospectors", List.of(
                new InsnFact(0, Op.GETSTATIC, List.of(new FieldRef(
                        "fixture/SuppressPropertiesBeanIntrospector", "SUPPRESS_CLASS", "Lfixture/I;")))));
        Rule.ConditionRule condition = new Rule.ConditionRule("PROPERTY",
                Match.of("fixture/BeanComparator"), new Rule.PropertyFilterDecl(
                        Match.of(registrationOwner), Match.of("resetBeanIntrospectors"),
                        Match.of("fixture/SuppressPropertiesBeanIntrospector"), "property", "class"));
        Map<String, ClassInfo> classes = new HashMap<>();
        classes.put("fixture/BeanComparator", classInfo("fixture/BeanComparator", List.of(), List.of()));
        classes.put(registrationOwner, classInfo(registrationOwner, List.of(), List.of(registration)));
        Blackboard retained = blackboard(classes, List.of(condition));
        Chain otherProperty = chain("fixture/BeanComparator", "compare", "compare", null);
        retained.addChain(otherProperty);
        calibrate(retained);
        assertNull(retained.calibrationOf(otherProperty.key()));
        assertTrue(retained.chainNotesOf(otherProperty.key()).stream()
                .anyMatch(note -> note.contains("other-properties=RETAINED")));

        Blackboard rejected = blackboard(classes, List.of(condition));
        ObjectGraphPlan plan = new ObjectGraphPlan(
                List.of(new ObjectGraphPlan.Node("entry", "fixture/BeanComparator",
                        ObjectGraphPlan.NodeKind.ALLOCATE, List.of())),
                List.of(new ObjectGraphPlan.FieldAssignment("entry", "property",
                        List.of(new ObjectGraphPlan.Value(ObjectGraphPlan.ValueKind.STRING, "class")))));
        Chain blocked = chain("fixture/BeanComparator", "compare", "compare", plan);
        rejected.addChain(blocked);
        calibrate(rejected);
        assertEquals("condition-property-filter:PROPERTY:property=class",
                rejected.calibrationOf(blocked.key()));
    }

    private static void calibrate(Blackboard blackboard) {
        ComponentConditionKnowledgeSource source = new ComponentConditionKnowledgeSource();
        source.init(blackboard);
        source.onEvent(blackboard, Event.of(EventType.SCAN_COMPLETE, -1, null));
    }

    private static Blackboard blackboard(Map<String, ClassInfo> classes,
                                         List<Rule.ConditionRule> conditions) {
        Graph graph = new Graph();
        for (ClassInfo info : classes.values()) {
            for (MethodInfo method : info.methods()) {
                graph.methodNode(method.owner(), method.name(), method.descriptor(), false);
            }
        }
        return new Blackboard(graph, new ClassHierarchy(classes, null), new FieldWriterIndex(),
                new RuleSet(List.of(), List.of(), List.of(), List.of(), List.of(), conditions), 20,
                Blackboard.ScanInputs.fastDefault(Path.of(".")));
    }

    private static ClassInfo classInfo(String name, List<String> interfaces,
                                       List<MethodInfo> methods) {
        return new ClassInfo(name, "java/lang/Object", interfaces, Modifier.PUBLIC,
                new ArrayList<>(methods), List.of());
    }

    private static MethodInfo method(String owner, String name, List<InsnFact> instructions) {
        return new MethodInfo(owner, name, "()V", Modifier.PUBLIC,
                instructions, List.of(), false);
    }

    private static Chain chain(String entryClass, String entryMethod, String entryKind,
                               ObjectGraphPlan plan) {
        return new Chain("fixture-condition", "CODE_EXEC", "HIGH", entryClass, entryMethod,
                entryKind, "fixture/Terminal", "run", List.of(), 0, "()V", "TERMINAL", plan);
    }
}
