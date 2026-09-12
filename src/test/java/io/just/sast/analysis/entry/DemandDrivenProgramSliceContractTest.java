package io.just.sast.analysis.entry;

import io.just.sast.config.Match;
import io.just.sast.config.Rule;
import io.just.sast.config.RuleSet;
import io.just.sast.model.ClassInfo;
import io.just.sast.model.InsnFact;
import io.just.sast.model.LoadResult;
import io.just.sast.model.MethodInfo;
import io.just.sast.model.MethodRef;
import io.just.sast.model.Op;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.lang.reflect.Modifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Protection for the generic application-anchored graph-facing dependency slice. */
class DemandDrivenProgramSliceContractTest {

    @Test
    void retainsApplicationReferencesAndRuleAnchorsButDropsUnrelatedDependencyNoise() {
        ClassInfo app = cls("app/Ingress", List.of(
                method("handle", "()V", new InsnFact(0, Op.INVOKESTATIC,
                        List.of(new MethodRef("lib/Helper", "decode", "()V"))))));
        ClassInfo helper = cls("lib/Helper", List.of(
                method("decode", "()V", new InsnFact(0, Op.INVOKEVIRTUAL,
                        List.of(new MethodRef("lib/Gadget", "readObject", "()V"))))));
        ClassInfo gadget = cls("lib/Gadget", List.of(
                method("readObject", "()V", new InsnFact(0, Op.INVOKEVIRTUAL,
                        List.of(new MethodRef("java/lang/Runtime", "exec", "(Ljava/lang/String;)Ljava/lang/Process;"))))));
        ClassInfo unrelated = cls("lib/Noise", List.of(method("noise", "()V")));
        Map<String, ClassInfo> classes = new LinkedHashMap<>();
        classes.put(app.internalName(), app);
        classes.put(helper.internalName(), helper);
        classes.put(gadget.internalName(), gadget);
        classes.put(unrelated.internalName(), unrelated);

        Rule.SinkRule sink = new Rule.SinkRule("runtime-exec", "COMMAND", "HIGH",
                new Rule.CallMatcher(Match.of("java/lang/Runtime"), Match.of("exec"), null),
                List.of(new Rule.TaintedPos.Arg(0)), Rule.SinkRole.TERMINAL);
        Rule.MagicEntryRule callback = new Rule.MagicEntryRule("read-object", "readObject",
                new Rule.MethodMatcher(Match.of("readObject"), Match.of("()V"), false),
                null, "deserialize");

        DemandDrivenProgramSlice.Result result = DemandDrivenProgramSlice.select(
                new LoadResult(classes, List.of(), classes.size(), 61),
                Set.of(app.internalName()),
                new RuleSet(List.of(sink), List.of(callback), List.of(), List.of(), List.of()));

        assertTrue(result.applied());
        assertEquals(Set.of("app/Ingress", "lib/Helper", "lib/Gadget"),
                result.load().classes().keySet());
        assertFalse(result.load().classes().containsKey("lib/Noise"));
        assertTrue(result.load().completenessReasons().contains(
                "DEPENDENCY_DEMAND_SLICE_APPLIED"));
        assertEquals(3, result.selectedClasses());
        assertEquals(2, result.selectedDependencies());
    }

    @Test
    void unknownApplicationScopeNeverSilentlySlicesAwayFacts() {
        ClassInfo app = cls("app/Ingress", List.of(method("handle", "()V")));
        ClassInfo dep = cls("lib/Dependency", List.of(method("run", "()V")));
        LoadResult input = new LoadResult(Map.of(app.internalName(), app,
                dep.internalName(), dep), List.of(), 2, 61);

        DemandDrivenProgramSlice.Result result = DemandDrivenProgramSlice.select(input,
                Set.of(), RuleSet.EMPTY);

        assertFalse(result.applied());
        assertEquals(input.classes(), result.load().classes());
        assertEquals(input.completenessReasons(), result.load().completenessReasons());
    }

    @Test
    void doesNotPromoteUnanchoredDeserializeCallbackToAProgramRoot() {
        ClassInfo app = cls("app/Plain", List.of(method("helper", "()V")));
        ClassInfo gadget = cls("lib/StandaloneGadget", List.of(
                method("readObject", "()V", new InsnFact(0, Op.INVOKEVIRTUAL,
                        List.of(new MethodRef("java/lang/Runtime", "exec",
                                "(Ljava/lang/String;)Ljava/lang/Process;"))))));
        Map<String, ClassInfo> classes = new LinkedHashMap<>();
        classes.put(app.internalName(), app);
        classes.put(gadget.internalName(), gadget);

        Rule.SinkRule sink = new Rule.SinkRule("runtime-exec", "COMMAND", "HIGH",
                new Rule.CallMatcher(Match.of("java/lang/Runtime"), Match.of("exec"), null),
                List.of(new Rule.TaintedPos.Arg(0)), Rule.SinkRole.TERMINAL);
        Rule.MagicEntryRule callback = new Rule.MagicEntryRule("read-object", "readObject",
                new Rule.MethodMatcher(Match.of("readObject"), Match.of("()V"), false),
                null, "deserialize");

        DemandDrivenProgramSlice.Result result = DemandDrivenProgramSlice.select(
                new LoadResult(classes, List.of(), classes.size(), 61),
                Set.of(app.internalName()),
                new RuleSet(List.of(sink), List.of(callback), List.of(), List.of(), List.of()));

        assertEquals(Set.of(app.internalName()), result.load().classes().keySet(),
                "a dependency callback without an application boundary must remain kernel-only");
        assertTrue(result.selectedDependencies() == 0,
                "unanchored callback roots must not consume dependency slice budget");
    }

    @Test
    void retainsCompleteSemanticFragmentAnchorsOnlyAfterApplicationBoundary() {
        String entryOwner = "javax/swing/event/EventListenerList";
        String sinkOwner = "com/sun/org/apache/xalan/internal/xsltc/trax/TemplatesImpl";
        List<String> fragmentOwners = List.of(
                entryOwner,
                "javax/swing/undo/UndoManager",
                "java/util/Vector",
                "com/fasterxml/jackson/databind/node/POJONode",
                "org/springframework/aop/framework/JdkDynamicAopProxy",
                "javax/xml/transform/Templates",
                sinkOwner);
        Map<String, ClassInfo> classes = new LinkedHashMap<>();
        ClassInfo app = new ClassInfo("app/Servlet", "javax/servlet/http/HttpServlet", List.of(),
                Modifier.PUBLIC, List.of(method("app/Servlet", "doGet",
                        "(Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;)V",
                        Modifier.PROTECTED)), List.of());
        classes.put(app.internalName(), app);
        for (String owner : fragmentOwners) {
            classes.put(owner, new ClassInfo(owner, "java/lang/Object", List.of(),
                    Modifier.PUBLIC, List.of(method(owner, "toString", "()Ljava/lang/String;",
                            Modifier.PUBLIC)),
                    List.of()));
        }
        Rule.SinkRule sink = new Rule.SinkRule("templates", "CODE_EXEC", "HIGH",
                new Rule.CallMatcher(Match.of(sinkOwner), Match.of("newTransformer"), null),
                List.of(), Rule.SinkRole.TERMINAL);
        Rule.FragmentRule fragment = new Rule.FragmentRule("event-listener-fragment", entryOwner,
                "toString", List.of(
                        new Rule.HopSpec("javax/swing/undo/UndoManager", "toString", null),
                        new Rule.HopSpec("java/util/Vector", "toString", null),
                        new Rule.HopSpec("com/fasterxml/jackson/databind/node/POJONode", "toString", null),
                        new Rule.HopSpec("org/springframework/aop/framework/JdkDynamicAopProxy", "invoke", null),
                        new Rule.HopSpec("javax/xml/transform/Templates", "getOutputProperties", null)),
                sinkOwner, "newTransformer");

        DemandDrivenProgramSlice.Result result = DemandDrivenProgramSlice.select(
                new LoadResult(classes, List.of(), classes.size(), 61),
                Set.of(app.internalName()),
                new RuleSet(List.of(sink), List.of(), List.of(), List.of(), List.of(fragment)));

        assertTrue(result.load().classes().keySet().containsAll(fragmentOwners),
                "a complete fragment is a semantic suffix and must survive pre-CPG slicing");
        assertEquals(fragmentOwners.size(), result.selectedDependencies(),
                "only complete fragment anchors should be admitted as dependency facts");
    }

    @Test
    void retainsConcreteSecondaryDeserializerHostsBehindConversionDispatch() {
        String sourceOwner = "lib/ObjectUtil";
        String sourceDescriptor = "([B[Ljava/lang/Class;)Ljava/lang/Object;";
        ClassInfo app = cls("app/Ingress", List.of(method("handle", "()V",
                new InsnFact(0, Op.INVOKEVIRTUAL, List.of(new MethodRef(
                        "java/io/ObjectInputStream", "readObject", "()Ljava/lang/Object;"))))));
        ClassInfo converter = cls("lib/BeanConverter", List.of(method("lib/BeanConverter", "convert", "(Ljava/lang/Object;)Ljava/lang/Object;", 0,
                new InsnFact(0, Op.INVOKESTATIC, List.of(new MethodRef(
                        sourceOwner, "deserialize", sourceDescriptor))))));
        ClassInfo source = cls(sourceOwner, List.of(method("deserialize", sourceDescriptor)));
        Map<String, ClassInfo> classes = new LinkedHashMap<>();
        classes.put(app.internalName(), app);
        classes.put(converter.internalName(), converter);
        classes.put(source.internalName(), source);

        Rule.SourceRule secondary = new Rule.SourceRule("objectutil-source", "deserialize",
                new Rule.CallMatcher(Match.of(sourceOwner), Match.of("deserialize"),
                        Match.of(sourceDescriptor)), null,
                List.of(new Rule.TaintedPos.Arg(0)));
        DemandDrivenProgramSlice.Result result = DemandDrivenProgramSlice.select(
                new LoadResult(classes, List.of(), classes.size(), 61),
                Set.of(app.internalName()),
                new RuleSet(List.of(), List.of(), List.of(secondary), List.of(), List.of()));

        assertTrue(result.applied());
        assertTrue(result.load().classes().containsKey(converter.internalName()),
                "a concrete method containing a secondary-deserialization source must be retained");
        assertTrue(result.load().classes().get(converter.internalName()).methods().stream()
                        .anyMatch(method -> method.name().equals("convert")),
                "the source-host method, not only its constructor, must survive method pruning");
    }

    private static ClassInfo cls(String name, List<MethodInfo> methods) {
        return new ClassInfo(name, "java/lang/Object", List.of(), 0, methods, List.of());
    }

    private static MethodInfo method(String name, String descriptor, InsnFact... instructions) {
        return new MethodInfo("unused", name, descriptor, 0, List.of(instructions), List.of(), false);
    }

    private static MethodInfo method(String owner, String name, String descriptor, int access,
                                     InsnFact... instructions) {
        return new MethodInfo(owner, name, descriptor, access, List.of(instructions), List.of(), false);
    }
}
