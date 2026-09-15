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

    @Test
    void retainsConditionPolicyDeclarationAndCallSiteInDemandSlice() {
        String appOwner = "app/Ingress";
        String policyOwner = "lib/PolicyOis";
        String messageOwner = "javax/jms/ObjectMessage";
        String terminalOwner = "fixture/Terminal";
        String checkDescriptor = "(Ljava/lang/Class;)V";
        ClassInfo app = new ClassInfo(appOwner, "java/lang/Object", List.of(), Modifier.PUBLIC,
                List.of(method(appOwner, "main", "([Ljava/lang/String;)V", Modifier.PUBLIC
                        | Modifier.STATIC, new InsnFact(0, Op.INVOKEINTERFACE,
                        List.of(new MethodRef(messageOwner, "getObject", "()Ljava/lang/Object;"))))),
                List.of());
        ClassInfo message = cls(messageOwner, List.of(
                method(messageOwner, "getObject", "()Ljava/lang/Object;", Modifier.PUBLIC)));
        MethodInfo resolver = method(policyOwner, "resolveClass", checkDescriptor,
                Modifier.PUBLIC, new InsnFact(0, Op.INVOKESPECIAL,
                        List.of(new MethodRef(policyOwner, "checkSecurity", checkDescriptor))));
        MethodInfo checker = method(policyOwner, "checkSecurity", checkDescriptor,
                Modifier.PRIVATE, new InsnFact(0, Op.INVOKESTATIC,
                        List.of(new MethodRef(terminalOwner, "touch", "()V"))));
        ClassInfo policy = new ClassInfo(policyOwner, "java/lang/Object", List.of(), Modifier.PUBLIC,
                List.of(resolver, checker), List.of());
        ClassInfo terminal = cls(terminalOwner,
                List.of(method(terminalOwner, "touch", "()V", Modifier.PUBLIC)));
        Map<String, ClassInfo> classes = new LinkedHashMap<>();
        for (ClassInfo info : List.of(app, message, policy, terminal)) {
            classes.put(info.internalName(), info);
        }
        Rule.SinkRule sink = new Rule.SinkRule("terminal-touch", "CODE_EXEC", "HIGH",
                new Rule.CallMatcher(Match.of(terminalOwner), Match.of("touch"), null),
                List.of(Rule.TaintedPos.Receiver.INSTANCE), Rule.SinkRole.TERMINAL);
        Rule.ConditionRule policyCondition = new Rule.ConditionRule("PACKAGE",
                Match.of(messageOwner), new Rule.SerializationPackagePolicy(
                        new Rule.CallMatcher(Match.of(policyOwner), Match.of("checkSecurity"), null),
                        List.of("java.lang")));

        DemandDrivenProgramSlice.Result result = DemandDrivenProgramSlice.select(
                new LoadResult(classes, List.of(), classes.size(), 61), Set.of(appOwner),
                new RuleSet(List.of(sink), List.of(), List.of(), List.of(), List.of(),
                        List.of(policyCondition)));

        List<MethodInfo> retained = result.load().classes().get(policyOwner).methods();
        assertTrue(retained.stream().anyMatch(method -> method.name().equals("resolveClass")),
                "the caller that wires the policy check must survive method pruning");
        assertTrue(retained.stream().anyMatch(method -> method.name().equals("checkSecurity")),
                "the declared policy method must survive method pruning");
    }

    @Test
    void selectsConcreteJdbcImplementationsAndTheirBoundedDispatchClosure() {
        String appOwner = "app/ConnectionServlet";
        String connectDescriptor =
                "(Ljava/lang/String;Ljava/util/Properties;)Ljava/sql/Connection;";
        ClassInfo app = new ClassInfo(appOwner, "javax/servlet/http/HttpServlet", List.of(),
                Modifier.PUBLIC, List.of(method(appOwner, "doGet", "()V", Modifier.PUBLIC,
                        new InsnFact(0, Op.INVOKEVIRTUAL, List.of(new MethodRef(
                                "java/net/URLClassLoader", "loadClass",
                                "(Ljava/lang/String;)Ljava/lang/Class;"))),
                        new InsnFact(1, Op.INVOKEVIRTUAL, List.of(new MethodRef(
                                "java/lang/Class", "newInstance", "()Ljava/lang/Object;"))),
                        new InsnFact(2, Op.INVOKEINTERFACE, List.of(new MethodRef(
                                "java/sql/Driver", "connect", connectDescriptor))))),
                List.of());
        ClassInfo driver = new ClassInfo("vendor/Driver", "java/lang/Object",
                List.of("java/sql/Driver"), Modifier.PUBLIC,
                List.of(method("vendor/Driver", "connect", connectDescriptor, Modifier.PUBLIC,
                        new InsnFact(0, Op.INVOKEVIRTUAL, List.of(new MethodRef(
                                "vendor/ConnectionFactory", "open", "()V"))))), List.of());
        ClassInfo abstractFactory = new ClassInfo("vendor/ConnectionFactory", "java/lang/Object",
                List.of(), Modifier.PUBLIC | Modifier.ABSTRACT,
                List.of(method("vendor/ConnectionFactory", "open", "()V",
                        Modifier.PUBLIC | Modifier.ABSTRACT)), List.of());
        ClassInfo concreteFactory = new ClassInfo("vendor/impl/ConnectionFactoryImpl",
                "vendor/ConnectionFactory", List.of(), Modifier.PUBLIC,
                List.of(method("vendor/impl/ConnectionFactoryImpl", "open", "()V",
                        Modifier.PUBLIC, new InsnFact(0, Op.INVOKESTATIC, List.of(new MethodRef(
                                "vendor/SocketFactoryFactory", "getSocketFactory", "()V"))))),
                List.of());
        ClassInfo socketFactory = new ClassInfo("vendor/SocketFactoryFactory", "java/lang/Object",
                List.of(), Modifier.PUBLIC,
                List.of(method("vendor/SocketFactoryFactory", "getSocketFactory", "()V",
                        Modifier.PUBLIC, new InsnFact(0, Op.INVOKESTATIC, List.of(new MethodRef(
                                "vendor/ObjectFactory", "instantiate", "()V"))))), List.of());
        ClassInfo objectFactory = new ClassInfo("vendor/ObjectFactory", "java/lang/Object",
                List.of(), Modifier.PUBLIC,
                List.of(method("vendor/ObjectFactory", "instantiate", "()V", Modifier.PUBLIC)),
                List.of());
        ClassInfo notDriver = new ClassInfo("vendor/NotDriver", "java/lang/Object", List.of(),
                Modifier.PUBLIC, List.of(method("vendor/NotDriver", "connect", connectDescriptor,
                        Modifier.PUBLIC)), List.of());
        Map<String, ClassInfo> classes = new LinkedHashMap<>();
        for (ClassInfo info : List.of(app, driver, abstractFactory, concreteFactory,
                socketFactory, objectFactory, notDriver)) {
            classes.put(info.internalName(), info);
        }

        DemandDrivenProgramSlice.Result result = DemandDrivenProgramSlice.select(
                new LoadResult(classes, List.of(), classes.size(), 61), Set.of(appOwner),
                RuleSet.EMPTY);

        assertTrue(result.applied());
        assertTrue(result.load().classes().keySet().containsAll(Set.of(
                driver.internalName(), abstractFactory.internalName(),
                concreteFactory.internalName(), socketFactory.internalName(),
                objectFactory.internalName())),
                "a dynamic Driver boundary must retain its concrete driver and bounded helper path");
        assertFalse(result.load().classes().containsKey(notDriver.internalName()),
                "a same-signature class without java.sql.Driver identity is not a driver candidate");
    }

    @Test
    void connectOnlyDoesNotPromoteEveryLoadedJdbcDriver() {
        String appOwner = "app/ConnectOnlyServlet";
        String connectDescriptor =
                "(Ljava/lang/String;Ljava/util/Properties;)Ljava/sql/Connection;";
        ClassInfo app = new ClassInfo(appOwner, "javax/servlet/http/HttpServlet", List.of(),
                Modifier.PUBLIC, List.of(method(appOwner, "doGet", "()V", Modifier.PUBLIC,
                        new InsnFact(0, Op.INVOKEINTERFACE, List.of(new MethodRef(
                                "java/sql/Driver", "connect", connectDescriptor))))),
                List.of());
        ClassInfo driver = new ClassInfo("vendor/Driver", "java/lang/Object",
                List.of("java/sql/Driver"), Modifier.PUBLIC,
                List.of(method("vendor/Driver", "connect", connectDescriptor, Modifier.PUBLIC)),
                List.of());
        Map<String, ClassInfo> classes = new LinkedHashMap<>();
        classes.put(app.internalName(), app);
        classes.put(driver.internalName(), driver);

        DemandDrivenProgramSlice.Result result = DemandDrivenProgramSlice.select(
                new LoadResult(classes, List.of(), classes.size(), 61), Set.of(appOwner),
                RuleSet.EMPTY);

        assertTrue(result.applied());
        assertFalse(result.load().classes().containsKey(driver.internalName()),
                "Driver.connect alone is an intermediate boundary, not a dynamic driver proof");
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
