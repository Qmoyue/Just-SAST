package io.just.sast.analysis.entry;

import io.just.sast.config.Match;
import io.just.sast.config.Rule;
import io.just.sast.config.RuleEngine;
import io.just.sast.config.RuleSet;
import io.just.sast.analysis.taint.OriginSupport;
import io.just.sast.cpg.build.CpgIndex;
import io.just.sast.cpg.graph.EdgeType;
import io.just.sast.cpg.graph.Graph;
import io.just.sast.cpg.graph.Node;
import io.just.sast.analysis.hierarchy.ClassHierarchy;
import io.just.sast.model.ClassInfo;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.lang.reflect.Modifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Contract coverage for the P3.1 entry/site/terminal index and its fail-closed scope gate. */
class ApplicationEntryIndexContractTest {

    private static final String APP = "fixture/app/Ingress";
    private static final String GADGET = "fixture/lib/Gadget";
    private static final String RUNTIME = "java/lang/Runtime";
    private static final String SINK_DESC = "(Ljava/lang/String;)Ljava/lang/Process;";
    private static final String APP_METHOD = APP + "#handle()V";
    private static final String GADGET_METHOD = GADGET + "#trigger()V";

    @Test
    void applicationScopeJoinsEntryForwardAndTerminalReverseSlices() {
        Graph graph = fixture();
        RuleSet rules = rules();
        RuleEngine engine = new RuleEngine(rules, new ClassHierarchy(Map.of(), null));

        ApplicationEntryIndex index = ApplicationEntryIndex.build(graph, engine,
                Set.of(APP), true);

        assertTrue(index.applicationScopeKnown());
        assertEquals(2, index.applicationEntries().size(),
                "magic entry and unconditional OIS source are distinct evidence roots");
        assertEquals(1, index.deserializeSites().size());
        assertTrue(index.hasDeserializeRoot(),
                "the entry index must own the typed deserialize-root fact");
        assertTrue(index.deserializeSites().get(0).applicationOwned());
        assertEquals(index.deserializeSites(), index.applicationInputSites());
        assertEquals(index.deserializeSites(), index.typedBindingSites());
        assertEquals(index.applicationInputSites(),
                index.applicationInputSitesForMember(APP, "handle"));
        assertTrue(index.applicationInputSitesForMember(APP, "missing").isEmpty());
        assertThrows(UnsupportedOperationException.class,
                () -> index.applicationInputSitesForMember(APP, "handle").clear());
        assertThrows(UnsupportedOperationException.class,
                () -> index.applicationInputSites().clear());
        assertThrows(UnsupportedOperationException.class,
                () -> index.typedBindingSites().add(index.deserializeSites().get(0)));
        assertEquals(1, index.terminalImpacts().size());
        assertEquals(index.terminalImpacts(), index.terminalDemandImpacts(),
                "the index-owned demand projection must retain only terminal impacts that can "
                        + "participate in the entry-forward/terminal-reverse join");
        assertThrows(UnsupportedOperationException.class,
                () -> index.terminalDemandImpacts().clear());
        assertTrue(index.entryForwardSlice().contains(APP_METHOD));
        assertTrue(index.entryForwardSlice().contains(GADGET_METHOD));
        assertTrue(index.sinkReverseSlice().contains(APP_METHOD));
        assertTrue(index.sinkReverseSlice().contains(GADGET_METHOD));
        assertTrue(index.entryTerminalIntersection().contains(APP_METHOD));
        assertTrue(index.entryTerminalIntersection().contains(GADGET_METHOD));
        assertTrue(index.isEntryForwardReachable(APP_METHOD));
        assertTrue(index.isSinkReverseReachable(GADGET_METHOD));
        assertTrue(index.isEntryTerminalDemand(APP_METHOD));
        assertFalse(index.isEntryTerminalDemand("fixture/other/Root#run()V"));
        assertTrue(index.dependencyCandidates().contains(GADGET_METHOD),
                "dependency suffix is retained only after entry/terminal intersection");
        assertTrue(index.allowsDependencyExpansion());
        assertTrue(index.semanticDigest().matches("[0-9a-f]{64}"));

        ApplicationEntryIndex second = ApplicationEntryIndex.build(fixture(), engine,
                Set.of(APP), true);
        assertEquals(index.semanticDigest(), second.semanticDigest(),
                "index identity must not depend on graph traversal insertion order");
    }

    @Test
    void exposesStableImmutableHotReadSetsWithoutRebuildingSlices() {
        ApplicationEntryIndex index = ApplicationEntryIndex.build(fixture(),
                new RuleEngine(rules(), new ClassHierarchy(Map.of(), null)),
                Set.of(APP), true);

        assertEquals(Set.copyOf(index.entryForwardSlice()), index.entryForwardMethodKeys());
        assertEquals(Set.copyOf(index.sinkReverseSlice()), index.sinkReverseMethodKeys());
        assertTrue(index.applicationEntryMethods(APP, "handle").contains(APP_METHOD));
        assertThrows(UnsupportedOperationException.class,
                () -> index.applicationEntryMethods(APP, "handle").add(APP_METHOD));
        assertThrows(UnsupportedOperationException.class,
                () -> index.entryForwardMethodKeys().add("fixture/other/Root#run()V"));
        assertThrows(UnsupportedOperationException.class,
                () -> index.sinkReverseMethodKeys().clear());
    }

    @Test
    void indexesTypedDeserializeHostsForCompositionWithoutRescanningGraph() {
        ApplicationEntryIndex index = ApplicationEntryIndex.build(fixture(),
                new RuleEngine(rules(), new ClassHierarchy(Map.of(), null)),
                Set.of(APP), true);

        assertEquals(1, index.deserializeHosts().size());
        ApplicationEntryIndex.DeserializeHost host = index.deserializeHosts().get(0);
        assertEquals(APP_METHOD, host.hostMethodKey());
        assertEquals(APP, host.hostOwner());
        assertEquals("handle", host.hostName());
        assertEquals("()V", host.hostDescriptor());
        assertEquals("java/io/ObjectInputStream", host.frameOwner());
        assertEquals("readObject", host.frameMethod());
        assertEquals("()Ljava/lang/Object;", host.frameDescriptor());
        assertThrows(UnsupportedOperationException.class,
                () -> index.deserializeHosts().clear());
    }

    @Test
    void indexesMechanismEntriesByOwnerForObjectGraphLookup() {
        Graph graph = new Graph();
        graph.methodNode(GADGET, "readObject", "()V", false);
        Rule.MagicEntryRule callback = new Rule.MagicEntryRule("gadget-read-object",
                "readObject", new Rule.MethodMatcher(Match.of("readObject"),
                Match.of("()V"), false), null, "deserialize");
        RuleSet callbackRules = new RuleSet(List.of(), List.of(callback), List.of(),
                List.of(), List.of());

        ApplicationEntryIndex index = ApplicationEntryIndex.build(graph,
                new RuleEngine(callbackRules, new ClassHierarchy(Map.of(), null)),
                Set.of(APP), true);

        List<ApplicationEntryIndex.ExecutionEntry> entries =
                index.mechanismEntriesForOwner(GADGET);
        assertEquals(1, entries.size());
        assertEquals(GADGET_METHOD.replace("trigger()V", "readObject()V"),
                entries.get(0).methodKey());
        assertEquals("readObject", entries.get(0).entryKind());
        assertFalse(entries.get(0).applicationOwned(),
                "dependency callbacks remain lookup facts, not application roots");
        assertTrue(index.mechanismEntriesForOwner("fixture/missing/Nope").isEmpty());
        assertThrows(UnsupportedOperationException.class, entries::clear);
    }

    @Test
    void unknownApplicationScopeCannotCreateDefaultRoots() {
        Graph graph = fixture();
        RuleEngine engine = new RuleEngine(rules(), new ClassHierarchy(Map.of(), null));

        ApplicationEntryIndex index = ApplicationEntryIndex.build(graph, engine, Set.of(), false);

        assertTrue(index.deserializeSites().stream().noneMatch(
                ApplicationEntryIndex.DeserializeSite::applicationOwned));
        assertTrue(index.applicationInputSites().isEmpty());
        assertTrue(index.typedBindingSites().isEmpty());
        assertTrue(index.applicationInputSitesForMember(APP, "handle").isEmpty());
        assertTrue(index.applicationEntries().isEmpty());
        assertTrue(index.hasDeserializeRoot(),
                "the raw deserialize boundary remains observable even when application scope is unknown");
        assertTrue(index.entryForwardSlice().isEmpty());
        assertFalse(index.allowsDependencyExpansion());
        assertTrue(index.completenessReasons().contains("APPLICATION_SCOPE_UNKNOWN"));
        assertTrue(index.completenessReasons().contains("NO_APPLICATION_ENTRY"));
    }

    @Test
    void publicDeserializeHelperDoesNotBecomeExternalApplicationEntry() {
        String controllerOwner = "fixture/app/Controller";
        String helperOwner = "fixture/app/ImportService";
        String controllerKey = controllerOwner + "#import(Ljava/lang/String;)V";
        String helperKey = helperOwner + "#decode(Ljava/lang/String;)V";
        Graph graph = new Graph();
        Node controller = graph.methodNode(controllerOwner, "import",
                "(Ljava/lang/String;)V", false);
        controller.propsNote("methodAccess", Modifier.PUBLIC);
        controller.propsNote("classAnnotationDescriptors", List.of(
                "Lorg/springframework/web/bind/annotation/RestController;"));
        controller.propsNote("methodAnnotationDescriptors", List.of(
                "Lorg/springframework/web/bind/annotation/PostMapping;"));
        Node helper = graph.methodNode(helperOwner, "decode", "(Ljava/lang/String;)V", false);
        helper.propsNote("methodAccess", Modifier.PUBLIC);
        Node ois = graph.methodNode("java/io/ObjectInputStream", "readObject",
                "()Ljava/lang/Object;", true);
        Node helperCall = graph.addCallNode(helperOwner, "decode", "(Ljava/lang/String;)V",
                "VIRTUAL", null, 0, controllerOwner, "import", "(Ljava/lang/String;)V");
        Node read = graph.addCallNode("java/io/ObjectInputStream", "readObject",
                "()Ljava/lang/Object;", "VIRTUAL", null, 0, helperOwner, "decode",
                "(Ljava/lang/String;)V");
        graph.addEdge(helperCall, helper, EdgeType.INVOKES, "VIRTUAL");
        graph.addEdge(read, ois, EdgeType.INVOKES, "VIRTUAL");
        graph.freeze();

        ApplicationEntryIndex index = ApplicationEntryIndex.build(graph,
                new RuleEngine(rules(), new ClassHierarchy(Map.of(), null)),
                Set.of(controllerOwner, helperOwner), true);

        assertTrue(index.isExternalEntryMethod(controllerKey));
        assertFalse(index.isExternalEntryMethod(helperKey),
                "Java public visibility and an OIS call do not prove an external boundary");
        assertTrue(index.applicationEntryMethods().contains(controllerKey));
        assertFalse(index.applicationEntryMethods().contains(helperKey));
        assertTrue(index.entryForwardSlice().contains(helperKey),
                "the helper remains reachable through the real controller prefix");
        assertTrue(index.deserializeSites().stream().anyMatch(site ->
                helperKey.equals(site.hostMethodKey()) && site.applicationOwned()
                        && site.externalInput()));
    }

    @Test
    void bindingSiteIsRetainedWhenTheSameControllerMethodReadsTheObject() {
        String controller = "fixture/app/Controller";
        String methodKey = controller + "#accept(Ljava/lang/String;)V";
        Graph graph = new Graph();
        Node endpoint = graph.methodNode(controller, "accept", "(Ljava/lang/String;)V", false);
        endpoint.propsNote("methodAccess", Modifier.PUBLIC);
        endpoint.propsNote("classAnnotationDescriptors", List.of(
                "Lorg/springframework/web/bind/annotation/RestController;"));
        endpoint.propsNote("methodAnnotationDescriptors", List.of(
                "Lorg/springframework/web/bind/annotation/PostMapping;"));
        Node ois = graph.methodNode("java/io/ObjectInputStream", "readObject",
                "()Ljava/lang/Object;", true);
        Node read = graph.addCallNode("java/io/ObjectInputStream", "readObject",
                "()Ljava/lang/Object;", "VIRTUAL", null, 12, controller, "accept",
                "(Ljava/lang/String;)V");
        graph.addEdge(read, ois, EdgeType.INVOKES, "VIRTUAL");
        graph.freeze();

        ApplicationEntryIndex index = ApplicationEntryIndex.build(graph,
                new RuleEngine(rules(), new ClassHierarchy(Map.of(), null)),
                Set.of(controller), true);

        assertEquals(2, index.deserializeSites().size(),
                "a controller method can expose both its framework binding and its Kryo/OIS site");
        assertTrue(index.deserializeSites().stream().anyMatch(site ->
                methodKey.equals(site.hostMethodKey())
                        && "builtin:ois-read".equals(site.ruleId())));
        assertTrue(index.deserializeSites().stream().anyMatch(site ->
                methodKey.equals(site.hostMethodKey())
                        && "builtin:framework-binding".equals(site.ruleId())
                        && site.bridge().equals("framework-binding")));
        assertEquals(2, index.applicationInputSitesForMember(controller, "accept").size());
        assertEquals(1, index.typedBindingSites().stream()
                .filter(site -> methodKey.equals(site.hostMethodKey())
                        && "builtin:framework-binding".equals(site.ruleId())).count());
    }

    @Test
    void knownScopeExcludesDependencyOnlyDeserializeRootFromLegacyClosure() {
        Graph graph = new Graph();
        Node dependencyEntry = graph.methodNode(GADGET, "readObject", "()V", false);
        Node runtime = graph.methodNode("java/lang/Runtime", "exec",
                "(Ljava/lang/String;)Ljava/lang/Process;", true);
        Node exec = graph.addCallNode("java/lang/Runtime", "exec",
                "(Ljava/lang/String;)Ljava/lang/Process;", "VIRTUAL", null, 0,
                GADGET, "readObject", "()V");
        graph.addEdge(exec, runtime, EdgeType.INVOKES, "VIRTUAL");
        graph.freeze();

        Rule.SinkRule sink = rules().sinks().get(0);
        Rule.MagicEntryRule readObject = new Rule.MagicEntryRule("dependency-read-object",
                "readObject", new Rule.MethodMatcher(Match.of("readObject"), Match.of("()V"),
                false), null, "deserialize");
        RuleSet rules = new RuleSet(List.of(sink), List.of(readObject), List.of(), List.of(),
                List.of());
        ClassHierarchy hierarchy = new ClassHierarchy(Map.of(), null);
        OriginSupport support = new OriginSupport(graph, hierarchy,
                new RuleEngine(rules, hierarchy), false, CpgIndex.empty(),
                Set.of(APP), true);

        assertFalse(support.entryDownstream(graph).contains(dependencyEntry.owner() + "#readObject()V"),
                "a dependency callback must not become an application root when scope is known");
    }

    @Test
    void demandAdmissionRejectsReverseReachableNonTerminalHost() {
        Graph graph = fixture();
        RuleEngine engine = new RuleEngine(rules(), new ClassHierarchy(Map.of(), null));
        ApplicationEntryIndex index = ApplicationEntryIndex.build(graph, engine,
                Set.of(APP), true);

        ApplicationEntryIndex.DemandDecision decision = index.demandAdmission(
                APP_METHOD, APP_METHOD, false);

        assertFalse(decision.admitted(), decision.toString());
        assertEquals(ApplicationEntryIndex.DemandStatus.TERMINAL_NOT_INDEXED,
                decision.status(),
                "reverse reachability alone must not turn an application caller into a sink host");
    }

    @Test
    void terminalAdmissionResolvesOnlyIndexedTerminalImpact() {
        Graph graph = fixture();
        RuleEngine engine = new RuleEngine(rules(), new ClassHierarchy(Map.of(), null));
        ApplicationEntryIndex index = ApplicationEntryIndex.build(graph, engine,
                Set.of(APP), true);

        ApplicationEntryIndex.TerminalDecision indexed = index.terminalAdmission(
                RUNTIME, "exec", SINK_DESC);
        assertTrue(indexed.admitted(), indexed.toString());
        assertEquals(GADGET_METHOD, indexed.hostMethodKey());
        assertEquals(ApplicationEntryIndex.TerminalStatus.INDEXED, indexed.status());
        assertEquals(1, index.terminalImpactsFor(RUNTIME, "exec", SINK_DESC).size());
        assertEquals(1, index.terminalImpactsFor(RUNTIME, "exec", "").size());
        assertThrows(UnsupportedOperationException.class,
                () -> index.terminalImpactsFor(RUNTIME, "exec", SINK_DESC).clear());

        ApplicationEntryIndex.TerminalDecision byName = index.terminalAdmission(
                RUNTIME, "exec", "");
        assertTrue(byName.admitted(), byName.toString());
        assertEquals(GADGET_METHOD, byName.hostMethodKey(),
                "descriptor-free terminal lookup must use the deterministic terminal index");

        ApplicationEntryIndex.TerminalDecision missing = index.terminalAdmission(
                APP, "handle", "()V");
        assertFalse(missing.admitted(), missing.toString());
        assertEquals(ApplicationEntryIndex.TerminalStatus.NOT_INDEXED, missing.status());
        assertEquals("TERMINAL_IMPACT_NOT_INDEXED", missing.reasonCode());
        assertTrue(index.terminalImpactsFor(APP, "handle", "()V").isEmpty());
    }

    @Test
    void producerAdmissionRejectsSeparateForwardAndReverseSlicesBeforeMaterialization() {
        Graph graph = new Graph();
        graph.methodNode(APP, "handle", "()V", false);
        Node gadget = graph.methodNode(GADGET, "trigger", "()V", false);
        Node runtime = graph.methodNode(RUNTIME, "exec", SINK_DESC, true);
        Node terminal = graph.addCallNode(RUNTIME, "exec", SINK_DESC, "VIRTUAL", null,
                0, GADGET, "trigger", "()V");
        graph.addEdge(terminal, runtime, EdgeType.INVOKES, "VIRTUAL");
        graph.freeze();

        RuleEngine engine = new RuleEngine(rules(), new ClassHierarchy(Map.of(), null));
        ApplicationEntryIndex index = ApplicationEntryIndex.build(graph, engine,
                Set.of(APP), true);
        ApplicationEntryIndex.ProducerCandidate candidate =
                new ApplicationEntryIndex.ProducerCandidate("runtime-exec", "COMMAND", "CRITICAL",
                        APP, "handle", "()V", "lifecycle", RUNTIME, "exec", SINK_DESC,
                        "TERMINAL", io.just.sast.blackboard.SinkRisk.CONTROLLED_EFFECT, false);

        ApplicationEntryIndex.ProducerAdmissionDecision decision =
                index.producerAdmission(candidate);

        assertEquals(ApplicationEntryIndex.ProducerAdmissionStatus.REJECTED, decision.status());
        assertEquals(ApplicationEntryIndex.CandidateAdmissionStatus.ENTRY_NOT_IN_TERMINAL_DEMAND,
                decision.candidate().status());
        assertTrue(index.entryForwardSlice().contains(APP_METHOD));
        assertTrue(index.sinkReverseSlice().contains(GADGET + "#trigger()V"));
        assertTrue(index.entryTerminalIntersection().isEmpty(),
                "independent slices must not be treated as a demand intersection");
    }

    @Test
    void producerDecisionExposesDeferredMaterializationPolicy() {
        ApplicationEntryIndex index = ApplicationEntryIndex.build(fixture(),
                new RuleEngine(rules(), new ClassHierarchy(Map.of(), null)),
                Set.of(APP), true);
        ApplicationEntryIndex.ProducerCandidate candidate =
                new ApplicationEntryIndex.ProducerCandidate("runtime-exec", "COMMAND", "CRITICAL",
                        GADGET, "trigger", "()V", "readObject", RUNTIME, "exec", SINK_DESC,
                        "TERMINAL", io.just.sast.blackboard.SinkRisk.HIGH_RISK_TERMINAL, false);

        ApplicationEntryIndex.ProducerAdmissionDecision decision =
                index.producerAdmission(candidate);

        assertEquals(ApplicationEntryIndex.ProducerAdmissionStatus.DEPENDENCY_SUFFIX,
                decision.status());
        assertEquals(ApplicationEntryIndex.MaterializationPolicy.DEFERRED_SUFFIX,
                decision.materializationPolicy());
        assertTrue(decision.retainForComposition());
        assertFalse(decision.materializeApplicationChain());
    }

    @Test
    void declaredTemplateFragmentMayCrossAnUnindexedStaticTerminal() {
        ApplicationEntryIndex index = ApplicationEntryIndex.build(fixture(),
                new RuleEngine(rules(), new ClassHierarchy(Map.of(), null)),
                Set.of(APP), true);
        String templateDescriptor = "()Ljavax/xml/transform/Transformer;";
        ApplicationEntryIndex.ProducerCandidate declared =
                new ApplicationEntryIndex.ProducerCandidate("templates-fragment", "CODE_EXEC",
                        "HIGH", "javax/swing/event/EventListenerList", "toString",
                        "()Ljava/lang/String;", "toString",
                        "com/sun/org/apache/xalan/internal/xsltc/trax/TemplatesImpl",
                        "newTransformer", templateDescriptor, "TERMINAL",
                        io.just.sast.blackboard.SinkRisk.HIGH_RISK_TERMINAL, true, false, true);

        ApplicationEntryIndex.ProducerAdmissionDecision decision =
                index.producerAdmission(declared);

        assertEquals(ApplicationEntryIndex.ProducerAdmissionStatus.BRIDGE_CONTINUATION,
                decision.status(), decision.toString());
        assertEquals(ApplicationEntryIndex.CandidateAdmissionStatus.DECLARED_FRAGMENT_CONTINUATION,
                decision.candidate().status());
        assertEquals(ApplicationEntryIndex.MaterializationPolicy.EAGER_BRIDGE,
                decision.materializationPolicy());
        assertEquals(ApplicationEntryIndex.TerminalStatus.NOT_INDEXED, decision.terminal().status());

        ApplicationEntryIndex.ProducerCandidate undeclared =
                new ApplicationEntryIndex.ProducerCandidate("templates-fragment", "CODE_EXEC",
                        "HIGH", "javax/swing/event/EventListenerList", "toString",
                        "()Ljava/lang/String;", "toString",
                        "com/sun/org/apache/xalan/internal/xsltc/trax/TemplatesImpl",
                        "newTransformer", templateDescriptor, "TERMINAL",
                        io.just.sast.blackboard.SinkRisk.HIGH_RISK_TERMINAL, true);
        assertEquals(ApplicationEntryIndex.ProducerAdmissionStatus.REJECTED,
                index.producerAdmission(undeclared).status());
    }

    @Test
    void typedDependencyContinuationMayEndAtIndexedIntermediateCapability() {
        String inputDescriptor = "()Ljava/lang/Object;";
        String signedObject = "java/security/SignedObject";
        String objectInput = "java/io/ObjectInput";
        Graph graph = new Graph();
        graph.methodNode(APP, "handle", "()V", false);
        graph.methodNode(signedObject, "getObject", inputDescriptor, false);
        Node readObject = graph.addCallNode(objectInput, "readObject", inputDescriptor,
                "INTERFACE", null, 0, signedObject, "getObject", inputDescriptor);
        Node inputMethod = graph.methodNode(objectInput, "readObject", inputDescriptor, true);
        graph.addEdge(readObject, inputMethod, EdgeType.INVOKES, "INTERFACE");
        graph.freeze();

        Rule.SinkRule capability = new Rule.SinkRule("object-input-read", "DESERIALIZE", "HIGH",
                new Rule.CallMatcher(Match.of(objectInput), Match.of("readObject"),
                        Match.of(inputDescriptor)), List.of(Rule.TaintedPos.Receiver.INSTANCE),
                Rule.SinkRole.CAPABILITY);
        Rule.MagicEntryRule entry = new Rule.MagicEntryRule("app-handler", "http",
                new Rule.MethodMatcher(Match.of("handle"), Match.of("()V"), false),
                null, "lifecycle");
        RuleSet ruleSet = new RuleSet(List.of(capability), List.of(entry), List.of(), List.of(), List.of());
        ApplicationEntryIndex index = ApplicationEntryIndex.build(graph,
                new RuleEngine(ruleSet, new ClassHierarchy(Map.of(), null)), Set.of(APP), true);

        ApplicationEntryIndex.ProducerCandidate candidate =
                new ApplicationEntryIndex.ProducerCandidate("signed-second", "DESERIALIZE", "HIGH",
                        signedObject, "getObject", inputDescriptor, "secondDeserialization",
                        objectInput, "readObject", inputDescriptor, "CAPABILITY", null, true);
        ApplicationEntryIndex.ProducerAdmissionDecision decision = index.producerAdmission(candidate);

        assertEquals(ApplicationEntryIndex.ProducerAdmissionStatus.BRIDGE_CONTINUATION,
                decision.status(), decision.toString());
        assertEquals(ApplicationEntryIndex.CandidateAdmissionStatus.TERMINAL_IMPACT_IS_INTERMEDIATE,
                decision.candidate().status());
        assertEquals(ApplicationEntryIndex.MaterializationPolicy.EAGER_BRIDGE,
                decision.materializationPolicy());
        assertTrue(decision.retainForComposition());
    }

    @Test
    void producerMaterializationPolicyMatrixKeepsRoutingAxesClosed() {
        ApplicationEntryIndex.ProducerCandidate candidate =
                new ApplicationEntryIndex.ProducerCandidate("rule", "category", "HIGH",
                        APP, "handle", "()V", "http", RUNTIME, "exec", SINK_DESC,
                        "TERMINAL", io.just.sast.blackboard.SinkRisk.CONTROLLED_EFFECT, false);
        ApplicationEntryIndex.TerminalDecision terminal =
                new ApplicationEntryIndex.TerminalDecision(
                        ApplicationEntryIndex.TerminalStatus.NOT_INDEXED, "", "", "", -1, "");
        ApplicationEntryIndex.CandidateAdmissionDecision admission =
                new ApplicationEntryIndex.CandidateAdmissionDecision(
                        ApplicationEntryIndex.CandidateAdmissionStatus.ADMITTED, APP_METHOD,
                        RUNTIME, "exec", SINK_DESC, true, true, false);
        Map<ApplicationEntryIndex.ProducerAdmissionStatus,
                ApplicationEntryIndex.MaterializationPolicy> expected = Map.of(
                ApplicationEntryIndex.ProducerAdmissionStatus.APPLICATION_CHAIN,
                ApplicationEntryIndex.MaterializationPolicy.EAGER_APPLICATION,
                ApplicationEntryIndex.ProducerAdmissionStatus.BRIDGE_CONTINUATION,
                ApplicationEntryIndex.MaterializationPolicy.EAGER_BRIDGE,
                ApplicationEntryIndex.ProducerAdmissionStatus.DEPENDENCY_SUFFIX,
                ApplicationEntryIndex.MaterializationPolicy.DEFERRED_SUFFIX,
                ApplicationEntryIndex.ProducerAdmissionStatus.KERNEL_ONLY,
                ApplicationEntryIndex.MaterializationPolicy.EAGER_KERNEL,
                ApplicationEntryIndex.ProducerAdmissionStatus.REJECTED,
                ApplicationEntryIndex.MaterializationPolicy.REJECTED);

        for (ApplicationEntryIndex.ProducerAdmissionStatus status
                : ApplicationEntryIndex.ProducerAdmissionStatus.values()) {
            ApplicationEntryIndex.ProducerAdmissionDecision decision =
                    new ApplicationEntryIndex.ProducerAdmissionDecision(status, admission,
                            terminal, status == ApplicationEntryIndex.ProducerAdmissionStatus
                                    .BRIDGE_CONTINUATION);
            ApplicationEntryIndex.MaterializationPolicy policy = expected.get(status);
            assertEquals(policy, decision.materializationPolicy(), status.name());
            assertEquals(status == ApplicationEntryIndex.ProducerAdmissionStatus.APPLICATION_CHAIN,
                    decision.materializeApplicationChain(), status.name());
            assertEquals(status == ApplicationEntryIndex.ProducerAdmissionStatus.BRIDGE_CONTINUATION
                            || status == ApplicationEntryIndex.ProducerAdmissionStatus.DEPENDENCY_SUFFIX,
                    decision.retainForComposition(), status.name());
            assertEquals(policy == ApplicationEntryIndex.MaterializationPolicy.EAGER_APPLICATION
                            || policy == ApplicationEntryIndex.MaterializationPolicy.EAGER_BRIDGE
                            || policy == ApplicationEntryIndex.MaterializationPolicy.EAGER_KERNEL,
                    policy.materializesImmediately(), status.name());
            assertEquals(policy == ApplicationEntryIndex.MaterializationPolicy.EAGER_BRIDGE
                            || policy == ApplicationEntryIndex.MaterializationPolicy.DEFERRED_SUFFIX,
                    policy.retainsForComposition(), status.name());
        }
    }

    @Test
    void frameworkAnnotationAndBindingFactsCreateApplicationBoundary() {
        Graph graph = new Graph();
        Node method = graph.methodNode("fixture/app/Controller", "accept",
                "(Ljava/lang/String;)V", false);
        method.propsNote("methodAccess", Modifier.PUBLIC);
        method.propsNote("classAnnotationDescriptors", List.of(
                "Lorg/springframework/web/bind/annotation/RestController;"));
        method.propsNote("methodAnnotationDescriptors", List.of(
                "Lorg/springframework/web/bind/annotation/PostMapping;"));
        graph.freeze();

        RuleEngine engine = new RuleEngine(rules(), new ClassHierarchy(Map.of(), null));
        ApplicationEntryIndex index = ApplicationEntryIndex.build(graph, engine,
                Set.of("fixture/app/Controller"), true);

        assertTrue(index.applicationEntries().stream().anyMatch(entry ->
                entry.methodKey().equals("fixture/app/Controller#accept(Ljava/lang/String;)V")
                        && entry.entryKind().equals("framework-http")));
        assertEquals(1, index.deserializeSites().size());
        assertEquals("framework-binding", index.deserializeSites().get(0).bridge());
        assertTrue(index.deserializeSites().get(0).externalInput());
        assertEquals(index.deserializeSites(), index.applicationInputSites());
        assertEquals(index.deserializeSites(), index.typedBindingSites());
    }

    @Test
    void indexesTypedBindingSitesByExactTargetOwner() {
        Graph graph = new Graph();
        Node method = graph.methodNode("fixture/app/Controller", "accept",
                "(Lfixture/app/Model;)V", false);
        method.propsNote("methodAccess", Modifier.PUBLIC);
        method.propsNote("classAnnotationDescriptors", List.of(
                "Lorg/springframework/web/bind/annotation/RestController;"));
        method.propsNote("methodAnnotationDescriptors", List.of(
                "Lorg/springframework/web/bind/annotation/PostMapping;"));
        graph.freeze();

        ApplicationEntryIndex index = ApplicationEntryIndex.build(graph,
                new RuleEngine(rules(), new ClassHierarchy(Map.of(), null)),
                Set.of("fixture/app/Controller", "fixture/app/Model"), true);

        assertEquals(1, index.typedBindingSitesForTarget("fixture/app/Model").size());
        assertEquals(index.typedBindingSites(),
                index.typedBindingSitesForTarget("fixture/app/Model"));
        assertTrue(index.typedBindingSitesForTarget("fixture/app/Unknown").isEmpty());
        assertThrows(UnsupportedOperationException.class,
                () -> index.typedBindingSitesForTarget("fixture/app/Model").clear());
    }

    @Test
    void acceptedAutoTypePrefixDoesNotJoinApplicationClassOutsidePrefix() {
        String controller = "fixture/app/Controller";
        String declared = "fixture/app/Note";
        String unrelated = "fixture/other/Metric";
        String endpointDescriptor = "(Lfixture/app/Note;)V";
        Graph graph = new Graph();
        Node endpoint = graph.methodNode(controller, "put", endpointDescriptor, false);
        endpoint.propsNote("methodAccess", Modifier.PUBLIC);
        endpoint.propsNote("classAnnotationDescriptors", List.of(
                "Lorg/springframework/web/bind/annotation/RestController;"));
        endpoint.propsNote("methodAnnotationDescriptors", List.of(
                "Lorg/springframework/web/bind/annotation/PutMapping;"));
        Node config = graph.methodNode(controller, "configure", "()V", false);
        config.propsNote("methodAccess", Modifier.PUBLIC);
        Node accept = graph.addCallNode("com/alibaba/fastjson/parser/ParserConfig",
                "addAccept", "(Ljava/lang/String;)V", "VIRTUAL", null, 0,
                controller, "configure", "()V");
        accept.propsNote("stringLiteralHints", List.of("fixture.app."));
        Node parserConfig = graph.methodNode("com/alibaba/fastjson/parser/ParserConfig",
                "addAccept", "(Ljava/lang/String;)V", true);
        graph.addEdge(accept, parserConfig, EdgeType.INVOKES, "VIRTUAL");
        graph.freeze();

        ClassHierarchy hierarchy = new ClassHierarchy(Map.of(
                declared, new ClassInfo(declared, "java/lang/Object", List.of(),
                        Modifier.PUBLIC | Modifier.FINAL, List.of(), List.of()),
                unrelated, new ClassInfo(unrelated, "java/lang/Object", List.of(),
                        Modifier.PUBLIC | Modifier.FINAL, List.of(), List.of())), null);
        RuleEngine engine = new RuleEngine(rules(), hierarchy);
        ApplicationEntryIndex index = ApplicationEntryIndex.build(graph, engine,
                Set.of(controller, declared, unrelated), true);

        ApplicationEntryIndex.DeserializeSite site = index.deserializeSites().stream()
                .filter(value -> value.hostMethodKey().startsWith(controller + "#put"))
                .findFirst().orElseThrow();
        assertTrue(site.targetTypes().contains(declared),
                "the declared request type remains a binding alternative");
        assertFalse(site.targetTypes().contains(unrelated),
                "an application class outside the accepted prefix is not a target");
        assertTrue(index.typedBindingSitesForTarget(unrelated).isEmpty(),
                "an application class outside the accepted prefix must not become a target");
    }

    @Test
    void protectedServletLifecycleAndInterfaceServiceAnnotationsAreApplicationEntries() {
        Graph graph = new Graph();
        Node servlet = graph.methodNode("fixture/app/Servlet", "doGet",
                "(Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;)V",
                false);
        servlet.propsNote("methodAccess", Modifier.PROTECTED);
        servlet.propsNote("classSuperName", "javax/servlet/http/HttpServlet");
        Node serviceContract = graph.methodNode("fixture/app/Service", "processTask",
                "([B)Ljava/lang/String;", false);
        serviceContract.propsNote("methodAccess", Modifier.PUBLIC);
        serviceContract.propsNote("classAnnotationDescriptors", List.of(
                "Ljavax/jws/WebService;"));
        serviceContract.propsNote("methodAnnotationDescriptors", List.of(
                "Ljavax/jws/WebMethod;"));
        Node serviceImpl = graph.methodNode("fixture/app/ServiceImpl", "processTask",
                "([B)Ljava/lang/String;", false);
        serviceImpl.propsNote("methodAccess", Modifier.PUBLIC);
        serviceImpl.propsNote("classInterfaces", List.of("fixture/app/Service"));
        graph.freeze();

        RuleEngine engine = new RuleEngine(rules(), new ClassHierarchy(Map.of(), null));
        ApplicationEntryIndex index = ApplicationEntryIndex.build(graph, engine,
                Set.of("fixture/app/Servlet", "fixture/app/Service",
                        "fixture/app/ServiceImpl"), true);

        assertTrue(index.executionEntries().stream().anyMatch(entry ->
                entry.methodKey().startsWith("fixture/app/Servlet#doGet")
                        && entry.entryKind().equals("servlet-lifecycle")
                        && entry.status() == io.just.sast.blackboard.FindingState.EntryStatus.EXTERNAL_ENTRY),
                () -> "missing protected servlet entry: " + index.executionEntries());
        assertTrue(index.executionEntries().stream().anyMatch(entry ->
                entry.methodKey().startsWith("fixture/app/ServiceImpl#processTask")
                        && entry.entryKind().equals("framework-service")
                        && entry.externalControlProven()));
        assertTrue(index.deserializeSites().stream().anyMatch(site ->
                site.hostMethodKey().startsWith("fixture/app/ServiceImpl#processTask")
                        && site.bridge().equals("framework-binding")));
    }

    @Test
    void indexesCxfEndpointAndServletFilterFactsFromTypedBytecodeCalls() {
        Graph graph = cxfFilterFixture("GET", true);
        ApplicationEntryIndex index = ApplicationEntryIndex.build(graph,
                new RuleEngine(rules(), new ClassHierarchy(Map.of(), null)),
                Set.of("fixture/app/Service", "fixture/app/ServiceImpl",
                        "fixture/app/CxfConfig", "fixture/app/AccessFilter"), true);

        String serviceKey = "fixture/app/ServiceImpl#processTask([B)Ljava/lang/String;";
        assertEquals(1, index.serviceEndpointsFor(serviceKey).size());
        ApplicationEntryIndex.ServiceEndpoint endpoint =
                index.serviceEndpointsFor(serviceKey).get(0);
        assertEquals("fixture/app/CxfConfig#internalDataServiceEndpoint()Ljava/lang/Object;",
                endpoint.configurationMethodKey());
        assertEquals("SOAP/CXF", endpoint.protocol());
        assertEquals("/DataSyncService", endpoint.publishPath());
        assertTrue(index.isFrameworkServiceMethod(serviceKey));
        assertTrue(index.isRegisteredServiceMethod(serviceKey));

        assertEquals(1, index.filterControls().size());
        ApplicationEntryIndex.FilterControl filter = index.filterControls().get(0);
        assertEquals("/services", filter.pathPrefix());
        assertEquals("/services", filter.blockedPath());
        assertEquals("GET", filter.blockedMethod());
        assertTrue(filter.remoteAddressGuard());
        assertTrue(filter.passThrough());
        assertTrue(filter.pathNormalization());
        assertEquals(io.just.sast.blackboard.EntryChainJoinEvidence.FilterDominance
                        .DOES_NOT_DOMINATE,
                index.filterDominanceFor(serviceKey));
        assertThrows(UnsupportedOperationException.class, () -> index.serviceEndpoints().clear());
        assertThrows(UnsupportedOperationException.class, () -> index.filterControls().clear());
    }

    @Test
    void filterDominanceChangesOnlyWithObservedRouteControlFact() {
        String serviceKey = "fixture/app/ServiceImpl#processTask([B)Ljava/lang/String;";
        ApplicationEntryIndex blocked = ApplicationEntryIndex.build(cxfFilterFixture("POST", true),
                new RuleEngine(rules(), new ClassHierarchy(Map.of(), null)),
                Set.of("fixture/app/Service", "fixture/app/ServiceImpl",
                        "fixture/app/CxfConfig", "fixture/app/AccessFilter"), true);
        assertEquals(io.just.sast.blackboard.EntryChainJoinEvidence.FilterDominance.DOMINATES,
                blocked.filterDominanceFor(serviceKey));

        ApplicationEntryIndex unregistered = ApplicationEntryIndex.build(
                cxfFilterFixture("GET", false),
                new RuleEngine(rules(), new ClassHierarchy(Map.of(), null)),
                Set.of("fixture/app/Service", "fixture/app/ServiceImpl",
                        "fixture/app/CxfConfig", "fixture/app/AccessFilter"), true);
        assertTrue(unregistered.serviceEndpointsFor(serviceKey).isEmpty());
        assertEquals(io.just.sast.blackboard.EntryChainJoinEvidence.FilterDominance.UNKNOWN,
                unregistered.filterDominanceFor(serviceKey),
                "a filter fact cannot be attached to an unregistered endpoint");
    }

    private static RuleSet rules() {
        Rule.SinkRule sink = new Rule.SinkRule("runtime-exec", "COMMAND", "CRITICAL",
                new Rule.CallMatcher(Match.of("java/lang/Runtime"), Match.of("exec"),
                        Match.of("(Ljava/lang/String;)Ljava/lang/Process;")),
                List.of(new Rule.TaintedPos.Arg(0)), Rule.SinkRole.TERMINAL);
        Rule.MagicEntryRule entry = new Rule.MagicEntryRule("app-handler", "http",
                new Rule.MethodMatcher(Match.of("handle"), Match.of("()V"), false),
                null, "lifecycle");
        return new RuleSet(List.of(sink), List.of(entry), List.of(), List.of(), List.of());
    }

    private static Graph cxfFilterFixture(String blockedMethod, boolean registerEndpoint) {
        String service = "fixture/app/Service";
        String serviceImpl = "fixture/app/ServiceImpl";
        String config = "fixture/app/CxfConfig";
        String filter = "fixture/app/AccessFilter";
        String serviceDescriptor = "([B)Ljava/lang/String;";
        Graph graph = new Graph();

        Node contract = graph.methodNode(service, "processTask", serviceDescriptor, false);
        contract.propsNote("methodAccess", Modifier.PUBLIC);
        contract.propsNote("classAnnotationDescriptors", List.of("Ljavax/jws/WebService;"));
        contract.propsNote("methodAnnotationDescriptors", List.of("Ljavax/jws/WebMethod;"));
        Node implementation = graph.methodNode(serviceImpl, "processTask", serviceDescriptor, false);
        implementation.propsNote("methodAccess", Modifier.PUBLIC);
        implementation.propsNote("classInterfaces", List.of(service));
        graph.methodNode(config, "internalDataServiceEndpoint", "()Ljava/lang/Object;", false);
        Node filterMethod = graph.methodNode(filter, "doFilter",
                "(Ljavax/servlet/ServletRequest;Ljavax/servlet/ServletResponse;"
                        + "Ljavax/servlet/FilterChain;)V", false);
        filterMethod.propsNote("methodAccess", Modifier.PUBLIC);
        filterMethod.propsNote("classInterfaces", List.of("javax/servlet/Filter"));

        Node serviceConstructor = graph.addCallNode(serviceImpl, "<init>", "()V", "SPECIAL",
                null, 0, config, "internalDataServiceEndpoint", "()Ljava/lang/Object;");

        if (registerEndpoint) {
            graph.addEdge(serviceConstructor, implementation, EdgeType.INVOKES, "SPECIAL");
            Node endpointConstructor = graph.addCallNode("org/apache/cxf/jaxws/EndpointImpl", "<init>",
                    "(Lorg/apache/cxf/Bus;Ljava/lang/Object;)V", "SPECIAL", null, 1, config,
                    "internalDataServiceEndpoint", "()Ljava/lang/Object;");
            graph.methodNode("org/apache/cxf/jaxws/EndpointImpl", "<init>",
                    "(Lorg/apache/cxf/Bus;Ljava/lang/Object;)V", true);
            graph.addEdge(endpointConstructor, graph.findMethodNode(
                    "org/apache/cxf/jaxws/EndpointImpl", "<init>",
                    "(Lorg/apache/cxf/Bus;Ljava/lang/Object;)V"), EdgeType.INVOKES, "SPECIAL");
            Node publish = graph.addCallNode("org/apache/cxf/jaxws/EndpointImpl", "publish",
                    "(Ljava/lang/String;)V", "VIRTUAL", null, 2, config,
                    "internalDataServiceEndpoint", "()Ljava/lang/Object;");
            publish.propsNote("stringLiteralHints", List.of("/DataSyncService"));
            graph.methodNode("org/apache/cxf/jaxws/EndpointImpl", "publish",
                    "(Ljava/lang/String;)V", true);
            graph.addEdge(publish, graph.findMethodNode("org/apache/cxf/jaxws/EndpointImpl",
                    "publish", "(Ljava/lang/String;)V"), EdgeType.INVOKES, "VIRTUAL");
        }

        addFilterCall(graph, "javax/servlet/http/HttpServletRequest", "getRequestURI",
                "()Ljava/lang/String;", filter, filterMethod.descriptor(), 0, null);
        addFilterCall(graph, "javax/servlet/http/HttpServletRequest", "getMethod",
                "()Ljava/lang/String;", filter, filterMethod.descriptor(), 1, null);
        addFilterCall(graph, "javax/servlet/http/HttpServletRequest", "getRemoteAddr",
                "()Ljava/lang/String;", filter, filterMethod.descriptor(), 2, null);
        addFilterCall(graph, filter, "isInternalAddress", "(Ljava/lang/String;)Z", filter,
                filterMethod.descriptor(), 3, null);
        Node prefix = addFilterCall(graph, "java/lang/String", "startsWith",
                "(Ljava/lang/String;)Z", filter, filterMethod.descriptor(), 4, List.of("/services"));
        Node blockedPath = addFilterCall(graph, "java/lang/String", "equals",
                "(Ljava/lang/Object;)Z", filter, filterMethod.descriptor(), 5, List.of("/services"));
        Node blockedVerb = addFilterCall(graph, "java/lang/String", "equalsIgnoreCase",
                "(Ljava/lang/String;)Z", filter, filterMethod.descriptor(), 6,
                List.of(blockedMethod));
        addFilterCall(graph, "javax/servlet/FilterChain", "doFilter",
                "(Ljavax/servlet/ServletRequest;Ljavax/servlet/ServletResponse;)V", filter,
                filterMethod.descriptor(), 7, null);
        addFilterCall(graph, filter, "normalizeUri", "(Ljava/lang/String;)Ljava/lang/String;",
                filter, filterMethod.descriptor(), 8, null);
        graph.freeze();
        return graph;
    }

    private static Node addFilterCall(Graph graph, String owner, String name, String descriptor,
                                      String hostOwner, String hostDescriptor, int offset,
                                      List<String> stringHints) {
        Node call = graph.addCallNode(owner, name, descriptor, "VIRTUAL", null, offset,
                hostOwner, "doFilter", hostDescriptor);
        if (stringHints != null) {
            call.propsNote("stringLiteralHints", stringHints);
        }
        return call;
    }

    private static Graph fixture() {
        Graph graph = new Graph();
        Node app = graph.methodNode(APP, "handle", "()V", false);
        Node gadget = graph.methodNode(GADGET, "trigger", "()V", false);
        graph.methodNode("java/io/ObjectInputStream", "readObject", "()Ljava/lang/Object;", true);
        graph.methodNode("java/lang/Runtime", "exec",
                "(Ljava/lang/String;)Ljava/lang/Process;", true);

        Node read = graph.addCallNode("java/io/ObjectInputStream", "readObject",
                "()Ljava/lang/Object;", "VIRTUAL", null, 0, APP, "handle", "()V");
        Node invokeGadget = graph.addCallNode(GADGET, "trigger", "()V", "STATIC", null,
                1, APP, "handle", "()V");
        Node exec = graph.addCallNode("java/lang/Runtime", "exec",
                "(Ljava/lang/String;)Ljava/lang/Process;", "VIRTUAL", null, 0,
                GADGET, "trigger", "()V");
        graph.addEdge(read, graph.findMethodNode("java/io/ObjectInputStream", "readObject",
                "()Ljava/lang/Object;"), EdgeType.INVOKES, "VIRTUAL");
        graph.addEdge(invokeGadget, gadget, EdgeType.INVOKES, "STATIC");
        graph.addEdge(exec, graph.findMethodNode("java/lang/Runtime", "exec",
                "(Ljava/lang/String;)Ljava/lang/Process;"), EdgeType.INVOKES, "VIRTUAL");
        graph.freeze();
        return graph;
    }
}
