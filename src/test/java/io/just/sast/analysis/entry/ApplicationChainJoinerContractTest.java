package io.just.sast.analysis.entry;

import io.just.sast.analysis.hierarchy.ClassHierarchy;
import io.just.sast.analysis.taint.OriginSupport;
import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.EvidenceAtom;
import io.just.sast.blackboard.HopKind;
import io.just.sast.config.Match;
import io.just.sast.config.Rule;
import io.just.sast.config.RuleEngine;
import io.just.sast.config.RuleSet;
import io.just.sast.cpg.build.CpgIndex;
import io.just.sast.cpg.graph.EdgeType;
import io.just.sast.cpg.graph.Graph;
import io.just.sast.cpg.graph.Node;
import io.just.sast.model.ClassInfo;
import io.just.sast.report.ApplicationTrace;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.lang.reflect.Modifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Contract coverage for the typed application-entry/dependency/terminal join seam. */
class ApplicationChainJoinerContractTest {

    private static final String APP = "fixture/app/Ingress";
    private static final String GADGET = "fixture/lib/Gadget";
    private static final String RUNTIME = "java/lang/Runtime";
    private static final String APP_METHOD = APP + "#handle()V";
    private static final String SINK_DESC = "(Ljava/lang/String;)Ljava/lang/Process;";

    @Test
    void joinsApplicationEntryToDependencySuffixAndTerminal() {
        Graph graph = fixture();
        RuleSet rules = rules();
        RuleEngine engine = new RuleEngine(rules, new ClassHierarchy(Map.of(), null));
        ApplicationEntryIndex index = ApplicationEntryIndex.build(graph, engine,
                Set.of(APP), true);
        Chain chain = chain();

        ApplicationChainEvidence evidence = ApplicationChainJoiner.build(index, graph,
                List.of(chain), true, "A".repeat(64), Set.of());

        assertEquals(1, evidence.joinCount());
        assertTrue(evidence.joinedChainKeys().contains(chain.key()));
        assertEquals(1, evidence.applicationStateCount());
        assertTrue(evidence.decisions().get(chain.key()).equals("JOINED"));
        assertEquals(1, evidence.graph().nodes().stream()
                .filter(node -> node.nodeKind().name().equals("ENTRY_CHAIN_JOIN")).count());
        assertTrue(evidence.graph().edges().stream().anyMatch(edge ->
                edge.reasonCode().equals("TERMINAL_IMPACT_REACHED")));
        assertTrue(evidence.semanticDigest().matches("[0-9a-f]{64}"));
        assertTrue(evidence.graph().toCanonicalJson().contains("APPLICATION_ENTRY"));
    }

    @Test
    void sharedSiteAndSuffixReuseEvidenceAtomsAcrossRawChainVariants() {
        Graph graph = fixture();
        RuleEngine engine = new RuleEngine(rules(), new ClassHierarchy(Map.of(), null));
        ApplicationEntryIndex index = ApplicationEntryIndex.build(graph, engine,
                Set.of(APP), true);
        Chain first = chain();
        Chain second = new Chain("fixture-variant", first.category(), first.severity(),
                first.entryClass(), first.entryMethod(), first.entryKind(), first.sinkClass(),
                first.sinkMethod(), first.hops(), first.unresolvedHops(), first.sinkDescriptor(),
                first.sinkRole());

        ApplicationChainEvidence evidence = ApplicationChainJoiner.build(index, graph,
                List.of(first, second), true, "A".repeat(64), Set.of());

        assertEquals(2, evidence.joinCount());
        long segments = evidence.graph().nodes().stream()
                .filter(EvidenceAtom.class::isInstance)
                .map(EvidenceAtom.class::cast)
                .filter(atom -> atom.kind() == EvidenceAtom.Kind.DEPENDENCY_SEGMENT)
                .count();
        assertEquals(1, segments,
                "raw rule/path variants must share one reusable dependency suffix atom");
    }

    @Test
    void reportProjectionRetainsRawChainKeyWithoutDegradingSharedAtoms() {
        Graph graph = fixture();
        RuleEngine engine = new RuleEngine(rules(), new ClassHierarchy(Map.of(), null));
        ApplicationEntryIndex index = ApplicationEntryIndex.build(graph, engine,
                Set.of(APP), true);
        Chain chain = chain();
        ApplicationChainEvidence evidence = ApplicationChainJoiner.build(index, graph,
                List.of(chain), true, "A".repeat(64), Set.of());

        Map<String, ApplicationTrace> traces = ApplicationTrace.fromEvidence(evidence);
        assertTrue(traces.containsKey(chain.key()),
                "a report renderer must be able to join typed evidence back to its raw chain");
        ApplicationTrace trace = traces.get(chain.key());
        assertEquals(APP, trace.applicationEntryClass());
        assertEquals(RUNTIME, trace.terminalOwner());
    }

    @Test
    void dependencyOnlyChainIsRejectedEvenWhenTerminalIsIndexed() {
        Graph graph = fixture();
        RuleEngine engine = new RuleEngine(rules(), new ClassHierarchy(Map.of(), null));
        ApplicationEntryIndex index = ApplicationEntryIndex.build(graph, engine,
                Set.of(APP), true);
        Chain dependencyOnly = new Chain("fixture", "COMMAND", "HIGH",
                GADGET, "trigger", "deserialize", RUNTIME, "exec", List.of(
                new ChainHop(GADGET, "trigger", RUNTIME, "exec", HopKind.DIRECT_CALL,
                        null, "direct", SINK_DESC, 0)), 0, SINK_DESC, "TERMINAL");

        ApplicationChainEvidence evidence = ApplicationChainJoiner.build(index, graph,
                List.of(dependencyOnly), true, "A".repeat(64), Set.of());

        assertEquals(0, evidence.joinCount());
        assertEquals("APPLICATION_ENTRY_NOT_IN_CHAIN", evidence.decisions().get(dependencyOnly.key()));
        assertTrue(evidence.reasons().contains("NO_APPLICATION_CHAIN_JOIN"));
    }

    @Test
    void typedAdmissionCountsCandidatesBeforeJoinMaterialization() {
        Graph graph = fixture();
        RuleEngine engine = new RuleEngine(rules(), new ClassHierarchy(Map.of(), null));
        ApplicationEntryIndex index = ApplicationEntryIndex.build(graph, engine,
                Set.of(APP), true);
        Chain accepted = chain();
        Chain dependencyOnly = new Chain("fixture-dependency-only", "COMMAND", "HIGH",
                GADGET, "trigger", "deserialize", RUNTIME, "exec", List.of(
                new ChainHop(GADGET, "trigger", RUNTIME, "exec", HopKind.DIRECT_CALL,
                        null, "direct", SINK_DESC, 0)), 0, SINK_DESC, "TERMINAL");

        ApplicationChainEvidence evidence = ApplicationChainJoiner.build(index, graph,
                List.of(accepted, dependencyOnly), true, "A".repeat(64), Set.of());

        assertEquals(1, evidence.admissionCandidateCount(),
                "only the typed entry-forward ∩ terminal-reverse candidate may reach join construction");
        assertEquals(1, evidence.admissionRejectedCount());
        assertEquals(ApplicationEntryIndex.CandidateAdmissionStatus.ADMITTED,
                evidence.admissionDecisions().get(accepted.key()));
        assertEquals(ApplicationEntryIndex.CandidateAdmissionStatus.APPLICATION_ENTRY_NOT_IN_CHAIN,
                evidence.admissionDecisions().get(dependencyOnly.key()));
        assertEquals(1, evidence.joinCount());
    }

    @Test
    void applicationEntryKeepsLookupBridgeAndLaterDependencyTerminal() {
        String lookupOwner = "javax/naming/InitialContext";
        String lookupDesc = "(Ljava/lang/String;)Ljava/lang/Object;";
        String responseOwner = "java/rmi/RemoteObject";
        String responseMethod = "readObject";
        String responseDesc = "()Ljava/lang/Object;";

        Graph graph = new Graph();
        Node app = graph.methodNode(APP, "handle", "()V", false);
        Node lookup = graph.methodNode(lookupOwner, "lookup", lookupDesc, true);
        Node lookupCall = graph.addCallNode(lookupOwner, "lookup", lookupDesc, "VIRTUAL", null,
                0, APP, "handle", "()V");
        graph.addEdge(lookupCall, lookup, EdgeType.INVOKES, "VIRTUAL");

        Node response = graph.methodNode(responseOwner, responseMethod, responseDesc, true);
        Node responseCall = graph.addCallNode(responseOwner, responseMethod, responseDesc,
                "STATIC", null, 1, "fixture/lib/Gadget", "trigger", "()V");
        graph.addEdge(responseCall, response, EdgeType.INVOKES, "STATIC");

        Node gadget = graph.methodNode("fixture/lib/Gadget", "trigger", "()V", false);
        Node runtime = graph.methodNode(RUNTIME, "exec", SINK_DESC, true);
        Node terminal = graph.addCallNode(RUNTIME, "exec", SINK_DESC, "VIRTUAL", null, 2,
                "fixture/lib/Gadget", "trigger", "()V");
        graph.addEdge(terminal, runtime, EdgeType.INVOKES, "VIRTUAL");
        graph.freeze();

        Rule.SinkRule sink = new Rule.SinkRule("runtime-exec", "COMMAND", "CRITICAL",
                new Rule.CallMatcher(Match.of(RUNTIME), Match.of("exec"), Match.of(SINK_DESC)),
                List.of(new Rule.TaintedPos.Arg(0)), Rule.SinkRole.TERMINAL);
        Rule.SourceRule lookupSource = new Rule.SourceRule("jndi-lookup", "jndi-lookup",
                new Rule.CallMatcher(Match.of(lookupOwner), Match.of("lookup"),
                        Match.of(lookupDesc)), null);
        Rule.MagicEntryRule entry = new Rule.MagicEntryRule("app-handler", "http",
                new Rule.MethodMatcher(Match.of("handle"), Match.of("()V"), false), null,
                "lifecycle");
        RuleEngine engine = new RuleEngine(new RuleSet(List.of(sink), List.of(entry),
                List.of(lookupSource), List.of(), List.of()),
                new ClassHierarchy(Map.of(), null));
        ApplicationEntryIndex index = ApplicationEntryIndex.build(graph, engine,
                Set.of(APP), true);

        Chain chain = new Chain("n1cat-shaped", "JNDI", "CRITICAL", APP, "handle", "http",
                RUNTIME, "exec", List.of(
                new ChainHop(APP, "handle", lookupOwner, "lookup", HopKind.DIRECT_CALL,
                        null, "bridge-jndi-lookup", lookupDesc, 0),
                new ChainHop(responseOwner, responseMethod, "fixture/lib/Gadget", "trigger",
                        HopKind.DIRECT_CALL, null, "bridge-rmi-response", responseDesc, 0),
                new ChainHop("fixture/lib/Gadget", "trigger", RUNTIME, "exec",
                        HopKind.DIRECT_CALL, null, "dependency-terminal", SINK_DESC, 0),
                new ChainHop(APP, "handle", APP, "handle", HopKind.ENTRY,
                        null, "http", "()V", null)), 0, SINK_DESC, "TERMINAL");

        ApplicationChainEvidence evidence = ApplicationChainJoiner.build(index, graph,
                List.of(chain), true, "A".repeat(64), Set.of());

        assertEquals(1, evidence.joinCount(), "lookup must not terminate the dependency suffix");
        assertEquals("JOINED", evidence.decisions().get(chain.key()));
        var join = evidence.joins().values().iterator().next();
        assertEquals(io.just.sast.blackboard.EntryChainJoinEvidence.ValueFlow.PROTOCOL_REPLY,
                join.valueFlow());
        assertEquals(io.just.sast.blackboard.EntryChainJoinEvidence.CallbackSemantics.PROTOCOL_REENTRY,
                join.callbackSemantics());
        assertTrue(!join.bridgeEvidenceIds().isEmpty(),
                "the lookup/RMI continuation must retain explicit bridge evidence");
        assertTrue(evidence.graph().nodes().stream().anyMatch(node ->
                node.nodeKind().name().equals("PROTOCOL_BRIDGE")));
        assertEquals(io.just.sast.blackboard.FindingState.ChainProgress.IMPACT_CHAIN_COMPLETE,
                evidence.states().get(chain.key()).chainProgress());
    }

    @Test
    void demandAdmissionRequiresEntryAndTerminalDemandOrTypedContinuation() {
        Graph graph = fixture();
        RuleEngine engine = new RuleEngine(rules(), new ClassHierarchy(Map.of(), null));
        ApplicationEntryIndex index = ApplicationEntryIndex.build(graph, engine,
                Set.of(APP), true);

        ApplicationEntryIndex.DemandDecision direct = index.demandAdmission(
                APP_METHOD, GADGET + "#trigger()V", false);
        assertTrue(direct.admitted(), direct.toString());
        assertEquals(ApplicationEntryIndex.DemandStatus.ENTRY_TERMINAL_INTERSECTION,
                direct.status());

        ApplicationEntryIndex.DemandDecision dependencyOnly = index.demandAdmission(
                GADGET + "#trigger()V", GADGET + "#trigger()V", false);
        assertFalse(dependencyOnly.admitted(), dependencyOnly.toString());
        assertEquals(ApplicationEntryIndex.DemandStatus.ENTRY_NOT_APPLICATION,
                dependencyOnly.status());
    }

    @Test
    void demandAdmissionAllowsExplicitBridgeWhenDirectIntersectionIsMissing() {
        String lookupOwner = "javax/naming/InitialContext";
        String lookupDesc = "(Ljava/lang/String;)Ljava/lang/Object;";
        String responseOwner = "java/rmi/RemoteObject";
        String responseDesc = "()Ljava/lang/Object;";
        Graph graph = new Graph();
        graph.methodNode(APP, "handle", "()V", false);
        Node lookup = graph.methodNode(lookupOwner, "lookup", lookupDesc, true);
        Node lookupCall = graph.addCallNode(lookupOwner, "lookup", lookupDesc, "VIRTUAL", null,
                0, APP, "handle", "()V");
        graph.addEdge(lookupCall, lookup, EdgeType.INVOKES, "VIRTUAL");
        graph.methodNode(responseOwner, "readObject", responseDesc, true);
        Node responseCall = graph.addCallNode(responseOwner, "readObject", responseDesc,
                "STATIC", null, 1, GADGET, "trigger", "()V");
        graph.addEdge(responseCall, graph.findMethodNode(responseOwner, "readObject", responseDesc),
                EdgeType.INVOKES, "STATIC");
        graph.methodNode(GADGET, "trigger", "()V", false);
        Node runtime = graph.methodNode(RUNTIME, "exec", SINK_DESC, true);
        Node terminal = graph.addCallNode(RUNTIME, "exec", SINK_DESC, "VIRTUAL", null, 2,
                GADGET, "trigger", "()V");
        graph.addEdge(terminal, runtime, EdgeType.INVOKES, "VIRTUAL");
        graph.freeze();
        Rule.SinkRule sink = new Rule.SinkRule("runtime-exec", "COMMAND", "CRITICAL",
                new Rule.CallMatcher(Match.of(RUNTIME), Match.of("exec"), Match.of(SINK_DESC)),
                List.of(new Rule.TaintedPos.Arg(0)), Rule.SinkRole.TERMINAL);
        Rule.SourceRule lookupSource = new Rule.SourceRule("jndi-lookup", "jndi-lookup",
                new Rule.CallMatcher(Match.of(lookupOwner), Match.of("lookup"),
                        Match.of(lookupDesc)), null);
        Rule.MagicEntryRule entry = new Rule.MagicEntryRule("app-handler", "http",
                new Rule.MethodMatcher(Match.of("handle"), Match.of("()V"), false), null,
                "lifecycle");
        RuleEngine bridgeEngine = new RuleEngine(new RuleSet(List.of(sink), List.of(entry),
                List.of(lookupSource), List.of(), List.of()),
                new ClassHierarchy(Map.of(), null));
        ApplicationEntryIndex index = ApplicationEntryIndex.build(graph, bridgeEngine,
                Set.of(APP), true);
        assertFalse(index.entryTerminalIntersection().contains(APP_METHOD));

        ApplicationEntryIndex.DemandDecision bridged = index.demandAdmission(
                APP_METHOD, GADGET + "#trigger()V", true);
        assertTrue(bridged.admitted(), bridged.toString());
        assertEquals(ApplicationEntryIndex.DemandStatus.BRIDGE_CONTINUATION,
                bridged.status());

        ApplicationEntryIndex.DemandDecision missingBridge = index.demandAdmission(
                APP_METHOD, GADGET + "#trigger()V", false);
        assertFalse(missingBridge.admitted(), missingBridge.toString());
        assertEquals(ApplicationEntryIndex.DemandStatus.ENTRY_NOT_IN_TERMINAL_DEMAND,
                missingBridge.status());
    }

    @Test
    void unknownScopeNeverCreatesJoinOrDynamicAdmission() {
        Graph graph = fixture();
        RuleEngine engine = new RuleEngine(rules(), new ClassHierarchy(Map.of(), null));
        ApplicationEntryIndex index = ApplicationEntryIndex.build(graph, engine,
                Set.of(), false);

        ApplicationChainEvidence evidence = ApplicationChainJoiner.build(index, graph,
                List.of(chain()), false, "A".repeat(64), Set.of());

        assertEquals(0, evidence.joinCount());
        assertFalse(evidence.joinedChainKeys().contains(chain().key()));
        assertTrue(evidence.reasons().contains("APPLICATION_SCOPE_UNKNOWN"));
    }

    @Test
    void joinsThroughConcreteApplicationCallerPrefixToAComposedHelper() {
        String helper = APP + "#decode(Ljava/lang/String;)Ljava/lang/Object;";
        Graph graph = new Graph();
        Node root = graph.methodNode(APP, "handle", "()V", false);
        Node helperMethod = graph.methodNode(APP, "decode",
                "(Ljava/lang/String;)Ljava/lang/Object;", false);
        Node runtime = graph.methodNode(RUNTIME, "exec", SINK_DESC, true);
        Node rootCall = graph.addCallNode(APP, "decode",
                "(Ljava/lang/String;)Ljava/lang/Object;", "SPECIAL", null, 0,
                APP, "handle", "()V");
        Node exec = graph.addCallNode(RUNTIME, "exec", SINK_DESC, "VIRTUAL", null, 1,
                APP, "decode", "(Ljava/lang/String;)Ljava/lang/Object;");
        graph.addEdge(rootCall, helperMethod, EdgeType.INVOKES, "SPECIAL");
        graph.addEdge(exec, runtime, EdgeType.INVOKES, "VIRTUAL");
        graph.freeze();

        RuleEngine engine = new RuleEngine(rules(), new ClassHierarchy(Map.of(), null));
        ApplicationEntryIndex index = ApplicationEntryIndex.build(graph, engine,
                Set.of(APP), true);
        Chain composedHelper = new Chain("fixture", "COMMAND", "HIGH", APP, "decode",
                "source", RUNTIME, "exec", List.of(
                new ChainHop(APP, "decode", RUNTIME, "exec", HopKind.DIRECT_CALL,
                        null, "direct", SINK_DESC, 0),
                new ChainHop(APP, "decode", APP, "decode", HopKind.ENTRY,
                        null, "source", "(Ljava/lang/String;)Ljava/lang/Object;", null)),
                0, SINK_DESC, "TERMINAL");

        ApplicationChainEvidence evidence = ApplicationChainJoiner.build(index, graph,
                List.of(composedHelper), true, "A".repeat(64), Set.of());

        assertEquals(1, evidence.joinCount());
        assertEquals("JOINED", evidence.decisions().get(composedHelper.key()));
        assertTrue(evidence.graph().toCanonicalJson().contains("APPLICATION_ENTRY_CALL_PREFIX"));
        assertTrue(evidence.graph().toCanonicalJson().contains(helper));
    }

    @Test
    void typedBindingTargetJoinsReflectiveSetterWithoutSyntheticCallEdge() {
        String servlet = "fixture/app/Servlet";
        String target = "fixture/lib/Bound";
        String bindingDesc = "(Ljava/lang/String;Ljava/lang/Class;)Ljava/lang/Object;";
        String setterDesc = "(Ljava/lang/String;)V";
        String sinkDesc = "(Ljava/lang/String;)Ljava/lang/Process;";
        Graph graph = new Graph();
        Node entry = graph.methodNode(servlet, "doGet",
                "(Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;)V",
                false);
        entry.propsNote("methodAccess", Modifier.PROTECTED);
        entry.propsNote("classSuperName", "javax/servlet/http/HttpServlet");
        Node mapper = graph.methodNode("com/fasterxml/jackson/databind/ObjectMapper",
                "readValue", bindingDesc, true);
        Node source = graph.addCallNode("com/fasterxml/jackson/databind/ObjectMapper", "readValue",
                bindingDesc, "VIRTUAL", null, 0, servlet, "doGet",
                "(Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;)V");
        source.propsNote("classLiteralHints", List.of(target));
        graph.addEdge(source, mapper, EdgeType.INVOKES, "VIRTUAL");
        Node setter = graph.methodNode(target, "setUrl", setterDesc, false);
        Node runtime = graph.methodNode(RUNTIME, "exec", sinkDesc, true);
        Node sink = graph.addCallNode(RUNTIME, "exec", sinkDesc, "VIRTUAL", null, 0,
                target, "setUrl", setterDesc);
        graph.addEdge(sink, runtime, EdgeType.INVOKES, "VIRTUAL");
        graph.freeze();

        Rule.SinkRule sinkRule = new Rule.SinkRule("runtime-exec", "COMMAND", "HIGH",
                new Rule.CallMatcher(Match.of(RUNTIME), Match.of("exec"), Match.of(sinkDesc)),
                List.of(new Rule.TaintedPos.Arg(0)), Rule.SinkRole.TERMINAL);
        Rule.SourceRule sourceRule = new Rule.SourceRule("jackson-read", "deserialize",
                new Rule.CallMatcher(Match.of("com/fasterxml/jackson/databind/ObjectMapper"),
                        Match.of("readValue"), Match.of(bindingDesc)), null);
        RuleSet rules = new RuleSet(List.of(sinkRule), List.of(), List.of(sourceRule), List.of(),
                List.of());
        RuleEngine engine = new RuleEngine(rules, new ClassHierarchy(Map.of(), null));
        ApplicationEntryIndex index = ApplicationEntryIndex.build(graph, engine,
                Set.of(servlet), true);
        assertTrue(index.deserializeSites().stream().anyMatch(site ->
                site.targetTypes().equals(List.of(target))));
        assertFalse(index.isApplicationBindingCallback(target, "setUrl", setterDesc));
        assertFalse(index.isApplicationBindingCallback("fixture/lib/Other", "setUrl",
                setterDesc));

        Chain chain = new Chain("runtime-exec", "COMMAND", "HIGH", target, "setUrl",
                "deserialize", RUNTIME, "exec", List.of(
                new ChainHop(target, "setUrl", RUNTIME, "exec", HopKind.DIRECT_CALL,
                        null, "direct", sinkDesc, 0),
                new ChainHop(target, "setUrl", target, "setUrl", HopKind.ENTRY,
                        null, "deserialize", setterDesc, 0)), 0, sinkDesc, "TERMINAL");

        ApplicationChainEvidence evidence = ApplicationChainJoiner.build(index, graph,
                List.of(chain), true, "A".repeat(64), Set.of());

        assertEquals(1, evidence.joinCount());
        assertEquals("JOINED", evidence.decisions().get(chain.key()));
        assertTrue(evidence.graph().toCanonicalJson().contains("TYPED_BINDING_TARGET"));
        assertTrue(evidence.graph().toCanonicalJson().contains("CALLBACK_ARGUMENT"));
    }

    @Test
    void acceptedAutoTypePrefixJoinsApplicationBindingToConcreteSetter() {
        String controller = "fixture/app/Controller";
        String target = "fixture/app/Metric";
        String setterDesc = "(Ljava/lang/String;)V";
        String sinkDesc = "()Ljava/lang/Process;";
        Graph graph = new Graph();
        Node endpoint = graph.methodNode(controller, "put", "(Lfixture/app/Note;)V", false);
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
        graph.methodNode("com/alibaba/fastjson/parser/ParserConfig", "addAccept",
                "(Ljava/lang/String;)V", true);
        graph.addEdge(accept, graph.findMethodNode(
                "com/alibaba/fastjson/parser/ParserConfig", "addAccept",
                "(Ljava/lang/String;)V"), EdgeType.INVOKES, "VIRTUAL");

        Node setter = graph.methodNode(target, "setValue", setterDesc, false);
        Node runtime = graph.methodNode(RUNTIME, "start", sinkDesc, true);
        Node sink = graph.addCallNode(RUNTIME, "start", sinkDesc, "VIRTUAL", null, 0,
                target, "setValue", setterDesc);
        graph.addEdge(sink, runtime, EdgeType.INVOKES, "VIRTUAL");
        graph.freeze();

        Rule.SinkRule sinkRule = new Rule.SinkRule("runtime-start", "COMMAND", "HIGH",
                new Rule.CallMatcher(Match.of(RUNTIME), Match.of("start"), Match.of(sinkDesc)),
                List.of(), Rule.SinkRole.TERMINAL);
        ClassHierarchy hierarchy = new ClassHierarchy(Map.of(
                "fixture/app/Note", new ClassInfo("fixture/app/Note", "java/lang/Object",
                        List.of(), Modifier.PUBLIC, List.of(), List.of()),
                target, new ClassInfo(target, "fixture/app/Note", List.of(), Modifier.PUBLIC,
                        List.of(), List.of())), null);
        RuleEngine engine = new RuleEngine(new RuleSet(List.of(sinkRule), List.of(),
                List.of(), List.of(), List.of()), hierarchy);
        ApplicationEntryIndex index = ApplicationEntryIndex.build(graph, engine,
                Set.of(controller, target), true, hierarchy);

        assertTrue(index.deserializeSites().stream().anyMatch(site ->
                site.hostMethodKey().startsWith(controller + "#put")
                        && site.targetTypes().contains(target)));
        assertTrue(index.isApplicationBindingCallback(target, "setValue", setterDesc));
        Chain chain = new Chain("runtime-start", "COMMAND", "HIGH", target, "setValue",
                "deserialize", RUNTIME, "start", List.of(
                new ChainHop(target, "setValue", target, "setValue", HopKind.ENTRY,
                        null, "deserialize", setterDesc, 0)), 0, sinkDesc, "TERMINAL");
        ApplicationChainEvidence evidence = ApplicationChainJoiner.build(index, graph,
                List.of(chain), true, "A".repeat(64), Set.of());

        assertEquals(1, evidence.joinCount());
        assertEquals("JOINED", evidence.decisions().get(chain.key()));
        assertTrue(evidence.graph().toCanonicalJson().contains("TYPED_BINDING_TARGET"));
    }

    @Test
    void typedIntermediateLookupCannotBecomeTerminalFinding() {
        String lookupDesc = "(Ljava/lang/String;)Ljava/lang/Object;";
        Graph graph = new Graph();
        Node entry = graph.methodNode(APP, "handle", "()V", false);
        Node lookup = graph.addCallNode("javax/naming/Context", "lookup", lookupDesc,
                "VIRTUAL", null, 0, APP, "handle", "()V");
        graph.methodNode("javax/naming/Context", "lookup", lookupDesc, true);
        graph.addEdge(lookup, graph.findMethodNode("javax/naming/Context", "lookup", lookupDesc),
                EdgeType.INVOKES, "VIRTUAL");
        Node runtime = graph.methodNode(RUNTIME, "exec",
                "(Ljava/lang/String;)Ljava/lang/Process;", true);
        Node runtimeCall = graph.addCallNode(RUNTIME, "exec",
                "(Ljava/lang/String;)Ljava/lang/Process;", "VIRTUAL", null, 1, APP, "handle", "()V");
        graph.addEdge(runtimeCall, runtime, EdgeType.INVOKES, "VIRTUAL");
        graph.freeze();
        Rule.SinkRule rule = new Rule.SinkRule("lookup", "JNDI", "HIGH",
                new Rule.CallMatcher(Match.of("javax/naming/Context"), Match.of("lookup"),
                        Match.of(lookupDesc)), List.of(new Rule.TaintedPos.Arg(0)));
        Rule.MagicEntryRule entryRule = new Rule.MagicEntryRule("app-handler", "http",
                new Rule.MethodMatcher(Match.of("handle"), Match.of("()V"), false), null,
                "lifecycle");
        Rule.SinkRule runtimeRule = new Rule.SinkRule("runtime-exec", "COMMAND", "HIGH",
                new Rule.CallMatcher(Match.of(RUNTIME), Match.of("exec"),
                        Match.of("(Ljava/lang/String;)Ljava/lang/Process;")), List.of(),
                Rule.SinkRole.TERMINAL);
        RuleSet rules = new RuleSet(List.of(rule, runtimeRule), List.of(entryRule), List.of(), List.of(),
                List.of());
        RuleEngine engine = new RuleEngine(rules, new ClassHierarchy(Map.of(), null));
        ApplicationEntryIndex index = ApplicationEntryIndex.build(graph, engine, Set.of(APP), true);
        Chain chain = new Chain("lookup", "JNDI", "HIGH", APP, "handle", "lifecycle",
                "javax/naming/Context", "lookup", List.of(new ChainHop(APP, "handle",
                "javax/naming/Context", "lookup", HopKind.DIRECT_CALL, null, "direct",
                lookupDesc, 0), new ChainHop(APP, "handle", APP, "handle", HopKind.ENTRY,
                null, "lifecycle", "()V", null)), 0, lookupDesc, "TERMINAL");
        ApplicationChainEvidence evidence = ApplicationChainJoiner.build(index, graph,
                List.of(chain), true, "A".repeat(64), Set.of());
        assertEquals("TERMINAL_IMPACT_IS_INTERMEDIATE", evidence.decisions().get(chain.key()));
        assertEquals(0, evidence.joinCount());
    }

    @Test
    void composedCallbackCanJoinExactApplicationEntryWhenDirectGraphIntersectionIsMissing() {
        Graph graph = new Graph();
        Node app = graph.methodNode(APP, "handle", "()V", false);
        Node gadget = graph.methodNode(GADGET, "trigger", "()V", false);
        Node runtime = graph.methodNode(RUNTIME, "exec", SINK_DESC, true);
        Node exec = graph.addCallNode(RUNTIME, "exec", SINK_DESC, "VIRTUAL", null, 0,
                GADGET, "trigger", "()V");
        graph.addEdge(exec, runtime, EdgeType.INVOKES, "VIRTUAL");
        graph.freeze();

        RuleEngine engine = new RuleEngine(rules(), new ClassHierarchy(Map.of(), null));
        ApplicationEntryIndex index = ApplicationEntryIndex.build(graph, engine,
                Set.of(APP), true);
        Chain composed = new Chain("fixture", "COMMAND", "HIGH", APP, "handle",
                "http", RUNTIME, "exec", List.of(
                new ChainHop(APP, "handle", GADGET, "trigger", HopKind.ENTRY,
                        null, "callback-object-graph", "()V", 0),
                new ChainHop(GADGET, "trigger", RUNTIME, "exec", HopKind.DIRECT_CALL,
                        null, "callback-terminal", SINK_DESC, 0)), 0, SINK_DESC, "TERMINAL");

        assertFalse(index.entryTerminalIntersection().contains(APP_METHOD),
                "the direct graph hint intentionally cannot see the semantic callback edge");
        ApplicationChainEvidence evidence = ApplicationChainJoiner.build(index, graph,
                List.of(composed), true, "A".repeat(64), Set.of());

        assertEquals(1, evidence.joinCount());
        assertEquals("JOINED", evidence.decisions().get(composed.key()));
    }

    @Test
    void terminalHostMayBeProvedByChainMethodIdentityWhenTerminalHopIsOmitted() {
        Graph graph = fixture();
        RuleEngine engine = new RuleEngine(rules(), new ClassHierarchy(Map.of(), null));
        ApplicationEntryIndex index = ApplicationEntryIndex.build(graph, engine,
                Set.of(APP), true);
        Chain abbreviated = new Chain("fixture-abbreviated", "COMMAND", "HIGH", APP,
                "handle", "deserialize", RUNTIME, "exec", List.of(
                new ChainHop(APP, "handle", GADGET, "trigger", HopKind.ENTRY,
                        null, "entry", "()V", 0)), 0, SINK_DESC, "TERMINAL");

        ApplicationChainEvidence evidence = ApplicationChainJoiner.build(index, graph,
                List.of(abbreviated), true, "A".repeat(64), Set.of());

        assertEquals(1, evidence.joinCount());
        assertEquals("JOINED", evidence.decisions().get(abbreviated.key()));
    }

    private static Chain chain() {
        return new Chain("fixture", "COMMAND", "HIGH", APP, "handle", "deserialize",
                RUNTIME, "exec", List.of(
                new ChainHop(APP, "handle", GADGET, "trigger", HopKind.ENTRY,
                        null, "entry", "()V", 0),
                new ChainHop(GADGET, "trigger", RUNTIME, "exec", HopKind.DIRECT_CALL,
                        null, "direct", SINK_DESC, 0)), 0, SINK_DESC, "TERMINAL");
    }

    private static RuleSet rules() {
        Rule.SinkRule sink = new Rule.SinkRule("runtime-exec", "COMMAND", "CRITICAL",
                new Rule.CallMatcher(Match.of(RUNTIME), Match.of("exec"), Match.of(SINK_DESC)),
                List.of(new Rule.TaintedPos.Arg(0)), Rule.SinkRole.TERMINAL);
        Rule.MagicEntryRule entry = new Rule.MagicEntryRule("app-handler", "http",
                new Rule.MethodMatcher(Match.of("handle"), Match.of("()V"), false),
                null, "lifecycle");
        return new RuleSet(List.of(sink), List.of(entry), List.of(), List.of(), List.of());
    }

    private static Graph fixture() {
        Graph graph = new Graph();
        Node app = graph.methodNode(APP, "handle", "()V", false);
        Node gadget = graph.methodNode(GADGET, "trigger", "()V", false);
        Node runtime = graph.methodNode(RUNTIME, "exec", SINK_DESC, true);
        Node read = graph.addCallNode("java/io/ObjectInputStream", "readObject",
                "()Ljava/lang/Object;", "VIRTUAL", null, 0, APP, "handle", "()V");
        Node invokeGadget = graph.addCallNode(GADGET, "trigger", "()V", "STATIC", null,
                1, APP, "handle", "()V");
        Node exec = graph.addCallNode(RUNTIME, "exec", SINK_DESC, "VIRTUAL", null, 0,
                GADGET, "trigger", "()V");
        graph.methodNode("java/io/ObjectInputStream", "readObject",
                "()Ljava/lang/Object;", true);
        graph.addEdge(read, graph.findMethodNode("java/io/ObjectInputStream", "readObject",
                "()Ljava/lang/Object;"), EdgeType.INVOKES, "VIRTUAL");
        graph.addEdge(invokeGadget, gadget, EdgeType.INVOKES, "STATIC");
        graph.addEdge(exec, runtime, EdgeType.INVOKES, "VIRTUAL");
        graph.freeze();
        return graph;
    }
}
