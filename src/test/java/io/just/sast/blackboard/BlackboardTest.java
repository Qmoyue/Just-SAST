package io.just.sast.blackboard;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;

import io.just.sast.analysis.entry.ApplicationEntryIndex;
import io.just.sast.analysis.hierarchy.ClassHierarchy;
import io.just.sast.config.Match;
import io.just.sast.config.Rule;
import io.just.sast.config.RuleEngine;
import io.just.sast.config.RuleSet;
import io.just.sast.cpg.graph.EdgeType;
import io.just.sast.cpg.graph.Graph;
import io.just.sast.cpg.graph.Node;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** 黑板契约：链按 key 去重、校准记录、链级注释归属。 */
class BlackboardTest {

    private static Blackboard empty() {
        return new Blackboard(new io.just.sast.cpg.graph.Graph(),
                new io.just.sast.analysis.hierarchy.ClassHierarchy(Map.of(), null),
                new io.just.sast.cpg.build.FieldWriterIndex(), io.just.sast.config.RuleSet.EMPTY, 20, Blackboard.ScanInputs.fastDefault(Path.of(".")));
    }

    private static Chain chain(String entryMethod) {
        List<ChainHop> hops = List.of(new ChainHop("A", entryMethod, "A", entryMethod,
                HopKind.ENTRY, null, "readObject", "", null));
        return new Chain("R", "CAT", "HIGH", "A", entryMethod, "readObject",
                "S", "sink", hops, 0);
    }

    @Test
    void addChainDeduplicatesByKey() {
        Blackboard bb = empty();
        assertTrue(bb.addChain(chain("readObject")));
        assertFalse(bb.addChain(chain("readObject")), "同 key 链去重");
        assertTrue(bb.addChain(chain("hashCode")));
        assertEquals(2, bb.chains().size());
    }

    @Test
    void chainIdentityKeepsDifferentRulesSeparate() {
        Blackboard bb = empty();
        Chain first = chain("readObject");
        Chain second = new Chain("R2", first.category(), first.severity(), first.entryClass(),
                first.entryMethod(), first.entryKind(), first.sinkClass(), first.sinkMethod(),
                first.hops(), first.unresolvedHops());
        assertTrue(bb.addChain(first));
        assertTrue(bb.addChain(second), "同一条路径被不同规则命中时不能丢失 rule_id");
        assertEquals(2, bb.chains().size());
    }

    @Test
    void chainIdentityKeepsOverloadedSinksSeparate() {
        Blackboard bb = empty();
        Chain first = new Chain("R", "CAT", "HIGH", "A", "readObject", "readObject",
                "S", "sink", List.of(), 0, "(Ljava/lang/String;)V");
        Chain second = new Chain("R", "CAT", "HIGH", "A", "readObject", "readObject",
                "S", "sink", List.of(), 0, "(I)V");
        assertTrue(bb.addChain(first));
        assertTrue(bb.addChain(second), "不同 sink 重载不得在黑板去重时折叠");
        assertEquals(2, bb.chains().size());
    }

    @Test
    void chainHopsAreImmutableSnapshots() {
        java.util.ArrayList<ChainHop> mutable = new java.util.ArrayList<>();
        Chain chain = new Chain("R", "CAT", "HIGH", "A", "m", "readObject",
                "S", "sink", mutable, 0);
        mutable.add(new ChainHop("A", "m", "S", "sink", HopKind.DIRECT_CALL,
                null, "test", "()V", null));
        assertEquals(0, chain.hops().size(), "Chain 不得受构造方后续修改影响");
        assertThrows(UnsupportedOperationException.class, () -> chain.hops().clear());
    }

    @Test
    void calibrationAndNotesAreKeyed() {
        Blackboard bb = empty();
        Chain c = chain("readObject");
        bb.addChain(c);
        bb.calibrateChain(c.key(), "safe-config");
        assertEquals("safe-config", bb.calibrationOf(c.key()));
        assertEquals(1, bb.calibrationCount());
        bb.chainNote(c.key(), "pattern:CC6");
        assertEquals(List.of("pattern:CC6"), bb.chainNotesOf(c.key()));
        assertEquals(List.of(), bb.chainNotesOf("missing"), "无注释的链返回空集");
    }

    @Test
    void incompleteReasonsAreDeduplicatedAndSnapshotted() {
        Blackboard bb = empty();
        bb.markIncomplete("FORWARD_STEP_CAP");
        bb.markIncomplete("FORWARD_STEP_CAP");
        bb.markIncomplete(" ");
        assertEquals(java.util.Set.of("FORWARD_STEP_CAP"), bb.completenessReasons());
        assertThrows(UnsupportedOperationException.class,
                () -> bb.completenessReasons().clear());
    }

    @Test
    void solverProducerRoutesOnlyDemandedApplicationChainToDefaultStore() {
        String appOwner = "fixture/app/Entry";
        String appDescriptor = "()V";
        String sinkOwner = "java/lang/Runtime";
        String sinkName = "exec";
        String sinkDescriptor = "(Ljava/lang/String;)Ljava/lang/Process;";
        Graph graph = new Graph();
        graph.methodNode(appOwner, "handle", appDescriptor, false);
        Node runtime = graph.methodNode(sinkOwner, sinkName, sinkDescriptor, true);
        Node sinkCall = graph.addCallNode(sinkOwner, sinkName, sinkDescriptor, "VIRTUAL", null,
                0, appOwner, "handle", appDescriptor);
        graph.addEdge(sinkCall, runtime, EdgeType.INVOKES, "VIRTUAL");
        String bridgeOwner = "javax/naming/InitialContext";
        String bridgeName = "lookup";
        String bridgeDescriptor = "(Ljava/lang/String;)Ljava/lang/Object;";
        Node lookup = graph.methodNode(bridgeOwner, bridgeName, bridgeDescriptor, true);
        Node bridgeCall = graph.addCallNode(bridgeOwner, bridgeName, bridgeDescriptor, "VIRTUAL", null,
                1, appOwner, "handle", appDescriptor);
        graph.addEdge(bridgeCall, lookup, EdgeType.INVOKES, "VIRTUAL");
        graph.methodNode("fixture/lib/Gadget", "trigger", appDescriptor, false);
        graph.freeze();

        Rule.SinkRule sink = new Rule.SinkRule("runtime-exec", "COMMAND", "HIGH",
                new Rule.CallMatcher(Match.of(sinkOwner), Match.of(sinkName),
                        Match.of(sinkDescriptor)), List.of(new Rule.TaintedPos.Arg(0)),
                Rule.SinkRole.TERMINAL);
        Rule.SinkRule bridgeSink = new Rule.SinkRule("jndi-lookup", "JNDI", "HIGH",
                new Rule.CallMatcher(Match.of(bridgeOwner), Match.of(bridgeName),
                        Match.of(bridgeDescriptor)), List.of(new Rule.TaintedPos.Arg(0)),
                Rule.SinkRole.TERMINAL);
        Rule.MagicEntryRule entry = new Rule.MagicEntryRule("app-entry", "http",
                new Rule.MethodMatcher(Match.of("handle"), Match.of(appDescriptor), false), null,
                "lifecycle");
        RuleSet rules = new RuleSet(List.of(sink, bridgeSink), List.of(entry), List.of(), List.of(), List.of());
        Blackboard.ScanInputs inputs = new Blackboard.ScanInputs(Path.of("fixture.jar"), List.of(),
                true, null, 0, null, Set.of(appOwner), true);
        Blackboard bb = new Blackboard(graph, new ClassHierarchy(Map.of(), null),
                new io.just.sast.cpg.build.FieldWriterIndex(), rules, 20, inputs);

        Chain application = new Chain("runtime-exec", "COMMAND", "HIGH", appOwner, "handle",
                "http", sinkOwner, sinkName, List.of(
                new ChainHop(appOwner, "handle", sinkOwner, sinkName, HopKind.DIRECT_CALL,
                        null, "direct", sinkDescriptor, 0),
                new ChainHop(appOwner, "handle", appOwner, "handle", HopKind.ENTRY,
                        null, "http", appDescriptor, null)), 0, sinkDescriptor, "TERMINAL");
        Chain dependencySuffix = new Chain("runtime-exec-suffix", "COMMAND", "HIGH",
                "fixture/lib/Gadget", "trigger", "readObject", sinkOwner, sinkName,
                List.of(new ChainHop("fixture/lib/Gadget", "trigger", sinkOwner, sinkName,
                        HopKind.DIRECT_CALL, null, "direct", sinkDescriptor, 0),
                        new ChainHop("fixture/lib/Gadget", "trigger", "fixture/lib/Gadget",
                                "trigger", HopKind.ENTRY, null, "readObject", appDescriptor,
                                null)), 0, sinkDescriptor, "TERMINAL");
        Chain applicationBridge = new Chain("jndi-lookup", "JNDI", "HIGH", appOwner, "handle",
                "http", bridgeOwner, bridgeName, List.of(
                new ChainHop(appOwner, "handle", bridgeOwner, bridgeName, HopKind.DIRECT_CALL,
                        null, "bridge-jndi-lookup", bridgeDescriptor, 0),
                new ChainHop(appOwner, "handle", appOwner, "handle", HopKind.ENTRY,
                        null, "http", appDescriptor, null)), 0, bridgeDescriptor, "TERMINAL");

        assertTrue(bb.addSolverCandidate(
                new ApplicationEntryIndex.ProducerCandidate(application.ruleId(), application.category(),
                        application.severity(), application.entryClass(), application.entryMethod(),
                        appDescriptor, application.entryKind(), application.sinkClass(),
                        application.sinkMethod(), application.sinkDescriptor(), application.sinkRole(),
                        application.sinkRisk(), false),
                () -> application));
        assertTrue(bb.addSolverCandidate(
                new ApplicationEntryIndex.ProducerCandidate(applicationBridge.ruleId(),
                        applicationBridge.category(), applicationBridge.severity(),
                        applicationBridge.entryClass(), applicationBridge.entryMethod(), appDescriptor,
                        applicationBridge.entryKind(), applicationBridge.sinkClass(),
                        applicationBridge.sinkMethod(), applicationBridge.sinkDescriptor(),
                        applicationBridge.sinkRole(), applicationBridge.sinkRisk(), true),
                () -> applicationBridge),
                "application-owned typed bridge remains a candidate for later suffix composition");
        AtomicBoolean dependencyMaterialized = new AtomicBoolean();
        assertTrue(bb.addSolverCandidate(
                new ApplicationEntryIndex.ProducerCandidate(dependencySuffix.ruleId(),
                        dependencySuffix.category(), dependencySuffix.severity(),
                        dependencySuffix.entryClass(), dependencySuffix.entryMethod(), appDescriptor,
                        dependencySuffix.entryKind(), dependencySuffix.sinkClass(),
                        dependencySuffix.sinkMethod(), dependencySuffix.sinkDescriptor(),
                        dependencySuffix.sinkRole(), dependencySuffix.sinkRisk(), false),
                () -> {
            dependencyMaterialized.set(true);
            return dependencySuffix;
                }));
        assertFalse(dependencyMaterialized.get(),
                "dependency suffix endpoint admission must defer its path payload");
        assertFalse(bb.compositionInputsLazy().deferredDependencySuffixes().isEmpty(),
                "lazy composition snapshot must retain the typed suffix endpoint");
        assertFalse(dependencyMaterialized.get(),
                "reading a lazy composition snapshot must not materialize the suffix");
        assertEquals(2, bb.chains().size(),
                "application terminal and bridge candidates stay in the default finding store");
        assertEquals(3, bb.compatibilityCompositionInputs().compatibilityAll().size(),
                "typed composition snapshot sees application candidates plus the separately routed suffix");
        assertTrue(dependencyMaterialized.get(),
                "the compatibility composition snapshot is the explicit deferred materialization boundary");
        assertEquals(0, bb.bridgeChains().size(),
                "an application-owned bridge must not be classified as a dependency bridge");
        assertEquals(List.of(dependencySuffix), bb.compatibilityDependencySuffixChains());
        assertEquals(3, bb.solverAdmissionMetrics().input());
        assertEquals(2, bb.solverAdmissionMetrics().applicationChains());
        assertEquals(1, bb.solverAdmissionMetrics().dependencySuffixes());
        assertEquals(0, bb.solverAdmissionMetrics().rejected());

        Blackboard.CompositionInputs compositionInputs = bb.compatibilityCompositionInputs();
        assertEquals(2, compositionInputs.applicationChains().size(),
                "application-owned chains must remain in the application composition input");
        assertTrue(compositionInputs.applicationChains().contains(application));
        assertTrue(compositionInputs.applicationChains().contains(applicationBridge));
        assertEquals(List.of(dependencySuffix), compositionInputs.dependencySuffixes(),
                "dependency terminal suffixes must remain a separate typed input");
        assertEquals(List.of(dependencySuffix), compositionInputs.compatibilityContinuationChains(),
                "dependency-side composition frontier must combine bridge and suffix inputs");
        assertTrue(compositionInputs.bridgeContinuations().isEmpty(),
                "application-owned bridge must not leak into dependency continuation input");
        assertEquals(3, compositionInputs.compatibilityAll().size(),
                "the compatibility union must preserve the historical composition input set");
    }

    @Test
    void rejectedSolverCandidateDoesNotInvokeChainMaterializer() {
        String appOwner = "fixture/app/Entry";
        String appDescriptor = "()V";
        String sinkOwner = "java/lang/Runtime";
        String sinkName = "exec";
        String sinkDescriptor = "(Ljava/lang/String;)Ljava/lang/Process;";
        Graph graph = new Graph();
        graph.methodNode(appOwner, "handle", appDescriptor, false);
        Node runtime = graph.methodNode(sinkOwner, sinkName, sinkDescriptor, true);
        Node sinkCall = graph.addCallNode(sinkOwner, sinkName, sinkDescriptor, "VIRTUAL", null,
                0, appOwner, "handle", appDescriptor);
        graph.addEdge(sinkCall, runtime, EdgeType.INVOKES, "VIRTUAL");
        graph.freeze();

        Rule.SinkRule sink = new Rule.SinkRule("runtime-exec", "COMMAND", "HIGH",
                new Rule.CallMatcher(Match.of(sinkOwner), Match.of(sinkName),
                        Match.of(sinkDescriptor)), List.of(new Rule.TaintedPos.Arg(0)),
                Rule.SinkRole.TERMINAL);
        Rule.MagicEntryRule entry = new Rule.MagicEntryRule("app-entry", "http",
                new Rule.MethodMatcher(Match.of("handle"), Match.of(appDescriptor), false), null,
                "lifecycle");
        RuleSet rules = new RuleSet(List.of(sink), List.of(entry), List.of(), List.of(), List.of());
        Blackboard.ScanInputs inputs = new Blackboard.ScanInputs(Path.of("fixture.jar"), List.of(),
                true, null, 0, null, Set.of(appOwner), true);
        Blackboard bb = new Blackboard(graph, new ClassHierarchy(Map.of(), null),
                new io.just.sast.cpg.build.FieldWriterIndex(), rules, 20, inputs);

        AtomicBoolean materialized = new AtomicBoolean();
        ApplicationEntryIndex.ProducerCandidate rejected = new ApplicationEntryIndex.ProducerCandidate(
                "missing-rule", "COMMAND", "HIGH", "fixture/lib/Gadget", "trigger", "()V",
                "readObject", sinkOwner, "notIndexed", "()V", "TERMINAL",
                SinkRisk.HIGH_RISK_TERMINAL, false);

        Blackboard.SolverAdmissionResult result = bb.admitSolverCandidate(rejected, () -> {
            materialized.set(true);
            return new Chain("missing-rule", "COMMAND", "HIGH", "fixture/lib/Gadget",
                    "trigger", "readObject", sinkOwner, "notIndexed", List.of(), 0,
                    "()V", "TERMINAL");
        });
        assertFalse(result.accepted());
        assertEquals(null, result.chain(), "rejected demand must not expose a materialized chain");
        assertFalse(materialized.get(), "rejected demand must fail before Chain materialization");
        assertEquals(1, bb.solverAdmissionMetrics().input());
        assertEquals(1, bb.solverAdmissionMetrics().rejected());
        assertEquals(0, bb.compatibilityCompositionInputs().compatibilityAll().size());
    }

    @Test
    void untypedDeferredMaterializationCannotBypassDemandDecision() {
        String appOwner = "fixture/app/Entry";
        String appDescriptor = "()V";
        String sinkOwner = "java/lang/Runtime";
        String sinkName = "exec";
        String sinkDescriptor = "(Ljava/lang/String;)Ljava/lang/Process;";
        Graph graph = new Graph();
        graph.methodNode(appOwner, "handle", appDescriptor, false);
        Node runtime = graph.methodNode(sinkOwner, sinkName, sinkDescriptor, true);
        Node sinkCall = graph.addCallNode(sinkOwner, sinkName, sinkDescriptor, "VIRTUAL", null,
                0, appOwner, "handle", appDescriptor);
        graph.addEdge(sinkCall, runtime, EdgeType.INVOKES, "VIRTUAL");
        graph.freeze();

        Rule.SinkRule sink = new Rule.SinkRule("runtime-exec", "COMMAND", "HIGH",
                new Rule.CallMatcher(Match.of(sinkOwner), Match.of(sinkName),
                        Match.of(sinkDescriptor)), List.of(new Rule.TaintedPos.Arg(0)),
                Rule.SinkRole.TERMINAL);
        Rule.MagicEntryRule entry = new Rule.MagicEntryRule("app-entry", "http",
                new Rule.MethodMatcher(Match.of("handle"), Match.of(appDescriptor), false), null,
                "lifecycle");
        RuleSet rules = new RuleSet(List.of(sink), List.of(entry), List.of(), List.of(), List.of());
        Blackboard bb = new Blackboard(graph, new ClassHierarchy(Map.of(), null),
                new io.just.sast.cpg.build.FieldWriterIndex(), rules, 20,
                new Blackboard.ScanInputs(Path.of("fixture.jar"), List.of(), true,
                        null, 0, null, Set.of(appOwner), true));
        Chain suffix = new Chain("runtime-exec", "COMMAND", "HIGH", "fixture/lib/Gadget",
                "trigger", "readObject", sinkOwner, sinkName,
                List.of(new ChainHop("fixture/lib/Gadget", "trigger", sinkOwner, sinkName,
                                HopKind.DIRECT_CALL, null, "direct", sinkDescriptor, 0),
                        new ChainHop("fixture/lib/Gadget", "trigger", "fixture/lib/Gadget",
                                "trigger", HopKind.ENTRY, null, "readObject", appDescriptor, null)),
                0, sinkDescriptor, "TERMINAL");
        ApplicationEntryIndex.ProducerCandidate candidate =
                new ApplicationEntryIndex.ProducerCandidate("runtime-exec", "COMMAND", "HIGH",
                        suffix.entryClass(), suffix.entryMethod(), appDescriptor, suffix.entryKind(),
                        suffix.sinkClass(), suffix.sinkMethod(), suffix.sinkDescriptor(),
                        suffix.sinkRole(), suffix.sinkRisk(), false);
        AtomicBoolean materialized = new AtomicBoolean();
        assertTrue(bb.addSolverCandidate(candidate, () -> {
            materialized.set(true);
            return suffix;
        }));
        Blackboard.DeferredDependencySuffix deferred =
                bb.compositionInputsLazy().deferredDependencySuffixes().get(0);
        assertFalse(materialized.get());

        // Expected red before p292: the untyped public helper still flushed the deferred path.
        assertFalse(bb.materializeDeferredDependencySuffix(deferred).accepted(),
                "deferred materialization must require a typed demand decision");
        assertFalse(materialized.get(),
                "an untyped demand must fail closed before invoking the supplier");

        ApplicationEntryIndex.ProducerAdmissionDecision demandDecision =
                bb.applicationEntryIndex().producerAdmission(deferred.candidate());
        ApplicationEntryIndex.ProducerCandidate otherEndpoint =
                new ApplicationEntryIndex.ProducerCandidate("runtime-exec", "COMMAND", "HIGH",
                        "fixture/lib/Other", "trigger", appDescriptor, "readObject",
                        sinkOwner, sinkName, sinkDescriptor, "TERMINAL", suffix.sinkRisk(), false);
        ApplicationEntryIndex.ProducerAdmissionDecision mismatchedDecision =
                bb.applicationEntryIndex().producerAdmission(otherEndpoint);
        assertEquals(ApplicationEntryIndex.MaterializationPolicy.DEFERRED_SUFFIX,
                mismatchedDecision.materializationPolicy());
        assertFalse(bb.materializeDeferredDependencySuffix(deferred, mismatchedDecision).accepted(),
                "a decision for another endpoint must not authorize this supplier");
        assertFalse(materialized.get());
        assertTrue(bb.materializeDeferredDependencySuffix(deferred, demandDecision).accepted(),
                "a matching typed demand may materialize the retained suffix");
        assertTrue(materialized.get());
    }

    @Test
    void admittedSolverCandidateInvokesMaterializerOnceAndRoutesChain() {
        String appOwner = "fixture/app/Entry";
        String appDescriptor = "()V";
        String sinkOwner = "java/lang/Runtime";
        String sinkName = "exec";
        String sinkDescriptor = "(Ljava/lang/String;)Ljava/lang/Process;";
        Graph graph = new Graph();
        graph.methodNode(appOwner, "handle", appDescriptor, false);
        Node runtime = graph.methodNode(sinkOwner, sinkName, sinkDescriptor, true);
        Node sinkCall = graph.addCallNode(sinkOwner, sinkName, sinkDescriptor, "VIRTUAL", null,
                0, appOwner, "handle", appDescriptor);
        graph.addEdge(sinkCall, runtime, EdgeType.INVOKES, "VIRTUAL");
        graph.freeze();

        Rule.SinkRule sink = new Rule.SinkRule("runtime-exec", "COMMAND", "HIGH",
                new Rule.CallMatcher(Match.of(sinkOwner), Match.of(sinkName),
                        Match.of(sinkDescriptor)), List.of(new Rule.TaintedPos.Arg(0)),
                Rule.SinkRole.TERMINAL);
        Rule.MagicEntryRule entry = new Rule.MagicEntryRule("app-entry", "http",
                new Rule.MethodMatcher(Match.of("handle"), Match.of(appDescriptor), false), null,
                "lifecycle");
        RuleSet rules = new RuleSet(List.of(sink), List.of(entry), List.of(), List.of(), List.of());
        Blackboard.ScanInputs inputs = new Blackboard.ScanInputs(Path.of("fixture.jar"), List.of(),
                true, null, 0, null, Set.of(appOwner), true);
        Blackboard bb = new Blackboard(graph, new ClassHierarchy(Map.of(), null),
                new io.just.sast.cpg.build.FieldWriterIndex(), rules, 20, inputs);

        AtomicBoolean materialized = new AtomicBoolean();
        ApplicationEntryIndex.ProducerCandidate admitted = new ApplicationEntryIndex.ProducerCandidate(
                "runtime-exec", "COMMAND", "HIGH", appOwner, "handle", appDescriptor,
                "http", sinkOwner, sinkName, sinkDescriptor, "TERMINAL",
                SinkRisk.CONTROLLED_EFFECT, false);
        Blackboard.SolverAdmissionResult result = bb.admitSolverCandidate(admitted, () -> {
            materialized.set(true);
            return new Chain("runtime-exec", "COMMAND", "HIGH", appOwner, "handle", "http",
                    sinkOwner, sinkName, List.of(
                    new ChainHop(appOwner, "handle", sinkOwner, sinkName, HopKind.DIRECT_CALL,
                            null, "direct", sinkDescriptor, 0),
                    new ChainHop(appOwner, "handle", appOwner, "handle", HopKind.ENTRY,
                            null, "http", appDescriptor, null)), 0, sinkDescriptor, "TERMINAL");
        });
        assertTrue(result.accepted());
        assertEquals(appOwner, result.chain().entryClass(),
                "accepted admission should expose the same materialized product to the caller");
        assertTrue(materialized.get(), "admitted demand must materialize its product once");
        assertEquals(1, bb.solverAdmissionMetrics().applicationChains());
        assertEquals(1, bb.chains().size());
    }

    @Test
    void unknownScopeCompatibilityAdmissionKeepsComposedProductInDefaultStore() {
        Blackboard bb = empty();
        Chain compatibility = chain("readObject");
        ApplicationEntryIndex.ProducerCandidate candidate =
                new ApplicationEntryIndex.ProducerCandidate(compatibility.ruleId(), compatibility.category(),
                        compatibility.severity(), compatibility.entryClass(), compatibility.entryMethod(), "",
                        compatibility.entryKind(), compatibility.sinkClass(), compatibility.sinkMethod(),
                        compatibility.sinkDescriptor(), compatibility.sinkRole(), compatibility.sinkRisk(), true);
        AtomicBoolean materialized = new AtomicBoolean();

        Blackboard.SolverAdmissionResult result = bb.admitCompatibilityCandidate(candidate, () -> {
            materialized.set(true);
            return compatibility;
        });

        assertTrue(result.accepted(), "unknown-scope compatibility composition remains a product");
        assertEquals(compatibility, result.chain());
        assertTrue(materialized.get(), "accepted compatibility output must materialize once");
        assertEquals(List.of(compatibility), bb.chains());
        assertTrue(bb.kernelOnlyChains().isEmpty(),
                "legacy unknown-scope composition is intentionally distinct from solver kernel routing");
        assertEquals(0, bb.solverAdmissionMetrics().input(),
                "compatibility composition does not pretend to be a solver admission");
    }

    @Test
    void unknownScopeCompatibilityAdmissionRejectsMaterializedEndpointMismatch() {
        Blackboard bb = empty();
        Chain expected = chain("readObject");
        Chain mismatched = chain("hashCode");
        ApplicationEntryIndex.ProducerCandidate candidate =
                new ApplicationEntryIndex.ProducerCandidate(expected.ruleId(), expected.category(),
                        expected.severity(), expected.entryClass(), expected.entryMethod(), "",
                        expected.entryKind(), expected.sinkClass(), expected.sinkMethod(),
                        expected.sinkDescriptor(), expected.sinkRole(), expected.sinkRisk(), true);

        Blackboard.SolverAdmissionResult result = bb.admitCompatibilityCandidate(candidate,
                () -> mismatched);

        assertFalse(result.accepted(), "compatibility output must still match its typed endpoint");
        assertEquals(null, result.chain());
        assertTrue(bb.chains().isEmpty(), "mismatched output must not reach the default store");
    }

    @Test
    void lazyCompositionCompatibilityViewFailsClosedOnDeferredMaterializerFailure() {
        ApplicationEntryIndex.ProducerCandidate candidate =
                new ApplicationEntryIndex.ProducerCandidate("runtime-exec", "COMMAND", "HIGH",
                        "dep/Gadget", "readObject", "()V", "readObject",
                        "java/lang/Runtime", "exec", "(Ljava/lang/String;)Ljava/lang/Process;",
                        "TERMINAL", SinkRisk.HIGH_RISK_TERMINAL, false);
        Blackboard.DeferredDependencySuffix deferred =
                new Blackboard.DeferredDependencySuffix(candidate, () -> {
                    throw new IllegalStateException("synthetic materializer failure");
                });
        Blackboard.CompositionInputs inputs = new Blackboard.CompositionInputs(
                List.of(), List.of(), List.of(), List.of(deferred));

        List<Chain> all = assertDoesNotThrow(inputs::compatibilityAll,
                "a compatibility projection must fail closed when a deferred producer fails");
        List<Chain> continuation = assertDoesNotThrow(inputs::compatibilityContinuationChains,
                "dependency continuation projection must preserve the same failure policy");
        assertTrue(all.isEmpty());
        assertTrue(continuation.isEmpty());
    }

    @Test
    void deferredCompatibilityProjectionMemoizesOneMaterializationAcrossViews() {
        Chain expected = chain("readObject");
        ApplicationEntryIndex.ProducerCandidate candidate =
                new ApplicationEntryIndex.ProducerCandidate(expected.ruleId(), expected.category(),
                        expected.severity(), expected.entryClass(), expected.entryMethod(), "",
                        expected.entryKind(), expected.sinkClass(), expected.sinkMethod(),
                        expected.sinkDescriptor(), expected.sinkRole(), expected.sinkRisk(), false);
        AtomicInteger materializations = new AtomicInteger();
        Blackboard.DeferredDependencySuffix deferred =
                new Blackboard.DeferredDependencySuffix(candidate, () -> {
                    materializations.incrementAndGet();
                    return expected;
                });
        Blackboard.CompositionInputs inputs = new Blackboard.CompositionInputs(
                List.of(), List.of(), List.of(), List.of(deferred));

        assertEquals(List.of(expected), inputs.compatibilityAll());
        assertEquals(List.of(expected), inputs.compatibilityContinuationChains());
        assertEquals(1, materializations.get(),
                "all compatibility views must share the memoized deferred payload");
    }

    @Test
    void compatibilityProjectionHasExplicitMaterializationBoundary() {
        Chain expected = chain("readObject");
        ApplicationEntryIndex.ProducerCandidate candidate =
                new ApplicationEntryIndex.ProducerCandidate(expected.ruleId(), expected.category(),
                        expected.severity(), expected.entryClass(), expected.entryMethod(), "",
                        expected.entryKind(), expected.sinkClass(), expected.sinkMethod(),
                        expected.sinkDescriptor(), expected.sinkRole(), expected.sinkRisk(), false);
        AtomicInteger materializations = new AtomicInteger();
        Blackboard.DeferredDependencySuffix deferred =
                new Blackboard.DeferredDependencySuffix(candidate, () -> {
                    materializations.incrementAndGet();
                    return expected;
                });
        Blackboard.CompositionInputs inputs = new Blackboard.CompositionInputs(
                List.of(), List.of(), List.of(), List.of(deferred));

        assertEquals(List.of(expected), inputs.compatibilityAll());
        assertEquals(List.of(expected), inputs.compatibilityContinuationChains());
        assertEquals(1, materializations.get(),
                "only the explicitly named compatibility projection may materialize a deferred payload");
    }

    @Test
    void blackboardCompatibilitySnapshotsHaveExplicitMaterializationNames() {
        Blackboard bb = empty();

        assertTrue(bb.compatibilityCompositionInputs().compatibilityAll().isEmpty());
        assertTrue(bb.compatibilityDependencySuffixChains().isEmpty());
    }

    @Test
    void deferredCompositionInputsExposeTypedEntryAndTerminalIndexes() {
        Chain expected = chain("readObject");
        ApplicationEntryIndex.ProducerCandidate candidate =
                new ApplicationEntryIndex.ProducerCandidate(expected.ruleId(), expected.category(),
                        expected.severity(), expected.entryClass(), expected.entryMethod(), "",
                        expected.entryKind(), expected.sinkClass(), expected.sinkMethod(),
                        expected.sinkDescriptor(), expected.sinkRole(), expected.sinkRisk(), false);
        Blackboard.DeferredDependencySuffix deferred =
                new Blackboard.DeferredDependencySuffix(candidate, () -> expected);
        Blackboard.CompositionInputs inputs = new Blackboard.CompositionInputs(
                List.of(), List.of(), List.of(), List.of(deferred));

        assertEquals(List.of(deferred), inputs.deferredDependencySuffixesForEntryKind("readObject"));
        assertEquals(List.of(deferred), inputs.deferredDependencySuffixesForTerminal(
                expected.sinkClass(), expected.sinkMethod(), expected.sinkDescriptor()));
        assertTrue(inputs.deferredDependencySuffixesForEntryKind("hashCode").isEmpty());
        assertTrue(inputs.deferredDependencySuffixesForTerminal(
                expected.sinkClass(), "other", expected.sinkDescriptor()).isEmpty());
    }
}
