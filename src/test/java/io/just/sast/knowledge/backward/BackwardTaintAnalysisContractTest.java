package io.just.sast.knowledge.backward;

import io.just.sast.analysis.entry.ApplicationEntryIndex;
import io.just.sast.analysis.hierarchy.ClassHierarchy;
import io.just.sast.blackboard.Blackboard;
import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.Event;
import io.just.sast.blackboard.EventType;
import io.just.sast.blackboard.SinkRisk;
import io.just.sast.config.Match;
import io.just.sast.config.Rule;
import io.just.sast.config.RuleSet;
import io.just.sast.cpg.build.FieldWriterIndex;
import io.just.sast.cpg.graph.EdgeType;
import io.just.sast.cpg.graph.Graph;
import io.just.sast.cpg.graph.Node;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Contract for backward producers: endpoint admission is independent of trace materialization. */
class BackwardTaintAnalysisContractTest {

    @Test
    void backwardProducerDescriptorPreservesTraceEndpointBeforeChainMaterialization() {
        String sinkDescriptor = "(Ljava/lang/String;)Ljava/lang/Process;";
        Rule.SinkRule rule = new Rule.SinkRule("runtime-exec", "COMMAND", "HIGH",
                new Rule.CallMatcher(Match.of("java/lang/Runtime"), Match.of("exec"),
                        Match.of(sinkDescriptor)), List.of(new Rule.TaintedPos.Arg(0)),
                Rule.SinkRole.TERMINAL, SinkRisk.CONTROLLED_EFFECT);

        ApplicationEntryIndex.ProducerCandidate candidate =
                new ApplicationEntryIndex.ProducerCandidate(rule.id(), rule.category(), rule.severity(),
                        "fixture/app/Deserializer", "read", "()V", "deserialization",
                        "java/lang/Runtime", "exec", sinkDescriptor, rule.role().name(),
                        rule.sinkRisk(), false);

        assertEquals("fixture/app/Deserializer", candidate.entryOwner());
        assertEquals("read", candidate.entryName());
        assertEquals("deserialization", candidate.entryKind());
        assertEquals("java/lang/Runtime", candidate.terminalOwner());
        assertEquals("exec", candidate.terminalName());
        assertEquals(sinkDescriptor, candidate.terminalDescriptor());
        assertFalse(candidate.continuationEvidence());
    }

    @Test
    void pendingChainMaterializerIsSharedAcrossRepeatedAdmissionReads() {
        ApplicationEntryIndex.ProducerCandidate candidate =
                new ApplicationEntryIndex.ProducerCandidate("runtime-exec", "CODE_EXEC", "HIGH",
                        "fixture/app/Deserializer", "read", "()V", "deserialization",
                        "java/lang/Runtime", "exec", "(Ljava/lang/String;)Ljava/lang/Process;",
                        "TERMINAL", null, false);
        Chain expected = new Chain("runtime-exec", "CODE_EXEC", "HIGH",
                "fixture/app/Deserializer", "read", "deserialization",
                "java/lang/Runtime", "exec", List.of(), 0,
                "(Ljava/lang/String;)Ljava/lang/Process;", "TERMINAL");
        AtomicInteger materializations = new AtomicInteger();
        BackwardTaintAnalysis.PendingChain pending = new BackwardTaintAnalysis.PendingChain(
                candidate, List.of(), 0, "semantic", "key", () -> {
                    materializations.incrementAndGet();
                    return expected;
                });

        assertSame(expected, pending.materializer().get());
        assertSame(expected, pending.materializer().get());
        assertEquals(1, materializations.get());
    }

    @Test
    void applicationWithoutVerifiedEntrySkipsSinkEnumerationWhileComponentStillRuns() {
        String appOwner = "fixture/app/NoEntry";
        String sinkOwner = "java/lang/Runtime";
        String sinkDescriptor = "(Ljava/lang/String;)Ljava/lang/Process;";
        Graph graph = new Graph();
        graph.methodNode(appOwner, "health", "()V", false);
        Node sink = graph.methodNode(sinkOwner, "exec", sinkDescriptor, true);
        Node call = graph.addCallNode(sinkOwner, "exec", sinkDescriptor, "VIRTUAL", null, 0,
                appOwner, "health", "()V");
        graph.addEdge(call, sink, EdgeType.INVOKES, "VIRTUAL");
        graph.freeze();

        Rule.SinkRule rule = new Rule.SinkRule("runtime-exec", "COMMAND", "HIGH",
                new Rule.CallMatcher(Match.of(sinkOwner), Match.of("exec"),
                        Match.of(sinkDescriptor)), List.of(new Rule.TaintedPos.Arg(0)),
                Rule.SinkRole.TERMINAL, SinkRisk.CONTROLLED_EFFECT);
        RuleSet rules = new RuleSet(List.of(rule), List.of(), List.of(), List.of(), List.of());

        Blackboard application = blackboard(graph, rules, true, appOwner);
        BackwardTaintAnalysis applicationAnalysis = new BackwardTaintAnalysis();
        applicationAnalysis.init(application);
        applicationAnalysis.onEvent(application, Event.of(EventType.SCAN_START, -1, null));
        assertTrue(application.sinkOutcomes().isEmpty(),
                "application no-entry must return before matching global sinks");
        assertTrue(application.chains().isEmpty());
        assertTrue(application.completenessReasons().contains("NO_APPLICATION_ENTRY"));

        Blackboard component = blackboard(graph, rules, false, appOwner);
        BackwardTaintAnalysis componentAnalysis = new BackwardTaintAnalysis();
        componentAnalysis.init(component);
        componentAnalysis.onEvent(component, Event.of(EventType.SCAN_START, -1, null));
        assertTrue(component.sinkOutcomes().containsKey(call.id()),
                "component mode must retain the shared sink search without an app gate");
    }

    private static Blackboard blackboard(Graph graph, RuleSet rules, boolean applicationScope,
                                         String appOwner) {
        return new Blackboard(graph, new ClassHierarchy(Map.of(), null), new FieldWriterIndex(),
                rules, 20, new Blackboard.ScanInputs(Path.of("fixture.jar"), List.of(), true,
                        null, 61, null, Set.of(appOwner), applicationScope));
    }
}
