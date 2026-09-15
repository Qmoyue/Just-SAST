package io.just.sast.knowledge.objectgraph;

import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.Blackboard;
import io.just.sast.blackboard.Event;
import io.just.sast.blackboard.EventType;
import io.just.sast.blackboard.HopKind;
import io.just.sast.analysis.entry.ApplicationEntryIndex;
import io.just.sast.blackboard.SinkRisk;
import io.just.sast.config.Match;
import io.just.sast.config.Rule;
import io.just.sast.config.RuleSet;
import io.just.sast.cpg.graph.EdgeType;
import io.just.sast.cpg.graph.Graph;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ObjectGraphEntryKnowledgeSourceContractTest {

    @Test
    void rerootProducerDescriptorPreservesFieldEntryAndTerminalBeforeMaterialization() {
        String sinkDescriptor = "(Ljava/lang/String;)Ljava/lang/Process;";
        Chain source = new Chain("runtime-exec", "COMMAND", "HIGH",
                "gadget/Trigger", "readObject", "readObject",
                "java/lang/Runtime", "exec", List.of(
                new ChainHop("gadget/Trigger", "readObject", "java/lang/Runtime", "exec",
                        HopKind.DIRECT_CALL, null, "backward", sinkDescriptor, 0),
                new ChainHop("gadget/Trigger", "readObject", "gadget/Trigger", "readObject",
                        HopKind.ENTRY, null, "readObject", "(Ljava/io/ObjectInputStream;)V", null)),
                0, sinkDescriptor, "TERMINAL");

        ApplicationEntryIndex.ProducerCandidate candidate =
                new ApplicationEntryIndex.ProducerCandidate(source.ruleId(), source.category(),
                        source.severity(), "app/Container", "readObject",
                        "(Ljava/io/ObjectInputStream;)V", "readObject", source.sinkClass(),
                        source.sinkMethod(), source.sinkDescriptor(), source.sinkRole(),
                        source.sinkRisk(), false);

        assertEquals("app/Container", candidate.entryOwner());
        assertEquals("readObject", candidate.entryName());
        assertEquals("readObject", candidate.entryKind());
        assertEquals("(Ljava/io/ObjectInputStream;)V", candidate.entryDescriptor());
        assertEquals("java/lang/Runtime", candidate.terminalOwner());
        assertEquals("exec", candidate.terminalName());
        assertEquals(sinkDescriptor, candidate.terminalDescriptor());
        assertFalse(candidate.continuationEvidence());
    }

    @Test
    void rerootProducerMaterializerIsSharedAcrossRepeatedAdmissionReads() {
        ApplicationEntryIndex.ProducerCandidate candidate =
                new ApplicationEntryIndex.ProducerCandidate("runtime-exec", "CODE_EXEC", "HIGH",
                        "app/Container", "readObject", "()V", "readObject",
                        "java/lang/Runtime", "exec", "(Ljava/lang/String;)Ljava/lang/Process;",
                        "TERMINAL", null, false);
        Chain expected = new Chain("runtime-exec", "CODE_EXEC", "HIGH", "app/Container",
                "readObject", "readObject", "java/lang/Runtime", "exec", List.of(), 0,
                "(Ljava/lang/String;)Ljava/lang/Process;", "TERMINAL");
        AtomicInteger materializations = new AtomicInteger();
        ObjectGraphEntryKnowledgeSource.RerootedProducer producer =
                new ObjectGraphEntryKnowledgeSource.RerootedProducer(candidate, () -> {
                    materializations.incrementAndGet();
                    return expected;
                });

        assertSame(expected, producer.materializer().get());
        assertSame(expected, producer.materializer().get());
        assertEquals(1, materializations.get());
    }

    @Test
    void objectGraphPassDoesNotFlushUnmatchedDeferredSuffixes() {
        String sinkDescriptor = "(Ljava/lang/String;)Ljava/lang/Process;";
        String entryDescriptor = "()V";
        Rule.SinkRule terminal = new Rule.SinkRule("runtime-exec", "CODE_EXEC", "CRITICAL",
                new Rule.CallMatcher(Match.of("java/lang/Runtime"), Match.of("exec"),
                        Match.of(sinkDescriptor)), List.of(), Rule.SinkRole.TERMINAL);
        Rule.MagicEntryRule entry = new Rule.MagicEntryRule("app-entry", "service",
                new Rule.MethodMatcher(Match.of("process"), Match.of(entryDescriptor), false), null,
                "lifecycle");
        RuleSet rules = new RuleSet(List.of(terminal), List.of(entry), List.of(), List.of(), List.of());

        Graph graph = new Graph();
        graph.methodNode("app/Entry", "process", entryDescriptor, false);
        graph.methodNode("dep/Terminal", "readObject", entryDescriptor, false);
        var runtime = graph.methodNode("java/lang/Runtime", "exec", sinkDescriptor, true);
        var sink = graph.addCallNode("java/lang/Runtime", "exec", sinkDescriptor,
                "VIRTUAL", null, 0, "dep/Terminal", "readObject", entryDescriptor);
        graph.addEdge(sink, runtime, EdgeType.INVOKES, "VIRTUAL");
        graph.freeze();

        Blackboard bb = new Blackboard(graph,
                new io.just.sast.analysis.hierarchy.ClassHierarchy(Map.of(), null),
                new io.just.sast.cpg.build.FieldWriterIndex(), rules, 20,
                new Blackboard.ScanInputs(Path.of("."), List.of(), false, null, 0, null,
                        Set.of("app/Entry"), true));
        Chain suffix = new Chain("runtime-exec", "CODE_EXEC", "CRITICAL", "dep/Terminal",
                "readObject", "readObject", "java/lang/Runtime", "exec", List.of(
                new ChainHop("dep/Terminal", "readObject", "java/lang/Runtime", "exec",
                        HopKind.DIRECT_CALL, null, "direct", sinkDescriptor, null),
                new ChainHop("dep/Terminal", "readObject", "dep/Terminal", "readObject",
                        HopKind.ENTRY, null, "readObject", entryDescriptor, null)), 0,
                sinkDescriptor, "TERMINAL");
        ApplicationEntryIndex.ProducerCandidate candidate =
                new ApplicationEntryIndex.ProducerCandidate(suffix.ruleId(), suffix.category(),
                        suffix.severity(), suffix.entryClass(), suffix.entryMethod(), entryDescriptor,
                        suffix.entryKind(), suffix.sinkClass(), suffix.sinkMethod(), suffix.sinkDescriptor(),
                        suffix.sinkRole(), SinkRisk.HIGH_RISK_TERMINAL, false);
        AtomicBoolean materialized = new AtomicBoolean();
        assertTrue(bb.addSolverCandidate(candidate, () -> {
            materialized.set(true);
            return suffix;
        }));

        ObjectGraphEntryKnowledgeSource source = new ObjectGraphEntryKnowledgeSource();
        source.init(bb);
        source.onEvent(bb, Event.of(EventType.SCAN_ANALYZED, -1, null));

        assertFalse(materialized.get(),
                "object-graph must not force a dependency suffix without a compatible object field");
        assertEquals(1, bb.compositionInputsLazy().deferredDependencySuffixes().size());
    }
}
