package io.just.sast.knowledge.fragment;

import io.just.sast.analysis.entry.ApplicationEntryIndex;
import io.just.sast.blackboard.Blackboard;
import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.Event;
import io.just.sast.blackboard.EventType;
import io.just.sast.blackboard.SinkRisk;
import io.just.sast.config.RuleSet;
import io.just.sast.config.YamlRuleLoader;
import io.just.sast.cpg.build.FieldWriterIndex;
import io.just.sast.cpg.graph.Graph;
import io.just.sast.analysis.hierarchy.ClassHierarchy;
import io.just.sast.config.Match;
import io.just.sast.config.Rule;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Contract for fragment producers: endpoint metadata exists before path materialization. */
class FragmentKnowledgeSourceContractTest {

    @Test
    void fragmentProducerDescriptorPreservesRuleAndTerminalMetadata() {
        String sinkDescriptor = "(Ljava/lang/String;)Ljava/lang/Process;";
        Rule.SinkRule rule = new Rule.SinkRule("runtime-exec", "COMMAND", "HIGH",
                new Rule.CallMatcher(Match.of("java/lang/Runtime"), Match.of("exec"),
                        Match.of(sinkDescriptor)), List.of(new Rule.TaintedPos.Arg(0)),
                Rule.SinkRole.TERMINAL, SinkRisk.CONTROLLED_EFFECT);

        ApplicationEntryIndex.ProducerCandidate candidate =
                new ApplicationEntryIndex.ProducerCandidate(rule.id(), rule.category(),
                        rule.severity(), "fixture/gadget/Trigger", "readObject",
                        "(Ljava/io/ObjectInputStream;)V", "readObject", "java/lang/Runtime",
                        "exec", sinkDescriptor, rule.role().name(), rule.sinkRisk(), false);

        assertEquals("runtime-exec", candidate.ruleId());
        assertEquals("fixture/gadget/Trigger", candidate.entryOwner());
        assertEquals("readObject", candidate.entryName());
        assertEquals("readObject", candidate.entryKind());
        assertEquals("(Ljava/io/ObjectInputStream;)V", candidate.entryDescriptor());
        assertEquals("java/lang/Runtime", candidate.terminalOwner());
        assertEquals("exec", candidate.terminalName());
        assertEquals(sinkDescriptor, candidate.terminalDescriptor());
        assertTrue(candidate.sinkRisk() == SinkRisk.CONTROLLED_EFFECT);
    }

    @Test
    void fragmentProducerMaterializerIsSharedAcrossRepeatedAdmissionReads() {
        ApplicationEntryIndex.ProducerCandidate candidate =
                new ApplicationEntryIndex.ProducerCandidate("runtime-exec", "CODE_EXEC", "HIGH",
                        "fixture/gadget/Trigger", "readObject", "()V", "readObject",
                        "java/lang/Runtime", "exec", "(Ljava/lang/String;)Ljava/lang/Process;",
                        "TERMINAL", null, false);
        Chain expected = new Chain("runtime-exec", "CODE_EXEC", "HIGH",
                "fixture/gadget/Trigger", "readObject", "readObject",
                "java/lang/Runtime", "exec", List.of(), 0,
                "(Ljava/lang/String;)Ljava/lang/Process;", "TERMINAL");
        AtomicInteger materializations = new AtomicInteger();
        FragmentKnowledgeSource.FragmentProducer producer =
                new FragmentKnowledgeSource.FragmentProducer(candidate, () -> {
                    materializations.incrementAndGet();
                    return expected;
                });

        assertSame(expected, producer.materializer().get());
        assertSame(expected, producer.materializer().get());
        assertEquals(1, materializations.get());
    }

    @Test
    void defaultMinimalTerminalIsMaterializedAsTypedContinuation() throws Exception {
        String templates = "com/sun/org/apache/xalan/internal/xsltc/trax/TemplatesImpl";
        String descriptor = "()Ljavax/xml/transform/Transformer;";
        RuleSet rules = new YamlRuleLoader().load(Files.newInputStream(
                Path.of("src/main/resources/rules/default-rules.yaml")));
        Graph graph = new Graph();
        graph.methodNode(templates, "newTransformer", descriptor, true);
        graph.freeze();
        Blackboard bb = new Blackboard(graph, new ClassHierarchy(Map.of(), null),
                new FieldWriterIndex(), rules, 20,
                new Blackboard.ScanInputs(Path.of("."), List.of(), false, true, 20,
                        null, 0, false, false, false, null, Set.of("app/Entry"), true));

        FragmentKnowledgeSource source = new FragmentKnowledgeSource();
        source.init(bb);
        source.onEvent(bb,
                Event.of(EventType.SCAN_ANALYZED, -1, null));

        List<Chain> bridgeChains = bb.bridgeChains();
        Blackboard.CompositionInputs lazyInputs = bb.compositionInputsLazy();
        assertTrue(bridgeChains.stream().anyMatch(chain ->
                        templates.equals(chain.entryClass())
                        && descriptor.equals(chain.sinkDescriptor())
                        && chain.hops().size() == 1),
                () -> "bridge=" + bridgeChains + ", app=" + bb.chains()
                        + ", suffix=" + bb.compatibilityDependencySuffixChains()
                        + ", kernel=" + bb.kernelOnlyChains()
                        + ", calibration=" + bb.calibrationCandidates()
                        + ", deferred=" + lazyInputs.deferredDependencySuffixes()
                        + ", metrics=" + bb.solverAdmissionMetrics());
    }
}
