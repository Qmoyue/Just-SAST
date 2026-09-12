package io.just.sast.knowledge.framework;

import io.just.sast.analysis.entry.ApplicationEntryIndex;
import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.SinkRisk;
import io.just.sast.config.Match;
import io.just.sast.config.Rule;
import io.just.sast.cpg.graph.Node;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Contract for framework bridge producers: typed endpoints exist before path materialization. */
class FrameworkBridgeKnowledgeSourceContractTest {

    @Test
    void frameworkProducerDescriptorPreservesBridgeAndTerminalMetadata() {
        String sinkDescriptor = "(Ljava/lang/Object;)Ljava/lang/Object;";
        Rule.SinkRule rule = new Rule.SinkRule("reflective-invoke", "REFLECTION", "HIGH",
                new Rule.CallMatcher(Match.of("java/lang/reflect/Method"), Match.of("invoke"),
                        Match.of(sinkDescriptor)), List.of(new Rule.TaintedPos.Arg(0)),
                Rule.SinkRole.CAPABILITY, SinkRisk.CONTROLLED_EFFECT);

        ApplicationEntryIndex.ProducerCandidate candidate =
                new ApplicationEntryIndex.ProducerCandidate(rule.id(), rule.category(),
                        rule.severity(), "fixture/app/Deserializer", "read", "()V",
                        "deserialize", "java/lang/reflect/Method", "invoke", sinkDescriptor,
                        rule.role().name(), rule.sinkRisk(), true);

        assertEquals("fixture/app/Deserializer", candidate.entryOwner());
        assertEquals("read", candidate.entryName());
        assertEquals("deserialize", candidate.entryKind());
        assertEquals("java/lang/reflect/Method", candidate.terminalOwner());
        assertEquals("invoke", candidate.terminalName());
        assertEquals(sinkDescriptor, candidate.terminalDescriptor());
        assertTrue(candidate.continuationEvidence());
    }

    @Test
    void frameworkPathIsDeferredAndSharedAfterAdmission() {
        Node start = new Node(1, "fixture/app", "read", "()V", "VIRTUAL",
                null, 1, "fixture/framework", "decode", "()V");
        Node sinkCaller = new Node(2, "fixture/framework", "decode", "()V", "VIRTUAL",
                null, 2, "java/lang/reflect/Method", "invoke", "()V");
        AtomicInteger materializations = new AtomicInteger();
        FrameworkBridgeKnowledgeSource.DeferredFrameworkPath deferred =
                new FrameworkBridgeKnowledgeSource.DeferredFrameworkPath(
                        sinkCaller, 2, () -> {
                            materializations.incrementAndGet();
                            return List.of(start, sinkCaller);
                        });

        assertEquals(2, deferred.pathSize());
        assertEquals(0, materializations.get());
        assertEquals(List.of(start, sinkCaller), deferred.materializer().get());
        assertEquals(List.of(start, sinkCaller), deferred.materializer().get());
        assertEquals(1, materializations.get());
    }

    @Test
    void frameworkPathFailureIsMemoizedAndFailClosed() {
        Node sinkCaller = new Node(3, "fixture/framework", "decode", "()V", "VIRTUAL",
                null, 3, "java/lang/reflect/Method", "invoke", "()V");
        AtomicInteger materializations = new AtomicInteger();
        RuntimeException expected = new IllegalStateException("framework path unavailable");
        FrameworkBridgeKnowledgeSource.DeferredFrameworkPath deferred =
                new FrameworkBridgeKnowledgeSource.DeferredFrameworkPath(
                        sinkCaller, 1, () -> {
                            materializations.incrementAndGet();
                            throw expected;
                        });

        RuntimeException first = assertThrows(RuntimeException.class,
                () -> deferred.materializer().get());
        RuntimeException second = assertThrows(RuntimeException.class,
                () -> deferred.materializer().get());

        assertSame(expected, first);
        assertSame(expected, second);
        assertEquals(1, materializations.get());
    }

    @Test
    void frameworkProducerMaterializerIsSharedAcrossRepeatedAdmissionReads() {
        ApplicationEntryIndex.ProducerCandidate candidate =
                new ApplicationEntryIndex.ProducerCandidate("reflective-invoke", "REFLECTION", "HIGH",
                        "fixture/app/Deserializer", "read", "()V", "deserialize",
                        "java/lang/reflect/Method", "invoke", "(Ljava/lang/Object;)Ljava/lang/Object;",
                        "CAPABILITY", null, true);
        Chain expected = new Chain("reflective-invoke", "REFLECTION", "HIGH",
                "fixture/app/Deserializer", "read", "deserialize",
                "java/lang/reflect/Method", "invoke", List.of(), 0,
                "(Ljava/lang/Object;)Ljava/lang/Object;", "CAPABILITY");
        AtomicInteger materializations = new AtomicInteger();
        FrameworkBridgeKnowledgeSource.FrameworkProducer producer =
                new FrameworkBridgeKnowledgeSource.FrameworkProducer(candidate, () -> {
                    materializations.incrementAndGet();
                    return expected;
                });

        assertSame(expected, producer.materializer().get());
        assertSame(expected, producer.materializer().get());
        assertEquals(1, materializations.get());
    }
}
