package io.just.sast.knowledge.backward;

import io.just.sast.analysis.entry.ApplicationEntryIndex;
import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.SinkRisk;
import io.just.sast.config.Match;
import io.just.sast.config.Rule;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;

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
}
