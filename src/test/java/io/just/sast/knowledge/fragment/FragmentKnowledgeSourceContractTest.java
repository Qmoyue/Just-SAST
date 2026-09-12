package io.just.sast.knowledge.fragment;

import io.just.sast.analysis.entry.ApplicationEntryIndex;
import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.SinkRisk;
import io.just.sast.config.Match;
import io.just.sast.config.Rule;
import org.junit.jupiter.api.Test;

import java.util.List;
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
}
