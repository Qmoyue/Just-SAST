package io.just.sast.knowledge.ois;

import io.just.sast.analysis.entry.ApplicationEntryIndex;
import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.SinkRisk;
import io.just.sast.config.Match;
import io.just.sast.config.Rule;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.HopKind;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.List;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;

/** Contract for callback producers: endpoint admission metadata is available before Chain creation. */
class DeserializationCallbackKnowledgeSourceContractTest {

    @Test
    void callbackProducerDescriptorIsIndependentOfMaterializedChain() {
        String sinkDescriptor = "(Ljava/lang/String;)Ljava/lang/Process;";
        Rule.SinkRule rule = new Rule.SinkRule("runtime-exec", "COMMAND", "HIGH",
                new Rule.CallMatcher(Match.of("java/lang/Runtime"), Match.of("exec"),
                        Match.of(sinkDescriptor)), List.of(new Rule.TaintedPos.Arg(0)),
                Rule.SinkRole.TERMINAL, SinkRisk.CONTROLLED_EFFECT);
        ApplicationEntryIndex.ProducerCandidate candidate =
                new ApplicationEntryIndex.ProducerCandidate(rule.id(), rule.category(), rule.severity(),
                        "fixture/app/Callback", "resolveClass", "(Ljava/io/ObjectStreamClass;)Ljava/lang/Class;",
                        "deserialization", "java/lang/Runtime", "exec", sinkDescriptor,
                        rule.role().name(), rule.sinkRisk(), false);

        assertEquals("fixture/app/Callback", candidate.entryOwner());
        assertEquals("resolveClass", candidate.entryName());
        assertEquals("deserialization", candidate.entryKind());
        assertEquals("java/lang/Runtime", candidate.terminalOwner());
        assertEquals(sinkDescriptor, candidate.terminalDescriptor());
        assertFalse(candidate.continuationEvidence());
    }

    @Test
    void callbackMachineryPathIsDeferredAndSharedAfterAdmission() {
        AtomicInteger materializations = new AtomicInteger();
        DeserializationCallbackKnowledgeSource.DeferredMachinery machinery =
                new DeserializationCallbackKnowledgeSource.DeferredMachinery(1, () -> {
                    materializations.incrementAndGet();
                    return List.of(new ChainHop("java/io/ObjectInputStream", "readObject",
                            "fixture/app/Callback", "resolveClass", HopKind.DIRECT_CALL,
                            null, "machinery", "()V", null));
                });

        assertEquals(1, machinery.hopCount());
        assertEquals(0, materializations.get(),
                "candidate admission metadata must not build callback machinery");
        List<ChainHop> first = machinery.materializer().get();
        List<ChainHop> second = machinery.materializer().get();
        assertEquals(first, second, "one resolver path must be shared by its admitted candidates");
        assertEquals(1, materializations.get(),
                "the deferred callback path should be materialized at most once");
    }

    @Test
    void callbackMachineryFailureIsMemoizedAndRemainsFailClosed() {
        AtomicInteger attempts = new AtomicInteger();
        RuntimeException failure = new IllegalStateException("path unavailable");
        DeserializationCallbackKnowledgeSource.DeferredMachinery machinery =
                new DeserializationCallbackKnowledgeSource.DeferredMachinery(1, () -> {
                    attempts.incrementAndGet();
                    throw failure;
                });

        RuntimeException first = assertThrows(RuntimeException.class,
                () -> machinery.materializer().get());
        RuntimeException second = assertThrows(RuntimeException.class,
                () -> machinery.materializer().get());
        assertSame(failure, first, "the first failure must remain typed and observable");
        assertSame(failure, second, "repeated reads must reuse the fail-closed result");
        assertEquals(1, attempts.get(),
                "a failed callback path must not rerun for every admitted candidate");
    }

    @Test
    void callbackMachineryNullPathIsMemoizedWithoutMaterializationDrift() {
        AtomicInteger attempts = new AtomicInteger();
        DeserializationCallbackKnowledgeSource.DeferredMachinery machinery =
                new DeserializationCallbackKnowledgeSource.DeferredMachinery(0, () -> {
                    attempts.incrementAndGet();
                    return null;
                });

        assertNull(machinery.materializer().get());
        assertNull(machinery.materializer().get());
        assertEquals(1, attempts.get(),
                "an unavailable callback path must be remembered as a typed null");
    }

    @Test
    void callbackProducerMaterializerIsSharedAcrossRepeatedAdmissionReads() {
        ApplicationEntryIndex.ProducerCandidate candidate =
                new ApplicationEntryIndex.ProducerCandidate("runtime-exec", "CODE_EXEC", "HIGH",
                        "fixture/app/Callback", "resolveClass", "()V", "deserialization",
                        "java/lang/Runtime", "exec", "(Ljava/lang/String;)Ljava/lang/Process;",
                        "TERMINAL", null, false);
        Chain expected = new Chain("runtime-exec", "CODE_EXEC", "HIGH",
                "fixture/app/Callback", "resolveClass", "deserialization",
                "java/lang/Runtime", "exec", List.of(), 0,
                "(Ljava/lang/String;)Ljava/lang/Process;", "TERMINAL");
        AtomicInteger materializations = new AtomicInteger();
        DeserializationCallbackKnowledgeSource.CallbackProducer producer =
                new DeserializationCallbackKnowledgeSource.CallbackProducer(candidate, () -> {
                    materializations.incrementAndGet();
                    return expected;
                });

        assertSame(expected, producer.materializer().get());
        assertSame(expected, producer.materializer().get());
        assertEquals(1, materializations.get());
    }
}
