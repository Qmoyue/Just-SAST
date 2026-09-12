package io.just.sast.knowledge.engine;

import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.HopKind;
import io.just.sast.analysis.entry.ApplicationEntryIndex;
import io.just.sast.config.Match;
import io.just.sast.config.Rule;
import io.just.sast.cpg.graph.Node;
import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicInteger;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Evidence reversal and sink metadata are stable products, not solver-local string assembly. */
class ForwardEvidenceEmitterContractTest {

    @Test
    void emitsLegacyChainWithDeterministicSinkToEntryOrder() {
        Rule.SinkRule rule = new Rule.SinkRule("sink.rule", "command", "HIGH",
                new Rule.CallMatcher(new Match("app/Sink"), new Match("run"),
                        new Match("(Ljava/lang/String;)V")),
                List.of(new Rule.TaintedPos.Arg(0)));
        Node call = new Node(3, "app/Sink", "run", "(Ljava/lang/String;)V", "VIRTUAL",
                null, 12, "app/Sink", "run", "(Ljava/lang/String;)V");
        ChainHop entry = new ChainHop("app/Entry", "readObject", "app/Mid", "go",
                HopKind.ENTRY, null, "readObject", "()V", null);
        ChainHop sink = new ChainHop("app/Mid", "go", "app/Sink", "run",
                HopKind.DIRECT_CALL, null, "call", "(Ljava/lang/String;)V", 0);

        ForwardEvidenceEmitter.LazyEmission emission = ForwardEvidenceEmitter.emitLazy(
                rule, call, List.of(entry, sink)).orElseThrow();
        Chain chain = emission.materializer().get();
        assertTrue(emission.candidate().matches(chain));
        assertEquals("sink.rule", chain.ruleId());
        assertEquals("app/Entry", chain.entryClass());
        assertEquals("readObject", chain.entryMethod());
        assertEquals("app/Sink", chain.sinkClass());
        assertEquals(List.of(sink, entry), chain.hops());
        assertEquals("TERMINAL", chain.sinkRole());
    }

    @Test
    void malformedEvidenceIsUnknownAndNotEmitted() {
        assertTrue(ForwardEvidenceEmitter.emitLazy(null, null, List.of()).isEmpty());
        assertTrue(ForwardEvidenceEmitter.emitLazy(null, null, null).isEmpty());
    }

    @Test
    void lazyEmissionExposesEndpointBeforeMaterializingReversedChain() {
        Rule.SinkRule rule = new Rule.SinkRule("sink.rule", "command", "HIGH",
                new Rule.CallMatcher(new Match("app/Sink"), new Match("run"),
                        new Match("(Ljava/lang/String;)V")),
                List.of(new Rule.TaintedPos.Arg(0)));
        Node call = new Node(3, "app/Sink", "run", "(Ljava/lang/String;)V", "VIRTUAL",
                null, 12, "app/Mid", "go", "()V");
        ChainHop entry = new ChainHop("app/Entry", "readObject", "app/Mid", "go",
                HopKind.ENTRY, null, "readObject", "()V", null);
        ChainHop sink = new ChainHop("app/Mid", "go", "app/Sink", "run",
                HopKind.DIRECT_CALL, null, "call", "(Ljava/lang/String;)V", 0);

        ForwardEvidenceEmitter.LazyEmission emission = ForwardEvidenceEmitter.emitLazy(
                rule, call, List.of(entry, sink)).orElseThrow();
        ApplicationEntryIndex.ProducerCandidate candidate = emission.candidate();
        assertEquals("app/Entry", candidate.entryOwner());
        assertEquals("()V", candidate.entryDescriptor());
        assertEquals("app/Sink", candidate.terminalOwner());
        assertEquals("(Ljava/lang/String;)V", candidate.terminalDescriptor());
        Chain materialized = emission.materializer().get();
        assertTrue(candidate.matches(materialized));
        assertEquals(List.of(sink, entry), materialized.hops());
    }

    @Test
    void lazyEmissionMaterializerIsSharedAcrossRepeatedAdmissionReads() {
        Rule.SinkRule rule = new Rule.SinkRule("sink.rule", "command", "HIGH",
                new Rule.CallMatcher(new Match("app/Sink"), new Match("run"),
                        new Match("(Ljava/lang/String;)V")),
                List.of(new Rule.TaintedPos.Arg(0)));
        ApplicationEntryIndex.ProducerCandidate candidate =
                new ApplicationEntryIndex.ProducerCandidate(rule.id(), rule.category(),
                        rule.severity(), "app/Entry", "readObject", "()V", "readObject",
                        "app/Sink", "run", "(Ljava/lang/String;)V", rule.role().name(),
                        rule.sinkRisk(), false);
        Chain expected = new Chain(rule.id(), rule.category(), rule.severity(),
                "app/Entry", "readObject", "readObject", "app/Sink", "run", List.of(),
                0, "(Ljava/lang/String;)V", rule.role().name());
        AtomicInteger materializations = new AtomicInteger();
        ForwardEvidenceEmitter.LazyEmission emission =
                new ForwardEvidenceEmitter.LazyEmission(candidate, () -> {
                    materializations.incrementAndGet();
                    return expected;
                });

        assertSame(expected, emission.materializer().get());
        assertSame(expected, emission.materializer().get());
        assertEquals(1, materializations.get());
    }
}
