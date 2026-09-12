package io.just.sast.knowledge.engine;

import io.just.sast.analysis.entry.ApplicationEntryIndex;
import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.config.Rule;
import io.just.sast.config.RuleSchemaV2;
import io.just.sast.cpg.graph.Node;
import io.just.sast.util.ChainMaterializer;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Supplier;

/**
 * Pure translation from a forward source-to-sink path to the legacy sink-to-entry Chain product.
 * Blackboard insertion, ranking and dynamic verification remain outside this owner.  Keeping
 * the reversal and entry metadata in one place prevents individual solver branches from
 * inventing subtly different evidence shapes.
 */
public final class ForwardEvidenceEmitter {
    private ForwardEvidenceEmitter() {
    }

    /** A typed endpoint admission plus the deferred path-to-Chain materializer. */
    public record LazyEmission(ApplicationEntryIndex.ProducerCandidate candidate,
                               Supplier<Chain> materializer) {
        public LazyEmission {
            candidate = Objects.requireNonNull(candidate, "candidate");
            materializer = ChainMaterializer.memoize(Objects.requireNonNull(materializer, "materializer"));
        }
    }

    /**
     * Build only endpoint metadata now; reversal, hop copying and Chain construction are
     * deferred until the blackboard's producer admission accepts the candidate.
     */
    public static Optional<LazyEmission> emitLazy(Rule.SinkRule rule, Node call,
                                                   List<ChainHop> forwardPath) {
        if (call == null) {
            return Optional.empty();
        }
        return emitLazy(rule, call.owner(), call.name(), call.descriptor(), forwardPath, 0);
    }

    /** Variant used for resolved reflective targets without a CALL node. */
    public static Optional<LazyEmission> emitLazy(Rule.SinkRule rule, String sinkOwner,
                                                   String sinkName, String sinkDescriptor,
                                                   List<ChainHop> forwardPath,
                                                   int unresolvedHops) {
        return emitLazy(rule, sinkOwner, sinkName, sinkDescriptor, forwardPath, unresolvedHops,
                false);
    }

    /** Variant for sinks reached through a typed semantic edge absent from the ordinary CPG. */
    public static Optional<LazyEmission> emitLazy(Rule.SinkRule rule, String sinkOwner,
                                                   String sinkName, String sinkDescriptor,
                                                   List<ChainHop> forwardPath,
                                                   int unresolvedHops,
                                                   boolean semanticContinuation) {
        if (rule == null || sinkOwner == null || sinkName == null || sinkDescriptor == null
                || forwardPath == null || forwardPath.isEmpty()
                || forwardPath.stream().anyMatch(java.util.Objects::isNull)) {
            return Optional.empty();
        }
        int forwardPathSize = forwardPath.size();
        ChainHop entry = forwardPath.get(0);
        String entryKind = entry.reason() == null ? "?" : entry.reason();
        boolean continuation = semanticContinuation
                || ApplicationEntryIndex.hasTypedContinuationEvidence(forwardPath)
                || (!RuleSchemaV2.isTerminalSink(rule)
                && !RuleSchemaV2.bridgesFor(rule).isEmpty());
        ApplicationEntryIndex.ProducerCandidate candidate =
                new ApplicationEntryIndex.ProducerCandidate(rule.id(), rule.category(),
                        rule.severity(), entry.fromOwner(), entry.fromName(),
                        entry.desc(), entryKind, sinkOwner, sinkName, sinkDescriptor,
                        rule.role().name(), rule.sinkRisk(), continuation);
        Supplier<Chain> materializer = () -> {
            if (forwardPath.size() != forwardPathSize) {
                return null;
            }
            List<ChainHop> hops = new ArrayList<>(forwardPath);
            Collections.reverse(hops);
            ChainHop materializedEntry = hops.get(hops.size() - 1);
            return new Chain(rule.id(), rule.category(), rule.severity(),
                    materializedEntry.fromOwner(), materializedEntry.fromName(),
                    materializedEntry.reason() == null ? "?" : materializedEntry.reason(),
                    sinkOwner, sinkName, hops, Math.max(0, unresolvedHops), sinkDescriptor,
                    rule.role().name(), null, rule.sinkRisk());
        };
        return Optional.of(new LazyEmission(candidate, materializer));
    }
}
