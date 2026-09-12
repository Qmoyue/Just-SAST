package io.just.sast.analysis.taint;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * Immutable method-level provenance product.
 *
 * <p>The wrapped forward result is already frozen by {@link ForwardOrigins.Result}.  This
 * type adds the method identity and a small deterministic telemetry projection so downstream
 * consumers do not need to know how the cache stores or computes a result.</p>
 */
public record OriginSummary(String methodKey, ForwardOrigins.Result result,
                            int stateCount, int arrayRelationCount,
                            int indexedArrayRelationCount, int containerRelationCount,
                            boolean complete, Set<String> unresolvedReasons) {

    public OriginSummary {
        methodKey = methodKey == null ? "" : methodKey.trim();
        result = result == null
                ? new ForwardOrigins.Result(Map.of(), Map.of(), Map.of(), Map.of(),
                true, Set.of("MISSING_ORIGIN_RESULT"))
                : result;
        stateCount = Math.max(0, stateCount);
        arrayRelationCount = Math.max(0, arrayRelationCount);
        indexedArrayRelationCount = Math.max(0, indexedArrayRelationCount);
        containerRelationCount = Math.max(0, containerRelationCount);
        LinkedHashSet<String> ordered = new LinkedHashSet<>();
        if (unresolvedReasons != null) {
            unresolvedReasons.stream().filter(value -> value != null && !value.isBlank())
                    .sorted().forEach(ordered::add);
        }
        unresolvedReasons = ordered.isEmpty()
                ? Set.of() : Collections.unmodifiableSet(ordered);
        complete = complete && !result.incomplete() && unresolvedReasons.isEmpty();
    }

    public String canonical() {
        return "origin-summary-v1:" + methodKey
                + "|states=" + stateCount
                + "|arrays=" + arrayRelationCount
                + "|indexed=" + indexedArrayRelationCount
                + "|containers=" + containerRelationCount
                + "|complete=" + complete
                + "|reasons=" + String.join(",", unresolvedReasons);
    }
}
