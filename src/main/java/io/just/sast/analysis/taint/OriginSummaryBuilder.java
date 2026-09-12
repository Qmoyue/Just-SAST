package io.just.sast.analysis.taint;

import io.just.sast.model.MethodInfo;

import java.util.Map;
import java.util.Set;

/** Sole owner for constructing immutable origin summaries from forward facts. */
public final class OriginSummaryBuilder {

    private OriginSummaryBuilder() {
    }

    public static OriginSummary build(MethodInfo method, ForwardOrigins.Result result) {
        String methodKey = method == null ? "" : OriginSupport.methodKey(method);
        return build(methodKey, result);
    }

    public static OriginSummary build(String methodKey, ForwardOrigins.Result result) {
        if (result == null) {
            return new OriginSummary(methodKey, null, 0, 0, 0, 0, false,
                    Set.of("MISSING_ORIGIN_RESULT"));
        }
        return new OriginSummary(methodKey, result,
                result.stateBefore().size(),
                result.arrayElements().size(),
                result.indexedArrayElements().size(),
                result.containerElements().size(),
                !result.incomplete(),
                result.incompleteReasons());
    }
}
