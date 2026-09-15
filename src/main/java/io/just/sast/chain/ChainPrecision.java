package io.just.sast.chain;

import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Function;

/** Stable, reportable precision dimensions for one static candidate chain. */
public final class ChainPrecision {

    public enum Controllability {
        CONCRETE, SEALED_SET, CHA_BOUNDED, POINTS_TO_BOUNDED, UNKNOWN
    }

    /** Static precision dimensions; unknown remains visible and is never treated as SAT. */
    public record Assessment(
            String controllability,
            String dispatchPrecision,
            String fieldPrecision,
            String reflectionPrecision,
            String construction,
            String completeness,
            int rank,
            List<String> reasons) {

        public Assessment {
            controllability = valueOrUnknown(controllability);
            dispatchPrecision = valueOrUnknown(dispatchPrecision);
            fieldPrecision = valueOrUnknown(fieldPrecision);
            reflectionPrecision = valueOrUnknown(reflectionPrecision);
            construction = valueOrUnknown(construction);
            completeness = valueOrUnknown(completeness);
            rank = Math.max(0, rank);
            reasons = reasons == null ? List.of() : List.copyOf(reasons);
        }

        public String compact() {
            return "controllability=" + controllability
                    + ";dispatch=" + dispatchPrecision
                    + ";field=" + fieldPrecision
                    + ";reflection=" + reflectionPrecision
                    + ";construction=" + construction
                    + ";completeness=" + completeness
                    + ";precision_rank=" + rank
                    + (reasons.isEmpty() ? "" : ";reasons=" + String.join("|", reasons));
        }
    }

    private ChainPrecision() {
    }

    public static Assessment assess(Chain chain, List<String> notes) {
        if (chain == null) {
            return new Assessment("UNKNOWN", "UNKNOWN", "UNKNOWN", "UNKNOWN", "UNKNOWN",
                    "UNKNOWN", 99, List.of("NULL_CHAIN"));
        }
        List<String> stableNotes = notes == null ? List.of() : notes;
        List<ChainHop> hops = chain.hops();
        List<String> reasons = new ArrayList<>();
        boolean hasDispatch = false;
        boolean hasReflection = false;
        boolean hasUnknown = chain.unresolvedHops() > 0;
        boolean hasPointFact = false;
        boolean hasExactReceiver = false;
        boolean hasSealedReceiver = false;
        boolean hasChaBoundedReceiver = false;
        boolean hasLambda = false;
        boolean hasNative = false;
        boolean hasField = false;
        boolean exactFields = true;
        boolean reflectiveSink = isReflectiveSink(chain);
        boolean reflectionRecovered = false;
        boolean externalProxyIdentityUnresolved = false;

        for (ChainHop hop : hops) {
            if (hop == null || hop.kind() == null) {
                hasUnknown = true;
                continue;
            }
            String reason = lower(hop.reason());
            if (reason.equals("serialized-proxy-handler")
                    || reason.equals("serialized-proxy-interface")
                    || reason.equals("serialized-proxy-handler-object")) {
                externalProxyIdentityUnresolved = true;
                hasUnknown = true;
                hasReflection = true;
            }
            switch (hop.kind()) {
                case VIRTUAL_DISPATCH -> {
                    hasDispatch = true;
                    if (reason.contains("unknown") || reason.contains("wildcard")
                            || reason.contains("skipped") || reason.contains("budget")) {
                        hasUnknown = true;
                    }
                    if (reason.contains("points-to") || reason.contains("pointsto")) {
                        hasPointFact = true;
                    }
                    if (reason.contains("receiver-exact") || reason.contains("exact-receiver")) {
                        hasExactReceiver = true;
                    }
                    if (reason.contains("receiver-sealed-set")) {
                        hasSealedReceiver = true;
                    }
                    if (reason.contains("receiver-cha-bounded")) {
                        hasChaBoundedReceiver = true;
                    }
                    if (reason.contains("receiver-unknown")) {
                        hasUnknown = true;
                    }
                }
                case LAMBDA -> {
                    hasDispatch = true;
                    hasLambda = true;
                }
                case FIELD_FLOW -> {
                    hasField = true;
                    if (hop.field() == null || hop.field().isBlank()
                            || hop.fieldOwner() == null || hop.fieldOwner().isBlank()) {
                        exactFields = false;
                        hasUnknown = true;
                    }
                }
                case NATIVE_CALLBACK -> {
                    hasDispatch = true;
                    hasNative = true;
                    if (!(reason.contains("same-receiver") || reason.contains("native-callback")
                            || reason.contains("bounded"))) {
                        hasUnknown = true;
                    } else {
                        hasPointFact = true;
                    }
                }
                case DIRECT_CALL, ENTRY -> {
                    // Exact bytecode edges and entry markers need no extra precision label.
                }
            }
            if (reason.contains("reflect") || reason.contains("proxy")
                    || reason.contains("method.invoke") || reason.contains("methodhandle")) {
                hasReflection = true;
                if (reason.contains("unknown") || reason.contains("wildcard")
                        || reason.contains("budget")) {
                    hasUnknown = true;
                } else {
                    reflectionRecovered = true;
                }
            }
        }

        boolean reflectionNote = stableNotes.stream().filter(java.util.Objects::nonNull)
                .map(ChainPrecision::lower)
                .anyMatch(note -> note.contains("reflect") || note.contains("proxy")
                        || note.contains("methodhandle"));
        hasReflection |= reflectionNote || reflectiveSink;
        boolean dispatchBudget = hasBudget(stableNotes, "DISPATCH_BUDGET")
                || hasBudget(stableNotes, "ENTRY_DISPATCH")
                || stableNotes.stream().filter(java.util.Objects::nonNull)
                .map(ChainPrecision::lower).anyMatch(note -> note.contains("dispatchskipped"))
                || hops.stream().filter(java.util.Objects::nonNull)
                .map(hop -> lower(hop.reason()))
                .anyMatch(reason -> reason.contains("dispatch") && reason.contains("budget"));
        boolean reflectionBudget = hasBudget(stableNotes, "REFLECTION_BUDGET")
                || stableNotes.stream().filter(java.util.Objects::nonNull)
                .map(ChainPrecision::lower).anyMatch(note -> note.contains("reflect")
                        && note.contains("budget"));
        if (dispatchBudget || reflectionBudget) {
            hasUnknown = true;
        }

        String controllability;
        if (hasUnknown) {
            controllability = "UNKNOWN";
            reasons.add("UNRESOLVED_OR_BUDGET_BOUND");
        } else if (hasExactReceiver && !hasPointFact && !hasNative) {
            controllability = "CONCRETE";
        } else if (hasSealedReceiver && !hasPointFact && !hasNative) {
            controllability = "SEALED_SET";
        } else if (hasPointFact || hasNative) {
            controllability = "POINTS_TO_BOUNDED";
        } else if (hasLambda || (hasReflection && !hasDispatch)) {
            controllability = "SEALED_SET";
        } else if (hasDispatch) {
            controllability = "CHA_BOUNDED";
        } else {
            controllability = "CONCRETE";
        }

        String dispatch = dispatchPrecision(hops, hasUnknown, hasExactReceiver,
                hasSealedReceiver, hasChaBoundedReceiver, hasPointFact, hasLambda, hasNative);
        String field = !hasField ? "NOT_APPLICABLE"
                : exactFields ? "EXACT_DECLARATION" : "NAME_ONLY";
        reflectionRecovered |= reflectionNote;
        String reflection = !hasReflection ? "NOT_APPLICABLE"
                : reflectionBudget || hasUnknown ? "UNKNOWN"
                : reflectiveSink && !reflectionRecovered ? "SINK_DECLARED_ONLY"
                : "RECOVERED_BOUNDED";
        String construction = construction(stableNotes, chain);
        String completeness = completeness(chain, stableNotes, hasUnknown);

        if (dispatchBudget) {
            reasons.add("DISPATCH_BUDGET");
        }
        if (reflectionBudget) {
            reasons.add("REFLECTION_BUDGET");
        }
        if (!exactFields && hasField) {
            reasons.add("FIELD_OWNER_UNRESOLVED");
        }
        if (reflectiveSink && !reflectionRecovered) {
            reasons.add("REFLECTION_TARGET_NOT_RECOVERED");
        }
        if (externalProxyIdentityUnresolved) {
            reasons.add("EXTERNAL_PROXY_OBJECT_IDENTITY_UNRESOLVED");
        }
        int rank = rank(controllability, dispatch, field, reflection, construction, completeness);
        return new Assessment(controllability, dispatch, field, reflection, construction,
                completeness, rank, stableUnique(reasons));
    }

    /** Static high-confidence gate used only as a presentation aid, never as export authority. */
    public static boolean isHighConfidence(Chain chain, List<String> notes) {
        if (chain == null || chain.unresolvedHops() != 0) {
            return false;
        }
        Assessment assessment = assess(chain, notes);
        return "COMPLETE".equals(assessment.completeness())
                && !"UNKNOWN".equals(assessment.controllability())
                && !"UNKNOWN".equals(assessment.dispatchPrecision())
                && !"UNKNOWN".equals(assessment.fieldPrecision())
                && !"UNKNOWN".equals(assessment.reflectionPrecision())
                && !"SINK_DECLARED_ONLY".equals(assessment.reflectionPrecision())
                && !"UNKNOWN".equals(assessment.construction())
                && !"PARTIAL".equals(assessment.construction())
                && !"PLAN_PARTIAL".equals(assessment.construction());
    }

    public static String toJson(Assessment assessment, Function<String, String> escape) {
        return toJson(assessment, escape, false);
    }

    public static String toJson(Assessment assessment, Function<String, String> escape,
                                boolean highConfidence) {
        Assessment value = assessment == null ? assess(null, List.of()) : assessment;
        Function<String, String> esc = escape == null ? Function.identity() : escape;
        StringBuilder json = new StringBuilder("{")
                .append("\"controllability\":\"").append(esc.apply(value.controllability()))
                .append("\",\"dispatch_precision\":\"").append(esc.apply(value.dispatchPrecision()))
                .append("\",\"field_precision\":\"").append(esc.apply(value.fieldPrecision()))
                .append("\",\"reflection_precision\":\"").append(esc.apply(value.reflectionPrecision()))
                .append("\",\"construction\":\"").append(esc.apply(value.construction()))
                .append("\",\"completeness\":\"").append(esc.apply(value.completeness()))
                .append("\",\"rank\":").append(value.rank())
                .append(",\"high_confidence\":").append(highConfidence)
                .append(",\"reasons\":[");
        for (int i = 0; i < value.reasons().size(); i++) {
            if (i > 0) {
                json.append(',');
            }
            json.append('"').append(esc.apply(value.reasons().get(i))).append('"');
        }
        return json.append("]}").toString();
    }

    private static String dispatchPrecision(List<ChainHop> hops, boolean unknown,
                                             boolean exactReceiver, boolean sealedReceiver,
                                             boolean chaBoundedReceiver, boolean points,
                                             boolean lambda, boolean nativeCallback) {
        if (unknown) return "UNKNOWN";
        if (exactReceiver) return "RECEIVER_EXACT";
        if (sealedReceiver) return "SEALED_SET";
        if (points || nativeCallback) return "POINTS_TO_BOUNDED";
        if (lambda) return "LAMBDA_EXACT";
        boolean dispatch = hops.stream().anyMatch(hop -> hop != null
                && (hop.kind() == io.just.sast.blackboard.HopKind.VIRTUAL_DISPATCH
                || hop.kind() == io.just.sast.blackboard.HopKind.NATIVE_CALLBACK
                || hop.kind() == io.just.sast.blackboard.HopKind.LAMBDA));
        return dispatch || chaBoundedReceiver ? "CHA_BOUNDED" : "EXACT";
    }

    private static String construction(List<String> notes, Chain chain) {
        if (notes.stream().anyMatch("static:constructible"::equals)) {
            return "CONSTRUCTIBLE";
        }
        if (notes.stream().anyMatch("degrade:partial-construct"::equals)) {
            return "PARTIAL";
        }
        if (chain.constructionPlan() != null && !chain.constructionPlan().isEmpty()) {
            return chain.constructionPlan().shapeSummary().valid() ? "DECLARED_PLAN" : "PLAN_PARTIAL";
        }
        return "UNKNOWN";
    }

    private static String completeness(Chain chain, List<String> notes, boolean unknown) {
        boolean degraded = notes.stream().filter(java.util.Objects::nonNull)
                .anyMatch(note -> note.startsWith("degrade:") || note.contains("BUDGET"));
        if (!unknown && chain.unresolvedHops() == 0 && !degraded) {
            return "COMPLETE";
        }
        return degraded || unknown ? "PARTIAL" : "COMPLETE";
    }

    private static int rank(String controllability, String dispatch, String field,
                            String reflection, String construction, String completeness) {
        int value = 0;
        value += rankOf(controllability, "CONCRETE", "SEALED_SET", "POINTS_TO_BOUNDED",
                "CHA_BOUNDED", "UNKNOWN");
        value += rankOf(dispatch, "EXACT", "RECEIVER_EXACT", "SEALED_SET", "LAMBDA_EXACT",
                "POINTS_TO_BOUNDED", "RECOVERED_BOUNDED", "CHA_BOUNDED", "UNKNOWN");
        value += switch (field) {
            case "NOT_APPLICABLE", "EXACT_DECLARATION" -> 0;
            case "NAME_ONLY" -> 1;
            case "UNKNOWN" -> 2;
            default -> 3;
        };
        value += switch (reflection) {
            case "NOT_APPLICABLE" -> 0;
            case "RECOVERED_BOUNDED" -> 1;
            case "SINK_DECLARED_ONLY" -> 2;
            case "UNKNOWN" -> 3;
            default -> 4;
        };
        value += rankOf(construction, "CONSTRUCTIBLE", "DECLARED_PLAN", "PARTIAL",
                "PLAN_PARTIAL", "UNKNOWN");
        value += rankOf(completeness, "COMPLETE", "PARTIAL", "UNKNOWN");
        return value;
    }

    private static int rankOf(String actual, String... ordered) {
        for (int i = 0; i < ordered.length; i++) {
            if (ordered[i].equals(actual)) return i;
        }
        return ordered.length;
    }

    private static boolean hasBudget(List<String> notes, String prefix) {
        return notes.stream().filter(java.util.Objects::nonNull).map(ChainPrecision::lower)
                .anyMatch(note -> note.contains(prefix.toLowerCase()));
    }

    private static boolean isReflectiveSink(Chain chain) {
        String owner = lower(chain.sinkClass());
        String method = lower(chain.sinkMethod());
        String category = lower(chain.category());
        return owner.startsWith("java/lang/reflect/") || owner.contains("methodhandle")
                || ("invoke".equals(method) && category.contains("reflect"));
    }

    private static List<String> stableUnique(List<String> values) {
        Set<String> unique = new LinkedHashSet<>(values);
        return unique.stream().sorted(Comparator.naturalOrder()).toList();
    }

    private static String lower(String value) {
        return value == null ? "" : value.toLowerCase(java.util.Locale.ROOT);
    }

    private static String valueOrUnknown(String value) {
        return value == null || value.isBlank() ? "UNKNOWN" : value;
    }
}
