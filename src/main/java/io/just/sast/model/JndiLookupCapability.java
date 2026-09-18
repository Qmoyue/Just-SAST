package io.just.sast.model;

import java.util.List;
import java.util.Objects;

/**
 * Immutable capability-boundary fact for one exact JNDI lookup or search call site.
 *
 * <p>A lookup URL/name is not a provider or terminal fact.  A known value therefore remains a
 * capability-only boundary, while an unknown value remains capability-only without inventing a
 * provider.  A broken same-method identity flow is kept as PARTIAL or UNKNOWN so a consumer
 * cannot silently promote an incomplete JNDI fragment into a complete chain.</p>
 */
public record JndiLookupCapability(
        JndiLookupCallSite callSite,
        List<JndiLookupIdentityFlow> identityFlows,
        Status status,
        Reason reason) {

    public static final String GRAPH_NOTE_KEY = "jndiLookupCapability";

    public enum Status {
        CAPABILITY_ONLY,
        PARTIAL,
        UNKNOWN
    }

    public enum Reason {
        LOOKUP_PROVIDER_NOT_RESOLVED,
        LOOKUP_URL_UNKNOWN,
        LOOKUP_URL_NULL,
        SEARCH_CAPABILITY_ONLY,
        LOOKUP_SEARCH_FLOW_MISSING,
        VALUE_FLOW_INCOMPLETE,
        IDENTITY_FLOW_UNKNOWN,
        IDENTITY_FLOW_AMBIGUOUS
    }

    public JndiLookupCapability {
        callSite = Objects.requireNonNull(callSite, "JNDI capability call site");
        identityFlows = List.copyOf(Objects.requireNonNull(identityFlows,
                "JNDI capability identity flows"));
        status = Objects.requireNonNull(status, "JNDI capability status");
        reason = Objects.requireNonNull(reason, "JNDI capability reason");
        for (JndiLookupIdentityFlow flow : identityFlows) {
            validateRelatedFlow(callSite, Objects.requireNonNull(flow,
                    "JNDI capability identity flow"));
        }
        Decision expected = decide(callSite, identityFlows);
        if (status != expected.status() || reason != expected.reason()) {
            throw new IllegalArgumentException(
                    "JNDI capability status does not match typed boundaries");
        }
    }

    /** Classify one exact JNDI call without resolving or executing a provider. */
    public static JndiLookupCapability classify(JndiLookupCallSite callSite,
                                                 List<JndiLookupIdentityFlow> identityFlows) {
        Objects.requireNonNull(callSite, "JNDI capability call site");
        List<JndiLookupIdentityFlow> flows = List.copyOf(Objects.requireNonNull(identityFlows,
                "JNDI capability identity flows"));
        Decision decision = decide(callSite, flows);
        return new JndiLookupCapability(callSite, flows, decision.status(), decision.reason());
    }

    public boolean capabilityOnly() {
        return status == Status.CAPABILITY_ONLY;
    }

    public String identity() {
        return "jndi-capability-v1|" + callSite.identity() + "|"
                + identityFlows.stream().map(JndiLookupIdentityFlow::identity).sorted().toList()
                + "|" + status + "|" + reason;
    }

    private static Decision decide(JndiLookupCallSite callSite,
                                   List<JndiLookupIdentityFlow> identityFlows) {
        if (incomplete(callSite)) {
            return new Decision(Status.PARTIAL, Reason.VALUE_FLOW_INCOMPLETE);
        }
        if (callSite.kind() == JndiLookupCallSite.Kind.INITIAL_CONTEXT_LOOKUP) {
            return switch (callSite.argument(0).value().state()) {
                case KNOWN -> new Decision(Status.CAPABILITY_ONLY,
                        Reason.LOOKUP_PROVIDER_NOT_RESOLVED);
                case UNKNOWN -> new Decision(Status.CAPABILITY_ONLY, Reason.LOOKUP_URL_UNKNOWN);
                case NULL -> new Decision(Status.PARTIAL, Reason.LOOKUP_URL_NULL);
            };
        }
        if (identityFlows.isEmpty()) {
            return new Decision(Status.PARTIAL, Reason.LOOKUP_SEARCH_FLOW_MISSING);
        }
        long partial = identityFlows.stream()
                .filter(flow -> flow.status() == JndiLookupIdentityFlow.Status.PARTIAL)
                .count();
        if (partial > 0) {
            return new Decision(Status.PARTIAL, Reason.VALUE_FLOW_INCOMPLETE);
        }
        long proved = identityFlows.stream()
                .filter(JndiLookupIdentityFlow::proved)
                .count();
        if (proved == identityFlows.size()) {
            return new Decision(Status.CAPABILITY_ONLY, Reason.SEARCH_CAPABILITY_ONLY);
        }
        return new Decision(Status.UNKNOWN,
                proved == 0 ? Reason.IDENTITY_FLOW_UNKNOWN : Reason.IDENTITY_FLOW_AMBIGUOUS);
    }

    private static boolean incomplete(JndiLookupCallSite callSite) {
        return callSite.values().stream().anyMatch(value -> value.value().producerOffset() < 0);
    }

    private static void validateRelatedFlow(JndiLookupCallSite callSite,
                                             JndiLookupIdentityFlow flow) {
        boolean related = callSite.kind() == JndiLookupCallSite.Kind.INITIAL_CONTEXT_LOOKUP
                ? callSite.identity().equals(flow.lookup().identity())
                : callSite.identity().equals(flow.search().identity());
        if (!related) {
            throw new IllegalArgumentException("JNDI capability flow is unrelated to call site");
        }
    }

    private record Decision(Status status, Reason reason) {
    }
}
