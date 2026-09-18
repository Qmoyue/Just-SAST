package io.just.sast.model;

import java.util.Objects;

/**
 * Same-method identity continuity from an InitialContext lookup result to a DirContext search.
 *
 * <p>The result of lookup may be statically unknown as a value, but its physical flow token is
 * still sufficient to prove that a later search receiver is the same value when the token is
 * retained through locals, aliases, or a cast.  URL text, search arguments, class names, and
 * target-provider behavior are deliberately outside this owner.</p>
 */
public record JndiLookupIdentityFlow(
        JndiLookupCallSite lookup,
        JndiLookupCallSite search,
        Status status,
        Reason reason) {

    public static final String GRAPH_NOTE_KEY = "jndiLookupIdentityFlow";

    public enum Status {
        PROVED,
        UNKNOWN
    }

    public enum Reason {
        NONE,
        LOOKUP_SEARCH_IDENTITY_MISMATCH
    }

    public JndiLookupIdentityFlow {
        lookup = Objects.requireNonNull(lookup, "JNDI lookup fact");
        search = Objects.requireNonNull(search, "JNDI search fact");
        status = Objects.requireNonNull(status, "JNDI identity-flow status");
        reason = Objects.requireNonNull(reason, "JNDI identity-flow reason");
        if (lookup.kind() != JndiLookupCallSite.Kind.INITIAL_CONTEXT_LOOKUP) {
            throw new IllegalArgumentException("JNDI identity-flow source must be InitialContext.lookup");
        }
        if (search.kind() != JndiLookupCallSite.Kind.DIR_CONTEXT_SEARCH) {
            throw new IllegalArgumentException("JNDI identity-flow sink must be DirContext.search");
        }
        Decision expected = decide(lookup, search);
        if (status != expected.status() || reason != expected.reason()) {
            throw new IllegalArgumentException("JNDI identity-flow status does not match identities");
        }
    }

    /** Join only the exact lookup result and search receiver identities. */
    public static JndiLookupIdentityFlow connect(JndiLookupCallSite lookup,
                                                  JndiLookupCallSite search) {
        Objects.requireNonNull(lookup, "JNDI lookup fact");
        Objects.requireNonNull(search, "JNDI search fact");
        Decision decision = decide(lookup, search);
        return new JndiLookupIdentityFlow(lookup, search, decision.status(), decision.reason());
    }

    public boolean proved() {
        return status == Status.PROVED;
    }

    public String identity() {
        return "jndi-identity-flow-v1|" + lookup.identity() + "|" + search.identity()
                + "|" + status + "|" + reason;
    }

    private static Decision decide(JndiLookupCallSite lookup, JndiLookupCallSite search) {
        String lookupResult = lookup.returnValue().orElseThrow(
                () -> new IllegalArgumentException("JNDI lookup result slot is missing"))
                .value().token();
        String searchReceiver = search.receiver().value().token();
        if (lookupResult.equals(searchReceiver)) {
            return new Decision(Status.PROVED, Reason.NONE);
        }
        return new Decision(Status.UNKNOWN, Reason.LOOKUP_SEARCH_IDENTITY_MISMATCH);
    }

    private record Decision(Status status, Reason reason) {
    }
}
