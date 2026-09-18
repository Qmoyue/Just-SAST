package io.just.sast.model;

import java.util.Objects;

/**
 * Same-method propagation from an exact {@code DirContext.search} result to an enumeration
 * consumer.
 *
 * <p>The enumeration receiver must retain the physical search-result identity.  An element
 * returned by the exact {@code next}/{@code nextElement} API is retained only as a declared
 * enumeration contract; it is not treated as the same object and it is never obtained by
 * executing the target provider.  This keeps container identity and element derivation separate
 * while making incomplete or mismatched bytecode visible.</p>
 */
public record JndiSearchReturnFlow(
        JndiLookupCallSite search,
        JndiNamingEnumerationCallSite consumer,
        Relation relation,
        Status status,
        Reason reason) {

    public static final String GRAPH_NOTE_KEY = "jndiSearchReturnFlow";

    public enum Relation {
        SAME_IDENTITY,
        DECLARED_CONTRACT,
        UNKNOWN
    }

    public enum Status {
        PROVED,
        PARTIAL,
        UNKNOWN
    }

    public enum Reason {
        NONE,
        VALUE_FLOW_INCOMPLETE,
        SEARCH_RETURN_DESCRIPTOR_MISMATCH,
        CONSUMER_RECEIVER_DESCRIPTOR_MISMATCH,
        CONSUMER_RESULT_DESCRIPTOR_MISMATCH,
        SEARCH_CONSUMER_IDENTITY_MISMATCH
    }

    public JndiSearchReturnFlow {
        search = Objects.requireNonNull(search, "JNDI search fact");
        consumer = Objects.requireNonNull(consumer, "JNDI enumeration consumer");
        relation = Objects.requireNonNull(relation, "JNDI search-return relation");
        status = Objects.requireNonNull(status, "JNDI search-return status");
        reason = Objects.requireNonNull(reason, "JNDI search-return reason");
        if (search.kind() != JndiLookupCallSite.Kind.DIR_CONTEXT_SEARCH) {
            throw new IllegalArgumentException("JNDI search-return producer must be DirContext.search");
        }
        Decision expected = decide(search, consumer);
        if (relation != expected.relation() || status != expected.status()
                || reason != expected.reason()) {
            throw new IllegalArgumentException(
                    "JNDI search-return status does not match typed propagation boundary");
        }
    }

    /** Connect only the exact search result to one exact enumeration consumer. */
    public static JndiSearchReturnFlow connect(JndiLookupCallSite search,
                                               JndiNamingEnumerationCallSite consumer) {
        Objects.requireNonNull(search, "JNDI search fact");
        Objects.requireNonNull(consumer, "JNDI enumeration consumer");
        Decision decision = decide(search, consumer);
        return new JndiSearchReturnFlow(search, consumer, decision.relation(), decision.status(),
                decision.reason());
    }

    public boolean proved() {
        return status == Status.PROVED;
    }

    public boolean declaredContract() {
        return relation == Relation.DECLARED_CONTRACT && proved();
    }

    public String identity() {
        return "jndi-search-return-v1|" + search.identity() + "|" + consumer.identity()
                + "|" + relation + "|" + status + "|" + reason;
    }

    private static Decision decide(JndiLookupCallSite search,
                                   JndiNamingEnumerationCallSite consumer) {
        JndiLookupCallSite.ValueIdentity searchResult = search.returnValue().orElseThrow(
                () -> new IllegalArgumentException("JNDI search result slot is missing"))
                .value();
        JndiLookupCallSite.ValueIdentity receiver = consumer.receiver().value();
        JndiLookupCallSite.ValueIdentity result = consumer.returnValue().value();
        if (incomplete(searchResult) || incomplete(receiver) || incomplete(result)) {
            return new Decision(Relation.UNKNOWN, Status.PARTIAL,
                    Reason.VALUE_FLOW_INCOMPLETE);
        }
        if (!JndiLookupCallSite.SEARCH_RETURN_DESCRIPTOR.equals(searchResult.descriptor())) {
            return new Decision(Relation.UNKNOWN, Status.UNKNOWN,
                    Reason.SEARCH_RETURN_DESCRIPTOR_MISMATCH);
        }
        if (!consumer.receiver().slot().descriptor().equals(receiver.descriptor())) {
            return new Decision(Relation.UNKNOWN, Status.UNKNOWN,
                    Reason.CONSUMER_RECEIVER_DESCRIPTOR_MISMATCH);
        }
        String expectedResult = consumer.returnsElement() ? "Ljava/lang/Object;" : "Z";
        if (!expectedResult.equals(result.descriptor())) {
            return new Decision(Relation.UNKNOWN, Status.UNKNOWN,
                    Reason.CONSUMER_RESULT_DESCRIPTOR_MISMATCH);
        }
        if (!searchResult.token().equals(receiver.token())) {
            return new Decision(Relation.UNKNOWN, Status.UNKNOWN,
                    Reason.SEARCH_CONSUMER_IDENTITY_MISMATCH);
        }
        if (consumer.returnsElement()
                || !JndiNamingEnumerationCallSite.NAMING_ENUMERATION_OWNER.equals(
                consumer.callSite().calleeOwner())) {
            return new Decision(Relation.DECLARED_CONTRACT, Status.PROVED, Reason.NONE);
        }
        return new Decision(Relation.SAME_IDENTITY, Status.PROVED, Reason.NONE);
    }

    private static boolean incomplete(JndiLookupCallSite.ValueIdentity value) {
        return value.producerOffset() < 0;
    }

    private record Decision(Relation relation, Status status, Reason reason) {
    }
}
