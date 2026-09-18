package io.just.sast.model;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * One bounded, same-method continuity fact from JDBC configuration into JAAS lifecycle calls.
 *
 * <p>This owner joins only physical identities already retained by the JDBC and JAAS call-site
 * owners.  Equal display text is never a join condition.  The fact is intentionally limited to
 * a method-local straight-line flow; interprocedural and concrete module resolution remain
 * separate later owners.</p>
 */
public record JaasLoginModuleFlow(
        JdbcConnectionCallSite jdbcConnection,
        JaasLoginModuleCallSite optionsEntry,
        List<JaasLoginModuleCallSite> optionMutations,
        JaasLoginModuleCallSite initialize,
        JaasLoginModuleCallSite login,
        List<PropertyOptionBridge> propertyOptionBridges,
        Status status,
        Reason reason) {

    public static final String GRAPH_NOTE_KEY = "jaasLoginModuleFlow";

    public enum Status {
        PROVED,
        PARTIAL,
        UNKNOWN
    }

    public enum Reason {
        NONE,
        JDBC_URL_NOT_KNOWN,
        JDBC_PROPERTIES_NOT_KNOWN,
        OPTIONS_MUTATION_NOT_PROVEN,
        PROPERTY_OPTIONS_NOT_CONNECTED,
        OPTIONS_IDENTITY_MISMATCH,
        LOGIN_RECEIVER_IDENTITY_MISMATCH,
        OPTION_MUTATION_IDENTITY_MISMATCH
    }

    /** One property key/value to options key/value identity comparison. */
    public record PropertyOptionBridge(
            JdbcConnectionCallSite.PropertyEntry property,
            JaasLoginModuleCallSite optionMutation,
            Status status,
            Reason reason) {
        public PropertyOptionBridge {
            property = Objects.requireNonNull(property, "JDBC property entry");
            optionMutation = Objects.requireNonNull(optionMutation, "JAAS option mutation");
            status = Objects.requireNonNull(status, "property/options status");
            reason = Objects.requireNonNull(reason, "property/options reason");
            if (optionMutation.kind() != JaasLoginModuleCallSite.Kind.OPTIONS_MAP_PUT) {
                throw new IllegalArgumentException("property/options endpoint is not Map.put");
            }
        }

        public static PropertyOptionBridge connect(
                JdbcConnectionCallSite.PropertyEntry property,
                JaasLoginModuleCallSite optionMutation) {
            Objects.requireNonNull(property, "JDBC property entry");
            Objects.requireNonNull(optionMutation, "JAAS option mutation");
            if (optionMutation.kind() != JaasLoginModuleCallSite.Kind.OPTIONS_MAP_PUT) {
                throw new IllegalArgumentException("property/options endpoint is not Map.put");
            }
            boolean key = property.key().token().equals(optionMutation.argument(0).value().token());
            boolean value = property.value().token()
                    .equals(optionMutation.argument(1).value().token());
            if (key && value) {
                return new PropertyOptionBridge(property, optionMutation, Status.PROVED,
                        Reason.NONE);
            }
            return new PropertyOptionBridge(property, optionMutation, Status.UNKNOWN,
                    Reason.PROPERTY_OPTIONS_NOT_CONNECTED);
        }

        public boolean proved() {
            return status == Status.PROVED;
        }
    }

    public JaasLoginModuleFlow {
        jdbcConnection = Objects.requireNonNull(jdbcConnection, "JDBC connection fact");
        optionsEntry = Objects.requireNonNull(optionsEntry, "JAAS options entry");
        optionMutations = List.copyOf(Objects.requireNonNull(optionMutations,
                "JAAS option mutations"));
        initialize = Objects.requireNonNull(initialize, "JAAS initialize fact");
        login = Objects.requireNonNull(login, "JAAS login fact");
        propertyOptionBridges = List.copyOf(Objects.requireNonNull(propertyOptionBridges,
                "property/options bridges"));
        status = Objects.requireNonNull(status, "JAAS flow status");
        reason = Objects.requireNonNull(reason, "JAAS flow reason");
        validateKinds(optionsEntry, optionMutations, initialize, login);
        Decision decision = decide(jdbcConnection, optionsEntry, optionMutations, initialize, login,
                propertyOptionBridges);
        if (status != decision.status() || reason != decision.reason()) {
            throw new IllegalArgumentException("JAAS flow status does not match typed identities");
        }
    }

    /** Join exact JDBC/JAAS facts without resolving or invoking any target implementation. */
    public static JaasLoginModuleFlow connect(
            JdbcConnectionCallSite jdbcConnection,
            JaasLoginModuleCallSite optionsEntry,
            List<JaasLoginModuleCallSite> optionMutations,
            JaasLoginModuleCallSite initialize,
            JaasLoginModuleCallSite login) {
        Objects.requireNonNull(jdbcConnection, "JDBC connection fact");
        Objects.requireNonNull(optionsEntry, "JAAS options entry");
        Objects.requireNonNull(optionMutations, "JAAS option mutations");
        Objects.requireNonNull(initialize, "JAAS initialize fact");
        Objects.requireNonNull(login, "JAAS login fact");
        List<JaasLoginModuleCallSite> mutations = List.copyOf(optionMutations);
        List<PropertyOptionBridge> bridges = new ArrayList<>();
        for (JdbcConnectionCallSite.PropertyEntry property : jdbcConnection.propertyEntries()) {
            for (JaasLoginModuleCallSite mutation : mutations) {
                boolean keyCandidate = property.key().token()
                        .equals(mutation.argument(0).value().token());
                boolean valueCandidate = property.value().token()
                        .equals(mutation.argument(1).value().token());
                if (keyCandidate || valueCandidate) {
                    bridges.add(PropertyOptionBridge.connect(property, mutation));
                }
            }
        }
        Decision decision = decide(jdbcConnection, optionsEntry, mutations, initialize, login,
                bridges);
        return new JaasLoginModuleFlow(jdbcConnection, optionsEntry, mutations, initialize, login,
                bridges, decision.status(), decision.reason());
    }

    public boolean proved() {
        return status == Status.PROVED;
    }

    public String identity() {
        return "jaas-flow-v1|" + jdbcConnection.identity() + "|" + optionsEntry.identity()
                + "|" + initialize.identity() + "|" + login.identity() + "|" + status
                + "|" + reason;
    }

    private static Decision decide(JdbcConnectionCallSite jdbcConnection,
                                   JaasLoginModuleCallSite optionsEntry,
                                   List<JaasLoginModuleCallSite> optionMutations,
                                   JaasLoginModuleCallSite initialize,
                                   JaasLoginModuleCallSite login,
                                   List<PropertyOptionBridge> bridges) {
        String optionsIdentity = optionsEntry.argument(2).value().token();
        if (!optionsIdentity.equals(initialize.argument(3).value().token())) {
            return new Decision(Status.UNKNOWN, Reason.OPTIONS_IDENTITY_MISMATCH);
        }
        if (!initialize.receiver().value().token().equals(login.receiver().value().token())) {
            return new Decision(Status.UNKNOWN, Reason.LOGIN_RECEIVER_IDENTITY_MISMATCH);
        }
        for (JaasLoginModuleCallSite mutation : optionMutations) {
            if (!optionsIdentity.equals(mutation.receiver().value().token())) {
                return new Decision(Status.UNKNOWN, Reason.OPTION_MUTATION_IDENTITY_MISMATCH);
            }
        }
        if (jdbcConnection.url().state() != JdbcConnectionCallSite.ValueState.KNOWN) {
            return new Decision(Status.PARTIAL, Reason.JDBC_URL_NOT_KNOWN);
        }
        if (jdbcConnection.properties().state() != JdbcConnectionCallSite.ValueState.KNOWN) {
            return new Decision(Status.PARTIAL, Reason.JDBC_PROPERTIES_NOT_KNOWN);
        }
        if (optionMutations.isEmpty()) {
            return new Decision(Status.PARTIAL, Reason.OPTIONS_MUTATION_NOT_PROVEN);
        }
        if (bridges.stream().noneMatch(PropertyOptionBridge::proved)) {
            return new Decision(Status.PARTIAL, Reason.PROPERTY_OPTIONS_NOT_CONNECTED);
        }
        return new Decision(Status.PROVED, Reason.NONE);
    }

    private static void validateKinds(JaasLoginModuleCallSite optionsEntry,
                                      List<JaasLoginModuleCallSite> optionMutations,
                                      JaasLoginModuleCallSite initialize,
                                      JaasLoginModuleCallSite login) {
        if (optionsEntry.kind() != JaasLoginModuleCallSite.Kind.APP_CONFIGURATION_ENTRY) {
            throw new IllegalArgumentException("JAAS options entry kind is invalid");
        }
        if (initialize.kind() != JaasLoginModuleCallSite.Kind.LOGIN_MODULE_INITIALIZE) {
            throw new IllegalArgumentException("JAAS initialize kind is invalid");
        }
        if (login.kind() != JaasLoginModuleCallSite.Kind.LOGIN_MODULE_LOGIN) {
            throw new IllegalArgumentException("JAAS login kind is invalid");
        }
        for (JaasLoginModuleCallSite mutation : optionMutations) {
            if (mutation == null
                    || mutation.kind() != JaasLoginModuleCallSite.Kind.OPTIONS_MAP_PUT) {
                throw new IllegalArgumentException("JAAS option mutation kind is invalid");
            }
        }
    }

    private record Decision(Status status, Reason reason) {
    }
}
