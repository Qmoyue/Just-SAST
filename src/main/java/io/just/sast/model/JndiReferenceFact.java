package io.just.sast.model;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Immutable fact for one statically observed {@code javax.naming.Reference} object.
 *
 * <p>The identity is the exact allocation in the enclosing method.  Constructor fields and
 * {@code RefAddr} fields are retained as typed values; an unresolved value is represented by
 * an explicit state rather than by a guessed string or an empty value.  This model is data-only:
 * it never loads, initializes, constructs, or invokes a target class.</p>
 */
public record JndiReferenceFact(ObjectIdentity identity, FieldValue type,
                                FieldValue factoryClass, FieldValue factoryLocation,
                                List<RefAddrFact> properties) {

    /** Graph note attached to the exact Reference constructor call node. */
    public static final String GRAPH_NOTE_KEY = "jndiReferenceFact";
    public static final String REFERENCE_OWNER = "javax/naming/Reference";
    public static final String REFERENCE_DESCRIPTOR = "L" + REFERENCE_OWNER + ";";
    public static final String REF_ADDR_OWNER = "javax/naming/RefAddr";
    public static final String STRING_REF_ADDR_OWNER = "javax/naming/StringRefAddr";

    public static final String REFERENCE_CONSTRUCTOR_ONE_DESCRIPTOR =
            "(Ljava/lang/String;)V";
    public static final String REFERENCE_CONSTRUCTOR_ADDRESS_DESCRIPTOR =
            "(Ljava/lang/String;L" + REF_ADDR_OWNER + ";)V";
    public static final String REFERENCE_CONSTRUCTOR_FACTORY_DESCRIPTOR =
            "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V";
    public static final String REFERENCE_CONSTRUCTOR_FULL_DESCRIPTOR =
            "(Ljava/lang/String;L" + REF_ADDR_OWNER + ";Ljava/lang/String;Ljava/lang/String;)V";
    public static final String STRING_REF_ADDR_CONSTRUCTOR_DESCRIPTOR =
            "(Ljava/lang/String;Ljava/lang/String;)V";
    public static final String REFERENCE_ADD_ADDRESS_DESCRIPTOR =
            "(L" + REF_ADDR_OWNER + ";)V";
    public static final String REFERENCE_ADD_INDEXED_ADDRESS_DESCRIPTOR =
            "(IL" + REF_ADDR_OWNER + ";)V";
    public static final String REFERENCE_REMOVE_DESCRIPTOR = "(I)V";
    public static final String REFERENCE_CLEAR_DESCRIPTOR = "()V";

    /** A field value whose absence, null, or uncertainty remains observable. */
    public record FieldValue(State state, String value) {
        public enum State {
            KNOWN,
            NULL,
            ABSENT,
            UNKNOWN
        }

        public FieldValue {
            state = Objects.requireNonNull(state, "Reference field state");
            if (state == State.KNOWN && value == null) {
                throw new IllegalArgumentException("known Reference field value must not be null");
            }
            if (state != State.KNOWN && value != null) {
                throw new IllegalArgumentException("non-known Reference field value must be null");
            }
        }

        public static FieldValue known(String value) {
            return new FieldValue(State.KNOWN, Objects.requireNonNull(value, "known value"));
        }

        public static FieldValue nullValue() {
            return new FieldValue(State.NULL, null);
        }

        public static FieldValue absent() {
            return new FieldValue(State.ABSENT, null);
        }

        public static FieldValue unknown() {
            return new FieldValue(State.UNKNOWN, null);
        }

        public boolean isKnown() {
            return state == State.KNOWN;
        }

        public boolean isUnknown() {
            return state == State.UNKNOWN;
        }

        public Optional<String> optionalValue() {
            return Optional.ofNullable(value);
        }
    }

    /** Physical identity for one object allocation and its exact constructor call. */
    public record ObjectIdentity(String owner, String hostMethodKey, int allocationOffset,
                                 int constructionOffset, long constructionCallId) {
        public ObjectIdentity {
            owner = requireText(owner, "Reference object owner");
            hostMethodKey = requireText(hostMethodKey, "Reference object host method");
            if (allocationOffset < 0) {
                throw new IllegalArgumentException("Reference allocation offset must be non-negative");
            }
            if (constructionOffset < 0) {
                throw new IllegalArgumentException("Reference construction offset must be non-negative");
            }
            if (constructionCallId < 0) {
                throw new IllegalArgumentException("Reference construction call id must be non-negative");
            }
        }

        /** Stable semantic identity excludes the graph-global node id. */
        public String identity() {
            return "jndi-object:" + owner + "@" + hostMethodKey + ":" + allocationOffset;
        }
    }

    /** One exact RefAddr object retained under its owning Reference identity. */
    public record RefAddrFact(ObjectIdentity identity, FieldValue type, FieldValue content) {
        public RefAddrFact {
            identity = Objects.requireNonNull(identity, "Reference address identity");
            type = Objects.requireNonNull(type, "Reference address type");
            content = Objects.requireNonNull(content, "Reference address content");
        }
    }

    public JndiReferenceFact {
        identity = Objects.requireNonNull(identity, "Reference identity");
        if (!REFERENCE_OWNER.equals(identity.owner())) {
            throw new IllegalArgumentException("Reference fact identity must use javax/naming/Reference");
        }
        type = Objects.requireNonNull(type, "Reference type");
        factoryClass = Objects.requireNonNull(factoryClass, "Reference factory class");
        factoryLocation = Objects.requireNonNull(factoryLocation, "Reference factory location");
        if (properties == null) {
            throw new IllegalArgumentException("Reference properties must not be null");
        }
        properties = List.copyOf(properties);
        for (RefAddrFact property : properties) {
            Objects.requireNonNull(property, "Reference property");
            if (!property.identity().identity().startsWith("jndi-object:")) {
                throw new IllegalArgumentException("Reference property identity is invalid");
            }
        }
    }

    /** Requested object/interface type supplied as Reference.className. */
    public FieldValue requestedType() {
        return type;
    }

    /** Alias used by bridge consumers that call the field factoryClassName. */
    public FieldValue factoryClassName() {
        return factoryClass;
    }

    /** Alias used by bridge consumers that call the field factoryClassLocation. */
    public FieldValue factoryClassLocation() {
        return factoryLocation;
    }

    /** Preserve the source API's RefAddr order; order is part of object identity semantics. */
    public List<RefAddrFact> addresses() {
        return properties;
    }

    private static String requireText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
        return value;
    }
}
