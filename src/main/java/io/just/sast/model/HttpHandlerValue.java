package io.just.sast.model;

import java.util.Objects;

/**
 * Immutable origin of the {@code HttpHandler} value supplied to one registration call.
 *
 * <p>The frontend records only two bytecode-proven producer shapes: an exact
 * {@code invokedynamic} result or an object created by an exact {@code new}/{@code <init>}
 * sequence.  A missing or unsupported origin is intentionally not represented as a guessed
 * handler.  The application-entry owner later joins this value with an actual graph edge and
 * the concrete request-source facts.</p>
 */
public record HttpHandlerValue(String hostMethodKey, int producerOffset, Kind kind,
                               long producerCallId, long constructionCallId,
                               String typeOwner, String typeDescriptor) {

    /** Graph note key used at the CPG seam; the value is a List of this record. */
    public static final String GRAPH_NOTE_KEY = "httpHandlerValues";

    public enum Kind {
        LAMBDA,
        ALLOCATION
    }

    public HttpHandlerValue {
        hostMethodKey = requireText(hostMethodKey, "hostMethodKey");
        if (producerOffset < 0) {
            throw new IllegalArgumentException("producerOffset must be non-negative");
        }
        kind = Objects.requireNonNull(kind, "kind");
        typeOwner = requireText(typeOwner, "typeOwner");
        typeDescriptor = requireText(typeDescriptor, "typeDescriptor");
        if (kind == Kind.LAMBDA) {
            if (producerCallId < 0 || constructionCallId != -1) {
                throw new IllegalArgumentException("lambda origin call shape is invalid");
            }
        } else if (producerCallId != -1 || constructionCallId < 0) {
            throw new IllegalArgumentException("allocation origin construction shape is invalid");
        }
        if (!typeDescriptor.startsWith("L") || !typeDescriptor.endsWith(";")) {
            throw new IllegalArgumentException("handler type descriptor must be an object type");
        }
    }

    /** Stable identity for the exact producer value in the enclosing method. */
    public String identity() {
        return "http-handler:" + hostMethodKey + "@" + producerOffset + ":" + kind;
    }

    public boolean lambda() {
        return kind == Kind.LAMBDA;
    }

    public boolean allocation() {
        return kind == Kind.ALLOCATION;
    }

    private static String requireText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
        return value;
    }
}
