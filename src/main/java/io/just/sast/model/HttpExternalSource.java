package io.just.sast.model;

import java.util.List;
import java.util.Objects;

/**
 * Immutable typed fact for one HTTP request API call observed in an application method.
 *
 * <p>The fact deliberately models both container-producing calls and value-producing calls.
 * A container is provenance for a later request value, while only {@link ValueRole#VALUE}
 * represents externally supplied data.  It records JVM descriptors and the physical call-site
 * identity; it does not infer a header name, query value, alias, route, or site membership.</p>
 */
public record HttpExternalSource(
        long callId,
        String hostMethodKey,
        int callOffset,
        String apiOwner,
        String apiName,
        String apiDescriptor,
        Kind kind,
        ValueRole valueRole,
        Slot receiver,
        List<Slot> arguments,
        String valueDescriptor) {

    public enum Kind {
        HEADER,
        QUERY,
        BODY
    }

    public enum ValueRole {
        CONTAINER,
        VALUE
    }

    /** One receiver/argument slot at the source call site. */
    public record Slot(int ordinal, String descriptor) {
        public Slot {
            if (ordinal < -1) {
                throw new IllegalArgumentException("slot ordinal must be -1 or greater");
            }
            descriptor = requireText(descriptor, "slot descriptor");
        }
    }

    public HttpExternalSource {
        if (callId < 0) {
            throw new IllegalArgumentException("callId must be non-negative");
        }
        hostMethodKey = requireText(hostMethodKey, "hostMethodKey");
        if (callOffset < 0) {
            throw new IllegalArgumentException("callOffset must be non-negative");
        }
        apiOwner = requireText(apiOwner, "apiOwner");
        apiName = requireText(apiName, "apiName");
        apiDescriptor = requireText(apiDescriptor, "apiDescriptor");
        kind = Objects.requireNonNull(kind, "kind");
        valueRole = Objects.requireNonNull(valueRole, "valueRole");
        receiver = Objects.requireNonNull(receiver, "receiver");
        if (receiver.ordinal() != -1) {
            throw new IllegalArgumentException("HTTP source receiver must use ordinal -1");
        }
        arguments = List.copyOf(Objects.requireNonNull(arguments, "arguments"));
        for (int index = 0; index < arguments.size(); index++) {
            Slot argument = Objects.requireNonNull(arguments.get(index), "source argument");
            if (argument.ordinal() != index) {
                throw new IllegalArgumentException("HTTP source argument ordinal is not dense");
            }
        }
        valueDescriptor = requireText(valueDescriptor, "value descriptor");
    }

    public String apiKey() {
        return apiOwner + "#" + apiName + apiDescriptor;
    }

    /** Stable identity for the value returned by this exact source API call. */
    public String valueIdentity() {
        return "call:" + callId + "@" + hostMethodKey + ":return";
    }

    public boolean externalInput() {
        return valueRole == ValueRole.VALUE;
    }

    private static String requireText(String value, String label) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(label + " must not be blank");
        }
        return value;
    }
}
