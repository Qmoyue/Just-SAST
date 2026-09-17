package io.just.sast.model;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;

/** Immutable result of bounded dispatch from one exact ObjectFactory call site. */
public record JndiObjectFactoryDispatch(JndiObjectFactoryCallSite callSite,
                                         List<Implementation> implementations,
                                         Status status) {

    public enum Status {
        RESOLVED,
        INTERFACE_ONLY,
        ABSTRACT_ONLY,
        UNKNOWN_IMPLEMENTATION
    }

    /** A concrete method target already present in the static call graph. */
    public record Implementation(String owner, String name, String descriptor) {
        public Implementation {
            owner = requireText(owner, "ObjectFactory implementation owner");
            name = requireText(name, "ObjectFactory implementation name");
            descriptor = requireText(descriptor, "ObjectFactory implementation descriptor");
            if (!JndiObjectFactoryCallSite.GET_OBJECT_INSTANCE_NAME.equals(name)
                    || !JndiObjectFactoryCallSite.GET_OBJECT_INSTANCE_DESCRIPTOR.equals(descriptor)) {
                throw new IllegalArgumentException("ObjectFactory implementation method is not exact");
            }
            if (JndiObjectFactoryCallSite.OBJECT_FACTORY_OWNER.equals(owner)) {
                throw new IllegalArgumentException("ObjectFactory interface is not a concrete implementation");
            }
        }

        public String methodKey() {
            return owner + "#" + name + descriptor;
        }
    }

    public JndiObjectFactoryDispatch {
        callSite = Objects.requireNonNull(callSite, "ObjectFactory call site");
        if (implementations == null) {
            throw new IllegalArgumentException("ObjectFactory implementations must not be null");
        }
        List<Implementation> ordered = new ArrayList<>(implementations.size());
        for (Implementation implementation : implementations) {
            ordered.add(Objects.requireNonNull(implementation, "ObjectFactory implementation"));
        }
        ordered.sort(Comparator.comparing(Implementation::methodKey));
        for (int index = 1; index < ordered.size(); index++) {
            if (ordered.get(index - 1).methodKey().equals(ordered.get(index).methodKey())) {
                throw new IllegalArgumentException("duplicate ObjectFactory implementation");
            }
        }
        implementations = List.copyOf(ordered);
        status = Objects.requireNonNull(status, "ObjectFactory dispatch status");
        if (status == Status.RESOLVED && implementations.isEmpty()) {
            throw new IllegalArgumentException("resolved ObjectFactory dispatch needs implementation");
        }
        if (status != Status.RESOLVED && !implementations.isEmpty()) {
            throw new IllegalArgumentException("unresolved ObjectFactory dispatch has implementations");
        }
    }

    public boolean resolved() {
        return status == Status.RESOLVED;
    }

    private static String requireText(String value, String label) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(label + " must not be blank");
        }
        return value;
    }
}
