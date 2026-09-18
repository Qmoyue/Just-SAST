package io.just.sast.model;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;

/**
 * Immutable hierarchy result for one proven proxy interface call.
 *
 * <p>A default method has one exact descriptor target.  An abstract interface method remains a
 * handler boundary and does not become a guessed implementation edge.  Multiple unrelated
 * defaults and missing/unresolved descriptors are retained as explicit bounded results.</p>
 */
public record ProxyInterfaceDispatch(
        ProxyInterfaceCallSite callSite,
        List<Declaration> declarations,
        Declaration target,
        Status status,
        Reason reason) {

    public enum Status {
        DEFAULT_RESOLVED,
        HANDLER_REQUIRED,
        PARTIAL,
        UNKNOWN
    }

    public enum Reason {
        NONE,
        VALUE_FLOW_INCOMPLETE,
        PROXY_CREATION_INCOMPLETE,
        INTERFACE_SET_UNKNOWN,
        NULL_RECEIVER,
        RECEIVER_DESCRIPTOR_MISMATCH,
        INTERFACE_TYPE_UNRESOLVED,
        INTERFACE_MEMBER_NOT_INTERFACE,
        INTERFACE_OWNER_NOT_DECLARED,
        DESCRIPTOR_NOT_DECLARED,
        DEFAULT_AMBIGUOUS
    }

    public enum Kind {
        DEFAULT_METHOD,
        ABSTRACT_METHOD
    }

    /** One exact declaration selected from the proved interface set. */
    public record Declaration(String owner, String name, String descriptor, Kind kind) {
        public Declaration {
            owner = requireText(owner, "proxy declaration owner");
            name = requireText(name, "proxy declaration name");
            descriptor = requireText(descriptor, "proxy declaration descriptor");
            kind = Objects.requireNonNull(kind, "proxy declaration kind");
            if (!validInternalName(owner)) {
                throw new IllegalArgumentException("proxy declaration owner is not an internal name");
            }
            if (!validMethodDescriptor(descriptor)) {
                throw new IllegalArgumentException("proxy declaration descriptor is invalid");
            }
        }

        public String methodKey() {
            return owner + "#" + name + descriptor;
        }
    }

    public ProxyInterfaceDispatch {
        callSite = Objects.requireNonNull(callSite, "proxy interface dispatch call site");
        List<Declaration> ordered = new ArrayList<>(Objects.requireNonNull(declarations,
                "proxy interface declarations"));
        ordered.replaceAll(value -> Objects.requireNonNull(value,
                "proxy interface declaration"));
        ordered.sort(Comparator.comparing(Declaration::methodKey)
                .thenComparing(Declaration::kind));
        for (int index = 1; index < ordered.size(); index++) {
            if (ordered.get(index - 1).methodKey().equals(ordered.get(index).methodKey())
                    && ordered.get(index - 1).kind() == ordered.get(index).kind()) {
                throw new IllegalArgumentException("duplicate proxy interface declaration");
            }
        }
        declarations = List.copyOf(ordered);
        target = target == null ? null : Objects.requireNonNull(target, "proxy dispatch target");
        status = Objects.requireNonNull(status, "proxy dispatch status");
        reason = Objects.requireNonNull(reason, "proxy dispatch reason");
        for (Declaration declaration : declarations) {
            if (!callSite.callSite().calleeName().equals(declaration.name())
                    || !callSite.callSite().calleeDescriptor().equals(declaration.descriptor())) {
                throw new IllegalArgumentException("proxy declaration descriptor is not call-site exact");
            }
        }
        if (target != null && !declarations.contains(target)) {
            throw new IllegalArgumentException("proxy dispatch target is not a declaration");
        }
        if (status == Status.DEFAULT_RESOLVED) {
            if (target == null || target.kind() != Kind.DEFAULT_METHOD || reason != Reason.NONE) {
                throw new IllegalArgumentException("resolved proxy default lacks exact target");
            }
        } else if (target != null) {
            throw new IllegalArgumentException("unresolved proxy dispatch has target");
        }
        if (status == Status.HANDLER_REQUIRED
                && declarations.stream().noneMatch(value -> value.kind() == Kind.ABSTRACT_METHOD)) {
            throw new IllegalArgumentException("handler boundary lacks abstract declaration");
        }
    }

    public static ProxyInterfaceDispatch unresolved(ProxyInterfaceCallSite site,
                                                     Status status, Reason reason) {
        if (status == Status.DEFAULT_RESOLVED || status == Status.HANDLER_REQUIRED) {
            throw new IllegalArgumentException("unresolved factory status is invalid");
        }
        return new ProxyInterfaceDispatch(site, List.of(), null, status, reason);
    }

    public static ProxyInterfaceDispatch handlerRequired(ProxyInterfaceCallSite site,
                                                         List<Declaration> declarations) {
        return new ProxyInterfaceDispatch(site, declarations, null, Status.HANDLER_REQUIRED,
                Reason.NONE);
    }

    public static ProxyInterfaceDispatch defaultResolved(ProxyInterfaceCallSite site,
                                                          Declaration target,
                                                          List<Declaration> declarations) {
        return new ProxyInterfaceDispatch(site, declarations, target, Status.DEFAULT_RESOLVED,
                Reason.NONE);
    }

    public boolean resolved() {
        return status == Status.DEFAULT_RESOLVED;
    }

    private static String requireText(String value, String label) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(label + " must not be blank");
        }
        if (value.indexOf('\r') >= 0 || value.indexOf('\n') >= 0) {
            throw new IllegalArgumentException(label + " must not contain a line break");
        }
        return value.trim();
    }

    private static boolean validInternalName(String value) {
        return value != null && !value.isBlank() && !value.startsWith("[")
                && value.indexOf('.') < 0 && value.indexOf(';') < 0
                && value.indexOf('(') < 0 && value.indexOf(')') < 0;
    }

    private static boolean validMethodDescriptor(String descriptor) {
        if (descriptor == null || !descriptor.startsWith("(")
                || descriptor.indexOf(')') <= 0
                || descriptor.indexOf(')') >= descriptor.length() - 1) {
            return false;
        }
        try {
            Descriptor.paramCount(descriptor);
            Descriptor.returnType(descriptor);
            return true;
        } catch (RuntimeException invalid) {
            return false;
        }
    }
}
