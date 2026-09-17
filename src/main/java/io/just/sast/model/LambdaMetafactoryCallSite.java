package io.just.sast.model;

import java.util.List;
import java.util.Objects;

/**
 * Immutable semantic view of one LambdaMetafactory invokedynamic call site.
 *
 * <p>The frontend owns the raw {@link InvokeDynamicRef}; this model is the typed bridge used
 * by the call graph and taint consumers.  Only the JVM-defined implementation-handle slot is
 * admitted.  In particular, metadata handles in an altMetafactory argument list are never
 * treated as additional implementations, and a method name is never used to guess a lambda
 * target.</p>
 */
public record LambdaMetafactoryCallSite(
        String factoryName,
        String factoryDescriptor,
        HandleRef bootstrap,
        String samDescriptor,
        HandleRef implementation,
        String instantiatedDescriptor,
        MethodRef functionalInterfaceMethod,
        int flags,
        List<String> markerInterfaces,
        List<String> bridgeDescriptors) {

    private static final String OWNER = "java/lang/invoke/LambdaMetafactory";
    private static final String METAFACTORY = "metafactory";
    private static final String ALT_METAFACTORY = "altMetafactory";
    private static final int H_INVOKESTATIC = 6;
    private static final int FLAG_SERIALIZABLE = 1;
    private static final int FLAG_MARKERS = 2;
    private static final int FLAG_BRIDGES = 4;
    private static final int KNOWN_FLAGS = FLAG_SERIALIZABLE | FLAG_MARKERS | FLAG_BRIDGES;

    /** Explicit result states keep malformed bytecode observable to graph builders. */
    public enum Status {
        RESOLVED,
        NOT_LAMBDA_METAFACTORY,
        UNKNOWN_BOOTSTRAP,
        UNKNOWN_ARGUMENTS,
        UNKNOWN_DESCRIPTOR
    }

    /** Typed parse result; non-resolved states deliberately carry no guessed site. */
    public record Resolution(Status status, LambdaMetafactoryCallSite site) {
        public Resolution {
            status = Objects.requireNonNull(status, "lambda resolution status");
            if ((status == Status.RESOLVED) != (site != null)) {
                throw new IllegalArgumentException("resolved lambda status/site mismatch");
            }
        }

        public boolean resolved() {
            return status == Status.RESOLVED;
        }
    }

    public LambdaMetafactoryCallSite {
        factoryName = requireText(factoryName, "factory name");
        factoryDescriptor = requireText(factoryDescriptor, "factory descriptor");
        bootstrap = Objects.requireNonNull(bootstrap, "bootstrap");
        samDescriptor = requireText(samDescriptor, "SAM descriptor");
        implementation = Objects.requireNonNull(implementation, "implementation");
        instantiatedDescriptor = requireText(instantiatedDescriptor, "instantiated descriptor");
        functionalInterfaceMethod = Objects.requireNonNull(functionalInterfaceMethod,
                "functional interface method");
        if (flags < 0 || (flags & ~KNOWN_FLAGS) != 0) {
            throw new IllegalArgumentException("unknown LambdaMetafactory flags");
        }
        markerInterfaces = List.copyOf(Objects.requireNonNull(markerInterfaces,
                "marker interfaces"));
        bridgeDescriptors = List.copyOf(Objects.requireNonNull(bridgeDescriptors,
                "bridge descriptors"));
    }

    /** Parse only the JVM-defined metafactory and altMetafactory layouts. */
    public static Resolution resolve(InvokeDynamicRef invokedynamic) {
        if (invokedynamic == null) {
            return unknown(Status.UNKNOWN_ARGUMENTS);
        }
        HandleRef bootstrap = invokedynamic.bootstrap();
        if (bootstrap == null || blank(bootstrap.owner()) || blank(bootstrap.name())) {
            return unknown(Status.UNKNOWN_BOOTSTRAP);
        }
        if (!OWNER.equals(bootstrap.owner())
                || !(METAFACTORY.equals(bootstrap.name())
                || ALT_METAFACTORY.equals(bootstrap.name()))) {
            return unknown(Status.NOT_LAMBDA_METAFACTORY);
        }
        if (bootstrap.tag() != H_INVOKESTATIC) {
            return unknown(Status.UNKNOWN_BOOTSTRAP);
        }
        if (!validMethodDescriptor(bootstrap.descriptor())
                || blank(invokedynamic.name())
                || !validMethodDescriptor(invokedynamic.descriptor())) {
            return unknown(Status.UNKNOWN_DESCRIPTOR);
        }

        List<Object> args = invokedynamic.bootstrapArgs();
        if (args == null || args.size() < 3) {
            return unknown(Status.UNKNOWN_ARGUMENTS);
        }
        if (!(args.get(0) instanceof TypeRef samType)
                || !(args.get(1) instanceof HandleRef implementation)
                || !(args.get(2) instanceof TypeRef instantiatedType)) {
            return unknown(Status.UNKNOWN_ARGUMENTS);
        }
        String samDescriptor = samType.descriptor();
        String instantiatedDescriptor = instantiatedType.descriptor();
        if (!validMethodDescriptor(samDescriptor)
                || !validMethodDescriptor(instantiatedDescriptor)
                || !validImplementation(implementation)) {
            return unknown(Status.UNKNOWN_DESCRIPTOR);
        }

        String functionalInterface = referenceInternalName(
                returnDescriptor(invokedynamic.descriptor()));
        if (functionalInterface == null) {
            return unknown(Status.UNKNOWN_DESCRIPTOR);
        }

        boolean alternate = ALT_METAFACTORY.equals(bootstrap.name());
        int flags = 0;
        List<String> markers = List.of();
        List<String> bridges = List.of();
        if (!alternate) {
            if (args.size() != 3) {
                return unknown(Status.UNKNOWN_ARGUMENTS);
            }
        } else {
            AltMetadata metadata = parseAltMetadata(args);
            if (metadata == null) {
                return unknown(Status.UNKNOWN_ARGUMENTS);
            }
            flags = metadata.flags();
            markers = metadata.markerInterfaces();
            bridges = metadata.bridgeDescriptors();
        }

        MethodRef samMethod = new MethodRef(functionalInterface, invokedynamic.name(), samDescriptor);
        LambdaMetafactoryCallSite site = new LambdaMetafactoryCallSite(
                invokedynamic.name(), invokedynamic.descriptor(), bootstrap, samDescriptor,
                implementation, instantiatedDescriptor, samMethod, flags, markers, bridges);
        return new Resolution(Status.RESOLVED, site);
    }

    private static AltMetadata parseAltMetadata(List<Object> args) {
        if (!(args.get(3) instanceof Integer flagValue)) {
            return null;
        }
        int flags = flagValue;
        if (flags < 0 || (flags & ~KNOWN_FLAGS) != 0) {
            return null;
        }
        int cursor = 4;
        List<String> markers = List.of();
        List<String> bridges = List.of();
        if ((flags & FLAG_MARKERS) != 0) {
            Integer count = nonNegativeCount(args, cursor++);
            if (count == null || count > args.size() - cursor) {
                return null;
            }
            java.util.ArrayList<String> values = new java.util.ArrayList<>(count);
            for (int i = 0; i < count; i++) {
                String marker = objectType(argumentType(args, cursor++));
                if (marker == null) {
                    return null;
                }
                values.add(marker);
            }
            markers = List.copyOf(values);
        }
        if ((flags & FLAG_BRIDGES) != 0) {
            Integer count = nonNegativeCount(args, cursor++);
            if (count == null || count > args.size() - cursor) {
                return null;
            }
            java.util.ArrayList<String> values = new java.util.ArrayList<>(count);
            for (int i = 0; i < count; i++) {
                String descriptor = methodType(argumentType(args, cursor++));
                if (descriptor == null) {
                    return null;
                }
                values.add(descriptor);
            }
            bridges = List.copyOf(values);
        }
        return cursor == args.size() ? new AltMetadata(flags, markers, bridges) : null;
    }

    private record AltMetadata(int flags, List<String> markerInterfaces,
                               List<String> bridgeDescriptors) {}

    private static Integer nonNegativeCount(List<Object> args, int index) {
        if (index >= args.size() || !(args.get(index) instanceof Integer value)
                || value < 0) {
            return null;
        }
        return value;
    }

    private static TypeRef argumentType(List<Object> args, int index) {
        return index < args.size() && args.get(index) instanceof TypeRef type ? type : null;
    }

    private static String methodType(TypeRef type) {
        return type != null && validMethodDescriptor(type.descriptor())
                ? type.descriptor() : null;
    }

    private static String objectType(TypeRef type) {
        if (type == null || type.descriptor() == null) {
            return null;
        }
        return referenceInternalName(type.descriptor());
    }

    private static boolean validImplementation(HandleRef handle) {
        if (handle == null || blank(handle.owner()) || blank(handle.name())
                || !validInternalName(handle.owner())
                || !validMethodDescriptor(handle.descriptor())) {
            return false;
        }
        return handle.tag() >= 5 && handle.tag() <= 9;
    }

    private static String referenceInternalName(String descriptor) {
        if (descriptor == null || descriptor.length() < 3
                || descriptor.charAt(0) != 'L' || descriptor.charAt(descriptor.length() - 1) != ';') {
            return null;
        }
        String name = descriptor.substring(1, descriptor.length() - 1);
        return validInternalName(name) ? name : null;
    }

    private static String returnDescriptor(String methodDescriptor) {
        int close = methodDescriptor.indexOf(')');
        return close < 0 ? null : methodDescriptor.substring(close + 1);
    }

    private static boolean validMethodDescriptor(String descriptor) {
        if (descriptor == null || descriptor.length() < 3 || descriptor.charAt(0) != '(') {
            return false;
        }
        int cursor = 1;
        while (cursor < descriptor.length() && descriptor.charAt(cursor) != ')') {
            int next = fieldEnd(descriptor, cursor, false);
            if (next < 0) {
                return false;
            }
            cursor = next;
        }
        if (cursor >= descriptor.length() || descriptor.charAt(cursor) != ')') {
            return false;
        }
        int end = fieldEnd(descriptor, cursor + 1, true);
        return end == descriptor.length();
    }

    private static int fieldEnd(String descriptor, int start, boolean allowVoid) {
        if (start >= descriptor.length()) {
            return -1;
        }
        int cursor = start;
        while (cursor < descriptor.length() && descriptor.charAt(cursor) == '[') {
            cursor++;
        }
        if (cursor >= descriptor.length()) {
            return -1;
        }
        char type = descriptor.charAt(cursor);
        if (type == 'V') {
            return allowVoid && cursor == start ? cursor + 1 : -1;
        }
        if ("BCDFIJSZ".indexOf(type) >= 0) {
            return cursor + 1;
        }
        if (type != 'L') {
            return -1;
        }
        int semicolon = descriptor.indexOf(';', cursor + 1);
        if (semicolon < 0 || !validInternalName(descriptor.substring(cursor + 1, semicolon))) {
            return -1;
        }
        return semicolon + 1;
    }

    private static boolean validInternalName(String name) {
        return !blank(name) && name.indexOf('.') < 0 && name.indexOf(';') < 0
                && name.indexOf('[') < 0;
    }

    private static String requireText(String value, String label) {
        if (blank(value)) {
            throw new IllegalArgumentException(label + " must not be blank");
        }
        return value;
    }

    private static boolean blank(String value) {
        return value == null || value.isBlank();
    }

    private static Resolution unknown(Status status) {
        return new Resolution(status, null);
    }
}
