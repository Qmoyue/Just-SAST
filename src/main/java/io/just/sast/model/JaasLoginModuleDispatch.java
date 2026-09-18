package io.just.sast.model;

import java.util.Objects;

/**
 * Immutable resolution evidence for one exact {@code LoginModule} lifecycle call.
 *
 * <p>The resolver records the concrete JndiLoginModule boundary only when its class bytes are
 * present in the initial input set or in a source with explicit JDK-image provenance.  Missing,
 * abstract, unrelated, and provenance-unknown cases remain typed non-resolutions; they never
 * become guessed concrete edges.</p>
 */
public record JaasLoginModuleDispatch(
        JaasLoginModuleCallSite callSite,
        String targetClass,
        Implementation implementation,
        Source source,
        Status status,
        JdkSourceInfo sourceInfo) {

    public static final String TARGET_CLASS = "com/sun/security/auth/module/JndiLoginModule";

    public enum Source {
        PROGRAM_INPUT,
        JDK_IMAGE,
        UNKNOWN
    }

    public enum Status {
        RESOLVED,
        CLASS_NOT_RESOLVED,
        SOURCE_NOT_PROVABLE,
        NOT_LOGIN_MODULE,
        INTERFACE_OR_ABSTRACT,
        METHOD_NOT_RESOLVED,
        METHOD_ABSTRACT
    }

    /** One exact concrete method declaration selected by bytecode-only method resolution. */
    public record Implementation(String owner, String name, String descriptor) {
        public Implementation {
            owner = requireText(owner, "JAAS implementation owner");
            name = requireText(name, "JAAS implementation name");
            descriptor = requireText(descriptor, "JAAS implementation descriptor");
            boolean initialize = JaasLoginModuleCallSite.INITIALIZE_NAME.equals(name)
                    && JaasLoginModuleCallSite.INITIALIZE_DESCRIPTOR.equals(descriptor);
            boolean login = JaasLoginModuleCallSite.LOGIN_NAME.equals(name)
                    && JaasLoginModuleCallSite.LOGIN_DESCRIPTOR.equals(descriptor);
            if (!initialize && !login) {
                throw new IllegalArgumentException("JAAS implementation method is not exact");
            }
        }

        public String methodKey() {
            return owner + "#" + name + descriptor;
        }
    }

    public JaasLoginModuleDispatch {
        callSite = Objects.requireNonNull(callSite, "JAAS call site");
        if (callSite.kind() != JaasLoginModuleCallSite.Kind.LOGIN_MODULE_INITIALIZE
                && callSite.kind() != JaasLoginModuleCallSite.Kind.LOGIN_MODULE_LOGIN) {
            throw new IllegalArgumentException("JAAS dispatch requires a lifecycle call");
        }
        targetClass = requireText(targetClass, "JAAS target class");
        if (!TARGET_CLASS.equals(targetClass)) {
            throw new IllegalArgumentException("JAAS target class is not JndiLoginModule");
        }
        source = Objects.requireNonNull(source, "JAAS resolution source");
        status = Objects.requireNonNull(status, "JAAS dispatch status");
        sourceInfo = sourceInfo == null
                ? new JdkSourceInfo(JdkSourceInfo.ImageKind.UNKNOWN, 0) : sourceInfo;
        if (status == Status.RESOLVED) {
            if (implementation == null || source == Source.UNKNOWN) {
                throw new IllegalArgumentException("resolved JAAS dispatch lacks proof");
            }
            if (callSite.kind() == JaasLoginModuleCallSite.Kind.LOGIN_MODULE_INITIALIZE
                    && (!JaasLoginModuleCallSite.INITIALIZE_NAME.equals(implementation.name())
                    || !JaasLoginModuleCallSite.INITIALIZE_DESCRIPTOR.equals(
                    implementation.descriptor()))) {
                throw new IllegalArgumentException("initialize dispatch method mismatch");
            }
            if (callSite.kind() == JaasLoginModuleCallSite.Kind.LOGIN_MODULE_LOGIN
                    && (!JaasLoginModuleCallSite.LOGIN_NAME.equals(implementation.name())
                    || !JaasLoginModuleCallSite.LOGIN_DESCRIPTOR.equals(
                    implementation.descriptor()))) {
                throw new IllegalArgumentException("login dispatch method mismatch");
            }
        } else if (implementation != null) {
            throw new IllegalArgumentException("unresolved JAAS dispatch has implementation");
        }
        if (source == Source.JDK_IMAGE && sourceInfo.imageKind() == JdkSourceInfo.ImageKind.UNKNOWN) {
            throw new IllegalArgumentException("JDK dispatch requires image provenance");
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
