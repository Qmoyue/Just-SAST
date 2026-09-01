package io.just.sast.verify;

/**
 * Runtime capability decision shared by the verifier launcher and its JDK matrix tests.
 * Security Manager availability is a compatibility detail; OS_STRICT is the only admissible
 * isolation boundary for JDKs that no longer provide that detail.
 */
public record JdkRuntimePolicy(int feature, boolean jvmPolicyAvailable,
                               boolean osStrictRequired, String reason) {

    public JdkRuntimePolicy {
        feature = Math.max(0, feature);
        reason = reason == null || reason.isBlank() ? "unknown" : reason;
    }

    public static JdkRuntimePolicy forFeature(int feature) {
        int normalized = Math.max(0, feature);
        if (normalized >= 24) {
            return new JdkRuntimePolicy(normalized, false, true,
                    "security-manager-removed-os-strict-required");
        }
        if (normalized >= 8) {
            return new JdkRuntimePolicy(normalized, true, false,
                    "jvm-policy-defense-in-depth");
        }
        return new JdkRuntimePolicy(normalized, false, true, "jdk-too-old");
    }

    public boolean admissible(boolean strictOsReady) {
        return jvmPolicyAvailable || (osStrictRequired && strictOsReady);
    }
}
