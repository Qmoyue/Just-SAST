package io.just.sast.verify;

/**
 * Runtime gate for the target child. The target JDK selected by {@code --jdk-home} may differ
 * from Just's JDK17 process, but every child must still run behind the authenticated Job Object.
 * Security Manager availability is only compatibility detail and never an isolation boundary.
 */
public record JdkRuntimePolicy(int feature, boolean jvmPolicyAvailable, String reason) {

    public JdkRuntimePolicy {
        feature = Math.max(0, feature);
        reason = reason == null || reason.isBlank() ? "unknown" : reason;
    }

    public static JdkRuntimePolicy forFeature(int feature) {
        int normalized = Math.max(0, feature);
        if (normalized >= 8) {
            return new JdkRuntimePolicy(normalized, normalized < 24,
                    normalized < 24
                            ? "jvm-policy-defense-in-depth"
                            : "security-manager-unavailable-job-object-required");
        }
        return new JdkRuntimePolicy(normalized, false, "jdk-too-old");
    }

    /** A target child is admissible only when the parent has configured the Job Object. */
    public boolean admissible(boolean jobObjectReady) {
        return feature >= 8 && jobObjectReady;
    }
}
