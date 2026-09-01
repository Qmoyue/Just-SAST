package io.just.sast.verify;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JdkRuntimePolicyTest {

    @Test
    void legacyJdksUseJvmDefenseInDepth() {
        JdkRuntimePolicy policy = JdkRuntimePolicy.forFeature(8);

        assertTrue(policy.jvmPolicyAvailable());
        assertFalse(policy.osStrictRequired());
        assertTrue(policy.admissible(false));
    }

    @Test
    void jdk24AndLaterRequireTheOuterOsBoundary() {
        JdkRuntimePolicy policy = JdkRuntimePolicy.forFeature(24);

        assertFalse(policy.jvmPolicyAvailable());
        assertTrue(policy.osStrictRequired());
        assertFalse(policy.admissible(false));
        assertTrue(policy.admissible(true));
    }
}
