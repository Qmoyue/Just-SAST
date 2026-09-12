package io.just.sast.verify;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * P2.9 protection for the separately compiled Java-8 verifier boundary.
 *
 * <p>The legacy verifier cannot import the Java-17 record implementation of InputBudget at
 * runtime.  Its parent-owned marker and Just-owned native fixture therefore use the verifier's
 * small, versioned compatibility reader.  Keep this source contract until the verifier is
 * generated from a shared Java-8-compatible module; direct bulk reads must not reappear.</p>
 */
class LegacyVerifierSourceContractTest {

    @Test
    void legacyBoundaryUsesVersionedStableBoundedReader() throws Exception {
        Path sourcePath = Path.of("src", "verify8", "java", "io", "just", "sast", "verify",
                "legacy", "LegacyChainVerifyProbe.java");
        String source = Files.readString(sourcePath);

        assertFalse(source.contains("Files.readAllBytes("),
                "legacy verifier must not allocate an unchecked file read");
        assertTrue(source.contains("LEGACY_INPUT_BUDGET_V1"),
                "legacy verifier must disclose its Java-8 compatibility budget");
        assertTrue(source.contains("readStableBoundedFile("),
                "marker/native reads must share one bounded reader");
        assertTrue(source.contains("LinkOption.NOFOLLOW_LINKS"),
                "legacy file inputs must reject final-component links");
        assertTrue(source.contains("verifyStableIdentity("),
                "legacy file inputs must verify identity after the read");
        assertFalse(source.contains("io.just.sast.util.ArchiveLimits"),
                "verify8 must not depend on a Java-17-only utility absent from its artifact");
    }
}
