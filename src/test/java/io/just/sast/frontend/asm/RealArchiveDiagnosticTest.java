package io.just.sast.frontend.asm;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

/** Temporary evidence probe for a real fat artifact; skipped when benchmark fixtures are absent. */
class RealArchiveDiagnosticTest {

    @Test
    void realFatArtifactDoesNotMisclassifyNestedAlignmentAsCorruption() throws Exception {
        java.nio.file.Path artifact = java.nio.file.Path.of("benchmark", "babychain", "babychain.jar");
        Assumptions.assumeTrue(java.nio.file.Files.isRegularFile(artifact));
        JarReader.ReadResult result = new JarReader().readDetailed(artifact, 8);
        List<String> corruption = result.completenessReasons().stream()
                .filter(reason -> reason.equals("ARCHIVE_CORRUPT"))
                .toList();
        System.out.println("REAL_ARCHIVE classes=" + result.classes().size()
                + " corruption=" + corruption);
        assertTrue(corruption.isEmpty(), corruption.toString());
    }
}
