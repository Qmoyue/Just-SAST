package io.just.sast.report;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertThrows;

/** Optional host-capability contract for report parent link/reparse rejection. */
class ReportLinkReparseContractTest {

    @Test
    void reportLayoutAndAtomicWriterRejectParentLink(@TempDir Path tmp) throws Exception {
        Path real = Files.createDirectories(tmp.resolve("real"));
        Path link = tmp.resolve("linked");
        try {
            Files.createSymbolicLink(link, real.getFileName());
        } catch (UnsupportedOperationException | IOException | SecurityException unsupported) {
            Assumptions.assumeTrue(false,
                    "symbolic links unavailable: " + unsupported.getMessage());
        }
        assertThrows(IOException.class, () -> ReportLayout.create(link.resolve("report")));
        assertThrows(IOException.class, () -> AtomicFiles.tempSibling(
                link.resolve("report").resolve("findings.json")));
    }
}
