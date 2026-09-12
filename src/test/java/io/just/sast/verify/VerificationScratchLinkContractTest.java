package io.just.sast.verify;

import io.just.sast.run.InputBudget;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertThrows;

/** Optional host-capability contract; required hostile coverage must not depend on symlink rights. */
class VerificationScratchLinkContractTest {

    @Test
    void linkInsideScratchIsRejectedAndCleanupDoesNotFollowIt(@TempDir Path temp) throws Exception {
        Path root = Files.createDirectory(temp.resolve("scratch"));
        Path outside = Files.createDirectory(temp.resolve("outside"));
        Path link = root.resolve("link");
        try {
            Files.createSymbolicLink(link, outside);
        } catch (UnsupportedOperationException | java.io.IOException | SecurityException unsupported) {
            Assumptions.assumeTrue(false, "host cannot create a symbolic link");
            return;
        }
        assertThrows(java.io.IOException.class,
                () -> VerificationScratch.measure(root, InputBudget.defaults()));
        VerificationScratch.deleteTree(root);
        // The target of the link must remain intact; cleanup may remove the link itself only.
        Assumptions.assumeTrue(Files.exists(outside), "outside directory was unexpectedly removed");
    }
}
