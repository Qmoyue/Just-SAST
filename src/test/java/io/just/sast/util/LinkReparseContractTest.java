package io.just.sast.util;

import io.just.sast.frontend.asm.JarReader;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Optional host capability contract for rejecting symlinked scan/classpath roots. */
class LinkReparseContractTest {

    @Test
    void jarReaderRejectsSymlinkedDirectoryBeforeFollowing(@TempDir Path tmp) throws Exception {
        Path link = symlinkedDirectory(tmp);
        IOException failure = assertThrows(IOException.class,
                () -> new JarReader().readDetailed(link));
        assertTrue(failure.getMessage().contains("符号链接")
                        || failure.getMessage().contains("reparse"), failure.getMessage());
    }

    private static Path symlinkedDirectory(Path tmp) throws IOException {
        Path real = tmp.resolve("real-classes");
        Files.createDirectories(real);
        Files.write(real.resolve("Marker.class"), new byte[]{1});
        Path link = tmp.resolve("linked-classes");
        try {
            Files.createSymbolicLink(link, real.getFileName());
        } catch (UnsupportedOperationException | IOException | SecurityException unsupported) {
            Assumptions.assumeTrue(false,
                    "symbolic links unavailable: " + unsupported.getMessage());
        }
        return link;
    }
}
