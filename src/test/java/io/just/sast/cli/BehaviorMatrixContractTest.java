package io.just.sast.cli;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** User-level behavior coverage for a failed fixture in the report matrix. */
class BehaviorMatrixContractTest {

    @Test
    void failedCacheFixtureIsVisibleAndCannotBecomeAnEmptyReport(@TempDir Path temp)
            throws Exception {
        Path target = temp.resolve("valid-target.jar");
        writeJar(target);
        Path cacheFile = Files.writeString(temp.resolve("cache-file"), "not a cache directory");
        Path output = temp.resolve("output");

        ByteArrayOutputStream captured = new ByteArrayOutputStream();
        PrintStream original = System.err;
        int code;
        try {
            System.setErr(new PrintStream(captured, true, StandardCharsets.UTF_8));
            code = new CommandLine(new JustMain()).execute(
                    "scan", "--jar", target.toString(), "--offline", "--fast",
                    "--cache", cacheFile.toString(), "--output", output.toString());
        } finally {
            System.setErr(original);
        }

        String error = captured.toString(StandardCharsets.UTF_8);
        assertEquals(3, code);
        assertTrue(error.contains("缓存操作失败"), error);
        assertFalse(Files.exists(output),
                "a failed run must not publish a plausible empty report");
    }

    private static void writeJar(Path file) throws Exception {
        try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(file))) {
            output.putNextEntry(new JarEntry("META-INF/fixture.marker"));
            output.write(new byte[]{1, 2, 3});
            output.closeEntry();
        }
    }
}
