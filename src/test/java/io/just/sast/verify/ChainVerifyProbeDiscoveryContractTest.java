package io.just.sast.verify;

import io.just.sast.run.InputBudget;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ChainVerifyProbeDiscoveryContractTest {

    @Test
    void directoryDiscoveryStopsAtTheRequestedBound(@TempDir Path temp) throws Exception {
        Path root = Files.createDirectory(temp.resolve("classes"));
        Files.write(root.resolve("A.class"), new byte[]{0});
        Files.write(root.resolve("B.class"), new byte[]{0});
        Files.write(root.resolve("C.class"), new byte[]{0});
        Files.writeString(root.resolve("README.txt"), "ignored");

        List<String> entries = ChainVerifyProbe.boundedClassPathEntries(root.toString(), 2);
        assertEquals(2, entries.size());
        assertTrue(entries.stream().allMatch(value -> value.endsWith(".class")), entries::toString);
    }

    @Test
    void jarDiscoveryStopsAtTheRequestedBound(@TempDir Path temp) throws Exception {
        Path jar = temp.resolve("classes.jar");
        try (OutputStream output = Files.newOutputStream(jar);
             JarOutputStream zip = new JarOutputStream(output)) {
            for (String name : List.of("A.class", "B.class", "C.class")) {
                zip.putNextEntry(new JarEntry(name));
                zip.write(0);
                zip.closeEntry();
            }
        }

        List<String> entries = ChainVerifyProbe.boundedClassPathEntries(jar.toString(), 2);
        assertEquals(2, entries.size());
        assertTrue(entries.stream().allMatch(value -> value.endsWith(".class")), entries::toString);
    }

    @Test
    void classpathDiscoveryUsesCallerArchiveBudgetAcrossRoots(@TempDir Path temp) throws Exception {
        Path first = temp.resolve("first.jar");
        Path second = temp.resolve("second.jar");
        writeSingleClassJar(first, "A.class");
        writeSingleClassJar(second, "B.class");
        InputBudget policy = InputBudget.defaults().withArchiveLimits(
                1024 * 1024, 1024 * 1024, 1024 * 1024, 1024, 1, 1, 64);
        InputBudget.Tracker tracker = policy.tracker();

        List<String> entries = ChainVerifyProbe.boundedClassPathEntries(
                first + java.io.File.pathSeparator + second, 8, tracker);
        assertEquals(1, entries.size(), () -> entries + " trackerEntries=" + tracker.entries());
        assertTrue(tracker.entries() > policy.maxArchiveEntries(),
                "the caller tracker must retain the attempted second root and stay exhausted");
    }

    @Test
    void isolationMarkerReadUsesCallerBudgetAndAcceptsStableMarker(@TempDir Path temp)
            throws Exception {
        Path marker = temp.resolve("ready.marker");
        Files.writeString(marker, "nonce-123\n");

        assertTrue(ChainVerifyProbe.readIsolationMarker(marker, "nonce-123",
                InputBudget.defaults()));

        InputBudget tiny = InputBudget.defaults().withArchiveLimits(
                1024, 1024, 4, 4, 32, 1, 32);
        assertFalse(ChainVerifyProbe.readIsolationMarker(marker, "nonce-123", tiny));
    }

    @Test
    void isolationMarkerRejectsLinksFailClosed(@TempDir Path temp) throws Exception {
        Path target = temp.resolve("target.marker");
        Files.writeString(target, "nonce-123");
        Path link = temp.resolve("link.marker");
        try {
            Files.createSymbolicLink(link, target);
            assertFalse(ChainVerifyProbe.readIsolationMarker(link, "nonce-123",
                    InputBudget.defaults()));
        } catch (UnsupportedOperationException | java.nio.file.FileSystemException ignored) {
            // Link creation is a host capability; stable regular-file coverage still runs.
        }
    }

    private static void writeSingleClassJar(Path jar, String name) throws Exception {
        try (OutputStream output = Files.newOutputStream(jar);
             JarOutputStream zip = new JarOutputStream(output)) {
            zip.putNextEntry(new JarEntry(name));
            zip.write(0);
            zip.closeEntry();
        }
    }
}
