package io.just.sast.verify;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.List;
import java.net.URLClassLoader;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** fat JAR/WAR classpath 展开契约：可加载、可清理且拒绝路径穿越。 */
class NestedClasspathTest {

    @Test
    void expandsBootLayoutAndCleansArtifacts(@TempDir Path tmp) throws Exception {
        Path archive = tmp.resolve("app.war");
        try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(archive))) {
            put(zip, "BOOT-INF/classes/app/Marker.class", new byte[]{1, 2, 3});
            put(zip, "BOOT-INF/lib/dependency.jar", "not-a-real-jar".getBytes(StandardCharsets.UTF_8));
        }

        Path extractedRoot;
        try (NestedClasspath classpath = NestedClasspath.open(List.of(archive))) {
            assertTrue(classpath.entries().size() == 3, classpath.entries().toString());
            Path classes = classpath.entries().get(1);
            extractedRoot = classes.getParent();
            assertTrue(Files.isRegularFile(classes.resolve("app/Marker.class")));
            assertTrue(classpath.entries().get(2).getFileName().toString().equals("dependency.jar"));
        }
        assertFalse(Files.exists(extractedRoot), "关闭 classpath 后不得残留解包目录");
    }

    @Test
    void rejectsNestedPathTraversal(@TempDir Path tmp) throws Exception {
        Path archive = tmp.resolve("unsafe.war");
        try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(archive))) {
            put(zip, "BOOT-INF/classes/../outside.class", new byte[]{1});
        }
        assertThrows(java.io.IOException.class, () -> NestedClasspath.open(List.of(archive)));
    }

    @Test
    void corruptArchiveFailsClosedWithStableReason(@TempDir Path tmp) throws Exception {
        Path archive = tmp.resolve("corrupt.war");
        Files.writeString(archive, "not-a-zip", StandardCharsets.US_ASCII);
        java.io.IOException failure = assertThrows(java.io.IOException.class,
                () -> NestedClasspath.open(List.of(archive)));
        assertTrue(failure.getMessage().startsWith("ARCHIVE_CORRUPT"), failure.getMessage());
    }

    @Test
    void extractedApplicationClassesAreLoadable(@TempDir Path tmp) throws Exception {
        String binaryName = "io.just.sast.verify.NestedClasspathFixture";
        String resourceName = "/io/just/sast/verify/NestedClasspathFixture.class";
        byte[] classBytes = NestedClasspathTest.class.getResourceAsStream(resourceName)
                .readAllBytes();
        Path archive = tmp.resolve("application.war");
        try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(archive))) {
            put(zip, "WEB-INF/classes/io/just/sast/verify/NestedClasspathFixture.class", classBytes);
        }

        try (NestedClasspath classpath = NestedClasspath.open(List.of(archive));
             URLClassLoader loader = new URLClassLoader(
                     classpath.urls().toArray(java.net.URL[]::new), null)) {
            Class<?> loaded = loader.loadClass(binaryName);
            assertEquals(binaryName, loaded.getName());
        }
    }

    @Test
    void expandsWorkspaceWarApplicationClassesWhenCorpusIsPresent() throws Exception {
        Path war = Path.of("benchmark", "n1cat", "n1cat.war").toAbsolutePath().normalize();
        Assumptions.assumeTrue(Files.isRegularFile(war));
        try (NestedClasspath classpath = NestedClasspath.open(List.of(war))) {
            assertTrue(classpath.entries().stream().anyMatch(path ->
                    Files.isRegularFile(path.resolve("ctf/n1cat/User.class"))),
                    classpath.entries().toString());
        }
    }

    @Test
    void recursivelyExpandsFatDependencyWithoutResettingClasspathBudget(@TempDir Path tmp)
            throws Exception {
        byte[] classBytes = NestedClasspathTest.class.getResourceAsStream(
                "/io/just/sast/verify/NestedClasspathFixture.class").readAllBytes();
        Path outer = tmp.resolve("outer.war");
        byte[] inner = zipBytes("inner-fat.jar", zip -> {
            put(zip, "BOOT-INF/classes/io/just/sast/verify/NestedClasspathFixture.class", classBytes);
        });
        try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(outer))) {
            put(zip, "BOOT-INF/lib/inner-fat.jar", inner);
        }

        List<Path> extracted;
        try (NestedClasspath classpath = NestedClasspath.open(List.of(outer))) {
            extracted = classpath.entries().stream()
                    .filter(path -> Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS))
                    .toList();
            assertTrue(extracted.stream().anyMatch(path -> Files.isRegularFile(path.resolve(
                    "io/just/sast/verify/NestedClasspathFixture.class"))),
                    classpath.entries().toString());
        }
        assertTrue(extracted.stream().noneMatch(Files::exists),
                "recursive extraction artifacts must be cleaned");
    }

    @Test
    void callerTrackerIsNotResetAcrossClasspathExpansions(@TempDir Path tmp) throws Exception {
        Path archive = tmp.resolve("shared-budget.war");
        try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(archive))) {
            put(zip, "BOOT-INF/classes/app/Marker.class", new byte[]{1, 2, 3});
        }
        io.just.sast.run.InputBudget policy = io.just.sast.run.InputBudget.defaults()
                .withArchiveLimits(16L * 1024 * 1024, 16L * 1024 * 1024,
                        16L * 1024 * 1024, 1024L, 1, 2, 128);
        io.just.sast.run.InputBudget.Tracker tracker = policy.tracker();
        try (NestedClasspath ignored = NestedClasspath.open(List.of(archive), policy, tracker)) {
            assertEquals(1, tracker.entries());
        }
        java.io.IOException failure = assertThrows(java.io.IOException.class,
                () -> NestedClasspath.open(List.of(archive), policy, tracker));
        assertTrue(failure.getMessage().contains("archive entry count exceeds limit"),
                failure.getMessage());
    }

    @Test
    void rejectsExtractionParentThatWasMaterializedAsAFile(@TempDir Path tmp) throws Exception {
        Path archive = tmp.resolve("parent-file.war");
        try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(archive))) {
            // The first entry creates classes/app as a regular output file.  The second
            // entry would need classes/app to be a directory; component-wise parent
            // creation must reject it before opening the output stream.
            put(zip, "BOOT-INF/classes/app", new byte[]{1});
            put(zip, "BOOT-INF/classes/app/Marker.class", new byte[]{2});
        }
        java.io.IOException failure = assertThrows(java.io.IOException.class,
                () -> NestedClasspath.open(List.of(archive)));
        assertTrue(failure.getMessage().contains("unsafe nested output parent"),
                failure.getMessage());
    }

    @Test
    void outputParentReplacementAfterSnapshotFailsClosed(@TempDir Path tmp) throws Exception {
        Path base = Files.createDirectories(tmp.resolve("owned"));
        Path parent = Files.createDirectories(base.resolve("classes").resolve("app"));
        NestedClasspath.OutputParentSnapshot snapshot =
                NestedClasspath.snapshotOutputParentForContract(base, parent);

        // Replace a snapshotted directory with a non-directory.  This models a concurrent
        // checkout/build replacement without requiring symlink privileges on Windows.
        Files.delete(parent);
        Files.writeString(parent, "replacement", StandardCharsets.UTF_8);

        java.io.IOException failure = assertThrows(java.io.IOException.class,
                () -> NestedClasspath.verifyOutputParentForContract(snapshot));
        assertTrue(failure.getMessage().contains("output parent changed during extraction")
                        || failure.getMessage().contains("unsafe nested output parent"),
                failure.getMessage());
    }

    @Test
    void materializedFatArchiveUsesChildJdkMultiReleaseFeature(@TempDir Path tmp) throws Exception {
        Path archive = tmp.resolve("multi-release.war");
        try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(archive))) {
            put(zip, "META-INF/MANIFEST.MF",
                    "Manifest-Version: 1.0\r\nMulti-Release: true\r\n\r\n"
                            .getBytes(StandardCharsets.US_ASCII));
            put(zip, "BOOT-INF/classes/io/example/Main.class", "base".getBytes(StandardCharsets.UTF_8));
            put(zip, "BOOT-INF/classes/META-INF/versions/9/io/example/Main.class",
                    "v9".getBytes(StandardCharsets.UTF_8));
            put(zip, "BOOT-INF/classes/META-INF/versions/17/io/example/Main.class",
                    "v17".getBytes(StandardCharsets.UTF_8));
        }

        try (NestedClasspath classpath = NestedClasspath.open(List.of(archive),
                io.just.sast.run.InputBudget.defaults(), 11)) {
            Path classes = classpath.entries().get(1);
            assertEquals("v9", Files.readString(classes.resolve("io/example/Main.class")));
            assertFalse(Files.exists(classes.resolve("META-INF/versions/17/io/example/Main.class")));
        }
        try (NestedClasspath classpath = NestedClasspath.open(List.of(archive),
                io.just.sast.run.InputBudget.defaults(), 8)) {
            Path classes = classpath.entries().get(1);
            assertEquals("base", Files.readString(classes.resolve("io/example/Main.class")));
        }
    }

    @FunctionalInterface
    private interface ZipWriter {
        void write(ZipOutputStream zip) throws Exception;
    }

    private static byte[] zipBytes(String ignored, ZipWriter writer) throws Exception {
        java.io.ByteArrayOutputStream output = new java.io.ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(output)) {
            writer.write(zip);
        }
        return output.toByteArray();
    }

    private static void put(ZipOutputStream zip, String name, byte[] content) throws Exception {
        zip.putNextEntry(new ZipEntry(name));
        zip.write(content);
        zip.closeEntry();
    }
}

final class NestedClasspathFixture {
}
