package io.just.sast.verify;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
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

    private static void put(ZipOutputStream zip, String name, byte[] content) throws Exception {
        zip.putNextEntry(new ZipEntry(name));
        zip.write(content);
        zip.closeEntry();
    }
}

final class NestedClasspathFixture {
}
