package io.just.sast.cli;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.tools.JavaCompiler;
import javax.tools.SimpleJavaFileObject;
import javax.tools.ToolProvider;
import java.io.File;
import java.net.URLClassLoader;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Production boundary fixtures for the static-only two-mode entry point. */
class StaticModeBehaviorTest {

    @Test
    void legacyVerificationRequestStillDoesNotLoadTargetClass(@TempDir Path temp) throws Exception {
        Path sentinel = temp.resolve("target-loaded.txt");
        String path = sentinel.toString().replace("\\", "\\\\");
        Path jar = compileToJar(temp.resolve("target.jar"), Map.of("app.Sentinel", """
                package app;
                public class Sentinel implements java.io.Serializable {
                    static {
                        try {
                            java.nio.file.Files.writeString(
                                    java.nio.file.Path.of("%s"), "loaded");
                        } catch (java.io.IOException failure) {
                            throw new java.io.UncheckedIOException(failure);
                        }
                    }
                    private void readObject(java.io.ObjectInputStream in) throws Exception {
                        in.defaultReadObject();
                    }
                }
                """.formatted(path)));
        try (URLClassLoader positiveControl = new URLClassLoader(
                new java.net.URL[]{jar.toUri().toURL()}, null)) {
            Class.forName("app.Sentinel", true, positiveControl);
        }
        assertEquals("loaded", Files.readString(sentinel),
                "the sentinel must prove that class initialization would be observable");
        Files.delete(sentinel);

        ScanPipeline.run(jar, null, temp.resolve("out"), null, false, true, null,
                true, 20);
        assertFalse(Files.exists(sentinel), "static analysis must not initialize target classes");
        String report = Files.readString(temp.resolve("out").resolve("report.json"));
        assertTrue(report.contains("\"target_code_executed\":\"NO\""));
    }

    @Test
    void componentKeepsKernelCandidateWhileApplicationRequiresJoin(@TempDir Path temp)
            throws Exception {
        Path dependency = compileToJar(temp.resolve("dependency.jar"), Map.of("dep.Gadget", """
                package dep;
                public class Gadget implements java.io.Serializable {
                    private String cmd;
                    private void readObject(java.io.ObjectInputStream in) throws Exception {
                        java.lang.Runtime.getRuntime().exec(this.cmd);
                        in.defaultReadObject();
                    }
                }
                """));
        Path componentOut = temp.resolve("component");
        ScanPipeline.run(dependency, null, componentOut, null, false, true, null,
                false, 0, false, false, false, null, null, false,
                ModeDemandPolicy.forMode(ScanMode.COMPONENT));
        String component = Files.readString(componentOut.resolve("report.json"));
        assertTrue(component.contains("\"mode\":\"component\""));
        assertTrue(component.contains("\"exported\":true"),
                "component mode must retain a dependency/kernel candidate without an app root");

        Path application = compileToJar(temp.resolve("application.jar"), Map.of("app.Main", """
                package app;
                public class Main { public void health() { } }
                """));
        Path applicationOut = temp.resolve("application");
        ScanPipeline.run(application, List.of(dependency), applicationOut, null, false, true, null,
                false, 0, false, false, false, null, null, false,
                ModeDemandPolicy.forMode(ScanMode.APPLICATION));
        String applicationReport = Files.readString(applicationOut.resolve("report.json"));
        assertTrue(applicationReport.contains("\"mode\":\"application\""));
        assertFalse(applicationReport.contains("\"exported\":true"),
                "application mode must not promote a dependency chain without a join");
    }

    @Test
    void negativeFixtureExplainsAnEmptyStaticResult(@TempDir Path temp) throws Exception {
        Path target = compileToJar(temp.resolve("negative.jar"), Map.of("negative.Empty", """
                package negative;
                public class Empty { public void health() { } }
                """));
        Path output = temp.resolve("negative-report");
        ScanPipeline.run(target, null, output, null, false, true, null,
                false, 0, false, false, false, null, null, false,
                ModeDemandPolicy.forMode(ScanMode.COMPONENT));
        String json = Files.readString(output.resolve("report.json"));
        String markdown = Files.readString(output.resolve("report.md"));
        assertTrue(json.contains("\"chains\":[]"), "negative fixture should have no chain rows");
        assertTrue(json.contains("\"kind\":\"EMPTY\""));
        assertTrue(json.contains("\"NO_CANDIDATES\""));
        assertTrue(markdown.contains("not proof that the artifact is safe"));
    }

    private static final class Source extends SimpleJavaFileObject {
        private final String code;

        Source(String className, String code) {
            super(URI.create("string:///" + className.replace('.', '/') + ".java"), Kind.SOURCE);
            this.code = code;
        }

        @Override
        public CharSequence getCharContent(boolean ignoreEncodingErrors) {
            return code;
        }
    }

    private static Path compileToJar(Path jarFile, Map<String, String> sources) throws Exception {
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        File classes = Files.createTempDirectory("just-static-mode-classes").toFile();
        try (var manager = compiler.getStandardFileManager(null, null, null)) {
            manager.setLocation(javax.tools.StandardLocation.CLASS_OUTPUT, List.of(classes));
            boolean ok = compiler.getTask(null, manager, null, null, null,
                    sources.entrySet().stream()
                            .map(entry -> (javax.tools.JavaFileObject)
                                    new Source(entry.getKey(), entry.getValue()))
                            .toList()).call();
            if (!ok) throw new IllegalStateException("fixture compilation failed");
        }
        try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(jarFile))) {
            addClasses(zip, classes, "");
        }
        return jarFile;
    }

    private static void addClasses(ZipOutputStream zip, File directory, String prefix)
            throws Exception {
        File[] files = directory.listFiles();
        if (files == null) return;
        for (File file : files) {
            String name = prefix + file.getName();
            if (file.isDirectory()) addClasses(zip, file, name + "/");
            else if (name.endsWith(".class")) {
                zip.putNextEntry(new ZipEntry(name));
                zip.write(Files.readAllBytes(file.toPath()));
                zip.closeEntry();
            }
        }
    }
}
