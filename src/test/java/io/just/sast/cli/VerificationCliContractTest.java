package io.just.sast.cli;

import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.junit.jupiter.api.Test;
import picocli.CommandLine;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.io.StringWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class VerificationCliContractTest {

    @Test
    void scanHelpExposesOnlyTheStaticScanContract() {
        CommandLine root = new CommandLine(new JustMain());
        StringWriter output = new StringWriter();
        root.getSubcommands().get("scan").usage(new PrintWriter(output));
        String help = output.toString();

        assertTrue(help.contains("--pom"));
        assertTrue(help.contains("--repository"));
        assertTrue(help.contains("--offline"));
        assertTrue(help.contains("--jdk-home"));
        assertFalse(help.contains("--no-verify"));
        assertFalse(help.contains("--verify-budget"));
        assertFalse(help.contains("--safe-exec"));
        assertFalse(help.contains("--safe-real-sink"));
        assertFalse(help.contains("--require-os-isolation"));
    }

    @Test
    void performanceHelpHidesRemovedExecutionSwitches() {
        CommandLine root = new CommandLine(new JustMain());
        StringWriter output = new StringWriter();
        root.getSubcommands().get("perf").usage(new PrintWriter(output));
        String help = output.toString();

        assertTrue(help.contains("--filter-p50-limit-ms"));
        assertFalse(help.contains("--dynamic-p50-limit-ms"));
        assertFalse(help.contains("--no-verify"));
        assertFalse(help.contains("--verify-budget"));
        assertFalse(help.contains("--safe-exec"));
        assertFalse(help.contains("--safe-real-sink"));
        assertFalse(help.contains("--require-os-isolation"));
    }

    @Test
    void subcommandHelpDoesNotRequireOperationalInputs() {
        assertEquals(0, new CommandLine(new JustMain()).execute("scan", "--help"));
        assertEquals(0, new CommandLine(new JustMain()).execute("perf", "--help"));
        assertEquals(0, new CommandLine(new JustMain()).execute("diff", "--help"));
    }

    @Test
    void scanAndPerformanceDoNotExposeVerifierConfiguration() {
        CommandLine root = new CommandLine(new JustMain());
        StringWriter scanOutput = new StringWriter();
        root.getSubcommands().get("scan").usage(new PrintWriter(scanOutput));
        StringWriter performanceOutput = new StringWriter();
        root.getSubcommands().get("perf").usage(new PrintWriter(performanceOutput));

        assertFalse(scanOutput.toString().contains("verify"));
        assertFalse(performanceOutput.toString().contains("verify"));
    }

    @Test
    void performanceDefaultDisclosureIsStaticOnly(@TempDir Path temp) {
        ByteArrayOutputStream captured = new ByteArrayOutputStream();
        PrintStream original = System.err;
        int code;
        try {
            System.setErr(new PrintStream(captured, true, StandardCharsets.UTF_8));
            code = new CommandLine(new JustMain()).execute(
                    "perf", "--jar", temp.resolve("missing.jar").toString());
        } finally {
            System.setErr(original);
        }

        String error = captured.toString(StandardCharsets.UTF_8);
        assertEquals(2, code);
        assertTrue(error.contains("analysisMode=STATIC_ONLY"), error);
        assertTrue(error.contains("boundedFiltering=ANALYSIS_ONLY"), error);
        assertFalse(error.contains("verificationMode=AUTO"), error);
    }

    @Test
    void removedExecutionOptionsAreUsageErrorsForScanAndPerformance(@TempDir Path temp) {
        Path missing = temp.resolve("not-an-input.jar");
        for (String option : List.of("--no-verify", "--verify-budget", "--safe-exec",
                "--safe-real-sink", "--require-os-isolation")) {
            int scanCode = new CommandLine(new JustMain()).execute(
                    "scan", "--jar", missing.toString(), option);
            assertEquals(2, scanCode, "scan must reject removed option " + option);

            int performanceCode = new CommandLine(new JustMain()).execute(
                    "perf", "--jar", missing.toString(), option);
            assertEquals(2, performanceCode,
                    "perf must reject removed option " + option);
        }
    }

    @Test
    void cacheCannotBeSilentlySkippedWhenReportPoliciesAreRequested(@TempDir Path temp) {
        Path missing = temp.resolve("not-an-input.jar");
        ByteArrayOutputStream captured = new ByteArrayOutputStream();
        PrintStream original = System.err;
        int code;
        try {
            System.setErr(new PrintStream(captured, true, StandardCharsets.UTF_8));
            code = new CommandLine(new JustMain()).execute(
                    "scan", "--jar", missing.toString(),
                    "--cache", temp.resolve("cache").toString(),
                    "--baseline", temp.resolve("baseline").toString());
        } finally {
            System.setErr(original);
        }

        assertEquals(2, code);
        assertTrue(captured.toString(StandardCharsets.UTF_8)
                .contains("--cache 不能与 --baseline 或 --suppressions 同时使用"));
    }

    @Test
    void explicitPomRepositoryAndOfflineOptionsFeedTheStaticPipeline(@TempDir Path temp)
            throws Exception {
        Path repository = temp.resolve("repository");
        write(repository, "fixture/library/1.0/library-1.0.pom",
                pom("fixture", "library", "1.0", ""));
        writeJar(repository.resolve("fixture/library/1.0/library-1.0.jar"));
        Path root = temp.resolve("pom.xml");
        write(temp, "pom.xml", pom("fixture", "root", "1.0",
                "<dependencies><dependency><groupId>fixture</groupId>"
                        + "<artifactId>library</artifactId><version>1.0</version></dependency></dependencies>"));
        Path target = temp.resolve("target.jar");
        writeJar(target);
        Path output = temp.resolve("output");

        ByteArrayOutputStream captured = new ByteArrayOutputStream();
        PrintStream original = System.err;
        int code;
        try {
            System.setErr(new PrintStream(captured, true, StandardCharsets.UTF_8));
            code = new CommandLine(new JustMain()).execute(
                    "scan", "--jar", target.toString(), "--pom", root.toString(),
                    "--repository", repository.toUri().toString(), "--offline",
                    "--fast", "--cache", temp.resolve("maven-cache").toString(),
                    "--output", output.toString());
        } finally {
            System.setErr(original);
        }

        assertEquals(0, code);
        String log = captured.toString(StandardCharsets.UTF_8);
        assertTrue(log.contains("dependencyCompletion=COMPLETE")
                        && log.contains("resolutionWallMs=")
                        && log.contains("scanTiming=dependencyResolutionMs=")
                        && log.contains("filterMs="), log);
        assertTrue(Files.isDirectory(output));
        String inventory = Files.readString(output.resolve("evidence/dependencies.csv"));
        String bom = Files.readString(output.resolve("meta/dependencies.sbom.json"));
        String metadata = Files.readString(output.resolve("meta/scan-metadata.json"));
        assertTrue(inventory.contains("derived"));
        assertTrue(inventory.contains("maven:repository=repository-1"), inventory);
        assertTrue(inventory.contains("DECLARED_ENVIRONMENT"), inventory);
        assertTrue(bom.contains("MAVEN_POM_RESOLVED"), bom);
        assertTrue(metadata.contains("\"dependency_resolution_ms\"")
                        && metadata.contains("\"network_download_wall_ms\"")
                        && metadata.contains("\"analysis_ms\"")
                        && metadata.contains("\"report_ms\"")
                        && metadata.contains("\"total_wall_ms\""), metadata);
    }

    @Test
    void classDirectoryWithoutPomReportsTheMissingEnvironmentBoundary(@TempDir Path temp)
            throws Exception {
        Path classes = temp.resolve("class-input");
        Path marker = classes.resolve("fixture/Marker.class");
        Files.createDirectories(marker.getParent());
        try (var input = VerificationCliContractTest.class
                .getResourceAsStream("/io/just/sast/cli/VerificationCliContractTest.class")) {
            if (input == null) {
                throw new IOException("test class resource is missing");
            }
            Files.write(marker, input.readAllBytes());
        }
        Path output = temp.resolve("directory-output");

        int code = new CommandLine(new JustMain()).execute(
                "scan", "--jar", classes.toString(), "--fast", "--offline",
                "--output", output.toString());

        assertEquals(0, code);
        String bom = Files.readString(output.resolve("meta/dependencies.sbom.json"));
        assertTrue(bom.contains("CLASS_DIRECTORY_INPUT:0"), bom);
        assertTrue(bom.contains("MAVEN_POM_NOT_PROVIDED"), bom);
    }

    @Test
    void selfContainedFatJarWithoutPomScansOffline(@TempDir Path temp) throws Exception {
        Path fat = temp.resolve("self-contained.jar");
        writeFatJar(fat);
        Path output = temp.resolve("fat-output");
        ByteArrayOutputStream captured = new ByteArrayOutputStream();
        PrintStream original = System.err;
        int code;
        try {
            System.setErr(new PrintStream(captured, true, StandardCharsets.UTF_8));
            code = new CommandLine(new JustMain()).execute(
                    "scan", "--jar", fat.toString(), "--offline", "--fast",
                    "--output", output.toString());
        } finally {
            System.setErr(original);
        }

        String log = captured.toString(StandardCharsets.UTF_8);
        assertEquals(0, code, log);
        assertFalse(log.contains("USAGE_ERROR"), log);
        assertTrue(Files.isRegularFile(output.resolve("report.json")));
        String inventory = Files.readString(output.resolve("evidence/dependencies.csv"));
        String bom = Files.readString(output.resolve("meta/dependencies.sbom.json"));
        assertTrue(inventory.contains("nested:BOOT-INF/lib/closure.jar"), inventory);
        assertTrue(bom.contains("MAVEN_POM_NOT_PROVIDED"), bom);
        try (var files = Files.walk(temp)) {
            assertTrue(files.noneMatch(path -> path.getFileName() != null
                    && path.getFileName().toString().equalsIgnoreCase("pom.xml")));
        }
    }

    @Test
    void noPomRepositoryRequestIsRejectedInsteadOfGuessingDependencies(@TempDir Path temp)
            throws Exception {
        Path fat = temp.resolve("self-contained.jar");
        writeFatJar(fat);
        ByteArrayOutputStream captured = new ByteArrayOutputStream();
        PrintStream original = System.err;
        int code;
        try {
            System.setErr(new PrintStream(captured, true, StandardCharsets.UTF_8));
            code = new CommandLine(new JustMain()).execute(
                    "scan", "--jar", fat.toString(), "--offline", "--fast",
                    "--repository", temp.resolve("repository").toUri().toString(),
                    "--output", temp.resolve("rejected-output").toString());
        } finally {
            System.setErr(original);
        }

        assertEquals(2, code);
        assertTrue(captured.toString(StandardCharsets.UTF_8)
                .contains("无 POM 时不能使用 --repository"));
        assertFalse(Files.exists(temp.resolve("rejected-output")));
    }

    @Test
    void unparseableArchiveFailsThroughCliWithoutPublishingAnEmptyReport(@TempDir Path temp)
            throws Exception {
        Path input = temp.resolve("unparseable.jar");
        Files.writeString(input, "not a zip archive", StandardCharsets.US_ASCII);
        Path output = temp.resolve("unparseable-output");
        ByteArrayOutputStream captured = new ByteArrayOutputStream();
        PrintStream original = System.err;
        int code;
        try {
            System.setErr(new PrintStream(captured, true, StandardCharsets.UTF_8));
            code = new CommandLine(new JustMain()).execute(
                    "scan", "--jar", input.toString(), "--offline", "--fast",
                    "--output", output.toString());
        } finally {
            System.setErr(original);
        }

        String error = captured.toString(StandardCharsets.UTF_8);
        assertTrue(code != 0, error);
        assertTrue(error.contains("INPUT_UNPARSEABLE"), error);
        assertFalse(Files.exists(output));
    }

    @Test
    void missingTypeKeepsStaticReportBoundedWithoutGuessingCoordinates(@TempDir Path temp)
            throws Exception {
        Path target = temp.resolve("missing-type.jar");
        writeClassJar(target, "fixture/MissingReference.class", missingReferenceBytes());
        Path output = temp.resolve("missing-type-output");

        int code = new CommandLine(new JustMain()).execute(
                "scan", "--jar", target.toString(), "--offline", "--fast",
                "--output", output.toString());

        assertEquals(0, code);
        String json = Files.readString(output.resolve("report.json"));
        assertTrue(json.contains("\"coverage\":\"BOUNDED\""), json);
        assertTrue(json.contains("DEPENDENCY_INPUT_INCOMPLETE"), json);
        assertTrue(json.contains("MISSING_TYPE"), json);
        assertTrue(json.contains("MISSING_TYPE:missing/NotProvided"), json);
        assertTrue(Files.readString(output.resolve("meta/dependencies.sbom.json"))
                .contains("MAVEN_POM_NOT_PROVIDED"));
        assertFalse(json.contains("fixture:missing-reference"),
                "missing bytecode types must not become guessed Maven coordinates");
    }

    @Test
    void duplicateClassKeepsBothInputSourcesAndBoundsTheReport(@TempDir Path temp)
            throws Exception {
        byte[] duplicate = simpleClassBytes("fixture/Duplicate");
        Path target = temp.resolve("target.jar");
        Path dependency = temp.resolve("duplicate-dependency.jar");
        writeClassJar(target, "fixture/Duplicate.class", duplicate);
        writeClassJar(dependency, "fixture/Duplicate.class", duplicate);
        Path output = temp.resolve("duplicate-output");

        int code = new CommandLine(new JustMain()).execute(
                "scan", "--jar", target.toString(), "--deps", dependency.toString(),
                "--offline", "--fast", "--output", output.toString());

        assertEquals(0, code);
        String json = Files.readString(output.resolve("report.json"));
        assertTrue(json.contains("\"coverage\":\"BOUNDED\""), json);
        assertTrue(json.contains("DUPLICATE_CLASS"), json);
        String inventory = Files.readString(output.resolve("evidence/dependencies.csv"));
        assertTrue(inventory.contains("target"), inventory);
        assertTrue(inventory.contains("dependency-1"), inventory);
    }

    @Test
    void versionConflictKeepsBothMavenVersionsAndBoundsTheReport(@TempDir Path temp)
            throws Exception {
        Path repository = temp.resolve("repository");
        write(repository, "fixture/left/1.0/left-1.0.pom",
                pom("fixture", "left", "1.0",
                        "<dependencies>" + dependencyXml("common", "1.0") + "</dependencies>"));
        write(repository, "fixture/right/1.0/right-1.0.pom",
                pom("fixture", "right", "1.0",
                        "<dependencies>" + dependencyXml("common", "2.0") + "</dependencies>"));
        write(repository, "fixture/common/1.0/common-1.0.pom",
                pom("fixture", "common", "1.0", ""));
        write(repository, "fixture/common/2.0/common-2.0.pom",
                pom("fixture", "common", "2.0", ""));
        writeJar(repository.resolve("fixture/left/1.0/left-1.0.jar"));
        writeJar(repository.resolve("fixture/right/1.0/right-1.0.jar"));
        writeJar(repository.resolve("fixture/common/1.0/common-1.0.jar"));
        writeJar(repository.resolve("fixture/common/2.0/common-2.0.jar"));

        Path root = temp.resolve("pom.xml");
        write(temp, "pom.xml", pom("fixture", "root", "1.0",
                "<dependencies>"
                        + dependencyXml("left", "1.0")
                        + dependencyXml("right", "1.0")
                        + "</dependencies>"));
        Path output = temp.resolve("version-conflict-output");
        Path target = temp.resolve("target.jar");
        writeJar(target);

        int code = new CommandLine(new JustMain()).execute(
                "scan", "--jar", target.toString(), "--pom", root.toString(),
                "--repository", repository.toUri().toString(), "--offline", "--fast",
                "--cache", temp.resolve("maven-cache").toString(),
                "--output", output.toString());

        assertEquals(0, code);
        String json = Files.readString(output.resolve("report.json"));
        assertTrue(json.contains("\"coverage\":\"BOUNDED\""), json);
        assertTrue(json.contains("DEPENDENCY_VERSION_AMBIGUOUS"), json);
        String inventory = Files.readString(output.resolve("evidence/dependencies.csv"));
        assertTrue(inventory.contains("fixture:common:1.0:jar:"), inventory);
        assertTrue(inventory.contains("fixture:common:2.0:jar:"), inventory);
    }

    @Test
    void missingPomArtifactContinuesWithAnExplicitDependencyLimit(@TempDir Path temp)
            throws Exception {
        Path repository = temp.resolve("empty-repository");
        Files.createDirectories(repository);
        Path root = temp.resolve("pom.xml");
        write(temp, "pom.xml", pom("fixture", "root", "1.0",
                "<dependencies>" + dependencyXml("not-present", "1.0") + "</dependencies>"));
        Path target = temp.resolve("target.jar");
        writeJar(target);
        Path output = temp.resolve("missing-artifact-output");

        int code = new CommandLine(new JustMain()).execute(
                "scan", "--jar", target.toString(), "--pom", root.toString(),
                "--repository", repository.toUri().toString(), "--offline", "--fast",
                "--cache", temp.resolve("maven-cache").toString(),
                "--output", output.toString());

        assertEquals(0, code);
        String json = Files.readString(output.resolve("report.json"));
        assertTrue(json.contains("\"coverage\":\"BOUNDED\""), json);
        assertTrue(json.contains("DEPENDENCY_INPUT_INCOMPLETE"), json);
    }

    private static String pom(String group, String artifact, String version, String dependencies) {
        return """
                <project xmlns="http://maven.apache.org/POM/4.0.0">
                  <modelVersion>4.0.0</modelVersion>
                  <groupId>%s</groupId><artifactId>%s</artifactId><version>%s</version>
                  %s
                </project>
                """.formatted(group, artifact, version, dependencies);
    }

    private static String dependencyXml(String artifact, String version) {
        return "<dependency><groupId>fixture</groupId><artifactId>"
                + artifact + "</artifactId><version>" + version + "</version></dependency>";
    }

    private static void write(Path directory, String name, String content) throws IOException {
        Path file = directory.resolve(name);
        Files.createDirectories(file.getParent());
        Files.writeString(file, content);
    }

    private static void writeJar(Path file) throws IOException {
        Files.createDirectories(file.getParent());
        try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(file))) {
            output.putNextEntry(new JarEntry("META-INF/fixture.marker"));
            output.write(new byte[]{1, 2, 3});
            output.closeEntry();
        }
    }

    private static void writeClassJar(Path file, String entryName, byte[] bytes) throws IOException {
        Files.createDirectories(file.getParent());
        try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(file))) {
            put(output, entryName, bytes);
        }
    }

    private static byte[] simpleClassBytes(String internalName) {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, internalName, null,
                "java/lang/Object", null);
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "run", "()V", null, null);
        method.visitCode();
        method.visitInsn(Opcodes.RETURN);
        method.visitMaxs(0, 0);
        method.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] missingReferenceBytes() {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "fixture/MissingReference", null,
                "java/lang/Object", null);
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "run", "()V", null, null);
        method.visitCode();
        method.visitInsn(Opcodes.ACONST_NULL);
        method.visitTypeInsn(Opcodes.CHECKCAST, "missing/NotProvided");
        method.visitInsn(Opcodes.POP);
        method.visitInsn(Opcodes.RETURN);
        method.visitMaxs(1, 0);
        method.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static void writeFatJar(Path file) throws IOException {
        byte[] root = classBytes("/io/just/sast/cli/VerificationCliContractTest.class");
        byte[] nested = classBytes("/io/just/sast/frontend/asm/NoPomNestedInputContractTest.class");
        byte[] nestedJar = jarBytes(
                "io/just/sast/frontend/asm/NoPomNestedInputContractTest.class", nested);
        Files.createDirectories(file.getParent());
        try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(file))) {
            put(output, "BOOT-INF/classes/io/just/sast/cli/VerificationCliContractTest.class", root);
            put(output, "BOOT-INF/lib/closure.jar", nestedJar);
        }
    }

    private static byte[] classBytes(String resource) throws IOException {
        try (var input = VerificationCliContractTest.class.getResourceAsStream(resource)) {
            if (input == null) {
                throw new IOException("class resource is missing: " + resource);
            }
            return input.readAllBytes();
        }
    }

    private static byte[] jarBytes(String name, byte[] bytes) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        try (JarOutputStream output = new JarOutputStream(buffer)) {
            put(output, name, bytes);
        }
        return buffer.toByteArray();
    }

    private static void put(JarOutputStream output, String name, byte[] bytes) throws IOException {
        output.putNextEntry(new JarEntry(name));
        output.write(bytes);
        output.closeEntry();
    }
}
