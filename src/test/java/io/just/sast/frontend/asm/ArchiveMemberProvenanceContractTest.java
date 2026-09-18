package io.just.sast.frontend.asm;

import io.just.sast.model.ArchiveMemberProvenance;
import io.just.sast.model.ArtifactProvenance;
import io.just.sast.model.LoadResult;
import io.just.sast.model.ProgramUniverse;
import io.just.sast.run.InputBudget;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Contract for member-level source/path/hash/role facts across the frontend boundary. */
class ArchiveMemberProvenanceContractTest {

    @Test
    void recordsRootNestedAndExplicitMemberFactsWithoutLeakingFilesystemPaths(
            @TempDir Path temp) throws Exception {
        byte[] applicationClass = fixtureBytes(
                "/io/just/sast/frontend/asm/BytecodeFrontendTest.class");
        byte[] dependencyClass = fixtureBytes(
                "/io/just/sast/analysis/entry/ApplicationEntryIndexContractTest.class");
        byte[] nestedBytes = zip(Map.of(
                "META-INF/maven/org.example/dep/pom.properties",
                bytes("groupId=org.example\nartifactId=dep\nversion=1.2.3\n"),
                "io/just/sast/analysis/entry/ApplicationEntryIndexContractTest.class",
                dependencyClass));

        Map<String, byte[]> outerEntries = new LinkedHashMap<>();
        outerEntries.put("META-INF/maven/com.example/app/pom.properties",
                bytes("groupId=com.example\nartifactId=app\nversion=9.8.7\n"));
        outerEntries.put("BOOT-INF/classes/io/just/sast/frontend/asm/BytecodeFrontendTest.class",
                applicationClass);
        outerEntries.put("BOOT-INF/lib/dep.jar", nestedBytes);
        byte[] outerBytes = zip(outerEntries);
        Path archive = temp.resolve("provenance.jar");
        Files.write(archive, outerBytes);

        JarReader.ReadResult read = new JarReader().readDetailed(archive, 17,
                InputBudget.defaults(), InputBudget.defaults().tracker());
        ArchiveMemberProvenance rootClass = read.classes().stream()
                .filter(value -> value.className().equals(
                        "io/just/sast/frontend/asm/BytecodeFrontendTest"))
                .findFirst().orElseThrow().provenance();
        assertEquals("provenance.jar", rootClass.source());
        assertEquals("BOOT-INF/classes/io/just/sast/frontend/asm/BytecodeFrontendTest.class",
                rootClass.archivePath());
        assertEquals(ArchiveMemberProvenance.Role.ROOT, rootClass.role());
        assertEquals(ArchiveMemberProvenance.Kind.CLASS, rootClass.kind());
        assertEquals(ArchiveMemberProvenance.sha256Of(applicationClass), rootClass.sha256());
        assertEquals("com.example:app:9.8.7", rootClass.coordinate());

        ArchiveMemberProvenance nestedJar = read.archiveMembers().stream()
                .filter(value -> value.kind() == ArchiveMemberProvenance.Kind.ARCHIVE
                        && value.archivePath().equals("BOOT-INF/lib/dep.jar"))
                .findFirst().orElseThrow();
        assertEquals("provenance.jar", nestedJar.source());
        assertEquals("provenance.jar!BOOT-INF/lib/dep.jar", nestedJar.logicalArtifact());
        assertEquals(ArchiveMemberProvenance.Role.NESTED_LIBRARY, nestedJar.role());
        assertEquals(ArchiveMemberProvenance.sha256Of(nestedBytes), nestedJar.sha256());
        assertEquals("org.example:dep:1.2.3", nestedJar.coordinate());

        ArchiveMemberProvenance nestedClass = read.classes().stream()
                .filter(value -> value.className().equals(
                        "io/just/sast/analysis/entry/ApplicationEntryIndexContractTest"))
                .findFirst().orElseThrow().provenance();
        assertEquals("provenance.jar!BOOT-INF/lib/dep.jar", nestedClass.source());
        assertEquals("io/just/sast/analysis/entry/ApplicationEntryIndexContractTest.class",
                nestedClass.archivePath());
        assertEquals(ArchiveMemberProvenance.Role.NESTED_LIBRARY, nestedClass.role());
        assertEquals("org.example:dep:1.2.3", nestedClass.coordinate());
        assertTrue(!nestedClass.source().contains(temp.toAbsolutePath().toString()),
                "member source must be a logical origin, not an absolute path");

        ArtifactProvenance application = new ArtifactProvenance("provenance.jar",
                ArtifactProvenance.Role.APPLICATION,
                ArchiveMemberProvenance.sha256Of(outerBytes), outerBytes.length);
        InputBudget budget = InputBudget.defaults();
        BytecodeFrontend.ScopedLoad scoped = new BytecodeFrontend(budget)
                .loadStreamingWithApplicationScope(List.of(archive), 17, budget.tracker(),
                        List.of(application));
        ArchiveMemberProvenance rootArchive = scoped.archiveMembers().stream()
                .filter(value -> value.kind() == ArchiveMemberProvenance.Kind.ARCHIVE
                        && value.archivePath().equals("<root>"))
                .findFirst().orElseThrow();
        assertEquals(ArchiveMemberProvenance.Role.ROOT, rootArchive.role());
        assertEquals(application.sha256(), rootArchive.sha256());
        assertEquals("com.example:app:9.8.7", rootArchive.coordinate());
        assertEquals(nestedClass, scoped.classProvenance().get(
                "io/just/sast/analysis/entry/ApplicationEntryIndexContractTest").get(0));

        ProgramUniverse universe = scoped.load().programUniverse();
        assertEquals(scoped.classProvenance(), universe.classProvenance());
        assertEquals(scoped.archiveMembers(), universe.archiveMembers());
        assertTrue(universe.semanticDigest().matches("[0-9a-f]{64}"));

        Path explicit = temp.resolve("explicit.jar");
        Files.write(explicit, zip(Map.of(
                "io/just/sast/analysis/entry/ApplicationEntryIndexContractTest.class",
                dependencyClass)));
        byte[] explicitBytes = Files.readAllBytes(explicit);
        ArtifactProvenance explicitProvenance = new ArtifactProvenance("explicit.jar",
                ArtifactProvenance.Role.DEPENDENCY,
                ArchiveMemberProvenance.sha256Of(explicitBytes), explicitBytes.length);
        BytecodeFrontend.ScopedLoad withExplicit = new BytecodeFrontend(budget)
                .loadStreamingWithApplicationScope(List.of(archive, explicit), 17,
                        budget.tracker(), List.of(application, explicitProvenance));
        assertTrue(withExplicit.archiveMembers().stream().anyMatch(value ->
                value.kind() == ArchiveMemberProvenance.Kind.ARCHIVE
                        && value.archivePath().equals("<root>")
                        && value.role() == ArchiveMemberProvenance.Role.EXPLICIT_DEPENDENCY));
        assertTrue(withExplicit.classProvenance().get(
                "io/just/sast/analysis/entry/ApplicationEntryIndexContractTest").stream()
                .anyMatch(value -> value.role() == ArchiveMemberProvenance.Role.NESTED_LIBRARY));
    }

    @Test
    void provenanceRejectsAbsoluteMemberPaths() {
        org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class, () ->
                new ArchiveMemberProvenance("app.jar", "C:/outside.class",
                        "A".repeat(64), ArchiveMemberProvenance.Role.ROOT, "",
                        "app.jar", ArchiveMemberProvenance.Kind.CLASS));
    }

    @Test
    void jdkClassBytesCarryJdkMemberProvenance() {
        InputBudget budget = InputBudget.defaults();
        ClassBytes bytes = JrtClassSource.runtime(budget, budget.tracker())
                .loadBytes("java/lang/String");

        assertNotNull(bytes);
        assertNotNull(bytes.provenance());
        assertEquals(ArchiveMemberProvenance.Role.JDK, bytes.provenance().role());
        assertEquals(ArchiveMemberProvenance.Kind.CLASS, bytes.provenance().kind());
        assertEquals("java/lang/String.class", bytes.provenance().archivePath());
        assertEquals(ArchiveMemberProvenance.sha256Of(bytes.bytes()),
                bytes.provenance().sha256());
        assertTrue(bytes.provenance().source().startsWith("jdk:"));
    }

    @Test
    void appendingDuplicateClassProvenanceCopiesFrozenBaseList() throws Exception {
        byte[] bytes = fixtureBytes(
                "/io/just/sast/frontend/asm/BytecodeFrontendTest.class");
        String className = "io/just/sast/frontend/asm/BytecodeFrontendTest";
        ArchiveMemberProvenance baseProvenance = ArchiveMemberProvenance.fromBytes(
                "base.jar", "base.jar", className + ".class", bytes,
                ArchiveMemberProvenance.Role.ROOT, ArchiveMemberProvenance.Kind.CLASS);
        ArchiveMemberProvenance extraProvenance = ArchiveMemberProvenance.fromBytes(
                "extra.jar", "extra.jar", className + ".class", bytes,
                ArchiveMemberProvenance.Role.EXPLICIT_DEPENDENCY,
                ArchiveMemberProvenance.Kind.CLASS);
        InputBudget budget = InputBudget.defaults();
        BytecodeFrontend frontend = new BytecodeFrontend(budget);
        InputBudget.Tracker tracker = budget.tracker();
        LoadResult base = frontend.load(new BytecodeFrontend.Inputs(
                List.of(new ClassBytes(className, bytes, "base", baseProvenance)),
                List.of(), List.of(), tracker, true));

        LoadResult merged = frontend.load(base,
                List.of(new ClassBytes(className, bytes, "extra", extraProvenance)), tracker);

        assertEquals(2, merged.classProvenance().get(className).size());
        assertEquals(baseProvenance, merged.classProvenance().get(className).get(0));
        assertEquals(extraProvenance, merged.classProvenance().get(className).get(1));
        assertTrue(merged.completenessReasons().contains("DUPLICATE_CLASS:" + className));
    }

    private static byte[] fixtureBytes(String resource) throws Exception {
        try (InputStream input = ArchiveMemberProvenanceContractTest.class
                .getResourceAsStream(resource)) {
            assertNotNull(input, "test class resource is missing: " + resource);
            return input.readAllBytes();
        }
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] zip(Map<String, byte[]> entries) throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(bytes)) {
            for (Map.Entry<String, byte[]> entry : entries.entrySet()) {
                zip.putNextEntry(new ZipEntry(entry.getKey()));
                zip.write(entry.getValue());
                zip.closeEntry();
            }
        }
        return bytes.toByteArray();
    }
}
