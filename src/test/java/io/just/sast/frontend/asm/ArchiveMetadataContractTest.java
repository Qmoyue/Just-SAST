package io.just.sast.frontend.asm;

import io.just.sast.model.ArchiveMetadata;
import io.just.sast.model.DependencyGraph;
import io.just.sast.run.InputBudget;
import io.just.sast.report.DependencyInventoryWriter;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Contract for bounded manifest/index/pom metadata capture and exact coordinate consumption. */
class ArchiveMetadataContractTest {

    @Test
    void capturesTopLevelAndNestedMetadataWithoutGuessingCoordinates(@TempDir Path temp)
            throws Exception {
        Map<String, byte[]> nested = new LinkedHashMap<>();
        nested.put("META-INF/MANIFEST.MF", bytes("Manifest-Version: 1.0\r\n\r\n"));
        nested.put("META-INF/maven/org.example/dep/pom.properties",
                bytes("groupId=org.example\nartifactId=dep\nversion=1.2.3\n"));

        Map<String, byte[]> outer = new LinkedHashMap<>();
        outer.put("META-INF/MANIFEST.MF", bytes("Manifest-Version: 1.0\r\n"
                + "Main-Class: sample.Main\r\n"
                + "Class-Path: lib/dep.jar lib/other.jar\r\n\r\n"));
        outer.put("BOOT-INF/classpath.idx", bytes("- \"BOOT-INF/lib/dep.jar\"\n"
                + "- \"BOOT-INF/lib/other.jar\"\n"));
        outer.put("BOOT-INF/layers.idx", bytes("- \"dependencies\":\n"
                + "  - \"BOOT-INF/lib/dep.jar\"\n"
                + "- \"application\":\n"
                + "  - \"BOOT-INF/classes/\"\n"));
        outer.put("META-INF/maven/com.example/app/pom.properties",
                bytes("groupId=com.example\nartifactId=app\nversion=9.8.7\n"));
        outer.put("META-INF/maven/wrong/path/pom.properties",
                bytes("groupId=not.the.path\nartifactId=path\nversion=0.0.1\n"));
        outer.put("BOOT-INF/lib/dep.jar", zip(nested));
        outer.put("BOOT-INF/lib/no-pom-7.6.5.jar", zip(Map.of()));

        Path archive = temp.resolve("metadata.jar");
        Files.write(archive, zip(outer));

        JarReader.ReadResult result = new JarReader().readDetailed(archive, 17,
                InputBudget.defaults(), InputBudget.defaults().tracker());

        ArchiveMetadata top = result.archiveMetadata().get("metadata.jar");
        assertEquals("sample.Main", top.manifestAttributes().get("Main-Class"));
        assertEquals(List.of("BOOT-INF/lib/dep.jar", "BOOT-INF/lib/other.jar"),
                top.classpathEntries());
        assertEquals(List.of(
                new ArchiveMetadata.LayerEntry("dependencies", "BOOT-INF/lib/dep.jar"),
                new ArchiveMetadata.LayerEntry("application", "BOOT-INF/classes/")),
                top.layerEntries());
        assertEquals(List.of("com.example:app:9.8.7"),
                top.pomProperties().stream().map(ArchiveMetadata.PomProperties::coordinate).toList());
        assertTrue(top.completenessReasons().contains("POM_PROPERTIES_INVALID"),
                top.completenessReasons().toString());

        ArchiveMetadata nestedMetadata = result.archiveMetadata()
                .get("metadata.jar!BOOT-INF/lib/dep.jar");
        assertEquals(List.of("org.example:dep:1.2.3"), nestedMetadata.pomProperties().stream()
                .map(ArchiveMetadata.PomProperties::coordinate).toList());

        InputBudget scopedBudget = InputBudget.defaults();
        BytecodeFrontend.ScopedLoad scoped = new BytecodeFrontend()
                .loadStreamingWithApplicationScope(List.of(archive), 17, scopedBudget.tracker());
        assertEquals(top, scoped.archiveMetadata().get("metadata.jar"));
        assertEquals(nestedMetadata,
                scoped.archiveMetadata().get("metadata.jar!BOOT-INF/lib/dep.jar"));

        InputBudget budget = InputBudget.defaults();
        DependencyGraph graph = new DependencyInventoryWriter().build(archive, List.of(),
                "archive-hash", 17, List.of(), null, result.archiveMetadata(), budget,
                budget.tracker());
        assertTrue(graph.nodes().values().stream().anyMatch(node ->
                node.source() == DependencyGraph.Source.ACTUAL_APPLICATION
                        && node.group().equals("com.example")
                        && node.name().equals("app")
                        && node.version().equals("9.8.7")));
        assertTrue(graph.nodes().values().stream().anyMatch(node ->
                node.source() == DependencyGraph.Source.ACTUAL_EMBEDDED
                        && node.group().equals("org.example")
                        && node.name().equals("dep")
                        && node.version().equals("1.2.3")));
        assertTrue(graph.nodes().values().stream().anyMatch(node ->
                node.source() == DependencyGraph.Source.ACTUAL_EMBEDDED
                        && node.group().isEmpty()
                        && node.name().equals("no-pom-7.6.5")
                        && node.version().equals("unknown")));
    }

    @Test
    void malformedIndexesRemainVisibleAsMetadataReasons() {
        ArchiveMetadata metadata = ArchiveMetadataParser.parse("invalid.jar", Map.of(
                "classpath.idx", bytes("not-a-list entry\n"),
                "layers.idx", bytes("- \"layer\":\n  not-a-list-entry\n")));

        assertTrue(metadata.classpathEntries().isEmpty());
        assertTrue(metadata.layerEntries().isEmpty());
        assertTrue(metadata.completenessReasons().contains("CLASSPATH_INDEX_INVALID"));
        assertTrue(metadata.completenessReasons().contains("LAYERS_INDEX_INVALID"));
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
