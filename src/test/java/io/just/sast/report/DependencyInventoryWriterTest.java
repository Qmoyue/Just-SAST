package io.just.sast.report;

import io.just.sast.util.ArtifactFingerprint;
import io.just.sast.run.InputBudget;
import io.just.sast.model.DependencyGraph;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.io.ByteArrayOutputStream;
import java.util.Map;
import java.util.Set;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DependencyInventoryWriterTest {

    @Test
    void writesDeterministicInventoryAndCycloneDxWithoutLocalPaths(@TempDir Path tmp)
            throws Exception {
        Path target = tmp.resolve("sample-app.jar");
        try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(target))) {
            output.putNextEntry(new JarEntry("META-INF/maven/example/sample/pom.properties"));
            output.write("groupId=example\nartifactId=sample\nversion=1.2.3\n"
                    .getBytes(java.nio.charset.StandardCharsets.UTF_8));
            output.closeEntry();
        }
        ReportLayout layout = ReportLayout.create(tmp.resolve("out"));
        String hash = ArtifactFingerprint.sha256(target);

        new DependencyInventoryWriter().write(layout, target, List.of(), hash, 17);

        String csv = Files.readString(layout.evidence().resolve("dependencies.csv"));
        String bom = Files.readString(layout.meta().resolve("dependencies.sbom.json"));
        assertTrue(csv.contains("application"));
        assertTrue(csv.contains("example"));
        assertTrue(bom.contains("\"bomFormat\":\"CycloneDX\""));
        assertTrue(bom.contains(hash));
        assertFalse(bom.contains(target.toAbsolutePath().toString()));

        String key = new ScanIdentityWriter().write(layout, hash, "dependency-inventory", null,
                null, 61, false, "component");
        String identity = Files.readString(layout.meta().resolve("scan-identity.json"));
        assertTrue(key.matches("[0-9a-f]{64}"));
        assertTrue(identity.contains("\"cache_key\":\"" + key + "\""));
        assertFalse(identity.contains(target.toAbsolutePath().toString()));
    }

    @Test
    void callerTrackerCoversNestedLibrariesAcrossTargetAndDependency(@TempDir Path tmp)
            throws Exception {
        Path target = nestedLibraryArchive(tmp.resolve("target.jar"), "target-lib.jar");
        Path dependency = nestedLibraryArchive(tmp.resolve("dependency.jar"), "dependency-lib.jar");
        Path out = tmp.resolve("out");
        ReportLayout layout = ReportLayout.create(out);
        InputBudget defaults = InputBudget.defaults();
        InputBudget budget = defaults.withArchiveLimits(
                defaults.maxPhysicalBytes(), defaults.maxCompressedBytes(),
                defaults.maxUncompressedBytes(), defaults.maxEntryBytes(),
                1, defaults.maxArchiveNesting(), defaults.maxClassEntries());
        InputBudget.Tracker tracker = budget.tracker();

        new DependencyInventoryWriter().write(layout, target, List.of(dependency),
                "target-hash", 17, List.of("dependency-hash"), budget, tracker);

        String csv = Files.readString(layout.evidence().resolve("dependencies.csv"));
        assertTrue(csv.contains("UNAVAILABLE:IOException"),
                "second nested archive must observe the caller's exhausted entry budget");
    }

    @Test
    void duplicateNestedEntryKeepsStableReasonInInventory(@TempDir Path tmp) throws Exception {
        Path target = tmp.resolve("duplicate.jar");
        Files.write(target, duplicateNameArchive());
        ReportLayout layout = ReportLayout.create(tmp.resolve("out"));

        new DependencyInventoryWriter().write(layout, target, List.of(), "target-hash", 17);

        String csv = Files.readString(layout.evidence().resolve("dependencies.csv"));
        String bom = Files.readString(layout.meta().resolve("dependencies.sbom.json"));
        assertTrue(csv.contains("ARCHIVE_DUPLICATE_ENTRY"),
                "duplicate archive names must remain an auditable stable inventory reason");
        assertTrue(csv.contains("error_detail"),
                "inventory CSV must expose structured duplicate detail instead of only a code");
        assertTrue(csv.contains("name=BOOT-INF/lib/a.jar"));
        assertTrue(csv.contains("firstOrdinal=1"));
        assertTrue(csv.contains("duplicateOrdinal=2"));
        assertTrue(bom.contains("just:error-detail"));
        assertTrue(bom.contains("duplicateOrdinal=2"));
    }

    @Test
    void buildsOneActualGraphForExplicitAndEmbeddedArtifacts(@TempDir Path tmp) throws Exception {
        Path target = nestedLibraryArchive(tmp.resolve("app.jar"), "embedded-1.0.jar");
        Path dependency = tmp.resolve("explicit-2.0.jar");
        Files.write(dependency, new byte[] {9, 8, 7});
        String targetHash = ArtifactFingerprint.sha256(target);
        String dependencyHash = ArtifactFingerprint.sha256(dependency);
        InputBudget budget = InputBudget.defaults();
        DependencyGraph graph = new DependencyInventoryWriter().build(target,
                List.of(dependency), targetHash, 17, List.of(dependencyHash), budget,
                budget.tracker());

        assertTrue(graph.nodes().values().stream().anyMatch(node ->
                node.source() == DependencyGraph.Source.ACTUAL_APPLICATION));
        assertTrue(graph.nodes().values().stream().anyMatch(node ->
                node.source() == DependencyGraph.Source.ACTUAL_EMBEDDED));
        assertTrue(graph.nodes().values().stream().anyMatch(node ->
                node.source() == DependencyGraph.Source.ACTUAL_EXPLICIT));
        assertTrue(graph.nodes().values().stream().anyMatch(node ->
                node.source() == DependencyGraph.Source.JDK));
        assertTrue(graph.edges().stream().anyMatch(edge -> "embedded".equals(edge.kind())));
        assertTrue(graph.nodes().values().stream().noneMatch(node ->
                node.sourceDetail().contains(tmp.toAbsolutePath().toString())));
        assertTrue(graph.semanticDigest().matches("[0-9a-f]{64}"));

        ReportLayout layout = ReportLayout.create(tmp.resolve("graph-report"));
        new DependencyInventoryWriter().write(layout, graph, targetHash);
        String csv = Files.readString(layout.evidence().resolve("dependencies.csv"));
        assertTrue(csv.contains("application"));
        assertTrue(csv.contains("nested"));
        assertTrue(csv.contains("direct"));
    }

    @Test
    void keepsSameBytesInSeparateActualInputNodesForClassConflictEvidence(@TempDir Path tmp)
            throws Exception {
        Path target = tmp.resolve("same.jar");
        Path dependency = tmp.resolve("same-copy.jar");
        Files.write(target, new byte[] {4, 5, 6});
        Files.copy(target, dependency);
        String hash = ArtifactFingerprint.sha256(target);

        DependencyGraph graph = new DependencyInventoryWriter().build(target, List.of(dependency),
                hash, 17, List.of(hash), InputBudget.defaults(), InputBudget.defaults().tracker());

        List<DependencyGraph.Node> actual = graph.nodes().values().stream()
                .filter(node -> node.source() == DependencyGraph.Source.ACTUAL_APPLICATION
                        || node.source() == DependencyGraph.Source.ACTUAL_EXPLICIT)
                .toList();
        assertEquals(2, actual.size());
        assertEquals(Set.of(0, 1), actual.stream()
                .map(DependencyGraph.Node::inputIndex).collect(java.util.stream.Collectors.toSet()));
        assertEquals(2, actual.stream().map(DependencyGraph.Node::ref).distinct().count());

        DependencyGraph bound = graph.bindClassOwners(Map.of("app/Entry", 0),
                Map.of("app/Entry", List.of(1)), Set.of("app/Entry"));
        assertEquals(DependencyGraph.Resolution.CONFLICT,
                bound.classOwner("app/Entry").orElseThrow().resolution());
        assertTrue(bound.applicationOwned("app/Entry"));
    }

    @Test
    void classDirectoryAndEnvironmentColumnsRemainVisible(@TempDir Path tmp) throws Exception {
        Path classes = tmp.resolve("classes");
        Path marker = classes.resolve("pkg/Marker.class");
        Files.createDirectories(marker.getParent());
        Files.write(marker, new byte[]{1, 2, 3});

        DependencyGraph graph = new DependencyInventoryWriter().build(classes, List.of(),
                "directory-hash", 17, List.of(), InputBudget.defaults(),
                InputBudget.defaults().tracker());
        assertTrue(graph.environmentConditions().contains("CLASS_DIRECTORY_INPUT:0"));

        ReportLayout layout = ReportLayout.create(tmp.resolve("directory-report"));
        new DependencyInventoryWriter().write(layout, graph, "directory-hash");
        String csv = Files.readString(layout.evidence().resolve("dependencies.csv"));
        String bom = Files.readString(layout.meta().resolve("dependencies.sbom.json"));
        assertTrue(csv.contains("deployment"));
        assertTrue(csv.contains("resolution_reason"));
        assertTrue(bom.contains("just:environment-condition"));
        assertTrue(bom.contains("CLASS_DIRECTORY_INPUT:0"));
        assertFalse(csv.contains(classes.toAbsolutePath().toString()));
    }

    /** Create two distinct equal-length entries, then rewrite the second name in local and
     * central headers to the first name.  ZipOutputStream itself rejects duplicate names. */
    private static byte[] duplicateNameArchive() throws Exception {
        String first = "BOOT-INF/lib/a.jar";
        String second = "BOOT-INF/lib/b.jar";
        ByteArrayOutputStream encoded = new ByteArrayOutputStream();
        try (JarOutputStream output = new JarOutputStream(encoded)) {
            output.putNextEntry(new JarEntry(first));
            output.write(new byte[] {1, 2, 3});
            output.closeEntry();
            output.putNextEntry(new JarEntry(second));
            output.write(new byte[] {4, 5, 6});
            output.closeEntry();
        }
        byte[] archive = encoded.toByteArray();
        List<Integer> locals = signatures(archive, 0x03, 0x04);
        List<Integer> centrals = signatures(archive, 0x01, 0x02);
        if (locals.size() != 2 || centrals.size() != 2) {
            throw new AssertionError("duplicate fixture must contain two local/central entries");
        }
        byte[] firstName = first.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] secondName = second.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        if (firstName.length != secondName.length) {
            throw new AssertionError("duplicate fixture names must have equal length");
        }
        System.arraycopy(firstName, 0, archive, locals.get(1) + 30, firstName.length);
        System.arraycopy(firstName, 0, archive, centrals.get(1) + 46, firstName.length);
        return archive;
    }

    private static List<Integer> signatures(byte[] bytes, int third, int fourth) {
        java.util.ArrayList<Integer> result = new java.util.ArrayList<>();
        for (int i = 0; i <= bytes.length - 4; i++) {
            if ((bytes[i] & 0xff) == 0x50 && (bytes[i + 1] & 0xff) == 0x4b
                    && (bytes[i + 2] & 0xff) == third && (bytes[i + 3] & 0xff) == fourth) {
                result.add(i);
            }
        }
        return result;
    }

    private static Path nestedLibraryArchive(Path archive, String nestedName) throws Exception {
        try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(archive))) {
            output.putNextEntry(new JarEntry("BOOT-INF/lib/" + nestedName));
            output.write(new byte[]{1, 2, 3});
            output.closeEntry();
        }
        return archive;
    }
}
