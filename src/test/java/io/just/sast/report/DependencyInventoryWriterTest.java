package io.just.sast.report;

import io.just.sast.util.ArtifactFingerprint;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

import static org.junit.jupiter.api.Assertions.assertFalse;
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
                null, 61, false, false, 0, false, false);
        String identity = Files.readString(layout.meta().resolve("scan-identity.json"));
        assertTrue(key.matches("[0-9a-f]{64}"));
        assertTrue(identity.contains("\"cache_key\":\"" + key + "\""));
        assertFalse(identity.contains(target.toAbsolutePath().toString()));
    }
}
