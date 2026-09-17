package io.just.sast.frontend.asm;

import io.just.sast.run.InputBudget;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Contract for in-place root and nested fat-archive loading without a POM or extraction tree. */
class NoPomNestedInputContractTest {

    @Test
    void rootBootWebAndGenericLibJarsAreLoadedAndScopedWithoutExtraction(@TempDir Path temp)
            throws Exception {
        String rootName = "io/just/sast/frontend/asm/NoPomNestedInputContractTest";
        String bootName = "io/just/sast/frontend/asm/BytecodeFrontendTest";
        String webName = "io/just/sast/frontend/asm/JarReaderTest";
        String libName = "io/just/sast/analysis/entry/ApplicationEntryIndexContractTest";

        byte[] rootBytes = classBytes("/" + rootName + ".class");
        byte[] bootBytes = classBytes("/" + bootName + ".class");
        byte[] webBytes = classBytes("/" + webName + ".class");
        byte[] libBytes = classBytes("/" + libName + ".class");

        Map<String, byte[]> bootEntries = Map.of(bootName + ".class", bootBytes);
        Map<String, byte[]> webEntries = Map.of(webName + ".class", webBytes);
        Map<String, byte[]> libEntries = Map.of(libName + ".class", libBytes);
        Map<String, byte[]> outerEntries = new LinkedHashMap<>();
        outerEntries.put("BOOT-INF/classes/" + rootName + ".class", rootBytes);
        outerEntries.put("BOOT-INF/lib/boot.jar", zip(bootEntries));
        outerEntries.put("WEB-INF/lib/web.jar", zip(webEntries));
        outerEntries.put("lib/plain.jar", zip(libEntries));

        Path fat = temp.resolve("self-contained-fat.jar");
        Files.write(fat, zip(outerEntries));

        BytecodeFrontend.ScopedLoad scoped = new BytecodeFrontend(InputBudget.defaults())
                .loadStreamingWithApplicationScope(List.of(fat), 17,
                        InputBudget.defaults().tracker());

        assertEquals(4, scoped.load().classCount(), scoped.load().diagnostics().toString());
        assertEquals(Set.of(rootName), scoped.applicationClassNames());
        assertEquals(List.of("nested:BOOT-INF/lib/boot.jar"), scoped.artifactDetails().get(bootName));
        assertEquals(List.of("nested:WEB-INF/lib/web.jar"), scoped.artifactDetails().get(webName));
        assertEquals(List.of("nested:lib/plain.jar"), scoped.artifactDetails().get(libName));
        try (var files = Files.list(temp)) {
            assertEquals(List.of(fat), files.toList(),
                    "nested jars must be consumed in-place, without an extraction tree");
        }
        assertTrue(scoped.unparseableArtifactIndexes().isEmpty());
    }

    private static byte[] classBytes(String resource) throws Exception {
        try (InputStream input = NoPomNestedInputContractTest.class.getResourceAsStream(resource)) {
            if (input == null) {
                throw new IllegalStateException("test class resource is missing: " + resource);
            }
            return input.readAllBytes();
        }
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
