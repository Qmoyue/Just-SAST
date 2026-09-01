package io.just.sast.frontend.asm;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.function.Function;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 输入解析契约：Spring Boot 前缀剥离、嵌套 jar 递归（jar-in-jar-in-lib）。 */
class JarReaderTest {

    private static byte[] zip(Map<String, Function<String, byte[]>> entries) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(out)) {
            for (var e : entries.entrySet()) {
                zip.putNextEntry(new ZipEntry(e.getKey()));
                zip.write(e.getValue().apply(e.getKey()));
                zip.closeEntry();
            }
        }
        return out.toByteArray();
    }

    private static byte[] markerClass(String name) {
        return ("fake-class:" + name).getBytes();
    }

    @Test
    void bootInfPrefixStripped(@TempDir Path tmp) throws Exception {
        Path jar = tmp.resolve("boot.jar");
        Files.write(jar, zip(Map.of(
                "BOOT-INF/classes/com/app/Main.class", JarReaderTest::markerClass)));
        List<ClassBytes> classes = new JarReader().read(jar);
        assertEquals(1, classes.size());
        assertEquals("com/app/Main", classes.get(0).className(), "BOOT-INF/classes 前缀应剥离");
    }

    @Test
    void nestedJarRecursesBeyondOneLevel(@TempDir Path tmp) throws Exception {
        // 最深层的 jar 里有 class：lib 内嵌套 jar → 内嵌套 jar 再内 class（深度 2 的 jar-in-jar-in-lib）
        byte[] innermost = zip(Map.of("deep/Secret.class", JarReaderTest::markerClass));
        byte[] middle = zip(Map.of(
                "BOOT-INF/lib/middle.jar", k -> innermost,
                "BOOT-INF/classes/com/app/App.class", JarReaderTest::markerClass));
        Path jar = tmp.resolve("fat.jar");
        Files.write(jar, middle);
        List<ClassBytes> classes = new JarReader().read(jar);
        List<String> names = classes.stream().map(ClassBytes::className).toList();
        assertTrue(names.contains("com/app/App"), "顶层 class 在: " + names);
        assertTrue(names.contains("deep/Secret"), "二层嵌套 jar 的 class 也应被解析: " + names);
    }

    @Test
    void streamingKeepsOrderAndReportsTheSameEntries(@TempDir Path tmp) throws Exception {
        byte[] nested = zip(Map.of("lib/Dependency.class", JarReaderTest::markerClass));
        Path jar = tmp.resolve("stream.jar");
        Map<String, Function<String, byte[]>> root = new LinkedHashMap<>();
        root.put("BOOT-INF/classes/com/app/Main.class", JarReaderTest::markerClass);
        root.put("BOOT-INF/lib/dependency.jar", ignored -> nested);
        Files.write(jar, zip(root));

        List<String> names = new ArrayList<>();
        JarReader.StreamResult result = new JarReader().streamDetailed(jar,
                bytes -> names.add(bytes.className()));
        List<String> compatibilityNames = new JarReader().read(jar).stream()
                .map(ClassBytes::className).toList();

        assertEquals(2, result.classesEmitted());
        assertEquals(compatibilityNames, names);
        assertTrue(result.completenessReasons().isEmpty());
    }

    @Test
    void duplicateClassesAcrossNestedArchivesAreReported(@TempDir Path tmp) throws Exception {
        byte[] nested = zip(Map.of("com/app/Main.class", JarReaderTest::markerClass));
        Path jar = tmp.resolve("duplicate.jar");
        Map<String, Function<String, byte[]>> root = new LinkedHashMap<>();
        root.put("BOOT-INF/classes/com/app/Main.class", JarReaderTest::markerClass);
        root.put("BOOT-INF/lib/dependency.jar", ignored -> nested);
        Files.write(jar, zip(root));

        JarReader.ReadResult result = new JarReader().readDetailed(jar);

        assertEquals(1, result.classes().size());
        assertTrue(result.completenessReasons().stream()
                .anyMatch(reason -> reason.equals("DUPLICATE_CLASS:com/app/Main")),
                result.completenessReasons().toString());
    }

    @Test
    void multiReleaseJarSelectsHighestCompatibleVariant(@TempDir Path tmp) throws Exception {
        Path jar = tmp.resolve("multi-release.jar");
        Map<String, Function<String, byte[]>> root = new LinkedHashMap<>();
        root.put("META-INF/MANIFEST.MF", ignored -> (
                "Manifest-Version: 1.0\r\nMulti-Release: true\r\n\r\n")
                .getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        root.put("com/app/Main.class", ignored -> markerClass("base"));
        root.put("META-INF/versions/9/com/app/Main.class", ignored -> markerClass("9"));
        root.put("META-INF/versions/17/com/app/Main.class", ignored -> markerClass("17"));
        Files.write(jar, zip(root));

        JarReader reader = new JarReader();
        JarReader.ReadResult java8 = reader.readDetailed(jar, 8);
        JarReader.ReadResult java11 = reader.readDetailed(jar, 11);
        JarReader.ReadResult java17 = reader.readDetailed(jar, 17);

        assertEquals("base", new String(java8.classes().get(0).bytes(),
                java.nio.charset.StandardCharsets.US_ASCII).substring("fake-class:".length()));
        assertEquals("9", new String(java11.classes().get(0).bytes(),
                java.nio.charset.StandardCharsets.US_ASCII).substring("fake-class:".length()));
        assertEquals("17", new String(java17.classes().get(0).bytes(),
                java.nio.charset.StandardCharsets.US_ASCII).substring("fake-class:".length()));
        assertEquals("com/app/Main", java17.classes().get(0).className());
        assertTrue(java17.completenessReasons().isEmpty(),
                "选择兼容版本不是完整性失败: " + java17.completenessReasons());
    }

    @Test
    void nestedMultiReleaseJarIsExplicitlyMarkedWhenStreamingKeepsBaseView(@TempDir Path tmp)
            throws Exception {
        Map<String, Function<String, byte[]>> nestedEntries = new LinkedHashMap<>();
        nestedEntries.put("META-INF/MANIFEST.MF", ignored -> (
                "Manifest-Version: 1.0\r\nMulti-Release: true\r\n\r\n")
                .getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        nestedEntries.put("com/app/Main.class", ignored -> markerClass("base"));
        nestedEntries.put("META-INF/versions/17/com/app/Main.class",
                ignored -> markerClass("17"));
        byte[] nested = zip(nestedEntries);
        Path jar = tmp.resolve("nested-multi-release.jar");
        Files.write(jar, zip(Map.of("BOOT-INF/lib/dependency.jar", ignored -> nested)));

        JarReader.ReadResult result = new JarReader().readDetailed(jar, 17);

        assertEquals(1, result.classes().size());
        assertEquals("base", new String(result.classes().get(0).bytes(),
                java.nio.charset.StandardCharsets.US_ASCII).substring("fake-class:".length()));
        assertTrue(result.completenessReasons().contains("MULTI_RELEASE_NESTED_UNSELECTED"),
                "nested MR stream cannot silently claim that the target feature was selected: "
                        + result.completenessReasons());
    }

    @Test
    void compressionRatioLimitIsObservable(@TempDir Path tmp) throws Exception {
        byte[] zeros = new byte[4 * 1024 * 1024];
        Path jar = tmp.resolve("ratio.jar");
        Map<String, Function<String, byte[]>> root = new LinkedHashMap<>();
        root.put("BOOT-INF/classes/com/app/HighlyCompressed.class", ignored -> zeros);
        Files.write(jar, zip(root));

        JarReader.ReadResult result = new JarReader().readDetailed(jar);

        assertTrue(result.classes().isEmpty());
        assertTrue(result.completenessReasons().contains("ARCHIVE_COMPRESSION_RATIO_CAP"),
                result.completenessReasons().toString());
    }

    @Test
    void malformedTopLevelZipIsAnAuditableCompletenessReason(@TempDir Path tmp) throws Exception {
        Path jar = tmp.resolve("malformed.jar");
        Files.write(jar, "not a zip".getBytes(java.nio.charset.StandardCharsets.US_ASCII));

        JarReader.ReadResult result = new JarReader().readDetailed(jar);

        assertTrue(result.classes().isEmpty());
        assertEquals(List.of("ARCHIVE_CORRUPT"), result.completenessReasons());
    }

    @Test
    void malformedNestedZipDoesNotHideValidOuterClasses(@TempDir Path tmp) throws Exception {
        Path jar = tmp.resolve("malformed-nested.jar");
        Map<String, Function<String, byte[]>> root = new LinkedHashMap<>();
        root.put("BOOT-INF/classes/com/app/Main.class", JarReaderTest::markerClass);
        root.put("BOOT-INF/lib/broken.jar", ignored ->
                "not a nested zip".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        Files.write(jar, zip(root));

        JarReader.ReadResult result = new JarReader().readDetailed(jar);

        assertEquals(1, result.classes().size());
        assertEquals("com/app/Main", result.classes().get(0).className());
        assertTrue(result.completenessReasons().contains("ARCHIVE_CORRUPT"),
                result.completenessReasons().toString());
    }

    @Test
    void consumerFailureClosesTopLevelAndNestedZipResources(@TempDir Path tmp) throws Exception {
        byte[] nested = zip(Map.of("lib/Dependency.class", JarReaderTest::markerClass));
        Path jar = tmp.resolve("consumer-failure.jar");
        Map<String, Function<String, byte[]>> root = new LinkedHashMap<>();
        root.put("app/Main.class", JarReaderTest::markerClass);
        root.put("BOOT-INF/lib/dependency.jar", ignored -> nested);
        Files.write(jar, zip(root));

        java.util.concurrent.atomic.AtomicInteger seen = new java.util.concurrent.atomic.AtomicInteger();
        java.io.IOException failure = org.junit.jupiter.api.Assertions.assertThrows(
                java.io.IOException.class,
                () -> new JarReader().streamDetailed(jar, bytes -> {
                    if (seen.incrementAndGet() >= 2) {
                        throw new java.io.IOException("consumer-stop");
                    }
                }));

        assertEquals("consumer-stop", failure.getMessage());
        Path moved = tmp.resolve("consumer-failure-moved.jar");
        Files.move(jar, moved);
        assertTrue(Files.isRegularFile(moved), "consumer 中断后 ZipFile/ZipInputStream 必须关闭");
    }
}
