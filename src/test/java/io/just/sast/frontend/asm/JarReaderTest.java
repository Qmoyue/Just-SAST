package io.just.sast.frontend.asm;

import io.just.sast.run.InputBudget;
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
import java.util.zip.CRC32;
import java.util.Arrays;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
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
    void nestedJarTrailingAlignmentBytesDoNotMasqueradeAsArchiveCorruption(@TempDir Path tmp)
            throws Exception {
        byte[] nested = zip(Map.of("dep/Marker.class", JarReaderTest::markerClass));
        // Spring Boot nested-jar layouts may retain legal alignment/trailing bytes in the
        // outer entry. The reader must consume them for the outer CRC without treating the
        // valid inner central directory as a corrupt archive.
        byte[] nestedWithAlignment = Arrays.copyOf(nested, nested.length + 64);
        Path jar = tmp.resolve("nested-alignment.jar");
        ByteArrayOutputStream outerBytes = new ByteArrayOutputStream();
        CRC32 outerCrc = new CRC32();
        outerCrc.update(nestedWithAlignment);
        try (ZipOutputStream outer = new ZipOutputStream(outerBytes)) {
            ZipEntry aligned = new ZipEntry("BOOT-INF/lib/aligned.jar");
            aligned.setMethod(ZipEntry.STORED);
            aligned.setSize(nestedWithAlignment.length);
            aligned.setCompressedSize(nestedWithAlignment.length);
            aligned.setCrc(outerCrc.getValue());
            outer.putNextEntry(aligned);
            outer.write(nestedWithAlignment);
            outer.closeEntry();
        }
        Files.write(jar, outerBytes.toByteArray());

        JarReader.ReadResult result = new JarReader().readDetailed(jar);

        assertTrue(result.classes().stream().anyMatch(c -> c.className().equals("dep/Marker")),
                result.classes().stream().map(ClassBytes::className).toList().toString());
        assertTrue(result.completenessReasons().stream()
                        .noneMatch(reason -> reason.equals("ARCHIVE_CORRUPT")),
                result.completenessReasons().toString());
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
    void resourceCallbackExposesOnlyTopLevelXml(@TempDir Path tmp) throws Exception {
        byte[] nested = zip(Map.of("WEB-INF/dependency.xml",
                ignored -> "<dependency/>".getBytes()));
        Map<String, Function<String, byte[]>> root = new LinkedHashMap<>();
        root.put("WEB-INF/web.xml", ignored -> "<web-app/>".getBytes());
        root.put("BOOT-INF/lib/dependency.jar", ignored -> nested);
        Path jar = tmp.resolve("resources.jar");
        Files.write(jar, zip(root));

        List<String> resources = new ArrayList<>();
        JarReader.StreamResult result = new JarReader().streamDetailedWithResources(jar,
                ignored -> { },
                (path, bytes, origin) -> resources.add(path),
                17, InputBudget.defaults(), InputBudget.defaults().tracker());

        assertEquals(0, result.classesEmitted());
        assertEquals(List.of("WEB-INF/web.xml"), resources);
        assertTrue(result.completenessReasons().isEmpty(), result.completenessReasons().toString());
    }

    @Test
    void directoryResourceCallbackIgnoresExplodedNestedLibraryXml(@TempDir Path tmp)
            throws Exception {
        Path root = tmp.resolve("exploded");
        Files.createDirectories(root.resolve("WEB-INF/lib"));
        Files.writeString(root.resolve("WEB-INF/web.xml"), "<web-app/>");
        Files.writeString(root.resolve("WEB-INF/lib/dependency.xml"), "<handler/>");

        List<String> resources = new ArrayList<>();
        JarReader.StreamResult result = new JarReader().streamDetailedWithResources(root,
                ignored -> { },
                (path, bytes, origin) -> resources.add(path),
                17, InputBudget.defaults(), InputBudget.defaults().tracker());

        assertEquals(List.of("WEB-INF/web.xml"), resources);
        assertTrue(result.completenessReasons().isEmpty(), result.completenessReasons().toString());
    }

    @Test
    void explicitInputBudgetControlsClassEmissionWithoutResettingArchiveAccounting(
            @TempDir Path tmp) throws Exception {
        Path jar = tmp.resolve("class-cap.jar");
        Map<String, Function<String, byte[]>> root = new LinkedHashMap<>();
        root.put("BOOT-INF/classes/com/app/One.class", JarReaderTest::markerClass);
        root.put("BOOT-INF/classes/com/app/Two.class", JarReaderTest::markerClass);
        Files.write(jar, zip(root));

        InputBudget budget = InputBudget.defaults().withArchiveLimits(
                1024 * 1024, 1024 * 1024, 1024 * 1024, 1024 * 1024,
                32, 2, 1);
        JarReader.StreamResult result = new JarReader().streamDetailed(jar,
                ignored -> { }, 17, budget);

        assertEquals(1, result.classesEmitted());
        assertTrue(result.completenessReasons().contains("CLASS_CAP:1"),
                result.completenessReasons().toString());
    }

    @Test
    void callerTrackerCarriesArchiveLimitsAcrossMultipleInputs(@TempDir Path tmp) throws Exception {
        Path first = tmp.resolve("first.jar");
        Path second = tmp.resolve("second.jar");
        Files.write(first, zip(Map.of("first/Main.class", JarReaderTest::markerClass)));
        Files.write(second, zip(Map.of("second/Main.class", JarReaderTest::markerClass)));
        InputBudget budget = InputBudget.defaults().withArchiveLimits(
                1024 * 1024, 1024 * 1024, 1024 * 1024, 1024 * 1024,
                1, 4, 10);
        InputBudget.Tracker tracker = budget.tracker();
        JarReader reader = new JarReader();
        JarReader.ReadResult firstResult = reader.readDetailed(first, 17, budget, tracker);
        JarReader.ReadResult secondResult = reader.readDetailed(second, 17, budget, tracker);

        assertEquals(1, firstResult.classes().size());
        assertTrue(secondResult.classes().isEmpty(), secondResult.classes().toString());
        assertTrue(secondResult.completenessReasons().contains("ARCHIVE_ENTRY_CAP:1"),
                secondResult.completenessReasons().toString());
    }

    @Test
    void directoryWalkIsBoundedBeforeClassMaterialization(@TempDir Path tmp) throws Exception {
        Path classes = tmp.resolve("classes");
        Files.createDirectories(classes.resolve("a/b"));
        Files.write(classes.resolve("a/b/Main.class"), markerClass("main"));
        InputBudget budget = InputBudget.defaults().withArchiveLimits(
                1024 * 1024, 1024 * 1024, 1024 * 1024, 1024,
                1, 4, 100);

        JarReader.StreamResult result = new JarReader().streamDetailed(classes,
                ignored -> { }, 17, budget);

        assertTrue(result.classesEmitted() == 0);
        assertTrue(result.completenessReasons().contains("ARCHIVE_ENTRY_CAP:1"),
                result.completenessReasons().toString());
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
    void nestedMultiReleaseJarSelectsTargetFeatureAfterBoundedFirstPass(@TempDir Path tmp)
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
        assertEquals("17", new String(result.classes().get(0).bytes(),
                java.nio.charset.StandardCharsets.US_ASCII).substring("fake-class:".length()));
        assertTrue(result.completenessReasons().isEmpty(),
                "nested MR selection is complete after the bounded first pass: "
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
    void crcFailureIsReportedAsArchiveCorruption(@TempDir Path tmp) throws Exception {
        byte[] payload = markerClass("crc");
        ByteArrayOutputStream encoded = new ByteArrayOutputStream();
        CRC32 crc = new CRC32();
        crc.update(payload);
        try (ZipOutputStream zip = new ZipOutputStream(encoded)) {
            ZipEntry entry = new ZipEntry("Main.class");
            entry.setMethod(ZipEntry.STORED);
            entry.setSize(payload.length);
            entry.setCompressedSize(payload.length);
            entry.setCrc(crc.getValue());
            zip.putNextEntry(entry);
            zip.write(payload);
            zip.closeEntry();
        }
        byte[] archive = encoded.toByteArray();
        boolean changed = false;
        // Corrupt the central-directory CRC (signature + 16) while leaving the local
        // header and payload intact; ZipFile must reject the entry when it reaches EOF.
        for (int i = 0; i <= archive.length - 4; i++) {
            if ((archive[i] & 0xff) == 0x50 && (archive[i + 1] & 0xff) == 0x4b
                    && (archive[i + 2] & 0xff) == 0x01 && (archive[i + 3] & 0xff) == 0x02) {
                archive[i + 16] ^= 0x01;
                changed = true;
                break;
            }
        }
        assertTrue(changed, "central-directory CRC was not located");
        Path jar = tmp.resolve("crc.jar");
        Files.write(jar, archive);

        JarReader.ReadResult result = new JarReader().readDetailed(jar);
        assertTrue(result.classes().isEmpty());
        assertTrue(result.completenessReasons().contains("ARCHIVE_CORRUPT"),
                result.completenessReasons().toString());
    }

    @Test
    void zip64CentralDirectoryIsAcceptedWithinEntryBudget(@TempDir Path tmp) throws Exception {
        Path jar = tmp.resolve("zip64.jar");
        // More than the classic 65,535-entry ZIP limit forces ZipOutputStream to emit a
        // ZIP64 end record. Empty metadata entries keep the fixture small and bounded.
        try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(jar))) {
            for (int i = 0; i < 65_536; i++) {
                zip.putNextEntry(new ZipEntry(String.format(java.util.Locale.ROOT,
                        "meta/e%05d.txt", i)));
                zip.closeEntry();
            }
        }
        InputBudget budget = InputBudget.defaults().withArchiveLimits(
                32 * 1024 * 1024, 32 * 1024 * 1024, 32 * 1024 * 1024,
                1024 * 1024, 70_000, 4, 1);
        JarReader.ReadResult result = new JarReader().readDetailed(jar, 17, budget);
        assertTrue(result.classes().isEmpty());
        assertTrue(result.completenessReasons().stream()
                .noneMatch(reason -> reason.startsWith("ARCHIVE_CORRUPT")),
                result.completenessReasons().toString());
    }

    @Test
    void randomizedZip64TailMutationsRemainBoundedAndAuditable(@TempDir Path tmp) throws Exception {
        ByteArrayOutputStream encoded = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(encoded)) {
            for (int i = 0; i < 65_536; i++) {
                zip.putNextEntry(new ZipEntry(String.format(java.util.Locale.ROOT,
                        "meta/z%05d.txt", i)));
                zip.closeEntry();
            }
        }
        byte[] original = encoded.toByteArray();
        List<Integer> zip64Offsets = new ArrayList<>();
        for (int i = 0; i <= original.length - 4; i++) {
            if ((original[i] & 0xff) == 0x50 && (original[i + 1] & 0xff) == 0x4b
                    && (original[i + 2] & 0xff) == 0x06 && (original[i + 3] & 0xff) == 0x06) {
                zip64Offsets.add(i);
            }
        }
        assertTrue(!zip64Offsets.isEmpty(), "fixture must contain a ZIP64 end record");
        Random random = new Random(0x4a5553542d5a3634L);
        InputBudget budget = InputBudget.defaults().withArchiveLimits(
                32 * 1024 * 1024, 32 * 1024 * 1024, 32 * 1024 * 1024,
                1024 * 1024, 70_000, 4, 1);
        for (int iteration = 0; iteration < 16; iteration++) {
            byte[] mutated = Arrays.copyOf(original, original.length);
            int offset = zip64Offsets.get(0) + 8 + random.nextInt(56);
            if (offset >= mutated.length) {
                offset = zip64Offsets.get(0) + 8;
            }
            mutated[offset] ^= (byte) (1 + random.nextInt(0xff));
            Path jar = tmp.resolve("zip64-tail-fuzz-" + iteration + ".jar");
            Files.write(jar, mutated);
            JarReader.ReadResult result = new JarReader().readDetailed(jar, 17, budget);
            assertTrue(result != null, "ZIP64 mutation must not escape as unchecked parser failure");
            assertTrue(result.completenessReasons().size() <= 4,
                    "reason list must remain bounded: " + result.completenessReasons());
        }
    }

    @Test
    void unknownNestedEntrySizeStillObeysReadBudget(@TempDir Path tmp) throws Exception {
        // ZipOutputStream emits a data descriptor for this deflated nested entry, so
        // ZipInputStream observes size == -1 until the payload is consumed.
        byte[] payload = new byte[128 * 1024];
        byte[] nested = zip(Map.of("deep/Unknown.class", ignored -> payload));
        Path jar = tmp.resolve("unknown-size-nested.jar");
        Files.write(jar, zip(Map.of("BOOT-INF/lib/dependency.jar", ignored -> nested)));
        InputBudget budget = InputBudget.defaults().withArchiveLimits(
                4 * 1024 * 1024, 4 * 1024 * 1024, 64 * 1024,
                2 * 1024 * 1024, 100, 4, 100);

        JarReader.ReadResult result = new JarReader().readDetailed(jar, 17, budget);

        assertTrue(result.classes().isEmpty(), "unknown-size payload must not bypass read cap");
        assertTrue(result.completenessReasons().stream().anyMatch(reason ->
                        reason.equals("ARCHIVE_ENTRY_READ_CAP")
                                || reason.equals("ARCHIVE_UNCOMPRESSED_BYTES_CAP")),
                result.completenessReasons().toString());
    }

    @Test
    void forgedCentralDirectorySizeFailsClosed(@TempDir Path tmp) throws Exception {
        byte[] archive = zip(Map.of("Main.class", JarReaderTest::markerClass));
        boolean changed = false;
        for (int i = 0; i <= archive.length - 4; i++) {
            if ((archive[i] & 0xff) == 0x50 && (archive[i + 1] & 0xff) == 0x4b
                    && (archive[i + 2] & 0xff) == 0x01 && (archive[i + 3] & 0xff) == 0x02) {
                // Central-directory uncompressed-size field (relative offset 24).
                Arrays.fill(archive, i + 24, i + 28, (byte) 0x7f);
                changed = true;
                break;
            }
        }
        assertTrue(changed, "central-directory entry was not located");
        Path jar = tmp.resolve("forged-size.jar");
        Files.write(jar, archive);

        JarReader.ReadResult result = new JarReader().readDetailed(jar);

        assertTrue(result.classes().isEmpty());
        assertTrue(result.completenessReasons().contains("ARCHIVE_CORRUPT")
                        || result.completenessReasons().stream()
                        .anyMatch(reason -> reason.contains("BYTES_CAP")),
                result.completenessReasons().toString());
    }

    @Test
    void truncatedCentralDirectoryIsAnAuditableCorruption(@TempDir Path tmp) throws Exception {
        byte[] archive = zip(Map.of("Main.class", JarReaderTest::markerClass));
        Path jar = tmp.resolve("truncated-central-directory.jar");
        Files.write(jar, Arrays.copyOf(archive, Math.max(0, archive.length - 9)));

        JarReader.ReadResult result = new JarReader().readDetailed(jar);

        assertTrue(result.classes().isEmpty());
        assertTrue(result.completenessReasons().contains("ARCHIVE_CORRUPT"),
                result.completenessReasons().toString());
    }

    @Test
    void randomizedCentralDirectoryMutationsRemainBoundedAndAuditable(@TempDir Path tmp)
            throws Exception {
        byte[] original = zip(Map.of("Main.class", JarReaderTest::markerClass,
                "meta/config.txt", ignored -> new byte[32]));
        List<Integer> centralOffsets = new ArrayList<>();
        for (int i = 0; i <= original.length - 4; i++) {
            if ((original[i] & 0xff) == 0x50 && (original[i + 1] & 0xff) == 0x4b
                    && (original[i + 2] & 0xff) == 0x01 && (original[i + 3] & 0xff) == 0x02) {
                centralOffsets.add(i);
            }
        }
        assertTrue(centralOffsets.size() >= 2, "fixture must contain a central directory");
        Random random = new Random(0x4a5553542d504239L);
        for (int iteration = 0; iteration < 64; iteration++) {
            byte[] mutated = Arrays.copyOf(original, original.length);
            int entry = centralOffsets.get(random.nextInt(centralOffsets.size()));
            int offset = entry + 8 + random.nextInt(36);
            if (offset >= mutated.length) {
                offset = entry + 24;
            }
            mutated[offset] ^= (byte) (1 + random.nextInt(0xff));
            Path jar = tmp.resolve("central-fuzz-" + iteration + ".jar");
            Files.write(jar, mutated);
            JarReader.ReadResult result = new JarReader().readDetailed(jar);
            assertTrue(result != null, "mutation must not escape as an unchecked parser failure");
            assertTrue(result.completenessReasons().size() <= 4,
                    "reason list must remain bounded: " + result.completenessReasons());
        }
    }

    @Test
    void deterministicWholeArchiveFuzzNeverEscapesBoundedReader(@TempDir Path tmp)
            throws Exception {
        byte[] nested = zip(Map.of("dep/Marker.class", JarReaderTest::markerClass));
        Map<String, Function<String, byte[]>> entries = new LinkedHashMap<>();
        entries.put("BOOT-INF/classes/app/Main.class", JarReaderTest::markerClass);
        entries.put("BOOT-INF/lib/dependency.jar", ignored -> nested);
        byte[] original = zip(entries);
        InputBudget budget = InputBudget.defaults().withArchiveLimits(
                2 * 1024 * 1024, 2 * 1024 * 1024, 2 * 1024 * 1024,
                128 * 1024, 256, 4, 64);
        Random random = new Random(0x4A55535441524348L);
        for (int iteration = 0; iteration < 128; iteration++) {
            byte[] mutated = Arrays.copyOf(original, original.length);
            int flips = 1 + random.nextInt(6);
            for (int flip = 0; flip < flips; flip++) {
                int offset = random.nextInt(mutated.length);
                mutated[offset] ^= (byte) (1 + random.nextInt(0xff));
            }
            Path jar = tmp.resolve("whole-archive-fuzz-" + iteration + ".jar");
            Files.write(jar, mutated);
            assertDoesNotThrow(() -> {
                try {
                    JarReader.ReadResult result = new JarReader().readDetailed(jar, 17, budget);
                    assertTrue(result.completenessReasons().size() <= 8,
                            "reason list must remain bounded: " + result.completenessReasons());
                } catch (java.io.IOException expected) {
                    // A malformed path/container may be rejected at the checked boundary; the
                    // contract is that no unchecked parser/allocation escape reaches callers.
                }
            }, "unchecked whole-archive parser escape at mutation " + iteration);
        }
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
    void corruptNestedEntryDoesNotHideLaterValidDependency(@TempDir Path tmp) throws Exception {
        byte[] broken = zip(Map.of("broken/Bad.class", ignored -> markerClass("broken")));
        boolean changed = false;
        for (int i = 0; i <= broken.length - 30; i++) {
            if ((broken[i] & 0xff) == 0x50 && (broken[i + 1] & 0xff) == 0x4b
                    && (broken[i + 2] & 0xff) == 0x03 && (broken[i + 3] & 0xff) == 0x04) {
                int nameLength = (broken[i + 26] & 0xff) | ((broken[i + 27] & 0xff) << 8);
                int extraLength = (broken[i + 28] & 0xff) | ((broken[i + 29] & 0xff) << 8);
                int payload = i + 30 + nameLength + extraLength;
                if (payload < broken.length) {
                    // Keep the outer entry valid, but change one byte in the nested
                    // compressed payload so the nested CRC check reports corruption while
                    // the outer reader can continue to the next library.
                    broken[payload] ^= 0x01;
                    changed = true;
                }
                break;
            }
        }
        assertTrue(changed, "nested central-directory CRC was not located");

        byte[] valid = zip(Map.of("valid/Good.class", ignored -> markerClass("valid")));
        Path jar = tmp.resolve("corrupt-nested-entry.jar");
        Map<String, Function<String, byte[]>> root = new LinkedHashMap<>();
        root.put("BOOT-INF/lib/a-broken.jar", ignored -> broken);
        root.put("BOOT-INF/lib/z-valid.jar", ignored -> valid);
        Files.write(jar, zip(root));

        JarReader.ReadResult result = new JarReader().readDetailed(jar);

        assertTrue(result.classes().stream().anyMatch(value ->
                        value.className().equals("valid/Good")),
                "a corrupt nested dependency must not hide later valid entries: "
                        + result.classes());
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

    @Test
    void topLevelContainerMutationFailsClosed(@TempDir Path tmp) throws Exception {
        Path jar = tmp.resolve("mutating.jar");
        Files.write(jar, zip(Map.of("app/Main.class", JarReaderTest::markerClass)));
        var before = Files.getLastModifiedTime(jar);

        java.io.IOException failure = assertThrows(java.io.IOException.class,
                () -> new JarReader().streamDetailed(jar, bytes ->
                        Files.setLastModifiedTime(jar,
                                java.nio.file.attribute.FileTime.fromMillis(
                                        before.toMillis() + 10_000L))));

        assertTrue(failure.getMessage().contains("ARCHIVE_CHANGED_DURING_READ"),
                failure.getMessage());
    }
}
