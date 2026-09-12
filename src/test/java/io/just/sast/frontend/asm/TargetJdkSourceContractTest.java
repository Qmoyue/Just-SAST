package io.just.sast.frontend.asm;

import io.just.sast.run.InputBudget;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Legacy rt.jar consumer contracts: index/time and classfile structure remain bounded. */
class TargetJdkSourceContractTest {

    @TempDir
    Path temp;

    @Test
    void legacyClassReadRunsStructuralPreflightBeforeAsm() throws Exception {
        Path rt = temp.resolve("jre").resolve("lib").resolve("rt.jar");
        Files.createDirectories(rt.getParent());
        byte[] malformed = minimalClass();
        // this_class points at Utf8 #1 instead of Class #2.
        malformed[41] = 0;
        malformed[42] = 1;
        try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(rt))) {
            zip.putNextEntry(new ZipEntry("A.class"));
            zip.write(malformed);
            zip.closeEntry();
        }
        try (TargetJdkSource source = new TargetJdkSource(temp, InputBudget.defaults())) {
            assertNull(source.load("A"));
            assertTrue(source.completenessReasons().stream()
                    .anyMatch(reason -> reason.startsWith("CLASSFILE_THIS_CLASS_REF")),
                    "malformed target class must be an auditable structural rejection: "
                            + source.completenessReasons());
        }
    }

    @Test
    void legacyIndexStopsWhenParseTimeBudgetIsExhausted() throws Exception {
        Path rt = temp.resolve("jre").resolve("lib").resolve("rt.jar");
        Files.createDirectories(rt.getParent());
        try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(rt))) {
            for (int i = 0; i < 512; i++) {
                zip.putNextEntry(new ZipEntry("p/C" + i + ".class"));
                zip.write(minimalClass());
                zip.closeEntry();
            }
        }
        InputBudget d = InputBudget.defaults();
        InputBudget tinyTime = new InputBudget(d.schemaVersion(), d.maxPhysicalBytes(),
                d.maxCompressedBytes(), d.maxUncompressedBytes(), d.maxEntryBytes(),
                d.maxCompressionRatio(), d.maxArchiveEntries(), d.maxArchiveNesting(),
                d.maxClassEntries(), d.maxRuleInputBytes(), d.maxRuleCodePoints(),
                d.maxRuleAliases(), d.maxRuleNestingDepth(), d.maxRuleDocuments(),
                d.maxRuleCount(), d.maxRuleCollectionItems(), d.maxRuleNodes(),
                d.maxRuleScalarChars(), d.maxPathChars(), 1L);
        try (TargetJdkSource source = new TargetJdkSource(temp, tinyTime)) {
            source.load("missing/Type");
            assertTrue(source.completenessReasons().stream()
                    .anyMatch(reason -> reason.startsWith("INPUT_PARSE_TIME_CAP")
                            || reason.startsWith("JDK_ARCHIVE_INPUT_BUDGET")),
                    "legacy index must expose its parse-time stop: " + source.completenessReasons());
        }
    }

    @Test
    void targetJdkCanShareCallerTrackerAcrossSourceInstances() throws Exception {
        Path rt = temp.resolve("jre").resolve("lib").resolve("rt.jar");
        Files.createDirectories(rt.getParent());
        byte[] bytes = minimalClass();
        try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(rt))) {
            zip.putNextEntry(new ZipEntry("A.class"));
            zip.write(bytes);
            zip.closeEntry();
        }
        InputBudget defaults = InputBudget.defaults();
        InputBudget tiny = new InputBudget(defaults.schemaVersion(), defaults.maxPhysicalBytes(),
                defaults.maxCompressedBytes(), 100L, defaults.maxEntryBytes(),
                defaults.maxCompressionRatio(), defaults.maxArchiveEntries(),
                defaults.maxArchiveNesting(), defaults.maxClassEntries(), defaults.maxRuleInputBytes(),
                defaults.maxRuleCodePoints(), defaults.maxRuleAliases(), defaults.maxRuleNestingDepth(),
                defaults.maxRuleDocuments(), defaults.maxRuleCount(), defaults.maxRuleCollectionItems(),
                defaults.maxRuleNodes(), defaults.maxRuleScalarChars(), defaults.maxPathChars(),
                defaults.maxParseMillis());
        InputBudget.Tracker tracker = tiny.tracker();
        try (TargetJdkSource first = new TargetJdkSource(temp, tiny, tracker);
             TargetJdkSource second = new TargetJdkSource(temp, tiny, tracker)) {
            assertTrue(first.load("A") != null);
            assertNull(second.load("A"), "a second source must not reset the caller budget");
            assertTrue(tracker.readUncompressedBytes() > 0L);
            assertTrue(second.completenessReasons().stream()
                    .anyMatch(reason -> reason.startsWith("JDK_")
                            || reason.startsWith("ARCHIVE_")),
                    second.completenessReasons().toString());
        }
    }

    @Test
    void legacyClassEntryCrcMismatchFailsClosed(@TempDir Path temp) throws Exception {
        Path rt = temp.resolve("jre").resolve("lib").resolve("rt.jar");
        Files.createDirectories(rt.getParent());
        byte[] payload = new byte[] {1, 2, 3, 4, 5, 6};
        ByteArrayOutputStream encoded = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(encoded)) {
            ZipEntry entry = new ZipEntry("A.class");
            entry.setMethod(ZipEntry.STORED);
            java.util.zip.CRC32 crc = new java.util.zip.CRC32();
            crc.update(payload);
            entry.setSize(payload.length);
            entry.setCompressedSize(payload.length);
            entry.setCrc(crc.getValue());
            zip.putNextEntry(entry);
            zip.write(payload);
            zip.closeEntry();
        }
        byte[] archive = encoded.toByteArray();
        boolean changed = false;
        for (int i = 0; i <= archive.length - 4; i++) {
            if ((archive[i] & 0xff) == 0x50 && (archive[i + 1] & 0xff) == 0x4b
                    && (archive[i + 2] & 0xff) == 0x01 && (archive[i + 3] & 0xff) == 0x02) {
                // Central-directory CRC field is signature + 16. Keep the local payload
                // intact so the only rejected fact is the entry-content identity mismatch.
                archive[i + 16] ^= 0x01;
                changed = true;
                break;
            }
        }
        assertTrue(changed, "central-directory CRC was not located");
        Files.write(rt, archive);

        try (TargetJdkSource source = new TargetJdkSource(temp, InputBudget.defaults())) {
            assertNull(source.loadBytes("A"),
                    "a class entry whose bytes do not match its ZIP CRC must not escape");
            assertTrue(source.completenessReasons().stream()
                            .anyMatch(reason -> reason.startsWith("JDK_CLASS_CRC_MISMATCH")),
                    "CRC mismatch must remain a stable class-entry reason: "
                            + source.completenessReasons());
        }
    }

    @Test
    void legacyListAllCrcMismatchFailsClosed(@TempDir Path temp) throws Exception {
        Path rt = temp.resolve("jre").resolve("lib").resolve("rt.jar");
        Files.createDirectories(rt.getParent());
        byte[] payload = new byte[] {9, 8, 7, 6, 5};
        ByteArrayOutputStream encoded = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(encoded)) {
            ZipEntry entry = new ZipEntry("A.class");
            entry.setMethod(ZipEntry.STORED);
            java.util.zip.CRC32 crc = new java.util.zip.CRC32();
            crc.update(payload);
            entry.setSize(payload.length);
            entry.setCompressedSize(payload.length);
            entry.setCrc(crc.getValue());
            zip.putNextEntry(entry);
            zip.write(payload);
            zip.closeEntry();
        }
        byte[] archive = encoded.toByteArray();
        boolean changed = false;
        for (int i = 0; i <= archive.length - 4; i++) {
            if ((archive[i] & 0xff) == 0x50 && (archive[i + 1] & 0xff) == 0x4b
                    && (archive[i + 2] & 0xff) == 0x01 && (archive[i + 3] & 0xff) == 0x02) {
                archive[i + 16] ^= 0x01;
                changed = true;
                break;
            }
        }
        assertTrue(changed, "central-directory CRC was not located");
        Files.write(rt, archive);

        try (TargetJdkSource source = new TargetJdkSource(temp, InputBudget.defaults())) {
            IOException failure = org.junit.jupiter.api.Assertions.assertThrows(IOException.class,
                    source::listAll);
            assertTrue(failure.getMessage().contains("JDK_CLASS_CRC_MISMATCH"),
                    "listAll must expose the same class-entry identity reason: "
                            + failure.getMessage());
        }
    }

    @Test
    void legacyClassEntryDigestChangeFailsClosedAcrossReads(@TempDir Path temp) throws Exception {
        Path rt = temp.resolve("jre").resolve("lib").resolve("rt.jar");
        Files.createDirectories(rt.getParent());
        writeStoredClass(rt, new byte[] {1, 2, 3, 4, 5, 6});

        try (TargetJdkSource source = new TargetJdkSource(temp, InputBudget.defaults())) {
            assertNotNull(source.loadBytes("A"), "the initial class entry must be readable");
            // Keep the entry name, size and ZIP shape stable while changing its content. A
            // later read must not rely only on mutable path/metadata identity.
            writeStoredClass(rt, new byte[] {6, 5, 4, 3, 2, 1});
            assertNull(source.loadBytes("A"),
                    "changed bytes for an already observed class entry must fail closed");
            assertTrue(source.completenessReasons().stream()
                            .anyMatch(reason -> reason.startsWith("JDK_CLASS_ENTRY_CHANGED")),
                    "content identity changes need a stable reason: "
                            + source.completenessReasons());
        }
    }

    private static void writeStoredClass(Path rt, byte[] payload) throws IOException {
        java.util.zip.CRC32 crc = new java.util.zip.CRC32();
        crc.update(payload);
        try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(rt))) {
            ZipEntry entry = new ZipEntry("A.class");
            entry.setMethod(ZipEntry.STORED);
            entry.setSize(payload.length);
            entry.setCompressedSize(payload.length);
            entry.setCrc(crc.getValue());
            zip.putNextEntry(entry);
            zip.write(payload);
            zip.closeEntry();
        }
    }

    private static byte[] minimalClass() throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        DataOutputStream data = new DataOutputStream(output);
        data.writeInt(0xCAFEBABE);
        data.writeShort(0);
        data.writeShort(52);
        data.writeShort(5); // cp_count
        writeUtf8(data, "A"); // #1
        data.writeByte(7);
        data.writeShort(1); // #2 Class
        writeUtf8(data, "java/lang/Object"); // #3
        data.writeByte(7);
        data.writeShort(3); // #4 Class
        data.writeShort(0x0021); // access
        data.writeShort(2); // this
        data.writeShort(4); // super
        data.writeShort(0); // interfaces
        data.writeShort(0); // fields
        data.writeShort(0); // methods
        data.writeShort(0); // attrs
        data.flush();
        return output.toByteArray();
    }

    private static void writeUtf8(DataOutputStream data, String value) throws IOException {
        byte[] bytes = value.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        data.writeByte(1);
        data.writeShort(bytes.length);
        data.write(bytes);
    }
}
