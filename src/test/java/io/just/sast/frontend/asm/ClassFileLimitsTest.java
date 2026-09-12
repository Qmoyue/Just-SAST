package io.just.sast.frontend.asm;

import io.just.sast.run.InputBudget;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.util.Arrays;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ClassFileLimitsTest {

    @Test
    void acceptsAValidClassBeforeAsmParsing() throws Exception {
        byte[] bytes;
        try (InputStream input = ClassFileLimitsTest.class.getResourceAsStream(
                "/io/just/sast/frontend/asm/ClassFileLimitsTest.class")) {
            bytes = input.readAllBytes();
        }
        assertDoesNotThrow(() -> ClassFileLimits.validate(bytes, InputBudget.defaults()));
    }

    @Test
    void rejectsForgedConstantPoolCountWithoutWalkingAttackerRange() {
        byte[] bytes = new byte[12];
        bytes[0] = (byte) 0xCA;
        bytes[1] = (byte) 0xFE;
        bytes[2] = (byte) 0xBA;
        bytes[3] = (byte) 0xBE;
        bytes[8] = (byte) 0xFF;
        bytes[9] = (byte) 0xFF;

        IOException failure = assertThrows(IOException.class,
                () -> ClassFileLimits.validate(bytes, InputBudget.defaults()));
        assertTrue(failure.getMessage().startsWith("CLASSFILE_CONSTANT_POOL_CAP"),
                failure.getMessage());
    }

    @Test
    void rejectsUnknownConstantPoolTagWithStableReason() {
        byte[] bytes = new byte[13];
        bytes[0] = (byte) 0xCA;
        bytes[1] = (byte) 0xFE;
        bytes[2] = (byte) 0xBA;
        bytes[3] = (byte) 0xBE;
        bytes[8] = 0;
        bytes[9] = 2;
        bytes[10] = 0;

        IOException failure = assertThrows(IOException.class,
                () -> ClassFileLimits.validate(bytes, InputBudget.defaults()));
        assertTrue(failure.getMessage().equals("CLASSFILE_CONSTANT_POOL_TAG:0"),
                failure.getMessage());
    }

    @Test
    void rejectsHeaderReferenceToWrongConstantPoolKind() throws Exception {
        Fixture fixture = minimalClass();
        writeU2(fixture.bytes, fixture.thisClassOffset, 1); // Utf8, not Class

        IOException failure = assertThrows(IOException.class,
                () -> ClassFileLimits.validate(fixture.bytes, InputBudget.defaults()));
        assertTrue(failure.getMessage().startsWith("CLASSFILE_THIS_CLASS_REF"),
                failure.getMessage());
    }

    @Test
    void rejectsConstantPoolMemberReferenceToWrongKind() throws Exception {
        Fixture fixture = minimalClass();
        writeU2(fixture.bytes, fixture.methodRefClassOffset, 1); // Utf8, not Class

        IOException failure = assertThrows(IOException.class,
                () -> ClassFileLimits.validate(fixture.bytes, InputBudget.defaults()));
        assertTrue(failure.getMessage().startsWith("CLASSFILE_METHODREF_CLASS_REF"),
                failure.getMessage());
    }

    @Test
    void parserHonorsCallerTimeBudgetBeforeStructuralWalk() throws Exception {
        Fixture fixture = minimalClass();
        InputBudget defaults = InputBudget.defaults();
        InputBudget tiny = new InputBudget(defaults.schemaVersion(), defaults.maxPhysicalBytes(),
                defaults.maxCompressedBytes(), defaults.maxUncompressedBytes(),
                defaults.maxEntryBytes(), defaults.maxCompressionRatio(),
                defaults.maxArchiveEntries(), defaults.maxArchiveNesting(),
                defaults.maxClassEntries(), defaults.maxRuleInputBytes(), defaults.maxRuleCodePoints(),
                defaults.maxRuleAliases(), defaults.maxRuleNestingDepth(), defaults.maxRuleDocuments(),
                defaults.maxRuleCount(), defaults.maxRuleCollectionItems(), defaults.maxRuleNodes(),
                defaults.maxRuleScalarChars(), defaults.maxPathChars(), 1L);
        InputBudget.Tracker tracker = tiny.tracker();
        Thread.sleep(100L);
        IOException failure = assertThrows(IOException.class,
                () -> ClassFileLimits.validate(fixture.bytes(), tiny, tracker));
        assertTrue(failure.getMessage().startsWith("INPUT_PARSE_TIME_CAP"),
                failure.getMessage());
    }

    @Test
    void deterministicMalformedClassFuzzNeverEscapesBoundedParser() throws Exception {
        Fixture fixture = minimalClass();
        Random random = new Random(0x4A555354434C4153L);
        for (int iteration = 0; iteration < 512; iteration++) {
            byte[] mutated = Arrays.copyOf(fixture.bytes(), fixture.bytes().length);
            int flips = 1 + random.nextInt(6);
            for (int flip = 0; flip < flips; flip++) {
                int offset = random.nextInt(mutated.length);
                mutated[offset] ^= (byte) (1 + random.nextInt(255));
            }
            assertDoesNotThrow(() -> {
                try {
                    ClassFileLimits.validate(mutated, InputBudget.defaults());
                } catch (IOException expected) {
                    // Malformed input is an expected, typed rejection, not a parser escape.
                }
            }, "unchecked parser escape at mutation " + iteration);
        }
    }

    private static void writeU2(byte[] bytes, int offset, int value) {
        bytes[offset] = (byte) (value >>> 8);
        bytes[offset + 1] = (byte) value;
    }

    private static Fixture minimalClass() throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        DataOutputStream data = new DataOutputStream(output);
        data.writeInt(0xCAFEBABE);
        data.writeShort(0);
        data.writeShort(52);
        data.writeShort(9); // constant_pool_count
        writeUtf8(data, "A");                         // #1
        data.writeByte(7);
        data.writeShort(1);                            // #2 Class
        writeUtf8(data, "java/lang/Object");          // #3
        data.writeByte(7);
        data.writeShort(3);                            // #4 Class
        writeUtf8(data, "<init>");                    // #5
        writeUtf8(data, "()V");                       // #6
        data.writeByte(12);
        data.writeShort(5);
        data.writeShort(6);                            // #7 NameAndType
        int methodRefClassOffset = output.size() + 1;
        data.writeByte(10);
        data.writeShort(4);
        data.writeShort(7);                            // #8 Methodref
        int thisClassOffset = output.size() + 2;
        data.writeShort(0x0021);                       // access_flags
        data.writeShort(2);                            // this_class
        data.writeShort(4);                            // super_class
        data.writeShort(0);                            // interfaces_count
        data.writeShort(0);                            // fields_count
        data.writeShort(0);                            // methods_count
        data.writeShort(0);                            // attributes_count
        data.flush();
        return new Fixture(output.toByteArray(), thisClassOffset, methodRefClassOffset);
    }

    private static void writeUtf8(DataOutputStream data, String value) throws Exception {
        byte[] bytes = value.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        data.writeByte(1);
        data.writeShort(bytes.length);
        data.write(bytes);
    }

    private record Fixture(byte[] bytes, int thisClassOffset, int methodRefClassOffset) {
    }
}
