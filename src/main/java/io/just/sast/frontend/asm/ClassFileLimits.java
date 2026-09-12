package io.just.sast.frontend.asm;

import io.just.sast.run.InputBudget;

import java.io.IOException;

/**
 * Bounded structural and reference preflight for untrusted class bytes.
 *
 * <p>ASM remains the only class parser and is still confined to the frontend.  This pass only
 * walks the class-file envelope before ASM allocates a {@code ClassNode}; it rejects impossible
 * or disproportionately large constant-pool/member/attribute tables and invalid constant-pool
 * references with stable reason codes.  The only temporary state is a one-byte-per-entry tag
 * table bounded by the same structural cap, never an object graph proportional to attacker data.
 * Counts are bounded by both the versioned byte budget and the minimum number of bytes required
 * by the class-file grammar, so a forged u2/u4 count cannot induce an unbounded loop.</p>
 */
public final class ClassFileLimits {

    private static final int MAGIC = 0xCAFEBABE;
    private static final int MAX_REASONABLE_STRUCTURAL_ITEMS = 1_000_000;

    private ClassFileLimits() {
    }

    /** Validate the class-file envelope and reference graph before ASM parsing. */
    public static void validate(byte[] bytes, InputBudget budget) throws IOException {
        validate(bytes, budget, null);
    }

    /** Validate while charging parser progress to the caller-owned scan tracker. */
    public static void validate(byte[] bytes, InputBudget budget,
                                InputBudget.Tracker tracker) throws IOException {
        if (bytes == null) {
            throw new IOException("CLASSFILE_NULL");
        }
        InputBudget policy = budget == null ? InputBudget.defaults() : budget;
        ParseGuard guard = new ParseGuard(tracker);
        guard.check();
        if (bytes.length > policy.maxEntryBytes()) {
            throw new IOException("CLASSFILE_BYTES_CAP:" + policy.maxEntryBytes());
        }
        if (bytes.length < 10 || readU4(bytes, 0) != MAGIC) {
            throw new IOException("CLASSFILE_HEADER_INVALID");
        }

        int structuralCap = Math.max(1_024,
                Math.min(MAX_REASONABLE_STRUCTURAL_ITEMS,
                        Math.max(1, bytes.length / 2)));
        int cursor = 8;
        int constantPoolCount = readU2(bytes, cursor);
        cursor += 2;
        if (constantPoolCount <= 1 || constantPoolCount > structuralCap) {
            throw new IOException("CLASSFILE_CONSTANT_POOL_CAP:" + structuralCap);
        }
        int constantPoolStart = cursor;
        ConstantPool constantPool = readConstantPool(bytes, cursor, constantPoolCount,
                structuralCap, guard);
        cursor = constantPool.cursor();
        validateConstantPoolReferences(bytes, constantPoolStart, constantPool.tags(), guard);

        // access_flags, this_class, super_class
        ensure(bytes, cursor, 6, "CLASSFILE_HEADER_TRUNCATED");
        cursor += 2; // access_flags
        int thisClass = readU2(bytes, cursor);
        requireTag(constantPool.tags(), thisClass, 7, "CLASSFILE_THIS_CLASS_REF");
        cursor += 2;
        int superClass = readU2(bytes, cursor);
        if (superClass != 0) {
            requireTag(constantPool.tags(), superClass, 7, "CLASSFILE_SUPER_CLASS_REF");
        }
        cursor += 2;
        int interfaces = readU2(bytes, cursor);
        cursor += 2;
        cursor = skipInterfaces(bytes, cursor, interfaces, structuralCap, constantPool.tags(), guard);
        cursor = skipMembers(bytes, cursor, structuralCap, "CLASSFILE_FIELDS_CAP",
                constantPool.tags(), guard);
        cursor = skipMembers(bytes, cursor, structuralCap, "CLASSFILE_METHODS_CAP",
                constantPool.tags(), guard);
        cursor = skipAttributes(bytes, cursor, structuralCap, "CLASSFILE_ATTRIBUTES_CAP",
                constantPool.tags(), guard);
        if (cursor != bytes.length) {
            throw new IOException("CLASSFILE_TRAILING_BYTES");
        }
    }

    private static ConstantPool readConstantPool(byte[] bytes, int cursor, int count, int cap,
                                                 ParseGuard guard)
            throws IOException {
        byte[] tags = new byte[count];
        int items = 0;
        for (int index = 1; index < count; index++) {
            guard.check();
            if (++items > cap) {
                throw new IOException("CLASSFILE_CONSTANT_POOL_CAP:" + cap);
            }
            ensure(bytes, cursor, 1, "CLASSFILE_CONSTANT_POOL_TRUNCATED");
            int tag = bytes[cursor++] & 0xff;
            tags[index] = (byte) tag;
            switch (tag) {
                case 1 -> {
                    ensure(bytes, cursor, 2, "CLASSFILE_CONSTANT_POOL_TRUNCATED");
                    int length = readU2(bytes, cursor);
                    cursor += 2;
                    ensure(bytes, cursor, length, "CLASSFILE_CONSTANT_POOL_TRUNCATED");
                    cursor += length;
                }
                case 3, 4 -> {
                    ensure(bytes, cursor, 4, "CLASSFILE_CONSTANT_POOL_TRUNCATED");
                    cursor += 4;
                }
                case 5, 6 -> {
                    ensure(bytes, cursor, 8, "CLASSFILE_CONSTANT_POOL_TRUNCATED");
                    cursor += 8;
                    // Long/double occupy two constant-pool indexes.
                    if (index + 1 >= count) {
                        throw new IOException("CLASSFILE_CONSTANT_POOL_WIDE_SLOT");
                    }
                    tags[++index] = 0;
                }
                case 7, 8, 16, 19, 20 -> {
                    ensure(bytes, cursor, 2, "CLASSFILE_CONSTANT_POOL_TRUNCATED");
                    cursor += 2;
                }
                case 9, 10, 11, 12, 17, 18 -> {
                    ensure(bytes, cursor, 4, "CLASSFILE_CONSTANT_POOL_TRUNCATED");
                    cursor += 4;
                }
                case 15 -> {
                    ensure(bytes, cursor, 3, "CLASSFILE_CONSTANT_POOL_TRUNCATED");
                    cursor += 3;
                }
                default -> throw new IOException("CLASSFILE_CONSTANT_POOL_TAG:" + tag);
            }
        }
        return new ConstantPool(cursor, tags);
    }

    private static int skipInterfaces(byte[] bytes, int cursor, int count, int cap,
                                      byte[] tags, ParseGuard guard) throws IOException {
        if (count > cap) {
            throw new IOException("CLASSFILE_INTERFACES_CAP:" + cap);
        }
        ensure(bytes, cursor, count * 2L, "CLASSFILE_TABLE_TRUNCATED");
        for (int i = 0; i < count; i++) {
            guard.check();
            int interfaceIndex = readU2(bytes, cursor);
            requireTag(tags, interfaceIndex, 7, "CLASSFILE_INTERFACE_REF");
            cursor += 2;
        }
        return cursor;
    }

    private static int skipMembers(byte[] bytes, int cursor, int cap, String reason,
                                   byte[] tags, ParseGuard guard) throws IOException {
        ensure(bytes, cursor, 2, "CLASSFILE_MEMBER_TABLE_TRUNCATED");
        int count = readU2(bytes, cursor);
        cursor += 2;
        if (count > cap) {
            throw new IOException(reason + ":" + cap);
        }
        for (int i = 0; i < count; i++) {
            guard.check();
            ensure(bytes, cursor, 8, "CLASSFILE_MEMBER_TRUNCATED");
            cursor += 2; // access_flags
            int nameIndex = readU2(bytes, cursor);
            requireTag(tags, nameIndex, 1, "CLASSFILE_MEMBER_NAME_REF");
            cursor += 2;
            int descriptorIndex = readU2(bytes, cursor);
            requireTag(tags, descriptorIndex, 1, "CLASSFILE_MEMBER_DESCRIPTOR_REF");
            cursor += 2;
            cursor = skipAttributes(bytes, cursor, cap, "CLASSFILE_ATTRIBUTES_CAP", tags, guard);
        }
        return cursor;
    }

    private static int skipAttributes(byte[] bytes, int cursor, int cap, String reason,
                                      byte[] tags, ParseGuard guard) throws IOException {
        ensure(bytes, cursor, 2, "CLASSFILE_ATTRIBUTE_TABLE_TRUNCATED");
        int count = readU2(bytes, cursor);
        cursor += 2;
        if (count > cap) {
            throw new IOException(reason + ":" + cap);
        }
        for (int i = 0; i < count; i++) {
            guard.check();
            ensure(bytes, cursor, 6, "CLASSFILE_ATTRIBUTE_TRUNCATED");
            int nameIndex = readU2(bytes, cursor);
            requireTag(tags, nameIndex, 1, "CLASSFILE_ATTRIBUTE_NAME_REF");
            cursor += 2;
            long length = readU4(bytes, cursor) & 0xffffffffL;
            cursor += 4;
            ensure(bytes, cursor, length, "CLASSFILE_ATTRIBUTE_TRUNCATED");
            cursor += (int) length;
        }
        return cursor;
    }

    /** Validate the constant-pool graph after all entry tags are known. */
    private static void validateConstantPoolReferences(byte[] bytes, int cursor, byte[] tags,
                                                       ParseGuard guard) throws IOException {
        for (int index = 1; index < tags.length; index++) {
            guard.check();
            int tag = tags[index] & 0xff;
            ensure(bytes, cursor, 1, "CLASSFILE_CONSTANT_POOL_TRUNCATED");
            int encodedTag = bytes[cursor++] & 0xff;
            if (encodedTag != tag) {
                throw new IOException("CLASSFILE_CONSTANT_POOL_TAG_MISMATCH:" + index);
            }
            switch (tag) {
                case 1 -> {
                    int length = readU2Checked(bytes, cursor, "CLASSFILE_CONSTANT_POOL_TRUNCATED");
                    cursor += 2;
                    ensure(bytes, cursor, length, "CLASSFILE_CONSTANT_POOL_TRUNCATED");
                    cursor += length;
                }
                case 3, 4 -> {
                    ensure(bytes, cursor, 4, "CLASSFILE_CONSTANT_POOL_TRUNCATED");
                    cursor += 4;
                }
                case 5, 6 -> {
                    ensure(bytes, cursor, 8, "CLASSFILE_CONSTANT_POOL_TRUNCATED");
                    cursor += 8;
                    index++;
                }
                case 7 -> {
                    int nameIndex = readU2Checked(bytes, cursor,
                            "CLASSFILE_CONSTANT_POOL_TRUNCATED");
                    requireTag(tags, nameIndex, 1, "CLASSFILE_CLASS_NAME_REF");
                    cursor += 2;
                }
                case 8 -> {
                    int stringIndex = readU2Checked(bytes, cursor,
                            "CLASSFILE_CONSTANT_POOL_TRUNCATED");
                    requireTag(tags, stringIndex, 1, "CLASSFILE_STRING_REF");
                    cursor += 2;
                }
                case 9, 10, 11 -> {
                    int classIndex = readU2Checked(bytes, cursor,
                            "CLASSFILE_CONSTANT_POOL_TRUNCATED");
                    int nameAndTypeIndex = readU2Checked(bytes, cursor + 2,
                            "CLASSFILE_CONSTANT_POOL_TRUNCATED");
                    requireTag(tags, classIndex, 7, "CLASSFILE_" + memberTagName(tag)
                            + "_CLASS_REF");
                    requireTag(tags, nameAndTypeIndex, 12, "CLASSFILE_" + memberTagName(tag)
                            + "_NAME_TYPE_REF");
                    cursor += 4;
                }
                case 12 -> {
                    int nameIndex = readU2Checked(bytes, cursor,
                            "CLASSFILE_CONSTANT_POOL_TRUNCATED");
                    int descriptorIndex = readU2Checked(bytes, cursor + 2,
                            "CLASSFILE_CONSTANT_POOL_TRUNCATED");
                    requireTag(tags, nameIndex, 1, "CLASSFILE_NAME_TYPE_NAME_REF");
                    requireTag(tags, descriptorIndex, 1, "CLASSFILE_NAME_TYPE_DESCRIPTOR_REF");
                    cursor += 4;
                }
                case 15 -> {
                    int referenceKind = readU1Checked(bytes, cursor,
                            "CLASSFILE_CONSTANT_POOL_TRUNCATED");
                    int referenceIndex = readU2Checked(bytes, cursor + 1,
                            "CLASSFILE_CONSTANT_POOL_TRUNCATED");
                    if (referenceKind < 1 || referenceKind > 9) {
                        throw new IOException("CLASSFILE_METHOD_HANDLE_KIND:" + referenceKind);
                    }
                    int expected = switch (referenceKind) {
                        case 1, 2, 3, 4 -> 9;
                        case 5, 8 -> 10;
                        case 6, 7 -> 10; // InterfaceMethodref is accepted for Java 8+.
                        case 9 -> 11;
                        default -> throw new AssertionError(referenceKind);
                    };
                    if (referenceKind == 6 || referenceKind == 7) {
                        requireAnyTag(tags, referenceIndex, 10, 11,
                                "CLASSFILE_METHOD_HANDLE_REF");
                    } else {
                        requireTag(tags, referenceIndex, expected, "CLASSFILE_METHOD_HANDLE_REF");
                    }
                    cursor += 3;
                }
                case 16, 19, 20 -> {
                    int nameIndex = readU2Checked(bytes, cursor,
                            "CLASSFILE_CONSTANT_POOL_TRUNCATED");
                    requireTag(tags, nameIndex, 1, "CLASSFILE_CONSTANT_POOL_REF");
                    cursor += 2;
                }
                case 17, 18 -> {
                    int nameAndTypeIndex = readU2Checked(bytes, cursor + 2,
                            "CLASSFILE_CONSTANT_POOL_TRUNCATED");
                    requireTag(tags, nameAndTypeIndex, 12, "CLASSFILE_DYNAMIC_NAME_TYPE_REF");
                    cursor += 4;
                }
                default -> throw new IOException("CLASSFILE_CONSTANT_POOL_TAG:" + tag);
            }
        }
    }

    private static String memberTagName(int tag) {
        return switch (tag) {
            case 9 -> "FIELDREF";
            case 10 -> "METHODREF";
            case 11 -> "INTERFACE_METHODREF";
            default -> "MEMBERREF";
        };
    }

    private static int readU1Checked(byte[] bytes, int offset, String reason) throws IOException {
        ensure(bytes, offset, 1, reason);
        return bytes[offset] & 0xff;
    }

    private static int readU2Checked(byte[] bytes, int offset, String reason) throws IOException {
        ensure(bytes, offset, 2, reason);
        return readU2(bytes, offset);
    }

    private static void requireTag(byte[] tags, int index, int expected, String reason)
            throws IOException {
        if (index <= 0 || index >= tags.length || (tags[index] & 0xff) != expected) {
            throw new IOException(reason + ":" + index);
        }
    }

    private static void requireAnyTag(byte[] tags, int index, int[] expected, String reason)
            throws IOException {
        if (index <= 0 || index >= tags.length) {
            throw new IOException(reason + ":" + index);
        }
        int actual = tags[index] & 0xff;
        for (int tag : expected) {
            if (actual == tag) {
                return;
            }
        }
        throw new IOException(reason + ":" + index);
    }

    private static void requireAnyTag(byte[] tags, int index, int first, int second,
                                      String reason) throws IOException {
        if (index <= 0 || index >= tags.length) {
            throw new IOException(reason + ":" + index);
        }
        int actual = tags[index] & 0xff;
        if (actual != first && actual != second) {
            throw new IOException(reason + ":" + index);
        }
    }

    private record ConstantPool(int cursor, byte[] tags) {
    }

    /** Low-overhead progress hook: parser loops remain cheap while still interruptible. */
    private static final class ParseGuard {
        private final InputBudget.Tracker tracker;
        private long steps;

        private ParseGuard(InputBudget.Tracker tracker) {
            this.tracker = tracker;
        }

        private void check() throws IOException {
            if (tracker != null && (steps++ == 0L || (steps & 0x3fL) == 0L)) {
                tracker.checkTime();
            }
        }
    }

    private static void ensure(byte[] bytes, int cursor, long amount, String reason)
            throws IOException {
        if (cursor < 0 || amount < 0 || amount > bytes.length - cursor) {
            throw new IOException(reason);
        }
    }

    private static int readU2(byte[] bytes, int offset) {
        return ((bytes[offset] & 0xff) << 8) | (bytes[offset + 1] & 0xff);
    }

    private static int readU4(byte[] bytes, int offset) {
        return ((bytes[offset] & 0xff) << 24)
                | ((bytes[offset + 1] & 0xff) << 16)
                | ((bytes[offset + 2] & 0xff) << 8)
                | (bytes[offset + 3] & 0xff);
    }
}
