package io.just.sast.frontend.asm;

import io.just.sast.run.InputBudget;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;

import java.io.ByteArrayInputStream;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class NativeMethodIndexTest {

    @Test
    void extractsOnlyNativeMethodsWithBoundedOutput() throws java.io.IOException {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "fixture/Native", null,
                "java/lang/Object", null);
        writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_NATIVE, "call", "()V", null, null)
                .visitEnd();
        writer.visitMethod(Opcodes.ACC_PUBLIC, "ordinary", "()V", null, null).visitEnd();
        writer.visitEnd();

        assertEquals(List.of("fixture/Native#call#()V"), NativeMethodIndex.read("fixture/Native",
                new ByteArrayInputStream(writer.toByteArray()), 2));
        assertEquals(List.of(), NativeMethodIndex.read("fixture/Native",
                new ByteArrayInputStream(writer.toByteArray()), 0));
    }

    @Test
    void explicitInputBudgetRejectsOversizedClassStream() {
        InputBudget defaults = InputBudget.defaults();
        InputBudget tiny = new InputBudget(defaults.schemaVersion(), defaults.maxPhysicalBytes(),
                defaults.maxCompressedBytes(), defaults.maxUncompressedBytes(), 8,
                defaults.maxCompressionRatio(), defaults.maxArchiveEntries(), defaults.maxArchiveNesting(),
                defaults.maxClassEntries(), defaults.maxRuleInputBytes(), defaults.maxRuleCodePoints(),
                defaults.maxRuleAliases(), defaults.maxRuleNestingDepth(), defaults.maxRuleDocuments(),
                defaults.maxRuleCount(), defaults.maxRuleCollectionItems(), defaults.maxRuleNodes(),
                defaults.maxRuleScalarChars(), defaults.maxPathChars(), defaults.maxParseMillis());
        assertThrows(java.io.IOException.class, () -> NativeMethodIndex.read("fixture/Native",
                new ByteArrayInputStream(new byte[16]), 1, tiny));
    }

    @Test
    void callerOwnedTrackerCapsAggregateNativeIndexReads() throws java.io.IOException {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "fixture/NativeAggregate", null,
                "java/lang/Object", null);
        writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_NATIVE, "call", "()V", null, null)
                .visitEnd();
        writer.visitEnd();
        byte[] bytes = writer.toByteArray();
        InputBudget defaults = InputBudget.defaults();
        InputBudget bounded = defaults.withArchiveLimits(defaults.maxPhysicalBytes(),
                defaults.maxCompressedBytes(), bytes.length + 1L, defaults.maxEntryBytes(),
                defaults.maxArchiveEntries(), defaults.maxArchiveNesting(),
                defaults.maxClassEntries());
        InputBudget.Tracker tracker = bounded.tracker();
        assertEquals(List.of("fixture/NativeAggregate#call#()V"), NativeMethodIndex.read(
                "fixture/NativeAggregate", new ByteArrayInputStream(bytes), 1,
                bounded, tracker));
        assertThrows(java.io.IOException.class, () -> NativeMethodIndex.read(
                "fixture/NativeAggregate", new ByteArrayInputStream(bytes), 1,
                bounded, tracker));
    }
}
