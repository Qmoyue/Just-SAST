package io.just.sast.frontend.asm;

import io.just.sast.model.ClassInfo;
import io.just.sast.model.FieldInfo;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;

import java.lang.reflect.Modifier;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Demand-driven JDK closure must load only referenced types and structural ancestors. */
class JdkClassSelectorTest {

    @Test
    void lazySelectionDoesNotMaterializeUnrelatedClasses() {
        Map<String, ClassBytes> available = new HashMap<>();
        available.put("seed/Child", classBytes("seed/Child", "seed/Base"));
        available.put("seed/Base", classBytes("seed/Base", "java/lang/Object"));
        available.put("java/lang/Object", classBytes("java/lang/Object", null));
        available.put("unused/Platform", classBytes("unused/Platform", "java/lang/Object"));

        ClassInfo application = new ClassInfo("app/Main", "java/lang/Object", List.of(),
                Modifier.PUBLIC, List.of(),
                List.of(new FieldInfo("app/Main", "value", "Lseed/Child;", 0)));
        JdkClassSelector.Selection selection = JdkClassSelector.selectDemandDriven(
                available::get, -1, Map.of(application.internalName(), application), Set.of(), List.of());

        List<String> names = selection.classes().stream().map(ClassBytes::className).toList();
        assertEquals(List.of("java/lang/Object", "seed/Base", "seed/Child"), names);
        assertEquals(3, selection.closureClasses());
        assertEquals(2, selection.initialSeeds());
        assertTrue(selection.classes().stream().noneMatch(c -> c.className().startsWith("unused/")));
    }

    private static ClassBytes classBytes(String name, String superName) {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, name, null,
                superName == null ? "java/lang/Object" : superName, null);
        writer.visitEnd();
        return new ClassBytes(name, writer.toByteArray(), "test");
    }
}
