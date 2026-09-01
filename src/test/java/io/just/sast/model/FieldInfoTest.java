package io.just.sast.model;

import org.junit.jupiter.api.Test;

import java.lang.reflect.Modifier;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FieldInfoTest {

    @Test
    void genericReferenceTypesIgnoreErasedContainerAndKeepNestedArguments() {
        FieldInfo field = new FieldInfo("app/Holder", "values", "Ljava/util/Map;", 0,
                null, "Ljava/util/Map<Ljava/lang/String;Ljava/util/List<Lapp/Gadget;>;>;");

        assertEquals(List.of("java/lang/String", "java/util/List", "app/Gadget"),
                field.genericReferenceTypes());
    }

    @Test
    void serialPersistentFieldsIsAnExplicitClassShapeMarker() {
        FieldInfo marker = new FieldInfo("app/Holder", "serialPersistentFields",
                "[Ljava/io/ObjectStreamField;", Modifier.PRIVATE | Modifier.STATIC, null);
        ClassInfo info = new ClassInfo("app/Holder", "java/lang/Object", List.of(),
                Modifier.PUBLIC, List.of(), List.of(marker));

        assertTrue(info.hasSerialPersistentFields());
        assertFalse(new ClassInfo("app/Other", "java/lang/Object", List.of(), Modifier.PUBLIC,
                List.of(), List.of()).hasSerialPersistentFields());
    }
}
