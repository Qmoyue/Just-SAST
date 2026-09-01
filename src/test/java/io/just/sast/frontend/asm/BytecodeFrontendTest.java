package io.just.sast.frontend.asm;

import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BytecodeFrontendTest {

    @Test
    void rejectsClassPathAndInternalNameMismatch() throws Exception {
        byte[] bytes = fixtureBytes();
        BytecodeFrontend.Inputs inputs = new BytecodeFrontend.Inputs(
                List.of(new ClassBytes("wrong/Name", bytes, "wrong/Name.class")),
                List.of(), List.of());

        var result = new BytecodeFrontend().load(inputs);

        assertTrue(result.classes().isEmpty());
        assertEquals(1, result.diagnosticCount());
        assertTrue(result.diagnostics().get(0).message().contains("CLASS_NAME_MISMATCH"),
                result.diagnostics().toString());
    }

    @Test
    void reportsDuplicateClassWhenMergingInputs() throws Exception {
        byte[] bytes = fixtureBytes();
        String name = "io/just/sast/frontend/asm/BytecodeFrontendTest";
        BytecodeFrontend.Inputs inputs = new BytecodeFrontend.Inputs(
                List.of(new ClassBytes(name, bytes, "first.class"),
                        new ClassBytes(name, bytes, "second.class")),
                List.of(), List.of());

        var result = new BytecodeFrontend().load(inputs);

        assertEquals(1, result.classCount());
        assertTrue(result.completenessReasons().contains("DUPLICATE_CLASS:" + name),
                result.completenessReasons().toString());
    }

    private static byte[] fixtureBytes() throws Exception {
        try (InputStream input = BytecodeFrontendTest.class.getResourceAsStream(
                "/io/just/sast/frontend/asm/BytecodeFrontendTest.class")) {
            if (input == null) {
                throw new IllegalStateException("test class resource missing");
            }
            return input.readAllBytes();
        }
    }
}
