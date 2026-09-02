package io.just.sast.config;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ModelSourceTest {

    @Test
    void parsesOnlyTheSmallDeclarativeGrammar() {
        ModelSource receiver = ModelSource.parse("this");
        assertTrue(receiver.receiver());
        assertFalse(receiver.element());
        assertNull(receiver.argumentOrdinal());

        ModelSource element = ModelSource.parse("element(arg02)");
        assertTrue(element.element());
        assertEquals("arg02", element.base());
        assertEquals(2, element.argumentOrdinal());

        assertTrue(ModelSource.isValid("arg0"));
        assertTrue(ModelSource.isValid("element(this)"));
    }

    @Test
    void rejectsMalformedAndOverflowingSources() {
        for (String source : new String[]{null, "", "arg", "arg-1", "argX",
                "element()", "element(element(this))", "element(arg999999999999999999)"}) {
            assertNull(ModelSource.parse(source), "unexpected model source: " + source);
        }
    }
}
