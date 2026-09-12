package io.just.sast.cli;

import org.junit.jupiter.api.Test;
import picocli.CommandLine;

import java.io.PrintWriter;
import java.io.StringWriter;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ScanModeContractTest {

    @Test
    void explicitModeVocabularyIsClosedAndCaseInsensitive() {
        assertEquals(ScanMode.COMPONENT, ScanMode.parse("component"));
        assertEquals(ScanMode.COMPONENT, ScanMode.parse("COMPONENT"));
        assertEquals(ScanMode.APPLICATION, ScanMode.parse("Application"));
        assertThrows(IllegalArgumentException.class, () -> ScanMode.parse("library"));
    }

    @Test
    void scanHelpDeclaresComponentDefaultAndApplicationEligibility() {
        CommandLine root = new CommandLine(new JustMain());
        StringWriter output = new StringWriter();
        root.getSubcommands().get("scan").usage(new PrintWriter(output));
        String help = output.toString();

        assertTrue(help.contains("--mode"));
        assertTrue(help.contains("component"));
        assertTrue(help.contains("application"));
    }
}
