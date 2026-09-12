package io.just.sast.cli;

import org.junit.jupiter.api.Test;
import picocli.CommandLine;

import java.io.StringWriter;
import java.io.PrintWriter;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class VerificationCliContractTest {

    @Test
    void scanHelpMakesAutoTrustBoundaryAndStaticOnlyPathExplicit() {
        CommandLine root = new CommandLine(new JustMain());
        StringWriter output = new StringWriter();
        root.getSubcommands().get("scan").usage(new PrintWriter(output));
        String help = output.toString();

        assertTrue(help.contains("--no-verify"));
        assertTrue(help.contains("不可信") || help.contains("来源不明"));
        assertFalse(help.contains("--safe-exec"));
        assertFalse(help.contains("--safe-real-sink"));
        assertFalse(help.contains("--require-os-isolation"));
    }

    @Test
    void performanceHelpHidesLegacyAdapterSwitches() {
        CommandLine root = new CommandLine(new JustMain());
        StringWriter output = new StringWriter();
        root.getSubcommands().get("perf").usage(new PrintWriter(output));
        String help = output.toString();

        assertTrue(help.contains("--no-verify"));
        assertFalse(help.contains("--safe-exec"));
        assertFalse(help.contains("--safe-real-sink"));
        assertFalse(help.contains("--require-os-isolation"));
    }

    @Test
    void scanAndPerformanceShareTheProductVerificationBudgetDefault() {
        CommandLine root = new CommandLine(new JustMain());
        StringWriter scanOutput = new StringWriter();
        root.getSubcommands().get("scan").usage(new PrintWriter(scanOutput));
        StringWriter performanceOutput = new StringWriter();
        root.getSubcommands().get("perf").usage(new PrintWriter(performanceOutput));

        assertEquals(io.just.sast.verify.VerificationDefaults.VERIFY_BUDGET, 32);
        assertTrue(scanOutput.toString().contains("默认 32"));
        assertTrue(performanceOutput.toString().contains("规范化 finding 组"));
    }
}
