package io.just.sast.cli;

import io.just.sast.run.InputBudget;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * diff 子命令契约：canonical report 读取、链身份与排序无关、静态证据变更可检出，
 * 缺少 report.json 或超过共享预算时明确失败。
 */
class DiffCommandTest {

    private static final String ROW_A = chain("R-0001", "JUST-SINK-COMMAND-EXEC-RUNTIME",
            "COMMAND_EXEC", "HIGH", "app/Gadget", "readObject",
            "(Ljava/io/ObjectInputStream;)V", "java/lang/Runtime", "exec",
            "([Ljava/lang/String;)V", "direct=2+2, entry=readObject");
    private static final String ROW_B = chain("R-0002", "JUST-SINK-JNDI", "JNDI", "HIGH",
            "app/Lookup", "readObject", "(Ljava/io/ObjectInputStream;)V",
            "javax/naming/Context", "lookup", "(Ljava/lang/String;)Ljava/lang/Object;",
            "entry=readObject");

    private static String chain(String id, String ruleId, String category, String severity,
                                String entryClass, String entryMethod, String entryDescriptor,
                                String sinkClass, String sinkMethod, String sinkDescriptor,
                                String marker) {
        return "{\"id\":" + json(id)
                + ",\"exported\":true,\"rule_id\":" + json(ruleId)
                + ",\"category\":" + json(category)
                + ",\"severity\":" + json(severity)
                + ",\"entry\":{\"class\":" + json(entryClass)
                + ",\"method\":" + json(entryMethod)
                + ",\"descriptor\":" + json(entryDescriptor)
                + ",\"kind\":\"readObject\"}"
                + ",\"sink\":{\"class\":" + json(sinkClass)
                + ",\"method\":" + json(sinkMethod)
                + ",\"descriptor\":" + json(sinkDescriptor)
                + ",\"role\":\"TERMINAL\",\"risk\":\"HIGH\"}"
                + ",\"state\":{\"feasibility\":\"UNKNOWN\"}"
                + ",\"ranking\":{\"explanation\":" + json(marker) + "}"
                + ",\"notes\":[" + json(marker) + "]"
                + ",\"hops\":[],\"application_trace\":null}";
    }

    private static Path writeReport(Path dir, String... chains) throws Exception {
        Files.createDirectories(dir);
        String report = "{\"schema_version\":\"JUST-REPORT-V1\",\"mode\":\"component\","
                + "\"chains\":[" + String.join(",", chains) + "]}\n";
        Path file = dir.resolve("report.json");
        Files.writeString(file, report, StandardCharsets.UTF_8);
        return file;
    }

    private static DiffCommand diff(Path oldDir, Path newDir) {
        DiffCommand command = new DiffCommand();
        command.oldDir = oldDir;
        command.newDir = newDir;
        return command;
    }

    private static DiffCommand diff(InputBudget budget, Path oldDir, Path newDir) {
        DiffCommand command = new DiffCommand(budget);
        command.oldDir = oldDir;
        command.newDir = newDir;
        return command;
    }

    @Test
    void escapedCanonicalStringsAreReadAsOneStaticFinding(@TempDir Path temp) throws Exception {
        Path oldDir = writeReport(temp.resolve("old"),
                chain("R-1", "RULE", "CATEGORY", "HIGH", "app/Entry", "read", "()V",
                        "java/lang/Runtime", "exec", "(Ljava/lang/String;)V",
                        "note with, quote \"x\" and unicode \u4e2d")).getParent();
        Path newDir = writeReport(temp.resolve("new"),
                chain("R-2", "RULE", "CATEGORY", "HIGH", "app/Entry", "read", "()V",
                        "java/lang/Runtime", "exec", "(Ljava/lang/String;)V",
                        "note with, quote \"x\" and unicode \u4e2d")).getParent();

        String output = captureDiff(oldDir, newDir);
        assertTrue(output.contains("新增链: 0") && output.contains("消失链: 0")
                        && output.contains("变更链: 0"), output);
    }

    @Test
    void chainIdReorderingIsNotAChange(@TempDir Path temp) throws Exception {
        Path oldDir = writeReport(temp.resolve("old"), ROW_A, ROW_B).getParent();
        String rowAPrime = ROW_A.replace("R-0001", "R-0007");
        String rowBPrime = ROW_B.replace("R-0002", "R-0001");
        Path newDir = writeReport(temp.resolve("new"), rowBPrime, rowAPrime).getParent();

        String output = captureDiff(oldDir, newDir);
        assertTrue(output.contains("新增链: 0") && output.contains("消失链: 0")
                        && output.contains("变更链: 0") && output.contains("不变链: 2"), output);
    }

    @Test
    void semanticChangeIsDetected(@TempDir Path temp) throws Exception {
        Path oldDir = writeReport(temp.resolve("old"), ROW_A).getParent();
        String changed = chain("R-0009", "JUST-SINK-COMMAND-EXEC-RUNTIME", "COMMAND_EXEC",
                "HIGH", "app/Gadget", "readObject", "(Ljava/io/ObjectInputStream;)V",
                "java/lang/Runtime", "exec", "([Ljava/lang/String;)V", "static path changed");
        Path newDir = writeReport(temp.resolve("new"), changed).getParent();

        String output = captureDiff(oldDir, newDir);
        assertTrue(output.contains("变更链: 1") && output.contains("不变链: 0"), output);
    }

    @Test
    void addedAndRemovedChainsAreReported(@TempDir Path temp) throws Exception {
        Path oldDir = writeReport(temp.resolve("old"), ROW_A).getParent();
        Path newDir = writeReport(temp.resolve("new"), ROW_A, ROW_B).getParent();

        String output = captureDiff(oldDir, newDir);
        assertTrue(output.contains("新增链: 1") && output.contains("消失链: 0"), output);
    }

    @Test
    void missingCanonicalReportIsUsageError(@TempDir Path temp) throws Exception {
        Files.createDirectories(temp.resolve("empty"));
        Path valid = writeReport(temp.resolve("valid"), ROW_A).getParent();

        assertEquals(ExitCode.USAGE.code(), diff(temp.resolve("empty"), valid).call());
        assertEquals(ExitCode.USAGE.code(), diff(valid, temp.resolve("empty")).call());
    }

    @Test
    void callerBudgetSpansBothReportsAndDoesNotPublishPartialDiff(@TempDir Path temp)
            throws Exception {
        Path oldDir = writeReport(temp.resolve("old"),
                chain("R-1", "RULE", "CATEGORY", "HIGH", "app/Entry", "read", "()V",
                        "java/lang/Runtime", "exec", "(Ljava/lang/String;)V", "x".repeat(900)))
                .getParent();
        Path newDir = writeReport(temp.resolve("new"),
                chain("R-2", "RULE", "CATEGORY", "HIGH", "app/Entry", "read", "()V",
                        "java/lang/Runtime", "exec", "(Ljava/lang/String;)V", "x".repeat(900)))
                .getParent();
        InputBudget defaults = InputBudget.defaults();
        InputBudget budget = new InputBudget(defaults.schemaVersion(), 1024, 1024, 1024,
                1024, defaults.maxCompressionRatio(), defaults.maxArchiveEntries(),
                defaults.maxArchiveNesting(), defaults.maxClassEntries(),
                defaults.maxRuleInputBytes(), defaults.maxRuleCodePoints(),
                defaults.maxRuleAliases(), defaults.maxRuleNestingDepth(),
                defaults.maxRuleDocuments(), defaults.maxRuleCount(),
                defaults.maxRuleCollectionItems(), defaults.maxRuleNodes(),
                defaults.maxRuleScalarChars(), defaults.maxPathChars(), defaults.maxParseMillis());

        java.io.PrintStream stdout = System.out;
        java.io.ByteArrayOutputStream output = new java.io.ByteArrayOutputStream();
        System.setOut(new java.io.PrintStream(output, true, StandardCharsets.UTF_8));
        try {
            assertEquals(ExitCode.USAGE.code(), diff(budget, oldDir, newDir).call());
        } finally {
            System.setOut(stdout);
        }
        assertEquals("", output.toString(StandardCharsets.UTF_8));
    }

    private static String captureDiff(Path oldDir, Path newDir) throws Exception {
        java.io.PrintStream stdout = System.out;
        java.io.ByteArrayOutputStream output = new java.io.ByteArrayOutputStream();
        System.setOut(new java.io.PrintStream(output, true, StandardCharsets.UTF_8));
        try {
            assertEquals(ExitCode.OK.code(), diff(oldDir, newDir).call());
        } finally {
            System.setOut(stdout);
        }
        return output.toString(StandardCharsets.UTF_8);
    }

    private static String json(String value) {
        StringBuilder result = new StringBuilder("\"");
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            switch (ch) {
                case '"' -> result.append("\\\"");
                case '\\' -> result.append("\\\\");
                case '\n' -> result.append("\\n");
                case '\r' -> result.append("\\r");
                case '\t' -> result.append("\\t");
                default -> result.append(ch);
            }
        }
        return result.append('"').toString();
    }
}
