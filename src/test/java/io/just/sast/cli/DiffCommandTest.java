package io.just.sast.cli;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * diff 子命令契约：RFC 4180 解析（带引号字段可含逗号）、链身份键与 chain_id 序号无关、
 * 语义字段变更可检出、缺失 findings.csv 是用法错误（退出码 2）。
 */
class DiffCommandTest {

    private static final String HEADER = "chain_id,rule_id,category,severity,confidence,confidence_score,quality,"
            + "entry_class,entry_method,entry_descriptor,entry_kind,sink_class,sink_method,sink_kind,sink_descriptor,"
            + "chain_length,unresolved_hops,variant_count,patterns,path,evidence,verify";

    /** 一行真实形态的 findings 数据：path/evidence 含逗号与引号（RFC 4180 转义）。 */
    private static final String ROW_A = "R-0001,JUST-SINK-COMMAND-EXEC-RUNTIME,COMMAND_EXEC,HIGH,"
            + "FEASIBLE,8,COMPLETE,app/Gadget,readObject,(Ljava/io/ObjectInputStream;)V,readObject,"
            + "java/lang/Runtime,exec,COMMAND_EXEC,([Ljava/lang/String;)V,2,0,1,,"
            + "\"app/Gadget.readObject -> java/lang/Runtime.exec\",\"direct=2+2, entry:readObject+2\","
            + "\"CONFIRMED;vars:rule=JUST-SINK-COMMAND-EXEC-RUNTIME;flow:fields=[cmd]\"";
    private static final String ROW_B = "R-0002,JUST-SINK-JNDI,JNDI,HIGH,"
            + "FEASIBLE,6,COMPLETE,app/Lookup,readObject,(Ljava/io/ObjectInputStream;)V,readObject,"
            + "javax/naming/Context,lookup,JNDI,(Ljava/lang/String;)Ljava/lang/Object;,3,0,1,,"
            + "\"app/Lookup.readObject -> javax/naming/Context.lookup\",\"entry:readObject+2\","
            + "\"vars:rule=JUST-SINK-JNDI;flow:fields=[]\"";

    private static Path writeFindings(Path dir, String... rows) throws Exception {
        Files.createDirectories(dir);
        StringBuilder csv = new StringBuilder(HEADER).append("\r\n");
        for (String row : rows) {
            csv.append(row).append("\r\n");
        }
        Path file = dir.resolve("findings.csv");
        Files.write(file, csv.toString().getBytes(StandardCharsets.UTF_8));
        return file;
    }

    private static DiffCommand diff(Path oldDir, Path newDir) {
        DiffCommand cmd = new DiffCommand();
        cmd.oldDir = oldDir;
        cmd.newDir = newDir;
        return cmd;
    }

    @Test
    void quotedCsvLineParsesCommasAndEscapedQuotes() {
        List<String> fields = DiffCommand.parseCsvLine(HEADER);
        assertEquals("chain_id", fields.get(0));
        assertEquals("verify", fields.get(fields.size() - 1));

        List<String> row = DiffCommand.parseCsvLine("a,\"b,c\",\"say \"\"hi\"\"\",plain");
        assertEquals(List.of("a", "b,c", "say \"hi\"", "plain"), row);
        // 行内引号字段里包含 RFC 4180 逐字节转义的 findings 行必须完整还原 21 列
        assertEquals(22, DiffCommand.parseCsvLine(ROW_A).size(),
                "带引号/逗号的行按 RFC 4180 解析后列数应与表头一致");
        assertEquals(DiffCommand.parseCsvLine(HEADER).size(), DiffCommand.parseCsvLine(ROW_A).size());
    }

    @Test
    void chainIdReorderingIsNotAChange(@TempDir Path tmp) throws Exception {
        // 两次扫描发现同一批链，仅组序号（chain_id 后缀）因排序变化——diff 应报告零差异
        Path oldDir = writeFindings(tmp.resolve("old"), ROW_A, ROW_B).getParent();
        String rowAPrime = ROW_A.replace("R-0001", "R-0007");
        String rowBPrime = ROW_B.replace("R-0002", "R-0001");
        Path newDir = writeFindings(tmp.resolve("new"), rowBPrime, rowAPrime).getParent();

        Integer code = diff(oldDir, newDir).call();
        assertEquals(ExitCode.OK.code(), code);
        String out = captureDiff(oldDir, newDir);
        assertTrue(out.contains("新增链: 0") && out.contains("消失链: 0") && out.contains("变更链: 0"),
                "chain_id 序号重排不应产生差异:\n" + out);
        assertTrue(out.contains("不变链: 2"), out);
    }

    @Test
    void semanticChangeIsDetected(@TempDir Path tmp) throws Exception {
        Path oldDir = writeFindings(tmp.resolve("old"), ROW_A).getParent();
        String rowAChanged = ROW_A.replace("FEASIBLE,8", "DEGRADED(verify-failed),6");
        Path newDir = writeFindings(tmp.resolve("new"), rowAChanged).getParent();

        String out = captureDiff(oldDir, newDir);
        assertTrue(out.contains("变更链: 1"), "confidence/score 变化应被检出:\n" + out);
        assertTrue(out.contains("不变链: 0"), out);
    }

    @Test
    void addedAndRemovedChainsAreReported(@TempDir Path tmp) throws Exception {
        Path oldDir = writeFindings(tmp.resolve("old"), ROW_A).getParent();
        Path newDir = writeFindings(tmp.resolve("new"), ROW_A, ROW_B).getParent();

        String out = captureDiff(oldDir, newDir);
        assertTrue(out.contains("新增链: 1"), out);
        assertTrue(out.contains("消失链: 0"), out);
    }

    @Test
    void missingFindingsCsvIsUsageError(@TempDir Path tmp) throws Exception {
        Files.createDirectories(tmp.resolve("empty"));
        Path valid = writeFindings(tmp.resolve("valid"), ROW_A).getParent();

        assertEquals(ExitCode.USAGE.code(), diff(tmp.resolve("empty"), valid).call(),
                "目录缺 findings.csv 应报用法错误");
        assertEquals(ExitCode.USAGE.code(), diff(valid, tmp.resolve("empty")).call());
    }

    /** 捕获 diff 的 stdout（结果表是用户可见产物）。 */
    private static String captureDiff(Path oldDir, Path newDir) throws Exception {
        java.io.PrintStream stdout = System.out;
        java.io.ByteArrayOutputStream buf = new java.io.ByteArrayOutputStream();
        System.setOut(new java.io.PrintStream(buf, true, StandardCharsets.UTF_8));
        try {
            Integer code = diff(oldDir, newDir).call();
            assertEquals(ExitCode.OK.code(), code);
        } finally {
            System.setOut(stdout);
        }
        return buf.toString(StandardCharsets.UTF_8);
    }
}
