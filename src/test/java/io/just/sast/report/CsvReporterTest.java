package io.just.sast.report;

import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.HopKind;
import io.just.sast.blackboard.SinkOutcome;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** CSV 报告契约：四表 schema、被拒链不进 findings 进 calibrations、patterns/evidence 列。 */
class CsvReporterTest {

    private static Chain chain(String entryMethod, String entryKind) {
        List<ChainHop> hops = List.of(
                new ChainHop("app/Sink", "run", "app/Sink", "run", HopKind.DIRECT_CALL, null, "call", "()V", null),
                new ChainHop(entryMethod, entryKind, entryMethod, entryKind, HopKind.ENTRY, null, entryKind, "", null));
        return new Chain("T-RULE", "CODE_EXEC", "HIGH", "app/Gadget", entryMethod, entryKind,
                "java/lang/Runtime", "exec", hops, 0);
    }

    @Test
    void writesFourTablesWithContractedHeaders(@TempDir Path tmp) throws Exception {
        Chain kept = chain("readObject", "readObject");
        Chain rejected = chain("equals", "equals");
        new CsvReporter().write(tmp, List.of(kept, rejected),
                Map.of(1L, new SinkOutcome("T-RULE", "CODE_EXEC", "java/lang/Runtime", "exec",
                        "app/Sink", "run", 0, "NO_PATH", 10, 0, 0)),
                Map.of(rejected.key(), "no-trigger"),
                Map.of(kept.key(), List.of("pattern:CC6")));
        String findings = Files.readString(tmp.resolve("findings.csv"));
        assertTrue(findings.startsWith("\uFEFFchain_id,rule_id"), "BOM + 表头契约");
        assertTrue(findings.contains("app/Gadget,readObject"), "保留链在 findings");
        assertFalse(findings.contains("app/Gadget,equals"), "被拒链不进 findings");
        assertTrue(findings.contains("CC6"), "patterns 列含模式名");
        assertTrue(findings.contains("entry:readObject+2"), "evidence 因子分解");
        String calibrations = Files.readString(tmp.resolve("calibrations.csv"));
        assertTrue(calibrations.contains("no-trigger"), "拒绝理由落盘可审计");
        String sinks = Files.readString(tmp.resolve("sinks.csv"));
        assertTrue(sinks.contains("NO_PATH"));
        String edges = Files.readString(tmp.resolve("edges.csv"));
        assertTrue(edges.contains("app/Sink,run"));
    }
}
