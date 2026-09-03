package io.just.sast.report;

import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.HopKind;
import io.just.sast.blackboard.SinkOutcome;
import io.just.sast.blackboard.VerificationSummary;
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
                new ChainHop("app/Sink", "run", "java/lang/Runtime", "exec", HopKind.DIRECT_CALL, null, "call", "()V", null),
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
        assertTrue(findings.contains("construction_status,construction_type,construction_fields")
                && findings.contains("verification_status,sink_distorted,sandbox_ready"));
        assertTrue(findings.contains("verification_scope,verification_group,sink_risk"));
        assertTrue(findings.contains("app/Gadget,readObject"), "保留链在 findings");
        assertFalse(findings.contains("app/Gadget,equals"), "被拒链不进 findings");
        assertTrue(findings.contains("CC6"), "patterns 列含模式名");
        assertTrue(findings.contains("entry:readObject+2"), "evidence 因子分解");
        String calibrations = Files.readString(tmp.resolve("calibrations.csv"));
        assertTrue(calibrations.startsWith("\uFEFFvariant_id,rule_id,category"), "拒绝表使用紧凑稳定 schema");
        assertTrue(calibrations.contains("path_digest,reject_reason")
                && calibrations.contains("app/Gadget,equals")
                && calibrations.contains("no-trigger"), "拒绝理由和入口摘要落盘可审计");
        String variants = Files.readString(tmp.resolve("chains.csv"));
        assertTrue(variants.contains("calibration_status,calibration_reason")
                && variants.contains("REJECTED"), "所有路径变体必须可通过状态回溯");
        String sinks = Files.readString(tmp.resolve("sinks.csv"));
        assertTrue(sinks.contains("NO_PATH"));
        String edges = Files.readString(tmp.resolve("edges.csv"));
        assertTrue(edges.contains("app/Sink,run"));
        assertTrue(findings.contains("java/lang/Runtime,exec,DIRECT_CALL,"),
                "sink_kind 必须记录调用边类型，不能复用 category");
    }

    @Test
    void structuredVerificationStateIsPreferredOverNoteOrder(@TempDir Path tmp) throws Exception {
        Chain kept = chain("readObject", "readObject");
        VerificationSummary summary = new VerificationSummary(
                "WINDOWS_JOB_OBJECT", 1, 1, 0, 1,
                Map.of("SINK_BLOCKED", 1), Map.of(),
                List.of(new VerificationSummary.ChainResult(
                        1, kept.key(), "SINK_BLOCKED", "SINK_CANARY", "HIGH", 22,
                        1, 5, "SINK_CANARY_BOUNDARY", "WINDOWS_JOB_OBJECT", "17.0.19",
                        "policy-1", true, true, "CLEANED")));
        new CsvReporter().write(ReportLayout.flat(tmp), List.of(kept), Map.of(), Map.of(),
                Map.of(kept.key(), List.of("verify:old-note")), summary);
        String findings = Files.readString(tmp.resolve("findings.csv"));
        assertTrue(findings.contains("status=SINK_BLOCKED"));
        assertTrue(findings.contains("backend=WINDOWS_JOB_OBJECT"));
        assertTrue(findings.contains("verification_group=boundary_only"));
        assertFalse(findings.contains("status=OLD-NOTE"));
    }

    @Test
    void groupedFindingRetainsConfirmedNonRepresentativeVariant(@TempDir Path tmp) throws Exception {
        Chain shortest = chain("readObject", "readObject");
        Chain longer = new Chain("T-RULE", "CODE_EXEC", "HIGH", "app/Gadget", "readObject",
                "readObject", "java/lang/Runtime", "exec", List.of(
                new ChainHop("app/Sink", "run", "java/lang/Runtime", "exec",
                        HopKind.DIRECT_CALL, null, "call", "()V", null),
                new ChainHop("app/Gadget", "readObject", "app/Sink", "run",
                        HopKind.DIRECT_CALL, null, "delegates", "()V", null),
                new ChainHop("app/Gadget", "readObject", "app/Gadget", "readObject",
                        HopKind.ENTRY, null, "readObject", "", null)), 0);
        VerificationSummary summary = new VerificationSummary(
                "WINDOWS_JOB_OBJECT", 2, 2, 0, 2,
                Map.of("SINK_BLOCKED", 1, "PARTIAL", 1), Map.of(),
                List.of(new VerificationSummary.ChainResult(2, longer.key(), "SINK_BLOCKED",
                        "canary", "HIGH", 22, 1, 5, "SINK_CANARY_BOUNDARY",
                        "WINDOWS_JOB_OBJECT", "17.0.19", "policy-1", true, true, "CLEANED"),
                        new VerificationSummary.ChainResult(1, shortest.key(), "PARTIAL",
                                "construction", "HIGH", 18, 1, 5, "PARTIAL",
                                "WINDOWS_JOB_OBJECT", "17.0.19", "policy-1", true, true, "CLEANED")));
        new CsvReporter().write(ReportLayout.flat(tmp), List.of(shortest, longer), Map.of(), Map.of(),
                Map.of(), summary);
        String findings = Files.readString(tmp.resolve("findings.csv"));
        assertTrue(findings.contains("status=SINK_BLOCKED"),
                "分组代表链未被动态确认的变体不应覆盖已确认变体");
        assertTrue(findings.contains("rank=2"), findings);
        assertTrue(findings.contains("app/Gadget.readObject -> app/Sink.run -> java/lang/Runtime.exec"),
                "代表路径必须与被选作最强证据的动态变体一致");
    }
}
