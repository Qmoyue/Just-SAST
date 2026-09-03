package io.just.sast.report;

import io.just.sast.analysis.hierarchy.ClassHierarchy;
import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.HopKind;
import io.just.sast.config.Match;
import io.just.sast.config.Rule;
import io.just.sast.config.RuleSet;
import io.just.sast.model.ClassInfo;
import io.just.sast.model.MethodInfo;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.lang.reflect.Modifier;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * SARIF 契约：driver.rules 全量声明（result 引用的 ruleId 必须存在——GitHub 渲染依赖）、
 * severity→level 映射、uri 用内部名路径、startLine 来自入口方法首行、
 * confidence 口径与 findings.csv 一致（verify:confirmed → CONFIRMED）、变体折叠不重复。
 */
class SarifReporterTest {

    private static Chain chain(String severity) {
        ChainHop entry = new ChainHop("app/Gadget", "readObject", "app/Gadget", "readObject",
                HopKind.ENTRY, null, "deserialize", "(Ljava/io/ObjectInputStream;)V", null);
        return new Chain("T-RULE", "CODE_EXEC", severity, "app/Gadget", "readObject", "readObject",
                "java/lang/Runtime", "exec", List.of(entry), 0);
    }

    private static ClassHierarchy hierarchyWithLine() {
        MethodInfo readObject = new MethodInfo("app/Gadget", "readObject",
                "(Ljava/io/ObjectInputStream;)V", Modifier.PRIVATE, List.of(), List.of(), true, 42);
        ClassInfo cls = new ClassInfo("app/Gadget", "java/lang/Object", List.of(),
                Modifier.PUBLIC, List.of(readObject), List.of());
        return new ClassHierarchy(Map.of("app/Gadget", cls), null);
    }

    private static RuleSet rules() {
        return new RuleSet(List.of(new Rule.SinkRule("T-RULE", "CODE_EXEC", "HIGH",
                new Rule.CallMatcher(Match.of("java/lang/Runtime"), Match.of("exec"), null),
                List.of(new Rule.TaintedPos.Arg(0)))), List.of(), List.of(), List.of(), List.of());
    }

    @Test
    void emitsRulesLevelRegionAndConfirmedParity(@TempDir Path tmp) throws Exception {
        Path out = tmp.resolve("sarif");
        Files.createDirectories(out);
        new SarifReporter().withHierarchy(hierarchyWithLine()).withRules(rules()).write(
                out, List.of(chain("HIGH")), Map.of(), Map.of());
        String sarif = Files.readString(out.resolve("findings.sarif"));

        // driver.rules 声明 + result ruleId 引用一致
        assertTrue(sarif.contains("\"rules\": [{\"id\": \"T-RULE\""), "rules 数组应声明 T-RULE:\n" + sarif);
        // severity HIGH → error
        assertTrue(sarif.contains("\"level\": \"error\""), sarif);
        // uri 内部名路径（斜杠），非点分
        assertTrue(sarif.contains("\"uri\": \"app/Gadget.class\""), sarif);
        // startLine 来自入口方法首行
        assertTrue(sarif.contains("\"startLine\": 42"), sarif);
        // 指纹存在
        assertTrue(sarif.contains("\"partialFingerprints\""), sarif);
        assertTrue(sarif.contains("\"precision\":{"), sarif);
        assertTrue(sarif.contains("\"construction\":{"), sarif);
        assertTrue(sarif.contains("\"verification_group\":\"not_selected\""), sarif);
        // OASIS 规范 schema
        assertTrue(sarif.contains("docs.oasis-open.org/sarif"), sarif);
    }

    @Test
    void mediumSeverityMapsToWarningAndVariantsFold(@TempDir Path tmp) throws Exception {
        Path out = tmp.resolve("sarif");
        Files.createDirectories(out);
        Chain a = chain("MEDIUM");
        Chain b = chain("MEDIUM"); // 同组变体
        new SarifReporter().withRules(rules()).write(out, List.of(a, b), Map.of(), Map.of());
        String sarif = Files.readString(out.resolve("findings.sarif"));
        assertTrue(sarif.contains("\"level\": \"warning\""), sarif);
        assertTrue(sarif.contains("\"results\": [") && sarif.indexOf("ruleId") == sarif.lastIndexOf("ruleId"),
                "同组变体应折叠为一个 result:\n" + sarif);
        // 无层次接线时不输出 region（不造假日行号）
        assertFalse(sarif.contains("startLine"));
    }

    @Test
    void confirmedNoteYieldsConfidentUpperCase(@TempDir Path tmp) throws Exception {
        Chain c = chain("HIGH");
        Path out = tmp.resolve("sarif2");
        new SarifReporter().withRules(rules()).write(
                out, List.of(c), Map.of(), Map.of(c.key(), List.of("verify:confirmed")));
        String sarif = Files.readString(out.resolve("findings.sarif"));
        assertTrue(sarif.contains("\"confidence\":\"CONFIRMED\""),
                "verify:confirmed 注记应映射 CONFIRMED（与 findings.csv 口径一致）:\n" + sarif);
    }

    @Test
    void usesSharedEvidenceOrderWhenFoldingVariants(@TempDir Path tmp) throws Exception {
        Chain shortest = new Chain("T-RULE", "CODE_EXEC", "HIGH", "app/Gadget", "readObject",
                "readObject", "java/lang/Runtime", "exec", List.of(
                new ChainHop("app/Gadget", "readObject", "java/lang/Runtime", "exec",
                        HopKind.DIRECT_CALL, null, "call", "()V", null),
                new ChainHop("app/Gadget", "readObject", "app/Gadget", "readObject",
                        HopKind.ENTRY, null, "readObject", "(Ljava/io/ObjectInputStream;)V", null)), 0);
        Chain longer = new Chain("T-RULE", "CODE_EXEC", "HIGH", "app/Gadget", "readObject",
                "readObject", "java/lang/Runtime", "exec", List.of(
                new ChainHop("app/Gadget", "readObject", "app/Mid", "run",
                        HopKind.DIRECT_CALL, null, "delegates", "()V", null),
                new ChainHop("app/Mid", "run", "java/lang/Runtime", "exec",
                        HopKind.DIRECT_CALL, null, "call", "()V", null),
                new ChainHop("app/Gadget", "readObject", "app/Gadget", "readObject",
                        HopKind.ENTRY, null, "readObject", "(Ljava/io/ObjectInputStream;)V", null)), 0);

        Path out = tmp.resolve("sarif-order");
        new SarifReporter().withRules(rules()).write(out, List.of(shortest, longer), Map.of(), Map.of());
        String sarif = Files.readString(out.resolve("findings.sarif"));
        assertTrue(sarif.contains("\"chain_length\":3")
                        && !sarif.contains("\"chain_length\":2"),
                "SARIF must choose the same strongest variant as the shared evidence tuple:\n"
                        + sarif);
    }
}
