package io.just.sast.config;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 规则装载契约：默认规则文件可装载、四类齐全、access/safe-config 字段解析、坏规则报错。 */
class YamlRuleLoaderTest {

    @Test
    void defaultRulesLoadWithAllKinds() throws IOException {
        Path rules = Path.of("src/main/resources/rules/default-rules.yaml");
        RuleSet set = new YamlRuleLoader().load(Files.newInputStream(rules));
        // 规则文件是可扩展数据；只锁定能力下限，不把新增通用规则误判为回归。
        assertTrue(set.sinks().size() >= 94, "sink 规则能力退化：实际 " + set.sinks().size());
        assertTrue(set.sources().size() >= 42, "source 规则能力退化：实际 " + set.sources().size());
        assertTrue(set.models().size() >= 21, "model 规则能力退化：实际 " + set.models().size());
        assertTrue(set.magicEntries().size() >= 14, "magic-entry 含序列化侧入口，实际 " + set.magicEntries().size());
        // id 唯一
        long ids = java.util.stream.Stream.of(set.sinks(), set.magicEntries(), set.sources(), set.models())
                .flatMap(List::stream).map(Rule::id).distinct().count();
        assertEquals(ids, set.sinks().size() + set.magicEntries().size() + set.sources().size() + set.models().size(),
                "规则 id 不得重复");
    }

    @Test
    void privateAccessAndSafeConfigParsed() throws IOException {
        String yaml = """
                rules:
                  - id: T-ENTRY
                    kind: magic-entry
                    entryKind: readObject
                    match:
                      method: { name: "readObject", descriptor: "(Ljava/io/ObjectInputStream;)V", access: private }
                      class: { implements: "java/io/Serializable" }
                  - id: T-SOURCE
                    kind: source
                    bridge: deserialize
                    match:
                      call: { owner: "a/B", name: "load" }
                    safe-config: { owner: "a/B", methods: [lock, seal] }
                """;
        RuleSet set = new YamlRuleLoader().load(new ByteArrayInputStream(yaml.getBytes(StandardCharsets.UTF_8)));
        Rule.MagicEntryRule entry = set.magicEntries().get(0);
        assertTrue(entry.method().privateOnly(), "access: private 应解析到 privateOnly");
        Rule.SourceRule source = set.sources().get(0);
        assertNotNull(source.safeConfig());
        assertEquals(java.util.Set.of("lock", "seal"), source.safeConfig().methods());
    }

    @Test
    void malformedRulesFailLoudly() {
        String bad = "rules:\n  - id: X\n    kind: sink\n    match: {}\n"; // 缺 match.call
        assertThrows(IOException.class, () ->
                new YamlRuleLoader().load(new ByteArrayInputStream(bad.getBytes(StandardCharsets.UTF_8))));
    }

    @Test
    void strictnessRejectsUnknownKindDuplicateIdAndMissingMatch() throws IOException {
        // 未知 kind 报错（静默跳过会掩盖拼写错误）
        Exception e = assertThrows(IOException.class, () ->
                new YamlRuleLoader().load(new ByteArrayInputStream(("""
                        rules:
                          - id: X
                            kind: sinc
                            match: { call: { owner: a/B } }
                        """).getBytes(StandardCharsets.UTF_8))));
        assertTrue(e.getMessage().contains("未知规则 kind"), e.getMessage());
        // 重复 id 报错（互相遮蔽）
        e = assertThrows(IOException.class, () ->
                new YamlRuleLoader().load(new ByteArrayInputStream(("""
                        rules:
                          - id: X
                            kind: sink
                            category: C
                            severity: HIGH
                            match: { call: { owner: a/B, name: m } }
                            tainted: [{arg: 0}]
                          - id: X
                            kind: sink
                            category: C
                            severity: HIGH
                            match: { call: { owner: a/C, name: m } }
                            tainted: [{arg: 0}]
                        """).getBytes(StandardCharsets.UTF_8))));
        assertTrue(e.getMessage().contains("重复"), e.getMessage());
        // match 缺失报错（历史 NPE）
        e = assertThrows(IOException.class, () ->
                new YamlRuleLoader().load(new ByteArrayInputStream("""
                        rules:
                          - id: X
                            kind: sink
                            category: C
                            severity: HIGH
                            tainted: [{arg: 0}]
                        """.getBytes(StandardCharsets.UTF_8))));
        assertTrue(e.getMessage().contains("缺少 match"), e.getMessage());
    }

    @Test
    void malformedNestedRuleFieldsFailWithRuleContext() {
        String badMatch = """
                rules:
                  - id: X
                    kind: sink
                    category: C
                    severity: HIGH
                    match: []
                    tainted: [{arg: 0}]
                """;
        Exception e = assertThrows(IOException.class, () -> new YamlRuleLoader().load(
                new ByteArrayInputStream(badMatch.getBytes(StandardCharsets.UTF_8))));
        assertTrue(e.getMessage().contains("X"), e.getMessage());

        String badTainted = """
                rules:
                  - id: X
                    kind: sink
                    category: C
                    severity: HIGH
                    match: { call: { owner: a/B, name: m } }
                    tainted: [{arg: -1}]
                """;
        e = assertThrows(IOException.class, () -> new YamlRuleLoader().load(
                new ByteArrayInputStream(badTainted.getBytes(StandardCharsets.UTF_8))));
        assertTrue(e.getMessage().contains("X"), e.getMessage());

        String badFragment = """
                rules:
                  - id: F
                    kind: chain-fragment
                    entryClass: a/Entry
                    sinkOwner: a/Sink
                    sinkName: run
                    hops: [{class: a/Hop}]
                """;
        e = assertThrows(IOException.class, () -> new YamlRuleLoader().load(
                new ByteArrayInputStream(badFragment.getBytes(StandardCharsets.UTF_8))));
        assertTrue(e.getMessage().contains("method"), e.getMessage());

        String badBridge = """
                rules:
                  - id: S
                    kind: source
                    bridge: deserialzie
                    match: {call: {owner: a/B, name: load}}
                """;
        e = assertThrows(IOException.class, () -> new YamlRuleLoader().load(
                new ByteArrayInputStream(badBridge.getBytes(StandardCharsets.UTF_8))));
        assertTrue(e.getMessage().contains("bridge"), e.getMessage());

        String badModel = """
                rules:
                  - id: M
                    kind: model
                    match: {call: {owner: a/B, name: load}}
                    actions: {return: [argX]}
                """;
        e = assertThrows(IOException.class, () -> new YamlRuleLoader().load(
                new ByteArrayInputStream(badModel.getBytes(StandardCharsets.UTF_8))));
        assertTrue(e.getMessage().contains("argN"), e.getMessage());
    }
}
