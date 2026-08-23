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
        assertTrue(set.sinks().size() >= 40, "sink 规则应 ≥40，实际 " + set.sinks().size());
        assertTrue(set.magicEntries().size() >= 14, "magic-entry 含序列化侧入口，实际 " + set.magicEntries().size());
        assertTrue(set.sources().size() >= 28, "source 规则含 marshalsec 扩充，实际 " + set.sources().size());
        assertEquals(10, set.models().size(), "model 规则 10 条");
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
}
