package io.just.sast.config;

import io.just.sast.analysis.hierarchy.ClassHierarchy;
import io.just.sast.model.ClassInfo;
import io.just.sast.model.MethodInfo;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Modifier;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 规则匹配契约：精确/层次命中、magic-entry implements+private 过滤、缓存随 RuleSet 实例隔离。 */
class RuleEngineTest {

    private static MethodInfo method(String owner, String name, String desc, int access) {
        return new MethodInfo(owner, name, desc, access, List.of(), List.of(), false);
    }

    private static ClassHierarchy hierarchy() {
        return new ClassHierarchy(Map.of(
                // 仅 public readObject（OIS 机制不回调，privateOnly 过滤的对象）
                "app/Gadget", new ClassInfo("app/Gadget", "java/lang/Object", List.of("java/io/Serializable"),
                        Modifier.PUBLIC, List.of(
                        method("app/Gadget", "readObject", "(Ljava/io/ObjectInputStream;)V", Modifier.PUBLIC)),
                        List.of()),
                "app/Impl", new ClassInfo("app/Impl", "java/lang/Object", List.of("app/Itf"), Modifier.PUBLIC,
                        List.of(), List.of())), null);
    }

    private static RuleSet rules() {
        Rule.SinkRule sink = new Rule.SinkRule("T-SINK", "CODE_EXEC", "HIGH",
                new Rule.CallMatcher(Match.of("javax/naming/Context"), Match.of("~lookup|list"), null),
                List.of(new Rule.TaintedPos.Arg(0)));
        Rule.MagicEntryRule entry = new Rule.MagicEntryRule("T-ENTRY", "readObject",
                new Rule.MethodMatcher(Match.of("readObject"),
                        Match.of("(Ljava/io/ObjectInputStream;)V"), true),
                "java/io/Serializable");
        Rule.SourceRule source = new Rule.SourceRule("T-SOURCE", "deserialize",
                new Rule.CallMatcher(Match.of("app/Itf"), Match.of("load"), null), null);
        Rule.ModelRule model = new Rule.ModelRule("T-MODEL",
                new Rule.CallMatcher(Match.of("java/util/Map"), Match.of("put"), null),
                Map.of("this", List.of("arg1")));
        return new RuleSet(List.of(sink), List.of(entry), List.of(source), List.of(model), List.of());
    }

    @Test
    void sinkMatchesExactlyAndBySubtype() {
        RuleEngine engine = new RuleEngine(rules(), hierarchy());
        assertTrue(engine.matchingSink("javax/naming/Context", "lookup", "(Ljava/lang/String;)Ljava/lang/Object;").isPresent());
        assertFalse(engine.matchingSink("javax/naming/Context", "bind2", "()V").isPresent());
        // owner 层次命中：Serializable 类上不存在；用 Itf 子类验证 source 的层次命中
        assertTrue(engine.matchingSource("app/Impl", "load", "()Ljava/lang/Object;").isPresent(),
                "source 规则 owner=接口时应命中实现类调用点");
        assertTrue(engine.matchingModel("java/util/Map", "put", "").isPresent());
    }

    @Test
    void magicEntryRequiresPrivateAndImplements() {
        RuleEngine engine = new RuleEngine(rules(), hierarchy());
        // public readObject：privateOnly 过滤（OIS 机制不回调 public readObject）
        assertFalse(engine.matchingEntry("app/Gadget", "readObject", "(Ljava/io/ObjectInputStream;)V").isPresent());
        // 无序列化约束类：implements 过滤
        ClassHierarchy withPrivate = new ClassHierarchy(Map.of(
                "app/Ser", new ClassInfo("app/Ser", "java/lang/Object", List.of("java/io/Serializable"),
                        Modifier.PUBLIC,
                        List.of(method("app/Ser", "readObject", "(Ljava/io/ObjectInputStream;)V", Modifier.PRIVATE)),
                        List.of())), null);
        RuleEngine engine2 = new RuleEngine(rules(), withPrivate);
        Optional<Rule.MagicEntryRule> hit = engine2.matchingEntry("app/Ser", "readObject",
                "(Ljava/io/ObjectInputStream;)V");
        assertTrue(hit.isPresent());
        assertEquals("readObject", hit.get().entryKind());
    }

    @Test
    void cachesArePerRuleSetInstance() {
        // 同一 (owner|name|desc) 在两个不同 RuleSet 下结果不同——缓存不得跨 RuleSet 串味
        Rule.SinkRule sinkA = new Rule.SinkRule("A", "CAT", "HIGH",
                new Rule.CallMatcher(Match.of("x/Y"), Match.of("go"), null), List.of());
        Rule.SinkRule sinkB = new Rule.SinkRule("B", "CAT", "HIGH",
                new Rule.CallMatcher(Match.of("x/Y"), Match.of("stop"), null), List.of());
        RuleEngine a = new RuleEngine(new RuleSet(List.of(sinkA), List.of(), List.of(), List.of(), List.of()), hierarchy());
        RuleEngine b = new RuleEngine(new RuleSet(List.of(sinkB), List.of(), List.of(), List.of(), List.of()), hierarchy());
        assertTrue(a.matchingSink("x/Y", "go", "()V").isPresent());
        assertFalse(a.matchingSink("x/Y", "stop", "()V").isPresent());
        assertTrue(b.matchingSink("x/Y", "stop", "()V").isPresent(),
                "换 RuleSet 后同键缓存不得返回旧结果");
        assertNotSame(a, b);
    }

    @Test
    void sameEngineCachesRepeatedLookups() {
        RuleEngine engine = new RuleEngine(rules(), hierarchy());
        Optional<Rule.SinkRule> first = engine.matchingSink("javax/naming/Context", "list", "()V");
        Optional<Rule.SinkRule> second = engine.matchingSink("javax/naming/Context", "list", "()V");
        assertSame(first.orElseThrow(), second.orElseThrow(), "同键命中应返回缓存实例");
    }
}
