package io.just.sast.knowledge.calibrate;

import io.just.sast.blackboard.Blackboard;
import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.Event;
import io.just.sast.blackboard.EventType;
import io.just.sast.blackboard.HopKind;
import io.just.sast.config.Match;
import io.just.sast.config.Rule;
import io.just.sast.config.RuleSet;
import io.just.sast.cpg.graph.Graph;
import io.just.sast.cpg.graph.NodeType;
import io.just.sast.model.ClassInfo;
import io.just.sast.model.InsnFact;
import io.just.sast.model.MethodInfo;
import io.just.sast.model.MethodRef;
import io.just.sast.model.Op;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Modifier;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * SafeConfig 契约（两个历史 bug 的回归）：
 * 1. 键口径一致——入口 owner#name（无描述符）能命中抑制集合（历史键错位永不抑制 bug）
 * 2. 偏移序——安全配置须早于框架入口调用（先反序列化后配置不抑制）
 */
class SafeConfigKnowledgeSourceTest {

    private static MethodInfo invokeSeq(String owner, String method, String... callSeq) {
        List<InsnFact> insns = new java.util.ArrayList<>();
        int offset = 0;
        for (String call : callSeq) {
            String[] parts = call.split(":");
            insns.add(new InsnFact(offset, Op.INVOKEVIRTUAL, List.of(new MethodRef("fake/Fw", parts[0], "()V"))));
            offset += 2;
        }
        return new MethodInfo(owner, method, "()V", Modifier.PUBLIC, List.copyOf(insns), List.of(), false);
    }

    private static Blackboard blackboardWith(MethodInfo... methods) {
        Graph graph = new Graph();
        java.util.Map<String, ClassInfo> classes = new java.util.HashMap<>();
        for (MethodInfo m : methods) {
            graph.methodNode(m.owner(), m.name(), m.descriptor(), false);
            classes.computeIfAbsent(m.owner(), k -> new ClassInfo(k, "java/lang/Object",
                    List.of(), Modifier.PUBLIC, new java.util.ArrayList<>(), List.of())).methods().add(m);
        }
        Rule.SourceRule source = new Rule.SourceRule("T-SOURCE", "deserialize",
                new Rule.CallMatcher(Match.of("fake/Fw"), Match.of("load"), null),
                new Rule.SafeConfigDecl(Match.of("fake/Fw"), Set.of("lock")));
        return new Blackboard(graph,
                new io.just.sast.analysis.hierarchy.ClassHierarchy(classes, null),
                new io.just.sast.cpg.build.FieldWriterIndex(),
                new RuleSet(List.of(), List.of(), List.of(source), List.of(), List.of()), 20);
    }

    private static Chain chainWithEntry(String owner, String method) {
        ChainHop hop = new ChainHop(owner, method, owner, method, HopKind.ENTRY, null, "deserialize", "", null);
        return new Chain("T-SOURCE", "DESERIALIZE", "HIGH", owner, method, "deserialize",
                "fake/Fw", "load", List.of(hop), 0);
    }

    @Test
    void configBeforeEntrySuppresses() {
        Blackboard bb = blackboardWith(invokeSeq("fake/App", "run", "lock", "load"));
        Chain chain = chainWithEntry("fake/App", "run");
        bb.addChain(chain);
        SafeConfigKnowledgeSource ks = new SafeConfigKnowledgeSource();
        ks.init(bb);
        ks.onEvent(bb, Event.of(EventType.SCAN_COMPLETE, -1, null));
        assertEquals("safe-config", bb.calibrationOf(chain.key()), "先 lock 后 load 的入口链应被抑制");
    }

    @Test
    void entryBeforeConfigIsNotSuppressed() {
        Blackboard bb = blackboardWith(invokeSeq("fake/App2", "run", "load", "lock"));
        Chain chain = chainWithEntry("fake/App2", "run");
        bb.addChain(chain);
        SafeConfigKnowledgeSource ks = new SafeConfigKnowledgeSource();
        ks.init(bb);
        ks.onEvent(bb, Event.of(EventType.SCAN_COMPLETE, -1, null));
        assertNull(bb.calibrationOf(chain.key()), "先 load 后 lock（配置晚于入口）不抑制");
    }
}
