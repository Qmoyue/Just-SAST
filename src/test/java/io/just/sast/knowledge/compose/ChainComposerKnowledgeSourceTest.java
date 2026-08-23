package io.just.sast.knowledge.compose;

import io.just.sast.blackboard.Blackboard;
import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.Event;
import io.just.sast.blackboard.EventType;
import io.just.sast.blackboard.HopKind;
import io.just.sast.config.RuleSet;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertTrue;

/** 链组装契约：DESER 桥（前段 sink 为二次反序列化 → 后段机制入口）。 */
class ChainComposerKnowledgeSourceTest {

    private static Chain chain(String ruleId, String category, String entryClass, String entryKind,
                               String sinkClass, String sinkMethod) {
        ChainHop hop = new ChainHop(entryClass, "e", entryClass, "e", HopKind.ENTRY, null, entryKind, "", null);
        return new Chain(ruleId, category, "HIGH", entryClass, "e", entryKind,
                sinkClass, sinkMethod, List.of(hop), 0);
    }

    @Test
    void deserializeSinkFrontBridgesToMechanismEntryBack() {
        // 前段：SignedObject.getObject 类二次反序列化 sink；后段：readObject 机制入口链
        Chain front = chain("T-DESER", "DESERIALIZE", "java/security/SignedObject", "readObject",
                "java/security/SignedObject", "getObject");
        Chain back = chain("T-SINK", "CODE_EXEC", "app/Gadget", "readObject",
                "java/lang/Runtime", "exec");
        Blackboard bb = new Blackboard(new io.just.sast.cpg.graph.Graph(),
                new io.just.sast.analysis.hierarchy.ClassHierarchy(Map.of(), null),
                new io.just.sast.cpg.build.FieldWriterIndex(), RuleSet.EMPTY, 20);
        bb.addChain(front);
        bb.addChain(back);
        new ChainComposerKnowledgeSource().onEvent(bb, Event.of(EventType.SCAN_ANALYZED, -1, null));
        boolean composed = bb.chains().stream().anyMatch(c ->
                c.entryClass().equals("java/security/SignedObject")
                        && c.sinkClass().equals("java/lang/Runtime")
                        && c.hops().stream().anyMatch(h -> "bridge-deser".equals(h.reason())));
        assertTrue(composed, "DESER 桥应组装 SignedObject 前段与 readObject 后段，实际链："
                + bb.chains().stream().map(Chain::key).toList());
    }
}
