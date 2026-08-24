package io.just.sast.knowledge.calibrate;

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

import static org.junit.jupiter.api.Assertions.assertEquals;

/** 模式识别契约：集合包含判定（同类重复出现不算覆盖两个必需类——历史重复计数 bug 的回归）。 */
class GadgetPatternKnowledgeSourceTest {

    private static Chain chainOver(String... pathOwners) {
        List<ChainHop> hops = new java.util.ArrayList<>();
        String prev = pathOwners[0];
        for (int i = 1; i < pathOwners.length; i++) {
            hops.add(new ChainHop(prev, "m", pathOwners[i], "n", HopKind.DIRECT_CALL, null, "call", "()V", null));
            prev = pathOwners[i];
        }
        hops.add(new ChainHop(pathOwners[0], "e", pathOwners[0], "e", HopKind.ENTRY, null, "readObject", "", null));
        return new Chain("R", "CAT", "HIGH", pathOwners[0], "readObject", "readObject",
                "S", "sink", hops, 0);
    }

    private static Blackboard run(Chain chain) {
        Blackboard bb = new Blackboard(new io.just.sast.cpg.graph.Graph(),
                new io.just.sast.analysis.hierarchy.ClassHierarchy(Map.of(), null),
                new io.just.sast.cpg.build.FieldWriterIndex(), RuleSet.EMPTY, 20,
                Blackboard.ScanInputs.fastDefault(java.nio.file.Path.of(".")));
        bb.addChain(chain);
        new GadgetPatternKnowledgeSource().onEvent(bb, Event.of(EventType.SCAN_COMPLETE, -1, null));
        return bb;
    }

    @Test
    void cc6RequiresBothTiedMapEntryAndLazyMap() {
        Blackboard bb = run(chainOver(
                "org/apache/commons/collections/keyvalue/TiedMapEntry",
                "org/apache/commons/collections/map/LazyMap",
                "sinkOwner"));
        assertEquals(List.of("pattern:CC6"), bb.chainNotesOf(bb.chains().get(0).key()));
    }

    @Test
    void repeatedSingleClassDoesNotSatisfyTwoClassPattern() {
        // TiedMapEntry 出现两次、无 LazyMap：不得误标 CC6（历史 sum>=size 重复计数 bug）
        Blackboard bb = run(chainOver(
                "org/apache/commons/collections/keyvalue/TiedMapEntry",
                "org/apache/commons/collections/keyvalue/TiedMapEntry$Other",
                "sinkOwner"));
        assertEquals(List.of(), bb.chainNotesOf(bb.chains().get(0).key()),
                "同一必需类重复出现不得凑满双类模式");
    }

    @Test
    void prefixMatchCoversInnerClasses() {
        // 路径类是必需类前缀（含内部类）即视为覆盖
        Blackboard bb = run(chainOver(
                "x/Entry", "org/apache/commons/collections/map/LazyMap$Factory",
                "sinkOwner"));
        // 第一个 hop from=x/Entry 不匹配 TiedMapEntry → CC6 不成立
        assertEquals(List.of(), bb.chainNotesOf(bb.chains().get(0).key()));
    }
}
