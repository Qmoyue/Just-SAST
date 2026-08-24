package io.just.sast.blackboard;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 黑板契约：链按 key 去重、校准记录、链级注释归属。 */
class BlackboardTest {

    private static Blackboard empty() {
        return new Blackboard(new io.just.sast.cpg.graph.Graph(),
                new io.just.sast.analysis.hierarchy.ClassHierarchy(Map.of(), null),
                new io.just.sast.cpg.build.FieldWriterIndex(), io.just.sast.config.RuleSet.EMPTY, 20, Blackboard.ScanInputs.fastDefault(Path.of(".")));
    }

    private static Chain chain(String entryMethod) {
        List<ChainHop> hops = List.of(new ChainHop("A", entryMethod, "A", entryMethod,
                HopKind.ENTRY, null, "readObject", "", null));
        return new Chain("R", "CAT", "HIGH", "A", entryMethod, "readObject",
                "S", "sink", hops, 0);
    }

    @Test
    void addChainDeduplicatesByKey() {
        Blackboard bb = empty();
        assertTrue(bb.addChain(chain("readObject")));
        assertFalse(bb.addChain(chain("readObject")), "同 key 链去重");
        assertTrue(bb.addChain(chain("hashCode")));
        assertEquals(2, bb.chains().size());
    }

    @Test
    void calibrationAndNotesAreKeyed() {
        Blackboard bb = empty();
        Chain c = chain("readObject");
        bb.addChain(c);
        bb.calibrateChain(c.key(), "safe-config");
        assertEquals("safe-config", bb.calibrationOf(c.key()));
        assertEquals(1, bb.calibrationCount());
        bb.chainNote(c.key(), "pattern:CC6");
        assertEquals(List.of("pattern:CC6"), bb.chainNotesOf(c.key()));
        assertEquals(List.of(), bb.chainNotesOf("missing"), "无注释的链返回空集");
    }
}
