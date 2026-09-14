package io.just.sast.knowledge.calibrate;

import io.just.sast.blackboard.Blackboard;
import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.Event;
import io.just.sast.blackboard.EventType;
import io.just.sast.blackboard.HopKind;
import io.just.sast.config.RuleSet;
import io.just.sast.cpg.graph.Graph;
import io.just.sast.model.ClassInfo;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Modifier;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/** Contract coverage for the generic deep-shape noise gate and real external entries. */
class ChainPrunerKnowledgeSourceTest {

    private static final String APP = "fixture/app/Service";
    private static final String DESC = "(Ljava/lang/Object;)V";

    @Test
    void deepShapeGateCannotEraseAnExactExternalApplicationEntry() {
        Blackboard blackboard = blackboard(Set.of(APP));
        Chain chain = deepChain();
        blackboard.addChain(chain);

        ChainPrunerKnowledgeSource source = new ChainPrunerKnowledgeSource();
        source.init(blackboard);
        source.onEvent(blackboard, Event.of(EventType.SCAN_COMPLETE, -1, null));

        assertNull(blackboard.calibrationOf(chain.key()),
                "an exact external entry is stronger than the generic deep-noise heuristic");
    }

    @Test
    void deepShapeGateStillRejectsAnUnanchoredCandidate() {
        Blackboard blackboard = blackboard(Set.of("fixture/app/Other"));
        Chain chain = deepChain();
        blackboard.addChain(chain);

        ChainPrunerKnowledgeSource source = new ChainPrunerKnowledgeSource();
        source.init(blackboard);
        source.onEvent(blackboard, Event.of(EventType.SCAN_COMPLETE, -1, null));

        assertEquals("deep-incoherent", blackboard.calibrationOf(chain.key()));
    }

    private static Blackboard blackboard(Set<String> applicationOwners) {
        Graph graph = new Graph();
        var method = graph.methodNode(APP, "process", DESC, false);
        method.propsNote("methodAccess", Modifier.PUBLIC);
        method.propsNote("classAnnotationDescriptors", List.of("Ljavax/jws/WebService;"));
        method.propsNote("methodAnnotationDescriptors", List.of("Ljavax/jws/WebMethod;"));
        method.propsNote("classSuperName", "java/lang/Object");
        method.propsNote("classInterfaces", List.of());
        graph.freeze();
        return new Blackboard(graph,
                new io.just.sast.analysis.hierarchy.ClassHierarchy(Map.of(
                        APP, new ClassInfo(APP, "java/lang/Object", List.of(), Modifier.PUBLIC,
                                List.of(), List.of())), null),
                new io.just.sast.cpg.build.FieldWriterIndex(), RuleSet.EMPTY, 20,
                new Blackboard.ScanInputs(Path.of("."), List.of(), false, false, 0, null, 0,
                        false, false, false, null, applicationOwners, true));
    }

    private static Chain deepChain() {
        List<ChainHop> hops = new ArrayList<>();
        hops.add(new ChainHop(APP, "process", APP, "process", HopKind.ENTRY,
                null, "source", DESC, null));
        for (int i = 0; i < 15; i++) {
            String from = "fixture/lib/Node" + i;
            String to = "fixture/lib/Node" + (i + 1);
            hops.add(new ChainHop(from, "call", to, "call", HopKind.DIRECT_CALL,
                    null, "call", "()V", null));
        }
        return new Chain("fixture-sink", "CODE_EXEC", "HIGH", APP, "process", "source",
                "fixture/lib/Terminal", "run", hops, 0, "()V", "TERMINAL");
    }
}
