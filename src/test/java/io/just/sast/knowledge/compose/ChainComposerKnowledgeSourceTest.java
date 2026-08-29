package io.just.sast.knowledge.compose;

import io.just.sast.blackboard.Blackboard;
import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.Event;
import io.just.sast.blackboard.EventType;
import io.just.sast.blackboard.HopKind;
import io.just.sast.config.RuleSet;
import io.just.sast.model.ClassInfo;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

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
                new io.just.sast.cpg.build.FieldWriterIndex(), RuleSet.EMPTY, 20,
                Blackboard.ScanInputs.fastDefault(java.nio.file.Path.of(".")));
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

    @Test
    void boundedSourceHostCoveragePrefersPrimaryArtifactTrigger(@TempDir Path temp) throws Exception {
        Path target = temp.resolve("target.jar");
        try (OutputStream output = Files.newOutputStream(target);
             JarOutputStream jar = new JarOutputStream(output)) {
            jar.putNextEntry(new JarEntry("app/Host.class"));
            jar.closeEntry();
            jar.putNextEntry(new JarEntry("app/Gadget.class"));
            jar.closeEntry();
        }

        io.just.sast.cpg.graph.Graph graph = new io.just.sast.cpg.graph.Graph();
        graph.addCallNode("java/io/ObjectInputStream", "readObject", "()Ljava/lang/Object;",
                "VIRTUAL", null, 0, "app/Host", "deserialize", "()V");
        graph.freeze();
        Blackboard bb = new Blackboard(graph,
                new io.just.sast.analysis.hierarchy.ClassHierarchy(Map.of(), null),
                new io.just.sast.cpg.build.FieldWriterIndex(), RuleSet.EMPTY, 20,
                new Blackboard.ScanInputs(target, List.of(), false, false, 0));
        bb.addChain(chain("T-NOISE", "CODE_EXEC", "dependency/Noise", "hashCode",
                "java/lang/Runtime", "exec"));
        bb.addChain(chain("T-APP", "CODE_EXEC", "app/Gadget", "hashCode",
                "java/lang/Runtime", "exec"));

        ChainComposerKnowledgeSource source = new ChainComposerKnowledgeSource();
        source.init(bb);
        source.onEvent(bb, Event.of(EventType.SCAN_ANALYZED, -1, null));

        assertTrue(bb.chains().stream().anyMatch(c ->
                        c.entryClass().equals("app/Host")
                                && c.hops().stream().anyMatch(h ->
                                "bridge-trigger-src".equals(h.reason())
                                        && h.toOwner().equals("app/Gadget"))),
                "有限的源宿主预算应优先覆盖主工件触发入口，而非依赖排序噪声");
    }

    @Test
    void customObjectInputStreamSubclassIsRecognizedAsSource(@TempDir Path temp) throws Exception {
        Path target = temp.resolve("target.jar");
        try (OutputStream output = Files.newOutputStream(target);
             JarOutputStream jar = new JarOutputStream(output)) {
            jar.putNextEntry(new JarEntry("app/Host.class"));
            jar.closeEntry();
            jar.putNextEntry(new JarEntry("app/Gadget.class"));
            jar.closeEntry();
        }

        io.just.sast.cpg.graph.Graph graph = new io.just.sast.cpg.graph.Graph();
        graph.addCallNode("framework/Stream", "readObject", "()Ljava/lang/Object;",
                "VIRTUAL", null, 0, "app/Host", "deserialize", "()V");
        graph.freeze();
        Blackboard bb = new Blackboard(graph,
                new io.just.sast.analysis.hierarchy.ClassHierarchy(Map.of(
                        "framework/Stream", new ClassInfo("framework/Stream",
                                "java/io/ObjectInputStream", List.of(), 0, List.of(), List.of())), null),
                new io.just.sast.cpg.build.FieldWriterIndex(), RuleSet.EMPTY, 20,
                new Blackboard.ScanInputs(target, List.of(), false, false, 0));
        bb.addChain(chain("T-NOISE", "CODE_EXEC", "dependency/Noise", "hashCode",
                "java/lang/Runtime", "exec"));
        bb.addChain(chain("T-APP", "CODE_EXEC", "app/Gadget", "hashCode",
                "java/lang/Runtime", "exec"));

        ChainComposerKnowledgeSource source = new ChainComposerKnowledgeSource();
        source.init(bb);
        source.onEvent(bb, Event.of(EventType.SCAN_ANALYZED, -1, null));

        assertTrue(bb.chains().stream().anyMatch(c ->
                        c.entryClass().equals("app/Host")
                                && c.hops().stream().anyMatch(h ->
                                "bridge-trigger-src".equals(h.reason())
                                        && h.fromOwner().equals("framework/Stream"))),
                "自定义 ObjectInputStream 子类的继承 readObject 应形成源宿主桥");
    }

    @Test
    void nestedDeserializeBridgesOnlyExplicitFrameworkBeanEntry() {
        Chain front = new Chain("T-FRONT", "DESERIALIZE", "HIGH",
                "app/Outer", "readObject", "readObject",
                "cn/hutool/core/util/ObjectUtil", "deserialize",
                List.of(new ChainHop("app/Outer", "readObject",
                        "cn/hutool/core/util/ObjectUtil", "deserialize", HopKind.DIRECT_CALL,
                        null, "deserialize", "([B)Ljava/lang/Object;", null),
                        new ChainHop("app/Outer", "readObject", "app/Outer", "readObject",
                                HopKind.ENTRY, null, "readObject", "()V", null)), 0);
        Chain back = new Chain("T-BACK", "CODE_EXEC", "HIGH",
                "app/Bean", "setValue", "deserialize",
                "java/lang/reflect/Method", "invoke",
                List.of(new ChainHop("app/Bean", "setValue", "java/lang/reflect/Method", "invoke",
                        HopKind.DIRECT_CALL, null, "deserialize", "", null),
                        new ChainHop("app/Bean", "setValue", "app/Bean", "setValue",
                                HopKind.ENTRY, null, "framework-bean-input",
                                "(Ljava/lang/Object;)V", null)), 0);
        Blackboard bb = new Blackboard(new io.just.sast.cpg.graph.Graph(),
                new io.just.sast.analysis.hierarchy.ClassHierarchy(Map.of(), null),
                new io.just.sast.cpg.build.FieldWriterIndex(), RuleSet.EMPTY, 20,
                Blackboard.ScanInputs.fastDefault(Path.of(".")));
        bb.addChain(front);
        bb.addChain(back);

        new ChainComposerKnowledgeSource().onEvent(bb,
                Event.of(EventType.SCAN_ANALYZED, -1, null));

        assertTrue(bb.chains().stream().anyMatch(c ->
                        c.entryClass().equals("app/Outer")
                                && c.sinkClass().equals("java/lang/reflect/Method")
                                && c.hops().stream().anyMatch(h -> "bridge-deser".equals(h.reason()))),
                "二次反序列化应桥接显式 framework-bean-input setter 入口");
    }
}
