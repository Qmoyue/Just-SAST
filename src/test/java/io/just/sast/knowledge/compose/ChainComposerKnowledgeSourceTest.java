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

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import io.just.sast.run.InputBudget;
import io.just.sast.config.Match;
import io.just.sast.config.Rule;
import io.just.sast.config.RuleEngine;
import io.just.sast.blackboard.ObjectGraphPlan;
import io.just.sast.analysis.entry.ApplicationEntryIndex;
import io.just.sast.cpg.graph.EdgeType;
import io.just.sast.cpg.graph.Graph;
import io.just.sast.cpg.graph.Node;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 链组装契约：DESER 桥（前段 sink 为二次反序列化 → 后段机制入口）。 */
class ChainComposerKnowledgeSourceTest {

    private static Chain chain(String ruleId, String category, String entryClass, String entryKind,
                               String sinkClass, String sinkMethod) {
        ChainHop hop = new ChainHop(entryClass, "e", entryClass, "e", HopKind.ENTRY, null, entryKind, "", null);
        return new Chain(ruleId, category, "HIGH", entryClass, "e", entryKind,
                sinkClass, sinkMethod, List.of(hop), 0);
    }

    private static Chain activatedSecondDeserialization(String activation) {
        String reason = "fragment-activation-" + activation;
        String descriptor = "()Ljava/lang/Object;";
        List<ChainHop> hops = List.of(
                new ChainHop("java/io/ObjectInputStream", "<init>", "java/io/ObjectInput",
                        "readObject", HopKind.DIRECT_CALL, null, reason, descriptor, null),
                new ChainHop("java/security/SignedObject", "getObject",
                        "java/io/ObjectInputStream", "<init>", HopKind.DIRECT_CALL, null,
                        reason, "", null),
                new ChainHop("java/security/SignedObject", "getObject",
                        "java/security/SignedObject", "getObject", HopKind.ENTRY, null,
                        "secondDeserialization", descriptor, null));
        return new Chain("signed-second", "DESERIALIZE", "HIGH",
                "java/security/SignedObject", "getObject", "secondDeserialization",
                "java/io/ObjectInput", "readObject", hops, 0, descriptor, "CAPABILITY");
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
    void secondDeserializationFragmentRequiresItsTypedActivationAxis() {
        Chain invokeFront = chain("T-INVOKE", "REFLECTION", "app/Front", "lifecycle",
                "java/lang/reflect/Method", "invoke");
        Chain deserializeFront = chain("T-DESER", "DESERIALIZE", "app/Deserializer",
                "readObject", "app/Deserializer", "readObject");
        Chain signed = activatedSecondDeserialization("invoke");
        Blackboard bb = new Blackboard(new io.just.sast.cpg.graph.Graph(),
                new io.just.sast.analysis.hierarchy.ClassHierarchy(Map.of(), null),
                new io.just.sast.cpg.build.FieldWriterIndex(), RuleSet.EMPTY, 20,
                Blackboard.ScanInputs.fastDefault(java.nio.file.Path.of(".")));
        bb.addChain(invokeFront);
        bb.addChain(deserializeFront);
        bb.addChain(signed);

        new ChainComposerKnowledgeSource().onEvent(bb, Event.of(EventType.SCAN_ANALYZED, -1, null));

        assertTrue(bb.chains().stream().anyMatch(c -> c.hops().stream()
                        .anyMatch(h -> "bridge-invoke".equals(h.reason()))),
                "invoke capability must be able to select SignedObject#getObject");
        assertFalse(bb.chains().stream()
                        .filter(c -> "app/Deserializer".equals(c.entryClass()))
                        .anyMatch(c -> c.hops().stream()
                                .anyMatch(h -> "bridge-deser".equals(h.reason()))),
                "a nested-deserialization prefix must not activate an invoke-only fragment");
    }

    @Test
    void deserializationOnlyRomeFragmentCannotBeSelectedByInvoke() {
        Chain invokeFront = chain("T-INVOKE", "REFLECTION", "app/Front", "lifecycle",
                "java/lang/reflect/Method", "invoke");
        Chain rome = new Chain("rome-deser", "CODE_EXEC", "HIGH",
                "com/sun/syndication/feed/impl/EqualsBean", "equals", "equals",
                "com/sun/org/apache/xalan/internal/xsltc/trax/TemplatesImpl", "newTransformer",
                List.of(
                        new ChainHop("com/sun/syndication/feed/impl/ToStringBean", "toString",
                                "com/sun/org/apache/xalan/internal/xsltc/trax/Templates",
                                "getOutputProperties", HopKind.DIRECT_CALL, null,
                                "fragment-activation-deserialize", "", null),
                        new ChainHop("com/sun/syndication/feed/impl/EqualsBean", "equals",
                                "com/sun/syndication/feed/impl/ToStringBean", "toString",
                                HopKind.DIRECT_CALL, null, "fragment-activation-deserialize", "", null),
                        new ChainHop("com/sun/syndication/feed/impl/EqualsBean", "equals",
                                "com/sun/syndication/feed/impl/EqualsBean", "equals", HopKind.ENTRY,
                                null, "equals", "(Ljava/lang/Object;)Z", null)),
                0, "()Ljavax/xml/transform/Transformer;", "TERMINAL");
        Blackboard bb = new Blackboard(new io.just.sast.cpg.graph.Graph(),
                new io.just.sast.analysis.hierarchy.ClassHierarchy(Map.of(), null),
                new io.just.sast.cpg.build.FieldWriterIndex(), RuleSet.EMPTY, 20,
                Blackboard.ScanInputs.fastDefault(java.nio.file.Path.of(".")));
        bb.addChain(invokeFront);
        bb.addChain(rome);

        new ChainComposerKnowledgeSource().onEvent(bb,
                Event.of(EventType.SCAN_ANALYZED, -1, null));

        assertFalse(bb.chains().stream().anyMatch(c -> c.hops().stream()
                        .anyMatch(h -> "bridge-invoke".equals(h.reason())
                                && "com/sun/syndication/feed/impl/EqualsBean".equals(h.toOwner()))),
                "ROME callback fragments must require a deserialization activation axis");
    }

    @Test
    void repeatedCompositionEventsKeepTheSameTypedFrontier() {
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
        ChainComposerKnowledgeSource source = new ChainComposerKnowledgeSource();

        source.onEvent(bb, Event.of(EventType.SCAN_ANALYZED, -1, null));
        List<String> first = bb.chains().stream().map(Chain::key).sorted().toList();
        source.onEvent(bb, Event.of(EventType.SCAN_ANALYZED, -1, null));
        List<String> second = bb.chains().stream().map(Chain::key).sorted().toList();

        assertEquals(first, second,
                "replaying the composition event must not retain or mutate a prior front projection");
    }

    @Test
    void deferredSuffixIsNotMaterializedWhenApplicationFrontHasNoBridgeDemand() {
        String sinkDescriptor = "(Ljava/lang/String;)Ljava/lang/Process;";
        String entryDescriptor = "()V";
        Rule.SinkRule terminal = new Rule.SinkRule("runtime-exec", "CODE_EXEC", "CRITICAL",
                new Rule.CallMatcher(Match.of("java/lang/Runtime"), Match.of("exec"),
                        Match.of(sinkDescriptor)), List.of(), Rule.SinkRole.TERMINAL);
        Rule.MagicEntryRule entry = new Rule.MagicEntryRule("app-entry", "service",
                new Rule.MethodMatcher(Match.of("process"), Match.of(entryDescriptor), false), null,
                "lifecycle");
        RuleSet rules = new RuleSet(List.of(terminal), List.of(entry), List.of(), List.of(), List.of());

        io.just.sast.cpg.graph.Graph graph = new io.just.sast.cpg.graph.Graph();
        graph.methodNode("app/Entry", "process", entryDescriptor, false);
        graph.methodNode("dep/Terminal", "readObject", entryDescriptor, false);
        var runtime = graph.methodNode("java/lang/Runtime", "exec", sinkDescriptor, true);
        var sink = graph.addCallNode("java/lang/Runtime", "exec", sinkDescriptor,
                "VIRTUAL", null, 0, "dep/Terminal", "readObject", entryDescriptor);
        graph.addEdge(sink, runtime, io.just.sast.cpg.graph.EdgeType.INVOKES, "VIRTUAL");
        graph.freeze();

        Blackboard bb = new Blackboard(graph,
                new io.just.sast.analysis.hierarchy.ClassHierarchy(Map.of(), null),
                new io.just.sast.cpg.build.FieldWriterIndex(), rules, 20,
                new Blackboard.ScanInputs(java.nio.file.Path.of("."), List.of(), false, true, 20,
                        null, 0, false, false, false, null, Set.of("app/Entry"), true));
        Chain applicationNoise = new Chain("unrelated", "OTHER", "LOW", "app/Entry", "process",
                "service", "java/lang/Object", "toString", List.of(
                new ChainHop("app/Entry", "process", "app/Entry", "process", HopKind.ENTRY,
                        null, "service", entryDescriptor, null)), 0, "()Ljava/lang/String;", "TERMINAL");
        Chain dependencySuffix = new Chain("runtime-exec", "CODE_EXEC", "CRITICAL",
                "dep/Terminal", "readObject", "readObject", "java/lang/Runtime", "exec",
                List.of(
                        new ChainHop("dep/Terminal", "readObject", "java/lang/Runtime", "exec",
                                HopKind.DIRECT_CALL, null, "direct", sinkDescriptor, null),
                        new ChainHop("dep/Terminal", "readObject", "dep/Terminal", "readObject",
                                HopKind.ENTRY, null, "readObject", entryDescriptor, null)), 0,
                sinkDescriptor, "TERMINAL");
        bb.addChain(applicationNoise);
        ApplicationEntryIndex.ProducerCandidate candidate =
                new ApplicationEntryIndex.ProducerCandidate(dependencySuffix.ruleId(),
                        dependencySuffix.category(), dependencySuffix.severity(),
                        dependencySuffix.entryClass(), dependencySuffix.entryMethod(), entryDescriptor,
                        dependencySuffix.entryKind(), dependencySuffix.sinkClass(),
                        dependencySuffix.sinkMethod(), dependencySuffix.sinkDescriptor(),
                        dependencySuffix.sinkRole(), dependencySuffix.sinkRisk(), false);
        AtomicBoolean materialized = new AtomicBoolean();
        assertTrue(bb.addSolverCandidate(candidate, () -> {
            materialized.set(true);
            return dependencySuffix;
        }));

        new ChainComposerKnowledgeSource().onEvent(bb,
                Event.of(EventType.SCAN_ANALYZED, -1, null));

        assertFalse(materialized.get(),
                "a dependency suffix must stay deferred when no application front can bridge to it");
        assertEquals(1, bb.compositionInputsLazy().deferredDependencySuffixes().size());
    }

    @Test
    void sourceHostProjectionDoesNotMaterializeDeferredTriggersWithoutGraphHosts() {
        String sinkDescriptor = "(Ljava/lang/String;)Ljava/lang/Process;";
        String entryDescriptor = "()V";
        Rule.SinkRule terminal = new Rule.SinkRule("runtime-exec", "CODE_EXEC", "CRITICAL",
                new Rule.CallMatcher(Match.of("java/lang/Runtime"), Match.of("exec"),
                        Match.of(sinkDescriptor)), List.of(), Rule.SinkRole.TERMINAL);
        Rule.MagicEntryRule entry = new Rule.MagicEntryRule("app-entry", "service",
                new Rule.MethodMatcher(Match.of("process"), Match.of(entryDescriptor), false), null,
                "lifecycle");
        RuleSet rules = new RuleSet(List.of(terminal), List.of(entry), List.of(), List.of(), List.of());
        io.just.sast.cpg.graph.Graph graph = new io.just.sast.cpg.graph.Graph();
        graph.methodNode("app/Entry", "process", entryDescriptor, false);
        graph.methodNode("dep/Terminal", "hashCode", entryDescriptor, false);
        var runtime = graph.methodNode("java/lang/Runtime", "exec", sinkDescriptor, true);
        var sink = graph.addCallNode("java/lang/Runtime", "exec", sinkDescriptor,
                "VIRTUAL", null, 0, "dep/Terminal", "hashCode", entryDescriptor);
        graph.addEdge(sink, runtime, io.just.sast.cpg.graph.EdgeType.INVOKES, "VIRTUAL");
        graph.freeze();

        Blackboard bb = new Blackboard(graph,
                new io.just.sast.analysis.hierarchy.ClassHierarchy(Map.of(), null),
                new io.just.sast.cpg.build.FieldWriterIndex(), rules, 20,
                new Blackboard.ScanInputs(java.nio.file.Path.of("."), List.of(), false, true, 20,
                        null, 0, false, false, false, null, Set.of("app/Entry"), true));
        Chain applicationNoise = new Chain("unrelated", "OTHER", "LOW", "app/Entry", "process",
                "service", "java/lang/Object", "toString", List.of(
                new ChainHop("app/Entry", "process", "app/Entry", "process", HopKind.ENTRY,
                        null, "service", entryDescriptor, null)), 0, "()Ljava/lang/String;", "TERMINAL");
        Chain dependencyTrigger = new Chain("runtime-exec", "CODE_EXEC", "CRITICAL",
                "dep/Terminal", "hashCode", "hashCode", "java/lang/Runtime", "exec",
                List.of(new ChainHop("dep/Terminal", "hashCode", "java/lang/Runtime", "exec",
                                HopKind.DIRECT_CALL, null, "direct", sinkDescriptor, null),
                        new ChainHop("dep/Terminal", "hashCode", "dep/Terminal", "hashCode",
                                HopKind.ENTRY, null, "hashCode", entryDescriptor, null)), 0,
                sinkDescriptor, "TERMINAL");
        bb.addChain(applicationNoise);
        ApplicationEntryIndex.ProducerCandidate candidate =
                new ApplicationEntryIndex.ProducerCandidate(dependencyTrigger.ruleId(),
                        dependencyTrigger.category(), dependencyTrigger.severity(),
                        dependencyTrigger.entryClass(), dependencyTrigger.entryMethod(), entryDescriptor,
                        dependencyTrigger.entryKind(), dependencyTrigger.sinkClass(),
                        dependencyTrigger.sinkMethod(), dependencyTrigger.sinkDescriptor(),
                        dependencyTrigger.sinkRole(), dependencyTrigger.sinkRisk(), false);
        AtomicBoolean materialized = new AtomicBoolean();
        assertTrue(bb.addSolverCandidate(candidate, () -> {
            materialized.set(true);
            return dependencyTrigger;
        }));

        new ChainComposerKnowledgeSource().onEvent(bb,
                Event.of(EventType.SCAN_ANALYZED, -1, null));

        assertFalse(materialized.get(),
                "deferred trigger payload must remain lazy when no graph source host can consume it");
        assertEquals(1, bb.compositionInputsLazy().deferredDependencySuffixes().size());
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

        assertTrue(bb.kernelOnlyChains().stream().anyMatch(c ->
                        c.entryClass().equals("app/Host")
                                && c.hops().stream().anyMatch(h ->
                                "bridge-trigger-src".equals(h.reason())
                                        && h.toOwner().equals("app/Gadget"))),
                "未知应用范围时，有限的 kernel 源宿主预算仍应优先覆盖主工件触发入口");
        assertTrue(bb.chains().stream().noneMatch(c -> c.entryClass().equals("app/Host")),
                "未知应用范围的 source-host 候选不得进入默认 product");
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

        // The source scan must resolve subtype relationships from the event target, not
        // from a Blackboard retained by a previous run.
        Blackboard staleOwner = new Blackboard(new io.just.sast.cpg.graph.Graph(),
                new io.just.sast.analysis.hierarchy.ClassHierarchy(Map.of(), null),
                new io.just.sast.cpg.build.FieldWriterIndex(), RuleSet.EMPTY, 20,
                Blackboard.ScanInputs.fastDefault(Path.of(".")));
        ChainComposerKnowledgeSource source = new ChainComposerKnowledgeSource();
        source.init(staleOwner);
        source.onEvent(bb, Event.of(EventType.SCAN_ANALYZED, -1, null));

        assertTrue(bb.kernelOnlyChains().stream().anyMatch(c ->
                        c.entryClass().equals("app/Host")
                                && c.hops().stream().anyMatch(h ->
                                "bridge-trigger-src".equals(h.reason())
                                        && h.fromOwner().equals("framework/Stream"))),
                "未知应用范围时，自定义 ObjectInputStream 子类仍应只形成 kernel 源宿主桥");
        assertTrue(bb.chains().stream().noneMatch(c -> c.entryClass().equals("app/Host")),
                "未知应用范围的自定义 source-host 候选不得进入默认 product");
    }

    @Test
    void sourceHostScanIsScopedToEachEventBlackboard(@TempDir Path temp) throws Exception {
        Path firstJar = temp.resolve("first.jar");
        Path secondJar = temp.resolve("second.jar");
        try (OutputStream output = Files.newOutputStream(firstJar);
             JarOutputStream jar = new JarOutputStream(output)) {
            jar.putNextEntry(new JarEntry("app/FirstHost.class"));
            jar.closeEntry();
            jar.putNextEntry(new JarEntry("app/Gadget.class"));
            jar.closeEntry();
        }
        try (OutputStream output = Files.newOutputStream(secondJar);
             JarOutputStream jar = new JarOutputStream(output)) {
            jar.putNextEntry(new JarEntry("app/SecondHost.class"));
            jar.closeEntry();
            jar.putNextEntry(new JarEntry("app/Gadget.class"));
            jar.closeEntry();
        }

        Blackboard first = sourceHostBoard(firstJar, "app/FirstHost");
        Blackboard second = sourceHostBoard(secondJar, "app/SecondHost");
        Chain trigger = chain("T-TRIGGER", "CODE_EXEC", "app/Gadget", "hashCode",
                "java/lang/Runtime", "exec");
        first.addChain(trigger);
        second.addChain(trigger);
        Chain secondTrigger = chain("T-TRIGGER-2", "CODE_EXEC", "app/OtherGadget", "hashCode",
                "java/lang/Runtime", "exec");
        first.addChain(secondTrigger);
        second.addChain(secondTrigger);

        ChainComposerKnowledgeSource source = new ChainComposerKnowledgeSource();
        source.onEvent(first, Event.of(EventType.SCAN_ANALYZED, -1, null));
        source.onEvent(second, Event.of(EventType.SCAN_ANALYZED, -1, null));

        assertTrue(first.kernelOnlyChains().stream().anyMatch(c ->
                        c.entryClass().equals("app/FirstHost")
                                && c.hops().stream().anyMatch(h ->
                                "bridge-trigger-src".equals(h.reason()))),
                "first event should retain its own source host");
        assertTrue(second.kernelOnlyChains().stream().anyMatch(c ->
                        c.entryClass().equals("app/SecondHost")
                                && c.hops().stream().anyMatch(h ->
                                "bridge-trigger-src".equals(h.reason()))),
                "second event must rescan its own Blackboard instead of reusing the first host");
    }

    @Test
    void primaryArtifactPriorityIsRecomputedForAReusedEvent(@TempDir Path temp) throws Exception {
        Path target = temp.resolve("target.jar");
        writePrimaryClasses(target, Set.of("app/OldPriority.class"));
        Blackboard bb = sourceHostBoard(target, "app/Host");
        bb.addChain(chain("N-1", "CODE_EXEC", "app/NotATrigger", "not-trigger",
                "java/lang/Runtime", "exec"));
        bb.addChain(chain("N-2", "CODE_EXEC", "app/NotATrigger2", "not-trigger",
                "java/lang/Runtime", "exec"));

        ChainComposerKnowledgeSource source = new ChainComposerKnowledgeSource();
        source.onEvent(bb, Event.of(EventType.SCAN_ANALYZED, -1, null));

        writePrimaryClasses(target, Set.of("app/NewPrimary.class"));
        for (int i = 0; i < 400; i++) {
            String suffix = String.format("%03d", i);
            bb.addChain(chain("A-" + suffix, "CODE_EXEC", "dep/Secondary" + suffix,
                    "hashCode", "java/lang/Runtime", "exec"));
        }
        bb.addChain(chain("Z-PRIMARY", "CODE_EXEC", "app/NewPrimary", "hashCode",
                "java/lang/Runtime", "exec"));

        source.onEvent(bb, Event.of(EventType.SCAN_ANALYZED, -1, null));

        assertTrue(bb.kernelOnlyChains().stream()
                        .anyMatch(chain -> chain.hops().stream().anyMatch(hop ->
                                "bridge-trigger-src".equals(hop.reason())
                                        && "app/NewPrimary".equals(hop.toOwner()))),
                "a reused source must recompute primary-artifact priority for the current event");
    }

    private static void writePrimaryClasses(Path target, Set<String> classEntries) throws IOException {
        try (OutputStream output = Files.newOutputStream(target);
             JarOutputStream jar = new JarOutputStream(output)) {
            for (String classEntry : classEntries) {
                jar.putNextEntry(new JarEntry(classEntry));
                jar.closeEntry();
            }
        }
    }

    private static Blackboard sourceHostBoard(Path target, String hostOwner) {
        io.just.sast.cpg.graph.Graph graph = new io.just.sast.cpg.graph.Graph();
        graph.addCallNode("framework/Stream", "readObject", "()Ljava/lang/Object;",
                "VIRTUAL", null, 0, hostOwner, "deserialize", "()V");
        graph.freeze();
        return new Blackboard(graph,
                new io.just.sast.analysis.hierarchy.ClassHierarchy(Map.of(
                        "framework/Stream", new ClassInfo("framework/Stream",
                                "java/io/ObjectInputStream", List.of(), 0, List.of(), List.of())), null),
                new io.just.sast.cpg.build.FieldWriterIndex(), RuleSet.EMPTY, 20,
                new Blackboard.ScanInputs(target, List.of(), false, false, 0));
    }

    @Test
    void knownApplicationScopeRejectsDependencyOnlySourceHosts(@TempDir Path temp) throws Exception {
        Path target = temp.resolve("target.jar");
        try (OutputStream output = Files.newOutputStream(target);
             JarOutputStream jar = new JarOutputStream(output)) {
            jar.putNextEntry(new JarEntry("app/Host.class"));
            jar.closeEntry();
            jar.putNextEntry(new JarEntry("dep/Host.class"));
            jar.closeEntry();
        }

        String runtimeDesc = "(Ljava/lang/String;)Ljava/lang/Process;";
        io.just.sast.cpg.graph.Graph graph = new io.just.sast.cpg.graph.Graph();
        graph.methodNode("app/Host", "deserialize", "()V", false);
        graph.methodNode("dep/Host", "deserialize", "()V", false);
        graph.methodNode("java/io/ObjectInputStream", "readObject", "()Ljava/lang/Object;", true);
        graph.methodNode("java/lang/Runtime", "exec", runtimeDesc, true);
        graph.addCallNode("java/io/ObjectInputStream", "readObject", "()Ljava/lang/Object;",
                "VIRTUAL", null, 0, "app/Host", "deserialize", "()V");
        graph.addCallNode("java/io/ObjectInputStream", "readObject", "()Ljava/lang/Object;",
                "VIRTUAL", null, 0, "dep/Host", "deserialize", "()V");
        var appSink = graph.addCallNode("java/lang/Runtime", "exec", runtimeDesc,
                "VIRTUAL", null, 1, "app/Host", "deserialize", "()V");
        var depSink = graph.addCallNode("java/lang/Runtime", "exec", runtimeDesc,
                "VIRTUAL", null, 1, "dep/Host", "deserialize", "()V");
        var runtime = graph.findMethodNode("java/lang/Runtime", "exec", runtimeDesc);
        graph.addEdge(appSink, runtime, io.just.sast.cpg.graph.EdgeType.INVOKES, "VIRTUAL");
        graph.addEdge(depSink, runtime, io.just.sast.cpg.graph.EdgeType.INVOKES, "VIRTUAL");
        graph.freeze();

        Rule.SinkRule sink = new Rule.SinkRule("runtime-exec", "COMMAND", "CRITICAL",
                new Rule.CallMatcher(Match.of("java/lang/Runtime"), Match.of("exec"),
                        Match.of(runtimeDesc)), List.of(new Rule.TaintedPos.Arg(0)),
                Rule.SinkRole.TERMINAL);
        Rule.MagicEntryRule entry = new Rule.MagicEntryRule("app-deserialize", "deserialize",
                new Rule.MethodMatcher(Match.of("deserialize"), Match.of("()V"), false),
                null, "deserialize");
        RuleSet rules = new RuleSet(List.of(sink), List.of(entry), List.of(), List.of(), List.of());
        var hierarchy = new io.just.sast.analysis.hierarchy.ClassHierarchy(Map.of(), null);
        Blackboard bb = new Blackboard(graph, hierarchy,
                new io.just.sast.cpg.build.FieldWriterIndex(), rules, 20,
                new Blackboard.ScanInputs(target, List.of(), false, false, 0, null, 0,
                        false, false, false, null, Set.of("app/Host"), true));
        bb.addChain(chain("T-APP", "CODE_EXEC", "app/Gadget", "hashCode",
                "java/lang/Runtime", "exec"));
        bb.addChain(chain("T-APP-2", "CODE_EXEC", "app/Gadget2", "hashCode",
                "java/lang/Runtime", "exec"));

        ChainComposerKnowledgeSource source = new ChainComposerKnowledgeSource();
        source.init(bb);
        source.onEvent(bb, Event.of(EventType.SCAN_ANALYZED, -1, null));

        assertTrue(bb.chains().stream().anyMatch(c -> c.entryClass().equals("app/Host")),
                "the application-owned deserialization host remains eligible");
        assertTrue(bb.chains().stream().noneMatch(c -> c.entryClass().equals("dep/Host")),
                "a dependency-only source host must not become a default product root");
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

        ChainComposerKnowledgeSource source = new ChainComposerKnowledgeSource();
        source.init(bb);
        source.onEvent(bb,
                Event.of(EventType.SCAN_ANALYZED, -1, null));

        assertTrue(bb.chains().stream().anyMatch(c ->
                        c.entryClass().equals("app/Outer")
                                && c.sinkClass().equals("java/lang/reflect/Method")
                                && c.hops().stream().anyMatch(h -> "bridge-deser".equals(h.reason()))),
                "二次反序列化应桥接显式 framework-bean-input setter 入口");
    }

    @Test
    void applicationPrefixOverlapsExactCallbackForSecondaryDeserializer() {
        String invokeDesc = "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;";
        String deserializeDesc = "([B)Ljava/lang/Object;";
        Rule.SinkRule invoke = new Rule.SinkRule("reflective-invoke", "REFLECTIVE_INVOKE",
                "HIGH", new Rule.CallMatcher(Match.of("java/lang/reflect/Method"),
                Match.of("invoke"), Match.of(invokeDesc)), List.of(), Rule.SinkRole.CAPABILITY);
        Rule.SinkRule deserialize = new Rule.SinkRule("secondary-deserialize", "DESERIALIZE",
                "HIGH", new Rule.CallMatcher(Match.of("dep/Deserializer"),
                Match.of("deserialize"), Match.of(deserializeDesc)), List.of(),
                Rule.SinkRole.TERMINAL);
        Rule.MagicEntryRule applicationEntry = new Rule.MagicEntryRule("app-entry", "service",
                new Rule.MethodMatcher(Match.of("process"), Match.of("()V"), false), null,
                "lifecycle");
        RuleSet rules = new RuleSet(List.of(invoke, deserialize), List.of(applicationEntry),
                List.of(), List.of(), List.of());

        io.just.sast.cpg.graph.Graph graph = new io.just.sast.cpg.graph.Graph();
        graph.methodNode("app/Entry", "process", "()V", false);
        graph.methodNode("dep/Callback", "equals", "(Ljava/lang/Object;)Z", false);
        graph.addCallNode("dep/Deserializer", "deserialize", deserializeDesc, "VIRTUAL", null, 0,
                "dep/Callback", "equals", "(Ljava/lang/Object;)Z");
        graph.freeze();
        Blackboard bb = new Blackboard(graph,
                new io.just.sast.analysis.hierarchy.ClassHierarchy(Map.of(), null),
                new io.just.sast.cpg.build.FieldWriterIndex(), rules, 20,
                new Blackboard.ScanInputs(Path.of("."), List.of(), false, true, 20,
                        null, 0, false, false, false, null, Set.of("app/Entry"), true));
        Chain front = new Chain("reflective-invoke", "REFLECTIVE_INVOKE", "HIGH",
                "app/Entry", "process", "source", "java/lang/reflect/Method", "invoke",
                List.of(
                        new ChainHop("dep/Callback", "equals", "dep/Callback", "equals",
                                HopKind.FIELD_FLOW, "value", "field", "", null),
                        new ChainHop("app/Entry", "process", "dep/Callback", "equals",
                                HopKind.VIRTUAL_DISPATCH, null, "callback", "(Ljava/lang/Object;)Z", null),
                        new ChainHop("app/Entry", "process", "app/Entry", "process",
                                HopKind.ENTRY, null, "service", "()V", null)), 0,
                invokeDesc, "CAPABILITY");
        Chain back = new Chain("secondary-deserialize", "DESERIALIZE", "HIGH",
                "dep/Callback", "equals", "equals", "dep/Deserializer", "deserialize",
                List.of(
                        new ChainHop("dep/Callback", "equals", "dep/Callback", "equals",
                                HopKind.FIELD_FLOW, "value", "field", "", null),
                        new ChainHop("dep/Callback", "equals", "dep/Callback", "equals",
                                HopKind.ENTRY, null, "equals", "(Ljava/lang/Object;)Z", null)), 0,
                deserializeDesc, "TERMINAL");
        bb.addChain(front);
        bb.addChain(back);

        ChainComposerKnowledgeSource source = new ChainComposerKnowledgeSource();
        source.init(bb);
        source.onEvent(bb, Event.of(EventType.SCAN_ANALYZED, -1, null));

        assertTrue(bb.chains().stream().anyMatch(chain ->
                        chain.entryClass().equals("app/Entry")
                                && chain.sinkClass().equals("dep/Deserializer")
                                && chain.hops().stream().anyMatch(hop ->
                                "bridge-second-deserialization-overlap".equals(hop.reason()))),
                "应用前缀应在精确 callback 处续接二次反序列化后缀："
                        + bb.chains().stream().map(Chain::key).toList());
    }

    @Test
    void knownApplicationScopeDoesNotComposeDependencyOnlyFront() {
        String invokeDesc = "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;";
        String sinkDesc = "(Ljava/lang/String;)Ljava/lang/Process;";
        Rule.SinkRule invoke = new Rule.SinkRule("reflective-invoke", "REFLECTIVE_INVOKE",
                "HIGH", new Rule.CallMatcher(Match.of("java/lang/reflect/Method"),
                Match.of("invoke"), Match.of(invokeDesc)), List.of(), Rule.SinkRole.CAPABILITY);
        Rule.SinkRule terminal = new Rule.SinkRule("runtime-exec", "CODE_EXEC", "CRITICAL",
                new Rule.CallMatcher(Match.of("java/lang/Runtime"), Match.of("exec"),
                        Match.of(sinkDesc)), List.of(), Rule.SinkRole.TERMINAL);
        Rule.MagicEntryRule entry = new Rule.MagicEntryRule("app-entry", "service",
                new Rule.MethodMatcher(Match.of("process"), Match.of("()V"), false), null,
                "lifecycle");
        RuleSet rules = new RuleSet(List.of(invoke, terminal), List.of(entry), List.of(),
                List.of(), List.of());

        io.just.sast.cpg.graph.Graph graph = new io.just.sast.cpg.graph.Graph();
        graph.methodNode("app/Entry", "process", "()V", false);
        graph.methodNode("dep/Callback", "equals", "(Ljava/lang/Object;)Z", false);
        graph.addCallNode("java/lang/Runtime", "exec", sinkDesc, "VIRTUAL", null, 0,
                "dep/Callback", "equals", "(Ljava/lang/Object;)Z");
        graph.freeze();

        Blackboard bb = new Blackboard(graph,
                new io.just.sast.analysis.hierarchy.ClassHierarchy(Map.of(), null),
                new io.just.sast.cpg.build.FieldWriterIndex(), rules, 20,
                new Blackboard.ScanInputs(Path.of("."), List.of(), false, true, 20,
                        null, 0, false, false, false, null, Set.of("app/Entry"), true));
        Chain appFront = new Chain("reflective-invoke", "REFLECTIVE_INVOKE", "HIGH",
                "app/Entry", "process", "source", "java/lang/reflect/Method", "invoke",
                List.of(
                        new ChainHop("app/Entry", "process", "java/lang/reflect/Method", "invoke",
                                HopKind.DIRECT_CALL, null, "direct", invokeDesc, null),
                        new ChainHop("app/Entry", "process", "app/Entry", "process",
                                HopKind.ENTRY, null, "service", "()V", null)), 0,
                invokeDesc, "CAPABILITY");
        Chain dependencyFront = new Chain("dependency-invoke", "REFLECTIVE_INVOKE", "HIGH",
                "dep/Noise", "readObject", "readObject", "java/lang/reflect/Method", "invoke",
                List.of(
                        new ChainHop("dep/Noise", "readObject", "java/lang/reflect/Method", "invoke",
                                HopKind.DIRECT_CALL, null, "direct", invokeDesc, null),
                        new ChainHop("dep/Noise", "readObject", "dep/Noise", "readObject",
                                HopKind.ENTRY, null, "readObject", "()V", null)), 0,
                invokeDesc, "CAPABILITY");
        Chain terminalBack = new Chain("runtime-exec", "CODE_EXEC", "CRITICAL",
                "dep/Terminal", "readObject", "readObject", "java/lang/Runtime", "exec",
                List.of(
                        new ChainHop("dep/Terminal", "readObject", "java/lang/Runtime", "exec",
                                HopKind.DIRECT_CALL, null, "direct", sinkDesc, null),
                        new ChainHop("dep/Terminal", "readObject", "dep/Terminal", "readObject",
                                HopKind.ENTRY, null, "readObject", "()V", null)), 0,
                sinkDesc, "TERMINAL");
        bb.addChain(appFront);
        bb.addChain(dependencyFront);
        AtomicBoolean dependencySuffixMaterialized = new AtomicBoolean();
        assertTrue(bb.addSolverCandidate(
                new ApplicationEntryIndex.ProducerCandidate(terminalBack.ruleId(), terminalBack.category(),
                        terminalBack.severity(), terminalBack.entryClass(), terminalBack.entryMethod(), "()V",
                        terminalBack.entryKind(), terminalBack.sinkClass(), terminalBack.sinkMethod(),
                        terminalBack.sinkDescriptor(), terminalBack.sinkRole(), terminalBack.sinkRisk(), false),
                () -> {
                    dependencySuffixMaterialized.set(true);
                    return terminalBack;
                }),
                "typed dependency terminal must remain available to the composition frontier");
        assertFalse(dependencySuffixMaterialized.get(),
                "typed dependency terminal should remain deferred until an application bridge asks for it");

        // The event Blackboard is the only scope owner.  A prior init on a different,
        // unknown-scope run must not make this known application scope fall back to the
        // broad compatibility composition pass.
        Blackboard staleOwner = new Blackboard(new io.just.sast.cpg.graph.Graph(),
                new io.just.sast.analysis.hierarchy.ClassHierarchy(Map.of(), null),
                new io.just.sast.cpg.build.FieldWriterIndex(), RuleSet.EMPTY, 20,
                Blackboard.ScanInputs.fastDefault(Path.of(".")));
        ChainComposerKnowledgeSource source = new ChainComposerKnowledgeSource();
        source.init(staleOwner);
        source.onEvent(bb, Event.of(EventType.SCAN_ANALYZED, -1, null));

        assertTrue(dependencySuffixMaterialized.get(),
                "an application invoke front is an explicit demand for the deferred terminal suffix");

        assertTrue(bb.chains().stream().anyMatch(chain ->
                        chain.entryClass().equals("app/Entry")
                                && chain.sinkClass().equals("java/lang/Runtime")
                                && chain.hops().stream().anyMatch(hop ->
                                "bridge-invoke".equals(hop.reason()))),
                "应用前缀仍必须续接已索引 terminal 后缀："
                        + bb.chains().stream().map(Chain::key).toList());
        assertTrue(bb.chains().stream().noneMatch(chain ->
                        chain.entryClass().equals("dep/Noise")
                                && chain.hops().stream().anyMatch(hop ->
                                "bridge-invoke".equals(hop.reason()))),
                "依赖侧反向可达/同形前缀不得在默认组合阶段物化："
                        + bb.chains().stream().map(Chain::key).toList());
    }

    @Test
    void knownApplicationScopeAdmitsApplicationHelperReachableFromEntry() {
        String invokeDesc = "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;";
        String sinkDesc = "(Ljava/lang/String;)Ljava/lang/Process;";
        Rule.SinkRule invoke = new Rule.SinkRule("reflective-invoke", "REFLECTIVE_INVOKE",
                "HIGH", new Rule.CallMatcher(Match.of("java/lang/reflect/Method"),
                Match.of("invoke"), Match.of(invokeDesc)), List.of(), Rule.SinkRole.CAPABILITY);
        Rule.SinkRule terminal = new Rule.SinkRule("runtime-exec", "CODE_EXEC", "CRITICAL",
                new Rule.CallMatcher(Match.of("java/lang/Runtime"), Match.of("exec"),
                        Match.of(sinkDesc)), List.of(), Rule.SinkRole.TERMINAL);
        Rule.MagicEntryRule entry = new Rule.MagicEntryRule("app-entry", "service",
                new Rule.MethodMatcher(Match.of("process"), Match.of("()V"), false), null,
                "lifecycle");
        RuleSet rules = new RuleSet(List.of(invoke, terminal), List.of(entry), List.of(),
                List.of(), List.of());

        io.just.sast.cpg.graph.Graph graph = new io.just.sast.cpg.graph.Graph();
        graph.methodNode("app/Entry", "process", "()V", false);
        var helper = graph.methodNode("app/Helper", "decode", "()V", false);
        var helperCall = graph.addCallNode("app/Helper", "decode", "()V", "STATIC", null, 0,
                "app/Entry", "process", "()V");
        graph.addEdge(helperCall, helper, io.just.sast.cpg.graph.EdgeType.INVOKES, "STATIC");
        graph.methodNode("dep/Terminal", "readObject", "()V", false);
        var sink = graph.addCallNode("java/lang/Runtime", "exec", sinkDesc,
                "VIRTUAL", null, 0, "dep/Terminal", "readObject", "()V");
        var runtime = graph.methodNode("java/lang/Runtime", "exec", sinkDesc, true);
        graph.addEdge(sink, runtime, io.just.sast.cpg.graph.EdgeType.INVOKES, "VIRTUAL");
        graph.freeze();

        Blackboard bb = new Blackboard(graph,
                new io.just.sast.analysis.hierarchy.ClassHierarchy(Map.of(), null),
                new io.just.sast.cpg.build.FieldWriterIndex(), rules, 20,
                new Blackboard.ScanInputs(Path.of("."), List.of(), false, true, 20,
                        null, 0, false, false, false, null,
                        Set.of("app/Entry", "app/Helper"), true));
        Chain helperFront = new Chain("reflective-invoke", "REFLECTIVE_INVOKE", "HIGH",
                "app/Helper", "decode", "source", "java/lang/reflect/Method", "invoke",
                List.of(
                        new ChainHop("app/Helper", "decode", "java/lang/reflect/Method", "invoke",
                                HopKind.DIRECT_CALL, null, "direct", invokeDesc, null),
                        new ChainHop("app/Helper", "decode", "app/Helper", "decode",
                                HopKind.ENTRY, null, "service", "()V", null)), 0,
                invokeDesc, "CAPABILITY");
        Chain terminalBack = new Chain("runtime-exec", "CODE_EXEC", "CRITICAL",
                "dep/Terminal", "readObject", "readObject", "java/lang/Runtime", "exec",
                List.of(
                        new ChainHop("dep/Terminal", "readObject", "java/lang/Runtime", "exec",
                                HopKind.DIRECT_CALL, null, "direct", sinkDesc, null),
                        new ChainHop("dep/Terminal", "readObject", "dep/Terminal", "readObject",
                                HopKind.ENTRY, null, "readObject", "()V", null)), 0,
                sinkDesc, "TERMINAL");
        bb.addChain(helperFront);
        bb.addChain(terminalBack);

        ChainComposerKnowledgeSource source = new ChainComposerKnowledgeSource();
        source.init(bb);
        source.onEvent(bb, Event.of(EventType.SCAN_ANALYZED, -1, null));

        assertTrue(bb.chains().stream().anyMatch(chain ->
                        chain.entryClass().equals("app/Helper")
                                && chain.sinkClass().equals("java/lang/Runtime")
                                && chain.hops().stream().anyMatch(hop ->
                                "bridge-invoke".equals(hop.reason()))),
                "应用入口可达的 helper 前缀必须保留在默认组合前沿："
                        + bb.chains().stream().map(Chain::key).toList());
    }

    @Test
    void knownApplicationScopeAdmitsTypedBindingCallbackFront() {
        String invokeDesc = "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;";
        String bindingDesc = "(Ljava/lang/String;Ljava/lang/Class;)Ljava/lang/Object;";
        String sinkDesc = "(Ljava/lang/String;)Ljava/lang/Process;";
        Rule.SinkRule invoke = new Rule.SinkRule("reflective-invoke", "REFLECTIVE_INVOKE",
                "HIGH", new Rule.CallMatcher(Match.of("java/lang/reflect/Method"),
                Match.of("invoke"), Match.of(invokeDesc)), List.of(), Rule.SinkRole.CAPABILITY);
        Rule.SinkRule terminal = new Rule.SinkRule("runtime-exec", "CODE_EXEC", "CRITICAL",
                new Rule.CallMatcher(Match.of("java/lang/Runtime"), Match.of("exec"),
                        Match.of(sinkDesc)), List.of(), Rule.SinkRole.TERMINAL);
        Rule.MagicEntryRule entry = new Rule.MagicEntryRule("app-entry", "service",
                new Rule.MethodMatcher(Match.of("process"), Match.of("()V"), false), null,
                "lifecycle");
        Rule.SourceRule binding = new Rule.SourceRule("json-read", "deserialize",
                new Rule.CallMatcher(Match.of("com/fasterxml/jackson/databind/ObjectMapper"),
                        Match.of("readValue"), Match.of(bindingDesc)), null);
        RuleSet rules = new RuleSet(List.of(invoke, terminal), List.of(entry), List.of(binding),
                List.of(), List.of());

        io.just.sast.cpg.graph.Graph graph = new io.just.sast.cpg.graph.Graph();
        graph.methodNode("app/Entry", "process", "()V", false);
        var mapper = graph.methodNode("com/fasterxml/jackson/databind/ObjectMapper",
                "readValue", bindingDesc, true);
        var source = graph.addCallNode("com/fasterxml/jackson/databind/ObjectMapper",
                "readValue", bindingDesc, "VIRTUAL", null, 0,
                "app/Entry", "process", "()V");
        source.propsNote("classLiteralHints", List.of("app/Helper"));
        graph.addEdge(source, mapper, io.just.sast.cpg.graph.EdgeType.INVOKES, "VIRTUAL");
        graph.methodNode("app/Helper", "decode", "(Ljava/lang/String;)V", false);
        graph.methodNode("dep/Terminal", "readObject", "()V", false);
        var sink = graph.addCallNode("java/lang/Runtime", "exec", sinkDesc,
                "VIRTUAL", null, 0, "dep/Terminal", "readObject", "()V");
        var runtime = graph.methodNode("java/lang/Runtime", "exec", sinkDesc, true);
        graph.addEdge(sink, runtime, io.just.sast.cpg.graph.EdgeType.INVOKES, "VIRTUAL");
        graph.freeze();

        Blackboard bb = new Blackboard(graph,
                new io.just.sast.analysis.hierarchy.ClassHierarchy(Map.of(), null),
                new io.just.sast.cpg.build.FieldWriterIndex(), rules, 20,
                new Blackboard.ScanInputs(Path.of("."), List.of(), false, true, 20,
                        null, 0, false, false, false, null,
                        Set.of("app/Entry", "app/Helper"), true));
        Chain helperFront = new Chain("reflective-invoke", "REFLECTIVE_INVOKE", "HIGH",
                "app/Helper", "decode", "source", "java/lang/reflect/Method", "invoke",
                List.of(
                        new ChainHop("app/Helper", "decode", "java/lang/reflect/Method", "invoke",
                                HopKind.DIRECT_CALL, null, "direct", invokeDesc, null),
                        new ChainHop("app/Helper", "decode", "app/Helper", "decode",
                                HopKind.ENTRY, null, "deserialize", "(Ljava/lang/String;)V", null)), 0,
                invokeDesc, "CAPABILITY");
        Chain terminalBack = new Chain("runtime-exec", "CODE_EXEC", "CRITICAL",
                "dep/Terminal", "readObject", "readObject", "java/lang/Runtime", "exec",
                List.of(
                        new ChainHop("dep/Terminal", "readObject", "java/lang/Runtime", "exec",
                                HopKind.DIRECT_CALL, null, "direct", sinkDesc, null),
                        new ChainHop("dep/Terminal", "readObject", "dep/Terminal", "readObject",
                                HopKind.ENTRY, null, "readObject", "()V", null)), 0,
                sinkDesc, "TERMINAL");
        bb.addChain(helperFront);
        bb.addChain(terminalBack);

        ChainComposerKnowledgeSource sourceKnowledge = new ChainComposerKnowledgeSource();
        sourceKnowledge.init(bb);
        sourceKnowledge.onEvent(bb, Event.of(EventType.SCAN_ANALYZED, -1, null));

        assertTrue(bb.chains().stream().anyMatch(chain ->
                        chain.entryClass().equals("app/Helper")
                                && chain.sinkClass().equals("java/lang/Runtime")
                                && chain.hops().stream().anyMatch(hop ->
                                "bridge-invoke".equals(hop.reason()))),
                "typed binding target must admit its callback front without a synthetic call edge: "
                        + bb.chains().stream().map(Chain::key).toList());
    }

    @Test
    void lookupBridgeJoinsOnlyADeclaredConstructibleFragment() {
        String lookupDesc = "(Ljava/lang/String;)Ljava/lang/Object;";
        Rule.SinkRule lookup = new Rule.SinkRule("lookup", "JNDI", "HIGH",
                new Rule.CallMatcher(Match.of("javax/naming/Context"), Match.of("lookup"),
                        Match.of(lookupDesc)), List.of(new Rule.TaintedPos.Arg(0)));
        Rule.SinkRule terminal = new Rule.SinkRule("templates", "CODE_EXEC", "HIGH",
                new Rule.CallMatcher(Match.of("com/sun/org/apache/xalan/internal/xsltc/trax/TemplatesImpl"),
                        Match.of("newTransformer"), Match.of("()Ljavax/xml/transform/Transformer;")),
                List.of(), Rule.SinkRole.TERMINAL);
        ObjectGraphPlan plan = new ObjectGraphPlan(List.of(
                new ObjectGraphPlan.Node("entry", "javax/swing/event/EventListenerList",
                        ObjectGraphPlan.NodeKind.ALLOCATE, List.of())), List.of());
        Rule.FragmentRule fragment = new Rule.FragmentRule("event-fragment",
                "javax/swing/event/EventListenerList", "toString", List.of(
                new Rule.HopSpec("javax/swing/undo/UndoManager", "toString", null)),
                "com/sun/org/apache/xalan/internal/xsltc/trax/TemplatesImpl", "newTransformer",
                "()Ljavax/xml/transform/Transformer;", plan);
        RuleSet rules = new RuleSet(List.of(lookup, terminal), List.of(), List.of(), List.of(),
                List.of(fragment));
        Blackboard bb = new Blackboard(new io.just.sast.cpg.graph.Graph(),
                new io.just.sast.analysis.hierarchy.ClassHierarchy(Map.of(), null),
                new io.just.sast.cpg.build.FieldWriterIndex(), rules, 20,
                Blackboard.ScanInputs.fastDefault(Path.of(".")));
        Chain front = new Chain("lookup", "JNDI", "HIGH", "app/User", "setUrl", "deserialize",
                "javax/naming/Context", "lookup", List.of(new ChainHop("app/User", "setUrl",
                "javax/naming/Context", "lookup", HopKind.DIRECT_CALL, null, "direct", lookupDesc,
                0)), 0, lookupDesc, "TERMINAL");
        Chain back = new Chain("templates", "CODE_EXEC", "HIGH",
                "javax/swing/event/EventListenerList", "toString", "toString",
                "com/sun/org/apache/xalan/internal/xsltc/trax/TemplatesImpl", "newTransformer",
                List.of(new ChainHop("javax/swing/event/EventListenerList", "toString",
                        "javax/swing/undo/UndoManager", "toString", HopKind.DIRECT_CALL,
                        null, "fragment", "()Ljava/lang/String;", null),
                        new ChainHop("javax/swing/event/EventListenerList", "toString",
                                "javax/swing/event/EventListenerList", "toString", HopKind.ENTRY,
                                null, "toString", "()Ljava/lang/String;", null)), 0,
                "()Ljavax/xml/transform/Transformer;", "TERMINAL", plan);
        bb.addChain(front);
        bb.addChain(back);

        // Typed sink/bridge rules belong to the event target; a stale owner with an empty
        // ruleset must not suppress a valid JNDI/RMI continuation.
        Blackboard staleOwner = new Blackboard(new io.just.sast.cpg.graph.Graph(),
                new io.just.sast.analysis.hierarchy.ClassHierarchy(Map.of(), null),
                new io.just.sast.cpg.build.FieldWriterIndex(), RuleSet.EMPTY, 20,
                Blackboard.ScanInputs.fastDefault(Path.of(".")));
        ChainComposerKnowledgeSource source = new ChainComposerKnowledgeSource();
        source.init(staleOwner);
        source.onEvent(bb,
                Event.of(EventType.SCAN_ANALYZED, -1, null));

        assertTrue(bb.chains().stream().anyMatch(chain ->
                        chain.entryClass().equals("app/User")
                                && chain.sinkClass().contains("TemplatesImpl")
                                && chain.hops().stream().anyMatch(hop ->
                                "bridge-jndi_rmi".equals(hop.reason()))),
                "JNDI lookup should bridge to the declared fragment only: "
                        + bb.chains().stream().map(Chain::key).toList());
    }

    @Test
    void boundedDirectoryDiscoveryFailsClosedAtSharedEntryLimit(@TempDir Path temp)
            throws Exception {
        Path root = temp.resolve("classes");
        Files.createDirectories(root.resolve("app"));
        Files.write(root.resolve("app/One.class"), new byte[] {1});
        Files.write(root.resolve("app/Two.class"), new byte[] {2});
        InputBudget defaults = InputBudget.defaults();
        InputBudget tiny = defaults.withArchiveLimits(defaults.maxPhysicalBytes(),
                defaults.maxCompressedBytes(), defaults.maxUncompressedBytes(),
                defaults.maxEntryBytes(), 2, defaults.maxArchiveNesting(),
                defaults.maxClassEntries());

        assertThrows(IOException.class,
                () -> ChainComposerKnowledgeSource.boundedPrimaryArtifactClasses(root, tiny),
                "directory discovery must charge root, directory and class entries to one tracker");
    }

    @Test
    void boundedArchiveDiscoveryRejectsUnsafeEntryBeforePriorityHint(@TempDir Path temp)
            throws Exception {
        Path jar = temp.resolve("target.jar");
        try (OutputStream output = Files.newOutputStream(jar);
             JarOutputStream archive = new JarOutputStream(output)) {
            archive.putNextEntry(new JarEntry("../escape.class"));
            archive.write(new byte[] {1});
            archive.closeEntry();
        }

        assertThrows(IOException.class,
                () -> ChainComposerKnowledgeSource.boundedPrimaryArtifactClasses(jar,
                        InputBudget.defaults()),
                "unsafe archive names must not influence source-host prioritisation");
    }

    @Test
    void boundedDiscoveryChargesCallerTrackerAcrossArtifacts(@TempDir Path temp)
            throws Exception {
        Path first = Files.createDirectories(temp.resolve("first").resolve("app"));
        Path second = Files.createDirectories(temp.resolve("second").resolve("app"));
        Files.write(first.resolve("One.class"), new byte[] {1});
        Files.write(second.resolve("Two.class"), new byte[] {2});
        InputBudget defaults = InputBudget.defaults();
        InputBudget tiny = defaults.withArchiveLimits(defaults.maxPhysicalBytes(),
                defaults.maxCompressedBytes(), defaults.maxUncompressedBytes(),
                defaults.maxEntryBytes(), 5, defaults.maxArchiveNesting(),
                defaults.maxClassEntries());
        InputBudget.Tracker tracker = tiny.tracker();

        assertTrue(ChainComposerKnowledgeSource.boundedPrimaryArtifactClasses(
                first.getParent(), tiny, tracker).contains("app/One"));
        assertThrows(IOException.class,
                () -> ChainComposerKnowledgeSource.boundedPrimaryArtifactClasses(
                        second.getParent(), tiny, tracker),
                "optional priority discovery must not reset the caller-owned aggregate budget");
    }

    @Test
    void replacedPrimaryArtifactDirectoryParentFailsClosed(@TempDir Path temp) throws Exception {
        Path parent = Files.createDirectory(temp.resolve("parent"));
        Path root = Files.createDirectory(parent.resolve("classes"));
        var snapshot = ChainComposerKnowledgeSource.snapshotPrimaryArtifactForContract(
                root, InputBudget.defaults());
        var before = Files.readAttributes(parent,
                java.nio.file.attribute.BasicFileAttributes.class,
                java.nio.file.LinkOption.NOFOLLOW_LINKS);
        org.junit.jupiter.api.Assumptions.assumeTrue(
                before.fileKey() != null || before.creationTime().toMillis() != 0L,
                "provider does not expose a stable directory identity");
        Files.delete(root);
        Files.delete(parent);
        Files.createDirectory(parent);
        Files.createDirectory(root);
        var after = Files.readAttributes(parent,
                java.nio.file.attribute.BasicFileAttributes.class,
                java.nio.file.LinkOption.NOFOLLOW_LINKS);
        org.junit.jupiter.api.Assumptions.assumeTrue(identityDiffers(before, after),
                "provider did not expose a replacement identity change");

        IOException failure = assertThrows(IOException.class,
                () -> ChainComposerKnowledgeSource.verifyPrimaryArtifactDirectoryForContract(
                        snapshot));
        assertTrue(failure.getMessage().contains("PRIMARY_ARTIFACT_CHANGED_DURING_READ"),
                failure.getMessage());
    }

    @Test
    void replacedPrimaryArtifactArchiveParentFailsClosed(@TempDir Path temp) throws Exception {
        Path parent = Files.createDirectory(temp.resolve("parent"));
        Path jar = parent.resolve("target.jar");
        try (OutputStream output = Files.newOutputStream(jar);
             JarOutputStream archive = new JarOutputStream(output)) {
            archive.putNextEntry(new JarEntry("app/One.class"));
            archive.write(new byte[] {1});
            archive.closeEntry();
        }
        var snapshot = ChainComposerKnowledgeSource.snapshotPrimaryArtifactFileForContract(
                jar, InputBudget.defaults());
        var before = Files.readAttributes(parent,
                java.nio.file.attribute.BasicFileAttributes.class,
                java.nio.file.LinkOption.NOFOLLOW_LINKS);
        org.junit.jupiter.api.Assumptions.assumeTrue(
                before.fileKey() != null || before.creationTime().toMillis() != 0L,
                "provider does not expose a stable directory identity");
        Files.delete(jar);
        Files.delete(parent);
        Files.createDirectory(parent);
        Files.write(parent.resolve("target.jar"), new byte[] {1});
        var after = Files.readAttributes(parent,
                java.nio.file.attribute.BasicFileAttributes.class,
                java.nio.file.LinkOption.NOFOLLOW_LINKS);
        org.junit.jupiter.api.Assumptions.assumeTrue(identityDiffers(before, after),
                "provider did not expose a replacement identity change");

        IOException failure = assertThrows(IOException.class,
                () -> ChainComposerKnowledgeSource.verifyPrimaryArtifactFileForContract(snapshot));
        assertTrue(failure.getMessage().contains("PRIMARY_ARTIFACT_CHANGED_DURING_READ"),
                failure.getMessage());
    }

    @Test
    void replacedPrimaryArtifactEntryFailsClosed(@TempDir Path temp) throws Exception {
        Path file = temp.resolve("Entry.class");
        Files.write(file, new byte[] {1, 2, 3});
        var before = Files.readAttributes(file,
                java.nio.file.attribute.BasicFileAttributes.class,
                java.nio.file.LinkOption.NOFOLLOW_LINKS);
        Files.write(file, new byte[] {1, 2, 3, 4, 5});

        IOException failure = assertThrows(IOException.class,
                () -> ChainComposerKnowledgeSource.verifyPrimaryArtifactEntryForContract(
                        file, before));
        assertTrue(failure.getMessage().contains("PRIMARY_ARTIFACT_CHANGED_DURING_READ"),
                failure::getMessage);
    }

    @Test
    void sourceHostedProducerPreservesTypedEndpointsBeforeAdmission() {
        String sinkDescriptor = "(Ljava/lang/String;)Ljava/lang/Process;";
        Chain back = new Chain("runtime-exec", "CODE_EXEC", "CRITICAL",
                "dep/Gadget", "hashCode", "hashCode", "java/lang/Runtime", "exec",
                List.of(
                        new ChainHop("dep/Gadget", "hashCode", "java/lang/Runtime", "exec",
                                HopKind.DIRECT_CALL, null, "terminal", sinkDescriptor, null),
                        new ChainHop("dep/Gadget", "hashCode", "dep/Gadget", "hashCode",
                                HopKind.ENTRY, null, "hashCode", "()I", null)), 2,
                sinkDescriptor, "TERMINAL");
        List<ChainHop> sourceHops = List.of(
                new ChainHop("dep/Gadget", "hashCode", "java/lang/Runtime", "exec",
                        HopKind.DIRECT_CALL, null, "bridge-trigger-src", sinkDescriptor, null),
                new ChainHop("app/Host", "deserialize", "dep/Gadget", "hashCode",
                        HopKind.VIRTUAL_DISPATCH, null, "bridge-source-deserialize", "()V", null),
                new ChainHop("app/Host", "deserialize", "app/Host", "deserialize",
                        HopKind.ENTRY, null, "source", "()V", null));

        AtomicBoolean hopsMaterialized = new AtomicBoolean();
        ChainComposerKnowledgeSource.SourceHostedProducer producer =
                ChainComposerKnowledgeSource.sourceHostedProducer(back, "app/Host", "deserialize",
                        "source", "()V", sourceHops.size(), true, () -> {
                            hopsMaterialized.set(true);
                            return sourceHops;
                        });

        assertNotNull(producer);
        assertFalse(hopsMaterialized.get(), "source-host hops must remain deferred before admission");
        var candidate = producer.candidate();
        assertEquals("runtime-exec", candidate.ruleId());
        assertEquals("CODE_EXEC", candidate.category());
        assertEquals("app/Host", candidate.entryOwner());
        assertEquals("deserialize", candidate.entryName());
        assertEquals("()V", candidate.entryDescriptor());
        assertEquals("source", candidate.entryKind());
        assertEquals("java/lang/Runtime", candidate.terminalOwner());
        assertEquals("exec", candidate.terminalName());
        assertEquals(sinkDescriptor, candidate.terminalDescriptor());
        assertEquals("TERMINAL", candidate.terminalRole());
        assertTrue(candidate.continuationEvidence());
        assertTrue(sourceHops.stream().anyMatch(hop ->
                "bridge-trigger-src".equals(hop.reason())));
        assertTrue(sourceHops.stream().anyMatch(hop ->
                "bridge-source-deserialize".equals(hop.reason())));
        assertFalse(hopsMaterialized.get(), "candidate inspection must not materialize source-host hops");
        assertNotNull(producer.materializer().get());
        assertTrue(hopsMaterialized.get(), "materializer should construct source-host hops on demand");

        AtomicBoolean materialized = new AtomicBoolean();
        Blackboard bb = new Blackboard(new io.just.sast.cpg.graph.Graph(),
                new io.just.sast.analysis.hierarchy.ClassHierarchy(Map.of(), null),
                new io.just.sast.cpg.build.FieldWriterIndex(), RuleSet.EMPTY, 20,
                new Blackboard.ScanInputs(Path.of("."), List.of(), false, false, 0, null, 0,
                        false, false, false, null, Set.of("app/Host"), true));
        assertFalse(bb.addSolverCandidate(candidate, () -> {
            materialized.set(true);
            return producer.materializer().get();
        }));
        assertEquals(1, bb.solverAdmissionMetrics().rejected());
        assertFalse(materialized.get(), "rejected source-host candidate must not materialize");
    }

    @Test
    void sourceHostedAdmissionUsesSuppliedBlackboardBeforeMaterialization() {
        Chain back = chain("runtime-exec", "CODE_EXEC", "dep/Gadget", "hashCode",
                "java/lang/Runtime", "exec");
        ChainComposerKnowledgeSource.SourceHostedProducer producer =
                ChainComposerKnowledgeSource.sourceHostedProducer(back, "dep/Host", "deserialize",
                        "source", "()V", 1, false, () -> List.of(new ChainHop(
                                "dep/Host", "deserialize", "dep/Host", "deserialize",
                                HopKind.ENTRY, null, "source", "()V", null)));
        assertNotNull(producer);

        AtomicBoolean materialized = new AtomicBoolean();
        Blackboard blackboard = new Blackboard(new io.just.sast.cpg.graph.Graph(),
                new io.just.sast.analysis.hierarchy.ClassHierarchy(Map.of(), null),
                new io.just.sast.cpg.build.FieldWriterIndex(), RuleSet.EMPTY, 20,
                new Blackboard.ScanInputs(Path.of("."), List.of(), false, false, 0, null, 0,
                        false, false, false, null, Set.of("app/Host"), true));
        ChainComposerKnowledgeSource source = new ChainComposerKnowledgeSource();

        assertFalse(source.admitSourceHosted(blackboard, producer, () -> {
            materialized.set(true);
            return producer.materializer().get();
        }));
        assertFalse(materialized.get(), "rejected source-host candidate must not materialize");
    }

    @Test
    void sourceHostedAdmissionRejectsDeferredPolicyBeforeMaterialization() {
        String appOwner = "app/Entry";
        String appDescriptor = "()V";
        String hostOwner = "dep/Host";
        String hostDescriptor = "()V";
        String sinkOwner = "java/lang/Runtime";
        String sinkName = "exec";
        String sinkDescriptor = "(Ljava/lang/String;)Ljava/lang/Process;";
        Graph graph = new Graph();
        graph.methodNode(appOwner, "handle", appDescriptor, false);
        Node host = graph.methodNode(hostOwner, "deserialize", hostDescriptor, false);
        Node runtime = graph.methodNode(sinkOwner, sinkName, sinkDescriptor, true);
        Node hostCall = graph.addCallNode(hostOwner, "deserialize", hostDescriptor, "VIRTUAL",
                null, 0, appOwner, "handle", appDescriptor);
        graph.addEdge(hostCall, host, EdgeType.INVOKES, "VIRTUAL");
        Node sinkCall = graph.addCallNode(sinkOwner, sinkName, sinkDescriptor, "VIRTUAL",
                null, 0, hostOwner, "deserialize", hostDescriptor);
        graph.addEdge(sinkCall, runtime, EdgeType.INVOKES, "VIRTUAL");
        graph.freeze();

        Rule.SinkRule sink = new Rule.SinkRule("runtime-exec", "CODE_EXEC", "CRITICAL",
                new Rule.CallMatcher(Match.of(sinkOwner), Match.of(sinkName),
                        Match.of(sinkDescriptor)), List.of(), Rule.SinkRole.TERMINAL);
        Rule.MagicEntryRule entry = new Rule.MagicEntryRule("app-entry", "http",
                new Rule.MethodMatcher(Match.of("handle"), Match.of(appDescriptor), false), null,
                "lifecycle");
        RuleSet rules = new RuleSet(List.of(sink), List.of(entry), List.of(), List.of(), List.of());
        Blackboard target = new Blackboard(graph,
                new io.just.sast.analysis.hierarchy.ClassHierarchy(Map.of(), null),
                new io.just.sast.cpg.build.FieldWriterIndex(), rules, 20,
                new Blackboard.ScanInputs(Path.of("."), List.of(), false, false, 0, null, 0,
                        false, false, false, null, Set.of(appOwner), true));
        Chain back = chain("runtime-exec", "CODE_EXEC", "dep/Gadget", "readObject",
                sinkOwner, sinkName);
        ChainComposerKnowledgeSource.SourceHostedProducer producer =
                ChainComposerKnowledgeSource.sourceHostedProducer(back, hostOwner, "deserialize",
                        "source", hostDescriptor, 1, false,
                        () -> List.of(new ChainHop(hostOwner, "deserialize", hostOwner,
                                "deserialize", HopKind.ENTRY, null, "source", hostDescriptor, null)));
        assertNotNull(producer);
        assertEquals(ApplicationEntryIndex.ProducerAdmissionStatus.DEPENDENCY_SUFFIX,
                target.applicationEntryIndex().producerAdmission(producer.candidate()).status());

        AtomicBoolean materialized = new AtomicBoolean();
        assertFalse(new ChainComposerKnowledgeSource().admitSourceHosted(target, producer, () -> {
            materialized.set(true);
            return producer.materializer().get();
        }));
        assertFalse(materialized.get(),
                "a deferred source-host endpoint must not cross the eager composition boundary");
        assertTrue(target.compatibilityDependencySuffixChains().isEmpty());
    }

    @Test
    void composedProducerDoesNotMaterializeBeforeTypedAdmission() {
        Chain front = new Chain("reflective-front", "REFLECTIVE_INVOKE", "HIGH",
                "dep/Front", "process", "source", "java/lang/reflect/Method", "invoke",
                List.of(new ChainHop("dep/Front", "process", "java/lang/reflect/Method", "invoke",
                        HopKind.DIRECT_CALL, null, "reflect", "()Ljava/lang/Object;", null),
                        new ChainHop("dep/Front", "process", "dep/Front", "process",
                                HopKind.ENTRY, null, "source", "()V", null)), 0);
        Chain back = chain("runtime-exec", "CODE_EXEC", "dep/Back", "hashCode",
                "java/lang/Runtime", "exec");

        ChainComposerKnowledgeSource.ComposedProducer producer =
                new ChainComposerKnowledgeSource().composedProducer(
                        front, back, ChainComposerKnowledgeSource.Bridge.INVOKE);

        assertNotNull(producer);
        AtomicBoolean materialized = new AtomicBoolean();
        Blackboard bb = new Blackboard(new io.just.sast.cpg.graph.Graph(),
                new io.just.sast.analysis.hierarchy.ClassHierarchy(Map.of(), null),
                new io.just.sast.cpg.build.FieldWriterIndex(), RuleSet.EMPTY, 20,
                new Blackboard.ScanInputs(Path.of("."), List.of(), false, false, 0, null, 0,
                        false, false, false, null, Set.of("app/Host"), true));

        assertFalse(bb.addSolverCandidate(producer.candidate(), () -> {
            materialized.set(true);
            return producer.materializer().get();
        }));
        assertEquals(1, bb.solverAdmissionMetrics().rejected());
        assertFalse(materialized.get(), "rejected composed candidate must not materialize");
    }

    @Test
    void composedAdmissionRejectsDeferredPolicyBeforeMaterialization() {
        Blackboard target = deferredPolicyBlackboard();
        Chain front = new Chain("front", "REFLECTIVE_INVOKE", "HIGH", "dep/Host",
                "deserialize", "source", "java/lang/reflect/Method", "invoke",
                List.of(new ChainHop("dep/Host", "deserialize", "java/lang/reflect/Method",
                                "invoke", HopKind.DIRECT_CALL, null, "reflect", "()V", null),
                        new ChainHop("dep/Host", "deserialize", "dep/Host", "deserialize",
                                HopKind.ENTRY, null, "source", "()V", null)), 0);
        Chain back = chain("runtime-exec", "CODE_EXEC", "dep/Gadget", "readObject",
                "java/lang/Runtime", "exec");
        ChainComposerKnowledgeSource source = new ChainComposerKnowledgeSource();
        ChainComposerKnowledgeSource.ComposedProducer producer = source.composedProducer(
                front, back, ChainComposerKnowledgeSource.Bridge.INVOKE);
        assertNotNull(producer);
        assertEquals(ApplicationEntryIndex.ProducerAdmissionStatus.DEPENDENCY_SUFFIX,
                target.applicationEntryIndex().producerAdmission(producer.candidate()).status());

        AtomicBoolean materialized = new AtomicBoolean();
        assertNull(source.admitComposed(target, new ChainComposerKnowledgeSource.ComposedProducer(
                producer.candidate(), () -> {
                    materialized.set(true);
                    return producer.materializer().get();
                })));
        assertFalse(materialized.get(),
                "a deferred composed endpoint must not cross an eager composition boundary");
        assertTrue(target.compatibilityDependencySuffixChains().isEmpty());
    }

    @Test
    void lazyCompositionProducerMaterializersAreSharedAcrossRepeatedReads() {
        ApplicationEntryIndex.ProducerCandidate candidate =
                new ApplicationEntryIndex.ProducerCandidate("runtime-exec", "CODE_EXEC", "HIGH",
                        "app/Host", "deserialize", "()V", "source", "java/lang/Runtime",
                        "exec", "(Ljava/lang/String;)Ljava/lang/Process;", "TERMINAL", null,
                        false);
        Chain expected = chain("runtime-exec", "CODE_EXEC", "app/Host", "source",
                "java/lang/Runtime", "exec");

        AtomicInteger sourceCalls = new AtomicInteger();
        ChainComposerKnowledgeSource.SourceHostedProducer sourceProducer =
                new ChainComposerKnowledgeSource.SourceHostedProducer(candidate, () -> {
                    sourceCalls.incrementAndGet();
                    return expected;
                });
        assertSame(expected, sourceProducer.materializer().get());
        assertSame(expected, sourceProducer.materializer().get());
        assertEquals(1, sourceCalls.get());

        AtomicInteger composedCalls = new AtomicInteger();
        ChainComposerKnowledgeSource.ComposedProducer composedProducer =
                new ChainComposerKnowledgeSource.ComposedProducer(candidate, () -> {
                    composedCalls.incrementAndGet();
                    return expected;
                });
        assertSame(expected, composedProducer.materializer().get());
        assertSame(expected, composedProducer.materializer().get());
        assertEquals(1, composedCalls.get());
    }

    private static boolean identityDiffers(
            java.nio.file.attribute.BasicFileAttributes before,
            java.nio.file.attribute.BasicFileAttributes after) {
        if (before.fileKey() != null || after.fileKey() != null) {
            return before.fileKey() == null || after.fileKey() == null
                    || !before.fileKey().equals(after.fileKey());
        }
        return !before.creationTime().equals(after.creationTime());
    }

    private static Blackboard deferredPolicyBlackboard() {
        String appOwner = "app/Entry";
        String appDescriptor = "()V";
        String hostOwner = "dep/Host";
        String hostDescriptor = "()V";
        String sinkOwner = "java/lang/Runtime";
        String sinkName = "exec";
        String sinkDescriptor = "(Ljava/lang/String;)Ljava/lang/Process;";
        Graph graph = new Graph();
        graph.methodNode(appOwner, "handle", appDescriptor, false);
        Node host = graph.methodNode(hostOwner, "deserialize", hostDescriptor, false);
        Node runtime = graph.methodNode(sinkOwner, sinkName, sinkDescriptor, true);
        Node hostCall = graph.addCallNode(hostOwner, "deserialize", hostDescriptor, "VIRTUAL",
                null, 0, appOwner, "handle", appDescriptor);
        graph.addEdge(hostCall, host, EdgeType.INVOKES, "VIRTUAL");
        Node sinkCall = graph.addCallNode(sinkOwner, sinkName, sinkDescriptor, "VIRTUAL",
                null, 0, hostOwner, "deserialize", hostDescriptor);
        graph.addEdge(sinkCall, runtime, EdgeType.INVOKES, "VIRTUAL");
        graph.freeze();
        Rule.SinkRule sink = new Rule.SinkRule("runtime-exec", "CODE_EXEC", "CRITICAL",
                new Rule.CallMatcher(Match.of(sinkOwner), Match.of(sinkName),
                        Match.of(sinkDescriptor)), List.of(), Rule.SinkRole.TERMINAL);
        Rule.MagicEntryRule entry = new Rule.MagicEntryRule("app-entry", "http",
                new Rule.MethodMatcher(Match.of("handle"), Match.of(appDescriptor), false), null,
                "lifecycle");
        RuleSet rules = new RuleSet(List.of(sink), List.of(entry), List.of(), List.of(), List.of());
        return new Blackboard(graph,
                new io.just.sast.analysis.hierarchy.ClassHierarchy(Map.of(), null),
                new io.just.sast.cpg.build.FieldWriterIndex(), rules, 20,
                new Blackboard.ScanInputs(Path.of("."), List.of(), false, false, 0, null, 0,
                        false, false, false, null, Set.of(appOwner), true));
    }
}
