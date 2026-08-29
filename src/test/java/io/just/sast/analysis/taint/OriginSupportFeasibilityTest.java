package io.just.sast.analysis.taint;

import io.just.sast.analysis.callgraph.CallGraphBuilder;
import io.just.sast.analysis.hierarchy.ClassHierarchy;
import io.just.sast.blackboard.Blackboard;
import io.just.sast.config.RuleEngine;
import io.just.sast.config.RuleSet;
import io.just.sast.config.YamlRuleLoader;
import io.just.sast.cpg.build.BuiltCpg;
import io.just.sast.cpg.build.CpgBuilder;
import io.just.sast.cpg.graph.Node;
import io.just.sast.cpg.graph.NodeType;
import io.just.sast.frontend.asm.BytecodeFrontend;
import io.just.sast.frontend.asm.JrtClassSource;
import io.just.sast.model.InsnFact;
import io.just.sast.model.LoadResult;
import io.just.sast.model.MethodInfo;
import io.just.sast.model.Op;
import io.just.sast.knowledge.backward.BackwardTaintAnalysis;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertTrue;

/** Regression contracts for the exact local-feasibility pass used to remove impossible sinks. */
class OriginSupportFeasibilityTest {

    @Test
    void metadataLengthGuardIsProvedFromClassModel() throws Exception {
        Fixture fixture = fixture("benchmark/Gleipner/chains/target/gleipner.chains-1.0-reflection-metaobjects.jar");
        MethodInfo method = fixture.load.classes()
                .get("gleipner/chains/reflection/metaobjects/MetaObjects_004_FP_Trampoline")
                .method("hashCode", "()I");

        Node sink = fixture.cpg.graph().nodesOfType(NodeType.CALL).stream()
                .filter(node -> "gleipner/core/SinkGadget".equals(node.owner())
                        && "sinkMethod".equals(node.name())
                        && "gleipner/chains/reflection/metaobjects/MetaObjects_004_FP_Trampoline"
                        .equals(node.methodOwner()))
                .findFirst()
                .orElseThrow();

        assertTrue(fixture.support.sinkPathProvablyUnreachable(method, sink.offset()),
                "getInterfaces().length == 1 is false for a class with no direct interfaces");
    }

    @Test
    void branchTruthUsesTheSameAbstractStateAsTheSinkGuard() throws Exception {
        Fixture fixture = fixture("benchmark/Gleipner/chains/target/gleipner.chains-1.0-reflection-metaobjects.jar");
        MethodInfo method = fixture.load.classes()
                .get("gleipner/chains/reflection/metaobjects/MetaObjects_004_FP_Trampoline")
                .method("hashCode", "()I");
        ForwardOrigins.Result state = fixture.support.origins().compute(method);
        Method branchTruth = OriginSupport.class.getDeclaredMethod("knownBranchResult",
                MethodInfo.class, ForwardOrigins.Result.class, InsnFact.class);
        branchTruth.setAccessible(true);

        boolean sawKnownTrue = false;
        for (InsnFact insn : method.instructions()) {
            if (!insn.op().isCondJump()) {
                continue;
            }
            Object value = branchTruth.invoke(fixture.support, method, state, insn);
            if (Boolean.TRUE.equals(value)) {
                sawKnownTrue = true;
                break;
            }
        }
        assertTrue(sawKnownTrue, "the metadata guard must be folded to the non-sink branch");
    }

    @Test
    void typedMethodCollectionMapsReflectiveReceiverToTargetMethod() throws Exception {
        Fixture fixture = fixture("benchmark/Gleipner/chains/target/gleipner.chains-1.0-ysoserial-vaadin.jar",
                "benchmark/Gleipner/just-rules.yaml");
        Blackboard bb = new Blackboard(fixture.cpg.graph(), fixture.hierarchy, fixture.cpg.fieldWriters(),
                fixture.rules, 20, new Blackboard.ScanInputs(Path.of("vaadin.jar"), java.util.List.of(),
                false, false, 20));
        var backward = new BackwardTaintAnalysis();
        backward.init(bb);
        var closure = bb.originSupport().entryDownstream(fixture.cpg.graph());
        assertTrue(closure.contains("gleipner/chains/ysoserial/vaadin1/Vaadin_Getter_SinkGadget#getOutputProperties()Ljava/lang/String;"));
        assertTrue(closure.contains("gleipner/chains/ysoserial/vaadin1/Vaadin_NestedMethodProperty#getValue()Ljava/lang/Object;"));
        var getter = fixture.load.classes()
                .get("gleipner/chains/ysoserial/vaadin1/Vaadin_Getter_SinkGadget")
                .method("getOutputProperties", "()Ljava/lang/String;");
        backward.onEvent(bb, io.just.sast.blackboard.Event.of(
                io.just.sast.blackboard.EventType.SCAN_START, -1, null));
        assertTrue(bb.chains().stream().anyMatch(chain ->
                "gleipner/chains/ysoserial/vaadin1/Vaadin_PropertySetItem".equals(chain.entryClass())
                        && "gleipner/core/SinkGadget".equals(chain.sinkClass())));
    }

    @Test
    void nativeCallbackUsesExplicitJniHop() throws Exception {
        Fixture fixture = fixture("benchmark/Gleipner/chains/target/gleipner.chains-1.0-jni.jar",
                "benchmark/Gleipner/just-rules.yaml");
        Blackboard bb = new Blackboard(fixture.cpg.graph(), fixture.hierarchy, fixture.cpg.fieldWriters(),
                fixture.rules, 20, new Blackboard.ScanInputs(Path.of("jni.jar"), java.util.List.of(),
                false, false, 20));
        MethodInfo target = fixture.load.classes().get("gleipner/chains/jni/Custom001Trampoline")
                .method("target", "()V");
        assertTrue(bb.originSupport().nativeCallbackSitesOf(target).size() == 1,
                () -> bb.originSupport().nativeCallbackSitesOf(target).toString());
        assertTrue(bb.originSupport().nativeCallbackSite(
                bb.originSupport().nativeCallbackSitesOf(target).get(0), target));
        var backward = new BackwardTaintAnalysis();
        backward.init(bb);
        backward.onEvent(bb, io.just.sast.blackboard.Event.of(
                io.just.sast.blackboard.EventType.SCAN_START, -1, null));
        assertTrue(bb.chains().stream().anyMatch(chain ->
                chain.entryClass().equals("gleipner/chains/jni/Custom001Trampoline")
                        && chain.hops().stream().anyMatch(hop -> hop.kind() == io.just.sast.blackboard.HopKind.NATIVE_CALLBACK)),
                () -> bb.chains().toString());
    }

    private static Fixture fixture(String jar) throws Exception {
        return fixture(jar, "src/main/resources/rules/default-rules.yaml");
    }

    private static Fixture fixture(String jar, String rulesPath) throws Exception {
        BytecodeFrontend frontend = new BytecodeFrontend();
        LoadResult load = frontend.loadStreaming(java.util.List.of(Path.of(jar)));
        JrtClassSource jdk = JrtClassSource.runtime();
        ClassHierarchy hierarchy = new ClassHierarchy(load.classes(), jdk);
        BuiltCpg cpg = new CpgBuilder().build(load);
        new CallGraphBuilder(hierarchy).build(cpg.graph());
        cpg.graph().freeze();
        RuleSet rules;
        try (InputStream in = Files.newInputStream(Path.of(rulesPath))) {
            rules = new YamlRuleLoader().load(in);
        }
        RuleEngine engine = new RuleEngine(rules, hierarchy);
        return new Fixture(load, cpg, hierarchy, rules, new OriginSupport(cpg.graph(), hierarchy, engine, false));
    }

    private record Fixture(LoadResult load, BuiltCpg cpg, ClassHierarchy hierarchy, RuleSet rules,
                           OriginSupport support) {
    }
}
