package io.just.sast.analysis.taint;

import io.just.sast.analysis.hierarchy.ClassHierarchy;
import io.just.sast.config.RuleEngine;
import io.just.sast.config.RuleSet;
import io.just.sast.cpg.build.BuiltCpg;
import io.just.sast.cpg.build.CpgBuilder;
import io.just.sast.cpg.graph.Graph;
import io.just.sast.cpg.graph.Node;
import io.just.sast.cpg.graph.NodeType;
import io.just.sast.frontend.asm.FactsExtractor;
import io.just.sast.model.ClassInfo;
import io.just.sast.model.LoadResult;
import io.just.sast.model.MethodInfo;
import io.just.sast.model.Op;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;
import org.objectweb.asm.Type;

import java.lang.reflect.Modifier;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Regression contracts for local feasibility and opaque callback edges.
 *
 * <p>The fixtures are assembled from ASM nodes in memory.  They intentionally do not depend on
 * the ignored benchmark directory, so the same semantic checks run in a clean CI checkout.</p>
 */
class OriginSupportFeasibilityTest {

    @Test
    void constantBranchMakesSinkPathUnreachable() {
        MethodInfo method = constantBranchMethod();
        assertTrue(emptySupport().sinkPathProvablyUnreachable(method, 2),
                "a known IFEQ branch must remove only the impossible normal edge");
    }

    @Test
    void branchTruthUsesTheSameAbstractStateAsTheSinkGuard() throws Exception {
        OriginSupport support = emptySupport();
        MethodInfo method = constantBranchMethod();
        ForwardOrigins.Result state = support.origins().compute(method);
        var branchTruth = OriginSupport.class.getDeclaredMethod("knownBranchResult",
                MethodInfo.class, ForwardOrigins.Result.class, io.just.sast.model.InsnFact.class);
        branchTruth.setAccessible(true);

        assertEquals(Boolean.TRUE, branchTruth.invoke(support, method, state, method.insnAt(1)),
                "the feasibility pass must fold the same constant branch used by sink pruning");
    }

    @Test
    void nativeCallbackUsesExplicitJniHop() {
        String owner = "fixture/NativeBridge";
        MethodInfo nativeMethod = emptyMethod(owner, "invokeNative", "()V",
                Modifier.PUBLIC | Modifier.NATIVE);
        MethodInfo callback = emptyMethod(owner, "onCallback", "()V", Modifier.PUBLIC);
        ClassInfo bridge = new ClassInfo(owner, "java/lang/Object", List.of(), Modifier.PUBLIC,
                List.of(nativeMethod, callback), List.of());
        ClassHierarchy hierarchy = new ClassHierarchy(Map.of(owner, bridge), null);

        Graph graph = new Graph();
        graph.methodNode(owner, nativeMethod.name(), nativeMethod.descriptor(), false);
        graph.methodNode(owner, callback.name(), callback.descriptor(), false);
        Node nativeCall = graph.addCallNode(owner, nativeMethod.name(), nativeMethod.descriptor(),
                "VIRTUAL", null, 0, "fixture/Host", "run", "()V");
        graph.freeze();

        OriginSupport support = new OriginSupport(graph, hierarchy,
                new RuleEngine(RuleSet.EMPTY, hierarchy), false);

        assertEquals(List.of(nativeCall), support.nativeCallbackSitesOf(callback));
        assertTrue(support.nativeCallbackSite(nativeCall, callback),
                "the same-receiver native callback must remain an explicit bounded edge");
    }

    @Test
    void methodCollectionReflectiveInvokeRecognizesTypedIteratorElement() {
        MethodNode method = new MethodNode(0, "run",
                "(Ljava/util/Iterator;Ljava/lang/Object;)Ljava/lang/Object;", null, null);
        method.instructions.add(new VarInsnNode(Op.ALOAD.code(), 1));
        method.instructions.add(new MethodInsnNode(Op.INVOKEINTERFACE.code(), "java/util/Iterator",
                "next", "()Ljava/lang/Object;", true));
        method.instructions.add(new TypeInsnNode(Op.CHECKCAST.code(), "java/lang/reflect/Method"));
        method.instructions.add(new VarInsnNode(Op.ALOAD.code(), 2));
        method.instructions.add(new InsnNode(Op.ACONST_NULL.code()));
        method.instructions.add(new MethodInsnNode(Op.INVOKEVIRTUAL.code(), "java/lang/reflect/Method",
                "invoke", "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;", false));
        method.instructions.add(new InsnNode(Op.ARETURN.code()));

        MethodInfo methodInfo = extract(method);
        ClassInfo host = new ClassInfo(methodInfo.owner(), "java/lang/Object", List.of(), Modifier.PUBLIC,
                List.of(methodInfo), List.of());
        LoadResult load = new LoadResult(Map.of(host.internalName(), host), List.of(), 1, 61);
        BuiltCpg cpg = new CpgBuilder().build(load);
        cpg.graph().freeze();
        ClassHierarchy hierarchy = new ClassHierarchy(load.classes(), null);
        OriginSupport support = new OriginSupport(cpg.graph(), hierarchy,
                new RuleEngine(RuleSet.EMPTY, hierarchy), false, cpg.index());
        Node invoke = cpg.graph().nodesOfType(NodeType.CALL).stream()
                .filter(node -> "java/lang/reflect/Method".equals(node.owner())
                        && "invoke".equals(node.name()))
                .findFirst()
                .orElseThrow();

        assertTrue(support.methodCollectionReflectiveInvokeSite(invoke),
                "a Method receiver obtained through Iterator.next and CHECKCAST must be recognized");
    }

    @Test
    void zeroArgumentReflectiveLookupRecoversEmptyClassArrayDescriptor() throws Exception {
        MethodNode method = new MethodNode(Modifier.PUBLIC | Modifier.STATIC, "run", "()V", null, null);
        method.instructions.add(new LdcInsnNode(Type.getObjectType("fixture/Target")));
        method.instructions.add(new LdcInsnNode("ping"));
        method.instructions.add(new InsnNode(Op.ICONST_0.code()));
        method.instructions.add(new TypeInsnNode(Op.ANEWARRAY.code(), "java/lang/Class"));
        method.instructions.add(new MethodInsnNode(Op.INVOKEVIRTUAL.code(), "java/lang/Class",
                "getMethod", "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;", false));
        method.instructions.add(new InsnNode(Op.POP.code()));
        method.instructions.add(new InsnNode(Op.RETURN.code()));

        MethodInfo hostMethod = extract("fixture/Host", method);
        MethodInfo targetMethod = emptyMethod("fixture/Target", "ping", "()V", Modifier.PUBLIC);
        ClassInfo host = new ClassInfo("fixture/Host", "java/lang/Object", List.of(), Modifier.PUBLIC,
                List.of(hostMethod), List.of());
        ClassInfo target = new ClassInfo("fixture/Target", "java/lang/Object", List.of(), Modifier.PUBLIC,
                List.of(targetMethod), List.of());
        LoadResult load = new LoadResult(Map.of(host.internalName(), host, target.internalName(), target),
                List.of(), 2, 61);
        BuiltCpg cpg = new CpgBuilder().build(load);
        cpg.graph().freeze();
        ClassHierarchy hierarchy = new ClassHierarchy(load.classes(), null);
        OriginSupport support = new OriginSupport(cpg.graph(), hierarchy,
                new RuleEngine(RuleSet.EMPTY, hierarchy), false, cpg.index());
        var lookup = hostMethod.instructions().stream()
                .filter(insn -> insn.op() == Op.INVOKEVIRTUAL
                        && insn.methodRef() != null
                        && "getMethod".equals(insn.methodRef().name()))
                .findFirst().orElseThrow();
        var descriptor = OriginSupport.class.getDeclaredMethod("reflectiveParameterDescriptor",
                MethodInfo.class, io.just.sast.model.InsnFact.class, io.just.sast.model.MethodRef.class);
        descriptor.setAccessible(true);

        assertEquals("()V", descriptor.invoke(support, hostMethod, lookup, lookup.methodRef()),
                "Class.getMethod(name) 的空 Class[] 必须恢复为零参数方法描述符");
    }

    @Test
    void indexesSerializableInvocationHandlerForExternallyAssembledProxy() {
        String handlerOwner = "fixture/ExternalHandler";
        String descriptor = OriginSupport.SERIALIZED_PROXY_HANDLER_DESCRIPTOR;
        MethodNode method = new MethodNode(Modifier.PUBLIC, "invoke", descriptor, null, null);
        method.instructions.add(new InsnNode(Op.ACONST_NULL.code()));
        method.instructions.add(new InsnNode(Op.ARETURN.code()));
        MethodInfo handlerMethod = extract(handlerOwner, method);
        ClassInfo handler = new ClassInfo(handlerOwner, "java/lang/Object",
                List.of("java/lang/reflect/InvocationHandler", "java/io/Serializable"),
                Modifier.PUBLIC | Modifier.FINAL, List.of(handlerMethod), List.of());

        Graph graph = new Graph();
        Node methodNode = graph.methodNode(handlerOwner, "invoke", descriptor, false);
        graph.freeze();
        ClassHierarchy hierarchy = new ClassHierarchy(Map.of(handlerOwner, handler), null);
        OriginSupport support = new OriginSupport(graph, hierarchy,
                new RuleEngine(RuleSet.EMPTY, hierarchy), false);

        assertTrue(support.isSerializedProxyHandler(handlerMethod));
        assertEquals(List.of(methodNode), support.serializedProxyHandlerMethods(),
                "serialized proxy callbacks must be indexed without requiring Proxy.newProxyInstance");
    }

    private static OriginSupport emptySupport() {
        Graph graph = new Graph();
        graph.freeze();
        ClassHierarchy hierarchy = new ClassHierarchy(Map.of(), null);
        return new OriginSupport(graph, hierarchy, new RuleEngine(RuleSet.EMPTY, hierarchy), false);
    }

    private static MethodInfo constantBranchMethod() {
        LabelNode taken = new LabelNode();
        MethodNode method = new MethodNode(0, "guard", "()V", null, null);
        method.instructions.add(new InsnNode(Op.ICONST_0.code()));
        method.instructions.add(new JumpInsnNode(Op.IFEQ.code(), taken));
        method.instructions.add(new InsnNode(Op.NOP.code()));
        method.instructions.add(new InsnNode(Op.RETURN.code()));
        method.instructions.add(taken);
        method.instructions.add(new InsnNode(Op.RETURN.code()));
        return extract(method);
    }

    private static MethodInfo emptyMethod(String owner, String name, String descriptor, int access) {
        return new MethodInfo(owner, name, descriptor, access, List.of(), List.of(), false);
    }

    private static MethodInfo extract(MethodNode method) {
        return extract("fixture/Host", method);
    }

    private static MethodInfo extract(String owner, MethodNode method) {
        ClassNode node = new ClassNode();
        node.name = owner;
        node.superName = "java/lang/Object";
        node.methods.add(method);
        return new FactsExtractor().extract(node).methods().get(0);
    }
}
