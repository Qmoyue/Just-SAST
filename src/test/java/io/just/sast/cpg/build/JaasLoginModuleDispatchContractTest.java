package io.just.sast.cpg.build;

import io.just.sast.analysis.callgraph.CallGraphBuilder;
import io.just.sast.analysis.hierarchy.ClassHierarchy;
import io.just.sast.cpg.graph.EdgeType;
import io.just.sast.cpg.graph.Graph;
import io.just.sast.frontend.asm.FactsExtractor;
import io.just.sast.frontend.asm.JrtClassSource;
import io.just.sast.model.ClassInfo;
import io.just.sast.model.JaasLoginModuleCallSite;
import io.just.sast.model.JaasLoginModuleDispatch;
import io.just.sast.model.JdkClassSource;
import io.just.sast.model.LoadResult;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JaasLoginModuleDispatchContractTest {

    @Test
    void runtimeJrtResolvesActualJndiLoginModuleMethodsAndAddsTypedEdges() {
        Fixture fixture = fixture();
        try (JrtClassSource source = JrtClassSource.runtime()) {
            int edges = new CallGraphBuilder(new ClassHierarchy(fixture.load().classes(), source))
                    .build(fixture.graph());

            assertEquals(4, edges);
            assertResolved(fixture.call(JaasLoginModuleCallSite.INITIALIZE_NAME,
                    JaasLoginModuleCallSite.INITIALIZE_DESCRIPTOR),
                    JaasLoginModuleDispatch.Source.JDK_IMAGE);
            assertResolved(fixture.call(JaasLoginModuleCallSite.LOGIN_NAME,
                    JaasLoginModuleCallSite.LOGIN_DESCRIPTOR),
                    JaasLoginModuleDispatch.Source.JDK_IMAGE);
        }
    }

    @Test
    void missingJdkSourceKeepsLoginModuleCapabilityWithoutConcreteEdge() {
        Fixture fixture = fixture();
        new CallGraphBuilder(new ClassHierarchy(fixture.load().classes(), null))
                .build(fixture.graph());

        for (var call : fixture.lifecycleCalls()) {
            JaasLoginModuleDispatch dispatch = dispatch(call);
            assertEquals(JaasLoginModuleDispatch.Status.CLASS_NOT_RESOLVED, dispatch.status());
            assertEquals(JaasLoginModuleDispatch.Source.UNKNOWN, dispatch.source());
            assertTrue(call.out().stream().noneMatch(edge -> edge.type() == EdgeType.DISPATCHES
                    && JaasLoginModuleDispatch.TARGET_CLASS.equals(edge.to().owner())));
        }
    }

    @Test
    void abstractInitialJndiLoginModuleRemainsCapabilityOnly() {
        Fixture fixture = fixture();
        ClassInfo abstractTarget = extract(abstractJndiLoginModuleBytes());
        try (JrtClassSource source = JrtClassSource.runtime()) {
            ClassHierarchy hierarchy = new ClassHierarchy(
                    Map.of(fixture.host().internalName(), fixture.host(),
                            abstractTarget.internalName(), abstractTarget), source);
            new CallGraphBuilder(hierarchy).build(fixture.graph());
        }

        for (var call : fixture.lifecycleCalls()) {
            JaasLoginModuleDispatch dispatch = dispatch(call);
            assertEquals(JaasLoginModuleDispatch.Status.INTERFACE_OR_ABSTRACT,
                    dispatch.status());
            assertFalse(dispatch.resolved());
            assertTrue(call.out().stream().noneMatch(edge -> edge.type() == EdgeType.DISPATCHES
                    && JaasLoginModuleDispatch.TARGET_CLASS.equals(edge.to().owner())));
        }
    }

    @Test
    void initialClassWithTheNameButWrongTypeIsNotTreatedAsLoginModule() {
        Fixture fixture = fixture();
        ClassInfo unrelatedTarget = extract(unrelatedJndiLoginModuleBytes());
        try (JrtClassSource source = JrtClassSource.runtime()) {
            ClassHierarchy hierarchy = new ClassHierarchy(
                    Map.of(fixture.host().internalName(), fixture.host(),
                            unrelatedTarget.internalName(), unrelatedTarget), source);
            new CallGraphBuilder(hierarchy).build(fixture.graph());
        }

        for (var call : fixture.lifecycleCalls()) {
            JaasLoginModuleDispatch dispatch = dispatch(call);
            assertEquals(JaasLoginModuleDispatch.Status.NOT_LOGIN_MODULE, dispatch.status());
            assertFalse(dispatch.resolved());
        }
    }

    @Test
    void classBytesWithoutJdkProvenanceCannotCreateConcreteEdge() {
        Fixture fixture = fixture();
        ClassInfo target = extract(abstractJndiLoginModuleBytes());
        JdkClassSource source = internalName ->
                JaasLoginModuleDispatch.TARGET_CLASS.equals(internalName) ? target : null;
        new CallGraphBuilder(new ClassHierarchy(fixture.load().classes(), source))
                .build(fixture.graph());

        for (var call : fixture.lifecycleCalls()) {
            JaasLoginModuleDispatch dispatch = dispatch(call);
            assertEquals(JaasLoginModuleDispatch.Status.SOURCE_NOT_PROVABLE,
                    dispatch.status());
            assertEquals(JaasLoginModuleDispatch.Source.UNKNOWN, dispatch.source());
            assertFalse(dispatch.resolved());
        }
    }

    @Test
    void concreteInitialClasspathJndiLoginModuleResolvesWithoutJdkDelegation() {
        Fixture fixture = fixture();
        ClassInfo target = extract(concreteJndiLoginModuleBytes());
        try (JrtClassSource source = JrtClassSource.runtime()) {
            ClassHierarchy hierarchy = new ClassHierarchy(
                    Map.of(fixture.host().internalName(), fixture.host(),
                            target.internalName(), target), source);
            new CallGraphBuilder(hierarchy).build(fixture.graph());
        }

        assertResolved(fixture.call(JaasLoginModuleCallSite.INITIALIZE_NAME,
                JaasLoginModuleCallSite.INITIALIZE_DESCRIPTOR),
                JaasLoginModuleDispatch.Source.PROGRAM_INPUT);
        assertResolved(fixture.call(JaasLoginModuleCallSite.LOGIN_NAME,
                JaasLoginModuleCallSite.LOGIN_DESCRIPTOR),
                JaasLoginModuleDispatch.Source.PROGRAM_INPUT);
    }

    private static void assertResolved(io.just.sast.cpg.graph.Node call,
                                       JaasLoginModuleDispatch.Source source) {
        JaasLoginModuleDispatch dispatch = dispatch(call);
        assertEquals(JaasLoginModuleDispatch.Status.RESOLVED, dispatch.status());
        assertEquals(source, dispatch.source());
        if (source == JaasLoginModuleDispatch.Source.JDK_IMAGE) {
            assertTrue(dispatch.sourceInfo().runtimeDelegated());
        }
        assertNotNull(dispatch.implementation());
        assertEquals(JaasLoginModuleDispatch.TARGET_CLASS,
                dispatch.implementation().owner());
        assertEquals(1, call.out().stream().filter(edge -> edge.type() == EdgeType.DISPATCHES
                && JaasLoginModuleDispatch.TARGET_CLASS.equals(edge.to().owner())
                && dispatch.implementation().name().equals(edge.to().name())
                && dispatch.implementation().descriptor().equals(edge.to().descriptor()))
                .count());
    }

    private static JaasLoginModuleDispatch dispatch(io.just.sast.cpg.graph.Node call) {
        Object value = call.note(JaasLoginModuleCallSite.DISPATCH_NOTE_KEY);
        assertTrue(value instanceof JaasLoginModuleDispatch);
        return (JaasLoginModuleDispatch) value;
    }

    private static Fixture fixture() {
        ClassInfo host = extract(hostBytes());
        LoadResult load = new LoadResult(Map.of(host.internalName(), host), List.of(), 1, 61);
        Graph graph = new CpgBuilder().build(load).graph();
        return new Fixture(host, load, graph,
                host.internalName() + "#flow()Z");
    }

    private static ClassInfo extract(byte[] bytes) {
        org.objectweb.asm.tree.ClassNode node = new org.objectweb.asm.tree.ClassNode();
        new ClassReader(bytes).accept(node, 0);
        return new FactsExtractor().extract(node);
    }

    private static byte[] hostBytes() {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "fixture/JndiDispatchHost", null,
                "java/lang/Object", null);
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "flow", "()Z", null, null);
        method.visitCode();
        method.visitInsn(Opcodes.ACONST_NULL);
        for (int index = 0; index < 4; index++) {
            method.visitInsn(Opcodes.ACONST_NULL);
        }
        method.visitMethodInsn(Opcodes.INVOKEINTERFACE,
                JaasLoginModuleCallSite.LOGIN_MODULE_OWNER,
                JaasLoginModuleCallSite.INITIALIZE_NAME,
                JaasLoginModuleCallSite.INITIALIZE_DESCRIPTOR, true);
        method.visitInsn(Opcodes.ACONST_NULL);
        method.visitMethodInsn(Opcodes.INVOKEINTERFACE,
                JaasLoginModuleCallSite.LOGIN_MODULE_OWNER,
                JaasLoginModuleCallSite.LOGIN_NAME,
                JaasLoginModuleCallSite.LOGIN_DESCRIPTOR, true);
        method.visitInsn(Opcodes.IRETURN);
        method.visitMaxs(5, 0);
        method.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] abstractJndiLoginModuleBytes() {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC | Opcodes.ACC_ABSTRACT,
                JaasLoginModuleDispatch.TARGET_CLASS, null, "java/lang/Object",
                new String[] {JaasLoginModuleCallSite.LOGIN_MODULE_OWNER});
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] unrelatedJndiLoginModuleBytes() {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, JaasLoginModuleDispatch.TARGET_CLASS,
                null, "java/lang/Object", null);
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] concreteJndiLoginModuleBytes() {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, JaasLoginModuleDispatch.TARGET_CLASS,
                null, "java/lang/Object", new String[] {JaasLoginModuleCallSite.LOGIN_MODULE_OWNER});
        MethodVisitor initialize = writer.visitMethod(Opcodes.ACC_PUBLIC,
                JaasLoginModuleCallSite.INITIALIZE_NAME,
                JaasLoginModuleCallSite.INITIALIZE_DESCRIPTOR, null, null);
        initialize.visitCode();
        initialize.visitInsn(Opcodes.RETURN);
        initialize.visitMaxs(0, 5);
        initialize.visitEnd();
        MethodVisitor login = writer.visitMethod(Opcodes.ACC_PUBLIC,
                JaasLoginModuleCallSite.LOGIN_NAME,
                JaasLoginModuleCallSite.LOGIN_DESCRIPTOR, null, null);
        login.visitCode();
        login.visitInsn(Opcodes.ICONST_1);
        login.visitInsn(Opcodes.IRETURN);
        login.visitMaxs(1, 1);
        login.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private record Fixture(ClassInfo host, LoadResult load, Graph graph, String hostKey) {
        private List<io.just.sast.cpg.graph.Node> lifecycleCalls() {
            return graph.callsOfMethod(hostKey).stream()
                    .filter(node -> JaasLoginModuleCallSite.LOGIN_MODULE_OWNER.equals(node.owner())
                            && "INTERFACE".equals(node.invokeKind()))
                    .toList();
        }

        private io.just.sast.cpg.graph.Node call(String name, String descriptor) {
            return lifecycleCalls().stream()
                    .filter(node -> name.equals(node.name()) && descriptor.equals(node.descriptor()))
                    .findFirst().orElseThrow();
        }
    }
}
