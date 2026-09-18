package io.just.sast.cpg.build;

import io.just.sast.analysis.callgraph.CallGraphBuilder;
import io.just.sast.analysis.hierarchy.ClassHierarchy;
import io.just.sast.cpg.graph.EdgeType;
import io.just.sast.cpg.graph.Graph;
import io.just.sast.cpg.graph.Node;
import io.just.sast.frontend.asm.FactsExtractor;
import io.just.sast.model.ClassInfo;
import io.just.sast.model.LoadResult;
import io.just.sast.model.ProxyCreationCallSite;
import io.just.sast.model.ProxyInterfaceCallSite;
import io.just.sast.model.ProxyInterfaceDispatch;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ProxyInterfaceDispatchContractTest {

    private static final String RUN = "()Ljava/lang/String;";
    private static final String RUN_INT = "(I)Ljava/lang/String;";

    @Test
    void abstractInterfaceUsesExactDescriptorAndStopsAtHandlerBoundary() {
        Fixture fixture = fixture(hostBytes("fixture/Service"),
                interfaceBytes("fixture/Service", false, true, false));
        Node call = fixture.call("fixture/Service", "run", RUN);

        ProxyInterfaceCallSite site = site(call);
        assertEquals(ProxyInterfaceCallSite.Status.PROVED, site.status());
        assertEquals("Lfixture/Service;", site.receiverSlot().descriptor());
        assertEquals(site.receiver().identity(), site.creation().proxy().identity());

        int edges = new CallGraphBuilder(fixture.hierarchy()).build(fixture.graph());
        ProxyInterfaceDispatch dispatch = dispatch(call);
        assertEquals(ProxyInterfaceDispatch.Status.HANDLER_REQUIRED, dispatch.status());
        assertEquals(ProxyInterfaceDispatch.Reason.NONE, dispatch.reason());
        assertEquals(List.of("fixture/Service#run" + RUN), dispatch.declarations().stream()
                .map(ProxyInterfaceDispatch.Declaration::methodKey).toList());
        assertTrue(edges > 0, "ordinary non-proxy calls may still have their own exact edges");
        assertTrue(call.out().isEmpty(), "abstract proxy method must not enumerate implementers");
    }

    @Test
    void defaultMethodResolvesOnlyTheExactDescriptor() {
        Fixture fixture = fixture(hostBytes("fixture/Service"),
                interfaceBytes("fixture/Service", true, true, true));
        Node call = fixture.call("fixture/Service", "run", RUN);

        int edges = new CallGraphBuilder(fixture.hierarchy()).build(fixture.graph());
        ProxyInterfaceDispatch dispatch = dispatch(call);
        assertEquals(ProxyInterfaceDispatch.Status.DEFAULT_RESOLVED, dispatch.status());
        assertEquals("fixture/Service", dispatch.target().owner());
        assertEquals(RUN, dispatch.target().descriptor());
        assertEquals(1, call.out().stream().filter(edge -> edge.type() == EdgeType.DISPATCHES)
                .count());
        assertTrue(edges > 0, "ordinary non-proxy calls may still have their own exact edges");
        assertTrue(call.out().stream().allMatch(edge -> RUN.equals(edge.to().descriptor())));
    }

    @Test
    void missingDescriptorIsUnknownWithoutGlobalInterfaceExpansion() {
        Fixture fixture = fixture(hostBytes("fixture/Service", "fixture/Service", RUN_INT),
                interfaceBytes("fixture/Service", false, true, false));
        Node call = fixture.call("fixture/Service", "run", RUN_INT);

        new CallGraphBuilder(fixture.hierarchy()).build(fixture.graph());
        ProxyInterfaceDispatch dispatch = dispatch(call);
        assertEquals(ProxyInterfaceDispatch.Status.UNKNOWN, dispatch.status());
        assertEquals(ProxyInterfaceDispatch.Reason.DESCRIPTOR_NOT_DECLARED, dispatch.reason());
        assertTrue(call.out().isEmpty());
    }

    @Test
    void twoUnrelatedDefaultsRemainAmbiguous() {
        Fixture fixture = fixture(hostBytes("fixture/First", "fixture/Second"),
                interfaceBytes("fixture/First", true, false, false),
                interfaceBytes("fixture/Second", true, false, false));
        Node call = fixture.call("fixture/First", "run", RUN);

        new CallGraphBuilder(fixture.hierarchy()).build(fixture.graph());
        ProxyInterfaceDispatch dispatch = dispatch(call);
        assertEquals(ProxyInterfaceDispatch.Status.UNKNOWN, dispatch.status());
        assertEquals(ProxyInterfaceDispatch.Reason.DEFAULT_AMBIGUOUS, dispatch.reason());
        assertEquals(List.of("fixture/First#run" + RUN, "fixture/Second#run" + RUN),
                dispatch.declarations().stream().map(ProxyInterfaceDispatch.Declaration::methodKey)
                        .toList());
        assertTrue(call.out().isEmpty());
    }

    @Test
    void ownerOutsideProxyInterfaceSetIsUnknown() {
        Fixture fixture = fixture(hostBytes("fixture/Service", "fixture/Other", RUN),
                interfaceBytes("fixture/Service", false, true, false),
                interfaceBytes("fixture/Other", false, true, false));
        Node call = fixture.call("fixture/Other", "run", RUN);

        new CallGraphBuilder(fixture.hierarchy()).build(fixture.graph());
        ProxyInterfaceDispatch dispatch = dispatch(call);
        assertEquals(ProxyInterfaceDispatch.Status.UNKNOWN, dispatch.status());
        assertEquals(ProxyInterfaceDispatch.Reason.INTERFACE_OWNER_NOT_DECLARED,
                dispatch.reason());
        assertTrue(call.out().isEmpty());
    }

    private static ProxyInterfaceCallSite site(Node call) {
        ProxyInterfaceCallSite site = (ProxyInterfaceCallSite) call.note(
                ProxyInterfaceCallSite.GRAPH_NOTE_KEY);
        assertNotNull(site);
        return site;
    }

    private static ProxyInterfaceDispatch dispatch(Node call) {
        ProxyInterfaceDispatch dispatch = (ProxyInterfaceDispatch) call.note(
                ProxyInterfaceCallSite.DISPATCH_NOTE_KEY);
        assertNotNull(dispatch);
        return dispatch;
    }

    private static Fixture fixture(byte[] host, byte[]... interfaces) {
        Map<String, ClassInfo> classes = new LinkedHashMap<>();
        classes.put(extract(host).internalName(), extract(host));
        for (byte[] value : interfaces) {
            ClassInfo info = extract(value);
            classes.put(info.internalName(), info);
        }
        LoadResult load = new LoadResult(classes, List.of(), 1, 61);
        Graph graph = new CpgBuilder().build(load).graph();
        ClassInfo hostInfo = classes.get("fixture/ProxyHost");
        if (hostInfo == null) {
            hostInfo = classes.values().stream()
                    .filter(info -> info.internalName().endsWith("ProxyHost"))
                    .findFirst().orElseThrow();
        }
        var method = hostInfo.methods().stream().filter(candidate -> "flow".equals(candidate.name()))
                .findFirst().orElseThrow();
        return new Fixture(graph, new ClassHierarchy(classes, null),
                hostInfo.internalName() + "#" + method.name() + method.descriptor());
    }

    private static ClassInfo extract(byte[] bytes) {
        org.objectweb.asm.tree.ClassNode node = new org.objectweb.asm.tree.ClassNode();
        new ClassReader(bytes).accept(node, 0);
        return new FactsExtractor().extract(node);
    }

    private static byte[] hostBytes(String... proxyInterfaces) {
        ClassWriter writer = hostWriter("fixture/ProxyHost");
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "flow", "()V", null, null);
        method.visitCode();
        emitKnownProxy(method, proxyInterfaces);
        String callOwner = proxyInterfaces[0].equals("fixture/First")
                ? "fixture/First" : proxyInterfaces[0];
        method.visitTypeInsn(Opcodes.CHECKCAST, callOwner);
        method.visitMethodInsn(Opcodes.INVOKEINTERFACE, callOwner, "run", RUN, true);
        method.visitInsn(Opcodes.POP);
        method.visitInsn(Opcodes.RETURN);
        method.visitMaxs(8, 0);
        method.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] hostBytes(String proxyInterface, String callOwner,
                                    String callDescriptor) {
        ClassWriter writer = hostWriter("fixture/ProxyHost");
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "flow", "()V", null, null);
        method.visitCode();
        emitKnownProxy(method, proxyInterface);
        method.visitTypeInsn(Opcodes.CHECKCAST, callOwner);
        if (RUN_INT.equals(callDescriptor)) {
            method.visitInsn(Opcodes.ICONST_1);
        }
        method.visitMethodInsn(Opcodes.INVOKEINTERFACE, callOwner, "run", callDescriptor, true);
        method.visitInsn(Opcodes.POP);
        method.visitInsn(Opcodes.RETURN);
        method.visitMaxs(8, 0);
        method.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static void emitKnownProxy(MethodVisitor method, String... interfaces) {
        method.visitLdcInsn(Type.getObjectType("fixture/ProxyHost"));
        method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Class", "getClassLoader",
                "()Ljava/lang/ClassLoader;", false);
        pushInt(method, interfaces.length);
        method.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Class");
        for (int index = 0; index < interfaces.length; index++) {
            method.visitInsn(Opcodes.DUP);
            pushInt(method, index);
            method.visitLdcInsn(Type.getObjectType(interfaces[index]));
            method.visitInsn(Opcodes.AASTORE);
        }
        method.visitTypeInsn(Opcodes.NEW, "fixture/Handler");
        method.visitInsn(Opcodes.DUP);
        method.visitMethodInsn(Opcodes.INVOKESPECIAL, "fixture/Handler", "<init>", "()V", false);
        method.visitMethodInsn(Opcodes.INVOKESTATIC, ProxyCreationCallSite.OWNER,
                ProxyCreationCallSite.NAME, ProxyCreationCallSite.DESCRIPTOR, false);
    }

    private static byte[] interfaceBytes(String name, boolean defaultRun,
                                          boolean abstractRun, boolean overload) {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC | Opcodes.ACC_INTERFACE | Opcodes.ACC_ABSTRACT,
                name, null, "java/lang/Object", null);
        if (defaultRun) {
            MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC, "run", RUN, null, null);
            method.visitCode();
            method.visitLdcInsn("default");
            method.visitInsn(Opcodes.ARETURN);
            method.visitMaxs(1, 0);
            method.visitEnd();
        } else if (abstractRun) {
            writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_ABSTRACT, "run", RUN, null, null)
                    .visitEnd();
        }
        if (overload) {
            MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_ABSTRACT,
                    "run", RUN_INT, null, null);
            method.visitEnd();
        }
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static ClassWriter hostWriter(String name) {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, name, null, "java/lang/Object", null);
        return writer;
    }

    private static void pushInt(MethodVisitor method, int value) {
        switch (value) {
            case 0 -> method.visitInsn(Opcodes.ICONST_0);
            case 1 -> method.visitInsn(Opcodes.ICONST_1);
            case 2 -> method.visitInsn(Opcodes.ICONST_2);
            default -> method.visitIntInsn(Opcodes.BIPUSH, value);
        }
    }

    private record Fixture(Graph graph, ClassHierarchy hierarchy, String hostKey) {
        private Node call(String owner, String name, String descriptor) {
            return graph.callsOfMethod(hostKey).stream()
                    .filter(node -> owner.equals(node.owner()) && name.equals(node.name())
                            && descriptor.equals(node.descriptor()))
                    .findFirst().orElseThrow();
        }
    }
}
