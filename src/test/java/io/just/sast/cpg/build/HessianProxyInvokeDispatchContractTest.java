package io.just.sast.cpg.build;

import io.just.sast.analysis.callgraph.CallGraphBuilder;
import io.just.sast.analysis.hierarchy.ClassHierarchy;
import io.just.sast.cpg.graph.Graph;
import io.just.sast.cpg.graph.Node;
import io.just.sast.frontend.asm.FactsExtractor;
import io.just.sast.model.ClassInfo;
import io.just.sast.model.HessianProxyInvokeDispatch;
import io.just.sast.model.LoadResult;
import io.just.sast.model.MethodId;
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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HessianProxyInvokeDispatchContractTest {

    private static final String API = "fixture/Api";
    private static final String RUN = "()Ljava/lang/String;";
    private static final String WRONG_INVOKE_DESCRIPTOR =
            "(Ljava/lang/Object;Ljava/lang/reflect/Method;)Ljava/lang/Object;";

    @Test
    void exactHessianHandlerConnectsOnlyFromAbstractProxyInterfaceDispatch() {
        Fixture fixture = fixture(false, HessianProxyInvokeDispatch.OWNER,
                HessianProxyInvokeDispatch.DESCRIPTOR, false);
        Node call = fixture.interfaceCall();

        ProxyInterfaceCallSite site = note(call, ProxyInterfaceCallSite.GRAPH_NOTE_KEY,
                ProxyInterfaceCallSite.class);
        assertEquals(ProxyInterfaceCallSite.Status.PROVED, site.status());

        new CallGraphBuilder(fixture.hierarchy()).build(fixture.graph());

        ProxyInterfaceDispatch interfaceDispatch = note(call,
                ProxyInterfaceCallSite.DISPATCH_NOTE_KEY, ProxyInterfaceDispatch.class);
        assertEquals(ProxyInterfaceDispatch.Status.HANDLER_REQUIRED,
                interfaceDispatch.status());
        HessianProxyInvokeDispatch dispatch = note(call,
                HessianProxyInvokeDispatch.GRAPH_NOTE_KEY, HessianProxyInvokeDispatch.class);
        assertEquals(HessianProxyInvokeDispatch.Status.PROVED, dispatch.status());
        assertEquals(HessianProxyInvokeDispatch.Reason.NONE, dispatch.reason());
        assertEquals(MethodId.of(HessianProxyInvokeDispatch.OWNER,
                HessianProxyInvokeDispatch.NAME, HessianProxyInvokeDispatch.DESCRIPTOR),
                dispatch.target());
        assertEquals(site.creation().handler().identity(), dispatch.handler().identity());
        assertEquals(HessianProxyInvokeDispatch.HANDLER_DESCRIPTOR,
                dispatch.handler().descriptor());
        assertTrue(call.out().stream().anyMatch(edge ->
                "HESSIAN_PROXY_INVOKE".equals(edge.label())
                        && HessianProxyInvokeDispatch.OWNER.equals(edge.to().owner())
                        && HessianProxyInvokeDispatch.DESCRIPTOR.equals(edge.to().descriptor())));
    }

    @Test
    void defaultInterfaceDispatchDoesNotInventHandlerInvokeEdge() {
        Fixture fixture = fixture(true, HessianProxyInvokeDispatch.OWNER,
                HessianProxyInvokeDispatch.DESCRIPTOR, false);
        Node call = fixture.interfaceCall();

        new CallGraphBuilder(fixture.hierarchy()).build(fixture.graph());

        ProxyInterfaceDispatch interfaceDispatch = note(call,
                ProxyInterfaceCallSite.DISPATCH_NOTE_KEY, ProxyInterfaceDispatch.class);
        assertEquals(ProxyInterfaceDispatch.Status.DEFAULT_RESOLVED,
                interfaceDispatch.status());
        HessianProxyInvokeDispatch dispatch = note(call,
                HessianProxyInvokeDispatch.GRAPH_NOTE_KEY, HessianProxyInvokeDispatch.class);
        assertEquals(HessianProxyInvokeDispatch.Status.UNKNOWN, dispatch.status());
        assertEquals(HessianProxyInvokeDispatch.Reason.INTERFACE_DISPATCH_NOT_HANDLER,
                dispatch.reason());
        assertFalse(call.out().stream().anyMatch(edge ->
                "HESSIAN_PROXY_INVOKE".equals(edge.label())));
        assertTrue(call.out().stream().anyMatch(edge ->
                "PROXY_DEFAULT".equals(edge.label())));
    }

    @Test
    void ordinaryInterfaceCallHasNoProxyOrHessianDispatchFact() {
        Fixture fixture = fixture(false, HessianProxyInvokeDispatch.OWNER,
                HessianProxyInvokeDispatch.DESCRIPTOR, true);
        Node call = fixture.interfaceCall();

        assertNull(call.note(ProxyInterfaceCallSite.GRAPH_NOTE_KEY));
        new CallGraphBuilder(fixture.hierarchy()).build(fixture.graph());
        assertNull(call.note(HessianProxyInvokeDispatch.GRAPH_NOTE_KEY));
        assertTrue(call.out().stream().noneMatch(edge ->
                "HESSIAN_PROXY_INVOKE".equals(edge.label())));
    }

    @Test
    void unknownHandlerValueKeepsHessianDispatchPartial() {
        Fixture fixture = fixture(false, HessianProxyInvokeDispatch.OWNER,
                HessianProxyInvokeDispatch.DESCRIPTOR, false, true);
        Node call = fixture.interfaceCall();

        new CallGraphBuilder(fixture.hierarchy()).build(fixture.graph());

        HessianProxyInvokeDispatch dispatch = note(call,
                HessianProxyInvokeDispatch.GRAPH_NOTE_KEY, HessianProxyInvokeDispatch.class);
        assertEquals(HessianProxyInvokeDispatch.Status.PARTIAL, dispatch.status());
        assertEquals(HessianProxyInvokeDispatch.Reason.HANDLER_UNKNOWN, dispatch.reason());
        assertFalse(call.out().stream().anyMatch(edge ->
                "HESSIAN_PROXY_INVOKE".equals(edge.label())));
    }

    @Test
    void nonHessianHandlerDescriptorCannotReachHessianInvoke() {
        Fixture fixture = fixture(false, "fixture/OtherHandler",
                HessianProxyInvokeDispatch.DESCRIPTOR, false);
        Node call = fixture.interfaceCall();

        new CallGraphBuilder(fixture.hierarchy()).build(fixture.graph());

        HessianProxyInvokeDispatch dispatch = note(call,
                HessianProxyInvokeDispatch.GRAPH_NOTE_KEY, HessianProxyInvokeDispatch.class);
        assertEquals(HessianProxyInvokeDispatch.Status.UNKNOWN, dispatch.status());
        assertEquals(HessianProxyInvokeDispatch.Reason.HANDLER_DESCRIPTOR_MISMATCH,
                dispatch.reason());
        assertFalse(call.out().stream().anyMatch(edge ->
                "HESSIAN_PROXY_INVOKE".equals(edge.label())));
    }

    @Test
    void wrongHessianInvokeOverloadRemainsUnknown() {
        Fixture fixture = fixture(false, HessianProxyInvokeDispatch.OWNER,
                WRONG_INVOKE_DESCRIPTOR, false);
        Node call = fixture.interfaceCall();

        new CallGraphBuilder(fixture.hierarchy()).build(fixture.graph());

        HessianProxyInvokeDispatch dispatch = note(call,
                HessianProxyInvokeDispatch.GRAPH_NOTE_KEY, HessianProxyInvokeDispatch.class);
        assertEquals(HessianProxyInvokeDispatch.Status.UNKNOWN, dispatch.status());
        assertEquals(HessianProxyInvokeDispatch.Reason.HESSIAN_INVOKE_NOT_EXACT,
                dispatch.reason());
        assertFalse(call.out().stream().anyMatch(edge ->
                "HESSIAN_PROXY_INVOKE".equals(edge.label())));
    }

    @Test
    void handlerIdentityMismatchIsAnInternalContractFailure() {
        Fixture fixture = fixture(false, HessianProxyInvokeDispatch.OWNER,
                HessianProxyInvokeDispatch.DESCRIPTOR, false);
        Node call = fixture.interfaceCall();
        new CallGraphBuilder(fixture.hierarchy()).build(fixture.graph());
        ProxyInterfaceDispatch interfaceDispatch = note(call,
                ProxyInterfaceCallSite.DISPATCH_NOTE_KEY, ProxyInterfaceDispatch.class);
        ProxyCreationCallSite.ValueIdentity expected = interfaceDispatch.callSite().creation()
                .handler();
        ProxyCreationCallSite.ValueIdentity other = ProxyCreationCallSite.ValueIdentity.known(
                new io.just.sast.model.TypedBridgeFact.FlowIdentity(
                        expected.identity().canonical() + ":other"),
                expected.descriptor(), expected.producerOffset());
        MethodId target = MethodId.of(HessianProxyInvokeDispatch.OWNER,
                HessianProxyInvokeDispatch.NAME, HessianProxyInvokeDispatch.DESCRIPTOR);

        assertThrows(IllegalArgumentException.class, () -> new HessianProxyInvokeDispatch(
                interfaceDispatch, other, target, HessianProxyInvokeDispatch.Status.PROVED,
                HessianProxyInvokeDispatch.Reason.NONE));
    }

    private static <T> T note(Node node, String key, Class<T> type) {
        Object value = node.note(key);
        assertNotNull(value);
        return type.cast(value);
    }

    private static Fixture fixture(boolean defaultMethod, String handlerOwner,
                                   String handlerInvokeDescriptor, boolean ordinaryCall) {
        return fixture(defaultMethod, handlerOwner, handlerInvokeDescriptor, ordinaryCall, false);
    }

    private static Fixture fixture(boolean defaultMethod, String handlerOwner,
                                   String handlerInvokeDescriptor, boolean ordinaryCall,
                                   boolean unknownHandler) {
        Map<String, ClassInfo> classes = new LinkedHashMap<>();
        ClassInfo host = extract(hostBytes(handlerOwner, ordinaryCall, unknownHandler));
        ClassInfo api = extract(interfaceBytes(defaultMethod));
        ClassInfo hessian = extract(handlerBytes(HessianProxyInvokeDispatch.OWNER,
                HessianProxyInvokeDispatch.DESCRIPTOR));
        ClassInfo handler = extract(handlerBytes(handlerOwner, handlerInvokeDescriptor));
        classes.put(host.internalName(), host);
        classes.put(api.internalName(), api);
        classes.put(hessian.internalName(), hessian);
        classes.put(handler.internalName(), handler);
        LoadResult load = new LoadResult(classes, List.of(), 1, 61);
        Graph graph = new CpgBuilder().build(load).graph();
        var method = host.method("flow", "()V");
        assertNotNull(method);
        return new Fixture(graph, new ClassHierarchy(classes, null),
                host.internalName() + "#" + method.name() + method.descriptor());
    }

    private static ClassInfo extract(byte[] bytes) {
        org.objectweb.asm.tree.ClassNode node = new org.objectweb.asm.tree.ClassNode();
        new ClassReader(bytes).accept(node, 0);
        return new FactsExtractor().extract(node);
    }

    private static byte[] hostBytes(String handlerOwner, boolean ordinaryCall,
                                    boolean unknownHandler) {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "fixture/ProxyHost", null,
                "java/lang/Object", null);
        writer.visitField(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC, "handler",
                "Ljava/lang/reflect/InvocationHandler;", null, null).visitEnd();
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "flow", "()V", null, null);
        method.visitCode();
        if (ordinaryCall) {
            method.visitInsn(Opcodes.ACONST_NULL);
            method.visitTypeInsn(Opcodes.CHECKCAST, API);
        } else {
            emitProxy(method, handlerOwner, unknownHandler);
            method.visitTypeInsn(Opcodes.CHECKCAST, API);
        }
        method.visitMethodInsn(Opcodes.INVOKEINTERFACE, API, "run", RUN, true);
        method.visitInsn(Opcodes.POP);
        method.visitInsn(Opcodes.RETURN);
        method.visitMaxs(8, 0);
        method.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static void emitProxy(MethodVisitor method, String handlerOwner,
                                  boolean unknownHandler) {
        method.visitLdcInsn(Type.getObjectType("fixture/ProxyHost"));
        method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Class", "getClassLoader",
                "()Ljava/lang/ClassLoader;", false);
        method.visitInsn(Opcodes.ICONST_1);
        method.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Class");
        method.visitInsn(Opcodes.DUP);
        method.visitInsn(Opcodes.ICONST_0);
        method.visitLdcInsn(Type.getObjectType(API));
        method.visitInsn(Opcodes.AASTORE);
        if (unknownHandler) {
            method.visitFieldInsn(Opcodes.GETSTATIC, "fixture/ProxyHost", "handler",
                    "Ljava/lang/reflect/InvocationHandler;");
        } else {
            method.visitTypeInsn(Opcodes.NEW, handlerOwner);
            method.visitInsn(Opcodes.DUP);
            method.visitMethodInsn(Opcodes.INVOKESPECIAL, handlerOwner, "<init>", "()V", false);
        }
        method.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/reflect/Proxy",
                "newProxyInstance", ProxyCreationCallSite.DESCRIPTOR, false);
    }

    private static byte[] interfaceBytes(boolean defaultMethod) {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC | Opcodes.ACC_INTERFACE | Opcodes.ACC_ABSTRACT,
                API, null, "java/lang/Object", null);
        if (defaultMethod) {
            MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC, "run", RUN, null, null);
            method.visitCode();
            method.visitLdcInsn("default");
            method.visitInsn(Opcodes.ARETURN);
            method.visitMaxs(1, 0);
            method.visitEnd();
        } else {
            writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_ABSTRACT, "run", RUN,
                    null, null).visitEnd();
        }
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] handlerBytes(String owner, String invokeDescriptor) {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, owner, null, "java/lang/Object",
                new String[]{"java/lang/reflect/InvocationHandler"});
        MethodVisitor constructor = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V",
                null, null);
        constructor.visitCode();
        constructor.visitVarInsn(Opcodes.ALOAD, 0);
        constructor.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>",
                "()V", false);
        constructor.visitInsn(Opcodes.RETURN);
        constructor.visitMaxs(1, 1);
        constructor.visitEnd();
        MethodVisitor invoke = writer.visitMethod(Opcodes.ACC_PUBLIC, "invoke", invokeDescriptor,
                null, null);
        invoke.visitCode();
        invoke.visitInsn(Opcodes.ACONST_NULL);
        invoke.visitInsn(Opcodes.ARETURN);
        invoke.visitMaxs(1, 4);
        invoke.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private record Fixture(Graph graph, ClassHierarchy hierarchy, String hostKey) {
        private Node interfaceCall() {
            return graph.callsOfMethod(hostKey).stream()
                    .filter(node -> API.equals(node.owner()) && "run".equals(node.name())
                            && RUN.equals(node.descriptor()))
                    .findFirst().orElseThrow();
        }
    }
}
