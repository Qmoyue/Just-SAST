package io.just.sast.cpg.build;

import io.just.sast.analysis.callgraph.CallGraphBuilder;
import io.just.sast.analysis.entry.ApplicationEntryIndex;
import io.just.sast.analysis.hierarchy.ClassHierarchy;
import io.just.sast.blackboard.Blackboard;
import io.just.sast.config.Match;
import io.just.sast.config.Rule;
import io.just.sast.config.RuleEngine;
import io.just.sast.config.RuleSet;
import io.just.sast.cpg.graph.Graph;
import io.just.sast.cpg.graph.NodeType;
import io.just.sast.frontend.asm.FactsExtractor;
import io.just.sast.model.ClassInfo;
import io.just.sast.model.HandleRef;
import io.just.sast.model.HttpExternalSource;
import io.just.sast.model.InsnFact;
import io.just.sast.model.InvokeDynamicRef;
import io.just.sast.model.LoadResult;
import io.just.sast.model.MethodInfo;
import io.just.sast.model.Op;
import io.just.sast.model.ProgramUniverse;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Handle;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CpgBuilderProgramUniverseTest {

    @Test
    void typedUniverseBuildMatchesLoadResultCompatibilityPath() {
        MethodNode node = new MethodNode(Opcodes.ACC_PUBLIC, "run", "()V", null, null);
        node.instructions.add(new InsnNode(Opcodes.RETURN));
        ClassNode classNode = new ClassNode();
        classNode.name = "fixture/Entry";
        classNode.superName = "java/lang/Object";
        classNode.methods.add(node);
        MethodInfo method = new FactsExtractor().extract(classNode).methods().get(0);
        ClassInfo info = new ClassInfo(classNode.name, classNode.superName, List.of(), classNode.access,
                List.of(method), List.of());
        LoadResult load = new LoadResult(Map.of(info.internalName(), info), List.of(), 1, 61);
        CpgBuilder builder = new CpgBuilder();

        BuiltCpg legacy = builder.build(load);
        BuiltCpg typed = builder.build(ProgramUniverse.from(load));
        assertEquals(legacy.graph().nodeCount(), typed.graph().nodeCount());
        assertEquals(legacy.graph().edgeCount(), typed.graph().edgeCount());
        assertEquals(legacy.index().methodCount(), typed.index().methodCount());
        assertEquals(legacy.fieldWriters().fieldCount(), typed.fieldWriters().fieldCount());
    }

    @Test
    void bindingCallRetainsOnlyNearbyClassLiteralHints() {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "fixture/app/Ingress", null,
                "java/lang/Object", null);
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC, "decode",
                "(Ljava/lang/String;)Ljava/lang/Object;", null, null);
        method.visitCode();
        method.visitVarInsn(Opcodes.ALOAD, 1);
        method.visitLdcInsn(Type.getObjectType("fixture/model/User"));
        method.visitMethodInsn(Opcodes.INVOKESTATIC, "fixture/Mapper", "readValue",
                "(Ljava/lang/String;Ljava/lang/Class;)Ljava/lang/Object;", false);
        method.visitInsn(Opcodes.ARETURN);
        method.visitMaxs(2, 2);
        method.visitEnd();
        writer.visitEnd();

        ClassNode node = new ClassNode();
        new org.objectweb.asm.ClassReader(writer.toByteArray()).accept(node, 0);
        ClassInfo info = new FactsExtractor().extract(node);
        LoadResult load = new LoadResult(Map.of(info.internalName(), info), List.of(), 1, 61);

        Graph graph = new CpgBuilder().build(load).graph();
        var call = graph.callsOfMethod("fixture/app/Ingress#decode(Ljava/lang/String;)Ljava/lang/Object;")
                .stream().findFirst().orElseThrow();
        assertEquals(List.of("fixture/model/User"), call.note("classLiteralHints"));
        assertTrue(call.notes().containsKey("classLiteralHints"));
    }

    @Test
    void configurationCallRetainsOnlyNearbyStringHints() {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "fixture/app/Config", null,
                "java/lang/Object", null);
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC, "configure",
                "()V", null, null);
        method.visitCode();
        method.visitLdcInsn("fixture.app.");
        method.visitMethodInsn(Opcodes.INVOKEVIRTUAL,
                "com/alibaba/fastjson/parser/ParserConfig", "addAccept",
                "(Ljava/lang/String;)V", false);
        method.visitInsn(Opcodes.RETURN);
        method.visitMaxs(2, 1);
        method.visitEnd();
        writer.visitEnd();

        ClassNode node = new ClassNode();
        new org.objectweb.asm.ClassReader(writer.toByteArray()).accept(node, 0);
        ClassInfo info = new FactsExtractor().extract(node);
        LoadResult load = new LoadResult(Map.of(info.internalName(), info), List.of(), 1, 61);

        Graph graph = new CpgBuilder().build(load).graph();
        var call = graph.callsOfMethod("fixture/app/Config#configure()V")
                .stream().findFirst().orElseThrow();
        assertEquals(List.of("fixture.app."), call.note("stringLiteralHints"));
        assertTrue(call.notes().containsKey("stringLiteralHints"));
    }

    @Test
    void asmLambdaBootstrapBecomesExactCallGraphEdge() {
        byte[] bytes = lambdaClassBytes();
        ClassNode node = new ClassNode();
        new ClassReader(bytes).accept(node, 0);
        ClassInfo info = new FactsExtractor().extract(node);
        LoadResult load = new LoadResult(Map.of(info.internalName(), info), List.of(), 1, 61);

        Graph graph = new CpgBuilder().build(load).graph();
        var call = graph.callsOfMethod("fixture/LambdaHost#make()Ljava/lang/Runnable;")
                .stream().filter(candidate -> candidate.type() == NodeType.CALL).findFirst()
                .orElseThrow();
        InvokeDynamicRef indy = (InvokeDynamicRef) call.prop("indy");
        assertEquals("metafactory", indy.bootstrap().name());
        assertEquals("fixture/LambdaHost", ((HandleRef) indy.bootstrapArgs().get(1)).owner());
        assertEquals("ordinary", ((HandleRef) indy.bootstrapArgs().get(1)).name());

        int edges = new CallGraphBuilder(new ClassHierarchy(load.classes(), null)).build(graph);

        assertEquals(1, edges);
        assertEquals("fixture/LambdaHost", call.out().get(0).to().owner());
        assertEquals("ordinary", call.out().get(0).to().name());
    }

    @Test
    void asmHttpHandlerBecomesTypedRequestSourceFacts() {
        byte[] bytes = httpHandlerClassBytes();
        ClassNode node = new ClassNode();
        new ClassReader(bytes).accept(node, 0);
        ClassInfo info = new FactsExtractor().extract(node);
        LoadResult load = new LoadResult(Map.of(info.internalName(), info), List.of(), 1, 61);

        Graph graph = new CpgBuilder().build(load).graph();
        ApplicationEntryIndex index = ApplicationEntryIndex.build(graph,
                new RuleEngine(RuleSet.EMPTY, new ClassHierarchy(load.classes(), null)),
                Set.of(info.internalName()), true);
        String handlerKey = info.internalName() + "#handle"
                + ApplicationEntryIndex.HTTP_HANDLER_HANDLE_DESCRIPTOR;

        assertTrue(index.isHttpHandlerMethod(handlerKey));
        assertTrue(index.isExternalEntryMethod(handlerKey));
        assertEquals(6, index.httpExternalSourcesFor(handlerKey).size());
        assertEquals(3, index.httpExternalSources().stream()
                .filter(HttpExternalSource::externalInput).count());
        assertTrue(index.httpExternalSources().stream().anyMatch(source ->
                source.kind() == HttpExternalSource.Kind.HEADER
                        && source.valueRole() == HttpExternalSource.ValueRole.VALUE
                        && "getFirst".equals(source.apiName())));
        assertTrue(index.httpExternalSources().stream().anyMatch(source ->
                source.kind() == HttpExternalSource.Kind.QUERY
                        && source.externalInput()
                        && "getQuery".equals(source.apiName())));
        assertTrue(index.httpExternalSources().stream().anyMatch(source ->
                source.kind() == HttpExternalSource.Kind.BODY
                        && source.externalInput()
                        && "readAllBytes".equals(source.apiName())));
        assertTrue(index.httpContextRegistrations().isEmpty(),
                "the source fixture has no createContext registration; P3.6 owns that join");
    }

    @Test
    void httpLambdaSiteRequiresTheActualLambdaEdgeAndCallbackValueSource() {
        LoadResult load = loadResult(httpLambdaWebClassBytes());
        Graph graph = new CpgBuilder().build(load).graph();
        RuleEngine engine = new RuleEngine(RuleSet.EMPTY,
                new ClassHierarchy(load.classes(), null));

        ApplicationEntryIndex beforeCallGraph = ApplicationEntryIndex.build(graph, engine,
                Set.of("fixture/app/HttpLambdaWeb"), true);
        assertEquals(1, beforeCallGraph.httpContextRegistrations().size());
        assertTrue(beforeCallGraph.httpExternalSources().stream()
                .anyMatch(HttpExternalSource::externalInput));
        assertTrue(beforeCallGraph.httpSites().isEmpty(),
                "a handler value without its actual lambda edge cannot form a site");
        assertTrue(beforeCallGraph.applicationSiteRoots().isEmpty(),
                "a non-site registration cannot create a site root");

        graph = new CpgBuilder().build(load).graph();
        assertTrue(new CallGraphBuilder(new ClassHierarchy(load.classes(), null)).build(graph) > 0);
        ApplicationEntryIndex index = ApplicationEntryIndex.build(graph, engine,
                Set.of("fixture/app/HttpLambdaWeb"), true);
        assertEquals(1, index.httpSites().size());
        ApplicationEntryIndex.HttpSite site = index.httpSites().get(0);
        assertEquals("fixture/app/HttpLambdaWeb#main([Ljava/lang/String;)V",
                site.entryMethodKey());
        assertEquals("fixture/app/HttpLambdaWeb#lambda$main$0"
                        + ApplicationEntryIndex.HTTP_HANDLER_HANDLE_DESCRIPTOR,
                site.handlerMethodKey());
        assertEquals(io.just.sast.cpg.graph.EdgeType.LAMBDA, site.handlerEdge().edgeType());
        assertTrue(site.externalSources().stream().allMatch(HttpExternalSource::externalInput));
        assertEquals(Set.of(site.handlerMethodKey()), index.applicationSiteRoots());
        assertEquals(site.externalSources(),
                index.httpExternalSourcesFor(site.handlerMethodKey()).stream()
                        .filter(HttpExternalSource::externalInput).toList());
    }

    @Test
    void verifiedHttpSiteCallbackIsAnApplicationRootForForwardReverseIntersection() {
        LoadResult load = loadResult(httpLambdaWebClassBytes());
        ClassHierarchy hierarchy = new ClassHierarchy(load.classes(), null);
        Graph graph = new CpgBuilder().build(load).graph();
        assertTrue(new CallGraphBuilder(hierarchy).build(graph) > 0);

        Rule.SinkRule terminal = new Rule.SinkRule("http-header-terminal", "HTTP", "HIGH",
                new Rule.CallMatcher(Match.of(ApplicationEntryIndex.HTTP_HEADERS_OWNER),
                        Match.of("getFirst"), Match.of("(Ljava/lang/String;)Ljava/lang/String;")),
                List.of(new Rule.TaintedPos.Arg(0)), Rule.SinkRole.TERMINAL);
        RuleEngine engine = new RuleEngine(
                new RuleSet(List.of(terminal), List.of(), List.of(), List.of(), List.of()),
                hierarchy);
        ApplicationEntryIndex index = ApplicationEntryIndex.build(graph, engine,
                Set.of("fixture/app/HttpLambdaWeb"), true);
        String handler = "fixture/app/HttpLambdaWeb#lambda$main$0"
                + ApplicationEntryIndex.HTTP_HANDLER_HANDLE_DESCRIPTOR;

        assertEquals(Set.of(handler), index.applicationSiteRoots());
        assertTrue(index.isApplicationSiteRoot(handler));
        assertTrue(index.hasVerifiedApplicationRoot());
        assertTrue(index.entryForwardSlice().contains(handler));
        assertTrue(index.sinkReverseSlice().contains(handler));
        assertTrue(index.entryTerminalIntersection().contains(handler));
        assertTrue(index.allowsDependencyExpansion());
        assertThrows(UnsupportedOperationException.class,
                () -> index.applicationSiteRoots().clear());

        Blackboard blackboard = new Blackboard(graph, hierarchy, new FieldWriterIndex(),
                new RuleSet(List.of(terminal), List.of(), List.of(), List.of(), List.of()), 20,
                new Blackboard.ScanInputs(Path.of("fixture.jar"), List.of(), true, null, 0,
                        null, Set.of("fixture/app/HttpLambdaWeb"), true));
        assertEquals(index.applicationSiteRoots(),
                blackboard.applicationEntryIndex().applicationSiteRoots());
        assertTrue(blackboard.originSupport().entryDownstream(graph).contains(handler));
    }

    @Test
    void httpAllocatedSiteRequiresConstructorEdgeTypedHandlerAndCallbackValueSource() {
        LoadResult load = loadResult(httpAllocatedWebClassBytes(), httpAllocatedHandlerClassBytes());
        Graph graph = new CpgBuilder().build(load).graph();
        RuleEngine engine = new RuleEngine(RuleSet.EMPTY,
                new ClassHierarchy(load.classes(), null));

        ApplicationEntryIndex beforeCallGraph = ApplicationEntryIndex.build(graph, engine,
                Set.of("fixture/app/HttpAllocatedWeb", "fixture/app/HttpAllocatedHandler"),
                true);
        assertTrue(beforeCallGraph.httpSites().isEmpty());

        graph = new CpgBuilder().build(load).graph();
        assertTrue(new CallGraphBuilder(new ClassHierarchy(load.classes(), null)).build(graph) > 0);
        ApplicationEntryIndex index = ApplicationEntryIndex.build(graph, engine,
                Set.of("fixture/app/HttpAllocatedWeb", "fixture/app/HttpAllocatedHandler"),
                true);
        assertEquals(1, index.httpSites().size());
        ApplicationEntryIndex.HttpSite site = index.httpSites().get(0);
        assertEquals("fixture/app/HttpAllocatedHandler#handle"
                        + ApplicationEntryIndex.HTTP_HANDLER_HANDLE_DESCRIPTOR,
                site.handlerMethodKey());
        assertEquals(io.just.sast.cpg.graph.EdgeType.INVOKES, site.handlerEdge().edgeType());
        assertEquals("fixture/app/HttpAllocatedHandler#<init>()V",
                site.handlerEdge().targetMethodKey());
        assertTrue(index.isHttpHandlerMethod(site.handlerMethodKey()));
        assertTrue(site.externalSources().stream().anyMatch(source ->
                source.kind() == HttpExternalSource.Kind.HEADER
                        && source.valueRole() == HttpExternalSource.ValueRole.VALUE));
    }

    @Test
    void missingLambdaBootstrapRemainsVisibleAsUnknown() {
        String owner = "fixture/MissingBootstrap";
        String descriptor = "()Ljava/lang/Runnable;";
        MethodInfo method = new MethodInfo(owner, "make", descriptor,
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                List.of(new InsnFact(0, Op.INVOKEDYNAMIC, List.of(new InvokeDynamicRef(
                                "run", descriptor, null, List.of()))),
                        new InsnFact(1, Op.ARETURN, List.of())),
                List.of(), false);
        ClassInfo info = new ClassInfo(owner, "java/lang/Object", List.of(), Opcodes.ACC_PUBLIC,
                List.of(method), List.of());
        LoadResult load = new LoadResult(Map.of(owner, info), List.of(), 1, 61);

        Graph graph = new CpgBuilder().build(load).graph();
        var call = graph.callsOfMethod(owner + "#make" + descriptor).get(0);
        int edges = new CallGraphBuilder(new ClassHierarchy(load.classes(), null)).build(graph);

        assertNull(call.owner());
        assertEquals(0, edges);
        assertEquals("UNKNOWN_BOOTSTRAP", call.note("lambdaResolution"));
        assertTrue(call.prop("indy") instanceof InvokeDynamicRef);
    }

    private static byte[] lambdaClassBytes() {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "fixture/LambdaHost", null,
                "java/lang/Object", null);

        MethodVisitor ordinary = writer.visitMethod(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC,
                "ordinary", "()V", null, null);
        ordinary.visitCode();
        ordinary.visitInsn(Opcodes.RETURN);
        ordinary.visitMaxs(0, 0);
        ordinary.visitEnd();

        MethodVisitor make = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "make",
                "()Ljava/lang/Runnable;", null, null);
        make.visitCode();
        make.visitInvokeDynamicInsn("run", "()Ljava/lang/Runnable;",
                new Handle(Opcodes.H_INVOKESTATIC, "java/lang/invoke/LambdaMetafactory",
                        "metafactory",
                        "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;"
                                + "Ljava/lang/invoke/MethodType;Ljava/lang/invoke/MethodType;"
                                + "Ljava/lang/invoke/MethodHandle;Ljava/lang/invoke/MethodType;)"
                                + "Ljava/lang/invoke/CallSite;", false),
                Type.getMethodType("()V"),
                new Handle(Opcodes.H_INVOKESTATIC, "fixture/LambdaHost", "ordinary", "()V", false),
                Type.getMethodType("()V"));
        make.visitInsn(Opcodes.ARETURN);
        make.visitMaxs(1, 0);
        make.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] httpHandlerClassBytes() {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "fixture/HttpHandlerHost", null,
                "java/lang/Object", new String[] {ApplicationEntryIndex.HTTP_HANDLER_OWNER});
        MethodVisitor handle = writer.visitMethod(Opcodes.ACC_PUBLIC,
                ApplicationEntryIndex.HTTP_HANDLER_HANDLE_NAME,
                ApplicationEntryIndex.HTTP_HANDLER_HANDLE_DESCRIPTOR, null, null);
        handle.visitCode();
        handle.visitVarInsn(Opcodes.ALOAD, 1);
        handle.visitMethodInsn(Opcodes.INVOKEINTERFACE,
                ApplicationEntryIndex.HTTP_EXCHANGE_OWNER, "getRequestHeaders",
                "()Lcom/sun/net/httpserver/Headers;", true);
        handle.visitLdcInsn("X-Lookup-URL");
        handle.visitMethodInsn(Opcodes.INVOKEVIRTUAL, ApplicationEntryIndex.HTTP_HEADERS_OWNER,
                "getFirst", "(Ljava/lang/String;)Ljava/lang/String;", false);
        handle.visitInsn(Opcodes.POP);

        handle.visitVarInsn(Opcodes.ALOAD, 1);
        handle.visitMethodInsn(Opcodes.INVOKEINTERFACE,
                ApplicationEntryIndex.HTTP_EXCHANGE_OWNER, "getRequestURI",
                "()Ljava/net/URI;", true);
        handle.visitMethodInsn(Opcodes.INVOKEVIRTUAL, ApplicationEntryIndex.HTTP_URI_OWNER,
                "getQuery", "()Ljava/lang/String;", false);
        handle.visitInsn(Opcodes.POP);

        handle.visitVarInsn(Opcodes.ALOAD, 1);
        handle.visitMethodInsn(Opcodes.INVOKEINTERFACE,
                ApplicationEntryIndex.HTTP_EXCHANGE_OWNER, "getRequestBody",
                "()Ljava/io/InputStream;", true);
        handle.visitMethodInsn(Opcodes.INVOKEVIRTUAL,
                ApplicationEntryIndex.JAVA_INPUT_STREAM_OWNER, "readAllBytes", "()[B", false);
        handle.visitInsn(Opcodes.POP);
        handle.visitInsn(Opcodes.RETURN);
        handle.visitMaxs(2, 2);
        handle.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static LoadResult loadResult(byte[]... classBytes) {
        Map<String, ClassInfo> classes = new java.util.HashMap<>();
        for (byte[] bytes : classBytes) {
            ClassNode node = new ClassNode();
            new ClassReader(bytes).accept(node, 0);
            ClassInfo info = new FactsExtractor().extract(node);
            classes.put(info.internalName(), info);
        }
        return new LoadResult(Map.copyOf(classes), List.of(), 1, 61);
    }

    private static byte[] httpLambdaWebClassBytes() {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "fixture/app/HttpLambdaWeb", null,
                "java/lang/Object", null);

        MethodVisitor lambda = writer.visitMethod(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC,
                "lambda$main$0", ApplicationEntryIndex.HTTP_HANDLER_HANDLE_DESCRIPTOR,
                null, new String[] {"java/io/IOException"});
        lambda.visitCode();
        lambda.visitVarInsn(Opcodes.ALOAD, 0);
        lambda.visitMethodInsn(Opcodes.INVOKEINTERFACE,
                ApplicationEntryIndex.HTTP_EXCHANGE_OWNER, "getRequestHeaders",
                "()Lcom/sun/net/httpserver/Headers;", true);
        lambda.visitLdcInsn("X-Lookup-URL");
        lambda.visitMethodInsn(Opcodes.INVOKEVIRTUAL, ApplicationEntryIndex.HTTP_HEADERS_OWNER,
                "getFirst", "(Ljava/lang/String;)Ljava/lang/String;", false);
        lambda.visitInsn(Opcodes.POP);
        lambda.visitInsn(Opcodes.RETURN);
        lambda.visitMaxs(2, 1);
        lambda.visitEnd();

        MethodVisitor main = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "main",
                "([Ljava/lang/String;)V", null, new String[] {"java/io/IOException"});
        main.visitCode();
        main.visitMethodInsn(Opcodes.INVOKESTATIC, ApplicationEntryIndex.HTTP_SERVER_OWNER,
                "create", "()Lcom/sun/net/httpserver/HttpServer;", false);
        main.visitLdcInsn("/lookup");
        main.visitInvokeDynamicInsn("handle", "()Lcom/sun/net/httpserver/HttpHandler;",
                lambdaMetafactory(),
                Type.getMethodType(ApplicationEntryIndex.HTTP_HANDLER_HANDLE_DESCRIPTOR),
                new Handle(Opcodes.H_INVOKESTATIC, "fixture/app/HttpLambdaWeb",
                        "lambda$main$0", ApplicationEntryIndex.HTTP_HANDLER_HANDLE_DESCRIPTOR, false),
                Type.getMethodType(ApplicationEntryIndex.HTTP_HANDLER_HANDLE_DESCRIPTOR));
        main.visitMethodInsn(Opcodes.INVOKEVIRTUAL, ApplicationEntryIndex.HTTP_SERVER_OWNER,
                ApplicationEntryIndex.HTTP_SERVER_CREATE_CONTEXT_NAME,
                ApplicationEntryIndex.HTTP_SERVER_CREATE_CONTEXT_DESCRIPTOR, false);
        main.visitInsn(Opcodes.POP);
        main.visitInsn(Opcodes.RETURN);
        main.visitMaxs(3, 1);
        main.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] httpAllocatedWebClassBytes() {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "fixture/app/HttpAllocatedWeb", null,
                "java/lang/Object", null);
        MethodVisitor main = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "main",
                "([Ljava/lang/String;)V", null, new String[] {"java/io/IOException"});
        main.visitCode();
        main.visitMethodInsn(Opcodes.INVOKESTATIC, ApplicationEntryIndex.HTTP_SERVER_OWNER,
                "create", "()Lcom/sun/net/httpserver/HttpServer;", false);
        main.visitLdcInsn("/lookup");
        main.visitTypeInsn(Opcodes.NEW, "fixture/app/HttpAllocatedHandler");
        main.visitInsn(Opcodes.DUP);
        main.visitMethodInsn(Opcodes.INVOKESPECIAL, "fixture/app/HttpAllocatedHandler", "<init>",
                "()V", false);
        main.visitMethodInsn(Opcodes.INVOKEVIRTUAL, ApplicationEntryIndex.HTTP_SERVER_OWNER,
                ApplicationEntryIndex.HTTP_SERVER_CREATE_CONTEXT_NAME,
                ApplicationEntryIndex.HTTP_SERVER_CREATE_CONTEXT_DESCRIPTOR, false);
        main.visitInsn(Opcodes.POP);
        main.visitInsn(Opcodes.RETURN);
        main.visitMaxs(4, 1);
        main.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static byte[] httpAllocatedHandlerClassBytes() {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "fixture/app/HttpAllocatedHandler", null,
                "java/lang/Object", new String[] {ApplicationEntryIndex.HTTP_HANDLER_OWNER});

        MethodVisitor constructor = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V",
                null, null);
        constructor.visitCode();
        constructor.visitVarInsn(Opcodes.ALOAD, 0);
        constructor.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>",
                "()V", false);
        constructor.visitInsn(Opcodes.RETURN);
        constructor.visitMaxs(1, 1);
        constructor.visitEnd();

        MethodVisitor handle = writer.visitMethod(Opcodes.ACC_PUBLIC,
                ApplicationEntryIndex.HTTP_HANDLER_HANDLE_NAME,
                ApplicationEntryIndex.HTTP_HANDLER_HANDLE_DESCRIPTOR, null,
                new String[] {"java/io/IOException"});
        handle.visitCode();
        handle.visitVarInsn(Opcodes.ALOAD, 1);
        handle.visitMethodInsn(Opcodes.INVOKEINTERFACE,
                ApplicationEntryIndex.HTTP_EXCHANGE_OWNER, "getRequestHeaders",
                "()Lcom/sun/net/httpserver/Headers;", true);
        handle.visitLdcInsn("X-Lookup-URL");
        handle.visitMethodInsn(Opcodes.INVOKEVIRTUAL, ApplicationEntryIndex.HTTP_HEADERS_OWNER,
                "getFirst", "(Ljava/lang/String;)Ljava/lang/String;", false);
        handle.visitInsn(Opcodes.POP);
        handle.visitInsn(Opcodes.RETURN);
        handle.visitMaxs(2, 2);
        handle.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static Handle lambdaMetafactory() {
        return new Handle(Opcodes.H_INVOKESTATIC, "java/lang/invoke/LambdaMetafactory",
                "metafactory",
                "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;"
                        + "Ljava/lang/invoke/MethodType;Ljava/lang/invoke/MethodType;"
                        + "Ljava/lang/invoke/MethodHandle;Ljava/lang/invoke/MethodType;)"
                        + "Ljava/lang/invoke/CallSite;",
                false);
    }
}
