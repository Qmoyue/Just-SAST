package io.just.sast.analysis.callgraph;

import io.just.sast.analysis.hierarchy.ClassHierarchy;
import io.just.sast.cpg.graph.EdgeType;
import io.just.sast.cpg.graph.Graph;
import io.just.sast.cpg.graph.Node;
import io.just.sast.cpg.graph.NodeType;
import io.just.sast.model.ClassInfo;
import io.just.sast.model.HandleRef;
import io.just.sast.model.InvokeDynamicRef;
import io.just.sast.model.MethodInfo;
import io.just.sast.model.TypeRef;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Modifier;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CallGraphBuilderTest {

    @Test
    void metafactoryUsesExactImplementationHandleAndPublishesTypedSite() {
        String descriptor = "()V";
        MethodInfo implementation = new MethodInfo("fixture/First", "ordinary", descriptor,
                Modifier.PUBLIC | Modifier.STATIC, List.of(), List.of(), false);
        ClassHierarchy hierarchy = hierarchyOf(implementation);

        InvokeDynamicRef indy = indy("metafactory", "run", "()Ljava/lang/Runnable;",
                List.of(new TypeRef(descriptor),
                        new HandleRef(6, "fixture/First", "ordinary", descriptor),
                        new TypeRef(descriptor)));
        Graph graph = graphWithCall(indy);

        Node call = graph.nodesOfType(NodeType.CALL).get(0);
        int edges = new CallGraphBuilder(hierarchy).build(graph);

        assertEquals(1, edges);
        assertEquals(1, call.out().stream().filter(edge -> edge.type() == EdgeType.LAMBDA).count());
        assertEquals("RESOLVED", call.note("lambdaResolution"));
        var site = (io.just.sast.model.LambdaMetafactoryCallSite) call.note("lambdaCallSite");
        assertEquals("fixture/First", site.implementation().owner());
        assertEquals("ordinary", site.implementation().name());
        assertEquals("java/lang/Runnable", site.functionalInterfaceMethod().owner());
        assertEquals("run", site.functionalInterfaceMethod().name());
        assertEquals(descriptor, site.functionalInterfaceMethod().descriptor());
        assertTrue(graph.nodesOfType(NodeType.METHOD).stream()
                .anyMatch(node -> "fixture/First".equals(node.owner())
                        && "ordinary".equals(node.name())));
    }

    @Test
    void altMetafactoryDoesNotTreatMetadataHandleAsImplementation() {
        String descriptor = "()V";
        MethodInfo implementation = new MethodInfo("fixture/First", "ordinary", descriptor,
                Modifier.PUBLIC | Modifier.STATIC, List.of(), List.of(), false);
        ClassHierarchy hierarchy = hierarchyOf(implementation);
        HandleRef implementationHandle = new HandleRef(6, "fixture/First", "ordinary", descriptor);
        HandleRef metadataHandle = new HandleRef(6, "fixture/Second", "metadata", descriptor);
        InvokeDynamicRef indy = indy("altMetafactory", "run", "()Ljava/lang/Runnable;",
                List.of(new TypeRef(descriptor), implementationHandle, new TypeRef(descriptor),
                        Integer.valueOf(0), metadataHandle));
        Graph graph = graphWithCall(indy);

        int edges = new CallGraphBuilder(hierarchy).build(graph);

        Node call = graph.nodesOfType(NodeType.CALL).get(0);
        assertEquals(0, edges);
        assertEquals(0, call.out().stream().filter(edge -> edge.type() == EdgeType.LAMBDA).count());
        assertEquals("UNKNOWN_ARGUMENTS", call.note("lambdaResolution"));
        assertTrue(graph.nodesOfType(NodeType.METHOD).stream()
                .noneMatch(node -> "fixture/First".equals(node.owner())
                        || "fixture/Second".equals(node.owner())));
    }

    @Test
    void altMetafactoryRetainsTypedMetadataAroundOneImplementation() {
        String descriptor = "()V";
        MethodInfo implementation = new MethodInfo("fixture/First", "ordinary", descriptor,
                Modifier.PUBLIC | Modifier.STATIC, List.of(), List.of(), false);
        ClassHierarchy hierarchy = hierarchyOf(implementation);
        InvokeDynamicRef indy = indy("altMetafactory", "run", "()Ljava/lang/Runnable;",
                List.of(new TypeRef(descriptor),
                        new HandleRef(6, "fixture/First", "ordinary", descriptor),
                        new TypeRef(descriptor), Integer.valueOf(6), Integer.valueOf(1),
                        new TypeRef("Lfixture/Marker;"), Integer.valueOf(1),
                        new TypeRef(descriptor)));
        Graph graph = graphWithCall(indy);

        int edges = new CallGraphBuilder(hierarchy).build(graph);

        Node call = graph.nodesOfType(NodeType.CALL).get(0);
        var site = (io.just.sast.model.LambdaMetafactoryCallSite) call.note("lambdaCallSite");
        assertEquals(1, edges);
        assertEquals(6, site.flags());
        assertEquals(List.of("fixture/Marker"), site.markerInterfaces());
        assertEquals(List.of(descriptor), site.bridgeDescriptors());
        assertEquals(1, call.out().stream().filter(edge -> edge.type() == EdgeType.LAMBDA).count());
    }

    @Test
    void wrongBootstrapDoesNotGuessLambdaByName() {
        String descriptor = "()V";
        MethodInfo implementation = new MethodInfo("fixture/First", "lambda$maybe", descriptor,
                Modifier.PUBLIC | Modifier.STATIC, List.of(), List.of(), false);
        ClassHierarchy hierarchy = hierarchyOf(implementation);
        InvokeDynamicRef indy = indy("notMetafactory", "lambda$maybe",
                "()Ljava/lang/Runnable;",
                List.of(new TypeRef(descriptor),
                        new HandleRef(6, "fixture/First", "lambda$maybe", descriptor),
                        new TypeRef(descriptor)));
        Graph graph = graphWithCall(indy);

        int edges = new CallGraphBuilder(hierarchy).build(graph);

        Node call = graph.nodesOfType(NodeType.CALL).get(0);
        assertEquals(0, edges);
        assertEquals(0, call.out().size());
        assertNull(call.note("lambdaResolution"));
        assertTrue(graph.nodesOfType(NodeType.METHOD).stream()
                .noneMatch(node -> "fixture/First".equals(node.owner())));
    }

    @Test
    void malformedMetafactoryDescriptorIsExplicitlyUnknown() {
        String descriptor = "()V";
        MethodInfo implementation = new MethodInfo("fixture/First", "ordinary", descriptor,
                Modifier.PUBLIC | Modifier.STATIC, List.of(), List.of(), false);
        ClassHierarchy hierarchy = hierarchyOf(implementation);
        InvokeDynamicRef indy = indy("metafactory", "run", "()Ljava/lang/Runnable;",
                List.of(new TypeRef("not-a-method-descriptor"),
                        new HandleRef(6, "fixture/First", "ordinary", descriptor),
                        new TypeRef(descriptor)));
        Graph graph = graphWithCall(indy);

        int edges = new CallGraphBuilder(hierarchy).build(graph);

        Node call = graph.nodesOfType(NodeType.CALL).get(0);
        assertEquals(0, edges);
        assertEquals("UNKNOWN_DESCRIPTOR", call.note("lambdaResolution"));
        assertEquals(0, call.out().size());
    }

    @Test
    void interfaceImplementerCapKeepsDeclaredEdgeWithoutGlobalExpansion() {
        String descriptor = "()V";
        MethodInfo declaration = new MethodInfo("fixture/Service", "run", descriptor,
                Modifier.PUBLIC | Modifier.ABSTRACT, List.of(), List.of(), false);
        Map<String, ClassInfo> classes = new java.util.LinkedHashMap<>();
        classes.put("fixture/Service", new ClassInfo("fixture/Service", "java/lang/Object",
                List.of(), Modifier.PUBLIC | Modifier.INTERFACE | Modifier.ABSTRACT,
                List.of(declaration), List.of()));
        for (int index = 0; index < 201; index++) {
            String owner = "fixture/Impl" + index;
            MethodInfo implementation = new MethodInfo(owner, "run", descriptor, Modifier.PUBLIC,
                    List.of(), List.of(), false);
            classes.put(owner, new ClassInfo(owner, "java/lang/Object",
                    List.of("fixture/Service"), Modifier.PUBLIC, List.of(implementation),
                    List.of()));
        }
        ClassHierarchy hierarchy = new ClassHierarchy(classes, null);
        Graph graph = new Graph();
        graph.methodNode("fixture/Host", "call", "()V", false);
        graph.addCallNode("fixture/Service", "run", descriptor, "INTERFACE", null, 0,
                "fixture/Host", "call", "()V");
        Node call = graph.nodesOfType(NodeType.CALL).get(0);

        int edges = new CallGraphBuilder(hierarchy).build(graph);

        assertEquals(1, edges);
        assertEquals(1, call.out().size());
        assertEquals(EdgeType.DISPATCHES, call.out().get(0).type());
        assertEquals("fixture/Service", call.out().get(0).to().owner());
        assertEquals("implementers-over-cap", call.note("dispatchSkipped"));
        assertTrue(graph.nodesOfType(NodeType.METHOD).stream()
                .noneMatch(node -> node.owner().startsWith("fixture/Impl")));
    }

    private static ClassHierarchy hierarchyOf(MethodInfo... methods) {
        Map<String, ClassInfo> classes = new java.util.LinkedHashMap<>();
        for (MethodInfo method : methods) {
            classes.put(method.owner(), new ClassInfo(method.owner(), "java/lang/Object", List.of(),
                    Modifier.PUBLIC, List.of(method), List.of()));
        }
        return new ClassHierarchy(classes, null);
    }

    private static InvokeDynamicRef indy(String bootstrapName, String name, String descriptor,
                                         List<Object> arguments) {
        return new InvokeDynamicRef(name, descriptor,
                new HandleRef(6, "java/lang/invoke/LambdaMetafactory", bootstrapName, "()V"),
                arguments);
    }

    private static Graph graphWithCall(InvokeDynamicRef indy) {
        Graph graph = new Graph();
        graph.methodNode("fixture/Host", "make", "()Ljava/lang/Runnable;", false);
        graph.addCallNode("java/lang/invoke/LambdaMetafactory", indy.name(), indy.descriptor(),
                "DYNAMIC", indy, 0, "fixture/Host", "make", "()Ljava/lang/Runnable;");
        return graph;
    }
}
