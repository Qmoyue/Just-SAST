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
import static org.junit.jupiter.api.Assertions.assertTrue;

class CallGraphBuilderTest {

    @Test
    void altMetafactoryRetainsAllMethodHandleTargetsWithoutDuplicateEdges() {
        String descriptor = "()V";
        MethodInfo first = new MethodInfo("fixture/First", "run", descriptor,
                Modifier.PUBLIC | Modifier.STATIC, List.of(), List.of(), false);
        MethodInfo second = new MethodInfo("fixture/Second", "run", descriptor,
                Modifier.PUBLIC | Modifier.STATIC, List.of(), List.of(), false);
        ClassHierarchy hierarchy = new ClassHierarchy(Map.of(
                "fixture/First", new ClassInfo("fixture/First", "java/lang/Object", List.of(),
                        Modifier.PUBLIC, List.of(first), List.of()),
                "fixture/Second", new ClassInfo("fixture/Second", "java/lang/Object", List.of(),
                        Modifier.PUBLIC, List.of(second), List.of())), null);

        HandleRef bootstrap = new HandleRef(6, "java/lang/invoke/LambdaMetafactory",
                "altMetafactory", "()V");
        HandleRef firstHandle = new HandleRef(6, "fixture/First", "run", descriptor);
        HandleRef secondHandle = new HandleRef(6, "fixture/Second", "run", descriptor);
        InvokeDynamicRef indy = new InvokeDynamicRef("run", "()Ljava/lang/Runnable;",
                bootstrap, List.of(new TypeRef("()V"), firstHandle, secondHandle,
                        Integer.valueOf(0)));

        Graph graph = new Graph();
        graph.methodNode("fixture/Host", "make", "()Ljava/lang/Runnable;", false);
        Node call = graph.addCallNode("java/lang/invoke/LambdaMetafactory", "altMetafactory",
                "()Ljava/lang/Runnable;", "DYNAMIC", indy, 0,
                "fixture/Host", "make", "()Ljava/lang/Runnable;");

        int edges = new CallGraphBuilder(hierarchy).build(graph);

        assertEquals(2, edges);
        assertEquals(2, call.out().stream().filter(edge -> edge.type() == EdgeType.LAMBDA).count());
        assertTrue(graph.nodesOfType(NodeType.METHOD).stream()
                .anyMatch(node -> "fixture/First".equals(node.owner())));
        assertTrue(graph.nodesOfType(NodeType.METHOD).stream()
                .anyMatch(node -> "fixture/Second".equals(node.owner())));
    }
}
