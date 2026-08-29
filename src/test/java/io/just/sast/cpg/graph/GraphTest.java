package io.just.sast.cpg.graph;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertEquals;

/** CPG 图只读契约：冻结后不仅 Graph 写入口，公开集合视图也不能被外部篡改。 */
class GraphTest {

    @Test
    void adjacencyAndTypeViewsCannotBeMutatedExternally() {
        Graph graph = new Graph();
        Node method = graph.addNode(NodeType.METHOD,
                Map.of("owner", "A", "name", "m", "desc", "()V"));
        Node call = graph.addNode(NodeType.CALL,
                Map.of("owner", "B", "name", "run", "desc", "()V"));
        graph.addEdge(call, method, EdgeType.INVOKES, "SPECIAL");
        graph.freeze();

        assertEquals(1, graph.nodesOfType(NodeType.METHOD).size());
        assertThrows(UnsupportedOperationException.class,
                () -> graph.nodesOfType(NodeType.METHOD).add(method));
        assertThrows(UnsupportedOperationException.class, () -> call.out().clear());
        assertThrows(UnsupportedOperationException.class, () -> method.in().clear());
    }

    @Test
    void compactCallNodeKeepsThePublicPropertyContract() {
        Graph graph = new Graph();
        Node call = graph.addCallNode("a/Owner", "run", "(Ljava/lang/Object;)V",
                "VIRTUAL", "indy-data", 17, "a/Host", "entry", "()V");

        assertEquals("a/Owner", call.strProp("owner"));
        assertEquals("run", call.strProp("name"));
        assertEquals("(Ljava/lang/Object;)V", call.strProp("desc"));
        assertEquals("VIRTUAL", call.strProp("invokeKind"));
        assertEquals(17, call.prop("offset"));
        assertEquals("a/Host", call.strProp("methodOwner"));
        assertEquals("entry", call.strProp("methodName"));
        assertEquals("()V", call.strProp("methodDesc"));
        assertEquals("indy-data", call.prop("indy"));
        assertEquals(call.props().get("owner"), call.prop("owner"));
    }

    @Test
    void callAndMethodIndexesResolveWithoutReconstructingNodes() {
        Graph graph = new Graph();
        Node method = graph.methodNode("a/Host", "entry", "()V", false);
        Node first = graph.addCallNode("a/Target", "first", "()V", "VIRTUAL", null,
                3, "a/Host", "entry", "()V");
        Node call = graph.addCallNode("a/Target", "run", "()V", "VIRTUAL", null,
                8, "a/Host", "entry", "()V");

        assertEquals(method, graph.findMethodNodeKey("a/Host#entry()V"));
        assertEquals(first, graph.findCallNode("a/Host#entry()V", 3));
        assertEquals(call, graph.findCallNode("a/Host#entry()V", 8));
        assertNull(graph.findCallNode("a/Host#entry()V", 4));
        assertEquals(List.of(first, call), graph.callsOfMethod("a/Host#entry()V"));
        graph.freeze();
        assertThrows(UnsupportedOperationException.class,
                () -> graph.callsOfMethod("a/Host#entry()V").clear());
    }
}
