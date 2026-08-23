package io.just.sast.cpg.graph;

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * CPG 内存图。只物化被消费的结构：
 * METHOD/CALL 节点 + 调用边（INVOKES/DISPATCHES/LAMBDA）。
 * CFG 与 def-use 由分析引擎按需计算（惰性），不落图。
 * 构建完成后调用 freeze()，此后禁止写入（分析期只读契约）。单线程契约：构建与分析均串行，不加锁。
 */
public final class Graph {

    private final List<Node> nodes = new ArrayList<>();
    private final Map<NodeType, List<Node>> byType = new EnumMap<>(NodeType.class);
    private final Map<String, Node> methodsByKey = new HashMap<>();
    private boolean frozen;

    public Node addNode(NodeType type, Map<String, Object> props) {
        assertWritable();
        Node node = new Node(nodes.size(), type, props);
        nodes.add(node);
        byType.computeIfAbsent(type, t -> new ArrayList<>()).add(node);
        if (type == NodeType.METHOD) {
            methodsByKey.put(methodKey(node.strProp("owner"), node.strProp("name"), node.strProp("desc")), node);
        }
        return node;
    }

    /** 取方法节点；不存在则创建（external 表示不在已解析类集合中）。 */
    public Node methodNode(String owner, String name, String desc, boolean external) {
        String key = methodKey(owner, name, desc);
        Node existing = methodsByKey.get(key);
        if (existing != null) {
            return existing;
        }
        Map<String, Object> props = new HashMap<>();
        props.put("owner", owner);
        props.put("name", name);
        props.put("desc", desc);
        props.put("external", external);
        return addNode(NodeType.METHOD, props);
    }

    /** 只读查找方法节点，不存在返回 null。 */
    public Node findMethodNode(String owner, String name, String desc) {
        return methodsByKey.get(methodKey(owner, name, desc));
    }

    public void addEdge(Node from, Node to, EdgeType type, String label) {
        assertWritable();
        Edge edge = new Edge(from, to, type, label);
        from.addOut(edge);
        to.addIn(edge);
    }

    /** 冻结图：构建期结束，此后只读。 */
    public void freeze() {
        frozen = true;
    }

    private void assertWritable() {
        if (frozen) {
            throw new IllegalStateException("图已冻结（分析期只读），禁止写入");
        }
    }

    public List<Node> nodesOfType(NodeType type) {
        List<Node> list = byType.get(type);
        return list != null ? list : List.of();
    }

    public Node node(long id) {
        return nodes.get((int) id);
    }

    public int nodeCount() {
        return nodes.size();
    }

    public int edgeCount() {
        int count = 0;
        for (Node node : nodes) {
            count += node.out().size();
        }
        return count;
    }

    private static String methodKey(String owner, String name, String desc) {
        return owner + "#" + name + desc;
    }
}
