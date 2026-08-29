package io.just.sast.cpg.graph;

import java.util.ArrayList;
import java.util.Collections;
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
    /** 调用点按宿主方法保持构建顺序；方法级图遍历无需再扫描整段指令。 */
    private final Map<String, List<Node>> callListsByMethod = new HashMap<>();
    private final Map<String, List<Node>> readOnlyCallListsByMethod = new HashMap<>();
    private final Map<NodeType, List<Node>> readOnlyByType = new EnumMap<>(NodeType.class);
    private int edgeCount;
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
        assertWritable();
        Node node = new Node(nodes.size(), owner, name, desc, external);
        nodes.add(node);
        byType.computeIfAbsent(NodeType.METHOD, t -> new ArrayList<>()).add(node);
        methodsByKey.put(key, node);
        return node;
    }

    /** CPG 热路径专用调用点入口；属性布局由 Node 紧凑保存。 */
    public Node addCallNode(String owner, String name, String desc, String invokeKind,
                            Object indy, int offset, String methodOwner,
                            String methodName, String methodDesc) {
        assertWritable();
        Node node = new Node(nodes.size(), owner, name, desc, invokeKind, indy, offset,
                methodOwner, methodName, methodDesc);
        nodes.add(node);
        byType.computeIfAbsent(NodeType.CALL, t -> new ArrayList<>()).add(node);
        String hostKey = methodKey(methodOwner, methodName, methodDesc);
        callListsByMethod.computeIfAbsent(hostKey, ignored -> new ArrayList<>()).add(node);
        return node;
    }

    /** 只读查找方法节点，不存在返回 null。 */
    public Node findMethodNode(String owner, String name, String desc) {
        return methodsByKey.get(methodKey(owner, name, desc));
    }

    /** 已有规范方法键的直接查找，避免热路径重复拆分/拼接 owner、name、descriptor。 */
    public Node findMethodNodeKey(String key) {
        return methodsByKey.get(key);
    }

    /** 通过宿主方法键和指令 offset 查找调用点；图构建完成后只读。 */
    public Node findCallNode(String methodKey, int offset) {
        List<Node> calls = callListsByMethod.get(methodKey);
        if (calls == null || calls.isEmpty()) {
            return null;
        }
        // CpgBuilder visits instructions in bytecode order, so the per-method list is
        // sorted by offset.  Binary search preserves the old O(1)-ish lookup contract
        // without retaining a boxed Integer/HashMap entry for every call site.
        int low = 0;
        int high = calls.size() - 1;
        while (low <= high) {
            int middle = (low + high) >>> 1;
            Node candidate = calls.get(middle);
            int candidateOffset = candidate.offset();
            if (candidateOffset < offset) {
                low = middle + 1;
            } else if (candidateOffset > offset) {
                high = middle - 1;
            } else {
                return candidate;
            }
        }
        return null;
    }

    /**
     * 取宿主方法内的调用点，顺序与前端添加 CALL 节点的顺序一致。
     * 构建完成后返回稳定只读视图；不存在调用点时返回共享空列表。
     */
    public List<Node> callsOfMethod(String methodKey) {
        List<Node> readOnly = readOnlyCallListsByMethod.get(methodKey);
        if (readOnly != null) {
            return readOnly;
        }
        List<Node> calls = callListsByMethod.get(methodKey);
        return calls == null ? List.of() : Collections.unmodifiableList(calls);
    }

    public void addEdge(Node from, Node to, EdgeType type, String label) {
        assertWritable();
        Edge edge = new Edge(from, to, type, label);
        from.addOut(edge);
        to.addIn(edge);
        edgeCount++;
    }

    /** 冻结图：构建期结束，此后只读。 */
    public void freeze() {
        frozen = true;
        for (Map.Entry<NodeType, List<Node>> entry : byType.entrySet()) {
            readOnlyByType.put(entry.getKey(), Collections.unmodifiableList(entry.getValue()));
        }
        for (Map.Entry<String, List<Node>> entry : callListsByMethod.entrySet()) {
            readOnlyCallListsByMethod.put(entry.getKey(), Collections.unmodifiableList(entry.getValue()));
        }
        for (Node node : nodes) {
            node.freezeAdjacency();
        }
    }

    private void assertWritable() {
        if (frozen) {
            throw new IllegalStateException("图已冻结（分析期只读），禁止写入");
        }
    }

    public List<Node> nodesOfType(NodeType type) {
        List<Node> list = byType.get(type);
        if (list == null) {
            return List.of();
        }
        List<Node> readOnly = readOnlyByType.get(type);
        return readOnly != null ? readOnly : Collections.unmodifiableList(list);
    }

    public Node node(long id) {
        return nodes.get((int) id);
    }

    public int nodeCount() {
        return nodes.size();
    }

    public int edgeCount() {
        return edgeCount;
    }

    private static String methodKey(String owner, String name, String desc) {
        return owner + "#" + name + desc;
    }
}
