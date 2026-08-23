package io.just.sast.analysis.taint;

import io.just.sast.cpg.graph.Edge;
import io.just.sast.cpg.graph.EdgeType;
import io.just.sast.cpg.graph.Graph;
import io.just.sast.cpg.graph.Node;
import io.just.sast.cpg.graph.NodeType;

import java.util.HashMap;
import java.util.Map;

/**
 * region 划分（GadgetHunter FSE'26 opcode 定界的静态子集）：
 * invokestatic/invokespecial（静态可解调用）将两方法并入同一 region；
 * invokevirtual/interface/dynamic（动态分派）为 region 边界。
 * 链的 region 跨越数 = 跨动态分派次数的近似——审计维度 + 深链结构门协同。
 */
public final class RegionMap {

    private final Map<String, String> parent = new HashMap<>();

    public RegionMap(Graph graph) {
        for (Node method : graph.nodesOfType(NodeType.METHOD)) {
            parent.putIfAbsent(key(method), key(method));
        }
        for (Node call : graph.nodesOfType(NodeType.CALL)) {
            String kind = call.strProp("invokeKind");
            if (!"STATIC".equals(kind) && !"SPECIAL".equals(kind)) {
                continue; // 动态分派 = region 边界
            }
            for (Edge edge : call.out()) {
                if (edge.type() == EdgeType.INVOKES || edge.type() == EdgeType.LAMBDA) {
                    union(keyOf(call), key(edge.to()));
                }
            }
        }
    }

    private static String key(Node m) {
        return m.strProp("owner") + "#" + m.strProp("name") + m.strProp("desc");
    }

    private static String keyOf(Node call) {
        return call.strProp("methodOwner") + "#" + call.strProp("methodName") + call.strProp("methodDesc");
    }

    private String find(String k) {
        String root = k;
        while (!parent.get(root).equals(root)) {
            root = parent.get(root);
        }
        String cur = k;
        while (!parent.get(cur).equals(cur)) {
            String next = parent.get(cur);
            parent.put(cur, root);
            cur = next;
        }
        return root;
    }

    private void union(String a, String b) {
        String ra = find(a);
        String rb = find(b);
        if (!ra.equals(rb)) {
            parent.put(ra, rb);
        }
    }

    /** 两方法是否同 region。 */
    public boolean sameRegion(String methodKeyA, String methodKeyB) {
        String a = parent.get(methodKeyA);
        String b = parent.get(methodKeyB);
        return a != null && b != null && find(a).equals(find(b));
    }
}
