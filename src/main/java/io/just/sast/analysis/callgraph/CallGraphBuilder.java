package io.just.sast.analysis.callgraph;

import io.just.sast.analysis.hierarchy.ClassHierarchy;
import io.just.sast.cpg.graph.EdgeType;
import io.just.sast.cpg.graph.Graph;
import io.just.sast.cpg.graph.Node;
import io.just.sast.cpg.graph.NodeType;
import io.just.sast.model.HandleRef;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import io.just.sast.model.InvokeDynamicRef;
import io.just.sast.util.JustLogger;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * CHA 调用图构建：静态/特殊调用定目标（SPECIAL 边用 resolveMethod 后的真实声明类）；
 * 分发目标做可见性剪枝（private/static/跨包 package-private 不可覆写，FLASH USENIX'25）；
 * 虚调用/接口调用按**传递子类型闭包**分发（深继承链中的覆写方法同样获得边）；
 * invokedynamic 解析 LambdaMetafactory → lambda 实现方法。
 * 反射与动态代理边不在此处盲加（噪音大），由前向引擎精扫按需解析。
 */
public final class CallGraphBuilder {

    /** 虚调用/接口实现枚举上限（超出只取声明目标；具体实现由接口反向分发补齐）。 */
    private static final int DISPATCH_CAP = 200;
    private static final String LAMBDA_METAFACTORY = "java/lang/invoke/LambdaMetafactory";

    private final ClassHierarchy hierarchy;

    public CallGraphBuilder(ClassHierarchy hierarchy) {
        this.hierarchy = hierarchy;
    }

    /** 返回添加的调用边数。 */
    public int build(Graph graph) {
        int edgeCount = 0;
        for (Node call : graph.nodesOfType(NodeType.CALL)) {
            String kind = call.strProp("invokeKind");
            String owner = call.strProp("owner");
            String name = call.strProp("name");
            String desc = call.strProp("desc");
            switch (kind) {
                case "STATIC", "SPECIAL" -> {
                    String resolved = hierarchy.resolveMethod(owner, name, desc);
                    // SPECIAL 边（super 调用）：用 resolveMethod 后的真实声明类，
                    // 避免幽灵节点（如 super.toString() 解析到 AbstractCollection 而非字节码里的 AbstractList）
                    String edgeOwner = resolved != null ? resolved : owner;
                    graph.addEdge(call, graph.methodNode(edgeOwner, name, desc, resolved == null),
                            EdgeType.INVOKES, kind);
                    edgeCount++;
                }
                case "VIRTUAL" -> edgeCount += addVirtual(graph, call, owner, name, desc);
                case "INTERFACE" -> edgeCount += addInterface(graph, call, owner, name, desc);
                case "DYNAMIC" -> edgeCount += addLambda(graph, call, (InvokeDynamicRef) call.prop("indy"));
                default -> JustLogger.debug("未知调用类型 {}: {}#{}", kind, owner, name);
            }
        }
        return edgeCount;
    }

    private int addVirtual(Graph graph, Node call, String owner, String name, String desc) {
        String declared = hierarchy.resolveMethod(owner, name, desc);
        // 传递子类型闭包（直接子类 + 所有孙类）：深继承链中的覆写方法同样获得分发边
        List<String> subtypes = transitiveSubtypes(owner);
        if (declared == null && subtypes.isEmpty()) {
            graph.addEdge(call, graph.methodNode(owner, name, desc, true), EdgeType.INVOKES, "VIRTUAL");
            return 1;
        }
        Set<String> targets = new LinkedHashSet<>();
        if (declared != null) {
            targets.add(declared);
        }
        if (subtypes.size() > DISPATCH_CAP) {
            call.propsNote("dispatchSkipped", subtypes.size());
        } else {
            for (String sub : subtypes) {
                String resolved = hierarchy.resolveMethod(sub, name, desc);
                // 可见性剪枝（FLASH, USENIX'25）：private/static/跨包 package-private 不可覆写，非真实分发目标
                // 包比较基准 = 被覆写方法的声明类（declared），非调用点静态类型
                String overrideRef = declared != null ? declared : owner;
                if (resolved != null && hierarchy.isOverridableDispatchTarget(overrideRef, sub, name, desc)) {
                    targets.add(resolved);
                }
            }
        }
        if (targets.isEmpty()) {
            graph.addEdge(call, graph.methodNode(owner, name, desc, true), EdgeType.INVOKES, "VIRTUAL");
            return 1;
        }
        int count = 0;
        for (String target : targets) {
            graph.addEdge(call, graph.methodNode(target, name, desc, false), EdgeType.DISPATCHES, "VIRTUAL");
            count++;
        }
        return count;
    }

    private int addInterface(Graph graph, Node call, String owner, String name, String desc) {
        String declared = hierarchy.resolveMethod(owner, name, desc);
        List<String> impls = hierarchy.implementers(owner, DISPATCH_CAP);
        Set<String> targets = new LinkedHashSet<>();
        if (declared != null) {
            targets.add(declared);
        }
        if (impls != null) {
            for (String impl : impls) {
                String resolved = hierarchy.resolveMethod(impl, name, desc);
                // 可见性剪枝（FLASH, USENIX'25）：private/static/跨包 package-private 不可覆写，非真实分发目标
                // 包比较基准 = 被覆写方法的声明类（declared），非调用点静态类型
                String overrideRef = declared != null ? declared : owner;
                if (resolved != null && hierarchy.isOverridableDispatchTarget(overrideRef, impl, name, desc)) {
                    targets.add(resolved);
                }
            }
        } else {
            call.propsNote("dispatchSkipped", "implementers-over-cap");
        }
        if (targets.isEmpty()) {
            graph.addEdge(call, graph.methodNode(owner, name, desc, true), EdgeType.INVOKES, "INTERFACE");
            return 1;
        }
        int count = 0;
        for (String target : targets) {
            graph.addEdge(call, graph.methodNode(target, name, desc, false), EdgeType.DISPATCHES, "INTERFACE");
            count++;
        }
        return count;
    }

    private int addLambda(Graph graph, Node call, InvokeDynamicRef indy) {
        if (indy == null) {
            return 0;
        }
        if (LAMBDA_METAFACTORY.equals(indy.bootstrap().owner()) && indy.bootstrapArgs().size() > 1) {
            Object impl = indy.bootstrapArgs().get(1);
            if (impl instanceof HandleRef h) {
                String target = hierarchy.resolveMethod(h.owner(), h.name(), h.descriptor());
                // 与 SPECIAL 边同语义：用解析后的真实声明类建节点（方法引用指向继承方法时避免幽灵节点）
                String edgeOwner = target != null ? target : h.owner();
                graph.addEdge(call, graph.methodNode(edgeOwner, h.name(), h.descriptor(), target == null),
                        EdgeType.LAMBDA, "LAMBDA");
                return 1;
            }
        }
        return 0;
    }

    /** 传递子类型闭包：BFS 穿过子类链（如 JsonSerializer → StdSerializer → BeanSerializerBase → BeanSerializer）。 */
    private List<String> transitiveSubtypes(String owner) {
        Set<String> result = new LinkedHashSet<>();
        Set<String> visited = new java.util.HashSet<>();
        Deque<String> work = new ArrayDeque<>();
        work.add(owner);
        while (!work.isEmpty()) {
            String cur = work.poll();
            if (!visited.add(cur)) {
                continue;
            }
            for (String sub : hierarchy.loadedSubtypes(cur)) {
                result.add(sub);
                work.add(sub);
            }
        }
        return new ArrayList<>(result);
    }
}
