package io.just.sast.analysis.callgraph;

import io.just.sast.analysis.hierarchy.ClassHierarchy;
import io.just.sast.cpg.graph.EdgeType;
import io.just.sast.cpg.graph.Graph;
import io.just.sast.cpg.graph.Node;
import io.just.sast.cpg.graph.NodeType;
import io.just.sast.model.HandleRef;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import io.just.sast.model.InvokeDynamicRef;
import io.just.sast.util.JustLogger;
import java.lang.reflect.Modifier;

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
    /**
     * Many bytecode call sites share the same erased receiver/name/descriptor. Resolving the
     * same subtype closure and visibility predicate once per hierarchy revision avoids a large
     * repeated allocation/lookup cost without changing the candidate set or its order.
     */
    private final Map<DispatchKey, DispatchPlan> dispatchCache = new HashMap<>();

    private record DispatchKey(String kind, String owner, String name, String descriptor,
                               long hierarchyRevision) {}

    private record DispatchPlan(List<String> targets, boolean fallback, boolean skipped,
                                int candidateCount) {}

    public CallGraphBuilder(ClassHierarchy hierarchy) {
        this.hierarchy = hierarchy;
    }

    /** 返回添加的调用边数。 */
    public int build(Graph graph) {
        dispatchCache.clear();
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
        DispatchPlan plan = dispatchPlan("VIRTUAL", owner, name, desc);
        if (plan.skipped()) {
            call.propsNote("dispatchSkipped", plan.candidateCount());
        }
        if (plan.fallback()) {
            graph.addEdge(call, graph.methodNode(owner, name, desc, true), EdgeType.INVOKES, "VIRTUAL");
            return 1;
        }
        int count = 0;
        for (String target : plan.targets()) {
            graph.addEdge(call, graph.methodNode(target, name, desc, false), EdgeType.DISPATCHES, "VIRTUAL");
            count++;
        }
        return count;
    }

    private int addInterface(Graph graph, Node call, String owner, String name, String desc) {
        DispatchPlan plan = dispatchPlan("INTERFACE", owner, name, desc);
        if (plan.skipped()) {
            call.propsNote("dispatchSkipped", plan.candidateCount() < 0
                    ? "implementers-over-cap" : plan.candidateCount());
        }
        if (plan.fallback()) {
            graph.addEdge(call, graph.methodNode(owner, name, desc, true), EdgeType.INVOKES, "INTERFACE");
            return 1;
        }
        int count = 0;
        for (String target : plan.targets()) {
            graph.addEdge(call, graph.methodNode(target, name, desc, false), EdgeType.DISPATCHES, "INTERFACE");
            count++;
        }
        return count;
    }

    private DispatchPlan dispatchPlan(String kind, String owner, String name, String desc) {
        DispatchKey key = new DispatchKey(kind, owner, name, desc, hierarchy.revision());
        DispatchPlan cached = dispatchCache.get(key);
        if (cached != null) {
            return cached;
        }
        String declared = hierarchy.resolveMethod(owner, name, desc);
        Set<String> targets = new LinkedHashSet<>();
        if (declared != null) {
            targets.add(declared);
        }
        // A final receiver class or a final/private/static declaration cannot have a
        // dynamically dispatched implementation.  Expanding its subtype closure is both
        // semantically redundant and very expensive for ubiquitous Object/JDK calls in fat
        // jars.  Keep the single resolved target and preserve the ordinary edge shape.
        if (declared != null && isFixedDispatch(owner, declared, name, desc)) {
            return new DispatchPlan(List.copyOf(targets), false, false, 0);
        }
        boolean skipped = false;
        int candidateCount = 0;
        if ("VIRTUAL".equals(kind)) {
            ClassHierarchy.SubtypeResult subtypeResult = hierarchy.transitiveSubtypes(owner, DISPATCH_CAP);
            List<String> subtypes = subtypeResult.values();
            candidateCount = subtypes.size();
            if (!subtypeResult.complete()) {
                skipped = true;
            } else {
                for (String sub : subtypes) {
                    String resolved = hierarchy.resolveMethod(sub, name, desc);
                    String overrideRef = declared != null ? declared : owner;
                    if (resolved != null
                            && hierarchy.isOverridableDispatchTarget(overrideRef, sub, name, desc)) {
                        targets.add(resolved);
                    }
                }
            }
        } else {
            List<String> implementers = hierarchy.implementers(owner, DISPATCH_CAP);
            if (implementers == null) {
                skipped = true;
                candidateCount = -1;
            } else {
                candidateCount = implementers.size();
                for (String impl : implementers) {
                    String resolved = hierarchy.resolveMethod(impl, name, desc);
                    String overrideRef = declared != null ? declared : owner;
                    if (resolved != null
                            && hierarchy.isOverridableDispatchTarget(overrideRef, impl, name, desc)) {
                        targets.add(resolved);
                    }
                }
            }
        }
        DispatchPlan result = targets.isEmpty()
                ? new DispatchPlan(List.of(), true, skipped, candidateCount)
                : new DispatchPlan(List.copyOf(targets), false, skipped, candidateCount);
        dispatchCache.put(key, result);
        return result;
    }

    private boolean isFixedDispatch(String receiverOwner, String declaredOwner,
                                    String name, String desc) {
        int access = hierarchy.methodAccess(declaredOwner, name, desc);
        if (access >= 0 && (Modifier.isFinal(access) || Modifier.isPrivate(access)
                || Modifier.isStatic(access))) {
            return true;
        }
        io.just.sast.model.ClassInfo receiver = hierarchy.classInfo(receiverOwner);
        return receiver != null && Modifier.isFinal(receiver.access());
    }

    private int addLambda(Graph graph, Node call, InvokeDynamicRef indy) {
        if (indy == null) {
            return 0;
        }
        if (indy.bootstrap() != null && LAMBDA_METAFACTORY.equals(indy.bootstrap().owner())) {
            // Both metafactory and altMetafactory keep the implementation handle in the
            // bootstrap argument list.  Scan all handle arguments after the SAM type instead
            // of hard-coding index 1: this preserves bridge/adapter variants emitted by newer
            // compilers and remains conservative because marker/bridge metadata is TypeRef,
            // not HandleRef.  A stable set avoids duplicate edges for repeated handles.
            Set<String> seen = new LinkedHashSet<>();
            int count = 0;
            for (int i = 1; i < indy.bootstrapArgs().size(); i++) {
                Object impl = indy.bootstrapArgs().get(i);
                if (impl instanceof HandleRef h && seen.add(h.owner() + "#"
                        + h.name() + h.descriptor())) {
                    String target = hierarchy.resolveMethod(h.owner(), h.name(), h.descriptor());
                    // 与 SPECIAL 边同语义：用解析后的真实声明类建节点（方法引用指向继承方法时避免幽灵节点）
                    String edgeOwner = target != null ? target : h.owner();
                    graph.addEdge(call,
                            graph.methodNode(edgeOwner, h.name(), h.descriptor(), target == null),
                            EdgeType.LAMBDA, "LAMBDA");
                    count++;
                }
            }
            return count;
        }
        return 0;
    }
}
