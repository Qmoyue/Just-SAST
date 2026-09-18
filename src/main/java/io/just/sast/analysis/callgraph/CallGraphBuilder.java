package io.just.sast.analysis.callgraph;

import io.just.sast.analysis.hierarchy.ClassHierarchy;
import io.just.sast.cpg.graph.EdgeType;
import io.just.sast.cpg.graph.Graph;
import io.just.sast.cpg.graph.Node;
import io.just.sast.cpg.graph.NodeType;
import io.just.sast.model.HandleRef;
import io.just.sast.model.HessianProxyInvokeDispatch;
import io.just.sast.model.LambdaMetafactoryCallSite;
import io.just.sast.model.JndiObjectFactoryCallSite;
import io.just.sast.model.JndiObjectFactoryDispatch;
import io.just.sast.model.JaasLoginModuleCallSite;
import io.just.sast.model.JaasLoginModuleDispatch;
import io.just.sast.model.JdkSourceInfo;
import io.just.sast.model.MethodId;
import io.just.sast.model.MethodInfo;
import io.just.sast.model.ProxyCreationCallSite;
import io.just.sast.model.ProxyInterfaceCallSite;
import io.just.sast.model.ProxyInterfaceDispatch;
import io.just.sast.model.ClassInfo;
import java.util.HashMap;
import java.util.Map;
import io.just.sast.model.InvokeDynamicRef;
import io.just.sast.util.JustLogger;
import java.lang.reflect.Modifier;

import java.util.ArrayList;
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
                case "INTERFACE" -> edgeCount += addInterfaceOrProxy(graph, call, owner, name, desc);
                case "DYNAMIC" -> edgeCount += addLambda(graph, call, (InvokeDynamicRef) call.prop("indy"));
                default -> JustLogger.debug("未知调用类型 {}: {}#{}", kind, owner, name);
            }
            annotateObjectFactoryDispatch(call);
            edgeCount += annotateJaasLoginModuleDispatch(graph, call);
        }
        return edgeCount;
    }

    /**
     * Publish the exact JNDI callback contract after ordinary bounded interface dispatch has
     * produced its graph edges.  This is evidence only: no factory class is loaded, initialized,
     * reflectively invoked, or interpreted here.
     */
    private void annotateObjectFactoryDispatch(Node call) {
        String hostMethodKey = call.methodOwner() + "#" + call.methodName()
                + call.methodDescriptor();
        var site = JndiObjectFactoryCallSite.fromCall(call.id(), hostMethodKey, call.offset(),
                call.owner(), call.name(), call.descriptor(), call.invokeKind());
        if (site.isEmpty()) {
            return;
        }
        JndiObjectFactoryCallSite callSite = site.get();
        call.propsNote(JndiObjectFactoryCallSite.GRAPH_NOTE_KEY, callSite);
        Map<String, JndiObjectFactoryDispatch.Implementation> implementations = new java.util.TreeMap<>();
        boolean interfaceOnly = false;
        boolean abstractOnly = false;
        for (var edge : call.out()) {
            Node target = edge.to();
            if (target == null || target.type() != NodeType.METHOD
                    || !JndiObjectFactoryCallSite.GET_OBJECT_INSTANCE_NAME.equals(target.name())
                    || !JndiObjectFactoryCallSite.GET_OBJECT_INSTANCE_DESCRIPTOR.equals(
                    target.descriptor())) {
                continue;
            }
            if (JndiObjectFactoryCallSite.OBJECT_FACTORY_OWNER.equals(target.owner())) {
                interfaceOnly = true;
                continue;
            }
            io.just.sast.model.ClassInfo targetClass = hierarchy.classInfo(target.owner());
            if (targetClass == null || !hierarchy.isSubtypeOf(target.owner(),
                    JndiObjectFactoryCallSite.OBJECT_FACTORY_OWNER)
                    || edge.type() != EdgeType.DISPATCHES) {
                continue;
            }
            if (targetClass.isInterface()) {
                interfaceOnly = true;
                continue;
            }
            if (Modifier.isAbstract(targetClass.access())) {
                abstractOnly = true;
                continue;
            }
            JndiObjectFactoryDispatch.Implementation implementation =
                    new JndiObjectFactoryDispatch.Implementation(target.owner(), target.name(),
                            target.descriptor());
            implementations.put(implementation.methodKey(), implementation);
        }
        JndiObjectFactoryDispatch.Status status;
        if (!implementations.isEmpty()) {
            status = JndiObjectFactoryDispatch.Status.RESOLVED;
        } else if (interfaceOnly) {
            status = JndiObjectFactoryDispatch.Status.INTERFACE_ONLY;
        } else if (abstractOnly) {
            status = JndiObjectFactoryDispatch.Status.ABSTRACT_ONLY;
        } else {
            status = JndiObjectFactoryDispatch.Status.UNKNOWN_IMPLEMENTATION;
        }
        call.propsNote(JndiObjectFactoryCallSite.DISPATCH_NOTE_KEY,
                new JndiObjectFactoryDispatch(callSite, new ArrayList<>(implementations.values()),
                        status));
    }

    /**
     * Resolve the exact JDK/classpath JndiLoginModule lifecycle target after ordinary CHA.
     * This reads ClassInfo only; it never loads, initializes, constructs, reflects, or invokes
     * the target class.  The direct edge is added only when provenance and method resolution
     * both prove the concrete target.
     */
    private int annotateJaasLoginModuleDispatch(Graph graph, Node call) {
        Object note = call.note(JaasLoginModuleCallSite.GRAPH_NOTE_KEY);
        if (!(note instanceof JaasLoginModuleCallSite callSite)
                || (callSite.kind() != JaasLoginModuleCallSite.Kind.LOGIN_MODULE_INITIALIZE
                && callSite.kind() != JaasLoginModuleCallSite.Kind.LOGIN_MODULE_LOGIN)) {
            return 0;
        }
        JaasLoginModuleDispatch dispatch = resolveJaasLoginModule(callSite);
        call.propsNote(JaasLoginModuleCallSite.DISPATCH_NOTE_KEY, dispatch);
        if (!dispatch.resolved()) {
            return 0;
        }
        JaasLoginModuleDispatch.Implementation implementation = dispatch.implementation();
        Node target = graph.methodNode(implementation.owner(), implementation.name(),
                implementation.descriptor(), !hierarchy.isInitialClass(implementation.owner()));
        if (call.out().stream().noneMatch(edge -> edge.type() == EdgeType.DISPATCHES
                && edge.to() == target)) {
            graph.addEdge(call, target, EdgeType.DISPATCHES, "JAAS_JNDI_LOGIN_MODULE");
            return 1;
        }
        return 0;
    }

    private JaasLoginModuleDispatch resolveJaasLoginModule(
            JaasLoginModuleCallSite callSite) {
        String targetClass = JaasLoginModuleDispatch.TARGET_CLASS;
        io.just.sast.model.ClassInfo target = hierarchy.classInfo(targetClass);
        if (target == null) {
            return new JaasLoginModuleDispatch(callSite, targetClass, null,
                    JaasLoginModuleDispatch.Source.UNKNOWN,
                    JaasLoginModuleDispatch.Status.CLASS_NOT_RESOLVED,
                    unknownJdkSource());
        }
        JdkSourceInfo sourceInfo = hierarchy.isInitialClass(targetClass)
                ? unknownJdkSource() : hierarchy.jdkSourceInfo();
        JaasLoginModuleDispatch.Source source = hierarchy.isInitialClass(targetClass)
                ? JaasLoginModuleDispatch.Source.PROGRAM_INPUT
                : sourceInfo.imageKind() == JdkSourceInfo.ImageKind.UNKNOWN
                ? JaasLoginModuleDispatch.Source.UNKNOWN
                : JaasLoginModuleDispatch.Source.JDK_IMAGE;
        if (source == JaasLoginModuleDispatch.Source.UNKNOWN) {
            return new JaasLoginModuleDispatch(callSite, targetClass, null, source,
                    JaasLoginModuleDispatch.Status.SOURCE_NOT_PROVABLE, sourceInfo);
        }
        if (!hierarchy.isSubtypeOf(targetClass, JaasLoginModuleCallSite.LOGIN_MODULE_OWNER)) {
            return new JaasLoginModuleDispatch(callSite, targetClass, null, source,
                    JaasLoginModuleDispatch.Status.NOT_LOGIN_MODULE, sourceInfo);
        }
        if (target.isInterface() || Modifier.isAbstract(target.access())) {
            return new JaasLoginModuleDispatch(callSite, targetClass, null, source,
                    JaasLoginModuleDispatch.Status.INTERFACE_OR_ABSTRACT, sourceInfo);
        }
        String name = callSite.kind() == JaasLoginModuleCallSite.Kind.LOGIN_MODULE_INITIALIZE
                ? JaasLoginModuleCallSite.INITIALIZE_NAME : JaasLoginModuleCallSite.LOGIN_NAME;
        String descriptor = callSite.kind() == JaasLoginModuleCallSite.Kind.LOGIN_MODULE_INITIALIZE
                ? JaasLoginModuleCallSite.INITIALIZE_DESCRIPTOR : JaasLoginModuleCallSite.LOGIN_DESCRIPTOR;
        String owner = hierarchy.resolveMethod(targetClass, name, descriptor);
        if (owner == null) {
            return new JaasLoginModuleDispatch(callSite, targetClass, null, source,
                    JaasLoginModuleDispatch.Status.METHOD_NOT_RESOLVED, sourceInfo);
        }
        int access = hierarchy.methodAccess(owner, name, descriptor);
        if (access < 0) {
            return new JaasLoginModuleDispatch(callSite, targetClass, null, source,
                    JaasLoginModuleDispatch.Status.METHOD_NOT_RESOLVED, sourceInfo);
        }
        if (Modifier.isAbstract(access)) {
            return new JaasLoginModuleDispatch(callSite, targetClass, null, source,
                    JaasLoginModuleDispatch.Status.METHOD_ABSTRACT, sourceInfo);
        }
        return new JaasLoginModuleDispatch(callSite,
                targetClass,
                new JaasLoginModuleDispatch.Implementation(owner, name, descriptor),
                source,
                JaasLoginModuleDispatch.Status.RESOLVED,
                sourceInfo);
    }

    private static JdkSourceInfo unknownJdkSource() {
        return new JdkSourceInfo(JdkSourceInfo.ImageKind.UNKNOWN, 0);
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

    /**
     * A receiver proven to be a local Proxy.newProxyInstance result must not fall through to
     * ordinary CHA implementer enumeration.  Resolve only the exact configured interfaces and
     * their exact (name, descriptor) declarations.
     */
    private int addInterfaceOrProxy(Graph graph, Node call, String owner, String name,
                                    String desc) {
        Object note = call.note(ProxyInterfaceCallSite.GRAPH_NOTE_KEY);
        if (!(note instanceof ProxyInterfaceCallSite site)) {
            return addInterface(graph, call, owner, name, desc);
        }
        ProxyInterfaceDispatch dispatch = resolveProxyInterfaceDispatch(site);
        call.propsNote(ProxyInterfaceCallSite.DISPATCH_NOTE_KEY, dispatch);
        HessianProxyInvokeDispatch hessian = resolveHessianProxyInvoke(dispatch);
        call.propsNote(HessianProxyInvokeDispatch.GRAPH_NOTE_KEY, hessian);
        if (hessian.resolved()) {
            Node targetNode = graph.methodNode(hessian.target().owner().internalName(),
                    hessian.target().name(), hessian.target().descriptor(),
                    !hierarchy.isInitialClass(hessian.target().owner().internalName()));
            graph.addEdge(call, targetNode, EdgeType.DISPATCHES, "HESSIAN_PROXY_INVOKE");
            return 1;
        }
        if (!dispatch.resolved()) {
            return 0;
        }
        ProxyInterfaceDispatch.Declaration target = dispatch.target();
        Node targetNode = graph.methodNode(target.owner(), target.name(), target.descriptor(),
                !hierarchy.isInitialClass(target.owner()));
        graph.addEdge(call, targetNode, EdgeType.DISPATCHES, "PROXY_DEFAULT");
        return 1;
    }

    /**
     * Resolve the handler only after proxy interface dispatch has proved a real handler boundary.
     * The target method is accepted from the initial classpath facts with its exact owner/name/
     * descriptor; no Hessian class is loaded, initialized, constructed, reflected, or invoked.
     */
    private HessianProxyInvokeDispatch resolveHessianProxyInvoke(
            ProxyInterfaceDispatch dispatch) {
        MethodId target = null;
        ProxyCreationCallSite.ValueIdentity handler = dispatch.callSite().creation().handler();
        if (dispatch.status() == ProxyInterfaceDispatch.Status.HANDLER_REQUIRED
                && handler.state() == ProxyCreationCallSite.ValueState.KNOWN
                && handler.producerOffset() >= 0
                && HessianProxyInvokeDispatch.HANDLER_DESCRIPTOR.equals(handler.descriptor())) {
            ClassInfo handlerClass = hierarchy.classInfo(HessianProxyInvokeDispatch.OWNER);
            if (handlerClass != null) {
                MethodInfo method = handlerClass.method(HessianProxyInvokeDispatch.NAME,
                        HessianProxyInvokeDispatch.DESCRIPTOR);
                if (method != null && !Modifier.isStatic(method.access())
                        && !Modifier.isAbstract(method.access())) {
                    target = MethodId.of(method);
                }
            }
        }
        return HessianProxyInvokeDispatch.connect(dispatch, target);
    }

    private ProxyInterfaceDispatch resolveProxyInterfaceDispatch(ProxyInterfaceCallSite site) {
        if (site.status() != ProxyInterfaceCallSite.Status.PROVED) {
            ProxyInterfaceDispatch.Status status = site.status()
                    == ProxyInterfaceCallSite.Status.PARTIAL
                    ? ProxyInterfaceDispatch.Status.PARTIAL
                    : ProxyInterfaceDispatch.Status.UNKNOWN;
            return ProxyInterfaceDispatch.unresolved(site, status, mapProxyReason(site.reason()));
        }
        if (!site.creation().interfaceSet().known()) {
            return ProxyInterfaceDispatch.unresolved(site, ProxyInterfaceDispatch.Status.PARTIAL,
                    ProxyInterfaceDispatch.Reason.INTERFACE_SET_UNKNOWN);
        }
        ClassInfo callOwner = hierarchy.classInfo(site.callSite().calleeOwner());
        if (callOwner == null) {
            return ProxyInterfaceDispatch.unresolved(site, ProxyInterfaceDispatch.Status.PARTIAL,
                    ProxyInterfaceDispatch.Reason.INTERFACE_TYPE_UNRESOLVED);
        }
        if (!callOwner.isInterface()) {
            return ProxyInterfaceDispatch.unresolved(site, ProxyInterfaceDispatch.Status.UNKNOWN,
                    ProxyInterfaceDispatch.Reason.INTERFACE_MEMBER_NOT_INTERFACE);
        }

        List<ProxyInterfaceDispatch.Declaration> declarations = new ArrayList<>();
        boolean unresolvedInterface = false;
        boolean ownerDeclared = false;
        for (String interfaceType : site.creation().interfaceSet().interfaceTypes()) {
            ClassInfo configured = hierarchy.classInfo(interfaceType);
            if (configured == null) {
                unresolvedInterface = true;
                continue;
            }
            if (!configured.isInterface()) {
                return ProxyInterfaceDispatch.unresolved(site,
                        ProxyInterfaceDispatch.Status.UNKNOWN,
                        ProxyInterfaceDispatch.Reason.INTERFACE_MEMBER_NOT_INTERFACE);
            }
            if (interfaceType.equals(site.callSite().calleeOwner())
                    || hierarchy.isSubtypeOf(interfaceType, site.callSite().calleeOwner())) {
                ownerDeclared = true;
            }
            String declarationOwner = hierarchy.resolveMethod(interfaceType,
                    site.callSite().calleeName(), site.callSite().calleeDescriptor());
            if (declarationOwner == null) {
                continue;
            }
            ClassInfo declarationClass = hierarchy.classInfo(declarationOwner);
            if (declarationClass == null) {
                unresolvedInterface = true;
                continue;
            }
            if (!declarationClass.isInterface()) {
                continue;
            }
            io.just.sast.model.MethodInfo method = declarationClass.method(
                    site.callSite().calleeName(), site.callSite().calleeDescriptor());
            if (method == null || Modifier.isStatic(method.access())
                    || Modifier.isPrivate(method.access())) {
                continue;
            }
            ProxyInterfaceDispatch.Kind kind = Modifier.isAbstract(method.access())
                    ? ProxyInterfaceDispatch.Kind.ABSTRACT_METHOD
                    : ProxyInterfaceDispatch.Kind.DEFAULT_METHOD;
            ProxyInterfaceDispatch.Declaration declaration =
                    new ProxyInterfaceDispatch.Declaration(declarationOwner,
                            site.callSite().calleeName(), site.callSite().calleeDescriptor(), kind);
            if (!declarations.contains(declaration)) {
                declarations.add(declaration);
            }
        }
        if (unresolvedInterface) {
            return ProxyInterfaceDispatch.unresolved(site, ProxyInterfaceDispatch.Status.PARTIAL,
                    ProxyInterfaceDispatch.Reason.INTERFACE_TYPE_UNRESOLVED);
        }
        if (declarations.isEmpty()) {
            return ProxyInterfaceDispatch.unresolved(site, ProxyInterfaceDispatch.Status.UNKNOWN,
                    ownerDeclared ? ProxyInterfaceDispatch.Reason.DESCRIPTOR_NOT_DECLARED
                            : ProxyInterfaceDispatch.Reason.INTERFACE_OWNER_NOT_DECLARED);
        }
        if (!ownerDeclared) {
            return ProxyInterfaceDispatch.unresolved(site, ProxyInterfaceDispatch.Status.UNKNOWN,
                    ProxyInterfaceDispatch.Reason.INTERFACE_OWNER_NOT_DECLARED);
        }

        List<ProxyInterfaceDispatch.Declaration> defaults = declarations.stream()
                .filter(declaration -> declaration.kind()
                        == ProxyInterfaceDispatch.Kind.DEFAULT_METHOD)
                .toList();
        if (defaults.isEmpty()) {
            return ProxyInterfaceDispatch.handlerRequired(site, declarations);
        }
        List<ProxyInterfaceDispatch.Declaration> mostSpecific = defaults.stream()
                .filter(candidate -> defaults.stream().allMatch(other ->
                        candidate.owner().equals(other.owner())
                                || hierarchy.isSubtypeOf(candidate.owner(), other.owner())))
                .toList();
        if (mostSpecific.size() != 1) {
            return new ProxyInterfaceDispatch(site, defaults, null,
                    ProxyInterfaceDispatch.Status.UNKNOWN,
                    ProxyInterfaceDispatch.Reason.DEFAULT_AMBIGUOUS);
        }
        return ProxyInterfaceDispatch.defaultResolved(site, mostSpecific.get(0), declarations);
    }

    private static ProxyInterfaceDispatch.Reason mapProxyReason(
            ProxyInterfaceCallSite.Reason reason) {
        return switch (reason) {
            case NONE -> ProxyInterfaceDispatch.Reason.NONE;
            case VALUE_FLOW_INCOMPLETE -> ProxyInterfaceDispatch.Reason.VALUE_FLOW_INCOMPLETE;
            case PROXY_CREATION_INCOMPLETE -> ProxyInterfaceDispatch.Reason.PROXY_CREATION_INCOMPLETE;
            case INTERFACE_SET_UNKNOWN -> ProxyInterfaceDispatch.Reason.INTERFACE_SET_UNKNOWN;
            case NULL_RECEIVER -> ProxyInterfaceDispatch.Reason.NULL_RECEIVER;
            case RECEIVER_DESCRIPTOR_MISMATCH ->
                    ProxyInterfaceDispatch.Reason.RECEIVER_DESCRIPTOR_MISMATCH;
        };
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
        LambdaMetafactoryCallSite.Resolution resolution =
                LambdaMetafactoryCallSite.resolve(indy);
        if (!resolution.resolved()) {
            if (resolution.status() != LambdaMetafactoryCallSite.Status.NOT_LAMBDA_METAFACTORY) {
                call.propsNote("lambdaResolution", resolution.status().name());
            }
            return 0;
        }
        LambdaMetafactoryCallSite site = resolution.site();
        call.propsNote("lambdaResolution", resolution.status().name());
        call.propsNote("lambdaCallSite", site);
        HandleRef implementation = site.implementation();
        String target = hierarchy.resolveMethod(implementation.owner(), implementation.name(),
                implementation.descriptor());
        // 与 SPECIAL 边同语义：用解析后的真实声明类建节点（方法引用指向继承方法时避免幽灵节点）
        String edgeOwner = target != null ? target : implementation.owner();
        graph.addEdge(call,
                graph.methodNode(edgeOwner, implementation.name(), implementation.descriptor(),
                        target == null),
                EdgeType.LAMBDA, "LAMBDA");
        return 1;
    }
}
