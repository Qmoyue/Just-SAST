package io.just.sast.analysis.taint;

import io.just.sast.analysis.hierarchy.ClassHierarchy;
import io.just.sast.config.RuleEngine;
import io.just.sast.cpg.graph.Edge;
import io.just.sast.cpg.graph.Graph;
import io.just.sast.cpg.graph.Node;
import io.just.sast.cpg.graph.NodeType;
import io.just.sast.model.ClassInfo;
import io.just.sast.model.Descriptor;
import io.just.sast.model.MethodInfo;
import io.just.sast.model.Op;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 共享分析支撑（经黑板分发，全部知识源复用同一实例）：
 * 调用点索引、方法解析缓存、跨方法实参定位、公共判定谓词、入口下游闭包。
 */
public final class OriginSupport {

    private final ForwardOrigins origins;
    private final Map<String, Long> callIdByKey = new HashMap<>();
    private final Map<String, MethodInfo> methodCache = new java.util.concurrent.ConcurrentHashMap<>();
    private final ClassHierarchy hierarchy;
    private final RuleEngine ruleEngine;
    /** --fast（跳过 JDK 全量加载）：入口闭包的框架供给门在 fast 下关闭（同历史行为）。 */
    private final boolean fast;
    /** 入口下游闭包（惰性一次构建）：反向剪枝与链剪枝共用。 */
    private Set<String> entryDownstream;
    /** 入口 BFS 距离（与下游闭包同一次遍历产出）：反向探索按离入口近者优先。 */
    private Map<String, Integer> entryDepths;
    /** 接口分发解析记忆：owner#name+desc → (解析类, 方法节点) 列表——闭包展开对同一
     * 接口签名的全部调用点复用（transitiveSubtypes + resolveMethod + findMethodNode 只算一次）。 */
    private final Map<String, List<Object[]>> ifaceDispatchCache = new HashMap<>();
    /** 反射跳索引（FLASH 反射跳边的向后版）：常量类 → Method.invoke 调用点（名字常量时精确映射）。 */
    private final Map<String, List<Node>> reflectiveInvokeByClass = new HashMap<>();
    private final Map<String, Node> reflectiveInvokeByMethod = new HashMap<>();
    private final Map<Long, List<String>> reflectiveClassesBySite = new HashMap<>();
    /** 框架包内的 Method.invoke 位点——框架反射供给的调用者池（包前缀源自 source 规则声明）。 */
    private final List<Node> frameworkMethodInvokeSites = new ArrayList<>();
    /** JavaBean 反射位点是否存在于框架包内（入口闭包的框架供给门）。 */
    private boolean frameworkJavabeanSite;
    /** 框架包前缀（source 规则声明的框架入口类派生，前 3 段——框架反射供给门的数据源）。 */
    private final Set<String> frameworkPackages;
    /** JavaBean 反射跳：接收者类型 → invoke 位点；类型不可解 → wildcard 位点。 */
    private final Map<String, List<Long>> javabeanSitesByClass = new HashMap<>();
    private final List<Long> javabeanWildcardSites = new ArrayList<>();
    private final Map<Long, String> javabeanSiteKinds = new HashMap<>();
    /** 占位类型集（JavaBean wildcard 精度门，惰性）。 */
    private java.util.Set<String> occupiableTypes;

    private final java.util.Map<Long, Node> callNodes = new HashMap<>();

    public OriginSupport(Graph graph, ClassHierarchy hierarchy, RuleEngine ruleEngine, boolean fast) {
        this.hierarchy = hierarchy;
        this.ruleEngine = ruleEngine;
        this.fast = fast;
        this.frameworkPackages = deriveFrameworkPackages();
        this.origins = new ForwardOrigins(callIdByKey);
        for (Node call : graph.nodesOfType(NodeType.CALL)) {
            callIdByKey.put(methodKey(call) + "@" + call.strProp("offset"), call.id());
            callNodes.put(call.id(), call);
        }
        indexReflectiveJumps(graph);
    }

    /** 框架包前缀：source 规则声明的框架入口类取前 3 段包名（与框架桥接 KS 的前缀口径一致）。 */
    private Set<String> deriveFrameworkPackages() {
        Set<String> packages = new HashSet<>();
        for (io.just.sast.config.Rule.SourceRule source : ruleEngine.rules().sources()) {
            io.just.sast.config.Match owner = source.call().owner();
            if (owner == null || owner.isRegex()) {
                continue; // 正则 owner 不参与包前缀派生（保守：正则目标不定界）
            }
            String[] segments = owner.pattern().split("/");
            int take = Math.min(3, segments.length);
            StringBuilder pkg = new StringBuilder();
            for (int i = 0; i < take; i++) {
                if (i > 0) {
                    pkg.append('/');
                }
                pkg.append(segments[i]);
            }
            packages.add(pkg.toString());
        }
        return packages;
    }

    /** 应用接口无条件传递展开的每构建预算。 */
    private static final int IFACE_EXPANSION_BUDGET = 0;

    /** 位点宿主是否在框架包内（source 规则派生前缀）。 */
    private boolean inFrameworkPackage(String hostOwner) {
        for (String prefix : frameworkPackages) {
            if (hostOwner.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    /** 反射跳索引规模（诊断）。 */
    public int reflectiveSiteCount() {
        return reflectiveClassesBySite.size();
    }

    /**
     * 反射跳索引：Method.invoke 调用点若其宿主方法内存在 `C.class.getMethod/getDeclaredMethod(...)`
     * （C 为 LDC 类常量、出现在 getMethod 调用点前的小窗口内），则该 invoke 位点按 FLASH 反射跳边语义
     * 视为 C 的 public 方法的伪调用者：方法名常量 → 精确到 C.名字；名字不可解（污点数据）→ C 的全部
     * public 方法（类常量保证目标集合有界）。
     */
    private void indexReflectiveJumps(Graph graph) {
        for (Node call : graph.nodesOfType(NodeType.CALL)) {
            if (!"java/lang/reflect/Method".equals(call.strProp("owner"))
                    || !"invoke".equals(call.strProp("name"))) {
                continue;
            }
            MethodInfo host = methodOf(call.strProp("methodOwner"), call.strProp("methodName"),
                    call.strProp("methodDesc"));
            if (host == null) {
                continue;
            }
            scanReflectiveLookup(host, call);
            scanJavaBeanAccess(host, call);
            // 框架包内的 Method.invoke 位点——框架反射供给调用者池
            // （包前缀源自 source 规则：框架以攻击者可控类名反射调用应用类方法的语义，
            //   只在框架真实出现在 classpath 时成立）
            if (inFrameworkPackage(host.owner())) {
                frameworkMethodInvokeSites.add(call);
            }
        }
        if (!reflectiveClassesBySite.isEmpty()) {
            io.just.sast.util.JustLogger.info("反射跳索引：{} 个 invoke 位点", reflectiveClassesBySite.size());
        }
    }

    /** 在 invoke 宿主方法体内找 `C.class.getXxxMethod(name, ...)` 模式（窗口式近似，窗口内常量配对）。 */
    private void scanReflectiveLookup(MethodInfo host, Node invokeSite) {
        var insns = host.instructions();
        for (int i = 0; i < insns.size(); i++) {
            var insn = insns.get(i);
            if (!insn.op().isInvoke() || insn.operands().isEmpty()
                    || !(insn.operands().get(0) instanceof io.just.sast.model.MethodRef ref)
                    || !"java/lang/Class".equals(ref.owner())
                    || !("getMethod".equals(ref.name()) || "getDeclaredMethod".equals(ref.name()))) {
                continue;
            }
            // 向前小窗口找 LDC 类常量与 LDC 字符串常量
            String classConst = null;
            String nameConst = null;
            for (int w = Math.max(0, i - 15); w < i; w++) {
                var prev = insns.get(w);
                if (prev.op() == io.just.sast.model.Op.LDC && !prev.operands().isEmpty()) {
                    Object cst = prev.operands().get(0);
                    if (cst instanceof io.just.sast.model.TypeRef t && classConst == null) {
                        classConst = t.descriptor().startsWith("L") && t.descriptor().endsWith(";")
                                ? t.descriptor().substring(1, t.descriptor().length() - 1)
                                : t.descriptor();
                    } else if (cst instanceof String n && nameConst == null) {
                        nameConst = n;
                    }
                }
            }
            if (classConst == null) {
                continue;
            }
            reflectiveInvokeByClass.computeIfAbsent(classConst, k -> new ArrayList<>(1)).add(invokeSite);
            reflectiveClassesBySite.computeIfAbsent(invokeSite.id(), k -> new ArrayList<>(1)).add(classConst);
            if (nameConst != null) {
                reflectiveInvokeByMethod.putIfAbsent(classConst + "#" + nameConst, invokeSite);
            }
        }
    }

    /**
     * JavaBean 反射跳（FLASH 第三支柱）：宿主方法内存在 PropertyDescriptor.getReadMethod/getWriteMethod
     * 产出的 Method 再 invoke 时，目标 = invoke 接收者声明类型的 JavaBean 前缀方法（get* 与 is* 读、set* 写）。
     * 接收者类型不可解（如 Object 字段）时枚举占位 Serializable 类的公共无参前缀方法（上限 50）。
     */
    private void scanJavaBeanAccess(MethodInfo host, Node invokeSite) {
        boolean read = false;
        boolean write = false;
        for (var insn : host.instructions()) {
            if (!insn.op().isInvoke() || insn.operands().isEmpty()
                    || !(insn.operands().get(0) instanceof io.just.sast.model.MethodRef ref)) {
                continue;
            }
            if ("java/beans/PropertyDescriptor".equals(ref.owner())) {
                if ("getReadMethod".equals(ref.name())) {
                    read = true;
                } else if ("getWriteMethod".equals(ref.name())) {
                    write = true;
                }
            }
        }
        if (!read && !write) {
            return;
        }
        if (inFrameworkPackage(host.owner())) {
            frameworkJavabeanSite = true;
        }
        // invoke 接收者（arg0）声明类型
        ForwardOrigins.State state = origins.compute(host)
                .stateBefore().get(invokeSite.prop("offset"));
        if (state == null || state.stack().size() < 2) {
            return;
        }
        var argOrigins = state.stack().get(state.stack().size() - 2).origins();
        String recvType = declaredTypeOf(argOrigins, host);
        // 万能类型（Object/Serializable）走 wildcard 路径——可调用于意类的 getter
        if (recvType != null && !isUniversalType(recvType)) {
            javabeanSitesByClass.computeIfAbsent(recvType, k -> new ArrayList<>(1)).add(invokeSite.id());
            javabeanSiteKinds.put(invokeSite.id(), read ? "read" : "write");
        } else {
            javabeanWildcardSites.add(invokeSite.id());
            javabeanSiteKinds.put(invokeSite.id(), read ? "read" : "write");
        }
    }

    /** JavaBean 前缀匹配（读：get 与 is 前缀公共非静态无参非 void；写：set 前缀公共非静态单参）。 */
    private static boolean javaBeanMatches(io.just.sast.model.MethodInfo m, String kind) {
        if (!java.lang.reflect.Modifier.isPublic(m.access())
                || java.lang.reflect.Modifier.isStatic(m.access())) {
            return false;
        }
        String n = m.name();
        if ("read".equals(kind)) {
            return (n.startsWith("get") && n.length() > 3 || n.startsWith("is") && n.length() > 2)
                    && Descriptor.paramCount(m.descriptor()) == 0
                    && !m.descriptor().endsWith(")V");
        }
        return n.startsWith("set") && n.length() > 3 && Descriptor.paramCount(m.descriptor()) == 1;
    }

    /** 常量类 C 的伪调用 invoke 位点（名字不可解时指向 C 全部 public 方法）。 */
    public List<Node> reflectiveInvokeSitesOf(String className) {
        return reflectiveInvokeByClass.getOrDefault(className, List.of());
    }

    /** (C, 方法名) 精确反射跳的 invoke 位点。 */
    public Node reflectiveInvokeSiteOf(String className, String methodName) {
        return reflectiveInvokeByMethod.get(className + "#" + methodName);
    }

    /** JavaBean 前缀方法（类+读写形态）的伪调用 invoke 位点（含 wildcard 位点）。 */
    public List<Node> javaBeanInvokeSitesOf(String className, String methodName) {
        List<Node> sites = new ArrayList<>();
        String kind = methodName.startsWith("get") || methodName.startsWith("is") ? "read" : "write";
        for (Long id : javabeanSitesByClass.getOrDefault(className, List.of())) {
            if (kind.equals(javabeanSiteKinds.get(id))) {
                sites.add(callNodes.get(id));
            }
        }
        // wildcard 位点可调用于意类的 getter——不限制 target 类
        for (Long id : javabeanWildcardSites) {
            if (kind.equals(javabeanSiteKinds.get(id))) {
                sites.add(callNodes.get(id));
            }
        }
        return sites;
    }

    /** JavaBean 类站点表（闭包用）。 */
    public Map<String, List<Long>> javabeanClassSites() {
        return javabeanSitesByClass;
    }

    /** JavaBean wildcard 位点（闭包用）。 */
    public List<Long> javabeanWildcardSiteIds() {
        return javabeanWildcardSites;
    }

    /** 全部反射跳 invoke 位点（含其常量类），供反射 sink 枚举。 */
    /** 框架包内的 Method.invoke 位点（反射供给调用者池）。 */
    public List<Node> frameworkMethodInvokeSites() {
        return frameworkMethodInvokeSites;
    }

    public Map<Long, List<String>> reflectiveSites() {
        return reflectiveClassesBySite;
    }

    public ForwardOrigins origins() {
        return origins;
    }

    /**
     * 入口下游闭包：从 magic entry 方法与 OIS 读宿主出发的下游可达方法键集合
     * （沿调用边 + 字段中介边——下游方法写入的字段，其读者可经字段流获得污点）。
     * 用途：反向剪枝（sink 宿主不在集合内可证明无链）与链剪枝（触发上下文判定）共用一份。
     */
    public Set<String> entryDownstream(Graph graph) {
        Set<String> downstream = entryDownstream;
        if (downstream != null) {
            return downstream;
        }
        Map<String, List<Node>> callsByMethod = new HashMap<>();
        Map<String, List<String>> fieldsWrittenBy = new HashMap<>();
        Map<String, List<String>> fieldReaders = new HashMap<>();
        for (Node call : graph.nodesOfType(NodeType.CALL)) {
            callsByMethod.computeIfAbsent(methodKey(call), k -> new ArrayList<>(1)).add(call);
        }
        for (Node m : graph.nodesOfType(NodeType.METHOD)) {
            MethodInfo info = methodOf(m.strProp("owner"), m.strProp("name"), m.strProp("desc"));
            if (info == null) {
                continue;
            }
            String key = methodKeyOf(m.strProp("owner"), m.strProp("name"), m.strProp("desc"));
            for (io.just.sast.model.InsnFact insn : info.instructions()) {
                if (insn.op().isFieldRead()) {
                    String fieldKey = insn.fieldRef().owner() + "#" + insn.fieldRef().name();
                    fieldReaders.computeIfAbsent(fieldKey, k -> new ArrayList<>(1)).add(key);
                } else if (insn.op().isFieldWrite()) {
                    String fieldKey = insn.fieldRef().owner() + "#" + insn.fieldRef().name();
                    fieldsWrittenBy.computeIfAbsent(key, k -> new ArrayList<>(1)).add(fieldKey);
                }
            }
        }
        downstream = new HashSet<>();
        Map<String, Integer> depths = new HashMap<>();
        Deque<Node> work = new ArrayDeque<>();
        Deque<Integer> workDepth = new ArrayDeque<>();
        for (Node m : graph.nodesOfType(NodeType.METHOD)) {
            String key = methodKeyOf(m.strProp("owner"), m.strProp("name"), m.strProp("desc"));
            if (ruleEngine.matchingEntry(m.strProp("owner"), m.strProp("name"), m.strProp("desc")).isPresent()
                    && downstream.add(key)) {
                depths.put(key, 0);
                work.add(m);
                workDepth.add(0);
            }
        }
        for (Node call : graph.nodesOfType(NodeType.CALL)) {
            boolean seed = isOisRead(call)
                    // source（框架反序列化入口）宿主与 OIS 宿主同级 seeding——威胁模型上
                    // 框架 parse 与 OIS readObject 都是「反序列化发生处」；框架内部的
                    // Method.invoke 位点由此进入闭包，反射供给伪调用者才能挂接应用类
                    // 的 setter/getter（fastjson @type / XStream / Hessian 的运行时类名分发）
                    || ruleEngine.matchingSource(call.strProp("owner"), call.strProp("name"),
                            call.strProp("desc")).isPresent();
            if (seed) {
                Node host = graph.findMethodNode(call.strProp("methodOwner"),
                        call.strProp("methodName"), call.strProp("methodDesc"));
                String key = host != null ? methodKeyOf(
                        host.strProp("owner"), host.strProp("name"), host.strProp("desc")) : null;
                if (host != null && key != null && downstream.add(key)) {
                    depths.put(key, 0);
                    work.add(host);
                    workDepth.add(0);
                }
            }
        }
        // JavaBean wildcard 直接种子：图中存在 getReadMethod/invoke 模式时，
        // 所有有 JavaBean getter 的 Serializable 类直接入闭包（不依赖中间方法可达）
        if (!javabeanWildcardSites.isEmpty()) {
            Set<String> getterClasses = computeSerializableWithGetters(graph);
            for (String cls : getterClasses) {
                var ci = hierarchy.classInfo(cls);
                if (ci == null) {
                    continue;
                }
                for (var mi : ci.methods()) {
                    if (javaBeanMatches(mi, "read")) {
                        String mk = methodKeyOf(cls, mi.name(), mi.descriptor());
                        if (downstream.add(mk)) {
                            depths.put(mk, 1);
                            Node mn = graph.findMethodNode(cls, mi.name(), mi.descriptor());
                            if (mn != null) {
                                work.add(mn);
                                workDepth.add(1);
                            }
                        }
                    }
                }
            }
        }
        // 框架反射供给种子：Method.invoke / JavaBean 反射位点宿主于框架包内（source 规则派生前缀，
        // 框架桥接语义真实成立）时，所有应用类的 public 非静态方法入闭包——
        // 框架（fastjson @type / XStream / SnakeYAML 等）以攻击者可控类名反射调用任意 public 方法。
        // 精度门：仅限非 JDK 类（避免万级 JDK 方法涌入闭包）。
        boolean hasFrameworkInvoke = !frameworkMethodInvokeSites.isEmpty() || frameworkJavabeanSite;
        if (hasFrameworkInvoke && !fast) {
            int added = 0;
            for (Node m : graph.nodesOfType(NodeType.METHOD)) {
                String owner = m.strProp("owner");
                if (owner.startsWith("java/") || owner.startsWith("javax/")
                        || owner.startsWith("sun/") || owner.startsWith("jdk/")
                        || owner.startsWith("com/sun/")) {
                    continue; // 跳过 JDK 类
                }
                // 框架反序列化不要求 Serializable（fastjson 用默认构造器+反射，XStream 用 Converter）
                int access = hierarchy.methodAccess(owner, m.strProp("name"), m.strProp("desc"));
                if (access >= 0 && java.lang.reflect.Modifier.isPublic(access)
                        && !java.lang.reflect.Modifier.isStatic(access)) {
                    String mk = methodKeyOf(owner, m.strProp("name"), m.strProp("desc"));
                    if (downstream.add(mk)) {
                        depths.put(mk, 1);
                        // 性能关键：不加入 work 队列——只入闭包集合（供 sink gate），不扩展下游 callee
                        added++;
                    }
                }
            }
            if (added > 0) {
                io.just.sast.util.JustLogger.debug("框架反射供给：{} 个方法入闭包", added);
            }
        }
        while (!work.isEmpty()) {
            Node m = work.poll();
            int depth = workDepth.poll();
            String key = methodKeyOf(m.strProp("owner"), m.strProp("name"), m.strProp("desc"));
            List<Node> calls = callsByMethod.get(key);
            if (calls != null) {
                // 反射跳边（FLASH 向后版）：invoke 位点的常量类 public 方法并入可达集
                for (Node call : calls) {
                    List<String> classes = reflectiveClassesBySite.get(call.id());
                    if (classes == null) {
                        continue;
                    }
                    for (String cls : classes) {
                        io.just.sast.model.ClassInfo ci = hierarchy.classInfo(cls);
                        if (ci == null) {
                            continue;
                        }
                        for (io.just.sast.model.MethodInfo mi : ci.methods()) {
                            if (!java.lang.reflect.Modifier.isPublic(mi.access())
                                    || java.lang.reflect.Modifier.isStatic(mi.access())) {
                                continue;
                            }
                            String mk = methodKeyOf(cls, mi.name(), mi.descriptor());
                            if (downstream.add(mk)) {
                                depths.put(mk, depth + 1);
                                Node mn = graph.findMethodNode(cls, mi.name(), mi.descriptor());
                                if (mn != null) {
                                    work.add(mn);
                                    workDepth.add(depth + 1);
                                }
                            }
                        }
                    }
                }
                // JavaBean 反射跳（FLASH）：getReadMethod/getWriteMethod invoke 位点 →
                // 接收者类型（可解）或占位 Serializable 类的 JavaBean 前缀方法并入可达集
                for (Node call : calls) {
                    if (javabeanSiteKinds.containsKey(call.id())) {
                        String kind = javabeanSiteKinds.get(call.id());
                        java.util.Set<String> targetClasses = new HashSet<>();
                        for (Map.Entry<String, List<Long>> e : javabeanSitesByClass.entrySet()) {
                            if (e.getValue().contains(call.id())) {
                                targetClasses.add(e.getKey());
                            }
                        }
                        if (targetClasses.isEmpty()) {
                            // wildcard（Object 接收者）：所有有 JavaBean 前缀方法的 Serializable 类
                            // FLASH 语义：receiver 攻击者可控时，任意 Serializable 类的 getter 均可被反射调用
                            if (occupiableTypes == null) {
                                occupiableTypes = computeSerializableWithGetters(graph);
                            }
                            targetClasses.addAll(occupiableTypes);
                        }
                        for (String cls2 : targetClasses) {
                            var ci2 = hierarchy.classInfo(cls2);
                            if (ci2 == null) {
                                continue;
                            }
                            for (var mi2 : ci2.methods()) {
                                if (javaBeanMatches(mi2, kind)) {
                                    String mk2 = methodKeyOf(cls2, mi2.name(), mi2.descriptor());
                                    if (downstream.add(mk2)) {
                                        depths.put(mk2, depth + 1);
                                        Node mn2 = graph.findMethodNode(cls2, mi2.name(), mi2.descriptor());
                                        if (mn2 != null) {
                                            work.add(mn2);
                                            workDepth.add(depth + 1);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                for (Node call : calls) {
                    for (Edge edge : call.out()) {
                        Node callee = edge.to();
                        String calleeKey = methodKeyOf(callee.strProp("owner"),
                                callee.strProp("name"), callee.strProp("desc"));
                        if (downstream.add(calleeKey)) {
                            depths.put(calleeKey, depth + 1);
                            work.add(callee);
                            workDepth.add(depth + 1);
                        }
                    }
                    // 反射跳边展开：Method.invoke 位点的常量类目标方法并入闭包
                    List<String> reflClasses = reflectiveClassesBySite.get(call.id());
                    if (reflClasses != null) {
                        for (String cls : reflClasses) {
                            var ci2 = hierarchy.classInfo(cls);
                            if (ci2 == null) {
                                continue;
                            }
                            for (var mi2 : ci2.methods()) {
                                if (!java.lang.reflect.Modifier.isPublic(mi2.access())) {
                                    continue;
                                }
                                String mk2 = methodKeyOf(cls, mi2.name(), mi2.descriptor());
                                if (downstream.add(mk2)) {
                                    depths.put(mk2, depth + 1);
                                    Node mn2 = graph.findMethodNode(cls, mi2.name(), mi2.descriptor());
                                    if (mn2 != null) {
                                        work.add(mn2);
                                        workDepth.add(depth + 1);
                                    }
                                }
                            }
                        }
                    }
                    // 分发展开：调用图分发边未物化全接收者集时闭包做全子类型展开。
                    // VIRTUAL：CHA 物化完整（超限时仅剩声明目标，out≤1）。
                    // INTERFACE：implementers 不穿透实现类的子类（子类覆写会漏）——应用接口
                    // 无条件传递展开（hibernate1 形态）；JDK 接口维持 out≤1 声明态
                    // （万级实现者的传递闭包经 JDK 图病毒扩散，真实语料耗时 3-14 倍）
                    String callOwner = call.strProp("owner");
                    boolean jdkIface = "INTERFACE".equals(call.strProp("invokeKind")) && isJdk(callOwner);
                    if (call.out().size() <= 1
                            || ("INTERFACE".equals(call.strProp("invokeKind")) && !jdkIface)) {
                        String callName = call.strProp("name");
                        String callDesc = call.strProp("desc");
                        if ("VIRTUAL".equals(call.strProp("invokeKind"))
                                || "INTERFACE".equals(call.strProp("invokeKind"))) {
                            String sigKey = callOwner + "#" + callName + callDesc;
                            List<Object[]> targets = ifaceDispatchCache.get(sigKey);
                            if (targets == null) {
                                targets = new ArrayList<>();
                                var ownerCi = hierarchy.classInfo(callOwner);
                                if (ownerCi != null) {
                                    java.util.List<String> impls = hierarchy.transitiveSubtypes(callOwner);
                                    if (impls != null) {
                                        for (String impl : impls) {
                                            String resolved = hierarchy.resolveMethod(impl, callName, callDesc);
                                            if (resolved != null) {
                                                targets.add(new Object[]{resolved,
                                                        graph.findMethodNode(resolved, callName, callDesc)});
                                            }
                                        }
                                    }
                                }
                                ifaceDispatchCache.put(sigKey, targets);
                            }
                            for (Object[] t : targets) {
                                String resolved = (String) t[0];
                                Node mn = (Node) t[1];
                                String mk = methodKeyOf(resolved, callName, callDesc);
                                if (downstream.add(mk)) {
                                    depths.put(mk, depth + 1);
                                    if (mn != null) {
                                        work.add(mn);
                                        workDepth.add(depth + 1);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            List<String> written = fieldsWrittenBy.get(key);
            if (written != null) {
                for (String fieldKey : written) {
                    for (String reader : fieldReaders.getOrDefault(fieldKey, List.of())) {
                        if (downstream.add(reader)) {
                            depths.put(reader, depth + 1);
                            Node rn = methodNodeOf(graph, reader);
                            if (rn != null) {
                                work.add(rn);
                                workDepth.add(depth + 1);
                            }
                        }
                    }
                }
            }
        }
        entryDownstream = downstream;
        entryDepths = depths;
        return downstream;
    }



    private static boolean isJdk(String internalName) {
        return internalName.startsWith("java/") || internalName.startsWith("javax/")
                || internalName.startsWith("jdk/") || internalName.startsWith("sun/")
                || internalName.startsWith("com/sun/");
    }


    /** 方法的入口 BFS 距离（未在下游闭包内返回 Integer.MAX_VALUE）。反向探索按升序使用。 */
    public int entryDepthOf(String methodKey) {
        Map<String, Integer> depths = entryDepths;
        return depths != null ? depths.getOrDefault(methodKey, Integer.MAX_VALUE) : Integer.MAX_VALUE;
    }

    private static Node methodNodeOf(Graph graph, String key) {
        int sep = key.indexOf('#');
        int paren = key.indexOf('(', sep);
        if (sep < 0 || paren < 0) {
            return null;
        }
        return graph.findMethodNode(key.substring(0, sep), key.substring(sep + 1, paren), key.substring(paren));
    }

    /** 调用点 id：方法键 + "@" + 指令 offset → CALL 节点 id；不存在返回 null。 */
    public Long callId(String methodKey, int offset) {
        return callIdByKey.get(methodKey + "@" + offset);
    }

    public MethodInfo methodOf(String owner, String name, String desc) {
        String key = methodKeyOf(owner, name, desc);
        MethodInfo cached = methodCache.get(key);
        if (cached != null) {
            return cached;
        }
        ClassInfo cls = hierarchy.classInfo(owner);
        MethodInfo method = cls != null ? cls.method(name, desc) : null;
        if (method != null) {
            methodCache.put(key, method);
        }
        return method;
    }

    /** CALL 节点所在的方法。 */
    public MethodInfo enclosingMethod(Node call) {
        return methodOf(call.strProp("methodOwner"), call.strProp("methodName"), call.strProp("methodDesc"));
    }

    /**
     * 调用点实参来源：slot 为被调方法的局部参数槽（实例方法 receiver=0，long/double 参数占 2 槽）。
     * 按参数序数定位调用点栈上的实参（receiver 深度 = paramCount，arg i 深度 = paramCount-1-i，
     * cat-2 实参与 cat-1 一样各占一个栈条目）；返回空集表示该位置无来源记录。
     */
    public Set<ValueOrigin> argOriginAt(Node callerCall, MethodInfo callerMethod, int slot) {
        ForwardOrigins.State state = origins.compute(callerMethod)
                .stateBefore().get(callerCall.prop("offset"));
        if (state == null) {
            return Set.of();
        }
        String desc = callerCall.strProp("desc");
        boolean calleeStatic = "STATIC".equals(callerCall.strProp("invokeKind"));
        int ordinal = Descriptor.paramOrdinal(desc, calleeStatic, slot);
        if (ordinal == -2) {
            return Set.of();
        }
        int paramCount = Descriptor.paramCount(desc);
        int depthFromTop = ordinal == -1 ? paramCount : paramCount - 1 - ordinal;
        if (depthFromTop < 0 || depthFromTop >= state.stack().size()) {
            return Set.of();
        }
        return state.stack().get(state.stack().size() - 1 - depthFromTop).origins();
    }


    /**
     * catch 可达性守卫（可判定才剪；GadgetHunter Guard 约束静态子集 + Gleipner FP 陷阱语义）：
     * a) CCE handler：守卫区唯一调用是 Class.cast，cast 目标类常量为实参声明类型的父类——必成功；
     * b) 受检反射查找异常：守卫区唯一调用是 forName/getDeclaredField/getField/getMethod/getDeclaredMethod
     *    且名字常量、目标可解析——必成功。反向与前向引擎在 sink 判定前共用。
     */
    public boolean catchProvablyUnreachable(MethodInfo method, int sinkOffset) {
        for (io.just.sast.model.TryCatchFact tc : method.tryCatch()) {
            boolean cce = "java/lang/ClassCastException".equals(tc.type());
            boolean reflectiveChecked = "java/lang/ClassNotFoundException".equals(tc.type())
                    || "java/lang/NoSuchFieldException".equals(tc.type())
                    || "java/lang/NoSuchMethodException".equals(tc.type())
                    || "java/lang/IllegalAccessException".equals(tc.type())
                    || "java/lang/InstantiationException".equals(tc.type());
            boolean runtimeDeterministic = isDeterministicRuntime(tc.type());
            if (!cce && !reflectiveChecked && !runtimeDeterministic) {
                continue;
            }
            if (sinkOffset < tc.handler() || sinkOffset > tc.handler() + 8) {
                continue;
            }
            io.just.sast.model.InsnFact soleInvoke = null;
            int invokeCount = 0;
            for (int i = tc.start(); i < tc.end() && i < method.instructions().size(); i++) {
                io.just.sast.model.InsnFact insn = method.instructions().get(i);
                if (insn.op().isInvoke()) {
                    invokeCount++;
                    soleInvoke = insn;
                }
            }
            if (runtimeDeterministic) {
                boolean anyThrower = invokeCount > 0;
                if (!anyThrower) {
                    for (int i = tc.start(); i < tc.end() && i < method.instructions().size(); i++) {
                        var insn = method.instructions().get(i);
                        var op = insn.op();
                        if (op == io.just.sast.model.Op.AALOAD || op == io.just.sast.model.Op.IALOAD
                                || op == io.just.sast.model.Op.AASTORE || op == io.just.sast.model.Op.IASTORE
                                || op == io.just.sast.model.Op.ARRAYLENGTH || op == io.just.sast.model.Op.GETFIELD
                                || op == io.just.sast.model.Op.IDIV || op == io.just.sast.model.Op.LDIV
                                || op == io.just.sast.model.Op.IREM || op == io.just.sast.model.Op.LREM) {
                            anyThrower = true;
                            break;
                        }
                    }
                }
                if (!anyThrower) {
                    return true;
                }
                continue;
            }
            if (invokeCount < 1) {
                continue;
            }
            if (reflectiveChecked) {
                // 按异常类型枚举守卫区内的"投掷者"调用；全部投掷者可判定必成功 → handler 不可达
                boolean sawThrower = false;
                boolean allSucceed = true;
                for (int i = tc.start(); i < tc.end() && i < method.instructions().size(); i++) {
                    io.just.sast.model.InsnFact insn = method.instructions().get(i);
                    if (!insn.op().isInvoke() || insn.operands().isEmpty()
                            || !(insn.operands().get(0) instanceof io.just.sast.model.MethodRef mref)
                            || !isThrowerOf(tc.type(), mref)) {
                        continue;
                    }
                    sawThrower = true;
                    if (!reflectiveLookupAlwaysSucceeds(method, tc, insn, mref)) {
                        allSucceed = false;
                        break;
                    }
                }
                if (sawThrower && allSucceed) {
                    return true;
                }
                continue;
            }
            if (!cce || invokeCount != 1
                    || !(soleInvoke.operands().get(0) instanceof io.just.sast.model.MethodRef ref)
                    || !"java/lang/Class".equals(ref.owner()) || !"cast".equals(ref.name())) {
                continue;
            }
            String castTarget = null;
            for (int w = Math.max(0, tc.start() - 8); w < soleInvoke.offset(); w++) {
                io.just.sast.model.InsnFact prev = method.instructions().get(w);
                if (prev.op() == io.just.sast.model.Op.LDC && !prev.operands().isEmpty()
                        && prev.operands().get(0) instanceof io.just.sast.model.TypeRef t) {
                    castTarget = t.descriptor().startsWith("L") && t.descriptor().endsWith(";")
                            ? t.descriptor().substring(1, t.descriptor().length() - 1)
                            : t.descriptor();
                }
            }
            if (castTarget == null) {
                continue;
            }
            ForwardOrigins.Result result = origins.compute(method);
            ForwardOrigins.State state = result.stateBefore().get(soleInvoke.offset());
            if (state == null || state.stack().size() < 2) {
                continue;
            }
            String argType = declaredTypeOf(state.stack().get(state.stack().size() - 1).origins(), method); // cast 实参在栈顶
            if (argType != null && hierarchy.isSubtypeOf(argType, castTarget)) {
                return true;
            }
        }
        return false;
    }

    /** A6: 确定性运行时异常——值依赖但可判定的子集。 */
    private static boolean isDeterministicRuntime(String type) {
        return "java/lang/ArithmeticException".equals(type)
                || "java/lang/ArrayStoreException".equals(type)
                || "java/util/EmptyStackException".equals(type)
                || "java/lang/IndexOutOfBoundsException".equals(type)
                || "java/lang/NegativeArraySizeException".equals(type)
                || "java/lang/NullPointerException".equals(type);
    }

    /** 该调用是否可能抛出 caughtType（受检反射族）。 */
    private static boolean isThrowerOf(String caughtType, io.just.sast.model.MethodRef ref) {
        return switch (caughtType) {
            case "java/lang/ClassNotFoundException" ->
                    "java/lang/Class".equals(ref.owner()) && "forName".equals(ref.name());
            case "java/lang/NoSuchFieldException" ->
                    "java/lang/Class".equals(ref.owner())
                            && ("getDeclaredField".equals(ref.name()) || "getField".equals(ref.name()));
            case "java/lang/NoSuchMethodException" ->
                    "java/lang/Class".equals(ref.owner())
                            && ("getMethod".equals(ref.name()) || "getDeclaredMethod".equals(ref.name())
                                || "getConstructor".equals(ref.name())
                                || "getDeclaredConstructor".equals(ref.name()));
            case "java/lang/IllegalAccessException" ->
                    ("java/lang/reflect/Field".equals(ref.owner())
                            && ("set".equals(ref.name()) || "get".equals(ref.name())))
                    || ("java/lang/reflect/Method".equals(ref.owner()) && "invoke".equals(ref.name()));
            case "java/lang/InstantiationException" ->
                    ("java/lang/Class".equals(ref.owner()) && "newInstance".equals(ref.name()))
                    || ("java/lang/reflect/Constructor".equals(ref.owner())
                            && "newInstance".equals(ref.name()));
            default -> false;
        };
    }

    /** 受检反射查找必成功判定：常量类 + 常量名字且目标可解析。 */
    private boolean reflectiveLookupAlwaysSucceeds(MethodInfo method, io.just.sast.model.TryCatchFact tc,
                                                   io.just.sast.model.InsnFact insn,
                                                   io.just.sast.model.MethodRef ref) {
        String classConst = null;
        String nameConst = null;
        for (int w = Math.max(0, tc.start() - 8); w < insn.offset(); w++) {
            io.just.sast.model.InsnFact prev = method.instructions().get(w);
            if (prev.op() == io.just.sast.model.Op.LDC && !prev.operands().isEmpty()) {
                Object cst = prev.operands().get(0);
                if (cst instanceof io.just.sast.model.TypeRef t && classConst == null) {
                    classConst = t.descriptor().startsWith("L") && t.descriptor().endsWith(";")
                            ? t.descriptor().substring(1, t.descriptor().length() - 1)
                            : t.descriptor();
                } else if (cst instanceof String n && nameConst == null) {
                    nameConst = n;
                }
            }
        }
        String lookupName = nameConst != null ? nameConst : ""; // 无常量名无法证明必成功（空名不解析）
        var target = classConst != null ? hierarchy.classInfo(classConst) : null;
        boolean noSetAccessible = true;
        for (int i = tc.start(); i < tc.end() && i < method.instructions().size(); i++) {
            var fact = method.instructions().get(i);
            if (fact.op().isInvoke() && !fact.operands().isEmpty()
                    && fact.operands().get(0) instanceof io.just.sast.model.MethodRef mr
                    && mr.name().equals("setAccessible")) {
                noSetAccessible = false;
            }
        }
        return switch (tc.type()) {
            case "java/lang/ClassNotFoundException" ->
                    "forName".equals(ref.name()) && hierarchy.classInfo(lookupName.replace('.', '/')) != null;
            case "java/lang/NoSuchFieldException" -> target != null && target.field(lookupName) != null;
            case "java/lang/NoSuchMethodException" ->
                    target != null && target.methods().stream().anyMatch(m -> m.name().equals(lookupName));
            case "java/lang/IllegalAccessException" -> {
                if (target == null || !noSetAccessible || target.isInterface()
                        || !java.lang.reflect.Modifier.isPublic(target.access())) {
                    yield false;
                }
                if ("java/lang/reflect/Field".equals(ref.owner())) {
                    var f = target.field(lookupName);
                    yield f != null && java.lang.reflect.Modifier.isPublic(f.access());
                }
                yield target.methods().stream().anyMatch(m -> m.name().equals(lookupName));
            }
            case "java/lang/InstantiationException" ->
                    target != null && !target.isInterface()
                            && !java.lang.reflect.Modifier.isAbstract(target.access());
            default -> false;
        };
    }

    /** 值来源集合的声明类型（一致时返回，分歧返回 null）。 */
    private String declaredTypeOf(Set<ValueOrigin> origins, MethodInfo in) {
        String type = null;
        for (ValueOrigin origin : origins) {
            String t = null;
            if (origin instanceof ValueOrigin.FieldRead f && !f.isStatic()) {
                String declaring = hierarchy.resolveField(f.owner(), f.field());
                io.just.sast.model.ClassInfo cls = declaring != null
                        ? hierarchy.classInfo(declaring) : hierarchy.classInfo(f.owner());
                io.just.sast.model.FieldInfo field = cls != null ? cls.field(f.field()) : null;
                if (field != null && field.descriptor().startsWith("L")) {
                    t = field.descriptor().substring(1, field.descriptor().length() - 1);
                }
            } else if (origin instanceof ValueOrigin.Insn i) {
                var op = in.insnAt(i.offset());
                if (op.op() == io.just.sast.model.Op.NEW && !op.operands().isEmpty()
                        && op.typeRef().descriptor().startsWith("L") && op.typeRef().descriptor().endsWith(";")) {
                    t = op.typeRef().descriptor().substring(1, op.typeRef().descriptor().length() - 1);
                } else if (op.op() == io.just.sast.model.Op.NEW && !op.operands().isEmpty()) {
                    t = op.typeRef().descriptor();
                }
            } else if (origin instanceof ValueOrigin.CallResult cr && cr.callNodeId() >= 0) {
                Node callNode = callNodes.get(cr.callNodeId());
                if (callNode != null && "<init>".equals(callNode.strProp("name"))) {
                    t = callNode.strProp("owner"); // new X() 构造器结果 = X
                }
            } else if (origin instanceof ValueOrigin.Param p) {
                t = Descriptor.paramType(in.descriptor(),
                        Descriptor.paramOrdinal(in.descriptor(), in.isStatic(), p.slot()));
                if (t != null && t.startsWith("L") && t.endsWith(";")) {
                    t = t.substring(1, t.length() - 1);
                } else {
                    t = null;
                }
            }
            if (t == null) {
                return null;
            }
            if (type == null) {
                type = t;
            } else if (!type.equals(t)) {
                return null;
            }
        }
        return type;
    }

    private static final Set<String> UNIVERSAL_TYPES = Set.of(
            "java/lang/Object", "java/io/Serializable", "java/lang/Cloneable", "java/lang/Comparable",
            "java/io/Externalizable", "java/util/Collection", "java/util/Map", "java/util/List",
            "java/util/Set");

    /** 所有有 JavaBean 前缀方法（get 前缀或 is 前缀 公共非静态无参非 void）的 Serializable 类。 */
    private static boolean isUniversalType(String t) {
        return "java/lang/Object".equals(t) || "java/io/Serializable".equals(t)
                || "java/io/Externalizable".equals(t) || "java/lang/Cloneable".equals(t)
                || "java/lang/Comparable".equals(t);
    }

    private Set<String> computeSerializableWithGetters(Graph graph) {
        Set<String> result = new HashSet<>();
        Set<String> owners = new HashSet<>();
        for (Node m : graph.nodesOfType(NodeType.METHOD)) {
            owners.add(m.strProp("owner"));
        }
        for (String owner : owners) {
            if (!hierarchy.isSerializable(owner)) {
                continue;
            }
            var ci = hierarchy.classInfo(owner);
            if (ci == null) {
                continue;
            }
            for (var mi : ci.methods()) {
                String n = mi.name();
                if (java.lang.reflect.Modifier.isPublic(mi.access())
                        && !java.lang.reflect.Modifier.isStatic(mi.access())
                        && ((n.startsWith("get") && n.length() > 3) || (n.startsWith("is") && n.length() > 2))
                        && Descriptor.paramCount(mi.descriptor()) == 0
                        && !mi.descriptor().endsWith(")V")) {
                    result.add(owner);
                    break;
                }
            }
        }
        return result;
    }

    private Set<String> computeOccupiable(Graph graph) {
        Set<String> types = new HashSet<>();
        Set<String> owners = new HashSet<>();
        for (Node m : graph.nodesOfType(NodeType.METHOD)) {
            owners.add(m.strProp("owner"));
        }
        for (String owner : owners) {
            var ci = hierarchy.classInfo(owner);
            if (ci == null || !hierarchy.isSerializable(owner)) {
                continue;
            }
            for (var f : ci.fields()) {
                if (java.lang.reflect.Modifier.isTransient(f.access())
                        || java.lang.reflect.Modifier.isStatic(f.access())) {
                    continue;
                }
                String d = f.descriptor();
                if (d.startsWith("L") && d.endsWith(";")) {
                    types.add(d.substring(1, d.length() - 1));
                } else if (d.startsWith("[L") && d.endsWith(";")) {
                    types.add(d.substring(2, d.length() - 1));
                }
            }
        }
        types.removeAll(UNIVERSAL_TYPES);
        return types;
    }

    /** ObjectInputStream 读调用（反序列化数据源，无条件可控）。 */
    public static boolean isOisRead(Node call) {
        String owner = call.strProp("owner");
        String name = call.strProp("name");
        return "java/io/ObjectInputStream".equals(owner)
                && (name.equals("readObject") || name.equals("readUnshared") || name.equals("readFields"));
    }

    /** 指令按值消耗的栈条目数（cat-2 值亦为单条目，条目数 = 值数）。 */
    public static int consumedCount(Op op) {
        return switch (op) {
            case NEW -> 0;
            case INEG, LNEG, FNEG, DNEG, I2L, I2F, I2D, L2I, L2F, L2D,
                    F2I, F2L, F2D, D2I, D2L, D2F, I2B, I2C, I2S,
                    ARRAYLENGTH, CHECKCAST, INSTANCEOF -> 1;
            case IALOAD, LALOAD, FALOAD, DALOAD, AALOAD, BALOAD, CALOAD, SALOAD,
                    IADD, LADD, FADD, DADD, ISUB, LSUB, FSUB, DSUB,
                    IMUL, LMUL, FMUL, DMUL, IDIV, LDIV, FDIV, DDIV,
                    IREM, LREM, FREM, DREM, ISHL, LSHL, ISHR, LSHR, IUSHR, LUSHR,
                    IAND, LAND, IOR, LOR, IXOR, LXOR, LCMP, FCMPL, FCMPG, DCMPL, DCMPG -> 2;
            default -> 0;
        };
    }

    public static String methodKey(MethodInfo method) {
        return method.owner() + "#" + method.name() + method.descriptor();
    }

    /** CALL 节点所在方法的键。 */
    public static String methodKey(Node call) {
        return methodKeyOf(call.strProp("methodOwner"), call.strProp("methodName"), call.strProp("methodDesc"));
    }

    public static String methodKeyOf(String owner, String name, String desc) {
        return owner + "#" + name + desc;
    }
}
