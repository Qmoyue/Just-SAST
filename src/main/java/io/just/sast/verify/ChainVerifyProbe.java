package io.just.sast.verify;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamClass;
import java.io.ObjectStreamConstants;
import java.io.ObjectStreamField;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.ArrayList;
import java.util.ArrayDeque;
import java.util.Collections;
import java.util.Deque;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/**
 * 链级验证探针：沿链的 FIELD_FLOW 跳构造完整对象图，触发入口方法，
 * 检查 sink 是否真实执行（异常栈帧的类名+方法名全等匹配）。
 *
 * 参数格式：
 *   arg0: entryClass|entryMethod|mode
 *   arg1: 链跳描述，逗号分隔：fromOwner.fieldName=toOwnerClassName
 *   arg2: sinkClass.sinkMethod[|descriptor]（用于 sink 特异性判定，点分类名）
 *
 * 判定标准：
 *   SINK_TRIGGERED — 异常栈帧中存在 declaringClass == sinkClass && methodName == sinkMethod
 *                    （栈帧级全等匹配：子串匹配会把 java.lang.RuntimeException 误判为
 *                    java.lang.Runtime，已废除）
 *   PARTIAL_PATH — 异常来自链中间环节（类型不匹配/空指针/入口方法缺失），sink 未到达
 *   EXECUTED — 入口方法真实调用且正常返回（无异常完成）
 */
public final class ChainVerifyProbe {

    private static final int MAX_GRAPH_OBJECTS = 128;
    private static final int MAX_PROXY_INTERFACES = 64;
    private static final int MAX_PROXY_METHODS = 128;
    /**
     * The launcher system loader is normally sufficient, but fat JAR/WAR verification has
     * class-path entries materialized immediately before the child is started.  Keep an
     * explicit read-only application loader as the context loader so lookup does not depend on
     * launcher-specific wildcard/manifest behavior.  Its parent remains the system loader,
     * preserving the probe and platform classes without duplicating them.
     */
    private static ClassLoader applicationLoader;

    /** Semantic source-host callback description; used only by the inert probe adapter. */
    private record SourceTrigger(String entryClass, String entryMethod, String callbackKind,
                                 String sourceOwner, String sourceMethod, String sourceDescriptor,
                                 String downstreamOwner, String downstreamMethod) {
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("usage: ChainVerifyProbe <entry|method|mode> [hops] [sink]");
            System.exit(2);
        }

        String[] entryParts = args[0].split("\\|", -1);
        if (entryParts.length < 2 || entryParts[0].isBlank() || entryParts[1].isBlank()) {
            System.err.println("usage: ChainVerifyProbe <entryClass|entryMethod|mode> [hops] [sink]");
            System.exit(2);
            return;
        }
        String entryClass = entryParts[0];
        String entryMethod = entryParts[1];
        String mode = entryParts.length > 2 ? entryParts[2] : "DIRECT";
        String entryDescriptor = entryParts.length > 3 ? entryParts[3] : "";

        // 解析链跳
        List<String[]> fieldLinks = new ArrayList<>(); // [fromOwner, fieldName, toClassName]
        if (args.length > 1 && !args[1].isEmpty()) {
            for (String hop : args[1].split(",")) {
                // format: fromOwner.fieldName=toClassName
                int eq = hop.indexOf('=');
                if (eq < 0) continue;
                String left = hop.substring(0, eq);
                String toClass = hop.substring(eq + 1);
                int dot = left.lastIndexOf('.');
                if (dot < 0) continue;
                fieldLinks.add(new String[]{left.substring(0, dot), left.substring(dot + 1), toClass});
            }
        }

        // sink 目标：方法名不能含 '.'，最后一个 '.' 前是类名（方法名参与判定——只匹配类会把
        // 路过 sink 类任意方法的堆栈都算触发）
        String sinkTarget = args.length > 2 ? args[2] : "";
        String sinkDescriptor = "";
        int descriptorBar = sinkTarget.lastIndexOf('|');
        if (descriptorBar > 0) {
            sinkDescriptor = sinkTarget.substring(descriptorBar + 1);
            sinkTarget = sinkTarget.substring(0, descriptorBar);
        }
        String sinkClassDotted = "";
        String sinkMethod = "";
        int sinkDot = sinkTarget.lastIndexOf('.');
        if (sinkDot > 0) {
            sinkClassDotted = sinkTarget.substring(0, sinkDot).replace('/', '.');
            sinkMethod = sinkTarget.substring(sinkDot + 1);
        }
        boolean unresolvedReflectiveTarget = args.length > 3
                && "UNRESOLVED".equals(args[3]);
        SourceTrigger sourceTrigger = parseSourceTrigger(args.length > 4 ? args[4] : "");

        try {
            installApplicationLoader();
            try {
                SandboxSecurityManager.install(java.nio.file.Path.of(
                        System.getProperty("java.io.tmpdir", ".")));
            } catch (Throwable sandboxFailure) {
                System.out.println("SANDBOX_UNAVAILABLE: "
                        + sandboxFailure.getClass().getSimpleName());
                System.exit(3);
                return;
            }
            // 0. 创建所有类的实例（自底向上）；无无参构造时回退到参数最少的构造器并按类型填默认值。
            //    类加载走 loadClass（非 Class.forName）——探针自身的类解析不得踩中 Class#forName canary
            Map<String, Object> instances = new HashMap<>();
            Class<?> entryCls = load(entryClass);
            boolean serializationSemantics = "SERIAL".equals(mode) || isTriggerMode(mode);
            Method selectedEntry = findMethod(entryCls, entryMethod, entryDescriptor);
            boolean staticEntry = selectedEntry != null
                    && Modifier.isStatic(selectedEntry.getModifiers());
            Object entryInstance;
            try {
                entryInstance = newInstance(entryCls, serializationSemantics);
            } catch (Exception constructionFailure) {
                // A static source host does not need an object instance. Keep the direct
                // invocation test useful while preserving a partial result for instance hosts.
                if (!staticEntry) {
                    throw constructionFailure;
                }
                entryInstance = null;
            }
            if (entryInstance != null) {
                instances.put(entryClass, entryInstance);
            }

            Object sourceTriggerInstance = null;
            if (sourceTrigger != null) {
                try {
                    String triggerName = sourceTrigger.entryClass().replace('/', '.');
                    sourceTriggerInstance = instances.get(triggerName);
                    if (sourceTriggerInstance == null) {
                        sourceTriggerInstance = newInstance(load(triggerName), true);
                        instances.put(triggerName, sourceTriggerInstance);
                    }
                } catch (Exception | LinkageError ignored) {
                    // The source adapter remains a normal bounded source probe when the
                    // semantic trigger class is unavailable on the target classpath.
                }
            }

            // The sink receiver is part of the executable path, but it is often supplied by
            // the serialized graph rather than by a reported FIELD_FLOW hop (notably for
            // InvocationHandler fields).  Create one application receiver once and let the
            // ordinary declared-type field linker reuse it; platform sink receivers remain
            // untouched so verification never instantiates Runtime/ProcessBuilder-like APIs.
            Object sinkReceiver = null;
            if (!sinkClassDotted.isBlank()) {
                try {
                    Class<?> sinkType = load(sinkClassDotted);
                    if (isApplicationType(sinkType)) {
                        sinkReceiver = newInstance(sinkType, serializationSemantics);
                        if (sinkReceiver != null) {
                            instances.putIfAbsent(sinkType.getName(), sinkReceiver);
                        }
                    }
                } catch (Exception | LinkageError ignored) {
                    // A missing receiver is reported as a partial construction later.
                }
            }

            // 创建链跳中涉及的类。字段依赖的 fromOwner 可能不是入口类（例如
            // InvocationHandler 的字段由入口 trampoline 通过构造器临时创建），
            // 两端都必须进入同一个有界对象图；只创建 toOwner 会把合法字段边
            // 错误降级为 owner-missing，并使后续字段类型约束无法生效。
            for (String[] link : fieldLinks) {
                String fromClass = link[0].replace('/', '.');
                String toClass = link[2].replace('/', '.');
                if (!instances.containsKey(fromClass)) {
                    try {
                        instances.put(fromClass, newInstance(load(fromClass), serializationSemantics));
                    } catch (Exception | LinkageError ignored) {
                    }
                }
                if (!instances.containsKey(toClass)) {
                    try {
                        instances.put(toClass, newInstance(load(toClass), serializationSemantics));
                    } catch (Exception | LinkageError ignored) {
                    }
                }
            }

            // 2. 链接字段（fromOwner.fieldName = toOwner 实例）
            List<String> unlinkedFields = new ArrayList<>();
            for (String[] link : fieldLinks) {
                String fromClass = link[0].replace('/', '.');
                String fieldName = link[1];
                String toClass = link[2].replace('/', '.');
                Object fromInstance = instances.get(fromClass);
                Object toInstance = instances.get(toClass);
                if (fromInstance == null) {
                    unlinkedFields.add(fromClass + "." + fieldName + ":owner-missing");
                    continue;
                }
                Field field = findField(fromInstance.getClass(), fieldName);
                if (field == null) {
                    unlinkedFields.add(fromClass + "." + fieldName + ":field-missing");
                    continue;
                }
                try {
                    field.setAccessible(true);
                    if (field.getType() == Object.class) {
                        // Object 字段可以承载任意链值。目标实例缺失时使用安全的
                        // 可反射默认值，而不是把入口对象错误地塞回字段（这会让
                        // input.getClass()/getMethod 链永远解析到入口宿主自身）。
                        Object fallback = defaultValue(Object.class);
                        field.set(fromInstance, toInstance != null ? toInstance
                                : (fallback != null ? fallback : entryInstance));
                    } else {
                        Object compatible = toInstance != null && field.getType().isInstance(toInstance)
                                ? toInstance : compatibleInstance(instances, field.getType());
                        if (compatible == null && serializationSemantics) {
                            // The static chain may only carry a method owner after the
                            // backwards traversal.  The JVM field declaration is the
                            // authoritative points-to constraint; use it to recover a
                            // constructor-free application object when the encoded hop
                            // target is abstract or otherwise imprecise.
                            compatible = safeNestedObject(field.getType());
                        }
                        if (compatible != null && field.getType().isInstance(compatible)) {
                            field.set(fromInstance, compatible);
                            instances.putIfAbsent(field.getType().getName(), compatible);
                        } else if (Map.class.isAssignableFrom(field.getType())
                            || Set.class.isAssignableFrom(field.getType())
                            || List.class.isAssignableFrom(field.getType())) {
                            // 集合布局构造：容器字段按声明类型实例化，链接目标放入
                            // key/元素位——后段入口对象经容器槽位进入对象图，
                            // 容器反序列化时触发其 hashCode/equals/compareTo
                            Object container = newCollection(field.getType());
                            Object element = toInstance != null ? toInstance : compatibleInstance(
                                    instances, Object.class);
                            if (container == null || element == null) {
                                unlinkedFields.add(fromClass + "." + fieldName + ":collection-unlinked");
                            } else {
                                if (container instanceof Map<?, ?> map) {
                                    @SuppressWarnings("unchecked")
                                    Map<Object, Object> m2 = (Map<Object, Object>) map;
                                    m2.put(element, "echo CHAIN_OK");
                                } else if (container instanceof Set<?> set) {
                                    @SuppressWarnings("unchecked")
                                    Set<Object> s2 = (Set<Object>) set;
                                    s2.add(element);
                                } else {
                                    @SuppressWarnings("unchecked")
                                    List<Object> l2 = (List<Object>) container;
                                    l2.add(element);
                                }
                                field.set(fromInstance, container);
                            }
                        } else if (!field.getType().isPrimitive() && field.getType() != String.class
                                && !field.getType().isEnum()) {
                            unlinkedFields.add(fromClass + "." + fieldName + ":type-mismatch");
                        }
                    }
                } catch (Exception | LinkageError e) {
                    unlinkedFields.add(fromClass + "." + fieldName + ":" + e.getClass().getSimpleName());
                }
            }

            // 3. 填充简单字段和安全的应用对象引用（含父类——getDeclaredFields 只看自身类）。
            //    序列化触发模式只为非 transient 的 Serializable 应用对象分配实例，
            //    且优先使用 allocateInstance，避免为了验证而执行目标构造器。
            Deque<Object> pending = new ArrayDeque<>(instances.values());
            Set<Object> visited = Collections.newSetFromMap(new IdentityHashMap<>());
            Map<Class<?>, Object> defaults = new HashMap<>();
            for (Object value : instances.values()) {
                defaults.putIfAbsent(value.getClass(), value);
            }
            while (!pending.isEmpty()) {
                Object inst = pending.removeFirst();
                if (!visited.add(inst)) {
                    continue;
                }
                for (Class<?> c = inst.getClass(); c != null && c != Object.class; c = c.getSuperclass()) {
                    for (Field f : c.getDeclaredFields()) {
                        if (Modifier.isStatic(f.getModifiers())) continue;
                        if (serializationSemantics && Modifier.isTransient(f.getModifiers())) continue;
                        try {
                            // JDK modules may reject deep reflection before the field is
                            // inspected (for example, private fields of java.lang.String).
                            // A denied field is merely an unfilled optional input; it must not
                            // abort the whole probe before the result can be classified as
                            // PARTIAL_PATH.
                            f.setAccessible(true);
                            if (f.get(inst) == null) {
                                if (sinkReceiver != null && f.getType().isInstance(sinkReceiver)) {
                                    f.set(inst, sinkReceiver);
                                    pending.addLast(sinkReceiver);
                                } else if (f.getType() == String.class) {
                                    // "toString"：在 Object 上恒可解析——方法名语义字段（如
                                    // methodName）经 getMethod 解析成功后链才能到达 Method.invoke；
                                    // 非 方法名语义的字符串作为普通参数传入 sink，sink 内抛错仍留栈帧
                                    f.set(inst, "toString");
                                } else if (unresolvedReflectiveTarget) {
                                    Object reflectiveShape = unresolvedReflectiveShape(
                                            f.getType(), sinkClassDotted, sinkMethod,
                                            serializationSemantics);
                                    if (reflectiveShape != null) {
                                        f.set(inst, reflectiveShape);
                                    }
                                } else if (f.getType() == Object.class) {
                                    f.set(inst, "toString");
                                } else if (f.getType().isArray()) {
                                    // 空数组：null 数组传给可变参/参数表方法会 NPE 短路链
                                    f.set(inst, java.lang.reflect.Array.newInstance(
                                            f.getType().getComponentType(), 0));
                                } else if (f.getType().isInterface()
                                         && entryInstance instanceof InvocationHandler handler
                                         && f.getType() != InvocationHandler.class) {
                                    // A handler may itself delegate to another proxy.  Build
                                    // that edge from the declared interface type, under the
                                    // same short bootstrap scope used for the outer proxy.
                                    Object nestedProxy = newProxy(f.getType(), handler);
                                    if (nestedProxy != null) {
                                        f.set(inst, nestedProxy);
                                    }
                                } else if (f.getType().isInterface()
                                         && f.getType() != InvocationHandler.class) {
                                    // A trampoline can receive a proxy whose handler is a
                                    // serialized application object. Recover a bounded set of
                                    // application handlers from the same class path and choose
                                    // the first JVM-compatible proxy; the handler object remains
                                    // in the normal pending graph so its sink fields are filled
                                    // by the same declared-type rules above.
                                    Object nestedProxy = applicationProxy(f.getType(),
                                            entryCls.getClassLoader(), serializationSemantics,
                                            instances, pending);
                                    if (nestedProxy != null) {
                                        f.set(inst, nestedProxy);
                                    }
                                } else if (f.getType() == int.class || f.getType() == Integer.class) {
                                    f.set(inst, 0);
                                } else if (f.getType() == boolean.class || f.getType() == Boolean.class) {
                                    f.set(inst, false);
                                } else if (isTriggerMode(mode)
                                        && (Map.class.isAssignableFrom(f.getType())
                                            || Set.class.isAssignableFrom(f.getType()))) {
                                    // 触发忠实模式：空的 Map/Set 字段放入入口对象——
                                    // 反序列化该容器时即按真实路径触发入口（TRIGGER 桥语义）
                                    Object container = newCollection(f.getType());
                                    if (container instanceof Map<?, ?> map) {
                                        @SuppressWarnings("unchecked")
                                        Map<Object, Object> m2 = (Map<Object, Object>) map;
                                        m2.put(entryInstance, "echo CHAIN_OK");
                                    } else if (container instanceof Set<?> set) {
                                        @SuppressWarnings("unchecked")
                                        Set<Object> s2 = (Set<Object>) set;
                                        s2.add(entryInstance);
                                    }
                                    if (container != null) {
                                        f.set(inst, container);
                                    }
                                } else if (serializationSemantics && instances.size() < MAX_GRAPH_OBJECTS) {
                                    Object nested = defaults.get(f.getType());
                                    if (nested == null) {
                                        for (Object candidate : defaults.values()) {
                                            if (f.getType().isInstance(candidate)) {
                                                nested = candidate;
                                                break;
                                            }
                                        }
                                    }
                                    if (nested == null) {
                                        nested = safeNestedObject(f.getType());
                                    }
                                    if (nested != null && f.getType().isInstance(nested)) {
                                        f.set(inst, nested);
                                        defaults.putIfAbsent(nested.getClass(), nested);
                                        instances.putIfAbsent(nested.getClass().getName(), nested);
                                        pending.addLast(nested);
                                    }
                                }
                            }
                        } catch (Exception | LinkageError ignored) {
                        }
                    }
                }
            }

            if (sourceTrigger != null && sourceTriggerInstance != null) {
                prepareSourceTrigger(sourceTrigger, sourceTriggerInstance);
            }

            if (!unlinkedFields.isEmpty()) {
                System.out.println("PARTIAL_PATH: field-unlinked=" + unlinkedFields.size());
                System.exit(0);
            }

            // 4. 触发入口（触发忠实：按真实反序列化的触发路径，非直接调用）
            switch (mode) {
                case "TRIGGER_HASH" -> {
                    // hashCode 入口的真实触发：对象作为 HashMap 的 key 被放入
                    new java.util.HashMap<Object, Object>().put(entryInstance, "echo CHAIN_OK");
                    if (reportLatchedCanary(sinkClassDotted, sinkMethod)) return;
                    System.out.println("EXECUTED");
                    System.exit(0);
                }
                case "TRIGGER_COMPARETO" -> {
                    // TreeSet 的第一次 add 不会比较；先放入同类基准对象，第二次 add
                    // 才会以真实自然排序语义调用 entryInstance.compareTo。
                    java.util.TreeSet<Object> set = new java.util.TreeSet<>();
                    set.add(newInstance(entryCls, serializationSemantics));
                    set.add(entryInstance);
                    if (reportLatchedCanary(sinkClassDotted, sinkMethod)) return;
                    System.out.println("EXECUTED");
                    System.exit(0);
                }
                case "TRIGGER_COMPARATOR" -> {
                    // Comparator 入口不是 Comparable 入口：把入口对象作为 TreeMap comparator，
                    // 两个不同 key 才会触发 Comparator.compare。
                    if (!(entryInstance instanceof java.util.Comparator<?>)) {
                        System.out.println("PARTIAL_PATH: entry-not-comparator");
                        System.exit(0);
                    }
                    @SuppressWarnings("unchecked")
                    java.util.Comparator<Object> c = (java.util.Comparator<Object>) entryInstance;
                    java.util.TreeMap<Object, Object> map = new java.util.TreeMap<>(c);
                    map.put("CHAIN_LEFT", "left");
                    map.put("CHAIN_RIGHT", "right");
                    if (reportLatchedCanary(sinkClassDotted, sinkMethod)) return;
                    System.out.println("EXECUTED");
                    System.exit(0);
                }
                case "TRIGGER_CONTAINS" -> {
                    // equals 入口的真实触发：非空集合的 contains 逐元素调用 equals
                    java.util.List<Object> l = new java.util.ArrayList<>();
                    l.add(new Object());
                    l.contains(entryInstance);
                    if (reportLatchedCanary(sinkClassDotted, sinkMethod)) return;
                    System.out.println("EXECUTED");
                    System.exit(0);
                }
                case "PROXY" -> {
                    if (!java.lang.reflect.InvocationHandler.class.isAssignableFrom(entryCls)) {
                        System.out.println("PARTIAL_PATH: entry-not-handler");
                        System.exit(0);
                    }
                    triggerProxyInterfaces(entryCls, (InvocationHandler) entryInstance);
                }
                case "SERIAL" -> {
                    SandboxSecurityManager.beginSerializationBootstrap();
                    try {
                        java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
                        Class<?> noDataTarget = readObjectNoDataTarget(instances, entryCls);
                        ObjectOutputStream output = noDataTarget == null
                                ? new ObjectOutputStream(bos)
                                : new MissingSuperclassObjectOutputStream(bos, noDataTarget);
                        try {
                            output.writeObject(entryInstance);
                        } finally {
                            output.close();
                        }
                        try (java.io.ObjectInputStream input = new java.io.ObjectInputStream(
                                new java.io.ByteArrayInputStream(bos.toByteArray()))) {
                            // 动态验证只需确认链是否能到达 sink；对象流本身也必须有界，
                            // 防止恶意 readObject 通过递归/海量引用把验证子 JVM 变成 DoS 点。
                            input.setObjectInputFilter(info ->
                                    info.depth() > 32 || info.references() > 4096
                                            || info.streamBytes() > 8L * 1024 * 1024
                                            ? java.io.ObjectInputFilter.Status.REJECTED
                                            : java.io.ObjectInputFilter.Status.UNDECIDED);
                            input.readObject();
                        }
                    } finally {
                        SandboxSecurityManager.endSerializationBootstrap();
                    }
                }
                case "SOURCE" -> {
                    if (selectedEntry == null) {
                        System.out.println("PARTIAL_PATH: entry-method-missing");
                        System.exit(0);
                    }
                    // Framework source methods often instantiate ObjectInputStream inside
                    // target code. Warm its JDK bootstrap while the trusted probe frame is
                    // still the permission boundary; otherwise Java 17's lambda/accessor
                    // initialization is attributed to the target frame and the sandbox
                    // rejects the source before the serialized callback can run.
                    SandboxSecurityManager.beginSerializationBootstrap();
                    try {
                        warmRuntimeSupport(sinkClassDotted);
                        invokeEntry(selectedEntry, entryInstance, true, sourceTrigger,
                                sourceTriggerInstance);
                    } finally {
                        SandboxSecurityManager.endSerializationBootstrap();
                    }
                    // A source adapter can reach an instrumented sink through reflection or
                    // a callback that wraps SinkReachedError in InvocationTargetException.
                    // Check the process-wide canary latch before treating the wrapper as a
                    // partial source failure; otherwise a real source-to-trigger path is
                    // systematically downgraded even though the sink was reached.
                    if (reportLatchedCanary(sinkClassDotted, sinkMethod)) return;
                    System.out.println("EXECUTED: source-default-input");
                    System.exit(0);
                }
                default -> {
                    Method m = selectedEntry != null ? selectedEntry
                            : findMethod(entryCls, entryMethod, "");
                    if (m == null) {
                        // 入口方法在目标类上不可解析：探针无法触发——不是"链执行完成"
                        System.out.println("PARTIAL_PATH: entry-method-missing");
                        System.exit(0);
                    }
                    m.setAccessible(true);
                    invokeEntry(m, entryInstance, false);
                }
            }

            if (reportLatchedCanary(sinkClassDotted, sinkMethod)) return;
            System.out.println("EXECUTED");
            System.exit(0);

        } catch (Throwable t) {
            // Reflection and deserialization commonly wrap an instrumented sink error before
            // it reaches this boundary.  The bootstrap canary latch is deliberately checked
            // before inspecting the wrapper cause, so a target catch/unwrap path cannot erase
            // an otherwise valid source-to-sink observation.
            if (reportLatchedCanary(sinkClassDotted, sinkMethod)) return;
            // 优先：sink canary 主动命中（插桩 sink 入口抛出的标记 Error，穿透 gadget 的
            // catch(Exception)）。命中须同时满足：标记 spec == 本链 sink 且栈中存在
            // 链入口方法帧（在 sink 帧之下）——排除探针自身基础设施误踩 sink。
            String marker = markerSpec(t);
            if (marker != null && sameSink(marker, sinkClassDotted, sinkMethod, sinkDescriptor)
                    && entryReached(t, entryClass, entryMethod)) {
                System.out.println("SINK_TRIGGERED: " + sinkClassDotted);
                System.err.println("SINK_REACHED: " + sinkClassDotted + "." + sinkMethod
                        + " (canary)");
                System.exit(1);
            }
            // 次选：栈帧级全等匹配（类名 + 方法名），含 cause 链——同样要求入口帧在场
            if (sinkDescriptor.isEmpty() && reachesSink(t, sinkClassDotted, sinkMethod)
                    && entryReached(t, entryClass, entryMethod)) {
                System.out.println("SINK_TRIGGERED: " + sinkClassDotted);
                System.err.println("SINK_REACHED: " + sinkClassDotted + "." + sinkMethod
                        + " in " + t.getClass().getName());
                System.exit(1);
            }
            // 链中间环节失败（非 sink）；消息带关键归因（如缺失类名），截断防长链污染输出
            Throwable detailCause = t;
            while (detailCause instanceof InvocationTargetException
                    && detailCause.getCause() != null) {
                detailCause = detailCause.getCause();
            }
            String detail = detailCause.getMessage();
            String cause = detailCause == t ? ""
                    : " cause=" + detailCause.getClass().getSimpleName();
            System.out.println("PARTIAL_PATH: " + t.getClass().getSimpleName() + cause
                    + (detail != null ? ": " + detail.split("\\R")[0].transform(
                        s -> s.length() > 120 ? s.substring(0, 120) : s) : ""));
            System.exit(0); // 正常退出 = 未到达 sink
        }
    }

    /** Return an already-created object satisfying the field's declared JVM type. */
    private static Object compatibleInstance(Map<String, Object> instances, Class<?> fieldType) {
        for (Object candidate : instances.values()) {
            if (candidate != null && fieldType.isInstance(candidate)) {
                return candidate;
            }
        }
        return null;
    }

    private static boolean isApplicationType(Class<?> type) {
        if (type == null || type.isPrimitive() || type.isArray()) {
            return false;
        }
        String name = type.getName();
        return !name.startsWith("java.") && !name.startsWith("javax.")
                && !name.startsWith("jdk.") && !name.startsWith("sun.")
                && !name.startsWith("com.sun.") && !name.startsWith("io.just.sast.");
    }

    private static Object applicationProxy(Class<?> iface, ClassLoader loader,
                                           boolean serializationSemantics,
                                           Map<String, Object> instances,
                                           Deque<Object> pending) {
        for (Class<?> handlerType : discoverApplicationHandlers(loader)) {
            try {
                Object candidate = newInstance(handlerType, serializationSemantics);
                if (!(candidate instanceof InvocationHandler handler)) {
                    continue;
                }
                instances.putIfAbsent(handlerType.getName(), candidate);
                pending.addLast(candidate);
                Object proxy = newProxy(iface, handler);
                if (proxy != null) {
                    return proxy;
                }
            } catch (Exception | LinkageError ignored) {
                // One handler may require a dependency absent from this target; continue with
                // the next bounded application candidate.
            }
        }
        return null;
    }

    private static List<Class<?>> discoverApplicationHandlers(ClassLoader loader) {
        TreeSet<String> names = new TreeSet<>();
        String classPath = System.getProperty("java.class.path", "");
        for (String entry : classPath.split(java.util.regex.Pattern.quote(
                java.io.File.pathSeparator))) {
            if (entry.isBlank()) {
                continue;
            }
            Path path = Path.of(entry);
            try {
                if (Files.isDirectory(path)) {
                    try (java.util.stream.Stream<Path> files = Files.walk(path)) {
                        files.filter(Files::isRegularFile)
                                .map(path::relativize)
                                .map(Path::toString)
                                .filter(name -> name.endsWith(".class"))
                                .forEach(name -> addHandlerCandidate(names, name));
                    }
                } else if (Files.isRegularFile(path) && entry.endsWith(".jar")) {
                    try (JarFile jar = new JarFile(path.toFile())) {
                        java.util.Enumeration<JarEntry> entries = jar.entries();
                        while (entries.hasMoreElements()) {
                            JarEntry jarEntry = entries.nextElement();
                            if (!jarEntry.isDirectory()) {
                                addHandlerCandidate(names, jarEntry.getName());
                            }
                        }
                    }
                }
            } catch (IOException | SecurityException ignored) {
                // Keep verification bounded when an optional classpath entry is unreadable.
            }
            if (names.size() >= MAX_PROXY_INTERFACES * 4) {
                break;
            }
        }
        List<Class<?>> result = new ArrayList<>();
        for (String name : names) {
            if (result.size() >= MAX_PROXY_INTERFACES) {
                break;
            }
            try {
                Class<?> candidate = Class.forName(name, false, loader);
                if (isApplicationType(candidate) && !candidate.isInterface()
                        && !Modifier.isAbstract(candidate.getModifiers())
                        && InvocationHandler.class.isAssignableFrom(candidate)) {
                    result.add(candidate);
                }
            } catch (ClassNotFoundException | LinkageError | SecurityException ignored) {
            }
        }
        return result;
    }

    private static void addHandlerCandidate(Set<String> names, String name) {
        if (!name.endsWith(".class") || name.contains("module-info")
                || name.contains("package-info")) {
            return;
        }
        String binary = name.substring(0, name.length() - 6).replace('/', '.')
                .replace('\\', '.');
        if (binary.startsWith("java.") || binary.startsWith("javax.")
                || binary.startsWith("jdk.") || binary.startsWith("sun.")
                || binary.startsWith("com.sun.") || binary.startsWith("io.just.sast.")) {
            return;
        }
        names.add(binary);
    }

    /**
     * Exercise a handler through bounded, classpath-derived proxy interfaces.  The scanner's
     * static graph already restricts a reported proxy callback to the interfaces passed at a
     * concrete allocation site; the child has no graph object, so it recovers that same JVM
     * contract by enumerating application interfaces and invoking only their declared methods.
     * No class name, method name, or benchmark package is special-cased here.
     */
    private static void triggerProxyInterfaces(Class<?> handlerType, InvocationHandler handler)
            throws Exception {
        List<Class<?>> interfaces = discoverApplicationInterfaces(handlerType.getClassLoader());
        if (interfaces.isEmpty()) {
            interfaces = List.of(Runnable.class);
        }
        int invoked = 0;
        for (Class<?> iface : interfaces) {
            Object proxy;
            try {
                proxy = newProxy(iface, handler);
            } catch (Throwable ignored) {
                continue;
            }
            if (proxy == null) {
                continue;
            }
            Method[] methods;
            try {
                methods = iface.getMethods();
            } catch (LinkageError | SecurityException ignored) {
                continue;
            }
            java.util.Arrays.sort(methods, java.util.Comparator
                    .comparing(Method::getName)
                    .thenComparing(ChainVerifyProbe::methodDescriptor));
            for (Method method : methods) {
                if (method.getDeclaringClass() == Object.class || invoked++ >= MAX_PROXY_METHODS) {
                    continue;
                }
                try {
                    Object[] arguments = proxyArguments(method.getParameterTypes());
                    method.invoke(proxy, arguments);
                } catch (InvocationTargetException target) {
                    Throwable cause = target.getCause();
                    if (cause instanceof io.just.sast.verify.boot.SinkReachedError error) {
                        throw error;
                    }
                    // A candidate interface is only a trigger hypothesis.  One method's
                    // type/argument failure must not suppress other methods on the interface.
                } catch (Throwable ignored) {
                    // Continue the bounded candidate search; the outer probe classifies a
                    // genuine sink canary through the latch or top-level marker.
                }
                if (io.just.sast.verify.boot.SinkCanaryGate.wasReached()) {
                    return;
                }
            }
            if (invoked >= MAX_PROXY_METHODS) {
                return;
            }
        }
    }

    private static Object newProxy(Class<?> iface, InvocationHandler handler) {
        if (iface == null || !iface.isInterface() || handler == null) {
            return null;
        }
        boolean bootstrap = false;
        try {
            SandboxSecurityManager.beginProxyBootstrap();
            bootstrap = true;
            return java.lang.reflect.Proxy.newProxyInstance(
                    iface.getClassLoader() == null ? ChainVerifyProbe.class.getClassLoader()
                            : iface.getClassLoader(),
                    new Class[]{iface}, handler);
        } catch (Throwable ignored) {
            return null;
        } finally {
            if (bootstrap) {
                SandboxSecurityManager.endProxyBootstrap();
            }
        }
    }

    private static Object[] proxyArguments(Class<?>[] types) {
        Object[] values = new Object[types.length];
        for (int i = 0; i < types.length; i++) {
            Object value = sourceValue(types[i]);
            values[i] = value != null || !types[i].isPrimitive() ? value : defaultValue(types[i]);
        }
        return values;
    }

    private static List<Class<?>> discoverApplicationInterfaces(ClassLoader loader) {
        TreeSet<String> names = new TreeSet<>();
        String classPath = System.getProperty("java.class.path", "");
        for (String entry : classPath.split(java.util.regex.Pattern.quote(
                java.io.File.pathSeparator))) {
            if (entry.isBlank()) {
                continue;
            }
            Path path = Path.of(entry);
            try {
                if (Files.isDirectory(path)) {
                    try (java.util.stream.Stream<Path> files = Files.walk(path)) {
                        files.filter(Files::isRegularFile)
                                .map(path::relativize)
                                .map(Path::toString)
                                .filter(name -> name.endsWith(".class"))
                                .forEach(name -> addInterfaceCandidate(names, name));
                    }
                } else if (Files.isRegularFile(path) && entry.endsWith(".jar")) {
                    try (JarFile jar = new JarFile(path.toFile())) {
                        java.util.Enumeration<JarEntry> entries = jar.entries();
                        while (entries.hasMoreElements()) {
                            JarEntry jarEntry = entries.nextElement();
                            if (!jarEntry.isDirectory()) {
                                addInterfaceCandidate(names, jarEntry.getName());
                            }
                        }
                    }
                }
            } catch (IOException | SecurityException ignored) {
                // Missing optional nested dependency: leave dynamic verification partial for
                // that candidate instead of widening access or aborting the child.
            }
            if (names.size() >= MAX_PROXY_INTERFACES * 4) {
                break;
            }
        }
        List<Class<?>> result = new ArrayList<>();
        for (String name : names) {
            if (result.size() >= MAX_PROXY_INTERFACES) {
                break;
            }
            try {
                Class<?> candidate = Class.forName(name, false, loader);
                if (candidate.isInterface() && candidate.getDeclaredMethods().length > 0
                        && !InvocationHandler.class.isAssignableFrom(candidate)) {
                    result.add(candidate);
                }
            } catch (ClassNotFoundException | LinkageError | SecurityException ignored) {
            }
        }
        return result;
    }

    private static void addInterfaceCandidate(Set<String> names, String name) {
        if (!name.endsWith(".class") || name.contains("module-info")
                || name.contains("package-info")) {
            return;
        }
        String binary = name.substring(0, name.length() - 6).replace('/', '.')
                .replace('\\', '.');
        if (binary.startsWith("java.") || binary.startsWith("javax.")
                || binary.startsWith("jdk.") || binary.startsWith("sun.")
                || binary.startsWith("com.sun.") || binary.startsWith("io.just.sast.")) {
            return;
        }
        names.add(binary);
    }


    private static boolean reportLatchedCanary(String sinkClass, String sinkMethod) {
        if (!io.just.sast.verify.boot.SinkCanaryGate.wasReached()) {
            return false;
        }
        System.out.println("SINK_TRIGGERED: " + sinkClass);
        System.err.println("SINK_REACHED: " + sinkClass + "." + sinkMethod + " (canary-latched)");
        return true;
    }

    /** 沿异常 cause 链（≤6 层）查找 SinkReachedError 标记，返回其 spec（无则 null）。 */
    static String markerSpec(Throwable top) {
        int depth = 0;
        for (Throwable t = top; t != null && depth < 6; t = t.getCause(), depth++) {
            if (t instanceof io.just.sast.verify.boot.SinkReachedError err) {
                return err.getMessage();
            }
        }
        return null;
    }

    /** canary spec 与链 sink 全等比对（spec 为内部类名，sink 为点分）。 */
    static boolean sameSink(String spec, String sinkClassDotted, String sinkMethod) {
        return sameSink(spec, sinkClassDotted, sinkMethod, "");
    }

    /** canary spec 与链 sink 全等比对；存在描述符时同时校验重载签名。 */
    static boolean sameSink(String spec, String sinkClassDotted, String sinkMethod, String sinkDescriptor) {
        int h = spec.indexOf('#');
        if (h <= 0) {
            return false;
        }
        String methodAndDescriptor = spec.substring(h + 1);
        int descriptorHash = methodAndDescriptor.indexOf('#');
        String method = descriptorHash < 0 ? methodAndDescriptor
                : methodAndDescriptor.substring(0, descriptorHash);
        String descriptor = descriptorHash < 0 ? ""
                : methodAndDescriptor.substring(descriptorHash + 1);
        return spec.substring(0, h).replace('/', '.').equals(sinkClassDotted)
                && method.equals(sinkMethod)
                && (descriptorHash < 0 || sinkDescriptor == null || sinkDescriptor.isEmpty()
                || sinkDescriptor.equals(descriptor));
    }

    /** 栈中是否存在链入口类#入口方法帧（真实执行过入口——探针基础设施误踩 sink 无此帧）。 */
    static boolean entryReached(Throwable top, String entryClass, String entryMethod) {
        int depth = 0;
        for (Throwable t = top; t != null && depth < 6; t = t.getCause(), depth++) {
            for (StackTraceElement frame : t.getStackTrace()) {
                if (entryClass.equals(frame.getClassName()) && entryMethod.equals(frame.getMethodName())) {
                    return true;
                }
            }
        }
        return false;
    }

    /** 异常及其 cause 链（≤6 层）的栈帧中是否存在 declaringClass == sinkClass 且 methodName == sinkMethod 的帧。 */
    static boolean reachesSink(Throwable top, String sinkClass, String sinkMethod) {
        if (sinkClass.isEmpty() || sinkMethod.isEmpty()) {
            return false;
        }
        int depth = 0;
        for (Throwable t = top; t != null && depth < 6; t = t.getCause(), depth++) {
            for (StackTraceElement frame : t.getStackTrace()) {
                if (sinkClass.equals(frame.getClassName()) && sinkMethod.equals(frame.getMethodName())) {
                    return true;
                }
            }
            // getStackTrace 对 JVM 优化过的异常可能返回空数组——退回有界诊断文本逐帧核对
            if (t.getStackTrace().length == 0) {
                String trace = formatDiagnosticStack(t);
                if (trace.contains("at " + sinkClass + "." + sinkMethod + "(")) {
                    return true;
                }
            }
        }
        return false;
    }



    /** 实例化：SERIAL/TRIGGER 对 Serializable 类优先模拟 OIS 的无构造器分配。 */
    static Object newInstance(Class<?> cls) throws Exception {
        return newInstance(cls, false);
    }

    static Object newInstance(Class<?> cls, boolean serializationSemantics) throws Exception {
        if (serializationSemantics && java.io.Serializable.class.isAssignableFrom(cls)) {
            Object allocated = allocateWithoutConstructor(cls);
            if (allocated != null) {
                return allocated;
            }
            // Falling back to an arbitrary target constructor would change a serialization
            // probe into target-code execution and can establish side effects before the
            // chain is even tested.  A failed constructor-free allocation is an honest
            // partial result instead.
            throw new IllegalStateException("constructor-free allocation unavailable: "
                    + cls.getName());
        }
        Constructor<?>[] ctors = cls.getDeclaredConstructors();
        Constructor<?> best = null;
        for (Constructor<?> c : ctors) {
            if (c.getParameterCount() == 0) {
                best = c;
                break;
            }
            if (best == null || c.getParameterCount() < best.getParameterCount()) {
                best = c;
            }
        }
        if (best == null) {
            throw new IllegalStateException("no constructor: " + cls.getName());
        }
        best.setAccessible(true);
        Class<?>[] ptypes = best.getParameterTypes();
        Object[] pvalues = new Object[ptypes.length];
        for (int i = 0; i < ptypes.length; i++) {
            pvalues[i] = defaultValue(ptypes[i]);
        }
        return best.newInstance(pvalues);
    }

    /** Unsafe 是探针内部的能力，不向目标工件暴露；失败时回退到反射构造并由结果降级。 */
    private static Object allocateWithoutConstructor(Class<?> cls) {
        boolean bootstrap = false;
        try {
            SandboxSecurityManager.beginSerializationBootstrap();
            bootstrap = true;
            Class<?> unsafeClass = ClassLoader.getSystemClassLoader().loadClass("sun.misc.Unsafe");
            Field field = unsafeClass.getDeclaredField("theUnsafe");
            field.setAccessible(true);
            Object unsafe = field.get(null);
            Method allocate = unsafeClass.getMethod("allocateInstance", Class.class);
            return allocate.invoke(unsafe, cls);
        } catch (Throwable ignored) {
            return null;
        } finally {
            if (bootstrap) {
                SandboxSecurityManager.endSerializationBootstrap();
            }
        }
    }

    /**
     * Allocate only an application Serializable object for graph completion.  Calling a
     * target constructor during verification would turn a data-shape check into arbitrary
     * target execution, so failure to obtain constructor-free allocation remains partial.
     */
    private static Object safeNestedObject(Class<?> type) {
        if (type.isInterface() || Modifier.isAbstract(type.getModifiers())
                || type.getClassLoader() == null
                || !java.io.Serializable.class.isAssignableFrom(type)) {
            return null;
        }
        return allocateWithoutConstructor(type);
    }

    /** 按类型的构造参数默认值（字符串用 "toString"——方法名语义恒可解析；数组给空）。 */
    private static Object defaultValue(Class<?> type) {
        if (type == String.class || type == Object.class) {
            return "toString";
        }
        if (type == int.class) {
            return Integer.valueOf(0);
        }
        if (type == long.class) {
            return Long.valueOf(0L);
        }
        if (type == short.class) {
            return Short.valueOf((short) 0);
        }
        if (type == byte.class) {
            return Byte.valueOf((byte) 0);
        }
        if (type == boolean.class) {
            return Boolean.FALSE;
        }
        if (type == char.class) {
            return Character.valueOf('a');
        }
        if (type == float.class) {
            return Float.valueOf(0.0f);
        }
        if (type == double.class) {
            return Double.valueOf(0.0d);
        }
        if (type.isArray()) {
            return java.lang.reflect.Array.newInstance(type.getComponentType(), 0);
        }
        return null;
    }

    /**
     * Locate a serializable class whose local hierarchy contains a readObjectNoData callback.
     * A normal round trip always writes the current superclass descriptor and therefore cannot
     * exercise that callback.  The candidate list is derived from the constructed graph and is
     * sorted for deterministic probe behavior; no target/package name is consulted.
     */
    private static Class<?> readObjectNoDataTarget(Map<String, Object> instances,
                                                   Class<?> entryType) {
        List<Class<?>> candidates = new ArrayList<>();
        Set<String> seen = new java.util.HashSet<>();
        if (entryType != null) {
            seen.add(entryType.getName());
            candidates.add(entryType);
        }
        for (Object value : instances.values()) {
            if (value != null && seen.add(value.getClass().getName())) {
                candidates.add(value.getClass());
            }
        }
        candidates.sort(java.util.Comparator.comparing(Class::getName));
        for (Class<?> candidate : candidates) {
            if (hasReadObjectNoDataAncestor(candidate) && canOmitSerializableParents(candidate)) {
                return candidate;
            }
        }
        return null;
    }

    private static boolean hasReadObjectNoDataAncestor(Class<?> type) {
        for (Class<?> current = type == null ? null : type.getSuperclass();
             current != null && current != Object.class;
             current = current.getSuperclass()) {
            try {
                current.getDeclaredMethod("readObjectNoData");
                return true;
            } catch (NoSuchMethodException ignored) {
            } catch (LinkageError denied) {
                return false;
            }
        }
        return false;
    }

    /**
     * Omitting a superclass descriptor is safe only when the omitted serializable slots carry
     * no fields or custom writeObject data.  Otherwise ObjectOutputStream would still append
     * bytes for a slot that the rewritten descriptor no longer advertises, making the probe
     * malformed rather than a faithful old-version stream.
     */
    private static boolean canOmitSerializableParents(Class<?> type) {
        for (Class<?> current = type == null ? null : type.getSuperclass();
             current != null && current != Object.class;
             current = current.getSuperclass()) {
            if (!java.io.Serializable.class.isAssignableFrom(current)) {
                break;
            }
            ObjectStreamClass descriptor = ObjectStreamClass.lookupAny(current);
            if (descriptor.getFields().length != 0 || declaresPrivateWriteObject(current)) {
                return false;
            }
        }
        return type != null && java.io.Serializable.class.isAssignableFrom(type);
    }

    private static boolean declaresPrivateWriteObject(Class<?> type) {
        try {
            Method method = type.getDeclaredMethod("writeObject", ObjectOutputStream.class);
            return Modifier.isPrivate(method.getModifiers()) && method.getReturnType() == void.class;
        } catch (NoSuchMethodException ignored) {
            return false;
        } catch (LinkageError denied) {
            return true;
        }
    }

    /**
     * A bounded serialization compatibility stream used solely for readObjectNoData probes.
     * It rewrites one descriptor as an old stream would have written it: the class remains in
     * the stream, while its local serializable parent descriptor is absent.  It never executes
     * target methods while writing and is enabled only after the graph-derived safety checks
     * above have accepted an empty/custom-data-free parent chain.
     */
    private static final class MissingSuperclassObjectOutputStream extends ObjectOutputStream {
        private final Class<?> missingParentTarget;

        private MissingSuperclassObjectOutputStream(java.io.OutputStream output, Class<?> target)
                throws IOException {
            super(output);
            this.missingParentTarget = target;
        }

        @Override
        protected void writeClassDescriptor(ObjectStreamClass descriptor) throws IOException {
            if (descriptor.forClass() == missingParentTarget) {
                writeDescriptorWithoutSuperclass(descriptor);
                return;
            }
            super.writeClassDescriptor(descriptor);
        }

        private void writeDescriptorWithoutSuperclass(ObjectStreamClass descriptor)
                throws IOException {
            writeUTF(descriptor.getName());
            writeLong(descriptor.getSerialVersionUID());
            Class<?> type = descriptor.forClass();
            byte flags;
            if (type != null && java.io.Externalizable.class.isAssignableFrom(type)) {
                flags = (byte) (ObjectStreamConstants.SC_EXTERNALIZABLE
                        | ObjectStreamConstants.SC_BLOCK_DATA);
            } else {
                flags = ObjectStreamConstants.SC_SERIALIZABLE;
                if (type != null && type.isEnum()) {
                    flags |= ObjectStreamConstants.SC_ENUM;
                }
                if (type != null && declaresPrivateWriteObject(type)) {
                    flags |= ObjectStreamConstants.SC_WRITE_METHOD;
                }
            }
            writeByte(flags);
            ObjectStreamField[] fields = descriptor.getFields();
            writeShort(fields.length);
            for (ObjectStreamField field : fields) {
                writeByte(field.getTypeCode());
                writeUTF(field.getName());
                char code = field.getTypeCode();
                if (code == 'L' || code == '[') {
                    writeObject(field.getTypeString());
                }
            }
            writeByte(ObjectStreamConstants.TC_ENDBLOCKDATA);
            writeByte(ObjectStreamConstants.TC_NULL);
        }
    }

    /** 触发忠实模式判定。 */
    static boolean isTriggerMode(String mode) {
        return "TRIGGER_HASH".equals(mode) || "TRIGGER_COMPARETO".equals(mode)
                || "TRIGGER_COMPARATOR".equals(mode) || "TRIGGER_CONTAINS".equals(mode);
    }

    /** 按声明类型实例化集合：具体类型反射实例化；接口/抽象类型——有序系（SortedX/NavigableX）
    /**
     * 取 Tree 实现（保持 compareTo 触发语义），其余取 Hash/Array 默认实现。
     */
    static Object newCollection(Class<?> type) {
        boolean isCollection = Map.class.isAssignableFrom(type) || Set.class.isAssignableFrom(type)
                || List.class.isAssignableFrom(type);
        if (!isCollection) {
            return null;
        }
        boolean ifaceOrAbstract = type.isInterface() || java.lang.reflect.Modifier.isAbstract(type.getModifiers());
        if (!ifaceOrAbstract) {
            return newInstanceQuietly(type);
        }
        if (java.util.SortedMap.class.isAssignableFrom(type)) {
            return new java.util.TreeMap<>();
        }
        if (Map.class.isAssignableFrom(type)) {
            return new java.util.HashMap<>();
        }
        if (java.util.SortedSet.class.isAssignableFrom(type)) {
            return new java.util.TreeSet<>();
        }
        if (Set.class.isAssignableFrom(type)) {
            return new java.util.HashSet<>();
        }
        if (List.class.isAssignableFrom(type)) {
            return new java.util.ArrayList<>();
        }
        return null;
    }

    private static Object newInstanceQuietly(Class<?> type) {
        try {
            return type.getDeclaredConstructor().newInstance();
        } catch (Exception | LinkageError e) {
            return null;
        }
    }

    /**
     * Build the application context before the deny-by-default manager is installed.  The
     * URLs are exactly the child JVM's class path, so this is a loader boundary, not an
     * additional filesystem capability.  Failure is harmless: load() still tries the
     * launcher loader below and reports a normal partial path when neither can resolve a
     * class.
     */
    private static void installApplicationLoader() {
        if (applicationLoader != null) {
            return;
        }
        ClassLoader system = ClassLoader.getSystemClassLoader();
        List<URL> urls = new ArrayList<>();
        String classPath = System.getProperty("java.class.path", "");
        for (String entry : classPath.split(java.util.regex.Pattern.quote(
                java.io.File.pathSeparator))) {
            if (entry.isBlank()) {
                continue;
            }
            try {
                urls.add(Path.of(entry).toAbsolutePath().normalize().toUri().toURL());
            } catch (Exception ignored) {
                // A malformed optional entry must not widen the probe or abort other entries.
            }
        }
        if (urls.isEmpty()) {
            applicationLoader = system;
            return;
        }
        try {
            URLClassLoader loader = new URLClassLoader(
                    urls.toArray(URL[]::new), system);
            applicationLoader = loader;
            Thread.currentThread().setContextClassLoader(loader);
        } catch (RuntimeException ignored) {
            applicationLoader = system;
        }
    }

    /** 类加载统一走显式应用 classloader：探针自身解析不触发 Class#forName canary。 */
    private static Class<?> load(String name) throws ClassNotFoundException {
        ClassLoader context = applicationLoader != null
                ? applicationLoader : Thread.currentThread().getContextClassLoader();
        ClassLoader system = ClassLoader.getSystemClassLoader();
        ClassNotFoundException first = null;
        if (context != null) {
            try {
                return context.loadClass(name);
            } catch (ClassNotFoundException failure) {
                first = failure;
            }
        }
        if (system != null && system != context) {
            try {
                return system.loadClass(name);
            } catch (ClassNotFoundException failure) {
                if (first == null) {
                    first = failure;
                }
            }
        }
        boolean resourcePresent = false;
        String resourceName = name.replace('.', '/') + ".class";
        if (context != null && context.getResource(resourceName) != null) {
            resourcePresent = true;
        } else if (system != null && system.getResource(resourceName) != null) {
            resourcePresent = true;
        }
        throw new ClassNotFoundException(name + " [resource="
                + (resourcePresent ? "present" : "missing") + "]", first);
    }

    private static Field findField(Class<?> cls, String name) {
        for (Class<?> c = cls; c != null; c = c.getSuperclass()) {
            try {
                return c.getDeclaredField(name);
            } catch (NoSuchFieldException ignored) {
            }
        }
        return null;
    }

    private static Method findMethod(Class<?> cls, String name) {
        return findMethod(cls, name, "");
    }

    /**
     * Entry descriptors disambiguate overloaded callbacks; old callers may omit one.
     *
     * <p>When a descriptor is available, resolve one exact JVM signature instead of asking
     * reflection for every method on a framework class. The latter eagerly resolves unrelated
     * optional parameter/return types and turns a usable entry point into a false
     * ClassNotFound/NoClassDefFound result when a fat jar intentionally omits an optional
     * integration. The descriptor path also avoids running target code.</p>
     */
    static Method findMethod(Class<?> cls, String name, String descriptor) {
        if (descriptor != null && !descriptor.isEmpty()) {
            Class<?>[] parameters = parameterTypes(descriptor);
            if (parameters != null) {
                try {
                    Method publicMethod = cls.getMethod(name, parameters);
                    if (descriptor.equals(methodDescriptor(publicMethod))) {
                        return publicMethod;
                    }
                } catch (NoSuchMethodException | LinkageError ignored) {
                    // Fall through to declaring-class lookup; a non-public callback may be
                    // inherited through an implementation class rather than exposed publicly.
                }
                for (Class<?> current = cls; current != null; current = current.getSuperclass()) {
                    try {
                        Method method = current.getDeclaredMethod(name, parameters);
                        return descriptor.equals(methodDescriptor(method)) ? method : null;
                    } catch (NoSuchMethodException ignored) {
                    } catch (LinkageError ignored) {
                        return null;
                    }
                }
                return null;
            }
            // Malformed/unresolvable descriptors are not a reason to scan every method.
            return null;
        }
        try {
            for (Method m : cls.getMethods()) {
                if (m.getName().equals(name)) {
                    return m;
                }
            }
            for (Class<?> current = cls; current != null; current = current.getSuperclass()) {
                for (Method m : current.getDeclaredMethods()) {
                    if (m.getName().equals(name)) {
                        return m;
                    }
                }
            }
        } catch (LinkageError ignored) {
            // Legacy callers without a descriptor cannot safely disambiguate a method when
            // reflection cannot resolve unrelated signatures; report partial instead.
        }
        return null;
    }

    /** Resolve only descriptor parameter types; target methods are not initialized. */
    private static Class<?>[] parameterTypes(String descriptor) {
        if (descriptor.length() < 3 || descriptor.charAt(0) != '(') {
            return null;
        }
        List<Class<?>> result = new ArrayList<>();
        int[] cursor = {1};
        try {
            while (cursor[0] < descriptor.length() && descriptor.charAt(cursor[0]) != ')') {
                result.add(descriptorType(descriptor, cursor));
            }
            if (cursor[0] >= descriptor.length() || descriptor.charAt(cursor[0]) != ')') {
                return null;
            }
            cursor[0]++;
            descriptorType(descriptor, cursor); // validate the return type as well
            return cursor[0] == descriptor.length()
                    ? result.toArray(Class<?>[]::new) : null;
        } catch (ClassNotFoundException | LinkageError | RuntimeException ignored) {
            return null;
        }
    }

    private static Class<?> descriptorType(String descriptor, int[] cursor)
            throws ClassNotFoundException {
        if (cursor[0] >= descriptor.length()) {
            throw new IllegalArgumentException("truncated descriptor");
        }
        char marker = descriptor.charAt(cursor[0]++);
        return switch (marker) {
            case 'B' -> byte.class;
            case 'C' -> char.class;
            case 'D' -> double.class;
            case 'F' -> float.class;
            case 'I' -> int.class;
            case 'J' -> long.class;
            case 'S' -> short.class;
            case 'Z' -> boolean.class;
            case 'V' -> void.class;
            case 'L' -> {
                int end = descriptor.indexOf(';', cursor[0]);
                if (end < 0) {
                    throw new IllegalArgumentException("unterminated object type");
                }
                String binaryName = descriptor.substring(cursor[0], end).replace('/', '.');
                cursor[0] = end + 1;
                yield load(binaryName);
            }
            case '[' -> {
                Class<?> component = descriptorType(descriptor, cursor);
                if (component == void.class) {
                    throw new IllegalArgumentException("void array");
                }
                yield java.lang.reflect.Array.newInstance(component, 0).getClass();
            }
            default -> throw new IllegalArgumentException("unknown descriptor type: " + marker);
        };
    }

    private static void invokeEntry(Method method, Object receiver, boolean source)
            throws Exception {
        invokeEntry(method, receiver, source, null, null);
    }

    private static void invokeEntry(Method method, Object receiver, boolean source,
                                    SourceTrigger sourceTrigger, Object triggerInstance)
            throws Exception {
        method.setAccessible(true);
        Class<?>[] types = method.getParameterTypes();
        if (!source && types.length == 0) {
            method.invoke(receiver);
            return;
        }
        if (!source && types.length == 1 && types[0] == String.class) {
            method.invoke(receiver, "echo CHAIN_OK");
            return;
        }
        if (!source) {
            // Preserve the previous DIRECT contract: unsupported attacker-controlled method
            // parameters are reported as PARTIAL rather than guessed silently.
            method.invoke(receiver);
            return;
        }
        Object[] arguments = new Object[types.length];
        byte[] adaptedPayload = sourcePayload(sourceTrigger, triggerInstance);
        for (int i = 0; i < types.length; i++) {
            arguments[i] = sourceValue(types[i], sourceTrigger, triggerInstance, adaptedPayload);
        }
        method.invoke(receiver, arguments);
    }

    private static SourceTrigger parseSourceTrigger(String encoded) {
        if (encoded == null || encoded.isBlank()) {
            return null;
        }
        String[] parts = encoded.split("\\|", -1);
        if (parts.length < 6 || parts[0].isBlank() || parts[1].isBlank()
                || parts[2].isBlank() || parts[3].isBlank() || parts[4].isBlank()) {
            return null;
        }
        return new SourceTrigger(parts[0], parts[1], parts[2], parts[3], parts[4], parts[5],
                parts.length > 6 ? parts[6] : "",
                parts.length > 7 ? parts[7] : "");
    }

    /**
     * Build a bounded in-memory callback collection for an ObjectInputStream source.
     * ArrayList serialization does not invoke the contained value's callback while the
     * probe is preparing the bytes; the callback runs only when the target source iterates
     * the deserialized collection, so the source entry frame participates in canary proof.
     */
    private static Object sourceValue(Class<?> type, SourceTrigger trigger,
                                      Object triggerInstance, byte[] adaptedPayload)
            throws IOException {
        if (adaptedPayload != null && trigger != null && triggerInstance != null) {
            byte[] payload = adaptedPayload;
            if (type == String.class || type == CharSequence.class) {
                return java.util.Base64.getEncoder().encodeToString(payload);
            }
            if (type == byte[].class) {
                return payload;
            }
            if (java.io.InputStream.class.isAssignableFrom(type)) {
                return new java.io.ByteArrayInputStream(payload);
            }
            if (java.io.Reader.class.isAssignableFrom(type)) {
                return new java.io.StringReader(
                        java.util.Base64.getEncoder().encodeToString(payload));
            }
            if ("com.esotericsoftware.kryo.io.Input".equals(type.getName())) {
                Object input = kryoInput(type, payload);
                if (input != null) {
                    return input;
                }
            }
            if (type.isInstance(triggerInstance)
                    || java.util.Collection.class.isAssignableFrom(type)) {
                return new SourceTriggerCollection(triggerInstance, trigger.callbackKind());
            }
        }
        return sourceValue(type);
    }

    private static byte[] sourcePayload(SourceTrigger trigger, Object triggerInstance)
            throws IOException {
        if (trigger == null || triggerInstance == null) {
            return null;
        }
        if (isObjectInputSource(trigger)) {
            return serializeSourceCollection(triggerInstance, trigger.callbackKind());
        }
        if (isKryoSource(trigger)) {
            return serializeKryoSource(triggerInstance, trigger.callbackKind());
        }
        return null;
    }

    private static boolean isKryoSource(SourceTrigger trigger) {
        return trigger != null
                && trigger.sourceOwner().startsWith("com/esotericsoftware/kryo/")
                && trigger.sourceMethod().startsWith("read");
    }

    /**
     * Match inherited ObjectInputStream reads as well as the base-class call owner.  The
     * scanner may preserve a custom stream subclass as the source owner; using the loaded
     * type relationship here keeps the runtime adapter aligned with the static hierarchy
     * without naming any framework or target class.
     */
    private static boolean isObjectInputSource(SourceTrigger trigger) {
        if (trigger == null || !("readObject".equals(trigger.sourceMethod())
                || "readUnshared".equals(trigger.sourceMethod())
                || "readFields".equals(trigger.sourceMethod()))) {
            return false;
        }
        String owner = trigger.sourceOwner();
        if ("java/io/ObjectInputStream".equals(owner)) {
            return true;
        }
        try {
            return java.io.ObjectInputStream.class.isAssignableFrom(
                    load(owner.replace('/', '.')));
        } catch (ClassNotFoundException | LinkageError | RuntimeException ignored) {
            return false;
        }
    }

    private static Object kryoInput(Class<?> type, byte[] payload) {
        try {
            Constructor<?> constructor = type.getConstructor(java.io.InputStream.class);
            return constructor.newInstance(new java.io.ByteArrayInputStream(payload));
        } catch (ReflectiveOperationException | LinkageError | RuntimeException ignored) {
            return null;
        }
    }

    private static byte[] serializeSourceCollection(Object value, String callbackKind)
            throws IOException {
        SandboxSecurityManager.beginSerializationBootstrap();
        try {
            java.io.ByteArrayOutputStream bytes = new java.io.ByteArrayOutputStream();
            try (ObjectOutputStream output = new ObjectOutputStream(bytes)) {
                output.writeObject(new SourceTriggerCollection(value, callbackKind));
            }
            byte[] payload = bytes.toByteArray();
            if (payload.length > 8 * 1024 * 1024) {
                throw new IOException("source probe payload exceeds limit");
            }
            return payload;
        } finally {
            SandboxSecurityManager.endSerializationBootstrap();
        }
    }

    /** Serialize an inert container through the target's Kryo implementation. */
    private static byte[] serializeKryoSource(Object value, String callbackKind)
            throws IOException {
        boolean bootstrap = false;
        try {
            SandboxSecurityManager.beginSerializationBootstrap();
            bootstrap = true;
            SandboxSecurityManager.beginSourceAdapter();
            warmKryoRuntime();
            Class<?> kryoType = load("com.esotericsoftware.kryo.Kryo");
            Object kryo = kryoType.getDeclaredConstructor().newInstance();
            invokeIfPresent(kryoType, kryo, "setReferences", boolean.class, true);
            invokeIfPresent(kryoType, kryo, "setRegistrationRequired", boolean.class, false);
            try {
                Class<?> strategyType = load("org.objenesis.strategy.StdInstantiatorStrategy");
                Object strategy = strategyType.getDeclaredConstructor().newInstance();
                Method setter = kryoType.getMethod("setInstantiatorStrategy",
                        load("org.objenesis.strategy.InstantiatorStrategy"));
                setter.invoke(kryo, strategy);
            } catch (ClassNotFoundException | NoSuchMethodException ignored) {
                // Optional Objenesis is not required for the bounded default serializer.
            }

            Object root = kryoSourceRoot(value, callbackKind);
            java.io.ByteArrayOutputStream bytes = new java.io.ByteArrayOutputStream();
            Class<?> outputType = load("com.esotericsoftware.kryo.io.Output");
            Object output = outputType.getConstructor(java.io.OutputStream.class)
                    .newInstance(bytes);
            Method writer = kryoType.getMethod("writeClassAndObject", outputType, Object.class);
            writer.invoke(kryo, output, root);
            try {
                outputType.getMethod("flush").invoke(output);
            } finally {
                outputType.getMethod("close").invoke(output);
            }
            byte[] payload = bytes.toByteArray();
            if (payload.length > 8 * 1024 * 1024) {
                throw new IOException("kryo probe payload exceeds limit");
            }
            return payload;
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause() == null ? e : e.getCause();
            throw new IOException("kryo source adapter failed: "
                    + cause.getClass().getSimpleName(), cause);
        } catch (ReflectiveOperationException | LinkageError | RuntimeException e) {
            throw new IOException("kryo source adapter failed: "
                    + e.getClass().getSimpleName(), e);
        } finally {
            SandboxSecurityManager.endSourceAdapter();
            if (bootstrap) {
                SandboxSecurityManager.endSerializationBootstrap();
            }
        }
    }

    /**
     * Kryo 4 probes optional java.time serializers during construction. Initialize those
     * JDK classes from the trusted probe frame so lambda-accessor bootstrap does not inherit
     * target-library frames and get denied by the child sandbox.
     */
    private static void warmKryoRuntime() {
        String[] optionalTypes = {
                "java.time.Duration", "java.time.Instant", "java.time.LocalDate",
                "java.time.LocalTime", "java.time.LocalDateTime", "java.time.ZoneOffset",
                "java.time.ZoneId", "java.time.OffsetTime", "java.time.OffsetDateTime",
                "java.time.ZonedDateTime", "java.time.Year", "java.time.YearMonth",
                "java.time.MonthDay", "java.time.Period"
        };
        for (String name : optionalTypes) {
            try {
                Class.forName(name, true, null);
            } catch (ClassNotFoundException | LinkageError | RuntimeException ignored) {
                // Optional JDK type unavailable on an older target runtime.
            }
        }
        // Kryo asks Class for a missing/public constructor while selecting a field
        // serializer. That error path first links Class.methodToString's string-concat
        // bootstrap; link it from the trusted probe frame before Kryo enters the stack.
        try {
            Object.class.getDeclaredConstructor(String.class);
        } catch (NoSuchMethodException ignored) {
            // Expected: this call exists only to initialize the JDK reflection path.
        }
    }

    private static void invokeIfPresent(Class<?> owner, Object target, String method,
                                        Class<?> parameter, Object value)
            throws ReflectiveOperationException {
        try {
            owner.getMethod(method, parameter).invoke(target, value);
        } catch (NoSuchMethodException ignored) {
            // Kryo minor versions may omit an optional tuning setter.
        }
    }

    private static Object kryoSourceRoot(Object value, String callbackKind) throws IOException {
        return switch (callbackKind) {
            case "compare" -> {
                if (!(value instanceof java.util.Comparator<?> comparator)) {
                    yield new java.util.ArrayList<>(java.util.List.of(value));
                }
                @SuppressWarnings("unchecked")
                java.util.Comparator<Object> ordered = (java.util.Comparator<Object>) comparator;
                java.util.TreeMap<Object, Object> map = new java.util.TreeMap<>(ordered);
                map.put("CHAIN_LEFT", "left");
                map.put("CHAIN_RIGHT", "right");
                yield map;
            }
            case "compareTo" -> {
                if (!(value instanceof Comparable<?>)) {
                    yield new java.util.ArrayList<>(java.util.List.of(value));
                }
                java.util.TreeSet<Object> set = new java.util.TreeSet<>();
                Object peer = newInstanceQuietly(value.getClass());
                if (peer != null) {
                    set.add(peer);
                }
                set.add(value);
                yield set;
            }
            case "hashCode", "equals" -> rawHashMap(value);
            default -> new java.util.ArrayList<>(java.util.List.of(value));
        };
    }

    /** Build one HashMap entry without calling the target key's hashCode in the probe. */
    private static Object rawHashMap(Object key) throws IOException {
        try {
            Object unsafe = probeUnsafe();
            Class<?> unsafeType = unsafe.getClass();
            Class<?> nodeType;
            try {
                nodeType = Class.forName("java.util.HashMap$Node", false, null);
            } catch (ClassNotFoundException unavailable) {
                nodeType = Class.forName("java.util.HashMap$Entry", false, null);
            }
            Object node = invokeUnsafe(unsafeType, unsafe, "allocateInstance",
                    new Class<?>[]{Class.class}, new Object[]{nodeType});
            unsafePutInt(unsafeType, unsafe, nodeType, node, "hash", 0);
            unsafePutObject(unsafeType, unsafe, nodeType, node, "key", key);
            unsafePutObject(unsafeType, unsafe, nodeType, node, "value", "CHAIN_OK");
            unsafePutObject(unsafeType, unsafe, nodeType, node, "next", null);

            java.util.HashMap<Object, Object> map = new java.util.HashMap<>();
            Object table = java.lang.reflect.Array.newInstance(nodeType, 1);
            java.lang.reflect.Array.set(table, 0, node);
            unsafePutObject(unsafeType, unsafe, java.util.HashMap.class, map, "table", table);
            unsafePutInt(unsafeType, unsafe, java.util.HashMap.class, map, "size", 1);
            return map;
        } catch (ReflectiveOperationException | LinkageError | RuntimeException e) {
            throw new IOException("hash callback adapter unavailable: "
                    + e.getClass().getSimpleName(), e);
        }
    }

    private static Object probeUnsafe() throws ReflectiveOperationException {
        Class<?> unsafeType = ClassLoader.getSystemClassLoader().loadClass("sun.misc.Unsafe");
        Field singleton = unsafeType.getDeclaredField("theUnsafe");
        singleton.setAccessible(true);
        return singleton.get(null);
    }

    private static Object invokeUnsafe(Class<?> owner, Object target, String method,
                                       Class<?>[] types, Object[] arguments)
            throws ReflectiveOperationException {
        return owner.getMethod(method, types).invoke(target, arguments);
    }

    private static void unsafePutObject(Class<?> unsafeType, Object unsafe, Class<?> owner,
                                        Object target, String fieldName, Object value)
            throws ReflectiveOperationException {
        Field field = findField(owner, fieldName);
        if (field == null) {
            throw new NoSuchFieldException(owner.getName() + "." + fieldName);
        }
        long offset = (Long) unsafeType.getMethod("objectFieldOffset", Field.class)
                .invoke(unsafe, field);
        unsafeType.getMethod("putObject", Object.class, long.class, Object.class)
                .invoke(unsafe, target, offset, value);
    }

    private static void unsafePutInt(Class<?> unsafeType, Object unsafe, Class<?> owner,
                                     Object target, String fieldName, int value)
            throws ReflectiveOperationException {
        Field field = findField(owner, fieldName);
        if (field == null) {
            throw new NoSuchFieldException(owner.getName() + "." + fieldName);
        }
        long offset = (Long) unsafeType.getMethod("objectFieldOffset", Field.class)
                .invoke(unsafe, field);
        unsafeType.getMethod("putInt", Object.class, long.class, int.class)
                .invoke(unsafe, target, offset, value);
    }

    /**
     * Complete a callback's first downstream object from the static semantic edge. This is
     * structural: a wrapper with a Class slot and an Object slot receives a probe-owned bean,
     * never a target TemplatesImpl/command/native object.
     */
    private static void prepareSourceTrigger(SourceTrigger trigger, Object triggerInstance) {
        if (trigger.downstreamOwner() == null || trigger.downstreamOwner().isBlank()) {
            return;
        }
        try {
            Class<?> downstreamType = load(trigger.downstreamOwner().replace('/', '.'));
            if (downstreamType.isInterface() || Modifier.isAbstract(downstreamType.getModifiers())
                    || !java.io.Serializable.class.isAssignableFrom(downstreamType)) {
                return;
            }
            Object downstream = newInstance(downstreamType, true);
            if (downstream == null) {
                return;
            }
            setReferenceField(triggerInstance, downstream);
            setClassField(triggerInstance, downstreamType);
            configureProbeBean(downstream);
        } catch (Exception | LinkageError ignored) {
            // Optional source adaptation must remain partial rather than widening access.
        }
    }

    private static void configureProbeBean(Object wrapper) {
        try {
            setClassField(wrapper, ProbeBean.class);
            setReferenceField(wrapper, new ProbeBean());
        } catch (RuntimeException | LinkageError ignored) {
            // The wrapper may not be a bean-style two-slot adapter.
        }
    }

    private static boolean setReferenceField(Object target, Object value) {
        if (target == null || value == null) {
            return false;
        }
        String[] preferred = {"_obj", "object", "delegate", "target", "value", "inner"};
        for (String name : preferred) {
            Field field = findField(target.getClass(), name);
            if (field != null && field.getType().isInstance(value) && setField(field, target, value)) {
                return true;
            }
        }
        for (Class<?> current = target.getClass(); current != null; current = current.getSuperclass()) {
            for (Field field : current.getDeclaredFields()) {
                if (!Modifier.isStatic(field.getModifiers())
                        && field.getType().isInstance(value)
                        && setField(field, target, value)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean setClassField(Object target, Class<?> value) {
        if (target == null || value == null) {
            return false;
        }
        for (Class<?> current = target.getClass(); current != null; current = current.getSuperclass()) {
            for (Field field : current.getDeclaredFields()) {
                if (!Modifier.isStatic(field.getModifiers()) && field.getType() == Class.class
                        && setField(field, target, value)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean setField(Field field, Object target, Object value) {
        try {
            field.setAccessible(true);
            field.set(target, value);
            return true;
        } catch (IllegalAccessException | RuntimeException | LinkageError ignored) {
            return false;
        }
    }

    /** Probe-owned, serializable bean: only a harmless getter can be called by a wrapper. */
    public static final class ProbeBean implements java.io.Serializable {
        private static final long serialVersionUID = 1L;

        public ProbeBean() {
        }

        public String getValue() {
            return "CHAIN_OK";
        }
    }

    /** Initialize JDK object-stream bootstrap code before a target source enters the stack. */
    private static void warmObjectInputStream() {
        try (java.io.ObjectInputStream input = new java.io.ObjectInputStream(
                new java.io.ByteArrayInputStream(new byte[0]))) {
            // The empty stream is intentional: construction initializes the JDK machinery,
            // then EOF is ignored without reading target-controlled bytes.
        } catch (IOException ignored) {
            // EOF is the expected result for the bounded bootstrap stream.
        }
    }

    /**
     * Initialize JDK protocol machinery from the trusted probe frame.  Some JDK classes
     * lazily link lambda accessors on their first real call; if that happens while a target
     * bean setter is on the stack, the deny-by-default manager correctly sees the target as
     * the first non-platform caller and blocks before the sink canary.  These initializers
     * are side-effect-free class linking only: they do not create a context, open a socket,
     * read attacker bytes, or load native code.
     */
    private static void warmRuntimeSupport(String sinkClass) {
        warmObjectInputStream();
        if (sinkClass == null) {
            return;
        }
        if (sinkClass.startsWith("javax.naming.") || sinkClass.startsWith("com.sun.naming.")) {
            warmClass("javax.naming.InitialContext");
            warmClass("com.sun.naming.internal.VersionHelper");
            warmClass("com.sun.naming.internal.ResourceManager");
            try {
                // The public constructor is the portable way to exercise the JDK's
                // internal property-reader lambdas; reflective access to com.sun.* is
                // intentionally not required (and is denied by strong modules).
                new javax.naming.InitialContext().close();
            } catch (javax.naming.NamingException | RuntimeException ignored) {
                // No provider is expected in the isolated probe. Initialization itself is
                // the warmup; provider lookup must never be retried with relaxed access.
            }
        }
    }

    private static void warmClass(String name) {
        try {
            Class.forName(name, true, null);
        } catch (ClassNotFoundException | LinkageError | RuntimeException ignored) {
            // Optional JDK implementation detail; a failed warmup must remain a normal
            // partial verification result rather than widening the sandbox.
        }
    }

    /** Serializable adapter that models the callback edge without a weaponized payload. */
    private static final class SourceTriggerCollection extends ArrayList<Object> {
        private final String callbackKind;

        private SourceTriggerCollection(Object value, String callbackKind) {
            this.callbackKind = callbackKind;
            super.add(value);
        }

        @Override
        public java.util.Iterator<Object> iterator() {
            java.util.Iterator<Object> delegate = super.iterator();
            return new java.util.Iterator<>() {
                private boolean triggered;

                @Override
                public boolean hasNext() {
                    return delegate.hasNext();
                }

                @Override
                public Object next() {
                    Object value = delegate.next();
                    if (!triggered) {
                        triggered = true;
                        invokeCallback(value, callbackKind);
                    }
                    return value;
                }

                @Override
                public void remove() {
                    delegate.remove();
                }
            };
        }

        private static void invokeCallback(Object value, String kind) {
            if (value == null) {
                return;
            }
            switch (kind) {
                case "hashCode" -> value.hashCode();
                case "toString" -> value.toString();
                case "equals" -> value.equals(new Object());
                case "compareTo" -> {
                    if (value instanceof Comparable<?> comparable) {
                        @SuppressWarnings("unchecked")
                        Comparable<Object> ordered = (Comparable<Object>) comparable;
                        ordered.compareTo(value);
                    }
                }
                case "compare" -> {
                    if (value instanceof java.util.Comparator<?> comparator) {
                        @SuppressWarnings("unchecked")
                        java.util.Comparator<Object> ordered =
                                (java.util.Comparator<Object>) comparator;
                        ordered.compare("CHAIN_LEFT", "CHAIN_RIGHT");
                    }
                }
                default -> {
                }
            }
        }
    }

    /** Safe, bounded source-host input; it never reads the network or the host filesystem. */
    private static Object sourceValue(Class<?> type) {
        if (type == String.class || type == CharSequence.class) {
            return "{}";
        }
        if (type == Object.class) {
            // Keep source-boundary probes non-null and in-memory. A map is a generic object
            // value accepted by many bean/data-binding APIs; it carries no host capability.
            return new java.util.LinkedHashMap<>();
        }
        if (type == byte[].class) {
            return "{}".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        }
        if (type == char[].class) {
            return "{}".toCharArray();
        }
        if (java.io.InputStream.class.isAssignableFrom(type)) {
            return new java.io.ByteArrayInputStream(
                    "{}".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        }
        if (java.io.Reader.class.isAssignableFrom(type)) {
            return new java.io.StringReader("{}");
        }
        if (java.io.OutputStream.class.isAssignableFrom(type)) {
            return new java.io.ByteArrayOutputStream();
        }
        if (java.util.Map.class.isAssignableFrom(type)) {
            return new java.util.HashMap<>();
        }
        if (java.util.Set.class.isAssignableFrom(type)) {
            return new java.util.HashSet<>();
        }
        if (java.util.List.class.isAssignableFrom(type)) {
            return new java.util.ArrayList<>();
        }
        if (type == Class.class) {
            return Object.class;
        }
        if (type.isArray()) {
            return java.lang.reflect.Array.newInstance(type.getComponentType(), 0);
        }
        if (type.isPrimitive()) {
            return defaultValue(type);
        }
        if (type.isEnum()) {
            Object[] values = type.getEnumConstants();
            return values != null && values.length > 0 ? values[0] : null;
        }
        return null;
    }

    /**
     * Bounded shape for a reflective chain whose target class/name is statically unknown.
     * The shape is derived solely from the reported sink: method name, an inert sink
     * receiver, and an inert string argument. It is intentionally limited to open
     * reference/array fields and never invokes a target constructor.
     */
    private static Object unresolvedReflectiveShape(Class<?> fieldType, String sinkClassName,
                                                    String sinkMethod, boolean serializationSemantics) {
        if (!isOpenReference(fieldType) || sinkMethod == null || sinkMethod.isBlank()) {
            return null;
        }
        Object receiver = null;
        try {
            Class<?> sinkClass = load(sinkClassName);
            if (!sinkClass.isInterface() && !Modifier.isAbstract(sinkClass.getModifiers())
                    && java.io.Serializable.class.isAssignableFrom(sinkClass)) {
                receiver = allocateWithoutConstructor(sinkClass);
            }
        } catch (Throwable ignored) {
            // A missing/abstract sink receiver leaves the probe partial; no constructor
            // fallback is allowed here because this branch is specifically safety-bound.
        }
        Class<?> component = fieldType.isArray() ? fieldType.getComponentType() : Object.class;
        if (component.isPrimitive() || !component.isAssignableFrom(String.class)
                || (receiver != null && !component.isInstance(receiver))) {
            return null;
        }
        Object shape = java.lang.reflect.Array.newInstance(component, 3);
        try {
            java.lang.reflect.Array.set(shape, 0, sinkMethod);
            if (receiver != null) {
                java.lang.reflect.Array.set(shape, 1, receiver);
            }
            java.lang.reflect.Array.set(shape, 2, "CHAIN_OK");
        } catch (IllegalArgumentException ignored) {
            return null;
        }
        return fieldType.isInstance(shape) ? shape : null;
    }

    private static boolean isOpenReference(Class<?> type) {
        return type == Object.class || type == java.io.Serializable.class
                || (type.isArray() && !type.getComponentType().isPrimitive());
    }

    private static String methodDescriptor(Method method) {
        StringBuilder descriptor = new StringBuilder("(");
        for (Class<?> parameter : method.getParameterTypes()) {
            descriptor.append(typeDescriptor(parameter));
        }
        return descriptor.append(')').append(typeDescriptor(method.getReturnType())).toString();
    }

    private static String typeDescriptor(Class<?> type) {
        if (type.isArray()) {
            return type.getName().replace('.', '/');
        }
        if (!type.isPrimitive()) {
            return "L" + type.getName().replace('.', '/') + ";";
        }
        return switch (type.getName()) {
            case "void" -> "V";
            case "boolean" -> "Z";
            case "byte" -> "B";
            case "char" -> "C";
            case "short" -> "S";
            case "int" -> "I";
            case "long" -> "J";
            case "float" -> "F";
            case "double" -> "D";
            default -> "V";
        };
    }

    private static String formatDiagnosticStack(Throwable top) {
        StringBuilder out = new StringBuilder(512);
        int depth = 0;
        for (Throwable t = top; t != null && depth < 6; t = t.getCause(), depth++) {
            out.append(t).append('\n');
            for (StackTraceElement frame : t.getStackTrace()) {
                out.append("\tat ").append(frame).append('\n');
            }
        }
        return out.toString();
    }
}
