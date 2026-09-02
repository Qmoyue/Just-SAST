package io.just.sast.verify;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
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
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
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
 *   SINK_BLOCKED — canary 在 declaringClass == sinkClass && methodName == sinkMethod 的边界抛出
 *                    （栈帧级全等匹配：子串匹配会把 java.lang.RuntimeException 误判为
 *                    java.lang.Runtime，已废除）
 *   PARTIAL_PATH — 异常来自链中间环节（类型不匹配/空指针/入口方法缺失），sink 未到达
 *   EXECUTED — 入口方法真实调用且正常返回（无异常完成）
 */
public final class ChainVerifyProbe {

    private static final int MAX_GRAPH_OBJECTS = 128;
    private static final int MAX_PROXY_INTERFACES = 64;
    private static final int MAX_PROXY_METHODS = 128;
    /** Parent/child result channel version. Plain target stdout is never a result channel. */
    private static final String PROTOCOL_PREFIX = "JUST_VERIFY_V1:";
    private static String protocolToken = "";
    private static String protocolRunId = "";
    private static String protocolChainFingerprint = "";
    private static String protocolSinkFingerprint = "";
    private static String protocolNonce = "";
    private static String protocolArtifactFingerprint = "";
    /** Capture adapter configuration before any target class is loaded or can mutate properties. */
    private static String safeSinkMode = "BOUNDARY";
    private static String safeSinkCategory = "";
    private static String safeSinkDisposition = "CANARY_BOUNDARY";
    private static String safeSinkKind = "UNSUPPORTED";
    private static String safeSinkPolicyDigest = "";
    private static String safeIsolationPolicyDigest = "";
    /** Captured before target code loads; the parent rejects an unknown proof protocol. */
    private static String safeAttestationVersion = "";
    /** Agent-owned attestation for the separate real-sink event gate. */
    private static boolean executionGateReady;
    private static String nativeFixtureDigest = "none";
    private static String safeScratchRoot = ".";
    private static String safeNativeScratchRoot = "";
    /** Captured before target code loads; SAFE_REAL may start only this fixed executable. */
    private static Path safeJavaExecutable;
    /** One-time parent secret and probe-owned authenticated result file. */
    private static final String RESULT_CHANNEL_PREFIX = "JUST_VERIFY_RESULT_V1:";
    private static final int RESULT_SECRET_HEX_LENGTH = 64;
    private static String resultChannelSecret = "";
    private static OutputStream resultChannel;
    private static boolean resultChannelBroken;
    /** Whether the child installed the kernel filesystem policy requested by its runner. */
    private static boolean landlockReady = true;
    /** Set only when the declarative graph used the probe-owned reflective proxy adapter. */
    private static boolean graphAdapterUsed;
    /**
     * The launcher system loader is normally sufficient, but fat JAR/WAR verification has
     * class-path entries materialized immediately before the child is started.  Keep an
     * explicit read-only application loader as the context loader so lookup does not depend on
     * launcher-specific wildcard/manifest behavior. Its parent is the platform loader,
     * preserving JDK classes without exposing the scanner application loader to target code.
     * The verifier loader contains the probe jar and target/dependency entries itself.
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
        protocolToken = args.length > 5 ? args[5] : "";
        protocolRunId = safeProperty("just.verify.run-id", "");
        protocolChainFingerprint = safeProperty("just.verify.chain-fingerprint", "");
        protocolSinkFingerprint = safeProperty("just.verify.sink-fingerprint", "");
        protocolNonce = safeProperty("just.verify.nonce", "");
        protocolArtifactFingerprint = safeProperty("just.verify.artifact-fingerprint", "");
        graphAdapterUsed = false;
        initializeResultChannel();
        if (!awaitIsolationReady()) {
            emit("SANDBOX_UNAVAILABLE: isolation-ready-timeout-or-missing");
            System.exit(3);
            return;
        }
        if (!strictOsAttestation()) {
            emit("SANDBOX_UNAVAILABLE: OS_ATTESTATION_FAILED");
            System.exit(3);
            return;
        }
        if (Boolean.parseBoolean(safeProperty("just.verify.landlock-required", "false"))) {
            landlockReady = installLandlock();
            if (!landlockReady) {
                emit("SANDBOX_UNAVAILABLE: LANDLOCK_ATTESTATION_FAILED");
                System.exit(3);
                return;
            }
        }
        // 解析链跳
        List<String[]> fieldLinks = parseFieldLinks(args.length > 1 ? args[1] : "");

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
        GraphPlan graphPlan = parseGraphPlan(args.length > 6 ? args[6] : "");
        if (args.length > 6 && args[6] != null && !args[6].isBlank() && graphPlan == null) {
            emit("PARTIAL_PATH: construction-plan-invalid");
            System.exit(0);
            return;
        }
        // These values are launcher-owned configuration. Capture them while only Just's probe
        // classes have been loaded; target code must not be able to widen a later adapter call
        // by replacing mutable System properties.
        safeSinkMode = safeProperty("just.verify.sink-mode", "BOUNDARY");
        safeSinkCategory = safeProperty("just.verify.sink-category", "");
        safeSinkDisposition = safeProperty("just.verify.sink-disposition", "CANARY_BOUNDARY");
        safeSinkKind = safeProperty("just.verify.real-kind", "UNSUPPORTED");
        safeSinkPolicyDigest = safeProperty("just.verify.sink-policy-digest", "");
        safeIsolationPolicyDigest = safeProperty("just.verify.isolation-policy-digest", "");
        safeAttestationVersion = safeProperty("just.verify.attestation-version", "");
        safeScratchRoot = boundedPathProperty("java.io.tmpdir");
        safeNativeScratchRoot = boundedPathProperty("just.verify.native-scratch");
        safeJavaExecutable = locateSafeJavaExecutable();
        if ("SAFE_REAL".equals(safeSinkMode)
                && !"OS_STRICT".equals(safeProperty("just.verify.isolation-level", "NONE"))) {
            emit("SANDBOX_UNAVAILABLE: SAFE_REAL_REQUIRES_OS_STRICT");
            System.exit(3);
            return;
        }

        try {
            installApplicationLoader();
            // JDK 24+ has no supported Security Manager boundary.  The parent has already
            // authenticated OS_STRICT before releasing this child; continue without the JVM
            // policy and keep all adapter effects fixed/owned by this probe.  On older JDKs the
            // deny-by-default manager remains a useful defense-in-depth layer.
            if (Runtime.version().feature() < 24) {
                try {
                    SandboxSecurityManager.install(java.nio.file.Path.of(
                            System.getProperty("java.io.tmpdir", ".")));
                } catch (Throwable sandboxFailure) {
                    emit("SANDBOX_UNAVAILABLE: " + sandboxFailure.getClass().getSimpleName());
                    System.exit(3);
                    return;
                }
            }
            // The parent authenticates this marker only after the OS backend has attached to
            // this exact child. Require both the agent-owned canary attestation and its
            // bootstrap identity binding before announcing readiness or loading target code.
            if (protocolToken.isEmpty()
                    || !protocolToken.equals(safeProperty("just.verify.canary-token", ""))) {
                emit("UNTESTABLE: CANARY_AGENT_NOT_READY");
                System.exit(3);
                return;
            }
            executionGateReady = !"SAFE_REAL".equals(safeSinkMode)
                    || io.just.sast.verify.boot.SinkExecutionGate.configured();
            if (!executionGateReady) {
                emit("UNTESTABLE: REAL_SINK_AGENT_NOT_READY");
                System.exit(3);
                return;
            }
            if (!protocolBound()) {
                emit("UNTESTABLE: PROTOCOL_BINDING_NOT_READY");
                System.exit(3);
                return;
            }
            emit("SANDBOX_READY: " + safeProperty("just.verify.backend", "unknown")
                    + "|landlock=" + (Boolean.parseBoolean(
                    safeProperty("just.verify.landlock-required", "false"))
                    ? (landlockReady ? "1" : "0") : "na")
                    + "|attestation=" + safeAttestationVersion);
            // The gate keeps its token in bootstrap memory; do not leave the attestation in the
            // mutable system-properties map where target code could read or replace it.
            System.clearProperty("just.verify.canary-token");
            if ("SAFE_REAL".equals(safeSinkMode)
                    && "NATIVE_FIXTURE".equals(safeSinkKind)
                    && !configureNativeFixtures()) {
                emit("UNTESTABLE: SAFE_NATIVE_FIXTURE_CONFIGURATION_FAILED");
                System.exit(3);
                return;
            }
            // 0. 创建所有类的实例（自底向上）；无无参构造时回退到参数最少的构造器并按类型填默认值。
            //    类加载走 loadClass（非 Class.forName）——探针自身的类解析不得踩中 Class#forName canary
            // Target class initialization can perform a loader/resource lookup before the
            // entry method is invoked. Warm JDK protocol machinery before that first target
            // frame so the sandbox does not mistake lazy JDK linking for target capability use.
            if ("SOURCE".equals(mode)) {
                warmRuntimeSupport(sinkClassDotted);
            } else {
                warmJdkRuntimeLinkage();
            }
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
                    sourceTriggerInstance = newSourceTriggerInstance(sourceTrigger, instances);
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
            // Source adapters serialize the callback receiver after this phase.  A static
            // field-flow edge may point at a non-serializable API helper (for example an
            // ObjectInputStream owner) even though the declared field is Object.  Keeping
            // that helper in the graph would make the bounded adapter fail before the target
            // source is reached; use the inert serializable fallback in that case.
            boolean serializedProbeGraph = serializationSemantics || sourceTrigger != null;
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
                        Object assigned = toInstance;
                        if (serializedProbeGraph && !(assigned instanceof java.io.Serializable)) {
                            assigned = null;
                        }
                        field.set(fromInstance, assigned != null ? assigned
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

            // 2a. Apply rule-declared object shape after ordinary FIELD_FLOW linking.  This
            // lets a fragment express array slots, final fields and a JDK proxy without adding
            // a target/package branch to the probe. Every node is still bounded and allocated
            // without calling a target constructor unless a rule explicitly uses CONSTRUCTOR.
            if (graphPlan != null && !graphPlan.isEmpty()) {
                applyGraphPlan(graphPlan, entryInstance, instances, serializedProbeGraph,
                        unlinkedFields);
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
                                } else if (Map.class.isAssignableFrom(f.getType())
                                        || Set.class.isAssignableFrom(f.getType())
                                        || List.class.isAssignableFrom(f.getType())) {
                                    // Source hosts commonly keep the deserialized value in a
                                    // collection before iterating it.  An empty JDK collection
                                    // is a bounded in-memory default and does not execute a
                                    // target constructor or introduce a capability.
                                    Object container = newCollection(f.getType());
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
                // Field wiring is part of the trusted, inert source adapter. Keep the narrow
                // adapter scope active here as well as during serialization; otherwise the
                // deny-by-default manager rejects setAccessible, leaves _obj as the generic
                // fallback, and the target may quietly return before any callback reaches the
                // canary.
                SandboxSecurityManager.beginSourceAdapter();
                try {
                    prepareSourceTrigger(sourceTrigger, sourceTriggerInstance);
                } finally {
                    SandboxSecurityManager.endSourceAdapter();
                }
            }

            if (!unlinkedFields.isEmpty()) {
                // Keep the count stable for aggregation, but include only a bounded prefix of
                // field reasons so a module-access/type mismatch can be fixed from one report
                // without retaining arbitrary target diagnostics in the parent process.
                int detailLimit = Math.min(8, unlinkedFields.size());
                String detail = String.join(",", unlinkedFields.subList(0, detailLimit));
                emit("PARTIAL_PATH: field-unlinked=" + unlinkedFields.size()
                        + ";details=" + detail);
                System.exit(0);
            }

            // 4. 触发入口（触发忠实：按真实反序列化的触发路径，非直接调用）
            switch (mode) {
                case "TRIGGER_HASH" -> {
                    // hashCode 入口的真实触发：对象作为 HashMap 的 key 被放入
                    new java.util.HashMap<Object, Object>().put(entryInstance, "echo CHAIN_OK");
                    if (reportRealSink(sinkClassDotted, sinkMethod, protocolToken)
                            || reportLatchedCanary(sinkClassDotted, sinkMethod, protocolToken)) return;
                    emit("CONCRETE_REACHED: " + mode);
                    System.exit(0);
                }
                case "TRIGGER_COMPARETO" -> {
                    // TreeSet 的第一次 add 不会比较；先放入同类基准对象，第二次 add
                    // 才会以真实自然排序语义调用 entryInstance.compareTo。
                    java.util.TreeSet<Object> set = new java.util.TreeSet<>();
                    set.add(newInstance(entryCls, serializationSemantics));
                    set.add(entryInstance);
                    if (reportRealSink(sinkClassDotted, sinkMethod, protocolToken)
                            || reportLatchedCanary(sinkClassDotted, sinkMethod, protocolToken)) return;
                    emit("CONCRETE_REACHED: " + mode);
                    System.exit(0);
                }
                case "TRIGGER_COMPARATOR" -> {
                    // Comparator 入口不是 Comparable 入口：把入口对象作为 TreeMap comparator，
                    // 两个不同 key 才会触发 Comparator.compare。
                    if (!(entryInstance instanceof java.util.Comparator<?>)) {
                        emit("PARTIAL_PATH: entry-not-comparator");
                        System.exit(0);
                    }
                    @SuppressWarnings("unchecked")
                    java.util.Comparator<Object> c = (java.util.Comparator<Object>) entryInstance;
                    java.util.TreeMap<Object, Object> map = new java.util.TreeMap<>(c);
                    map.put("CHAIN_LEFT", "left");
                    map.put("CHAIN_RIGHT", "right");
                    if (reportRealSink(sinkClassDotted, sinkMethod, protocolToken)
                            || reportLatchedCanary(sinkClassDotted, sinkMethod, protocolToken)) return;
                    emit("CONCRETE_REACHED: " + mode);
                    System.exit(0);
                }
                case "TRIGGER_CONTAINS" -> {
                    // equals 入口的真实触发：非空集合的 contains 逐元素调用 equals
                    java.util.List<Object> l = new java.util.ArrayList<>();
                    l.add(new Object());
                    l.contains(entryInstance);
                    if (reportRealSink(sinkClassDotted, sinkMethod, protocolToken)
                            || reportLatchedCanary(sinkClassDotted, sinkMethod, protocolToken)) return;
                    emit("CONCRETE_REACHED: " + mode);
                    System.exit(0);
                }
                case "PROXY" -> {
                    if (!java.lang.reflect.InvocationHandler.class.isAssignableFrom(entryCls)) {
                        emit("PARTIAL_PATH: entry-not-handler");
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
                        try (java.io.ObjectInputStream input = new ApplicationObjectInputStream(
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
                        emit("PARTIAL_PATH: entry-method-missing");
                        System.exit(0);
                    }
                    SandboxSecurityManager.beginSerializationBootstrap();
                    try {
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
                    if (reportRealSink(sinkClassDotted, sinkMethod, protocolToken)
                            || reportLatchedCanary(sinkClassDotted, sinkMethod, protocolToken)) return;
                    emit("CONCRETE_REACHED: source-entry-returned");
                    System.exit(0);
                }
                default -> {
                    Method m = selectedEntry != null ? selectedEntry
                            : findMethod(entryCls, entryMethod, "");
                    if (m == null) {
                        // 入口方法在目标类上不可解析：探针无法触发——不是"链执行完成"
                        emit("PARTIAL_PATH: entry-method-missing");
                        System.exit(0);
                    }
                    m.setAccessible(true);
                    boolean graphBootstrap = graphPlan != null && !graphPlan.isEmpty();
                    if (graphBootstrap) {
                        // Jackson/bean metadata may lazily use setAccessible while rendering
                        // a declared POJONode. Keep that compatibility window scoped to this
                        // probe-owned graph trigger; target callbacks remain the first frame
                        // and cannot borrow it.
                        SandboxSecurityManager.beginSerializationBootstrap();
                    }
                    try {
                        invokeEntry(m, entryInstance, false);
                    } finally {
                        if (graphBootstrap) {
                            SandboxSecurityManager.endSerializationBootstrap();
                        }
                    }
                }
            }

            if (reportRealSink(sinkClassDotted, sinkMethod, protocolToken)
                    || reportLatchedCanary(sinkClassDotted, sinkMethod, protocolToken)) return;
            if ("SERIAL".equals(mode) || "PROXY".equals(mode) || isTriggerMode(mode)) {
                emit("CONCRETE_REACHED: " + mode);
            } else {
                emit("EXECUTED");
            }
            System.exit(0);

        } catch (Throwable t) {
            // Reflection and deserialization commonly wrap an instrumented sink error before
            // it reaches this boundary.  The bootstrap canary latch is deliberately checked
            // before inspecting the wrapper cause, so a target catch/unwrap path cannot erase
            // an otherwise valid source-to-sink observation.
            if (reportRealSink(sinkClassDotted, sinkMethod, protocolToken)
                    || reportLatchedCanary(sinkClassDotted, sinkMethod, protocolToken)) return;
            // 优先：sink canary 主动命中（插桩 sink 入口抛出的标记 Error，穿透 gadget 的
            // catch(Exception)）。命中须同时满足：标记 spec == 本链 sink 且栈中存在
            // 链入口方法帧（在 sink 帧之下）——排除探针自身基础设施误踩 sink。
            String marker = markerSpec(t);
            if (marker != null && sameSink(marker, sinkClassDotted, sinkMethod, sinkDescriptor)
                    && entryReached(t, entryClass, entryMethod)) {
                emit("SINK_BLOCKED: " + sinkClassDotted);
                System.err.println("SINK_REACHED: " + sinkClassDotted + "." + sinkMethod
                        + " (canary)");
                System.exit(1);
            }
            // 次选：栈帧级全等匹配（类名 + 方法名），含 cause 链——同样要求入口帧在场
            if (sinkDescriptor.isEmpty() && reachesSink(t, sinkClassDotted, sinkMethod)
                    && entryReached(t, entryClass, entryMethod)) {
                emit("UNTESTABLE: sink-frame-without-canary");
                System.err.println("SINK_REACHED: " + sinkClassDotted + "." + sinkMethod
                        + " without canary (not confirmed)");
                System.exit(0);
            }
            // 链中间环节失败（非 sink）；消息带关键归因（如缺失类名），截断防长链污染输出
            Throwable detailCause = t;
            while (detailCause instanceof InvocationTargetException
                    && detailCause.getCause() != null) {
                detailCause = detailCause.getCause();
            }
            String detail = describeFailure(detailCause);
            String cause = detailCause == t ? ""
                    : " cause=" + detailCause.getClass().getSimpleName();
            emit("PARTIAL_PATH: " + t.getClass().getSimpleName() + cause
                    + (detail != null && !detail.isEmpty() ? ": " + detail.split("\\R")[0].transform(
                        s -> s.length() > 160 ? s.substring(0, 160) : s) : ""));
            System.exit(0); // 正常退出 = 未到达 sink
        }
    }

    private static List<String[]> parseFieldLinks(String encoded) {
        List<String[]> result = new ArrayList<>(); // [fromOwner, fieldName, toClassName]
        if (encoded == null || encoded.isEmpty()) {
            return result;
        }
        if (encoded.startsWith("v2;")) {
            int cursor = 3;
            while (cursor < encoded.length()) {
                String[] values = new String[3];
                for (int i = 0; i < values.length; i++) {
                    int colon = encoded.indexOf(':', cursor);
                    if (colon <= cursor) {
                        return List.of();
                    }
                    int length;
                    try {
                        length = Integer.parseInt(encoded.substring(cursor, colon));
                    } catch (NumberFormatException malformed) {
                        return List.of();
                    }
                    int start = colon + 1;
                    int end = start + length;
                    if (length < 0 || end < start || end > encoded.length()) {
                        return List.of();
                    }
                    values[i] = encoded.substring(start, end);
                    cursor = end;
                }
                result.add(values);
            }
            return result;
        }
        // Compatibility with hand-launched probes and pre-v2 callers.
        for (String hop : encoded.split(",")) {
            int eq = hop.indexOf('=');
            if (eq < 0) continue;
            String left = hop.substring(0, eq);
            String toClass = hop.substring(eq + 1);
            int dot = left.lastIndexOf('.');
            if (dot < 0) continue;
            result.add(new String[]{left.substring(0, dot), left.substring(dot + 1), toClass});
        }
        return result;
    }

    /** A probe-local mirror of ObjectGraphPlan; verify8 stays Java 8 compatible. */
    private enum GraphNodeKind { ALLOCATE, PROXY, REFLECTIVE_PROXY, CONSTRUCTOR }

    private static final class GraphValue {
        private final String kind;
        private final String value;

        private GraphValue(String kind, String value) {
            this.kind = kind;
            this.value = value == null ? "" : value;
        }
    }

    private static final class GraphNode {
        private final String id;
        private final String type;
        private final GraphNodeKind kind;
        private final List<GraphValue> arguments;

        private GraphNode(String id, String type, GraphNodeKind kind, List<GraphValue> arguments) {
            this.id = id;
            this.type = type;
            this.kind = kind;
            this.arguments = arguments;
        }
    }

    private static final class GraphField {
        private final String owner;
        private final String field;
        private final List<GraphValue> values;

        private GraphField(String owner, String field, List<GraphValue> values) {
            this.owner = owner;
            this.field = field;
            this.values = values;
        }
    }

    private static final class GraphPlan {
        private final List<GraphNode> nodes;
        private final List<GraphField> fields;

        private GraphPlan(List<GraphNode> nodes, List<GraphField> fields) {
            this.nodes = nodes;
            this.fields = fields;
        }

        private boolean isEmpty() {
            return nodes.isEmpty() && fields.isEmpty();
        }
    }

    /** Parse the ObjectGraphPlan v1 count/length-prefixed representation. */
    private static GraphPlan parseGraphPlan(String encoded) {
        if (encoded == null || encoded.isEmpty()) {
            return new GraphPlan(List.of(), List.of());
        }
        try {
            GraphCursor cursor = new GraphCursor(encoded);
            if (!cursor.take("v1;")) {
                return null;
            }
            if (!cursor.take('N')) {
                return null;
            }
            int nodeCount = cursor.count();
            if (!cursor.take(';') || nodeCount < 0 || nodeCount > 64) {
                return null;
            }
            List<GraphNode> nodes = new ArrayList<>(nodeCount);
            Set<String> ids = new java.util.HashSet<>();
            for (int i = 0; i < nodeCount; i++) {
                String id = cursor.text();
                String type = cursor.text();
                String kindText = cursor.text();
                int argCount = cursor.count();
                if (id == null || type == null || kindText == null || argCount < 0 || argCount > 16
                        || !cursor.take(';') || !ids.add(id)) {
                    return null;
                }
                GraphNodeKind kind;
                try {
                    kind = GraphNodeKind.valueOf(kindText);
                } catch (IllegalArgumentException invalidKind) {
                    return null;
                }
                List<GraphValue> arguments = new ArrayList<>(argCount);
                for (int a = 0; a < argCount; a++) {
                    String valueKind = cursor.text();
                    String value = cursor.text();
                    if (valueKind == null || value == null || !validGraphValueKind(valueKind)) {
                        return null;
                    }
                    arguments.add(new GraphValue(valueKind, value));
                }
                nodes.add(new GraphNode(id, type, kind, arguments));
            }
            if (!cursor.take('F')) {
                return null;
            }
            int fieldCount = cursor.count();
            if (!cursor.take(';') || fieldCount < 0 || fieldCount > 128) {
                return null;
            }
            List<GraphField> fields = new ArrayList<>(fieldCount);
            for (int i = 0; i < fieldCount; i++) {
                String owner = cursor.text();
                String field = cursor.text();
                int valueCount = cursor.count();
                if (owner == null || field == null || valueCount <= 0 || valueCount > 32
                        || !cursor.take(';')) {
                    return null;
                }
                List<GraphValue> values = new ArrayList<>(valueCount);
                for (int v = 0; v < valueCount; v++) {
                    String valueKind = cursor.text();
                    String value = cursor.text();
                    if (valueKind == null || value == null || !validGraphValueKind(valueKind)) {
                        return null;
                    }
                    values.add(new GraphValue(valueKind, value));
                }
                fields.add(new GraphField(owner, field, values));
            }
            return cursor.atEnd() ? new GraphPlan(nodes, fields) : null;
        } catch (RuntimeException malformed) {
            return null;
        }
    }

    private static boolean validGraphValueKind(String kind) {
        return "REF".equals(kind) || "CLASS".equals(kind) || "STRING".equals(kind)
                || "INT".equals(kind) || "LONG".equals(kind) || "BOOLEAN".equals(kind)
                || "NULL".equals(kind);
    }

    /** Small parser kept allocation-bounded by the plan limits and each length prefix. */
    private static final class GraphCursor {
        private final String input;
        private int offset;

        private GraphCursor(String input) {
            this.input = input;
        }

        private boolean take(String value) {
            if (!input.startsWith(value, offset)) {
                return false;
            }
            offset += value.length();
            return true;
        }

        private boolean take(char value) {
            if (offset >= input.length() || input.charAt(offset) != value) {
                return false;
            }
            offset++;
            return true;
        }

        private int count() {
            int start = offset;
            while (offset < input.length() && Character.isDigit(input.charAt(offset))) {
                offset++;
            }
            if (start == offset || offset >= input.length()) {
                throw new IllegalArgumentException("missing count");
            }
            return Integer.parseInt(input.substring(start, offset));
        }

        private String text() {
            int length = count();
            if (!take(':') || length < 0 || length > 512 || offset + length > input.length()) {
                throw new IllegalArgumentException("invalid text");
            }
            String value = input.substring(offset, offset + length);
            offset += length;
            return value;
        }

        private boolean atEnd() {
            return offset == input.length();
        }
    }

    /** Resolve and apply a rule-declared shape; every failure remains a partial-path reason. */
    private static void applyGraphPlan(GraphPlan plan, Object entryInstance,
                                       Map<String, Object> instances,
                                       boolean serializationSemantics,
                                       List<String> unlinked) {
        Map<String, Object> bindings = new HashMap<>();
        if (entryInstance != null) {
            bindings.put("entry", entryInstance);
        }
        Set<GraphNode> pending = java.util.Collections.newSetFromMap(
                new IdentityHashMap<GraphNode, Boolean>());
        pending.addAll(plan.nodes);
        int passes = Math.max(1, plan.nodes.size() + 1);
        for (int pass = 0; pass < passes && !pending.isEmpty(); pass++) {
            boolean progress = false;
            for (GraphNode node : new ArrayList<>(pending)) {
                if ("entry".equals(node.id) && entryInstance != null) {
                    bindings.put(node.id, entryInstance);
                    pending.remove(node);
                    progress = true;
                    continue;
                }
                List<Object> args = new ArrayList<>(node.arguments.size());
                boolean resolved = true;
                for (GraphValue value : node.arguments) {
                    ResolvedGraphValue resolvedValue = resolveGraphValue(value, bindings);
                    if (!resolvedValue.resolved) {
                        resolved = false;
                        break;
                    }
                    args.add(resolvedValue.value);
                }
                if (!resolved) {
                    continue;
                }
                try {
                    Class<?> type = load(node.type.replace('/', '.'));
                    Object object;
                    if (node.kind == GraphNodeKind.PROXY) {
                        Object handler = args.isEmpty() ? null : args.get(0);
                        object = handler instanceof InvocationHandler
                                ? newProxy(type, (InvocationHandler) handler) : null;
                    } else if (node.kind == GraphNodeKind.REFLECTIVE_PROXY) {
                        // This adapter is intentionally probe-owned. It preserves the
                        // interface-to-target dispatch shape while avoiding initialization of
                        // a target framework handler whose static logger/bootstrap may perform
                        // unrelated effects under the sandbox.
                        Object target = args.isEmpty() ? null : args.get(0);
                        String preferredMethod = args.size() > 1 && args.get(1) instanceof String
                                ? (String) args.get(1) : "";
                        object = target == null ? null
                                : newProxy(type, new SafeReflectiveInvocationHandler(target,
                                        preferredMethod, type));
                        if (object != null) {
                            graphAdapterUsed = true;
                        }
                    } else if (node.kind == GraphNodeKind.CONSTRUCTOR) {
                        object = constructGraphNode(type, args);
                    } else {
                        // ALLOCATE is the safe default even for a non-Serializable helper:
                        // Unsafe allocation skips arbitrary target constructors. Field plans
                        // are responsible for restoring only the state they can prove.
                        object = allocateWithoutConstructor(type);
                    }
                    if (object == null) {
                        unlinked.add(node.id + ":node-unavailable");
                        pending.remove(node);
                        progress = true;
                        continue;
                    }
                    bindings.put(node.id, object);
                    instances.putIfAbsent(type.getName(), object);
                    pending.remove(node);
                    progress = true;
                } catch (Throwable failure) {
                    unlinked.add(node.id + ":" + failure.getClass().getSimpleName());
                    pending.remove(node);
                    progress = true;
                }
            }
            if (!progress) {
                break;
            }
        }
        for (GraphNode node : pending) {
            unlinked.add(node.id + ":node-reference-unresolved");
        }
        SandboxSecurityManager.beginProxyBootstrap();
        try {
            for (var assignment : plan.fields) {
                Object owner = bindings.get(assignment.owner);
                if (owner == null) {
                    owner = instances.get(assignment.owner.replace('/', '.'));
                }
                if (owner == null) {
                    unlinked.add(assignment.owner + "." + assignment.field + ":owner-missing");
                    continue;
                }
                List<Object> values = new ArrayList<>(assignment.values.size());
                boolean resolved = true;
                for (GraphValue value : assignment.values) {
                    ResolvedGraphValue resolvedValue = resolveGraphValue(value, bindings);
                    if (!resolvedValue.resolved) {
                        resolved = false;
                        break;
                    }
                    values.add(resolvedValue.value);
                }
                if (!resolved) {
                    unlinked.add(assignment.owner + "." + assignment.field + ":value-missing");
                    continue;
                }
                Field field = findField(owner.getClass(), assignment.field);
                if (field == null) {
                    unlinked.add(assignment.owner + "." + assignment.field + ":field-missing");
                    continue;
                }
                try {
                    Object assigned = graphFieldValue(field.getType(), values);
                    if (assigned == GraphFieldFailure.VALUE) {
                        unlinked.add(assignment.owner + "." + assignment.field + ":type-mismatch");
                    } else if (!setGraphField(field, owner, assigned)) {
                        unlinked.add(assignment.owner + "." + assignment.field
                                + ":field-write-denied");
                    }
                } catch (Throwable failure) {
                    unlinked.add(assignment.owner + "." + assignment.field + ":"
                            + failure.getClass().getSimpleName());
                }
            }
        } finally {
            SandboxSecurityManager.endProxyBootstrap();
        }
    }

    private static final class ResolvedGraphValue {
        private final boolean resolved;
        private final Object value;

        private ResolvedGraphValue(boolean resolved, Object value) {
            this.resolved = resolved;
            this.value = value;
        }
    }

    private static ResolvedGraphValue resolveGraphValue(GraphValue value,
                                                        Map<String, Object> bindings) {
        try {
            switch (value.kind) {
                case "REF":
                    return bindings.containsKey(value.value)
                            ? new ResolvedGraphValue(true, bindings.get(value.value))
                            : new ResolvedGraphValue(false, null);
                case "CLASS":
                    return new ResolvedGraphValue(true, load(value.value.replace('/', '.')));
                case "STRING":
                    return new ResolvedGraphValue(true, value.value);
                case "INT":
                    return new ResolvedGraphValue(true, Integer.valueOf(value.value));
                case "LONG":
                    return new ResolvedGraphValue(true, Long.valueOf(value.value));
                case "BOOLEAN":
                    return new ResolvedGraphValue(true, Boolean.valueOf(value.value));
                case "NULL":
                    return new ResolvedGraphValue(true, null);
                default:
                    return new ResolvedGraphValue(false, null);
            }
        } catch (Throwable failure) {
            return new ResolvedGraphValue(false, null);
        }
    }

    private static Object constructGraphNode(Class<?> type, List<Object> arguments)
            throws Exception {
        for (Constructor<?> constructor : type.getDeclaredConstructors()) {
            Class<?>[] parameterTypes = constructor.getParameterTypes();
            if (parameterTypes.length != arguments.size()) {
                continue;
            }
            boolean compatible = true;
            for (int i = 0; i < parameterTypes.length; i++) {
                if (arguments.get(i) == null ? parameterTypes[i].isPrimitive()
                        : !box(parameterTypes[i]).isInstance(arguments.get(i))) {
                    compatible = false;
                    break;
                }
            }
            if (!compatible) {
                continue;
            }
            constructor.setAccessible(true);
            return constructor.newInstance(arguments.toArray());
        }
        throw new IllegalArgumentException("constructor-not-found:" + type.getName());
    }

    /** Safe proxy adapter for a declared interface/target pair; never calls a target setter. */
    private static final class SafeReflectiveInvocationHandler implements InvocationHandler {
        private final Object target;
        private final String preferredMethod;
        private final Class<?> interfaceType;

        private SafeReflectiveInvocationHandler(Object target, String preferredMethod,
                                               Class<?> interfaceType) {
            this.target = target;
            this.preferredMethod = preferredMethod == null ? "" : preferredMethod;
            this.interfaceType = interfaceType;
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] arguments) throws Throwable {
            String methodName = preferredMethod.isBlank() ? method.getName() : preferredMethod;
            Class<?>[] parameterTypes = preferredMethod.isBlank()
                    ? method.getParameterTypes() : new Class<?>[0];
            Method targetMethod = null;
            // Invoke through the exported interface method when possible. On Java 17 a public
            // implementation method in a non-exported JDK package can be inaccessible even
            // though its interface is public; the interface dispatch preserves the same
            // contract without --add-opens.
            if (interfaceType != null && interfaceType.isInterface()) {
                try {
                    targetMethod = interfaceType.getMethod(methodName, parameterTypes);
                } catch (NoSuchMethodException ignored) {
                    // Fall through to a public implementation method for ordinary interfaces.
                }
            }
            if (targetMethod == null) {
                try {
                    targetMethod = target.getClass().getMethod(methodName, parameterTypes);
                } catch (NoSuchMethodException missingPublicMethod) {
                    targetMethod = target.getClass().getDeclaredMethod(methodName, parameterTypes);
                    // Only a public interface contract is eligible for this adapter. A private
                    // target method would turn the generic proxy into an access escalation.
                    if (!Modifier.isPublic(targetMethod.getModifiers())) {
                        throw missingPublicMethod;
                    }
                }
            }
            try {
                return targetMethod.invoke(target, arguments);
            } catch (InvocationTargetException targetFailure) {
                Throwable cause = targetFailure.getCause();
                throw cause == null ? targetFailure : cause;
            }
        }
    }

    private static Class<?> box(Class<?> type) {
        if (!type.isPrimitive()) return type;
        if (type == boolean.class) return Boolean.class;
        if (type == byte.class) return Byte.class;
        if (type == short.class) return Short.class;
        if (type == char.class) return Character.class;
        if (type == int.class) return Integer.class;
        if (type == long.class) return Long.class;
        if (type == float.class) return Float.class;
        if (type == double.class) return Double.class;
        return Void.class;
    }

    private enum GraphFieldFailure { VALUE }

    private static Object graphFieldValue(Class<?> fieldType, List<Object> values) {
        if (fieldType.isArray()) {
            Object array = java.lang.reflect.Array.newInstance(fieldType.getComponentType(), values.size());
            for (int i = 0; i < values.size(); i++) {
                Object value = values.get(i);
                if (value == null && fieldType.getComponentType().isPrimitive()) {
                    return GraphFieldFailure.VALUE;
                }
                if (value != null && !box(fieldType.getComponentType()).isInstance(value)) {
                    return GraphFieldFailure.VALUE;
                }
                java.lang.reflect.Array.set(array, i, value);
            }
            return array;
        }
        if (values.size() != 1) {
            return GraphFieldFailure.VALUE;
        }
        Object value = values.get(0);
        if (value == null) {
            return fieldType.isPrimitive() ? GraphFieldFailure.VALUE : null;
        }
        return box(fieldType).isInstance(value) ? value : GraphFieldFailure.VALUE;
    }

    /**
     * Write only a rule-declared, type-checked instance field.  Java 17 modules reject
     * setAccessible for several JDK collection/event classes used by real gadget graphs;
     * the probe may use its already-scoped Unsafe allocator as a compatibility fallback.
     * This never invokes a target setter or constructor and remains inside the probe-only
     * serialization bootstrap scope.
     */
    private static boolean setGraphField(Field field, Object target, Object value) {
        if (Modifier.isStatic(field.getModifiers())) {
            return false;
        }
        try {
            field.setAccessible(true);
            field.set(target, value);
            return true;
        } catch (Throwable reflectiveDenied) {
            boolean bootstrap = false;
            try {
                SandboxSecurityManager.beginSerializationBootstrap();
                bootstrap = true;
                Object unsafe = probeUnsafe();
                Class<?> unsafeType = unsafe.getClass();
                long offset = (Long) unsafeType.getMethod("objectFieldOffset", Field.class)
                        .invoke(unsafe, field);
                Class<?> type = field.getType();
                if (!type.isPrimitive()) {
                    unsafeType.getMethod("putObject", Object.class, long.class, Object.class)
                            .invoke(unsafe, target, offset, value);
                } else if (type == boolean.class) {
                    unsafeType.getMethod("putBoolean", Object.class, long.class, boolean.class)
                            .invoke(unsafe, target, offset, ((Boolean) value).booleanValue());
                } else if (type == byte.class) {
                    unsafeType.getMethod("putByte", Object.class, long.class, byte.class)
                            .invoke(unsafe, target, offset, ((Number) value).byteValue());
                } else if (type == short.class) {
                    unsafeType.getMethod("putShort", Object.class, long.class, short.class)
                            .invoke(unsafe, target, offset, ((Number) value).shortValue());
                } else if (type == char.class) {
                    unsafeType.getMethod("putChar", Object.class, long.class, char.class)
                            .invoke(unsafe, target, offset, ((Character) value).charValue());
                } else if (type == int.class) {
                    unsafeType.getMethod("putInt", Object.class, long.class, int.class)
                            .invoke(unsafe, target, offset, ((Number) value).intValue());
                } else if (type == long.class) {
                    unsafeType.getMethod("putLong", Object.class, long.class, long.class)
                            .invoke(unsafe, target, offset, ((Number) value).longValue());
                } else if (type == float.class) {
                    unsafeType.getMethod("putFloat", Object.class, long.class, float.class)
                            .invoke(unsafe, target, offset, ((Number) value).floatValue());
                } else if (type == double.class) {
                    unsafeType.getMethod("putDouble", Object.class, long.class, double.class)
                            .invoke(unsafe, target, offset, ((Number) value).doubleValue());
                } else {
                    return false;
                }
                return true;
            } catch (Throwable unsafeDenied) {
                return false;
            } finally {
                if (bootstrap) {
                    SandboxSecurityManager.endSerializationBootstrap();
                }
            }
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
        String classPath = targetClassPath();
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
        String classPath = targetClassPath();
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


    /** Report only the separate target-call/body events produced by REAL_SANITIZED. */
    private static boolean reportRealSink(String sinkClass, String sinkMethod, String token) {
        if (!"SAFE_REAL".equals(safeSinkMode) || !executionGateReady) {
            return false;
        }
        waitForRealEvidence();
        boolean body = io.just.sast.verify.boot.SinkExecutionGate.bodyEntered();
        boolean bodyReturned = io.just.sast.verify.boot.SinkExecutionGate.bodyReturned();
        boolean call = io.just.sast.verify.boot.SinkExecutionGate.callObserved();
        boolean applicationBody = "APPLICATION_BODY".equals(safeSinkKind);
        if ((applicationBody && !bodyReturned) || (!applicationBody && !call)) {
            if (body) {
                emit(token, "UNTESTABLE: REAL_SINK_BODY_DID_NOT_RETURN;body=1;body_returned=0");
                return true;
            }
            if (io.just.sast.verify.boot.SinkExecutionGate.callAttempted()) {
                emit(token, "UNTESTABLE: REAL_SINK_CALL_DID_NOT_RETURN;attempted=1");
                return true;
            }
            return false;
        }
        boolean nativeComplete = io.just.sast.verify.boot.SinkExecutionGate.nativeLoadSucceeded()
                && io.just.sast.verify.boot.SinkExecutionGate.nativeCallObserved();
        if ("NATIVE_FIXTURE".equals(safeSinkKind) && !nativeComplete) {
            emit(token, "UNTESTABLE: REAL_NATIVE_FIXTURE_INCOMPLETE;native_load="
                    + (io.just.sast.verify.boot.SinkExecutionGate.nativeLoadSucceeded() ? "1" : "0")
                    + ";native_call="
                    + (io.just.sast.verify.boot.SinkExecutionGate.nativeCallObserved() ? "1" : "0"));
            return true;
        }
        String status = nativeComplete ? "JNI_EXECUTED_SAFE" : "SINK_EXECUTED_SAFE";
        String detail = status + ":body=" + (body ? "1" : "0")
                + ";body_returned=" + (bodyReturned ? "1" : "0")
                + ";call=" + (call ? "1" : "0")
                + ";attempted=" + (io.just.sast.verify.boot.SinkExecutionGate.callAttempted() ? "1" : "0")
                + ";native_load=" + (io.just.sast.verify.boot.SinkExecutionGate.nativeLoadSucceeded() ? "1" : "0")
                + ";native_call=" + (io.just.sast.verify.boot.SinkExecutionGate.nativeCallObserved() ? "1" : "0")
                + ";native_spec=" + safeLabel(io.just.sast.verify.boot.SinkExecutionGate.nativeCallSpec())
                + ";nested_blocked=" + (io.just.sast.verify.boot.SinkExecutionGate.nestedBlocked() ? "1" : "0")
                + ";native_digest=" + safeLabel(nativeFixtureDigest)
                + ";sanitizer=" + safeLabel(io.just.sast.verify.boot.SinkExecutionGate.sanitizer());
        emit(token, detail);
        System.err.println("SINK_EXECUTED_SAFE: " + sinkClass + "." + sinkMethod
                + " body=" + (body ? "1" : "0") + " call=" + (call ? "1" : "0")
                + " native=" + (nativeComplete ? "1" : "0"));
        return true;
    }

    /**
     * Some valid gadget sinks finish on a target-created thread (the JNI and thread fixtures
     * deliberately exercise this shape).  Wait only when no exact event exists, and only for a
     * bounded interval; the common synchronous path pays no polling cost.
     */
    private static void waitForRealEvidence() {
        if (io.just.sast.verify.boot.SinkExecutionGate.bodyReturned()
                || io.just.sast.verify.boot.SinkExecutionGate.callObserved()) {
            return;
        }
        long deadline = System.nanoTime() + ("NATIVE_FIXTURE".equals(safeSinkKind)
                ? 300_000_000L : 150_000_000L);
        while (System.nanoTime() < deadline) {
            try {
                Thread.sleep(10L);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                return;
            }
            if (io.just.sast.verify.boot.SinkExecutionGate.bodyReturned()
                    || io.just.sast.verify.boot.SinkExecutionGate.callObserved()) {
                return;
            }
        }
    }

    private static String safeLabel(String value) {
        if (value == null) {
            return "";
        }
        String clean = value.replace('\r', '_').replace('\n', '_').replace('|', '_');
        return clean.length() > 96 ? clean.substring(0, 96) : clean;
    }

    private static boolean reportLatchedCanary(String sinkClass, String sinkMethod, String token) {
        if (!io.just.sast.verify.boot.SinkCanaryGate.wasReached()) {
            return false;
        }
        SafeSinkAdapter.AdapterResult safeEffect = observeSafeEffect(sinkClass, sinkMethod);
        if (safeEffect != null && safeEffect.effectObserved()
                && safeSinkDisposition.equals(safeEffect.decision().disposition().name())) {
            emit(token, "SAFE_EFFECT_OBSERVED:" + safeSinkDisposition
                    + ";mode=" + safeSinkMode
                    + ";effect=" + safeEffect.effect()
                    + ";effect_digest=" + SafeSinkAdapter.effectDigest(safeEffect.effect())
                    + adapterSuffix());
            System.err.println("SINK_REACHED: " + sinkClass + "." + sinkMethod
                    + " (canary-latched; safe effect observed; target body not entered)");
            return true;
        }
        emit(token, "SINK_BLOCKED: " + sinkClass + adapterSuffix());
        System.err.println("SINK_REACHED: " + sinkClass + "." + sinkMethod + " (canary-latched)");
        return true;
    }

    /** Run only the fixed adapter effect after the target sink frame has been unwound. */
    private static SafeSinkAdapter.AdapterResult observeSafeEffect(String sinkClass,
                                                                    String sinkMethod) {
        if (!"SAFE_EXEC".equals(safeSinkMode)
                || "CANARY_BOUNDARY".equals(safeSinkDisposition)
                || "DENIED".equals(safeSinkDisposition)
                || safeSinkPolicyDigest.isBlank()) {
            return null;
        }
        try {
            Path scratch = Path.of(safeScratchRoot).toAbsolutePath().normalize();
            SafeSinkAdapter.Policy policy = "SAFE_REAL".equals(safeSinkMode)
                    ? SafeSinkAdapter.safeRealExecution(scratch)
                    : SafeSinkAdapter.safeExecution(scratch);
            if (!policy.digest().equals(safeSinkPolicyDigest)) {
                System.err.println("SAFE_EFFECT_NOT_OBSERVED: policy-digest-mismatch");
                return null;
            }
            SafeSinkAdapter.Sink sink = new SafeSinkAdapter.Sink(safeSinkCategory,
                    sinkClass.replace('.', '/'), sinkMethod, "");
            return SafeSinkAdapter.observe(policy, sink, null, safeJavaExecutable);
        } catch (RuntimeException failure) {
            System.err.println("SAFE_EFFECT_NOT_OBSERVED: "
                    + failure.getClass().getSimpleName());
            return null;
        }
    }

    private static Path locateSafeJavaExecutable() {
        try {
            Path home = Path.of(System.getProperty("java.home", "."));
            String executable = System.getProperty("os.name", "")
                    .toLowerCase(java.util.Locale.ROOT).contains("win") ? "java.exe" : "java";
            Path candidate = home.resolve("bin").resolve(executable).toAbsolutePath().normalize();
            if (!Files.isRegularFile(candidate)) {
                return null;
            }
            if (!Files.isRegularFile(candidate, java.nio.file.LinkOption.NOFOLLOW_LINKS)
                    || io.just.sast.util.ArchiveLimits.isLinkOrReparsePoint(candidate)) {
                return null;
            }
            return candidate;
        } catch (RuntimeException ignored) {
            return null;
        }
    }

    /** Emit only a probe-owned, per-attempt result marker; target output remains diagnostic. */
    private static void emit(String status) {
        emit(protocolToken, status);
    }

    private static void emit(String token, String status) {
        String safeStatus = status == null ? "UNTESTABLE: null-status"
                : status.replace('\r', ' ').replace('\n', ' ');
        if (safeStatus.startsWith("SANDBOX_READY")) {
            safeStatus += "|policy=" + safeIsolationPolicyDigest;
        }
        if (safeStatus.length() > 4096) {
            safeStatus = safeStatus.substring(0, 4096);
        }
        if (!protocolRunId.isBlank() && !protocolChainFingerprint.isBlank()
                && !protocolSinkFingerprint.isBlank() && !protocolNonce.isBlank()
                && !protocolArtifactFingerprint.isBlank()) {
            String frame = "JUST_VERIFY_V2:" + (token == null ? "" : token) + ":"
                    + protocolRunId + ":" + protocolChainFingerprint + ":"
                    + protocolSinkFingerprint + ":" + protocolNonce + ":"
                    + protocolArtifactFingerprint + ":" + safeStatus;
            writeResultFrame(frame);
            System.out.println(frame);
            return;
        }
        System.out.println(PROTOCOL_PREFIX + (token == null ? "" : token) + ":" + safeStatus);
    }

    /**
     * Establish the result channel before any target class can run.  The parent writes one
     * one-time secret to stdin; the probe owns the newly-created file and authenticates every
     * V2 frame.  Failure is fail-closed in the parent, while stdout remains diagnostic only.
     */
    private static void initializeResultChannel() {
        // Unlike protocol labels, this is a filesystem path and may legitimately exceed the
        // short metadata-property bound used for tokens/categories.  Keep it bounded and
        // reject control characters before resolving it.
        String resultFile = boundedPathProperty("just.verify.result-file");
        if (resultFile == null || resultFile.isBlank()) {
            return;
        }
        try {
            String secret = readResultSecret();
            if (!validResultSecret(secret)) {
                resultChannelBroken = true;
                return;
            }
            Path path = Path.of(resultFile).toAbsolutePath().normalize();
            resultChannel = Files.newOutputStream(path, StandardOpenOption.CREATE_NEW,
                    StandardOpenOption.WRITE);
            resultChannelSecret = secret;
        } catch (Exception failure) {
            resultChannelBroken = true;
            closeResultChannel();
        }
    }

    private static String readResultSecret() throws IOException {
        InputStream input = System.in;
        byte[] buffer = new byte[RESULT_SECRET_HEX_LENGTH + 2];
        int length = 0;
        try {
            while (length < buffer.length) {
                int value = input.read();
                if (value < 0 || value == '\n') {
                    break;
                }
                if (value != '\r') {
                    buffer[length++] = (byte) value;
                }
            }
        } finally {
            input.close();
        }
        if (length != RESULT_SECRET_HEX_LENGTH) {
            return "";
        }
        return new String(buffer, 0, length, StandardCharsets.US_ASCII);
    }

    private static boolean validResultSecret(String secret) {
        return secret != null && secret.matches("[0-9a-fA-F]{" + RESULT_SECRET_HEX_LENGTH + "}");
    }

    private static void writeResultFrame(String frame) {
        if (resultChannel == null || resultChannelBroken || !validResultSecret(resultChannelSecret)) {
            return;
        }
        try {
            String line = RESULT_CHANNEL_PREFIX + resultMac(frame) + ":" + frame + "\n";
            resultChannel.write(line.getBytes(StandardCharsets.UTF_8));
            resultChannel.flush();
        } catch (IOException | RuntimeException failure) {
            resultChannelBroken = true;
            closeResultChannel();
        }
    }

    private static String resultMac(String frame) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(resultChannelSecret.getBytes(StandardCharsets.US_ASCII),
                    "HmacSHA256"));
            byte[] digest = mac.doFinal(frame.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(digest.length * 2);
            for (byte value : digest) {
                hex.append(String.format(java.util.Locale.ROOT, "%02x", value & 0xff));
            }
            return hex.toString();
        } catch (GeneralSecurityException impossible) {
            return "";
        }
    }

    private static void closeResultChannel() {
        if (resultChannel == null) {
            return;
        }
        try {
            resultChannel.close();
        } catch (IOException ignored) {
            // The parent will reject an incomplete/unauthenticated channel.
        } finally {
            resultChannel = null;
        }
    }

    private static boolean protocolBound() {
        try {
            return io.just.sast.verify.boot.SinkCanaryGate.protocolBound(protocolRunId,
                    protocolChainFingerprint, protocolSinkFingerprint, protocolNonce,
                    protocolArtifactFingerprint);
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static String adapterSuffix() {
        return graphAdapterUsed ? ";adapter=REFLECTIVE_PROXY" : "";
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

    /** Keep a bounded cause chain so runtime/linkage denials remain diagnosable. */
    private static String describeFailure(Throwable failure) {
        if (failure == null) {
            return "";
        }
        StringBuilder detail = new StringBuilder();
        Throwable current = failure;
        int depth = 0;
        while (current != null && depth++ < 4) {
            if (detail.length() > 0) {
                detail.append(" caused-by ");
            }
            detail.append(current.getClass().getSimpleName());
            String message = current.getMessage();
            if (message != null && !message.isEmpty()) {
                detail.append(": ").append(message.replace('\n', ' ').replace('\r', ' '));
            }
            Throwable next = current.getCause();
            if (next == current) {
                break;
            }
            current = next;
        }
        if (detail.length() > 384) {
            detail.setLength(384);
        }
        return detail.toString();
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
     * Build the application context before the deny-by-default manager is installed. The
     * URLs are the target/dependency portion of the child JVM class path; the probe JAR is
     * deliberately excluded. This is a loader boundary, not an additional filesystem
     * capability. Failure is harmless: load() reports a normal partial path when the isolated
     * application loader cannot resolve a class.
     */
    private static void installApplicationLoader() {
        if (applicationLoader != null) {
            return;
        }
        List<URL> urls = new ArrayList<>();
        String classPath = targetClassPath();
        String probeJar = System.getProperty("just.verify.probe-jar", "");
        String normalizedProbe = probeJar.isBlank() ? ""
                : Path.of(probeJar).toAbsolutePath().normalize().toString();
        for (String entry : classPath.split(java.util.regex.Pattern.quote(
                java.io.File.pathSeparator))) {
            if (entry.isBlank()) {
                continue;
            }
            try {
                Path normalized = Path.of(entry).toAbsolutePath().normalize();
                if (!normalizedProbe.isEmpty() && normalized.toString().equals(normalizedProbe)) {
                    continue;
                }
                urls.add(normalized.toUri().toURL());
            } catch (Exception ignored) {
                // A malformed optional entry must not widen the probe or abort other entries.
            }
        }
        if (urls.isEmpty()) {
            // An empty application class path cannot resolve the target entry. Keep the
            // platform loader as the boundary; falling back to the launcher system loader
            // would expose scanner classes and dependencies to target code.
            applicationLoader = ClassLoader.getPlatformClassLoader();
            return;
        }
        try {
            URLClassLoader loader = new URLClassLoader(
                    urls.toArray(URL[]::new), ClassLoader.getPlatformClassLoader());
            applicationLoader = loader;
            Thread.currentThread().setContextClassLoader(loader);
        } catch (RuntimeException ignored) {
            applicationLoader = ClassLoader.getPlatformClassLoader();
        }
    }

    /**
     * The parent attaches the OS boundary before releasing this marker. Waiting here keeps
     * target class loading and static initialization out of the short pre-attachment window.
     * A manually launched probe without the nonce is intentionally not a valid verification.
     */
    private static boolean awaitIsolationReady() {
        String marker = System.getProperty("just.verify.isolation-ready", "");
        String expected = System.getProperty("just.verify.isolation-token", "");
        if (marker.isBlank() || expected.isBlank() || expected.length() > 128) {
            return false;
        }
        Path markerPath;
        try {
            markerPath = Path.of(marker).toAbsolutePath().normalize();
        } catch (RuntimeException invalidPath) {
            return false;
        }
        long deadline = System.nanoTime() + 5L * 1_000_000_000L;
        while (System.nanoTime() < deadline) {
            try {
                if (Files.isRegularFile(markerPath) && Files.size(markerPath) <= 256L) {
                    String actual = Files.readString(markerPath).strip();
                    if (expected.equals(actual)) {
                        return true;
                    }
                }
            } catch (IOException | RuntimeException ignored) {
                // The parent may still be creating/renaming the marker.
            }
            try {
                Thread.sleep(10L);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                return false;
            }
        }
        return false;
    }

    /**
     * Verify the strict Linux claims from inside the child before any target class is loaded.
     * Namespace presence alone is not enough: the attestation also requires the configured
     * nobody uid, no_new_privs, seccomp filter mode and the cgroup-v2 controllers requested by
     * the launcher. Other capability levels intentionally remain usable without this Linux-only
     * probe and are reported as their weaker, explicit level.
     */
    private static boolean strictOsAttestation() {
        if (!"OS_STRICT".equals(safeProperty("just.verify.isolation-level", "NONE"))) {
            return true;
        }
        String os = System.getProperty("os.name", "").toLowerCase(java.util.Locale.ROOT);
        if (os.contains("win")) {
            return "WINDOWS_APPCONTAINER_STRICT".equals(
                    safeProperty("just.verify.backend", ""))
                    && io.just.sast.verify.boot.WindowsProcessAttestation.appContainerLow();
        }
        if (!os.contains("linux")) {
            return false;
        }
        try {
            for (String namespace : List.of("user", "mnt", "pid", "net", "ipc", "uts")) {
                if (!Files.exists(Path.of("/proc/self/ns", namespace))) {
                    return false;
                }
            }
            String status = Files.readString(Path.of("/proc/self/status"));
            if (!status.matches("(?s).*\\nUid:\\s+65534(?:\\s|$).*")) {
                return false;
            }
            if (!status.matches("(?s).*\\nNoNewPrivs:\\s+1(?:\\s|$).*")) {
                return false;
            }
            if (!status.matches("(?s).*\\nSeccomp:\\s+[12](?:\\s|$).*")) {
                return false;
            }
            String controllers = Files.readString(Path.of("/sys/fs/cgroup/cgroup.controllers"));
            if (!List.of("cpu", "memory", "pids").stream().allMatch(controllers::contains)) {
                return false;
            }
            if (!cgroupLimitsAttested()) {
                return false;
            }
            if ("true".equalsIgnoreCase(safeProperty("just.verify.loopback", "false"))) {
                return java.net.NetworkInterface.getByInetAddress(
                        java.net.InetAddress.getLoopbackAddress()) != null;
            }
            return true;
        } catch (IOException | RuntimeException ignored) {
            return false;
        }
    }

    /**
     * Verify effective cgroup-v2 placement and finite limits, rather than trusting the host
     * controller list alone.  A strict launcher that only exposes the controller files but
     * leaves this process in an unlimited parent cgroup is not a resource boundary.
     */
    private static boolean cgroupLimitsAttested() {
        try {
            Path mount = Path.of("/sys/fs/cgroup");
            Path cgroupFile = Path.of("/proc/self/cgroup");
            if (!Files.isDirectory(mount) || !Files.isRegularFile(cgroupFile)) {
                return false;
            }
            String relative = "";
            for (String line : Files.readString(cgroupFile).split("\\R")) {
                if (line.startsWith("0::")) {
                    relative = line.substring(3).trim();
                    break;
                }
            }
            if (relative.isBlank()) {
                return false;
            }
            Path group = mount.resolve(relative.startsWith("/")
                    ? relative.substring(1) : relative).normalize();
            if (!group.startsWith(mount) || !Files.isDirectory(group)) {
                return false;
            }
            String pid = Long.toString(ProcessHandle.current().pid());
            if (!Files.readString(group.resolve("cgroup.procs")).lines()
                    .map(String::strip).anyMatch(pid::equals)) {
                return false;
            }
            long memory = finiteCgroupValue(Files.readString(group.resolve("memory.max")));
            long pids = finiteCgroupValue(Files.readString(group.resolve("pids.max")));
            String[] cpu = Files.readString(group.resolve("cpu.max")).strip().split("\\s+");
            long quota = cpu.length > 0 && !"max".equals(cpu[0])
                    ? finiteCgroupValue(cpu[0]) : -1L;
            return memory > 0L && pids > 0L && quota > 0L;
        } catch (IOException | RuntimeException ignored) {
            return false;
        }
    }

    private static long finiteCgroupValue(String value) {
        if (value == null || value.isBlank() || "max".equals(value.strip())) {
            return -1L;
        }
        try {
            long parsed = Long.parseLong(value.strip());
            return parsed > 0L ? parsed : -1L;
        } catch (NumberFormatException ignored) {
            return -1L;
        }
    }

    /** Install the child-side Landlock filesystem policy before loading target classes. */
    private static boolean installLandlock() {
        try {
            List<Path> writable = new ArrayList<>();
            Path temp = Path.of(System.getProperty("java.io.tmpdir", "."))
                    .toAbsolutePath().normalize();
            if (Files.isDirectory(temp)) {
                writable.add(temp);
            }
            String resultFile = boundedPathProperty("just.verify.result-file");
            if (!resultFile.isBlank()) {
                Path parent = Path.of(resultFile).toAbsolutePath().normalize().getParent();
                if (parent != null && Files.isDirectory(parent) && !writable.contains(parent)) {
                    writable.add(parent);
                }
            }
            return LinuxLandlock.install(writable);
        } catch (RuntimeException failure) {
            return false;
        }
    }

    private static String safeProperty(String key, String fallback) {
        String value = System.getProperty(key, fallback);
        if (value == null || value.isBlank() || value.length() > 96
                || value.indexOf('\n') >= 0 || value.indexOf('\r') >= 0) {
            return fallback;
        }
        return value;
    }

    private static String boundedPathProperty(String key) {
        String value = System.getProperty(key, "");
        if (value == null || value.isBlank() || value.length() > 4096
                || value.indexOf('\n') >= 0 || value.indexOf('\r') >= 0) {
            return "";
        }
        return value;
    }

    private static String targetClassPath() {
        String classPath = System.getProperty("just.verify.target-cp", "");
        if (classPath.isBlank()) {
            // Compatibility for an explicitly/manual launched probe. Production children use
            // the target-only property, keeping the system loader limited to the probe jar.
            return System.getProperty("java.class.path", "");
        }
        return classPath;
    }

    /**
     * Materialize only the verifier-owned native fixture.  Target JAR native resources are
     * deliberately never extracted or loaded: a native library is executable code, so treating
     * an artifact-provided .dll/.so as a "safe fixture" would defeat the isolation contract.
     * The fixture is selected by the Just resource path, checked against a release-time digest,
     * checked for the current executable format/CPU, and copied below the child scratch root.
     */
    private static boolean configureNativeFixtures() {
        try {
            Path scratch = Path.of(safeScratchRoot).toAbsolutePath().normalize();
            if (!Files.isDirectory(scratch, LinkOption.NOFOLLOW_LINKS)
                    || io.just.sast.util.ArchiveLimits.isLinkOrReparsePoint(scratch)) {
                return false;
            }
            Path nativeRoot = safeNativeScratchRoot.isBlank()
                    ? scratch.resolve("native").normalize()
                    : Path.of(safeNativeScratchRoot).toAbsolutePath().normalize();
            if ((!safeNativeScratchRoot.isBlank() && nativeRoot.equals(scratch))
                    || (!safeNativeScratchRoot.isBlank()
                    && io.just.sast.util.ArchiveLimits.isLinkOrReparsePoint(nativeRoot))
                    || !Files.isDirectory(nativeRoot, LinkOption.NOFOLLOW_LINKS)) {
                return false;
            }
            String resourceName = trustedNativeResource();
            String expectedDigest = trustedNativeDigest(resourceName);
            if (resourceName.isEmpty() || expectedDigest.isEmpty()) {
                return false;
            }
            // Keep the platform-mapped filename: System.loadLibrary resolves a basename through
            // java.library.path and must reach this exact verifier-owned file. The directory is
            // unique per child, so a prefix adds no isolation and only breaks lookup semantics.
            Path output = nativeRoot.resolve(nativeFileName(resourceName))
                    .normalize();
            if (!output.startsWith(nativeRoot)
                    || !Files.isRegularFile(output, LinkOption.NOFOLLOW_LINKS)
                    || io.just.sast.util.ArchiveLimits.isLinkOrReparsePoint(output)) {
                return false;
            }
            MessageDigest resourceDigest = MessageDigest.getInstance("SHA-256");
            long resourceBytes = 0L;
            try (InputStream input = ChainVerifyProbe.class.getResourceAsStream(resourceName)) {
                if (input == null) {
                    return false;
                }
                byte[] buffer = new byte[32 * 1024];
                int read;
                while ((read = input.read(buffer)) >= 0) {
                    if (read == 0) continue;
                    resourceBytes += read;
                    if (resourceBytes > 16L * 1024L * 1024L) return false;
                    resourceDigest.update(buffer, 0, read);
                }
            }
            if (resourceBytes == 0L) {
                return false;
            }
            if (!expectedDigest.equalsIgnoreCase(hex(resourceDigest.digest()))) {
                return false;
            }
            MessageDigest outputDigest = MessageDigest.getInstance("SHA-256");
            long outputBytes = 0L;
            try (InputStream input = Files.newInputStream(output)) {
                byte[] buffer = new byte[32 * 1024];
                for (int read; (read = input.read(buffer)) >= 0; ) {
                    if (read == 0) continue;
                    outputBytes += read;
                    if (outputBytes > 16L * 1024L * 1024L) return false;
                    outputDigest.update(buffer, 0, read);
                }
            }
            String fileHex = hex(outputDigest.digest());
            if (outputBytes == 0L || !expectedDigest.equalsIgnoreCase(fileHex)
                    || !nativeCompatible(output)) {
                return false;
            }
            String absolute = output.toAbsolutePath().normalize().toString();
            String fileName = nativeFileName(resourceName).toLowerCase(java.util.Locale.ROOT);
            String stem = nativeResourceStem(fileName);
            Map<String, String> mapping = new java.util.TreeMap<>();
            mapping.put(fileName, absolute);
            if (!stem.isEmpty()) mapping.put(stem, absolute);
            nativeFixtureDigest = fileHex;
            io.just.sast.verify.boot.SinkExecutionGate.setNativeMap(encodeNativeMap(mapping));
            return io.just.sast.verify.boot.SinkExecutionGate.configured();
        } catch (IOException | NoSuchAlgorithmException | RuntimeException failure) {
            return false;
        }
    }

    private static String trustedNativeResource() {
        String os = System.getProperty("os.name", "").toLowerCase(java.util.Locale.ROOT);
        String arch = System.getProperty("os.arch", "").toLowerCase(java.util.Locale.ROOT);
        String platform = os.contains("win") ? "windows" : os.contains("linux") ? "linux"
                : os.contains("mac") || os.contains("darwin") ? "macos" : "";
        String cpu = arch.contains("amd64") || arch.contains("x86_64") || arch.contains("x64")
                ? "x86-64" : arch.contains("aarch64") || arch.contains("arm64")
                ? "aarch64" : arch.matches("i[3-6]86") || arch.equals("x86") ? "x86" : "";
        String mapped = System.mapLibraryName("just-safe-jni");
        return platform.isEmpty() || cpu.isEmpty() ? ""
                : "/native/" + platform + "-" + cpu + "/" + mapped;
    }

    private static String trustedNativeDigest(String resourceName) {
        return "/native/windows-x86-64/just-safe-jni.dll".equals(resourceName)
                ? "9bec06088563f4f6d33d91bb04df4f05bf1c53fd38939b6c7600f4bf036c0506" : "";
    }

    private static String nativeFileName(String resourceName) {
        int slash = resourceName.lastIndexOf('/');
        return slash >= 0 ? resourceName.substring(slash + 1) : resourceName;
    }

    /** Reject a fixture for the wrong executable format or CPU before System.load sees it. */
    private static boolean nativeCompatible(Path path) {
        try {
            byte[] header = new byte[4096];
            int length = 0;
            try (InputStream input = Files.newInputStream(path, StandardOpenOption.READ)) {
                while (length < header.length) {
                    int read = input.read(header, length, header.length - length);
                    if (read < 0) break;
                    if (read == 0) continue;
                    length += read;
                }
            }
            String os = System.getProperty("os.name", "").toLowerCase(java.util.Locale.ROOT);
            String arch = System.getProperty("os.arch", "").toLowerCase(java.util.Locale.ROOT);
            int archCode = normalizedArch(arch);
            if (archCode < 0 || length < 20) return false;
            if (os.contains("win")) {
                if (length < 64 || header[0] != 'M' || header[1] != 'Z') return false;
                int pe = littleEndianInt(header, 0x3c);
                return pe >= 0 && pe + 6 <= length && header[pe] == 'P'
                        && header[pe + 1] == 'E' && header[pe + 2] == 0 && header[pe + 3] == 0
                        && littleEndianShort(header, pe + 4) == peMachine(archCode);
            }
            if (os.contains("linux")) {
                if (length < 20 || header[0] != 0x7f || header[1] != 'E'
                        || header[2] != 'L' || header[3] != 'F') return false;
                int klass = header[4] & 0xff;
                int expectedClass = archCode == 2 ? 1 : 2;
                return klass == expectedClass && elfMachine(header) == elfMachine(archCode);
            }
            if (os.contains("mac") || os.contains("darwin")) {
                int magic = bigEndianInt(header, 0);
                int littleMagic = littleEndianInt(header, 0);
                boolean big = magic == 0xfeedface || magic == 0xfeedfacf;
                boolean little = littleMagic == 0xfeedface || littleMagic == 0xfeedfacf;
                if (!big && !little) return false;
                int machine = big ? bigEndianInt(header, 4) : littleEndianInt(header, 4);
                return machine == machoMachine(archCode);
            }
            return false;
        } catch (IOException | RuntimeException failure) {
            return false;
        }
    }

    private static int normalizedArch(String arch) {
        if (arch.contains("amd64") || arch.contains("x86_64") || arch.contains("x64")) {
            return 1;
        }
        if (arch.matches("i[3-6]86") || arch.equals("x86")) return 2;
        if (arch.contains("aarch64") || arch.contains("arm64")) return 3;
        return -1;
    }

    private static int peMachine(int arch) {
        return arch == 1 ? 0x8664 : arch == 2 ? 0x14c : 0xaa64;
    }

    private static int elfMachine(int arch) {
        return arch == 1 ? 62 : arch == 2 ? 3 : 183;
    }

    private static int machoMachine(int arch) {
        return arch == 1 ? 0x01000007 : arch == 2 ? 7 : 0x0100000c;
    }

    private static int littleEndianInt(byte[] bytes, int offset) {
        if (offset < 0 || offset + 4 > bytes.length) return -1;
        return (bytes[offset] & 0xff) | ((bytes[offset + 1] & 0xff) << 8)
                | ((bytes[offset + 2] & 0xff) << 16) | ((bytes[offset + 3] & 0xff) << 24);
    }

    private static int bigEndianInt(byte[] bytes, int offset) {
        if (offset < 0 || offset + 4 > bytes.length) return -1;
        return ((bytes[offset] & 0xff) << 24) | ((bytes[offset + 1] & 0xff) << 16)
                | ((bytes[offset + 2] & 0xff) << 8) | (bytes[offset + 3] & 0xff);
    }

    private static int littleEndianShort(byte[] bytes, int offset) {
        if (offset < 0 || offset + 2 > bytes.length) return -1;
        return (bytes[offset] & 0xff) | ((bytes[offset + 1] & 0xff) << 8);
    }

    private static int elfMachine(byte[] bytes) {
        return littleEndianShort(bytes, 18);
    }

    private static String nativeResourceStem(String key) {
        if (key.endsWith(".dll")) return key.substring(0, key.length() - 4);
        if (key.endsWith(".dylib")) return key.substring(0, key.length() - 6);
        int so = key.indexOf(".so");
        return so > 0 ? key.substring(0, so) : "";
    }

    private static String encodeNativeMap(Map<String, String> mapping) {
        StringBuilder result = new StringBuilder("v1,");
        for (Map.Entry<String, String> item : mapping.entrySet()) {
            if (result.length() > 3) result.append(',');
            result.append(hex(item.getKey().getBytes(StandardCharsets.UTF_8)))
                    .append('=').append(hex(item.getValue().getBytes(StandardCharsets.UTF_8)));
        }
        return result.toString();
    }

    private static String hex(byte[] value) {
        StringBuilder result = new StringBuilder(value.length * 2);
        for (byte item : value) result.append(String.format(java.util.Locale.ROOT,
                "%02x", item & 0xff));
        return result.toString();
    }

    /** 类加载统一走显式应用 classloader：探针自身解析不触发 Class#forName canary。 */
    private static Class<?> load(String name) throws ClassNotFoundException {
        ClassLoader context = applicationLoader != null
                ? applicationLoader : Thread.currentThread().getContextClassLoader();
        ClassNotFoundException first = null;
        if (context != null) {
            try {
                return context.loadClass(name);
            } catch (ClassNotFoundException failure) {
                first = failure;
            }
        }
        boolean resourcePresent = false;
        String resourceName = name.replace('.', '/') + ".class";
        if (context != null && context.getResource(resourceName) != null) {
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

    /**
     * Resolve serialized application classes through the isolated application loader. The
     * default ObjectInputStream resolver asks the latest user-defined system loader, which is
     * deliberately probe-only in this process; that made valid SERIAL candidates fail with
     * ClassNotFoundException even though the target JAR was present in target-cp. The resolver
     * stays inside the already-approved loader and never initializes a target class by name.
     */
    private static final class ApplicationObjectInputStream extends java.io.ObjectInputStream {
        private ApplicationObjectInputStream(java.io.InputStream input) throws java.io.IOException {
            super(input);
        }

        @Override
        protected Class<?> resolveClass(ObjectStreamClass descriptor)
                throws java.io.IOException, ClassNotFoundException {
            try {
                return resolveSerializedType(descriptor.getName());
            } catch (ClassNotFoundException missing) {
                return super.resolveClass(descriptor);
            }
        }

        @Override
        protected Class<?> resolveProxyClass(String[] interfaces)
                throws java.io.IOException, ClassNotFoundException {
            if (applicationLoader != null && interfaces != null) {
                Class<?>[] resolved = new Class<?>[interfaces.length];
                try {
                    for (int i = 0; i < interfaces.length; i++) {
                        resolved[i] = applicationLoader.loadClass(interfaces[i]);
                    }
                    return java.lang.reflect.Proxy.getProxyClass(applicationLoader, resolved);
                } catch (IllegalArgumentException | SecurityException ignored) {
                    // Fall through to ObjectInputStream's standard resolver for a JDK proxy.
                }
            }
            return super.resolveProxyClass(interfaces);
        }
    }

    private static Class<?> resolveSerializedType(String name) throws ClassNotFoundException {
        if (applicationLoader == null || name == null || name.isEmpty()) {
            throw new ClassNotFoundException(name);
        }
        if (!name.startsWith("[")) {
            return applicationLoader.loadClass(name);
        }
        Class<?> component = resolveSerializedType(name.substring(1));
        return java.lang.reflect.Array.newInstance(component, 0).getClass();
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
        if (adaptedPayload != null && trigger != null) {
            byte[] payload = adaptedPayload;
            if (type == String.class || type == CharSequence.class) {
                return java.util.Base64.getEncoder().encodeToString(payload);
            }
            if (type == byte[].class) {
                return payload;
            }
            if (type == java.io.ObjectInputStream.class) {
                try {
                    return new java.io.ObjectInputStream(
                            new java.io.ByteArrayInputStream(payload));
                } catch (IOException ignored) {
                    // The bounded in-memory payload is valid; an unexpected stream failure is
                    // a genuine adapter capability boundary, not a reason to invoke a target
                    // ObjectInputStream subclass constructor.
                }
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
            if (type == Object.class || java.util.Collection.class.isAssignableFrom(type)) {
                Object seed = triggerInstance != null
                        ? triggerInstance : inertCallbackSeed(trigger.callbackKind());
                Object collection = sourceCollection(seed, trigger.callbackKind());
                if (type.isInstance(collection)) {
                    return collection;
                }
            }
            if (triggerInstance != null && type.isInstance(triggerInstance)) {
                return triggerInstance;
            }
        }
        return sourceValue(type);
    }

    private static byte[] sourcePayload(SourceTrigger trigger, Object triggerInstance)
            throws IOException {
        if (trigger == null) {
            return null;
        }
        Object seed = triggerInstance != null
                ? triggerInstance : inertCallbackSeed(trigger.callbackKind());
        if (isObjectInputSource(trigger)) {
            return serializeSourceCollection(seed, trigger.callbackKind());
        }
        if (isKryoSource(trigger)) {
            return serializeKryoSource(seed, trigger.callbackKind());
        }
        return null;
    }

    /**
     * Allocate the callback receiver without running target constructors. Abstract receiver
     * types are common in CHA paths (for example a collection base class); recover a concrete
     * sibling only from the target class path and only when the JVM type relation agrees.
     * This is an optional, bounded adapter aid, not a benchmark-specific class lookup.
     */
    private static Object newSourceTriggerInstance(SourceTrigger trigger,
                                                   Map<String, Object> instances)
            throws ClassNotFoundException {
        String triggerName = trigger.entryClass().replace('/', '.');
        Object existing = instances.get(triggerName);
        if (existing != null) {
            return existing;
        }
        Class<?> requested = load(triggerName);
        boolean requiresSerializable = isObjectInputSource(trigger);
        Object result = allocateCallbackObject(requested, requiresSerializable);
        if (result == null && (requested.isInterface() || Modifier.isAbstract(requested.getModifiers()))) {
            String packageName = requested.getPackageName();
            String prefix = packageName.isBlank() ? "" : packageName + ".";
            for (String name : discoverApplicationClassNames(prefix)) {
                try {
                    Class<?> candidate = Class.forName(name, false, applicationLoader);
                    if (!requested.isAssignableFrom(candidate)) {
                        continue;
                    }
                    result = allocateCallbackObject(candidate, requiresSerializable);
                    if (result != null) {
                        break;
                    }
                } catch (ClassNotFoundException | LinkageError | SecurityException ignored) {
                    // One optional subtype must not suppress other compatible candidates.
                }
            }
        }
        if (result != null) {
            instances.put(triggerName, result);
        }
        return result;
    }

    private static Object allocateCallbackObject(Class<?> type, boolean requiresSerializable) {
        if (type == null || type.isInterface() || Modifier.isAbstract(type.getModifiers())
                || (requiresSerializable && !java.io.Serializable.class.isAssignableFrom(type))) {
            return null;
        }
        return allocateWithoutConstructor(type);
    }

    private static final int MAX_CALLBACK_SUBTYPES = 256;

    private static List<String> discoverApplicationClassNames(String packagePrefix) {
        TreeSet<String> names = new TreeSet<>();
        String classPath = targetClassPath();
        for (String entry : classPath.split(java.util.regex.Pattern.quote(
                java.io.File.pathSeparator))) {
            if (entry.isBlank() || names.size() >= MAX_CALLBACK_SUBTYPES) {
                break;
            }
            Path path = Path.of(entry);
            try {
                if (Files.isDirectory(path)) {
                    Path scanRoot = packagePrefix == null || packagePrefix.isBlank()
                            ? path : path.resolve(packagePrefix.replace('.', java.io.File.separatorChar));
                    if (!Files.isDirectory(scanRoot)) {
                        continue;
                    }
                    try (java.util.stream.Stream<Path> files = Files.walk(scanRoot)) {
                        files.filter(Files::isRegularFile)
                                .map(path::relativize)
                                .map(Path::toString)
                                .filter(name -> name.endsWith(".class"))
                                .forEach(name -> addApplicationClassCandidate(names, name,
                                        packagePrefix));
                    }
                } else if (Files.isRegularFile(path) && entry.endsWith(".jar")) {
                    try (JarFile jar = new JarFile(path.toFile())) {
                        java.util.Enumeration<JarEntry> entries = jar.entries();
                        String packagePath = packagePrefix == null ? ""
                                : packagePrefix.replace('.', '/');
                        while (entries.hasMoreElements() && names.size() < MAX_CALLBACK_SUBTYPES) {
                            JarEntry jarEntry = entries.nextElement();
                            if (!jarEntry.isDirectory()
                                    && (packagePath.isBlank()
                                    || jarEntry.getName().startsWith(packagePath))) {
                                addApplicationClassCandidate(names, jarEntry.getName(),
                                        packagePrefix);
                            }
                        }
                    }
                }
            } catch (IOException | SecurityException ignored) {
                // Optional classpath roots remain an honest partial boundary.
            }
        }
        return List.copyOf(names);
    }

    private static void addApplicationClassCandidate(Set<String> names, String name,
                                                     String packagePrefix) {
        if (!name.endsWith(".class") || name.contains("module-info")
                || name.contains("package-info")) {
            return;
        }
        String binary = name.substring(0, name.length() - 6).replace('/', '.').replace('\\', '.');
        if ((packagePrefix != null && !binary.startsWith(packagePrefix))
                || binary.startsWith("java.") || binary.startsWith("javax.")
                || binary.startsWith("jdk.") || binary.startsWith("sun.")
                || binary.startsWith("com.sun.") || binary.startsWith("io.just.sast.")) {
            return;
        }
        names.add(binary);
    }

    private static Object inertCallbackSeed(String callbackKind) {
        return switch (callbackKind == null ? "" : callbackKind) {
            case "hashCode", "equals", "compareTo", "compare", "toString" ->
                    new java.util.AbstractMap.SimpleEntry<>("CHAIN_OK", "CHAIN_OK");
            default -> new java.util.ArrayList<>();
        };
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
                // Keep the stream class graph inside the JDK and the target application.  A
                // probe-private collection would be resolved by the target's application
                // loader during readObject and turn a valid source check into ClassNotFoundException.
                output.writeObject(sourceCollection(value, callbackKind));
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

    /**
     * Build a source container whose callback, when possible, is performed by the target JVM's
     * own collection deserialization.  This is deliberately shape-based: it uses only the
     * callback category recovered from the chain and never names a benchmark or gadget class.
     */
    private static Object sourceCollection(Object value, String callbackKind) throws IOException {
        return switch (callbackKind) {
            case "hashCode" -> rawHashSet(value);
            case "equals" -> {
                Object peer = duplicateWithoutConstructor(value);
                yield peer == null ? rawHashSet(value) : rawHashSet(value, peer);
            }
            default -> new java.util.ArrayList<>(java.util.List.of(value));
        };
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
            // Kryo's MapSerializer calls put() while reading a HashMap. HashSet is not a
            // safe substitute: with an instantiator strategy Kryo may allocate it without
            // running the constructor, leaving its internal map null and making the target
            // catch an NPE before the callback. The raw map keeps the classic bounded shape.
            case "hashCode" -> rawHashMap(value);
            case "equals" -> {
                Object peer = duplicateWithoutConstructor(value);
                yield peer == null ? rawHashMap(value) : rawHashMap(value, peer);
            }
            default -> new java.util.ArrayList<>(java.util.List.of(value));
        };
    }

    /** Build raw HashMap entries without calling target callbacks while preparing the probe. */
    private static Object rawHashMap(Object... keys) throws IOException {
        try {
            if (keys == null || keys.length == 0) {
                throw new IllegalArgumentException("at least one key is required");
            }
            Object unsafe = probeUnsafe();
            Class<?> unsafeType = unsafe.getClass();
            Class<?> nodeType;
            try {
                nodeType = Class.forName("java.util.HashMap$Node", false, null);
            } catch (ClassNotFoundException unavailable) {
                nodeType = Class.forName("java.util.HashMap$Entry", false, null);
            }
            Object head = null;
            for (int i = keys.length - 1; i >= 0; i--) {
                Object node = invokeUnsafe(unsafeType, unsafe, "allocateInstance",
                        new Class<?>[]{Class.class}, new Object[]{nodeType});
                unsafePutInt(unsafeType, unsafe, nodeType, node, "hash", 0);
                unsafePutObject(unsafeType, unsafe, nodeType, node, "key", keys[i]);
                unsafePutObject(unsafeType, unsafe, nodeType, node, "value", "CHAIN_OK");
                unsafePutObject(unsafeType, unsafe, nodeType, node, "next", head);
                head = node;
            }

            java.util.HashMap<Object, Object> map = new java.util.HashMap<>();
            Object table = java.lang.reflect.Array.newInstance(nodeType, 1);
            java.lang.reflect.Array.set(table, 0, head);
            unsafePutObject(unsafeType, unsafe, java.util.HashMap.class, map, "table", table);
            unsafePutInt(unsafeType, unsafe, java.util.HashMap.class, map, "size", keys.length);
            return map;
        } catch (ReflectiveOperationException | LinkageError | RuntimeException e) {
            throw new IOException("hash callback adapter unavailable: "
                    + e.getClass().getSimpleName(), e);
        }
    }

    /** Turn the raw map into a JDK HashSet so target readObject invokes key callbacks. */
    private static Object rawHashSet(Object... keys) throws IOException {
        try {
            Object unsafe = probeUnsafe();
            Class<?> unsafeType = unsafe.getClass();
            java.util.HashSet<Object> set = new java.util.HashSet<>();
            unsafePutObject(unsafeType, unsafe, java.util.HashSet.class, set, "map",
                    rawHashMap(keys));
            return set;
        } catch (ReflectiveOperationException | LinkageError | RuntimeException e) {
            throw new IOException("hash-set callback adapter unavailable: "
                    + e.getClass().getSimpleName(), e);
        }
    }

    /** Create an inert second instance without running target constructors for equals probes. */
    private static Object duplicateWithoutConstructor(Object value) {
        if (!(value instanceof java.io.Serializable)) {
            return null;
        }
        try {
            return allocateWithoutConstructor(value.getClass());
        } catch (Exception | LinkageError ignored) {
            return null;
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
            Class<?> declaredType = null;
            Class<?> concreteType = null;
            for (String candidate : trigger.downstreamOwner().split(",")) {
                if (candidate.isBlank()) {
                    continue;
                }
                try {
                    Class<?> type = load(candidate.replace('/', '.'));
                    if (declaredType == null) {
                        declaredType = type;
                    }
                    if (!type.isInterface() && !Modifier.isAbstract(type.getModifiers())
                            && java.io.Serializable.class.isAssignableFrom(type)) {
                        concreteType = type;
                        break;
                    }
                } catch (ClassNotFoundException | LinkageError | RuntimeException ignored) {
                    // An optional implementation must not disable other nearby candidates.
                }
            }
            if (concreteType == null) {
                return;
            }
            Object downstream = newInstance(concreteType, true);
            if (downstream == null || !setReferenceField(triggerInstance, downstream)) {
                return;
            }
            setClassField(triggerInstance, declaredType == null ? concreteType : declaredType);
            if (declaredType == concreteType) {
                configureInertGetterValue(downstream);
            }
        } catch (Exception | LinkageError ignored) {
            // Optional source adaptation must remain partial rather than widening access.
        }
    }

    private static void configureInertGetterValue(Object wrapper) {
        try {
            // The target application loader deliberately cannot see probe-private classes.
            // Use a JDK-visible, serializable getter-shaped value so the source adapter never
            // leaks ChainVerifyProbe$ProbeBean into a target object graph (which would become
            // a loader-dependent ClassNotFoundException during real deserialization). SimpleEntry
            // is not Kryo 4-safe on Java 17+ because java.base does not open its private fields;
            // String has a built-in serializer and harmless JavaBeans getters instead.
            setClassField(wrapper, String.class);
            setReferenceField(wrapper, "CHAIN_OK");
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
        warmJdkRuntimeLinkage();
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

    private static void warmJdkRuntimeLinkage() {
        warmObjectInputStream();
        warmReflectionRuntime();
        warmJdkDateLinkage();
        // A target class initializer may ask its application loader for a resource. On
        // Java 9+ that lookup can lazily initialize the JRT URL handler, whose lambda
        // metafactory performs reflective setup. Link it while the caller is still the
        // trusted probe frame; otherwise the deny-by-default manager attributes the same
        // JDK bootstrap permission to the target initializer and downgrades a valid path.
        warmClass("sun.net.www.protocol.jrt.Handler");
        warmClass("sun.net.protocol.jrt.JavaRuntimeURLConnection");
    }

    /**
     * Prime the JDK locale/date implementation used by Jackson's first POJONode rendering.
     * Some Java 17 images request a broad read/write property permission while lazily
     * selecting the locale provider; doing this from the trusted probe keeps that JDK
     * bootstrap out of a target callback without granting target code a property capability.
     */
    private static void warmJdkDateLinkage() {
        try {
            java.util.Locale.getDefault();
            java.util.TimeZone utc = java.util.TimeZone.getTimeZone("UTC");
            new java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSX",
                    java.util.Locale.US).setTimeZone(utc);
            new java.util.GregorianCalendar(utc, java.util.Locale.US).getTimeInMillis();
        } catch (RuntimeException ignored) {
            // Runtime-specific locale providers are optional; failure remains a normal
            // partial-path result rather than widening the sandbox.
        }
    }

    /**
     * Prime the JDK reflection accessor path while the caller is still the trusted probe.
     * The first Method/Class reflective call on older runtimes may lazily define an accessor
     * class. If that linkage happens from a target callback, the deny-by-default policy sees
     * a target frame and rejects createClassLoader before the canary call site is reached.
     * These calls invoke only JDK Object/Class methods and never target code.
     */
    private static void warmReflectionRuntime() {
        try {
            Method objectToString = Object.class.getMethod("toString");
            objectToString.invoke(new Object());
            Method stringToString = String.class.getMethod("toString");
            stringToString.invoke("CHAIN_WARMUP");
            Method classGetMethod = Class.class.getMethod("getMethod", String.class,
                    Class[].class);
            classGetMethod.invoke(Object.class, "toString", new Class<?>[0]);
        } catch (ReflectiveOperationException | RuntimeException ignored) {
            // A runtime-specific accessor implementation may already be unavailable. Keep
            // the normal bounded PARTIAL_PATH result instead of widening permissions.
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
