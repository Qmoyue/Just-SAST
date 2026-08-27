package io.just.sast.verify;
import java.util.List;
import java.util.Map;
import java.util.Set;

import java.lang.reflect.Constructor;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.*;

/**
 * 链级验证探针：沿链的 FIELD_FLOW 跳构造完整对象图，触发入口方法，
 * 检查 sink 是否真实执行（异常栈帧的类名+方法名全等匹配）。
 *
 * 参数格式：
 *   arg0: entryClass|entryMethod|mode
 *   arg1: 链跳描述，逗号分隔：fromOwner.fieldName=toOwnerClassName
 *   arg2: sinkClass.sinkMethod（用于 sink 特异性判定，点分类名）
 *
 * 判定标准：
 *   SINK_TRIGGERED — 异常栈帧中存在 declaringClass == sinkClass && methodName == sinkMethod
 *                    （栈帧级全等匹配：子串匹配会把 java.lang.RuntimeException 误判为
 *                    java.lang.Runtime，已废除）
 *   PARTIAL_PATH — 异常来自链中间环节（类型不匹配/空指针/入口方法缺失），sink 未到达
 *   EXECUTED — 入口方法真实调用且正常返回（无异常完成）
 */
public final class ChainVerifyProbe {

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("usage: ChainVerifyProbe <entry|method|mode> [hops] [sink]");
            System.exit(2);
        }

        String[] entryParts = args[0].split("\\|");
        String entryClass = entryParts[0];
        String entryMethod = entryParts[1];
        String mode = entryParts.length > 2 ? entryParts[2] : "DIRECT";

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
        String sinkClassDotted = "";
        String sinkMethod = "";
        int sinkDot = sinkTarget.lastIndexOf('.');
        if (sinkDot > 0) {
            sinkClassDotted = sinkTarget.substring(0, sinkDot).replace('/', '.');
            sinkMethod = sinkTarget.substring(sinkDot + 1);
        }

        try {
            // 0. 预初始化 printStackTrace 依赖的 IdentityHashMap：深层 gadget 递归栈中首次
            //    触发其 <clinit> 会因 SOE 被永久毒化（此后一切栈打印 NCDFE），浅栈先建即免疫
            try {
                load("java.util.IdentityHashMap");
            } catch (Throwable ignored) {
            }

            // 1. 创建所有类的实例（自底向上）；无无参构造时回退到参数最少的构造器并按类型填默认值。
            //    类加载走 loadClass（非 Class.forName）——探针自身的类解析不得踩中 Class#forName canary
            Map<String, Object> instances = new HashMap<>();
            Class<?> entryCls = load(entryClass);
            Object entryInstance = newInstance(entryCls);
            instances.put(entryClass, entryInstance);

            // 创建链跳中涉及的类
            for (String[] link : fieldLinks) {
                String toClass = link[2].replace('/', '.');
                if (!instances.containsKey(toClass)) {
                    try {
                        instances.put(toClass, newInstance(load(toClass)));
                    } catch (Exception ignored) {
                    }
                }
            }

            // 2. 链接字段（fromOwner.fieldName = toOwner 实例）
            for (String[] link : fieldLinks) {
                String fromClass = link[0].replace('/', '.');
                String fieldName = link[1];
                String toClass = link[2].replace('/', '.');
                Object fromInstance = instances.get(fromClass);
                Object toInstance = instances.get(toClass);
                if (fromInstance != null && toInstance != null) {
                    try {
                        Field field = findField(fromInstance.getClass(), fieldName);
                        if (field != null) {
                            field.setAccessible(true);
                            if (field.getType().isInstance(toInstance)) {
                                field.set(fromInstance, toInstance);
                            } else if (field.getType() == Object.class) {
                                field.set(fromInstance, toInstance);
                            } else if (Map.class.isAssignableFrom(field.getType())
                                    || Set.class.isAssignableFrom(field.getType())
                                    || List.class.isAssignableFrom(field.getType())) {
                                // 集合布局构造：容器字段按声明类型实例化，链接目标放入
                                // key/元素位——后段入口对象经容器槽位进入对象图，
                                // 容器反序列化时触发其 hashCode/equals/compareTo
                                Object container = newCollection(field.getType());
                                if (container != null) {
                                    if (container instanceof Map<?, ?> map) {
                                        @SuppressWarnings("unchecked")
                                        Map<Object, Object> m2 = (Map<Object, Object>) map;
                                        m2.put(toInstance, "echo CHAIN_OK");
                                    } else if (container instanceof Set<?> set) {
                                        @SuppressWarnings("unchecked")
                                        Set<Object> s2 = (Set<Object>) set;
                                        s2.add(toInstance);
                                    } else {
                                        @SuppressWarnings("unchecked")
                                        List<Object> l2 = (List<Object>) container;
                                        l2.add(toInstance);
                                    }
                                    field.set(fromInstance, container);
                                }
                            }
                        }
                    } catch (Exception ignored) {
                    }
                }
            }

            // 3. 填充未链接的 String/Object 字段（含父类——getDeclaredFields 只看自身类）
            for (Object inst : instances.values()) {
                for (Class<?> c = inst.getClass(); c != null && c != Object.class; c = c.getSuperclass()) {
                    for (Field f : c.getDeclaredFields()) {
                        if (Modifier.isStatic(f.getModifiers())) continue;
                        f.setAccessible(true);
                        try {
                            if (f.get(inst) == null) {
                                if (f.getType() == String.class) {
                                    // "toString"：在 Object 上恒可解析——方法名语义字段（如
                                    // methodName）经 getMethod 解析成功后链才能到达 Method.invoke；
                                    // 非 方法名语义的字符串作为普通参数传入 sink，sink 内抛错仍留栈帧
                                    f.set(inst, "toString");
                                } else if (f.getType() == Object.class) {
                                    f.set(inst, "toString");
                                } else if (f.getType().isArray()) {
                                    // 空数组：null 数组传给可变参/参数表方法会 NPE 短路链
                                    f.set(inst, java.lang.reflect.Array.newInstance(
                                            f.getType().getComponentType(), 0));
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
                                }
                            }
                        } catch (Exception ignored) {
                        }
                    }
                }
            }

            // 4. 触发入口（触发忠实：按真实反序列化的触发路径，非直接调用）
            switch (mode) {
                case "TRIGGER_HASH" -> {
                    // hashCode 入口的真实触发：对象作为 HashMap 的 key 被放入
                    new java.util.HashMap<Object, Object>().put(entryInstance, "echo CHAIN_OK");
                    System.out.println("EXECUTED");
                    System.exit(0);
                }
                case "TRIGGER_TREESET" -> {
                    // compareTo/compare 入口的真实触发：对象进入自然有序容器
                    new java.util.TreeSet<Object>().add(entryInstance);
                    System.out.println("EXECUTED");
                    System.exit(0);
                }
                case "TRIGGER_CONTAINS" -> {
                    // equals 入口的真实触发：非空集合的 contains 逐元素调用 equals
                    java.util.List<Object> l = new java.util.ArrayList<>();
                    l.add(new Object());
                    l.contains(entryInstance);
                    System.out.println("EXECUTED");
                    System.exit(0);
                }
                case "PROXY" -> {
                    if (!java.lang.reflect.InvocationHandler.class.isAssignableFrom(entryCls)) {
                        System.out.println("PARTIAL_PATH: entry-not-handler");
                        System.exit(0);
                    }
                    Object proxy = java.lang.reflect.Proxy.newProxyInstance(
                            ChainVerifyProbe.class.getClassLoader(),
                            new Class[]{Runnable.class},
                            (java.lang.reflect.InvocationHandler) entryInstance);
                    ((Runnable) proxy).run();
                }
                case "SERIAL" -> {
                    java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
                    new java.io.ObjectOutputStream(bos).writeObject(entryInstance);
                    new java.io.ObjectInputStream(
                            new java.io.ByteArrayInputStream(bos.toByteArray())).readObject();
                }
                default -> {
                    Method m = findMethod(entryCls, entryMethod);
                    if (m == null) {
                        // 入口方法在目标类上不可解析：探针无法触发——不是"链执行完成"
                        System.out.println("PARTIAL_PATH: entry-method-missing");
                        System.exit(0);
                    }
                    m.setAccessible(true);
                    if (m.getParameterCount() == 1 && m.getParameterTypes()[0] == String.class) {
                        m.invoke(entryInstance, "echo CHAIN_OK");
                    } else {
                        m.invoke(entryInstance);
                    }
                }
            }

            System.out.println("EXECUTED");
            System.exit(0);

        } catch (Throwable t) {
            // 优先：sink canary 主动命中（插桩 sink 入口抛出的标记 Error，穿透 gadget 的
            // catch(Exception)）。命中须同时满足：标记 spec == 本链 sink 且栈中存在
            // 链入口方法帧（在 sink 帧之下）——排除探针自身基础设施误踩 sink。
            String marker = markerSpec(t);
            if (marker != null && sameSink(marker, sinkClassDotted, sinkMethod)
                    && entryReached(t, entryClass, entryMethod)) {
                System.out.println("SINK_TRIGGERED: " + sinkClassDotted);
                System.err.println("SINK_REACHED: " + sinkClassDotted + "." + sinkMethod
                        + " (canary)");
                System.exit(1);
            }
            // 次选：栈帧级全等匹配（类名 + 方法名），含 cause 链——同样要求入口帧在场
            if (reachesSink(t, sinkClassDotted, sinkMethod)
                    && entryReached(t, entryClass, entryMethod)) {
                System.out.println("SINK_TRIGGERED: " + sinkClassDotted);
                System.err.println("SINK_REACHED: " + sinkClassDotted + "." + sinkMethod
                        + " in " + t.getClass().getName());
                System.exit(1);
            }
            // 链中间环节失败（非 sink）；消息带关键归因（如缺失类名），截断防长链污染输出
            String detail = t.getMessage();
            System.out.println("PARTIAL_PATH: " + t.getClass().getSimpleName()
                    + (detail != null ? ": " + detail.split("\\R")[0].transform(
                        s -> s.length() > 120 ? s.substring(0, 120) : s) : ""));
            System.exit(0); // 正常退出 = 未到达 sink
        }
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
        int h = spec.indexOf('#');
        if (h <= 0) {
            return false;
        }
        return spec.substring(0, h).replace('/', '.').equals(sinkClassDotted)
                && spec.substring(h + 1).equals(sinkMethod);
    }

    /** 栈中是否存在链入口类#入口方法帧（真实执行过入口——探针基础设施误踩 sink 无此帧）。 */
    static boolean entryReached(Throwable top, String entryClass, String entryMethod) {
        for (StackTraceElement frame : top.getStackTrace()) {
            if (entryClass.equals(frame.getClassName()) && entryMethod.equals(frame.getMethodName())) {
                return true;
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
            // getStackTrace 对 JVM 优化过的异常可能返回空数组——退回字符串形式逐帧核对
            if (t.getStackTrace().length == 0) {
                String trace = getStackTrace(t);
                if (trace.contains("at " + sinkClass + "." + sinkMethod + "(")) {
                    return true;
                }
            }
        }
        return false;
    }



    /** 实例化：优先无参构造；否则取参数最少的构造器，参数按类型填默认值。 */
    static Object newInstance(Class<?> cls) throws Exception {
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

    /** 按类型的构造参数默认值（字符串用 "toString"——方法名语义恒可解析；数组给空）。 */
    private static Object defaultValue(Class<?> type) {
        if (type == String.class || type == Object.class) {
            return "toString";
        }
        if (type == int.class || type == long.class || type == short.class || type == byte.class) {
            return 0;
        }
        if (type == boolean.class) {
            return false;
        }
        if (type == char.class) {
            return 'a';
        }
        if (type == float.class || type == double.class) {
            return 0.0d;
        }
        if (type.isArray()) {
            return java.lang.reflect.Array.newInstance(type.getComponentType(), 0);
        }
        return null;
    }

    /** 触发忠实模式判定。 */
    static boolean isTriggerMode(String mode) {
        return "TRIGGER_HASH".equals(mode) || "TRIGGER_TREESET".equals(mode)
                || "TRIGGER_CONTAINS".equals(mode);
    }

    /** 按声明类型实例化集合：具体类型反射实例化；接口/抽象类型——有序系（SortedX/NavigableX）
     *  取 Tree 实现（保持 compareTo 触发语义），其余取 Hash/Array 默认实现。 */
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
        } catch (Exception e) {
            return null;
        }
    }

    /** 类加载统一走应用 classloader 的 loadClass：探针自身解析不触发 Class#forName canary。 */
    private static Class<?> load(String name) throws ClassNotFoundException {
        return ClassLoader.getSystemClassLoader().loadClass(name);
    }

    private static Field findField(Class<?> cls, String name) {        for (Class<?> c = cls; c != null; c = c.getSuperclass()) {
            try {
                return c.getDeclaredField(name);
            } catch (NoSuchFieldException ignored) {
            }
        }
        return null;
    }

    private static Method findMethod(Class<?> cls, String name) {
        for (Method m : cls.getMethods()) {
            if (m.getName().equals(name)) return m;
        }
        for (Method m : cls.getDeclaredMethods()) {
            if (m.getName().equals(name)) return m;
        }
        return null;
    }

    private static String getStackTrace(Throwable t) {
        java.io.StringWriter sw = new java.io.StringWriter();
        t.printStackTrace(new java.io.PrintWriter(sw));
        return sw.toString();
    }
}
