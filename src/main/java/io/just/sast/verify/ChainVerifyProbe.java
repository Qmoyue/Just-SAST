package io.just.sast.verify;
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
            // 1. 创建所有类的实例（自底向上）
            Map<String, Object> instances = new HashMap<>();
            // 先创建入口类
            Class<?> entryCls = Class.forName(entryClass);
            Object entryInstance = entryCls.getDeclaredConstructor().newInstance();
            instances.put(entryClass, entryInstance);

            // 创建链跳中涉及的类
            for (String[] link : fieldLinks) {
                String toClass = link[2].replace('/', '.');
                if (!instances.containsKey(toClass)) {
                    try {
                        Class<?> cls = Class.forName(toClass);
                        Object inst = cls.getDeclaredConstructor().newInstance();
                        instances.put(toClass, inst);
                    } catch (Exception e) {
                        // 某些类可能没有默认构造器——尝试找任何 public 构造器
                        try {
                            Class<?> cls = Class.forName(toClass);
                            for (Constructor<?> ctor : cls.getConstructors()) {
                                if (ctor.getParameterCount() == 0) {
                                    instances.put(toClass, ctor.newInstance());
                                    break;
                                }
                            }
                        } catch (Exception ignored) {
                        }
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
                            // 如果字段类型不匹配，尝试适配
                            if (field.getType().isInstance(toInstance)) {
                                field.set(fromInstance, toInstance);
                            } else if (field.getType() == Object.class) {
                                field.set(fromInstance, toInstance);
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
                                    f.set(inst, "echo CHAIN_OK");
                                } else if (f.getType() == Object.class) {
                                    f.set(inst, "echo CHAIN_OK");
                                } else if (f.getType() == int.class || f.getType() == Integer.class) {
                                    f.set(inst, 0);
                                } else if (f.getType() == boolean.class || f.getType() == Boolean.class) {
                                    f.set(inst, false);
                                }
                            }
                        } catch (Exception ignored) {
                        }
                    }
                }
            }

            // 4. 触发入口方法
            switch (mode) {
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

        } catch (Exception e) {
            // sink 特异性判定：栈帧级全等匹配（类名 + 方法名），含 cause 链
            if (reachesSink(e, sinkClassDotted, sinkMethod)) {
                System.out.println("SINK_TRIGGERED: " + sinkClassDotted);
                System.err.println("SINK_REACHED: " + sinkClassDotted + "." + sinkMethod
                        + " in " + e.getClass().getName());
                System.exit(1);
            }
            // 链中间环节失败（非 sink）
            System.out.println("PARTIAL_PATH: " + e.getClass().getSimpleName());
            System.exit(0); // 正常退出 = 未到达 sink
        }
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
