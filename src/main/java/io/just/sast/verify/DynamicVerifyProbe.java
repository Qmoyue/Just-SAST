package io.just.sast.verify;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.Proxy;

/**
 * 通用动态验证探针：预编译一次，命令行参数指定目标类/方法/模式。
 * 消除逐链编译开销——每链仅需 JVM 启动（~0.3s）。
 *
 * 用法：java -cp probe:target.jar DynamicVerifyProbe <class> <method> <mode>
 * mode: DIRECT | PROXY | SERIAL
 */
public final class DynamicVerifyProbe {

    public static void main(String[] args) throws Exception {
        if (args.length < 3) {
            System.err.println("usage: DynamicVerifyProbe <class> <method> <mode>");
            System.exit(2);
        }
        String className = args[0];
        String methodName = args[1];
        String mode = args[2];

        try {
            Class<?> cls = Class.forName(className);
            Object instance = cls.getDeclaredConstructor().newInstance();

            // 填充 String/Object 字段为测试值
            for (Field f : cls.getDeclaredFields()) {
                if (Modifier.isStatic(f.getModifiers())) continue;
                f.setAccessible(true);
                Class<?> type = f.getType();
                if (type == String.class) {
                    f.set(instance, "echo VERIFY_OK");
                } else if (type == Object.class) {
                    f.set(instance, "echo VERIFY_OK");
                } else if (type == int.class || type == Integer.class) {
                    f.set(instance, 1);
                } else if (type == boolean.class || type == Boolean.class) {
                    f.set(instance, true);
                }
            }

            switch (mode) {
                case "DIRECT" -> {
                    // 直接调用目标方法
                    Method m = findMethod(cls, methodName);
                    if (m == null) {
                        System.err.println("METHOD_NOT_FOUND: " + methodName);
                        System.exit(3);
                    }
                    m.setAccessible(true);
                    Object result = m.getParameterCount() == 1 && m.getParameterTypes()[0] == String.class
                            ? m.invoke(instance, "echo VERIFY_OK")
                            : m.invoke(instance);
                    System.out.println("EXECUTED: " + methodName + " → " + result);
                }
                case "PROXY" -> {
                    // 创建动态代理并触发 invoke
                    if (java.lang.reflect.InvocationHandler.class.isAssignableFrom(cls)) {
                        Object handler = instance;
                        Object proxy = Proxy.newProxyInstance(
                                DynamicVerifyProbe.class.getClassLoader(),
                                new Class[]{Runnable.class},
                                (java.lang.reflect.InvocationHandler) handler);
                        ((Runnable) proxy).run();
                        System.out.println("EXECUTED: proxy.invoke → " + methodName);
                    } else {
                        Method m = findMethod(cls, methodName);
                        if (m != null) {
                            m.setAccessible(true);
                            m.invoke(instance);
                            System.out.println("EXECUTED: " + methodName);
                        }
                    }
                }
                case "SERIAL" -> {
                    // 序列化/反序列化往返
                    java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
                    new java.io.ObjectOutputStream(bos).writeObject(instance);
                    Object result = new java.io.ObjectInputStream(
                            new java.io.ByteArrayInputStream(bos.toByteArray())).readObject();
                    System.out.println("ROUNDTRIP_OK: " + result.getClass().getName());
                }
            }
        } catch (Exception e) {
            System.err.println("TRIGGERED: " + e.getClass().getName() + ": " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
        System.exit(0);
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
}
