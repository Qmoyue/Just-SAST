package io.just.sast.verify;

import io.just.sast.blackboard.Chain;
import io.just.sast.util.JustLogger;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.Proxy;
import java.util.*;

/**
 * 动态验证：Payload 生成器——对候选链尝试构造真实可执行的对象/调用。
 *
 * 三种验证模式（按链入口类型自动选择）：
 * 1. DIRECT_INVOKE：入口为 public 方法 → 反射创建实例 + 直接调用方法
 * 2. SERIALIZATION：入口为 readObject 等 → 构造实例 → 序列化 → 子进程反序列化
 * 3. PROXY_INVOKE：入口为 proxyInvoke → 创建动态代理 → 触发 handler.invoke
 *
 * 每条链生成一个可执行的验证脚本（Java 源码），由 VerifyRunner 在子进程中编译执行。
 */
public final class PayloadGenerator {

    public record GeneratedPayload(String mode, String className, String methodName, String testArg, String description) {}

    /** 为链生成验证 payload 描述。 */
    public GeneratedPayload generate(Chain chain) {
        String entryClass = chain.entryClass().replace('/', '.');
        String entryMethod = chain.entryMethod();
        String entryKind = chain.entryKind();

        switch (entryKind) {
            case "proxyInvoke" -> {
                return new GeneratedPayload("PROXY_INVOKE", entryClass, entryMethod,
                        "verify-test", "动态代理触发 " + entryClass + "." + entryMethod);
            }
            case "readObject", "readObjectNoData", "readExternal", "readResolve" -> {
                return new GeneratedPayload("SERIALIZATION", entryClass, entryMethod,
                        null, "序列化/反序列化触发 " + entryClass + "." + entryMethod);
            }
            default -> {
                // hashCode / toString / equals / setter / 任意 public 方法
                return new GeneratedPayload("DIRECT_INVOKE", entryClass, entryMethod,
                        "verify-test", "直接调用 " + entryClass + "." + entryMethod);
            }
        }
    }

    /** 生成可在子进程中执行的 Java 验证代码。 */
    public String generateVerificationCode(Chain chain, String targetJarPath) {
        GeneratedPayload payload = generate(chain);
        String cls = payload.className();
        String method = payload.methodName();
        String mode = payload.mode();

        StringBuilder sb = new StringBuilder();
        sb.append("import java.lang.reflect.*;\n");
        sb.append("import java.io.*;\n\n");
        sb.append("public class VerifyProbe {\n");
        sb.append("    public static void main(String[] args) throws Exception {\n");
        sb.append("        try {\n");

        switch (mode) {
            case "DIRECT_INVOKE" -> {
                sb.append("            Class<?> cls = Class.forName(\"").append(cls).append("\");\n");
                sb.append("            Object instance = cls.getDeclaredConstructor().newInstance();\n");
                sb.append("            // 设置 Serializable 字段为测试值\n");
                sb.append("            for (Field f : cls.getDeclaredFields()) {\n");
                sb.append("                if (java.lang.reflect.Modifier.isStatic(f.getModifiers())) continue;\n");
                sb.append("                f.setAccessible(true);\n");
                sb.append("                if (f.getType() == String.class) {\n");
                sb.append("                    f.set(instance, \"verify-test\");\n");
                sb.append("                } else if (f.getType() == Object.class) {\n");
                sb.append("                    f.set(instance, \"verify-test\");\n");
                sb.append("                }\n");
                sb.append("            }\n");
                sb.append("            Method m = cls.getMethod(\"").append(method).append("\", String.class);\n");
                sb.append("            m.invoke(instance, \"echo VERIFY_TRIGGERED\");\n");
                sb.append("            System.out.println(\"EXECUTED\");\n");
            }
            case "PROXY_INVOKE" -> {
                sb.append("            Class<?> handlerClass = Class.forName(\"").append(cls).append("\");\n");
                sb.append("            Object handler = handlerClass.getDeclaredConstructor().newInstance();\n");
                sb.append("            // 设置 handler 字段\n");
                sb.append("            for (Field f : handlerClass.getDeclaredFields()) {\n");
                sb.append("                if (java.lang.reflect.Modifier.isStatic(f.getModifiers())) continue;\n");
                sb.append("                f.setAccessible(true);\n");
                sb.append("                if (f.getType() == String.class) f.set(handler, \"echo VERIFY_TRIGGERED\");\n");
                sb.append("            }\n");
                sb.append("            Object proxy = Proxy.newProxyInstance(\n");
                sb.append("                VerifyProbe.class.getClassLoader(),\n");
                sb.append("                new Class[]{Runnable.class}, (InvocationHandler) handler);\n");
                sb.append("            ((Runnable) proxy).run();\n");
                sb.append("            System.out.println(\"EXECUTED\");\n");
            }
            case "SERIALIZATION" -> {
                sb.append("            // 序列化/反序列化验证\n");
                sb.append("            Class<?> cls = Class.forName(\"").append(cls).append("\");\n");
                sb.append("            Object instance = cls.getDeclaredConstructor().newInstance();\n");
                sb.append("            for (Field f : cls.getDeclaredFields()) {\n");
                sb.append("                if (java.lang.reflect.Modifier.isStatic(f.getModifiers())) continue;\n");
                sb.append("                f.setAccessible(true);\n");
                sb.append("                if (f.getType() == String.class) f.set(instance, \"verify-test\");\n");
                sb.append("            }\n");
                sb.append("            ByteArrayOutputStream bos = new ByteArrayOutputStream();\n");
                sb.append("            new ObjectOutputStream(bos).writeObject(instance);\n");
                sb.append("            Object result = new ObjectInputStream(\n");
                sb.append("                new ByteArrayInputStream(bos.toByteArray())).readObject();\n");
                sb.append("            System.out.println(\"ROUNDTRIP_OK: \" + result.getClass().getName());\n");
            }
        }

        sb.append("        } catch (Exception e) {\n");
        sb.append("            System.err.println(\"TRIGGERED: \" + e.getClass().getName());\n");
        sb.append("            e.printStackTrace();\n");
        sb.append("            System.exit(1);\n");
        sb.append("        }\n");
        sb.append("        System.exit(0);\n");
        sb.append("    }\n");
        sb.append("}\n");
        return sb.toString();
    }
}
