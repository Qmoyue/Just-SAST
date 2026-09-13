package io.just.sast.cli;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.tools.JavaCompiler;
import javax.tools.SimpleJavaFileObject;
import javax.tools.ToolProvider;
import java.io.File;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 引擎能力契约（端到端）：
 * - 数组元素流：AASTORE 污点值 → 字段/参数粒度的数组容器污点 → AALOAD 读出可控（历史缺陷：跨方法断链）
 * - lambda 分发：lambda 实参经函数式接口调用时污点传给实现方法（历史缺陷：indy 结果被 CHA+Serializable 过滤掉）
 * - 框架反射供给门：无框架在 classpath 时常量类反射查找不得把全应用 public 方法拉进入口闭包（NO_PATH 剪枝保留）
 */
class EngineCapabilityTest {

    private static final class Source extends SimpleJavaFileObject {
        private final String code;

        Source(String className, String code) {
            super(URI.create("string:///" + className.replace('.', '/') + ".java"), Kind.SOURCE);
            this.code = code;
        }

        @Override public CharSequence getCharContent(boolean ignoreEncodingErrors) {
            return code;
        }
    }

    private static Path compileToJar(Path jarFile, Map<String, String> sources) throws Exception {
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        File classesDir = Files.createTempDirectory("just-cap-classes").toFile();
        try (var fm = compiler.getStandardFileManager(null, null, null)) {
            fm.setLocation(javax.tools.StandardLocation.CLASS_OUTPUT, List.of(classesDir));
            boolean ok = compiler.getTask(null, fm, null, null, null,
                    sources.entrySet().stream()
                            .map(e -> (javax.tools.JavaFileObject) new Source(e.getKey(), e.getValue()))
                            .toList())
                    .call();
            if (!ok) {
                throw new IllegalStateException("fixture 编译失败");
            }
        }
        try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(jarFile))) {
            addClasses(zip, classesDir, "");
        }
        return jarFile;
    }

    private static void addClasses(ZipOutputStream zip, File dir, String prefix) throws Exception {
        for (File f : dir.listFiles()) {
            String name = prefix + f.getName();
            if (f.isDirectory()) {
                addClasses(zip, f, name + "/");
            } else if (name.endsWith(".class")) {
                zip.putNextEntry(new ZipEntry(name));
                zip.write(Files.readAllBytes(f.toPath()));
                zip.closeEntry();
            }
        }
    }

    @Test
    void arrayElementFlowCrossesMethodBoundary(@TempDir Path tmp) throws Exception {
        String carrier = """
                package app;
                public class Carrier implements java.io.Serializable {
                    public Object[] cells;
                }
                """;
        String gadget = """
                package app;
                public class ArrayGadget implements java.io.Serializable {
                    private Carrier carrier;
                    private String cmd;
                    private void readObject(java.io.ObjectInputStream in) throws Exception {
                        Carrier c = new Carrier();
                        fill(c, this.cmd);
                        Runtime.getRuntime().exec((String) c.cells[0]);
                        in.defaultReadObject();
                    }
                    private static void fill(Carrier c, Object v) {
                        c.cells[0] = v;
                    }
                }
                """;
        Path jar = compileToJar(tmp.resolve("arr.jar"), Map.of("app.Carrier", carrier, "app.ArrayGadget", gadget));
        Path out = tmp.resolve("out");
        ScanPipeline.run(jar, null, out, null, false, true, null, false, 20);
        String findings = Files.readString(out.resolve("findings").resolve("findings.csv"));
        assertTrue(findings.contains("app/ArrayGadget,readObject") && findings.contains("java/lang/Runtime,exec"),
                "数组元素流（fill 内 AASTORE → Carrier.cells 字段污点 → readObject 内 AALOAD）应闭合链:\n"
                        + findings);
    }

    @Test
    void lambdaArgumentDispatchesToImplMethod(@TempDir Path tmp) throws Exception {
        String fn = """
                package app;
                public interface Fn {
                    void go(String s);
                }
                """;
        String gadget = """
                package app;
                public class LambdaGadget implements java.io.Serializable {
                    private String cmd;
                    private void readObject(java.io.ObjectInputStream in) throws Exception {
                        dispatch(s -> {
                            try {
                                Runtime.getRuntime().exec(s);
                            } catch (Exception ignored) {
                            }
                        }, this.cmd);
                        in.defaultReadObject();
                    }
                    private static void dispatch(Fn f, String cmd) {
                        f.go(cmd);
                    }
                }
                """;
        Path jar = compileToJar(tmp.resolve("lambda.jar"), Map.of("app.Fn", fn, "app.LambdaGadget", gadget));
        Path out = tmp.resolve("out");
        ScanPipeline.run(jar, null, out, null, false, true, null, false, 20);
        String findings = Files.readString(out.resolve("findings").resolve("findings.csv"));
        assertTrue(findings.contains("app/LambdaGadget,readObject") && findings.contains("java/lang/Runtime,exec"),
                "lambda 实参经 f.go(cmd) 分发时污点应到达 lambda$0 实现方法:\n" + findings);
    }

    @Test
    void directCapturedLambdaCallReachesImplementation(@TempDir Path tmp) throws Exception {
        String gadget = """
                package app;
                public class DirectLambdaGadget implements java.io.Serializable {
                    private String cmd;
                    private void readObject(java.io.ObjectInputStream in) throws Exception {
                        java.util.function.Consumer<String> consumer = value -> {
                            try {
                                Runtime.getRuntime().exec(value);
                            } catch (Exception ignored) {
                            }
                        };
                        consumer.accept(this.cmd);
                        in.defaultReadObject();
                    }
                }
                """;
        Path jar = compileToJar(tmp.resolve("direct-lambda.jar"),
                Map.of("app.DirectLambdaGadget", gadget));
        Path out = tmp.resolve("out");
        ScanPipeline.run(jar, null, out, null, false, true, null, false, 20);
        String findings = Files.readString(out.resolve("findings").resolve("findings.csv"));
        assertTrue(findings.contains("app/DirectLambdaGadget,readObject")
                        && findings.contains("java/lang/Runtime,exec"),
                "直接调用捕获 this 的 lambda 时，污点应映射到 synthetic 实现方法:\n" + findings);
    }

    @Test
    void derivedIteratorViewDoesNotDispatchToUnrelatedImplementation(@TempDir Path tmp)
            throws Exception {
        String gadget = """
                package app;
                public class CollectionGadget implements java.io.Serializable {
                    private java.util.Collection<Object> values;
                    private void readObject(java.io.ObjectInputStream in) throws Exception {
                        java.util.Iterator<Object> iterator = values.iterator();
                        iterator.next();
                        in.defaultReadObject();
                    }
                }
                """;
        String unrelated = """
                package app;
                public class UnrelatedIterator implements java.util.Iterator<Object> {
                    public boolean hasNext() { return true; }
                    public Object next() {
                        try {
                            Runtime.getRuntime().exec("not-a-real-command");
                        } catch (Exception ignored) {
                        }
                        return null;
                    }
                    public void remove() { }
                }
                """;
        Path jar = compileToJar(tmp.resolve("iterator-view.jar"),
                Map.of("app.CollectionGadget", gadget, "app.UnrelatedIterator", unrelated));
        Path out = tmp.resolve("out");
        ScanPipeline.run(jar, null, out, null, false, true, null, false, 20);
        String findings = Files.readString(out.resolve("findings").resolve("findings.csv"));
        assertFalse(findings.contains("app/UnrelatedIterator,next"),
                "iterator view 本身不是反序列化对象，不能通过 CHA 把无关实现接入:\n" + findings);
    }

    @Test
    void deserializationLifecycleKindsAndSerializedFieldsAreTyped(@TempDir Path tmp)
            throws Exception {
        String resolve = """
                package app;
                public final class ResolveGadget implements java.io.Serializable {
                    private String command;
                    private Object readResolve() throws Exception {
                        Runtime.getRuntime().exec(this.command);
                        return this;
                    }
                }
                """;
        String external = """
                package app;
                public final class ExternalGadget implements java.io.Externalizable {
                    private String command;
                    public ExternalGadget() { }
                    public void readExternal(java.io.ObjectInput in) throws java.io.IOException {
                        Runtime.getRuntime().exec(this.command);
                    }
                    public void writeExternal(java.io.ObjectOutput out) throws java.io.IOException { }
                }
                """;
        String field = """
                package app;
                public final class FieldGadget implements java.io.Serializable {
                    private String command;
                    private transient String transientCommand;
                    private static String staticCommand;
                    private void readObject(java.io.ObjectInputStream in) throws Exception {
                        Runtime.getRuntime().exec(this.command);
                        Runtime.getRuntime().exec(this.transientCommand);
                        Runtime.getRuntime().exec(staticCommand);
                        in.defaultReadObject();
                    }
                }
                """;
        Path jar = compileToJar(tmp.resolve("lifecycle-positive.jar"), Map.of(
                "app.ResolveGadget", resolve, "app.ExternalGadget", external,
                "app.FieldGadget", field));
        Path positiveOut = tmp.resolve("positive-out");
        ScanPipeline.run(jar, null, positiveOut, null, false, true, null, false, 20);
        String positiveFindings = Files.readString(
                positiveOut.resolve("findings").resolve("findings.csv"));
        assertTrue(positiveFindings.contains("app/ResolveGadget,readResolve")
                        && positiveFindings.contains("app/ExternalGadget,readExternal")
                        && positiveFindings.contains("app/FieldGadget,readObject")
                        && positiveFindings.contains("java/lang/Runtime,exec"),
                "readResolve/readExternal/非 transient 字段应形成反序列化链:\n" + positiveFindings);

        String replace = """
                package app;
                public final class ReplaceGadget implements java.io.Serializable {
                    private String command;
                    private Object writeReplace() throws Exception {
                        Runtime.getRuntime().exec(this.command);
                        return this;
                    }
                }
                """;
        String fakeExternal = """
                package app;
                public final class FakeExternal implements java.io.Serializable {
                    private String command;
                    public void readExternal(java.io.ObjectInput in) throws java.io.IOException {
                        Runtime.getRuntime().exec(this.command);
                    }
                }
                """;
        String excludedFields = """
                package app;
                public final class ExcludedFields implements java.io.Serializable {
                    private transient String transientCommand;
                    private static String staticCommand;
                    private void readObject(java.io.ObjectInputStream in) throws Exception {
                        Runtime.getRuntime().exec(this.transientCommand);
                        Runtime.getRuntime().exec(staticCommand);
                        in.defaultReadObject();
                    }
                }
                """;
        Path negativeJar = compileToJar(tmp.resolve("lifecycle-negative.jar"), Map.of(
                "app.ReplaceGadget", replace, "app.FakeExternal", fakeExternal,
                "app.ExcludedFields", excludedFields));
        Path negativeOut = tmp.resolve("negative-out");
        ScanPipeline.run(negativeJar, null, negativeOut, null, false, true, null, false, 20);
        String negativeFindings = Files.readString(
                negativeOut.resolve("findings").resolve("findings.csv"));
        assertFalse(negativeFindings.contains("app/ReplaceGadget,writeReplace"),
                "writeReplace 是序列化侧回调，不能成为反序列化根:\n" + negativeFindings);
        assertFalse(negativeFindings.contains("app/FakeExternal,readExternal"),
                "Serializable 类的同名方法不是 Externalizable 回调:\n" + negativeFindings);
        assertFalse(negativeFindings.contains("app/ExcludedFields,readObject"),
                "transient/static 字段不得制造可控字段流:\n" + negativeFindings);
    }

    @Test
    void nativeCallbackUsesSameReceiverAndRejectsUnrelatedMethods(@TempDir Path tmp)
            throws Exception {
        String bridge = """
                package app;
                public final class NativeBridge implements java.io.Serializable {
                    private String command;
                    public native void invokeNative();
                    public void onCallback() throws Exception {
                        Runtime.getRuntime().exec(this.command);
                    }
                    private void hiddenCallback() throws Exception {
                        Runtime.getRuntime().exec(this.command);
                    }
                    private void readObject(java.io.ObjectInputStream in) throws Exception {
                        invokeNative();
                        in.defaultReadObject();
                    }
                }
                """;
        String unrelated = """
                package app;
                public final class UnrelatedNativeTarget {
                    public void onCallback() throws Exception {
                        Runtime.getRuntime().exec("not-a-real-command");
                    }
                }
                """;
        Path jar = compileToJar(tmp.resolve("native-callback.jar"), Map.of(
                "app.NativeBridge", bridge, "app.UnrelatedNativeTarget", unrelated));
        Path out = tmp.resolve("out");
        ScanPipeline.run(jar, null, out, null, false, true, null, false, 20);
        String findings = Files.readString(out.resolve("findings").resolve("findings.csv"));
        assertTrue(findings.contains("app/NativeBridge,readObject")
                        && findings.contains("app/NativeBridge.onCallback")
                        && findings.contains("native=1")
                        && findings.contains("java/lang/Runtime,exec"),
                "native 回调应保留同 receiver 的显式 JNI 跳转:\n" + findings);
        assertFalse(findings.contains("hiddenCallback"),
                "private callback 不满足 JNI 回调的公开目标契约:\n" + findings);
        assertFalse(findings.contains("app/UnrelatedNativeTarget.onCallback"),
                "native callback 不得跨到无关 receiver:\n" + findings);
    }

    @Test
    void reflectiveLookupWithoutFrameworkKeepsNoPathPruning(@TempDir Path tmp) throws Exception {
        // 无框架类在 classpath：app 内的常量类反射查找不得触发"框架反射供给"（历史缺陷：门恒开，
        // 全应用 public 方法入闭包，NO_PATH 剪枝失效）
        String reflective = """
                package app;
                public class Reflective {
                    public Object poke() throws Exception {
                        java.lang.reflect.Method m = String.class.getMethod("hashCode");
                        return m.invoke("x");
                    }
                }
                """;
        String isolated = """
                package app;
                public class Isolated implements java.io.Serializable {
                    private String cmd;
                    public void fetch() {
                        try {
                            Runtime.getRuntime().exec(this.cmd);
                        } catch (Exception ignored) {
                        }
                    }
                }
                """;
        Path jar = compileToJar(tmp.resolve("gate.jar"),
                Map.of("app.Reflective", reflective, "app.Isolated", isolated));
        Path out = tmp.resolve("out");
        ScanPipeline.run(jar, null, out, null, false, true, null, false, 20);
        String sinks = Files.readString(out.resolve("evidence").resolve("sinks.csv"));
        assertTrue(sinks.lines().anyMatch(l -> l.contains("app/Isolated") && l.contains("fetch")
                        && l.contains("NO_PATH")),
                "无框架时不可达入口的 sink 宿主应判 NO_PATH:\n" + sinks);
        String findings = Files.readString(out.resolve("findings").resolve("findings.csv"));
        assertFalse(findings.contains("app/Isolated,fetch"), "不可达链不得出现在 findings");
    }
}
