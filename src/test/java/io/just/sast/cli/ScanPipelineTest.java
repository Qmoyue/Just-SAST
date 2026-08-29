package io.just.sast.cli;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.tools.JavaCompiler;
import javax.tools.SimpleJavaFileObject;
import javax.tools.ToolProvider;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 端到端用户流：源码 → 内存编译 → jar → CLI 扫描 → CSV 断言。
 * 覆盖：readObject 入口链检出、equals 无触发链被剪枝、框架桥接中间路径、SafeConfig 顺序抑制。
 */
class ScanPipelineTest {

    @Test
    void invalidTargetIsReportedAsUsageErrorBeforeAnalysis() {
        assertThrows(ScanPipeline.UsageException.class, () -> ScanPipeline.run(
                Path.of("target", "definitely-missing-input.jar"), List.of(),
                Path.of("target", "just-test-output"), null,
                false, true, null, false, 0));
    }

    /** 内存 Java 源。 */
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

    /** 编译到临时目录并打包为 jar。 */
    private static Path compileToJar(Path jarFile, Map<String, String> sources) throws Exception {
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        File classesDir = Files.createTempDirectory("just-test-classes").toFile();
        javax.tools.DiagnosticCollector<javax.tools.JavaFileObject> diagnostics =
                new javax.tools.DiagnosticCollector<>();
        try (javax.tools.StandardJavaFileManager fm =
                     compiler.getStandardFileManager(diagnostics, null, null)) {
            fm.setLocation(javax.tools.StandardLocation.CLASS_OUTPUT, List.of(classesDir));
            boolean ok = compiler.getTask(null, fm, diagnostics, null, null,
                    sources.entrySet().stream()
                            .map(e -> (javax.tools.JavaFileObject) new Source(e.getKey(), e.getValue()))
                            .toList())
                    .call();
            if (!ok) {
                diagnostics.getDiagnostics().forEach(d ->
                        System.err.println("[fixture-compile] " + d));
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

    private static final String GADGET = """
            package app;
            public class Gadget implements java.io.Serializable {
                private String cmd;
                private void readObject(java.io.ObjectInputStream in) throws Exception {
                    Runtime.getRuntime().exec(this.cmd);
                    in.defaultReadObject();
                }
            }
            """;

    private static final String EQ_GADGET = """
            package app;
            public class EqGadget implements java.io.Serializable {
                private String cmd;
                public boolean equals(Object o) {
                    try {
                        Runtime.getRuntime().exec(this.cmd);
                    } catch (Exception ignored) {
                    }
                    return true;
                }
            }
            """;

    @Test
    void findsReadObjectChainAndPrunesUntriggeredEquals(@TempDir Path tmp) throws Exception {
        Path jar = compileToJar(tmp.resolve("app.jar"),
                Map.of("app.Gadget", GADGET, "app.EqGadget", EQ_GADGET));
        Path out = tmp.resolve("out");
        ScanPipeline.run(jar, null, out, null, false, true, null, true, 20);
        String findings = Files.readString(out.resolve("findings").resolve("findings.csv"));
        String calibrations = Files.readString(out.resolve("evidence").resolve("calibrations.csv"));
        // 正向链：app/Gadget.readObject → Runtime.exec（rule JUST-SINK-COMMAND-EXEC-RUNTIME）
        assertTrue(findings.contains("app/Gadget,readObject") && findings.contains("java/lang/Runtime,exec"),
                "readObject 链应检出：\n" + findings);
        // equals 入口无反序列化可达触发者：链被剪枝（no-trigger）而非上报
        assertTrue(calibrations.contains("app/EqGadget") && calibrations.contains("no-trigger"),
                "无触发 equals 链应进 calibrations.csv：\n" + calibrations);
        assertFalse(findings.contains("app/EqGadget,equals"), "被剪枝链不得出现在 findings");
    }

    @Test
    void deserializeSourceReturnSeedsForwardTaint(@TempDir Path tmp) throws Exception {
        String parser = """
                package app;
                public class Parser {
                    public static String parse(String value) { return value; }
                }
                """;
        String app = """
                package app;
                public class SourceApp {
                    public static void run() throws Exception {
                        String command = Parser.parse("echo");
                        Runtime.getRuntime().exec(command);
                    }
                }
                """;
        String rules = """
                rules:
                  - id: T-SOURCE
                    kind: source
                    bridge: deserialize
                    match:
                      call: { owner: "app/Parser", name: "parse" }
                  - id: T-SINK
                    kind: sink
                    category: COMMAND_EXEC
                    severity: HIGH
                    match:
                      call: { owner: "java/lang/Runtime", name: "exec" }
                    tainted: [{arg: 0}]
                """;
        Path jar = compileToJar(tmp.resolve("source.jar"),
                Map.of("app.Parser", parser, "app.SourceApp", app));
        Path rulesFile = tmp.resolve("source-rules.yaml");
        Files.write(rulesFile, rules.getBytes(StandardCharsets.UTF_8));
        Path out = tmp.resolve("out");
        ScanPipeline.run(jar, null, out, rulesFile, false, true, null, false, 0);
        String findings = Files.readString(out.resolve("findings").resolve("findings.csv"));
        assertTrue(findings.contains("app/SourceApp,run")
                        && findings.contains("java/lang/Runtime,exec"),
                "deserialize source 的返回值应作为前向污点入口闭合到 sink:\n" + findings);
    }

    @Test
    void deserializeSourceModelsGenericBeanSetterInputWithoutOpeningEveryPublicMethod(@TempDir Path tmp)
            throws Exception {
        String parser = """
                package fake;
                public class Parser {
                    public static Object parse(String value) { return value; }
                }
                """;
        String api = """
                package app;
                public class Api {
                    public static Object parse(String value) { return fake.Parser.parse(value); }
                }
                """;
        String bean = """
                package app;
                public class Bean {
                    public void setCommand(String command) throws Exception {
                        Runtime.getRuntime().exec(command);
                    }
                }
                """;
        String unrelated = """
                package app;
                public class Unrelated {
                    public void run(String command) throws Exception {
                        Runtime.getRuntime().exec(command);
                    }
                }
                """;
        String rules = """
                rules:
                  - id: T-BEAN-SOURCE
                    kind: source
                    bridge: deserialize
                    match:
                      call: { owner: "fake/Parser", name: "parse" }
                  - id: T-RUNTIME-SINK
                    kind: sink
                    category: COMMAND_EXEC
                    severity: HIGH
                    match:
                      call: { owner: "java/lang/Runtime", name: "exec" }
                    tainted: [{arg: 0}]
                """;
        Path jar = compileToJar(tmp.resolve("bean.jar"), Map.of(
                "fake.Parser", parser, "app.Api", api, "app.Bean", bean, "app.Unrelated", unrelated));
        Path rulesFile = tmp.resolve("bean-rules.yaml");
        Files.write(rulesFile, rules.getBytes(StandardCharsets.UTF_8));
        Path out = tmp.resolve("out");

        ScanPipeline.run(jar, null, out, rulesFile, false, true, null, false, 0);

        String findings = Files.readString(out.resolve("findings").resolve("findings.csv"));
        assertTrue(findings.contains("app/Bean,setCommand")
                        && findings.contains("java/lang/Runtime,exec"),
                "deserialize source 应建立通用 setter 输入边界：\n" + findings);
        assertFalse(findings.contains("app/Unrelated,run"),
                "普通公共方法不能仅因存在 source 就被泛化为外部输入：\n" + findings);
    }

    @Test
    void frameworkBridgeKeepsPipelineHopsAndSafeConfigSuppressesInOrder(@TempDir Path tmp) throws Exception {
        String fw = """
                package fake;
                public class Fw {
                    public void lock() {}
                    public Object load(String s) throws Exception { return run(s); }
                    private Object run(String s) throws Exception {
                        java.lang.reflect.Method m = String.class.getMethod("hashCode");
                        return m.invoke(s, new Object[0]);
                    }
                }
                """;
        String safeApp = """
                package app;
                public class SafeApp implements java.io.Serializable {
                    private void readObject(java.io.ObjectInputStream in) throws Exception {
                        fake.Fw fw = new fake.Fw();
                        fw.lock();   // 配置先于入口 → 抑制
                        fw.load("x");
                        in.defaultReadObject();
                    }
                }
                """;
        String unsafeApp = """
                package app;
                public class UnsafeApp implements java.io.Serializable {
                    private void readObject(java.io.ObjectInputStream in) throws Exception {
                        fake.Fw fw = new fake.Fw();
                        fw.load("x"); // 入口先于 lock → 不抑制
                        fw.lock();
                        in.defaultReadObject();
                    }
                }
                """;
        String rules = """
                rules:
                  - id: T-SINK
                    kind: sink
                    category: REFLECTIVE_INVOKE
                    severity: HIGH
                    match:
                      call: { owner: "java/lang/reflect/Method", name: "invoke" }
                    tainted: [{arg: 0}]
                  - id: T-SOURCE
                    kind: source
                    bridge: deserialize
                    match:
                      call: { owner: "fake/Fw", name: "load" }
                    safe-config: { owner: "fake/Fw", methods: [lock] }
                  - id: T-ENTRY
                    kind: magic-entry
                    entryKind: readObject
                    match:
                      method: { name: "readObject", descriptor: "(Ljava/io/ObjectInputStream;)V", access: private }
                      class: { implements: "java/io/Serializable" }
                """;
        Path jar = compileToJar(tmp.resolve("fw.jar"), Map.of(
                "fake.Fw", fw, "app.SafeApp", safeApp, "app.UnsafeApp", unsafeApp));
        Path rulesFile = tmp.resolve("rules.yaml");
        Files.write(rulesFile, rules.getBytes(StandardCharsets.UTF_8));
        Path out = tmp.resolve("out");
        ScanPipeline.run(jar, null, out, rulesFile, false, true, null, true, 20);
        String findings = Files.readString(out.resolve("findings").resolve("findings.csv"));
        // UnsafeApp：入口链保留，且框架管线中间跳（Fw.load → Fw.run → Method.invoke）保留
        assertTrue(findings.contains("app/UnsafeApp,readObject"), "未安全配置的入口链应上报：\n" + findings);
        assertTrue(findings.contains("fake/Fw.run"), "管线中间跳应保留：\n" + findings);
        // SafeApp：先 lock 后 load → safe-config 抑制
        assertFalse(findings.contains("app/SafeApp,readObject"),
                "安全配置先于入口的链应被抑制：\n" + findings);
        String calibrations = Files.readString(out.resolve("evidence").resolve("calibrations.csv"));
        assertTrue(calibrations.contains("app/SafeApp") && calibrations.contains("safe-config"),
                "抑制理由应进 calibrations.csv：\n" + calibrations);
    }

    @Test
    void exitCodeZeroOnSuccess(@TempDir Path tmp) throws Exception {
        Path jar = compileToJar(tmp.resolve("app.jar"), Map.of("app.Gadget", GADGET));
        ScanPipeline.ScanResult result = ScanPipeline.run(jar, null, tmp.resolve("out"), null,
                false, true, null, true, 20);
        assertTrue(result.exitCode() == 0);
        assertFalse(result.chains().isEmpty());
        Path output = tmp.resolve("out");
        String metadata = Files.readString(output.resolve("meta").resolve("scan-metadata.json"));
        assertTrue(metadata.contains("\"completeness\"")
                        && metadata.contains("\"verification\":\"")
                        && metadata.contains("\"phase_ms\""),
                "扫描元数据必须公开完整性、验证模式和阶段耗时：\n" + metadata);
        assertTrue(Files.exists(output.resolve("index.md"))
                        && Files.exists(output.resolve("findings").resolve("findings.md"))
                        && Files.exists(output.resolve("verification").resolve("payload.json"))
                        && Files.exists(output.resolve("verification").resolve("payload.md")),
                "生产扫描必须生成根索引和分类后的阅读产物");
        String index = Files.readString(output.resolve("index.md"));
        assertTrue(index.contains("[Payload review](verification/payload.md)")
                        && index.contains("[Dynamic verification](verification/dynamic-verification.json)"),
                "根索引必须暴露人类/agent 两条阅读入口：\n" + index);
    }
}
