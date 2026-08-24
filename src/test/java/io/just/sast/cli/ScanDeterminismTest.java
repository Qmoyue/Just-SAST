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

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * NFR8 确定性契约：同一输入两次扫描，findings/chains 输出逐字节一致。
 * 这是 diff 功能与回归基线的前提——精扫并行批的事实替换必须与处理顺序无关。
 */
class ScanDeterminismTest {

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
        File classesDir = Files.createTempDirectory("just-det-classes").toFile();
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

    /** 多入口 + 容器投毒 + 接口分发：制造等长路径平局，检验代表路径选择的顺序无关性。 */
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

    private static final String FIELD_GADGET = """
            package app;
            public class FieldGadget implements java.io.Serializable {
                private Gadget inner;
                private String cmd;
                public String toString() {
                    try {
                        Runtime.getRuntime().exec(this.cmd);
                    } catch (Exception ignored) {
                    }
                    return "x";
                }
            }
            """;

    @Test
    void repeatedScanProducesIdenticalOutput(@TempDir Path tmp) throws Exception {
        Path jar = compileToJar(tmp.resolve("app.jar"),
                Map.of("app.Gadget", GADGET, "app.FieldGadget", FIELD_GADGET));
        Path out1 = tmp.resolve("out1");
        Path out2 = tmp.resolve("out2");
        ScanPipeline.run(jar, null, out1, null, false, true, null, true);
        ScanPipeline.run(jar, null, out2, null, false, true, null, true);
        for (String file : List.of("findings.csv", "chains.csv", "edges.csv", "calibrations.csv")) {
            assertEquals(Files.readString(out1.resolve(file)), Files.readString(out2.resolve(file)),
                    file + " 两次扫描应逐字节一致（NFR8）");
        }
    }
}
