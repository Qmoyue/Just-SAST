package io.just.sast.frontend.asm;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 输入解析契约：Spring Boot 前缀剥离、嵌套 jar 递归（jar-in-jar-in-lib）。 */
class JarReaderTest {

    private static byte[] zip(Map<String, Function<String, byte[]>> entries) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(out)) {
            for (var e : entries.entrySet()) {
                zip.putNextEntry(new ZipEntry(e.getKey()));
                zip.write(e.getValue().apply(e.getKey()));
                zip.closeEntry();
            }
        }
        return out.toByteArray();
    }

    private static byte[] markerClass(String name) {
        return ("fake-class:" + name).getBytes();
    }

    @Test
    void bootInfPrefixStripped(@TempDir Path tmp) throws Exception {
        Path jar = tmp.resolve("boot.jar");
        Files.write(jar, zip(Map.of(
                "BOOT-INF/classes/com/app/Main.class", JarReaderTest::markerClass)));
        List<ClassBytes> classes = new JarReader().read(jar);
        assertEquals(1, classes.size());
        assertEquals("com/app/Main", classes.get(0).className(), "BOOT-INF/classes 前缀应剥离");
    }

    @Test
    void nestedJarRecursesBeyondOneLevel(@TempDir Path tmp) throws Exception {
        // 最深层的 jar 里有 class：lib 内嵌套 jar → 内嵌套 jar 再内 class（深度 2 的 jar-in-jar-in-lib）
        byte[] innermost = zip(Map.of("deep/Secret.class", JarReaderTest::markerClass));
        byte[] middle = zip(Map.of(
                "BOOT-INF/lib/middle.jar", k -> innermost,
                "BOOT-INF/classes/com/app/App.class", JarReaderTest::markerClass));
        Path jar = tmp.resolve("fat.jar");
        Files.write(jar, middle);
        List<ClassBytes> classes = new JarReader().read(jar);
        List<String> names = classes.stream().map(ClassBytes::className).toList();
        assertTrue(names.contains("com/app/App"), "顶层 class 在: " + names);
        assertTrue(names.contains("deep/Secret"), "二层嵌套 jar 的 class 也应被解析: " + names);
    }
}
