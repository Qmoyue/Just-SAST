package io.just.sast.frontend.asm;

import io.just.sast.model.ClassInfo;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * jrt-fs 外部挂载契约（--jdk-home Java 9+ 真实现）：
 * 默认用运行时自身 home 验证挂载路径；提供 -Djust.test.jdk=<home>（如 jabba JDK 11/21）时
 * 按 release 版本推导类存在性断言，证明读到的是目标镜像而非运行时。
 */
class JrtExternalMountTest {

    @Test
    void mountsExternalImageAndLoadsCoreClass() throws Exception {
        Path home = Path.of(System.getProperty("java.home"));
        JrtClassSource jrt = JrtClassSource.external(home);
        ClassInfo object = jrt.load("java/lang/Object");
        assertNotNull(object, "外部挂载应能读 java/lang/Object");
        assertEquals("java/lang/Object", object.internalName());
        assertTrue(jrt.listAll(JrtClassSource.DESER_MODULES).size() > 1000,
                "全量枚举模块类应达到千级");
    }

    @Test
    void crossVersionImageReflectsTargetNotRuntime() throws Exception {
        // 例：-Djust.test.jdk=C:/Users/29263/.jabba/jdk/temurin@11.0.31
        String jdk = System.getProperty("just.test.jdk");
        Assumptions.assumeTrue(jdk != null, "仅当提供 -Djust.test.jdk 时验证跨版本挂载");
        Path home = Path.of(jdk);
        Assumptions.assumeTrue(Files.exists(home.resolve("lib").resolve("jrt-fs.jar")),
                "Java 8 走 rt.jar 路线，无 jrt-fs.jar");
        int targetMajor = releaseMajor(home);
        JrtClassSource jrt = JrtClassSource.external(home);
        // java/lang/Record 于 JDK 16 引入：目标 <16 应缺失、≥16 应存在（与运行时版本无关）
        ClassInfo record = jrt.load("java/lang/Record");
        if (targetMajor < 16) {
            assertTrue(record == null, "JDK " + targetMajor + " 镜像不应含 java/lang/Record"
                    + "（若读到说明挂载的是运行时而非目标镜像）");
        } else {
            assertNotNull(record, "JDK " + targetMajor + " 镜像应含 java/lang/Record");
        }
    }

    private static int releaseMajor(Path home) throws Exception {
        for (String line : Files.readAllLines(home.resolve("release"))) {
            if (line.startsWith("JAVA_VERSION=\"")) {
                String v = line.substring("JAVA_VERSION=\"".length()).replace("\"", "").trim();
                int idx = v.indexOf('.');
                return Integer.parseInt(idx > 0 ? v.substring(0, idx) : v);
            }
        }
        throw new IllegalStateException("release 文件无 JAVA_VERSION: " + home);
    }
}
