package io.just.sast.frontend.asm;

import io.just.sast.model.ClassInfo;
import io.just.sast.model.JdkClassSource;
import io.just.sast.util.JustLogger;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * 目标 JDK 类来源（--jdk-home 指定）：
 * - Java 8 及以下（有 rt.jar）：从 $jdkHome/jre/lib/ 或 $jdkHome/lib/ 读 rt.jar + 辅助 jar
 * - Java 9+（有 lib/jrt-fs.jar）：挂载目标 JDK 的 jrt-fs.jar 对其模块镜像打开文件系统——
 *   读取的是目标 JDK 的类而非运行时的（JDK 版本决定 gadget 存亡，不可用运行时顶替）
 */
public final class TargetJdkSource implements JdkClassSource {

    private final ClassFileReader reader = new ClassFileReader();
    /** 内部名 → 所在 jar 路径（Java 8 模式） */
    private final Map<String, Path> classToJar = new HashMap<>();
    private final List<Path> coreJars = new ArrayList<>();
    private boolean legacyIndexBuilt;
    /** Java 9+ 模式的目标镜像 */
    private final JrtClassSource jrtDelegate;
    private final String jdkDescription;

    public TargetJdkSource(Path jdkHome) throws IOException {
        Path home = jdkHome.toAbsolutePath().normalize();
        if (!Files.isDirectory(home)) {
            throw new IOException("--jdk-home 不是目录: " + home);
        }
        // Java 8 及以下：找 rt.jar（JDK 在 $home/jre/lib/rt.jar，JRE 在 $home/lib/rt.jar）
        Path rtJar = home.resolve("jre").resolve("lib").resolve("rt.jar");
        if (!Files.exists(rtJar)) {
            rtJar = home.resolve("lib").resolve("rt.jar");
        }
        if (Files.exists(rtJar)) {
            jdkDescription = detectLegacyVersion(home) + "（rt.jar 模式）";
            coreJars.add(rtJar);
            // 辅助 jar：jce / jsse / charsets / resources（反序列化相关类可能分布在多个 jar）
            Path libDir = rtJar.getParent();
            for (String aux : List.of("jce.jar", "jsse.jar", "charsets.jar", "resources.jar")) {
                Path auxPath = libDir.resolve(aux);
                if (Files.exists(auxPath)) {
                    coreJars.add(auxPath);
                }
            }
            jrtDelegate = null;
            JustLogger.info("目标 JDK 来源：{}（{} 个核心 jar：{}）",
                    jdkDescription, coreJars.size(),
                    coreJars.stream().map(p -> p.getFileName().toString())
                            .collect(java.util.stream.Collectors.joining(", ")));
            return;
        }
        // Java 9+：挂载目标 JDK 的 jrt-fs（真实现，非运行时回退）
        if (Files.exists(home.resolve("release"))) {
            jrtDelegate = JrtClassSource.external(home);
            jdkDescription = readReleaseVersion(home) + "（jrt-fs 外部挂载）";
            JustLogger.info("目标 JDK 来源：{}（读取目标镜像，非运行时）", jdkDescription);
            return;
        }
        throw new IOException("--jdk-home 无法识别 JDK 结构（既无 rt.jar 也无 release 文件）: " + home);
    }

    @Override
    public ClassInfo load(String internalName) {
        ClassBytes bytes = loadBytes(internalName);
        if (bytes == null) {
            return null;
        }
        try {
            return reader.read(bytes.bytes());
        } catch (Exception e) {
            JustLogger.debug("目标 JDK 类加载失败 {}: {}", internalName, e.getMessage());
            return null;
        }
    }

    /** 按内部名读取原始 class，避免完整模式预先 materialize 整个 JDK。 */
    public ClassBytes loadBytes(String internalName) {
        if (jrtDelegate != null) {
            return jrtDelegate.loadBytes(internalName);
        }
        // Java 8 模式：从 classToJar 索引（懒构建）或遍历 jar 查找
        Path jarPath = classToJar.get(internalName);
        if (jarPath == null) {
            jarPath = findInJars(internalName);
            if (jarPath == null) {
                return null;
            }
            classToJar.put(internalName, jarPath);
        }
        try (ZipFile zip = new ZipFile(jarPath.toFile())) {
            ZipEntry entry = zip.getEntry(internalName + ".class");
            if (entry == null) {
                return null;
            }
            return new ClassBytes(internalName, zip.getInputStream(entry).readAllBytes(),
                    "jdk:" + jarPath.getFileName());
        } catch (Exception e) {
            JustLogger.debug("目标 JDK 类加载失败 {}: {}", internalName, e.getMessage());
            return null;
        }
    }

    /** 枚举全部核心 jar 的类（替代 jrt 的 listAll，全量分析用）。 */
    public List<ClassBytes> listAll() throws IOException {
        if (jrtDelegate != null) {
            return jrtDelegate.listAll(JrtClassSource.DESER_MODULES);
        }
        List<ClassBytes> result = new ArrayList<>();
        for (Path jar : coreJars) {
            try (ZipFile zip = new ZipFile(jar.toFile())) {
                var entries = zip.entries();
                while (entries.hasMoreElements()) {
                    ZipEntry entry = entries.nextElement();
                    String name = entry.getName();
                    if (entry.isDirectory() || !name.endsWith(".class")
                            || name.startsWith("META-INF/versions/")) {
                        continue;
                    }
                    String className = name.substring(0, name.length() - 6);
                    classToJar.putIfAbsent(className, jar);
                    result.add(new ClassBytes(className,
                            zip.getInputStream(entry).readAllBytes(), "jdk:" + jar.getFileName()));
                }
            }
        }
        if (jrtDelegate == null) {
            legacyIndexBuilt = true;
        }
        return result;
    }

    public String description() {
        return jdkDescription;
    }

    private Path findInJars(String internalName) {
        ensureLegacyIndex();
        return classToJar.get(internalName);
    }

    /**
     * Build only the Java 8 central-directory index once. The old path reopened every core
     * jar for every unresolved reference during closure planning; this is metadata-only and
     * avoids retaining any class bytes while removing that repeated disk scan.
     */
    private synchronized void ensureLegacyIndex() {
        if (legacyIndexBuilt) {
            return;
        }
        for (Path jar : coreJars) {
            try (ZipFile zip = new ZipFile(jar.toFile())) {
                var entries = zip.entries();
                while (entries.hasMoreElements()) {
                    ZipEntry entry = entries.nextElement();
                    String name = entry.getName();
                    if (entry.isDirectory() || !name.endsWith(".class")
                            || name.startsWith("META-INF/versions/")) {
                        continue;
                    }
                    classToJar.putIfAbsent(name.substring(0, name.length() - 6), jar);
                }
            } catch (IOException e) {
                JustLogger.debug("目标 JDK 索引构建失败 {}: {}", jar, e.getMessage());
            }
        }
        legacyIndexBuilt = true;
    }

    /** 从 $jdkHome/release 或目录名推断版本描述。 */
    private static String detectLegacyVersion(Path home) {
        // 尝试读 jre/release（部分发行版有）
        for (Path release : List.of(home.resolve("release"), home.resolve("jre").resolve("release"))) {
            String version = readVersionFromRelease(release);
            if (version != null) {
                return "JDK " + version;
            }
        }
        // 回退：目录名推断（如 jdk8u202 → JDK 8u202）
        String name = home.getFileName().toString().toLowerCase();
        if (name.contains("jdk7") || name.contains("jre7")) {
            return "JDK 7";
        }
        if (name.contains("jdk8") || name.contains("jre8")) {
            return "JDK 8";
        }
        return "JDK (legacy, " + name + ")";
    }

    private static String readReleaseVersion(Path home) {
        String version = readVersionFromRelease(home.resolve("release"));
        return version != null ? "JDK " + version : "JDK 9+";
    }

    private static String readVersionFromRelease(Path releaseFile) {
        try {
            for (String line : Files.readAllLines(releaseFile)) {
                if (line.startsWith("JAVA_VERSION=")) {
                    return line.substring("JAVA_VERSION=".length()).replace("\"", "").trim();
                }
            }
        } catch (IOException ignored) {
        }
        return null;
    }
}
