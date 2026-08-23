package io.just.sast.frontend.asm;

import io.just.sast.util.IoUtil;
import io.just.sast.util.JustLogger;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;

/**
 * 读取 JAR / class 目录 / 单个 class 文件。
 * 支持 Spring Boot fat jar：BOOT-INF/classes 下的类 + BOOT-INF/lib 下的嵌套 jar 递归解析。
 */
public final class JarReader {

    /** 嵌套 jar 递归深度上限，防 zip 炸弹。 */
    private static final int MAX_NESTING = 4;
    /** 单次扫描的 class 条目上限。 */
    private static final int MAX_CLASSES = 100_000;

    private static final String[] CLASS_PREFIXES = {"BOOT-INF/classes/", "WEB-INF/classes/"};
    private static final String[] LIB_PREFIXES = {"BOOT-INF/lib/", "WEB-INF/lib/"};
    private static final String SKIPPED_MULTIRELEASE = "META-INF/versions/";

    public List<ClassBytes> read(Path target) throws IOException {
        if (!Files.exists(target)) {
            throw new IOException("目标不存在: " + target);
        }
        if (Files.isDirectory(target)) {
            List<ClassBytes> out = new ArrayList<>();
            readDirectory(target, out, target.getFileName().toString());
            return out;
        }
        String name = target.getFileName().toString();
        if (name.endsWith(".jar") || name.endsWith(".zip") || name.endsWith(".war")) {
            List<ClassBytes> out = new ArrayList<>();
            readJarFile(target, out, name, 0);
            return out;
        }
        if (name.endsWith(".class")) {
            return List.of(new ClassBytes(classNameFromPath(name), Files.readAllBytes(target), name));
        }
        throw new IOException("不支持的输入: " + target + "（仅支持 .jar/.zip/.class/目录）");
    }

    private void readDirectory(Path dir, List<ClassBytes> out, String origin) throws IOException {
        try (Stream<Path> stream = Files.walk(dir)) {
            stream.filter(Files::isRegularFile)
                    .filter(p -> p.getFileName().toString().endsWith(".class"))
                    .forEach(p -> {
                        try {
                            String rel = dir.relativize(p).toString().replace('\\', '/');
                            out.add(new ClassBytes(classNameFromPath(rel), Files.readAllBytes(p), origin));
                        } catch (IOException e) {
                            JustLogger.warn("读取失败 {}: {}", p, e.getMessage());
                        }
                    });
        }
    }

    private void readJarFile(Path jar, List<ClassBytes> out, String origin, int depth) throws IOException {
        try (ZipFile zip = new ZipFile(jar.toFile())) {
            var entries = zip.entries();
            while (entries.hasMoreElements()) {
                if (out.size() > MAX_CLASSES) {
                    JustLogger.warn("class 条目超过上限 {}，停止解析 {}", MAX_CLASSES, jar);
                    return;
                }
                ZipEntry entry = entries.nextElement();
                String path = entry.getName();
                if (path.startsWith(SKIPPED_MULTIRELEASE)) {
                    continue; // multi-release 变体暂不解析
                }
                if (entry.isDirectory()) {
                    continue;
                }
                if (path.endsWith(".class")) {
                    out.add(new ClassBytes(stripClassPrefix(path), IoUtil.readAll(zip.getInputStream(entry)),
                            origin + "!" + path));
                } else if (depth < MAX_NESTING && isNestedLib(path)) {
                    byte[] nested = IoUtil.readAll(zip.getInputStream(entry));
                    readNestedJar(nested, out, origin + "!" + path, depth + 1);
                }
            }
        }
    }

    /** 嵌套 jar 内继续递归：lib 内的 class + 更深层的 jar（jar-in-jar-in-lib，至 MAX_NESTING 层）。 */
    private void readNestedJar(byte[] bytes, List<ClassBytes> out, String origin, int depth) throws IOException {
        try (ZipInputStream zip = new ZipInputStream(new ByteArrayInputStream(bytes))) {
            ZipEntry entry;
            while ((entry = zip.getNextEntry()) != null) {
                if (out.size() > MAX_CLASSES) {
                    JustLogger.warn("class 条目超过上限 {}，停止解析嵌套 jar", MAX_CLASSES);
                    return;
                }
                String path = entry.getName();
                if (path.startsWith(SKIPPED_MULTIRELEASE) || entry.isDirectory()) {
                    continue;
                }
                if (path.endsWith(".class")) {
                    out.add(new ClassBytes(stripClassPrefix(path), IoUtil.readAll(zip), origin + "!" + path));
                } else if (path.endsWith(".jar") && depth < MAX_NESTING) {
                    readNestedJar(IoUtil.readAll(zip), out, origin + "!" + path, depth + 1);
                }
            }
        }
    }

    private static boolean isNestedLib(String path) {
        for (String prefix : LIB_PREFIXES) {
            if (path.startsWith(prefix) && path.endsWith(".jar")) {
                return true;
            }
        }
        return false;
    }

    private static String stripClassPrefix(String path) {
        for (String prefix : CLASS_PREFIXES) {
            if (path.startsWith(prefix)) {
                path = path.substring(prefix.length());
                break;
            }
        }
        return classNameFromPath(path);
    }

    private static String classNameFromPath(String path) {
        return path.endsWith(".class") ? path.substring(0, path.length() - 6) : path;
    }
}
