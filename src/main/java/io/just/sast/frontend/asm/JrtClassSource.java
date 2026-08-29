package io.just.sast.frontend.asm;

import io.just.sast.model.ClassInfo;
import io.just.sast.model.JdkClassSource;
import io.just.sast.util.JustLogger;

import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.DirectoryStream;
import java.nio.file.FileSystem;
import java.nio.file.FileSystemNotFoundException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.spi.FileSystemProvider;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.stream.Stream;

/**
 * 通过 jrtfs 读取 JDK 模块镜像类：按需懒加载 + 全量模块枚举。
 * 两种构造：runtime()（运行时自身镜像）/ external(jdkHome)（挂载目标 JDK 的 lib/jrt-fs.jar
 * 并对其 runtime image 打开文件系统——读的是目标 JDK 的类，而非运行时的）。
 * JDK 版本决定 gadget 存亡（如新 JDK 移除/加固的类），--jdk-home 场景必须读目标镜像。
 */
public final class JrtClassSource implements JdkClassSource {

    /** 与反序列化链相关的 JDK 模块（全量加载集）。 */
    public static final List<String> DESER_MODULES = List.of(
            "java.base", "java.naming", "java.rmi", "java.management", "java.scripting", "java.sql",
            // TemplatesImpl and the XML transformer implementation are part of
            // the JDK XML module. They are a common deserialization sink even
            // when the application bytecode reaches them through reflection,
            // so omitting java.xml makes the default full scan incomplete.
            "java.xml");

    private final ClassFileReader reader = new ClassFileReader();
    private final FileSystem jrt;
    private final Map<String, String> moduleIndex = new HashMap<>();
    private boolean fullIndexBuilt;

    private JrtClassSource(FileSystem jrt) {
        this.jrt = jrt;
    }

    /** 运行时 JDK 自身的 jrt 文件系统（JVM 启动即存在）。 */
    public static JrtClassSource runtime() {
        try {
            return new JrtClassSource(FileSystems.getFileSystem(URI.create("jrt:/")));
        } catch (FileSystemNotFoundException e) {
            throw new IllegalStateException("运行时无 jrt 文件系统（非模块化 JDK？）", e);
        }
    }

    /**
     * 外部目标 JDK：加载其 lib/jrt-fs.jar（独立 URLClassLoader，避免被运行时内置 provider 抢先），
     * 用该 provider 以 jrt:/ URI + java.home 环境参数对目标镜像打开文件系统
     * （实测 Path 变体在 jrt-fs 上未实现，URI 变体 + java.home 是可行路径）。
     */
    public static JrtClassSource external(Path jdkHome) throws IOException {
        Path jrtFsJar = jdkHome.resolve("lib").resolve("jrt-fs.jar");
        if (!Files.exists(jrtFsJar)) {
            throw new IOException("目标 JDK 缺少 lib/jrt-fs.jar: " + jdkHome);
        }
        URLClassLoader loader = new URLClassLoader(new URL[] {jrtFsJar.toUri().toURL()},
                ClassLoader.getPlatformClassLoader());
        for (FileSystemProvider candidate : ServiceLoader.load(FileSystemProvider.class, loader)) {
            if ("jrt".equalsIgnoreCase(candidate.getScheme())) {
                FileSystem fs = candidate.newFileSystem(URI.create("jrt:/"),
                        Map.of("java.home", jdkHome.toAbsolutePath().toString()));
                return new JrtClassSource(fs);
            }
        }
        throw new IOException("jrt-fs.jar 中未找到 jrt FileSystemProvider: " + jrtFsJar);
    }

    /** 兜底构造：先试 external，目标不是模块化 JDK（无 jrt-fs.jar）返回 null 由调用方降级。 */
    public static JrtClassSource externalOrNull(Path jdkHome) {
        try {
            return external(jdkHome);
        } catch (IOException e) {
            JustLogger.warn("外部 JDK jrt-fs 挂载失败（{}），回退运行时镜像", e.getMessage());
            return null;
        }
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
            JustLogger.debug("JDK 类加载失败 {}: {}", internalName, e.getMessage());
            return null;
        }
    }

    /** 按内部名读取原始 class，仅供 frontend 的按需闭包规划使用。 */
    public ClassBytes loadBytes(String internalName) {
        try {
            String module = moduleOf(internalName);
            if (module == null) {
                return null;
            }
            Path classFile = jrt.getPath("modules", module, internalName + ".class");
            if (!Files.exists(classFile)) {
                return null;
            }
            return new ClassBytes(internalName, Files.readAllBytes(classFile), "jdk:/" + module);
        } catch (Exception e) {
            JustLogger.debug("JDK 类加载失败 {}: {}", internalName, e.getMessage());
            return null;
        }
    }

    private String moduleOf(String internalName) throws IOException {
        if (moduleIndex.containsKey(internalName)) {
            return moduleIndex.get(internalName);
        }
        Path inJavaBase = jrt.getPath("modules", "java.base", internalName + ".class");
        if (Files.exists(inJavaBase)) {
            moduleIndex.put(internalName, "java.base");
            return "java.base";
        }
        if (!fullIndexBuilt) {
            buildFullIndex();
            fullIndexBuilt = true;
        }
        return moduleIndex.get(internalName); // 不存在则 null
    }

    private void buildFullIndex() throws IOException {
        Path modules = jrt.getPath("modules");
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(modules)) {
            for (Path module : ds) {
                if (!Files.isDirectory(module)) {
                    continue;
                }
                String moduleName = module.getFileName().toString();
                try (Stream<Path> walk = Files.walk(module)) {
                    walk.filter(p -> p.toString().endsWith(".class")).forEach(p -> {
                        String rel = module.relativize(p).toString().replace('\\', '/');
                        String className = rel.substring(0, rel.length() - 6);
                        moduleIndex.putIfAbsent(className, moduleName);
                    });
                }
            }
        }
    }

    /** 枚举指定模块的全部类字节（--jdk 全量分析用）。 */
    public List<ClassBytes> listAll(List<String> modules) throws IOException {
        List<ClassBytes> result = new ArrayList<>();
        Path modulesRoot = jrt.getPath("modules");
        for (String module : modules) {
            Path modulePath = modulesRoot.resolve(module);
            if (!Files.isDirectory(modulePath)) {
                continue;
            }
            try (Stream<Path> walk = Files.walk(modulePath)) {
                walk.filter(p -> p.toString().endsWith(".class")).forEach(p -> {
                    String rel = modulePath.relativize(p).toString().replace('\\', '/');
                    String className = rel.substring(0, rel.length() - 6);
                    try {
                        result.add(new ClassBytes(className, Files.readAllBytes(p), "jdk:/" + module));
                    } catch (IOException e) {
                        JustLogger.debug("JDK 类读取失败 {}: {}", className, e.getMessage());
                    }
                });
            }
        }
        return result;
    }
}
