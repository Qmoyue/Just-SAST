package io.just.sast.frontend.asm;

import io.just.sast.model.ClassInfo;
import io.just.sast.model.JdkClassSource;
import io.just.sast.util.JustLogger;

import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.FileSystem;
import java.nio.file.FileSystemNotFoundException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.spi.FileSystemProvider;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
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
    /** Non-null only for external images; the runtime JRT filesystem must never be closed here. */
    private final URLClassLoader ownerLoader;
    /** Class-to-module hits are shared by lazy hierarchy lookups. */
    private final Map<String, String> moduleIndex = new ConcurrentHashMap<>();
    /** Negative lookups must also be memoized; optional framework types are often repeated. */
    private final Set<String> missingClasses = ConcurrentHashMap.newKeySet();
    /** Package-to-module candidates avoid walking every configured module on the first miss. */
    private final Map<String, List<String>> packageIndex = new ConcurrentHashMap<>();
    private volatile boolean fullIndexBuilt;
    private final int feature;
    private volatile boolean closed;

    private JrtClassSource(FileSystem jrt, int feature) {
        this(jrt, feature, null);
    }

    private JrtClassSource(FileSystem jrt, int feature, URLClassLoader ownerLoader) {
        this.jrt = jrt;
        this.feature = Math.max(0, feature);
        this.ownerLoader = ownerLoader;
    }

    /** 运行时 JDK 自身的 jrt 文件系统（JVM 启动即存在）。 */
    public static JrtClassSource runtime() {
        try {
            return new JrtClassSource(FileSystems.getFileSystem(URI.create("jrt:/")),
                    Runtime.version().feature());
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
        try {
            for (FileSystemProvider candidate : ServiceLoader.load(FileSystemProvider.class, loader)) {
                if ("jrt".equalsIgnoreCase(candidate.getScheme())) {
                    FileSystem fs = candidate.newFileSystem(URI.create("jrt:/"),
                            Map.of("java.home", jdkHome.toAbsolutePath().toString()));
                    return new JrtClassSource(fs, readFeature(jdkHome), loader);
                }
            }
        } catch (IOException | RuntimeException failure) {
            closeQuietly(loader);
            throw failure;
        }
        closeQuietly(loader);
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

    /** Feature represented by this JRT image, used for multi-release archive selection. */
    public int feature() {
        return feature;
    }

    /** Close only resources owned by external(Path); runtime() remains process-owned. */
    @Override
    public void close() {
        if (ownerLoader == null || closed) {
            return;
        }
        synchronized (this) {
            if (closed) {
                return;
            }
            closed = true;
            try {
                jrt.close();
            } catch (IOException | RuntimeException e) {
                JustLogger.debug("外部 JDK jrt 文件系统关闭失败: {}", e.getMessage());
            }
            closeQuietly(ownerLoader);
        }
    }

    @Override
    public String moduleOf(String internalName) {
        try {
            return moduleOfChecked(internalName);
        } catch (IOException failure) {
            JustLogger.debug("JRT 模块查询失败 {}: {}", internalName, failure.getMessage());
            return null;
        } catch (RuntimeException ignored) {
            // The JRT provider is allowed to reject a missing package or a malformed
            // descriptor with a provider-specific runtime exception.  Module lookup is
            // optional metadata; an application-owned or array name is simply not a JRT
            // class and must not flood a normal scan with one debug line per reference.
            return null;
        }
    }

    private String moduleOfChecked(String internalName) throws IOException {
        if (internalName == null || internalName.isBlank()
                || internalName.indexOf('[') >= 0
                || (internalName.startsWith("L") && internalName.endsWith(";"))) {
            return null;
        }
        String cached = moduleIndex.get(internalName);
        if (cached != null) {
            return cached;
        }
        if (missingClasses.contains(internalName)) {
            return null;
        }
        Path inJavaBase = jrt.getPath("modules", "java.base", internalName + ".class");
        if (Files.exists(inJavaBase)) {
            moduleIndex.put(internalName, "java.base");
            return "java.base";
        }
        for (String module : modulesForPackage(packageName(internalName))) {
            Path classFile = jrt.getPath("modules", module, internalName + ".class");
            if (Files.exists(classFile)) {
                moduleIndex.putIfAbsent(internalName, module);
                return moduleIndex.get(internalName);
            }
        }
        if (!fullIndexBuilt) {
            // Unknown JDK names used to trigger a walk of every module.  Just's default
            // deserialization model has a bounded module surface; indexing only that surface
            // keeps a missing optional type from turning one lookup into a full JRT scan.
            synchronized (this) {
                if (!fullIndexBuilt) {
                    buildFullIndex(DESER_MODULES);
                    fullIndexBuilt = true;
                }
            }
        }
        String result = moduleIndex.get(internalName);
        if (result == null) {
            missingClasses.add(internalName);
        }
        return result;
    }

    /**
     * JRT exposes a package index. Querying it is O(number of modules containing the package),
     * while walking every class below /modules is O(the whole image). Keep a sorted immutable
     * list so external and runtime images have identical lookup order.
     */
    private List<String> modulesForPackage(String packageName) {
        if (packageName == null || packageName.isBlank()) {
            return List.of();
        }
        List<String> cached = packageIndex.get(packageName);
        if (cached != null) {
            return cached;
        }
        try {
            Path packagePath = jrt.getPath("packages", packageName);
            if (!Files.isDirectory(packagePath)) {
                packageIndex.put(packageName, List.of());
                return List.of();
            }
            List<String> modules;
            try (Stream<Path> children = Files.list(packagePath)) {
                modules = children.map(path -> path.getFileName().toString())
                        .sorted().toList();
            }
            List<String> stable = List.copyOf(modules);
            packageIndex.putIfAbsent(packageName, stable);
            return packageIndex.get(packageName);
        } catch (IOException e) {
            // The package index is an optimization, not a correctness boundary.  Providers
            // for older/external images may expose /modules but not /packages; let moduleOf
            // fall back to the bounded deserialization-module index instead of turning a JDK
            // lookup into a silent load failure.
            JustLogger.debug("JRT package index unavailable {}: {}", packageName, e.getMessage());
            return List.of();
        } catch (RuntimeException ignored) {
            // Some JRT providers throw NPE/IllegalArgumentException for a package that is
            // absent from the image.  Treat that as an ordinary negative lookup; package
            // indexing is an optimization and never a semantic proof.
            packageIndex.putIfAbsent(packageName, List.of());
            return List.of();
        }
    }

    private static String packageName(String internalName) {
        int slash = internalName.lastIndexOf('/');
        return slash < 0 ? "" : internalName.substring(0, slash);
    }

    private static int readFeature(java.nio.file.Path jdkHome) {
        try {
            java.nio.file.Path release = jdkHome.resolve("release");
            if (java.nio.file.Files.isRegularFile(release)) {
                for (String line : java.nio.file.Files.readAllLines(release)) {
                    if (!line.startsWith("JAVA_VERSION=")) {
                        continue;
                    }
                    String version = line.substring("JAVA_VERSION=".length())
                            .replace("\"", "").trim();
                    String normalized = version.startsWith("1.") ? version.substring(2)
                            : version.split("[.+-]", 2)[0];
                    int dot = normalized.indexOf('.');
                    return Integer.parseInt(dot < 0 ? normalized : normalized.substring(0, dot));
                }
            }
        } catch (IOException | RuntimeException ignored) {
            // An unknown image version falls back to the scanner runtime selection.
        }
        return 0;
    }

    private void buildFullIndex(List<String> modulesToIndex) throws IOException {
        Path modules = jrt.getPath("modules");
        for (String moduleName : modulesToIndex) {
            Path module = modules.resolve(moduleName);
            if (!Files.isDirectory(module)) {
                continue;
            }
            try (Stream<Path> walk = Files.walk(module)) {
                walk.filter(p -> p.toString().endsWith(".class")).forEach(p -> {
                    String rel = module.relativize(p).toString().replace('\\', '/');
                    String className = rel.substring(0, rel.length() - 6);
                    moduleIndex.putIfAbsent(className, moduleName);
                });
            }
        }
    }

    private static void closeQuietly(URLClassLoader loader) {
        try {
            loader.close();
        } catch (IOException | RuntimeException e) {
            JustLogger.debug("外部 JDK jrt 类加载器关闭失败: {}", e.getMessage());
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
        result.sort(java.util.Comparator.comparing(ClassBytes::className)
                .thenComparing(ClassBytes::origin));
        return result;
    }
}
