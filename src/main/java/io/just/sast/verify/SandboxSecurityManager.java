package io.just.sast.verify;

import java.io.FilePermission;
import java.io.IOException;
import java.net.NetPermission;
import java.net.SocketPermission;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.io.SerializablePermission;
import java.lang.reflect.ReflectPermission;
import java.security.CodeSource;
import java.security.Permission;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.PropertyPermission;

/**
 * 探针 JVM 的最后一道 Java 级权限门。
 *
 * <p>这不是 OS 沙箱：目标工件仍在探针进程的用户身份下运行，生产环境必须叠加容器、
 * 低权限账户和无网络策略。本类的职责是让 Just 在没有外部 runner 时也做到 deny-by-default，
 * 并且在权限门无法安装时停止探针，不把不安全执行伪装成动态验证。</p>
 */
@SuppressWarnings("removal")
public final class SandboxSecurityManager extends SecurityManager {

    private final Path writableRoot;
    private final Path writableRealRoot;
    private final boolean writableRootRealPathAvailable;
    private final List<Path> readableRoots;
    private final List<Path> readableRealRoots;
    /** Only verifier classes from this code source may request reflective escape hatches. */
    private final String trustedCodeSource;
    /** Filesystem real-path probing can itself ask the SecurityManager for read access. */
    private final ThreadLocal<Boolean> resolvingPath = ThreadLocal.withInitial(() -> false);
    /**
     * JDK serialization may create a short-lived reflection accessor while reading a graph.
     * This is deliberately scoped to a probe-owned operation; it is not a permanent grant to
     * target code and is entered only after the caller has passed trustedProbeCaller().
     */
    private static final ThreadLocal<Integer> SERIALIZATION_BOOTSTRAP_DEPTH =
            ThreadLocal.withInitial(() -> 0);
    /** Proxy class generation is a JDK bootstrap operation, not a target capability grant. */
    private static final ThreadLocal<Integer> PROXY_BOOTSTRAP_DEPTH =
            ThreadLocal.withInitial(() -> 0);
    /** Kryo/other serializer construction may need reflective access before target entry. */
    private static final ThreadLocal<Integer> SOURCE_ADAPTER_DEPTH =
            ThreadLocal.withInitial(() -> 0);
    /** Fixed adapter-owned command/network capabilities; target frames never enter these scopes. */
    private static final ThreadLocal<Path> SAFE_REAL_EXECUTABLE = new ThreadLocal<>();
    private static final ThreadLocal<Boolean> SAFE_REAL_NETWORK =
            ThreadLocal.withInitial(() -> false);

    SandboxSecurityManager(Path writableRoot, List<Path> readableRoots) {
        this.writableRoot = normalize(writableRoot);
        this.writableRealRoot = realPath(this.writableRoot);
        this.writableRootRealPathAvailable = canResolveRealPath(this.writableRoot);
        this.readableRoots = readableRoots == null ? List.of()
                : readableRoots.stream().map(SandboxSecurityManager::normalize).toList();
        this.readableRealRoots = this.readableRoots.stream().map(SandboxSecurityManager::realPath).toList();
        this.trustedCodeSource = codeSourceOf(SandboxSecurityManager.class);
    }

    /** 安装一次；JDK 不支持 SecurityManager 时抛出，让探针以不可验证结束。 */
    public static void install(Path writableRoot) {
        SecurityManager existing = System.getSecurityManager();
        if (existing != null) {
            if (existing instanceof SandboxSecurityManager) {
                return;
            }
            throw new SecurityException("another security manager is already installed");
        }
        if (writableRoot == null) {
            throw new IllegalArgumentException("writable root is required");
        }
        if (!Files.isDirectory(writableRoot)) {
            throw new IllegalArgumentException("writable root is not a directory: " + writableRoot);
        }
        List<Path> roots = new ArrayList<>();
        // The probe launcher classpath intentionally contains only the verifier artifact. The
        // target/dependency roots arrive through a separate property so an input class cannot
        // reach verifier classes through its defining loader. Keep the system property fallback
        // for manually launched probes and older callers.
        String classPath = System.getProperty("just.verify.target-cp",
                System.getProperty("java.class.path", ""));
        for (String entry : classPath.split(java.util.regex.Pattern.quote(java.io.File.pathSeparator))) {
            if (!entry.isBlank()) {
                roots.add(normalize(Path.of(entry)));
            }
        }
        Path cwd = Path.of(System.getProperty("user.dir", "."));
        roots.add(normalize(cwd));
        Path tmp = normalize(writableRoot);
        roots.add(tmp);
        // 允许读取运行时本身，但不允许借此扩大到用户目录；JDK 模块通常不会触发 FilePermission，
        // 这里只覆盖类路径式运行时/兼容 JDK 的 rt.jar 读取。
        Path javaHome = normalize(Path.of(System.getProperty("java.home", ".")));
        roots.add(javaHome);
        System.setSecurityManager(new SandboxSecurityManager(tmp, roots));
    }

    @Override
    public void checkPermission(Permission permission) {
        if (permission == null) {
            throw new SecurityException("null permission");
        }
        if (permission instanceof FilePermission file) {
            checkFile(file);
            return;
        }
        if (permission instanceof SocketPermission) {
            throw new SecurityException("network denied: " + permission.getName());
        }
        if (permission instanceof NetPermission) {
            // The JDK's class-path URL handler asks for this non-network permission while
            // resolving jar resources. Allow that narrow bootstrap operation only through
            // the trusted probe; target code still cannot install arbitrary URL handlers.
            if ("specifyStreamHandler".equals(permission.getName())) {
                // This permission is used by the JDK URL implementation while resolving
                // class-path resources; it does not grant a socket or file capability. Keep
                // it only on a trusted probe/bootstrap stack so target code cannot install a
                // custom handler and widen the child's network boundary.
                if (trustedProbeCaller() || trustedSourceAdapterCaller()) {
                    return;
                }
            }
            throw new SecurityException("network permission denied: " + permission.getName());
        }
        if (permission instanceof PropertyPermission property) {
            if (property.getActions().contains("write")) {
                // JDK bootstrap code may materialize a bounded cache while the trusted probe
                // initializes an optional serializer. This remains probe-only: target frames
                // fail trustedProbeCaller/trustedSourceAdapterCaller and stay deny-by-default.
                if (!trustedProbeCaller() && !trustedSourceAdapterCaller()
                        && !trustedSerializerRuntimeCaller()
                        && !trustedDataBindingCaller()
                        && !("*".equals(property.getName())
                        && trustedJdkPropertyAccessCaller())) {
                    throw new SecurityException("property write denied: " + property.getName()
                            + " [caller=" + firstNonPlatformFrameLocation() + "]");
                }
            }
            if ("just.verify.canary-token".equals(property.getName())
                    && !trustedProbeCaller()) {
                // The attestation is consumed by the trusted probe frame only. Exposing it
                // to target code would let an entry method call the bootstrap gate directly
                // and manufacture a positive boundary without reaching the instrumented sink.
                throw new SecurityException("canary attestation read denied");
            }
        }
        if (permission instanceof ReflectPermission || permission instanceof SerializablePermission) {
            // A target gadget can otherwise call setAccessible()/serialization escape hooks
            // after the probe has installed this manager. The probe needs these permissions
            // to construct the *test* object graph, but target frames must never inherit them.
            // The bootstrap scopes below are lifecycle markers only. They must never be an
            // authorization signal: while OIS/Proxy is invoking target code, the scope is
            // still active and a target frame is above the probe on the stack.
            if (!trustedProbeCaller() && !trustedSourceAdapterCaller()
                    && !(permission instanceof ReflectPermission
                    && (trustedLambdaBootstrapCaller()
                    || trustedSerializerRuntimeCaller()
                    || trustedDataBindingCaller()))) {
                throw new SecurityException("reflective/serialization privilege denied: "
                        + permission.getName());
            }
            return;
        }
        if (permission instanceof RuntimePermission runtime) {
            String name = runtime.getName();
            if (name.equals("setSecurityManager")
                    || name.startsWith("loadLibrary")
                    || name.equals("createNativeThread")
                    || name.equals("shutdownHooks")
                    || name.equals("setIO")
                    || name.equals("manageProcess")
                    || name.equals("modifyThread")
                    || name.equals("modifyThreadGroup")
                    || name.equals("readFileDescriptor")
                    || name.equals("writeFileDescriptor")
                    || name.equals("queuePrintJob")) {
                throw new SecurityException("runtime permission denied: " + name);
            }
            if (name.startsWith("getenv.")) {
                // The parent clears the environment and supplies only JVM startup values
                // before setting this marker. Read-only access to that minimal environment
                // lets libraries initialize normally without exposing the analyst's secrets;
                // an explicitly launched probe without the marker remains deny-by-default.
                if (Boolean.getBoolean("just.verify.sanitized-env")) {
                    return;
                }
                throw new SecurityException("environment read denied: " + name);
            }
            if (name.equals("createClassLoader")) {
                // ObjectStreamClass/Proxy may create a short-lived JDK loader while the
                // probe builds or reads an object. The first non-platform frame, rather than
                // an active scope, is the authorization boundary; target code runs inside
                // the same scopes and must remain denied.
                if (!trustedProbeCaller() && !trustedSourceAdapterCaller()
                        && !trustedLambdaBootstrapCaller()
                        && !trustedSerializerRuntimeCaller()
                        && !trustedDataBindingCaller()) {
                    throw new SecurityException("runtime permission denied: " + name);
                }
                return;
            }
            // exitVM 由 checkExit 按调用栈区分探针收尾和目标工件请求。
            if (name.startsWith("exitVM")) {
                return;
            }
        }
        // 普通属性读取和不改变边界的 JDK 权限保持可用。
    }

    @Override
    public void checkPackageAccess(String packageName) {
        // The transformed target bytecode invokes the one-purpose canary gate from the
        // bootstrap loader.  ClassLoader.checkPackageAccess() reports that lookup against
        // the target frame, so requiring trustedProbeCaller() here would reject every real
        // sink boundary before the gate can run.  This package contains only the immutable
        // gate/error classes; the main verifier namespace remains closed to target code.
        if (packageName != null && (packageName.equals("io.just.sast.verify.boot")
                || packageName.startsWith("io.just.sast.verify.boot."))) {
            return;
        }
        if (packageName != null && (packageName.equals("io.just.sast")
                || packageName.startsWith("io.just.sast.")) && !trustedProbeCaller()) {
            throw new SecurityException("verifier package access denied: " + packageName);
        }
    }

    /**
     * SecurityManager's class context is more reliable here than a package-name allowlist:
     * an input JAR is allowed to define a class with the same package prefix. Require both
     * the verifier namespace and the exact code-source location of this manager. JDK frames
     * are skipped because the permission check passes through implementation classes first.
     *
     * <p>Only the first non-platform frame is trusted. Looking for any trusted frame would
     * accidentally grant a target method permission merely because the probe is below it on
     * the same call stack—the normal shape of every dynamic verification.</p>
     */
    private boolean trustedProbeCaller() {
        Class<?> frame = firstNonPlatformFrame();
        return frame != null && isVerifierFrame(frame);
    }

    /**
     * Java 9+ links an ordinary target lambda by reflectively opening the generated lambda
     * constructor. This is a JDK implementation step, not target-requested reflection, but
     * it runs while the target class initializer is on the stack. Keep the exception narrow:
     * only the JDK lambda metafactory plus its reflective constructor path qualifies; a target
     * calling setAccessible directly still has no such frames and remains denied.
     */
    private boolean trustedLambdaBootstrapCaller() {
        boolean metafactory = false;
        boolean constructorAccess = false;
        for (Class<?> frame : getClassContext()) {
            String name = frame.getName();
            if (name.equals("java.lang.invoke.InnerClassLambdaMetafactory")
                    || name.startsWith("java.lang.invoke.InnerClassLambdaMetafactory$")) {
                metafactory = true;
            }
            if (name.equals("java.lang.reflect.Constructor")
                    || name.equals("java.lang.reflect.AccessibleObject")) {
                constructorAccess = true;
            }
        }
        return metafactory && constructorAccess;
    }

    private Class<?> firstNonPlatformFrame() {
        for (Class<?> frame : getClassContext()) {
            if (frame != SandboxSecurityManager.class && !isPlatformFrame(frame)) {
                return frame;
            }
        }
        return null;
    }

    private String firstNonPlatformFrameLocation() {
        for (StackTraceElement frame : new Throwable().getStackTrace()) {
            String className = frame.getClassName();
            if (className.equals(SandboxSecurityManager.class.getName())
                    || className.startsWith("java.") || className.startsWith("javax.")
                    || className.startsWith("sun.") || className.startsWith("jdk.")) {
                continue;
            }
            return className + "." + frame.getMethodName();
        }
        Class<?> frame = firstNonPlatformFrame();
        return frame == null ? "unknown" : frame.getName();
    }

    /** Entered by the probe before an OIS/OOS operation that may bootstrap accessors. */
    static void beginSerializationBootstrap() {
        SecurityManager current = System.getSecurityManager();
        if (current == null) {
            return;
        }
        if (!(current instanceof SandboxSecurityManager manager)
                || !manager.trustedProbeCaller()) {
            throw new SecurityException("serialization bootstrap is probe-only");
        }
        SERIALIZATION_BOOTSTRAP_DEPTH.set(SERIALIZATION_BOOTSTRAP_DEPTH.get() + 1);
    }

    static void endSerializationBootstrap() {
        int depth = SERIALIZATION_BOOTSTRAP_DEPTH.get();
        if (depth <= 1) {
            SERIALIZATION_BOOTSTRAP_DEPTH.remove();
        } else {
            SERIALIZATION_BOOTSTRAP_DEPTH.set(depth - 1);
        }
    }

    /** Entered only around Proxy.newProxyInstance class generation. */
    static void beginProxyBootstrap() {
        SecurityManager current = System.getSecurityManager();
        if (current == null) {
            return;
        }
        if (!(current instanceof SandboxSecurityManager manager)
                || !manager.trustedProbeCaller()) {
            throw new SecurityException("proxy bootstrap is probe-only");
        }
        PROXY_BOOTSTRAP_DEPTH.set(PROXY_BOOTSTRAP_DEPTH.get() + 1);
    }

    static void endProxyBootstrap() {
        int depth = PROXY_BOOTSTRAP_DEPTH.get();
        if (depth <= 1) {
            PROXY_BOOTSTRAP_DEPTH.remove();
        } else {
            PROXY_BOOTSTRAP_DEPTH.set(depth - 1);
        }
    }

    /** Enter only while the trusted probe builds an inert serializer input. */
    static void beginSourceAdapter() {
        SecurityManager current = System.getSecurityManager();
        if (current == null) {
            return;
        }
        if (!(current instanceof SandboxSecurityManager manager)
                || !manager.trustedProbeCaller()) {
            throw new SecurityException("source adapter is probe-only");
        }
        SOURCE_ADAPTER_DEPTH.set(SOURCE_ADAPTER_DEPTH.get() + 1);
    }

    static void endSourceAdapter() {
        int depth = SOURCE_ADAPTER_DEPTH.get();
        if (depth <= 1) {
            SOURCE_ADAPTER_DEPTH.remove();
        } else {
            SOURCE_ADAPTER_DEPTH.set(depth - 1);
        }
    }

    /** Allow one verifier-owned fixed executable to be started by SAFE_REAL only. */
    static void beginSafeRealExec(Path executable) {
        SecurityManager current = System.getSecurityManager();
        if (current == null) {
            return;
        }
        if (!(current instanceof SandboxSecurityManager manager)
                || !manager.trustedProbeCaller() || executable == null) {
            throw new SecurityException("safe-real command is probe-only");
        }
        SAFE_REAL_EXECUTABLE.set(executable.toAbsolutePath().normalize());
    }

    static void endSafeRealExec() {
        SAFE_REAL_EXECUTABLE.remove();
    }

    /** Allow one literal loopback round trip by the verifier-owned adapter. */
    static void beginSafeRealNetwork() {
        SecurityManager current = System.getSecurityManager();
        if (current == null) {
            return;
        }
        if (!(current instanceof SandboxSecurityManager manager)
                || !manager.trustedProbeCaller()) {
            throw new SecurityException("safe-real network is probe-only");
        }
        SAFE_REAL_NETWORK.set(true);
    }

    static void endSafeRealNetwork() {
        SAFE_REAL_NETWORK.remove();
    }

    /**
     * Serializer libraries are allowed to prepare their own metadata, but an application
     * callback is not. The whitelist is deliberately limited to the adapter's library stack;
     * target frames therefore cannot inherit this temporary permission while it is active.
     */
    private boolean trustedSourceAdapterCaller() {
        if (SOURCE_ADAPTER_DEPTH.get() <= 0) {
            return false;
        }
        boolean sawProbe = false;
        for (Class<?> frame : getClassContext()) {
            if (frame == SandboxSecurityManager.class || isPlatformFrame(frame)) {
                continue;
            }
            String name = frame.getName();
            if (isVerifierFrame(frame)) {
                sawProbe = true;
                continue;
            }
            if (name.startsWith("com.esotericsoftware.kryo.")
                    || name.startsWith("org.objenesis.")
                    || name.startsWith("com.esotericsoftware.reflectasm.")
                    || name.startsWith("com.esotericsoftware.minlog.")) {
                continue;
            }
            return false;
        }
        return sawProbe;
    }

    /**
     * Kryo 4 + Objenesis can lazily define a serialization constructor during the target's
     * own bounded deserialization call. That implementation detail is not a target class
     * loader request when the first non-platform frame is the serializer itself. Keep this
     * allowance limited to the known serializer stack and to this one JVM permission; file,
     * network, native and reflection permissions remain denied for target code.
     */
    private boolean trustedSerializerRuntimeCaller() {
        boolean firstNonPlatform = true;
        boolean sawKryo = false;
        for (Class<?> frame : getClassContext()) {
            if (frame == SandboxSecurityManager.class || isPlatformFrame(frame)) {
                continue;
            }
            String name = frame.getName();
            if (firstNonPlatform) {
                firstNonPlatform = false;
                if (!isSerializerFrame(name)) {
                    return false;
                }
            }
            sawKryo |= name.startsWith("com.esotericsoftware.kryo.");
        }
        return !firstNonPlatform && sawKryo;
    }

    /**
     * Jackson may lazily open its own bean metadata while the probe renders a declared
     * POJONode/object graph.  Permit only its narrow reflective/property bootstrap, only
     * inside the probe's serialization scope, and only when Jackson is the first application
     * frame.  An application callback that merely invokes Jackson therefore does not inherit
     * this allowance; its own frame remains the boundary and is denied.
     */
    private boolean trustedDataBindingCaller() {
        if (SERIALIZATION_BOOTSTRAP_DEPTH.get() <= 0) {
            return false;
        }
        boolean firstNonPlatform = true;
        for (Class<?> frame : getClassContext()) {
            if (frame == SandboxSecurityManager.class || isPlatformFrame(frame)) {
                continue;
            }
            String name = frame.getName();
            if (firstNonPlatform) {
                firstNonPlatform = false;
                return name.startsWith("com.fasterxml.jackson.databind.")
                        || name.startsWith("com.fasterxml.jackson.core.");
            }
        }
        return false;
    }

    /**
     * Java 8--11's privileged property helper requests the broad read/write permission used by
     * {@code System.getProperties()}, even when the caller only reads a cached runtime value.
     * Keep that compatibility window tied to an active probe-owned serialization operation and
     * the JDK helper frame; a target direct call to {@code System.getProperties()} remains denied.
     */
    private boolean trustedJdkPropertyAccessCaller() {
        if (SERIALIZATION_BOOTSTRAP_DEPTH.get() <= 0) {
            return false;
        }
        for (Class<?> frame : getClassContext()) {
            String name = frame.getName();
            if (name.equals("sun.security.action.GetPropertyAction")
                    || name.startsWith("sun.security.action.GetPropertyAction$")) {
                return true;
            }
        }
        return false;
    }

    private static boolean isSerializerFrame(String name) {
        return name.startsWith("com.esotericsoftware.kryo.")
                || name.startsWith("org.objenesis.")
                || name.startsWith("com.esotericsoftware.reflectasm.")
                || name.startsWith("com.esotericsoftware.minlog.");
    }

    private static boolean isPlatformFrame(Class<?> frame) {
        ClassLoader loader = frame.getClassLoader();
        return loader == null || loader == ClassLoader.getPlatformClassLoader();
    }

    private boolean isVerifierFrame(Class<?> frame) {
        return frame.getName().startsWith("io.just.sast.verify.")
                && trustedCodeSource != null
                && trustedCodeSource.equals(codeSourceOf(frame));
    }

    private static String codeSourceOf(Class<?> type) {
        try {
            CodeSource source = type.getProtectionDomain().getCodeSource();
            return source == null || source.getLocation() == null
                    ? null : source.getLocation().toExternalForm();
        } catch (RuntimeException e) {
            return null;
        }
    }

    @Override
    public void checkExit(int status) {
        // Runtime/Shutdown implementation frames are platform-loader classes. The first
        // application frame is the capability boundary; class identity prevents an input
        // JAR from spoofing the probe package or class name.
        if (firstNonPlatformFrame() == ChainVerifyProbe.class) {
            return;
        }
        throw new SecurityException("target System.exit denied: " + status);
    }

    @Override
    public void checkExec(String cmd) {
        if (safeRealExecutableAllowed(cmd)) {
            return;
        }
        throw new SecurityException("exec denied: " + cmd);
    }

    @Override
    public void checkLink(String lib) {
        throw new SecurityException("native load denied: " + lib);
    }

    @Override
    public void checkConnect(String host, int port) {
        if (Boolean.TRUE.equals(SAFE_REAL_NETWORK.get()) && loopback(host)) {
            return;
        }
        throw new SecurityException("connect denied: " + host + ":" + port);
    }

    @Override
    public void checkListen(int port) {
        if (Boolean.TRUE.equals(SAFE_REAL_NETWORK.get())) {
            return;
        }
        throw new SecurityException("listen denied: " + port);
    }

    @Override
    public void checkAccept(String host, int port) {
        if (Boolean.TRUE.equals(SAFE_REAL_NETWORK.get()) && loopback(host)) {
            return;
        }
        throw new SecurityException("accept denied: " + host + ":" + port);
    }

    @Override
    public void checkMulticast(java.net.InetAddress address) {
        throw new SecurityException("multicast denied: " + address);
    }

    private boolean safeRealExecutableAllowed(String command) {
        Path allowed = SAFE_REAL_EXECUTABLE.get();
        if (allowed == null || !trustedProbeCaller() || command == null || command.isBlank()) {
            return false;
        }
        try {
            Path candidate = Path.of(command).toAbsolutePath().normalize();
            return candidate.equals(allowed) && Files.isRegularFile(candidate)
                    && !ArchiveLink.isLink(candidate);
        } catch (RuntimeException ignored) {
            return false;
        }
    }

    private static boolean loopback(String host) {
        if (host == null) {
            return false;
        }
        String value = host.strip().toLowerCase(Locale.ROOT);
        return value.equals("127.0.0.1") || value.equals("localhost")
                || value.equals("::1") || value.equals("0:0:0:0:0:0:0:1");
    }

    private static final class ArchiveLink {
        private static boolean isLink(Path path) {
            if (Files.isSymbolicLink(path)) {
                return true;
            }
            try {
                return Boolean.TRUE.equals(Files.getAttribute(path, "dos:reparsePoint",
                        LinkOption.NOFOLLOW_LINKS));
            } catch (IOException | RuntimeException ignored) {
                return false;
            }
        }
    }

    private void checkFile(FilePermission permission) {
        String name = permission.getName();
        if (name == null || name.equals("<<ALL FILES>>")) {
            throw new SecurityException("unbounded file permission denied");
        }
        final Path path;
        try {
            path = normalize(Path.of(name));
        } catch (RuntimeException e) {
            throw new SecurityException("invalid file permission denied: " + name, e);
        }
        String actions = permission.getActions();
        if (actions.contains("readlink")
                && !Boolean.TRUE.equals(resolvingPath.get())) {
            // NIO may request readlink while the manager resolves an explicitly trusted
            // readable root. Allow only that re-entrant boundary check; a target's direct
            // Files.readSymbolicLink call arrives with the guard clear and remains denied.
            throw new SecurityException("symbolic-link permission denied");
        }
        boolean write = actions.contains("write") || actions.contains("delete");
        if (write && !safeUnder(path, writableRoot, writableRealRoot)) {
            throw new SecurityException("file write denied: " + path + " root=" + writableRoot
                    + " realRoot=" + writableRealRoot);
        }
        if (actions.contains("read") && !readable(path)) {
            // Keep the failure useful without placing a host path in the child protocol. The
            // parent report is path-free as well, so a stable boundary category is more useful
            // than a path that will be redacted after the fact.
            throw new SecurityException("file read denied ["
                    + readableRootCategory(path) + "]");
        }
        if (actions.contains("execute") && !safeUnder(path, writableRoot, writableRealRoot)) {
            throw new SecurityException("file execute denied: " + path);
        }
    }

    private boolean readable(Path path) {
        Path resolvedPath = resolveForRead(path);
        for (int i = 0; i < readableRoots.size(); i++) {
            if (safeUnder(path, readableRoots.get(i), readableRealRoots.get(i))) {
                return true;
            }
            // Jabba and several managed JDK installers expose the selected runtime through
            // a junction/symbolic link (for example jdk/default). The lexical root is
            // explicitly trusted above, while the resolved root is the actual read boundary.
            // Check that resolved root independently so normal JDK resources such as tzdb.dat
            // do not become a false PARTIAL_PATH. This does not widen the boundary: the real
            // root is derived from the same explicitly configured readable root and writes
            // still use writableRoot's real-path-only check.
            Path realRoot = readableRealRoots.get(i);
            if (!realRoot.equals(readableRoots.get(i))
                    && safeUnder(resolvedPath, realRoot, realRoot)) {
                return true;
            }
            // A managed JDK may expose java.home through a junction. Windows can reject the
            // handle used by toRealPath from inside a SecurityManager even though the same
            // process can read the runtime. Rebase the explicitly trusted root without
            // resolving the root again, and reject every link/reparse component below it.
            if (!realRoot.equals(readableRoots.get(i))
                    && managedRootRead(path, readableRoots.get(i), realRoot)) {
                return true;
            }
            // Some managed Windows hosts deny GetFinalPathNameByHandle for a freshly
            // materialized temp tree even though the tree is the explicit classpath root.
            // A strict real-path check would then turn every nested WAR/JAR class into a
            // misleading ClassNotFoundException.  Fall back only for reads, only below an
            // explicitly supplied root, and reject symbolic-link components when the host
            // exposes them.  Writes and executes remain real-path-only.
            if (lexicallySafeRead(path, readableRoots.get(i))) {
                return true;
            }
        }
        return false;
    }

    private boolean managedRootRead(Path path, Path lexicalRoot, Path realRoot) {
        return "rebased".equals(managedRootReadReason(path, lexicalRoot, realRoot));
    }

    private String managedRootReadReason(Path path, Path lexicalRoot, Path realRoot) {
        if (!under(path, lexicalRoot) || realRoot.equals(lexicalRoot)) {
            return "not-applicable";
        }
        boolean alreadyResolving = Boolean.TRUE.equals(resolvingPath.get());
        resolvingPath.set(true);
        try {
            Path relative = lexicalRoot.relativize(path);
            Path current = lexicalRoot;
            for (Path component : relative) {
                current = current.resolve(component);
                if (isLinkOrReparsePoint(current)) {
                    return "link-component";
                }
            }
            // realRoot was resolved before this manager was installed; keeping the rebased
            // path below that immutable root is the same boundary check without a second OS
            // handle lookup. The returned path is intentionally not opened here.
            return under(realRoot.resolve(relative), realRoot) ? "rebased" : "rebase-outside";
        } catch (RuntimeException e) {
            return "error-" + e.getClass().getSimpleName();
        } finally {
            if (alreadyResolving) {
                resolvingPath.set(true);
            } else {
                resolvingPath.remove();
            }
        }
    }

    private String readableRootCategory(Path path) {
        for (int i = 0; i < readableRoots.size(); i++) {
            Path lexical = readableRoots.get(i);
            if (under(path, lexical)) {
                boolean alreadyResolving = Boolean.TRUE.equals(resolvingPath.get());
                resolvingPath.set(true);
                try {
                    Path existing = path;
                    while (existing != null && !Files.exists(existing, LinkOption.NOFOLLOW_LINKS)) {
                        existing = existing.getParent();
                    }
                    if (existing == null) {
                        return "explicit-root-" + i + "-no-existing-ancestor";
                    }
                    String managed = managedRootReadReason(path, lexical,
                            readableRealRoots.get(i));
                    Path resolved = existing.toRealPath();
                    return "explicit-root-" + i + "-"
                            + (under(resolved, readableRealRoots.get(i))
                            ? "real-under" : "real-outside") + "-" + managed;
                } catch (IOException e) {
                    return "explicit-root-" + i + "-"
                            + managedRootReadReason(path, lexical,
                            readableRealRoots.get(i)) + "-io-"
                            + e.getClass().getSimpleName();
                } catch (RuntimeException e) {
                    return "explicit-root-" + i + "-"
                            + e.getClass().getSimpleName();
                } finally {
                    if (alreadyResolving) {
                        resolvingPath.set(true);
                    } else {
                        resolvingPath.remove();
                    }
                }
            }
            Path real = readableRealRoots.get(i);
            if (!real.equals(lexical) && under(path, real)) {
                return "resolved-root-" + i;
            }
        }
        return "outside-explicit-roots";
    }

    /** Resolve an existing read target once before checking a symlinked readable root. */
    private Path resolveForRead(Path path) {
        boolean alreadyResolving = Boolean.TRUE.equals(resolvingPath.get());
        if (alreadyResolving) {
            return path;
        }
        resolvingPath.set(true);
        try {
            return Files.exists(path, LinkOption.NOFOLLOW_LINKS) ? path.toRealPath() : path;
        } catch (IOException | RuntimeException ignored) {
            return path;
        } finally {
            resolvingPath.remove();
        }
    }

    private boolean lexicallySafeRead(Path path, Path root) {
        if (!under(path, root)) {
            return false;
        }
        boolean alreadyResolving = Boolean.TRUE.equals(resolvingPath.get());
        resolvingPath.set(true);
        try {
            Path relative = root.relativize(path);
            // The root itself is an explicit launcher-owned capability (java.home may be a
            // managed symlink). Only descendants must be link-free so an input path cannot
            // escape the selected root through a nested junction/reparse point.
            Path current = root;
            for (Path component : relative) {
                current = current.resolve(component);
                if (isLinkOrReparsePoint(current)) {
                    return false;
                }
            }
            return true;
        } catch (RuntimeException e) {
            return false;
        } finally {
            if (alreadyResolving) {
                resolvingPath.set(true);
            } else {
                resolvingPath.remove();
            }
        }
    }

    private static Path normalize(Path path) {
        return path.toAbsolutePath().normalize();
    }

    /**
     * Lexical startsWith alone is insufficient: an allowed directory may contain a symlink or
     * Windows reparse point leading outside the sandbox. Existing paths are resolved fully;
     * new paths are checked through their nearest existing ancestor.
     */
    private boolean safeUnder(Path path, Path lexicalRoot, Path realRoot) {
        if (!under(path, lexicalRoot)) {
            return false;
        }
        if (Boolean.TRUE.equals(resolvingPath.get())) {
            return true;
        }
        resolvingPath.set(true);
        try {
            Path existing = path;
            while (existing != null && !Files.exists(existing, LinkOption.NOFOLLOW_LINKS)) {
                existing = existing.getParent();
            }
            if (existing == null) {
                return false;
            }
            if (existing.equals(lexicalRoot)) {
                // Do not trust the lexical root merely because it exists: a caller can
                // supply a junction/symlink root. Resolve the exact root as well; the
                // lexical read fallback below remains the managed-host compatibility path.
                Path real = existing.toRealPath();
                return under(real, realRoot);
            }
            Path real = existing.toRealPath();
            return under(real, realRoot);
        } catch (IOException | RuntimeException e) {
            // A few managed Windows file systems deny GetFinalPathNameByHandle for an
            // explicitly-created temporary directory. If and only if resolving the trusted
            // writable root itself failed, use a component-by-component no-link check. This
            // preserves the deny-by-default rule for junctions/reparse points and avoids
            // turning that host quirk into a false dynamic failure.
            return lexicalRoot.equals(writableRoot) && !writableRootRealPathAvailable
                    && lexicallySafePath(path, lexicalRoot);
        } finally {
            resolvingPath.remove();
        }
    }

    private boolean lexicallySafePath(Path path, Path root) {
        if (!under(path, root) || !Files.exists(root, LinkOption.NOFOLLOW_LINKS)
                || isLinkOrReparsePoint(root)) {
            return false;
        }
        try {
            Path current = root;
            Path relative = root.relativize(path);
            for (Path component : relative) {
                current = current.resolve(component);
                if (!Files.exists(current, LinkOption.NOFOLLOW_LINKS)) {
                    return true;
                }
                if (isLinkOrReparsePoint(current)) {
                    return false;
                }
            }
            return true;
        } catch (RuntimeException e) {
            return false;
        }
    }

    private static boolean isLinkOrReparsePoint(Path path) {
        if (Files.isSymbolicLink(path)) {
            return true;
        }
        if (!isWindows()) {
            return false;
        }
        try {
            Object value = Files.getAttribute(path, "dos:reparsePoint", LinkOption.NOFOLLOW_LINKS);
            return Boolean.TRUE.equals(value);
        } catch (IOException | RuntimeException e) {
            // The stock Windows NIO provider does not expose this DOS attribute on every
            // supported JDK. Keep the symbolic-link result, and rely on the OS backend's
            // handle/ACL checks for reparse-point enforcement when it is available.
            return false;
        }
    }

    private static Path realPath(Path path) {
        try {
            return path.toRealPath();
        } catch (IOException | RuntimeException e) {
            // Some Windows providers reject GetFinalPathNameByHandle for a managed
            // symlink. Resolve a direct link target before the manager is installed so the
            // child can still validate reads against the immutable real root.
            try {
                if (Files.isSymbolicLink(path)) {
                    Path link = Files.readSymbolicLink(path);
                    return normalize(link.isAbsolute() ? link : path.getParent().resolve(link));
                }
            } catch (IOException | RuntimeException ignored) {
                // Keep the lexical root; the caller will fail closed if it cannot validate it.
            }
            return path;
        }
    }

    private static boolean canResolveRealPath(Path path) {
        try {
            path.toRealPath();
            return true;
        } catch (IOException | RuntimeException e) {
            return false;
        }
    }

    private static boolean under(Path path, Path root) {
        if (path == null || root == null) {
            return false;
        }
        Path normalizedPath = path.toAbsolutePath().normalize();
        Path normalizedRoot = root.toAbsolutePath().normalize();
        if (!isWindows()) {
            return normalizedPath.equals(normalizedRoot)
                    || normalizedPath.startsWith(normalizedRoot);
        }
        // Windows paths are case-insensitive, while Path.startsWith is provider-specific
        // and may compare the spelling of a freshly-created TempDir literally. Keep the
        // component boundary check explicit so "root2" cannot match "root".
        String candidate = normalizedPath.toString();
        String allowed = normalizedRoot.toString();
        if (candidate.equalsIgnoreCase(allowed)) {
            return true;
        }
        if (!candidate.regionMatches(true, 0, allowed, 0, allowed.length())
                || candidate.length() <= allowed.length()) {
            return false;
        }
        return isSeparator(allowed.charAt(allowed.length() - 1))
                || isSeparator(candidate.charAt(allowed.length()));
    }

    private static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win");
    }

    private static boolean isSeparator(char value) {
        return value == '\\' || value == '/';
    }
}
