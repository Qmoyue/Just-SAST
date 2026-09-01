package io.just.sast.verify.legacy;

import java.io.FilePermission;
import java.io.IOException;
import java.net.NetPermission;
import java.net.SocketPermission;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.io.SerializablePermission;
import java.lang.reflect.ReflectPermission;
import java.security.CodeSource;
import java.security.Permission;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/** Java 8 deny-by-default permission layer for the isolated verification JVM. */
@SuppressWarnings("deprecation")
public final class LegacySandboxSecurityManager extends SecurityManager {

    private final Path writableRoot;
    private final Path writableRealRoot;
    private final boolean writableRootRealPathAvailable;
    private final List<Path> readableRoots;
    private final List<Path> readableRealRoots;
    private final String trustedCodeSource;
    private final ThreadLocal<Boolean> resolving = new ThreadLocal<Boolean>();
    /** Lifecycle markers only; never used as a permission grant. */
    private static final ThreadLocal<Integer> SERIALIZATION_BOOTSTRAP_DEPTH =
            new ThreadLocal<Integer>();
    private static final ThreadLocal<Integer> PROXY_BOOTSTRAP_DEPTH =
            new ThreadLocal<Integer>();
    /** Kryo/other serializer construction may need bounded reflective bootstrap access. */
    private static final ThreadLocal<Integer> SOURCE_ADAPTER_DEPTH =
            new ThreadLocal<Integer>();

    private LegacySandboxSecurityManager(Path writableRoot, List<Path> readableRoots) {
        this.writableRoot = normalize(writableRoot);
        this.writableRealRoot = realPath(this.writableRoot);
        this.writableRootRealPathAvailable = canResolveRealPath(this.writableRoot);
        this.readableRoots = new ArrayList<Path>();
        this.readableRealRoots = new ArrayList<Path>();
        for (Path root : readableRoots) {
            Path normalized = normalize(root);
            this.readableRoots.add(normalized);
            this.readableRealRoots.add(realPath(normalized));
        }
        this.trustedCodeSource = codeSourceOf(LegacySandboxSecurityManager.class);
    }

    public static void install(Path writableRoot) {
        if (writableRoot == null || !Files.isDirectory(writableRoot)) {
            throw new IllegalArgumentException("writable root is not a directory");
        }
        SecurityManager existing = System.getSecurityManager();
        if (existing != null) {
            if (existing instanceof LegacySandboxSecurityManager) {
                return;
            }
            throw new SecurityException("another security manager is already installed");
        }
        List<Path> roots = new ArrayList<Path>();
        String classPath = System.getProperty("just.verify.target-cp",
                System.getProperty("java.class.path", ""));
        String separator = java.io.File.pathSeparator;
        for (String entry : classPath.split(java.util.regex.Pattern.quote(separator))) {
            if (!entry.isEmpty()) {
                roots.add(normalize(Paths.get(entry)));
            }
        }
        roots.add(normalize(Paths.get(System.getProperty("user.dir", "."))));
        roots.add(normalize(writableRoot));
        roots.add(normalize(Paths.get(System.getProperty("java.home", "."))));
        System.setSecurityManager(new LegacySandboxSecurityManager(writableRoot, roots));
    }

    @Override
    public void checkPermission(Permission permission) {
        if (permission == null) {
            throw new SecurityException("null permission");
        }
        if (permission instanceof FilePermission) {
            checkFile((FilePermission) permission);
            return;
        }
        if (permission instanceof SocketPermission) {
            throw new SecurityException("network denied: " + permission.getName());
        }
        if (permission instanceof NetPermission) {
            // URLClassPath uses this non-network permission while opening jar resources.
            // It does not grant socket access, but an input JAR must not use it to install
            // an arbitrary handler. Restrict the compatibility grant to the verifier stack.
            if ("specifyStreamHandler".equals(permission.getName())) {
                if (trustedProbeCaller() || trustedSourceAdapterCaller()) {
                    return;
                }
            }
            throw new SecurityException("network permission denied: " + permission.getName());
        }
        if (permission instanceof java.util.PropertyPermission) {
            if (permission.getActions().indexOf("write") >= 0) {
                // JDK 8/11 bootstrap code may materialize a bounded cache while the trusted
                // probe initializes a serializer (for example Kryo's java.time support).
                // This is not a target grant: once control enters application code the first
                // non-platform frame is no longer a verifier frame and the write is denied.
                if (!trustedProbeCaller() && !trustedSourceAdapterCaller()
                        && !trustedSerializerRuntimeCaller()
                        && !("*".equals(permission.getName())
                        && trustedJdkPropertyAccessCaller())) {
                    throw new SecurityException("property write denied: " + permission.getName()
                            + " [caller=" + firstNonPlatformFrameLocation() + "]");
                }
            }
            if ("just.verify.canary-token".equals(permission.getName())
                    && !trustedProbeCaller()) {
                throw new SecurityException("canary attestation read denied");
            }
        }
        if (permission instanceof ReflectPermission || permission instanceof SerializablePermission) {
            // Scope markers are not permission grants. During deserialization and proxy
            // callbacks the target frame is still above the probe; only the first
            // non-platform frame may authorize verifier-internal reflection.
            if (!trustedProbeCaller() && !trustedSourceAdapterCaller()
                    && !(permission instanceof ReflectPermission
                    && (trustedLambdaBootstrapCaller()
                    || trustedSerializerRuntimeCaller()))) {
                throw new SecurityException("reflective/serialization privilege denied: "
                        + permission.getName());
            }
            return;
        }
        if (permission instanceof RuntimePermission) {
            String name = permission.getName();
            if ("setSecurityManager".equals(name) || name.startsWith("loadLibrary")
                    || "createNativeThread".equals(name)
                    || "shutdownHooks".equals(name) || "setIO".equals(name)
                    || "manageProcess".equals(name) || "createClassLoader".equals(name)
                    || "modifyThread".equals(name) || "modifyThreadGroup".equals(name)
                    || "readFileDescriptor".equals(name) || "writeFileDescriptor".equals(name)) {
                // ObjectStreamClass may create a short-lived loader while the trusted probe
                // serializes a callback receiver. The probe code source is already the
                // isolated verifier artifact; target frames are still denied because the
                // first non-platform caller is no longer a verifier frame.
                if ("createClassLoader".equals(name)
                        && (trustedProbeCaller() || trustedSourceAdapterCaller()
                        || trustedLambdaBootstrapCaller()
                        || trustedSerializerRuntimeCaller())) {
                    return;
                }
                throw new SecurityException("runtime permission denied: " + name
                        + " [caller=" + firstNonPlatformFrameLocation() + "]");
            }
            if (name.startsWith("getenv.")) {
                if (Boolean.getBoolean("just.verify.sanitized-env")) {
                    return;
                }
                throw new SecurityException("environment read denied: " + name);
            }
        }
    }

    @Override
    public void checkPackageAccess(String packageName) {
        // The transformed JDK sink resolves the shared canary gate from the bootstrap loader.
        // Keep only this dependency-free package linkable; the verifier and target namespaces
        // remain closed to application code.
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
     * Require the legacy probe's own code source; package names alone are not a trust boundary.
     * Only the first non-platform frame is trusted. Checking for any trusted frame would also
     * bless target code because the probe necessarily remains below the target on its stack.
     */
    private boolean trustedProbeCaller() {
        Class<?>[] context = getClassContext();
        for (Class<?> frame : context) {
            if (frame == LegacySandboxSecurityManager.class || isPlatformFrame(frame)) {
                continue;
            }
            return isVerifierFrame(frame);
        }
        return false;
    }

    /** Narrow compatibility allowance for JDK lambda-constructor linkage. */
    private boolean trustedLambdaBootstrapCaller() {
        boolean metafactory = false;
        boolean constructorAccess = false;
        Class<?>[] context = getClassContext();
        for (Class<?> frame : context) {
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

    static void beginSerializationBootstrap() {
        SecurityManager current = System.getSecurityManager();
        if (!(current instanceof LegacySandboxSecurityManager)
                || !((LegacySandboxSecurityManager) current).trustedProbeCaller()) {
            throw new SecurityException("serialization bootstrap is probe-only");
        }
        Integer depth = SERIALIZATION_BOOTSTRAP_DEPTH.get();
        SERIALIZATION_BOOTSTRAP_DEPTH.set(depth == null ? 1 : depth + 1);
    }

    static void endSerializationBootstrap() {
        Integer depth = SERIALIZATION_BOOTSTRAP_DEPTH.get();
        if (depth == null || depth <= 1) {
            SERIALIZATION_BOOTSTRAP_DEPTH.remove();
        } else {
            SERIALIZATION_BOOTSTRAP_DEPTH.set(depth - 1);
        }
    }

    /** Enter only while the trusted legacy probe serializes an inert source value. */
    static void beginSourceAdapter() {
        SecurityManager current = System.getSecurityManager();
        if (!(current instanceof LegacySandboxSecurityManager)
                || !((LegacySandboxSecurityManager) current).trustedProbeCaller()) {
            throw new SecurityException("source adapter is probe-only");
        }
        Integer depth = SOURCE_ADAPTER_DEPTH.get();
        SOURCE_ADAPTER_DEPTH.set(depth == null ? 1 : depth + 1);
    }

    static void endSourceAdapter() {
        Integer depth = SOURCE_ADAPTER_DEPTH.get();
        if (depth == null || depth <= 1) {
            SOURCE_ADAPTER_DEPTH.remove();
        } else {
            SOURCE_ADAPTER_DEPTH.set(depth - 1);
        }
    }

    static void beginProxyBootstrap() {
        SecurityManager current = System.getSecurityManager();
        if (!(current instanceof LegacySandboxSecurityManager)
                || !((LegacySandboxSecurityManager) current).trustedProbeCaller()) {
            throw new SecurityException("proxy bootstrap is probe-only");
        }
        Integer depth = PROXY_BOOTSTRAP_DEPTH.get();
        PROXY_BOOTSTRAP_DEPTH.set(depth == null ? 1 : depth + 1);
    }

    static void endProxyBootstrap() {
        Integer depth = PROXY_BOOTSTRAP_DEPTH.get();
        if (depth == null || depth <= 1) {
            PROXY_BOOTSTRAP_DEPTH.remove();
        } else {
            PROXY_BOOTSTRAP_DEPTH.set(depth - 1);
        }
    }

    private static boolean isPlatformFrame(Class<?> frame) {
        ClassLoader loader = frame.getClassLoader();
        if (loader == null) {
            return true;
        }
        // Java 9+ loads a substantial part of the JDK through the platform loader rather
        // than the bootstrap loader. The verifier8 artifact is compiled on Java 8, so it
        // cannot link ClassLoader.getPlatformClassLoader() directly; use the stable loader
        // identity instead. On Java 8 the class is absent and the bootstrap check above is
        // the complete platform definition.
        return "jdk.internal.loader.ClassLoaders$PlatformClassLoader"
                .equals(loader.getClass().getName());
    }

    private boolean isVerifierFrame(Class<?> frame) {
        return frame.getName().startsWith("io.just.sast.verify.legacy.")
                && trustedCodeSource != null
                && trustedCodeSource.equals(codeSourceOf(frame));
    }

    /**
     * Allow only serializer implementation frames while the probe prepares inert bytes.
     * This scope is never consulted by the target invocation path: the first non-platform
     * frame must still be a verifier frame or the permission is denied.
     */
    private boolean trustedSourceAdapterCaller() {
        Integer depth = SOURCE_ADAPTER_DEPTH.get();
        if (depth == null || depth <= 0) {
            return false;
        }
        boolean sawProbe = false;
        Class<?>[] context = getClassContext();
        for (Class<?> frame : context) {
            if (frame == LegacySandboxSecurityManager.class || isPlatformFrame(frame)) {
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
     * own bounded deserialization call. This is the one compatibility allowance needed for
     * that serializer runtime; it does not grant target reflection, file, network or native
     * privileges. The first non-platform frame must be a known serializer implementation.
     */
    private boolean trustedSerializerRuntimeCaller() {
        boolean firstNonPlatform = true;
        boolean sawKryo = false;
        for (Class<?> frame : getClassContext()) {
            if (frame == LegacySandboxSecurityManager.class || isPlatformFrame(frame)) {
                continue;
            }
            String name = frame.getName();
            if (firstNonPlatform) {
                firstNonPlatform = false;
                if (!isSerializerFrame(name)) {
                    return false;
                }
            }
            sawKryo = sawKryo || name.startsWith("com.esotericsoftware.kryo.");
        }
        return !firstNonPlatform && sawKryo;
    }

    /**
     * Java 8--11's privileged property helper requests the broad read/write permission used by
     * {@code System.getProperties()}, even when the caller only reads a cached runtime value.
     * Keep that compatibility window tied to an active probe-owned serialization operation and
     * the JDK helper frame; a target direct call to {@code System.getProperties()} remains denied.
     */
    private boolean trustedJdkPropertyAccessCaller() {
        Integer depth = SERIALIZATION_BOOTSTRAP_DEPTH.get();
        if (depth == null || depth <= 0) {
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
        if (firstNonPlatformFrame() == LegacyChainVerifyProbe.class) {
            return;
        }
        throw new SecurityException("target System.exit denied: " + status);
    }

    private Class<?> firstNonPlatformFrame() {
        for (Class<?> frame : getClassContext()) {
            if (frame != LegacySandboxSecurityManager.class && !isPlatformFrame(frame)) {
                return frame;
            }
        }
        return null;
    }

    private String firstNonPlatformFrameLocation() {
        for (StackTraceElement frame : new Throwable().getStackTrace()) {
            String className = frame.getClassName();
            if (className.equals(LegacySandboxSecurityManager.class.getName())
                    || className.startsWith("java.") || className.startsWith("javax.")
                    || className.startsWith("sun.") || className.startsWith("jdk.")) {
                continue;
            }
            return className + "." + frame.getMethodName();
        }
        Class<?> frame = firstNonPlatformFrame();
        return frame == null ? "unknown" : frame.getName();
    }

    @Override
    public void checkExec(String cmd) {
        throw new SecurityException("exec denied: " + cmd);
    }

    @Override
    public void checkLink(String lib) {
        throw new SecurityException("native load denied: " + lib);
    }

    @Override
    public void checkConnect(String host, int port) {
        throw new SecurityException("connect denied: " + host + ":" + port);
    }

    @Override
    public void checkListen(int port) {
        throw new SecurityException("listen denied: " + port);
    }

    @Override
    public void checkAccept(String host, int port) {
        throw new SecurityException("accept denied: " + host + ":" + port);
    }

    @Override
    public void checkMulticast(java.net.InetAddress address) {
        throw new SecurityException("multicast denied: " + address);
    }

    private void checkFile(FilePermission permission) {
        String name = permission.getName();
        if (name == null || "<<ALL FILES>>".equals(name)) {
            throw new SecurityException("unbounded file permission denied");
        }
        Path path = normalize(Paths.get(name));
        String actions = permission.getActions();
        if (actions.indexOf("readlink") >= 0) {
            throw new SecurityException("symbolic-link permission denied: " + path);
        }
        boolean write = actions.indexOf("write") >= 0 || actions.indexOf("delete") >= 0;
        if (write && !safeUnder(path, writableRoot, writableRealRoot)) {
            throw new SecurityException("file write denied: " + path);
        }
        if (actions.indexOf("read") >= 0 && !readable(path)) {
            throw new SecurityException("file read denied: " + path);
        }
        if (actions.indexOf("execute") >= 0 && !safeUnder(path, writableRoot, writableRealRoot)) {
            throw new SecurityException("file execute denied: " + path);
        }
    }

    private boolean readable(Path path) {
        Path resolvedPath = resolveForRead(path);
        for (int i = 0; i < readableRoots.size(); i++) {
            if (safeUnder(path, readableRoots.get(i), readableRealRoots.get(i))) {
                return true;
            }
            // Jabba and managed JDK installers may expose the runtime through a
            // symlink/junction such as jdk/default. Permit reads below the resolved form of
            // the explicitly configured root; writes remain real-path-only below writableRoot.
            Path realRoot = readableRealRoots.get(i);
            if (!realRoot.equals(readableRoots.get(i))
                    && safeUnder(resolvedPath, realRoot, realRoot)) {
                return true;
            }
            // On managed Windows hosts a real-path query can be denied for a freshly
            // materialized classpath tree.  Reads may use a lexical fallback only below an
            // explicit root; every component is still checked for a symbolic link. Writes
            // and executes remain strict real-path checks.
            if (lexicallySafeRead(path, readableRoots.get(i))) {
                return true;
            }
        }
        return false;
    }

    private Path resolveForRead(Path path) {
        boolean alreadyResolving = Boolean.TRUE.equals(resolving.get());
        if (alreadyResolving) {
            return path;
        }
        resolving.set(Boolean.TRUE);
        try {
            return Files.exists(path, LinkOption.NOFOLLOW_LINKS) ? path.toRealPath() : path;
        } catch (IOException | RuntimeException ignored) {
            return path;
        } finally {
            resolving.remove();
        }
    }

    private boolean lexicallySafeRead(Path path, Path root) {
        if (!under(path, root)) {
            return false;
        }
        boolean alreadyResolving = Boolean.TRUE.equals(resolving.get());
        resolving.set(Boolean.TRUE);
        try {
            Path relative = root.relativize(path);
            Path current = root;
            if (isLinkOrReparsePoint(current)) {
                return false;
            }
            for (Path component : relative) {
                current = current.resolve(component);
                if (isLinkOrReparsePoint(current)) {
                    return false;
                }
            }
            return true;
        } catch (RuntimeException denied) {
            return false;
        } finally {
            if (alreadyResolving) {
                resolving.set(Boolean.TRUE);
            } else {
                resolving.remove();
            }
        }
    }

    private boolean safeUnder(Path path, Path lexicalRoot, Path realRoot) {
        if (!under(path, lexicalRoot)) {
            return false;
        }
        if (Boolean.TRUE.equals(resolving.get())) {
            return true;
        }
        resolving.set(Boolean.TRUE);
        try {
            Path existing = path;
            while (existing != null && !Files.exists(existing, LinkOption.NOFOLLOW_LINKS)) {
                existing = existing.getParent();
            }
            if (existing == null) {
                return false;
            }
            if (existing.equals(lexicalRoot)) {
                return under(existing.toRealPath(), realRoot);
            }
            return under(existing.toRealPath(), realRoot);
        } catch (Exception denied) {
            return lexicalRoot.equals(writableRoot) && !writableRootRealPathAvailable
                    && lexicallySafePath(path, lexicalRoot);
        } finally {
            resolving.remove();
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
        } catch (RuntimeException denied) {
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
        } catch (Exception denied) {
            // Some Java 8 Windows providers do not expose the DOS reparse attribute. The
            // parent OS backend remains responsible for that check; retain no-link checks
            // here instead of rejecting every explicitly-created scratch directory.
            return false;
        }
    }

    private static Path normalize(Path path) {
        return path.toAbsolutePath().normalize();
    }

    private static Path realPath(Path path) {
        try {
            return path.toRealPath();
        } catch (Exception ignored) {
            return path;
        }
    }

    private static boolean canResolveRealPath(Path path) {
        try {
            path.toRealPath();
            return true;
        } catch (Exception ignored) {
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
        // Path.startsWith may compare Windows spelling case-sensitively on managed hosts.
        // Compare case-insensitively but retain a path-component boundary.
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
        return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).indexOf("win") >= 0;
    }

    private static boolean isSeparator(char value) {
        return value == '\\' || value == '/';
    }
}
