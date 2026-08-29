package io.just.sast.verify.legacy;

import java.io.FilePermission;
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
    private final List<Path> readableRoots;
    private final List<Path> readableRealRoots;
    private final String trustedCodeSource;
    private final ThreadLocal<Boolean> resolving = new ThreadLocal<Boolean>();
    /** Lifecycle markers only; never used as a permission grant. */
    private static final ThreadLocal<Integer> SERIALIZATION_BOOTSTRAP_DEPTH =
            new ThreadLocal<Integer>();
    private static final ThreadLocal<Integer> PROXY_BOOTSTRAP_DEPTH =
            new ThreadLocal<Integer>();

    private LegacySandboxSecurityManager(Path writableRoot, List<Path> readableRoots) {
        this.writableRoot = normalize(writableRoot);
        this.writableRealRoot = realPath(this.writableRoot);
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
        String classPath = System.getProperty("java.class.path", "");
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
            // It does not grant socket access or URL factory installation; those capabilities
            // remain denied below/through RuntimePermission. Keeping this JDK plumbing
            // consistent with the modern verifier avoids framework class-loading false
            // negatives on Java 8.
            if ("specifyStreamHandler".equals(permission.getName())) {
                return;
            }
            throw new SecurityException("network permission denied: " + permission.getName());
        }
        if (permission instanceof java.util.PropertyPermission
                && permission.getActions().indexOf("write") >= 0) {
            throw new SecurityException("property write denied: " + permission.getName());
        }
        if (permission instanceof ReflectPermission || permission instanceof SerializablePermission) {
            // Scope markers are not permission grants. During deserialization and proxy
            // callbacks the target frame is still above the probe; only the first
            // non-platform frame may authorize verifier-internal reflection.
            if (!trustedProbeCaller()) {
                throw new SecurityException("reflective/serialization privilege denied: "
                        + permission.getName());
            }
            return;
        }
        if (permission instanceof RuntimePermission) {
            String name = permission.getName();
            if ("setSecurityManager".equals(name) || name.startsWith("loadLibrary")
                    || name.startsWith("getenv.") || "createNativeThread".equals(name)
                    || "shutdownHooks".equals(name) || "setIO".equals(name)
                    || "manageProcess".equals(name) || "createClassLoader".equals(name)
                    || "modifyThread".equals(name) || "modifyThreadGroup".equals(name)
                    || "readFileDescriptor".equals(name) || "writeFileDescriptor".equals(name)) {
                throw new SecurityException("runtime permission denied: " + name);
            }
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
        return frame.getClassLoader() == null;
    }

    private boolean isVerifierFrame(Class<?> frame) {
        return frame.getName().startsWith("io.just.sast.verify.legacy.")
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

    @Override
    public void checkExec(String cmd) {
        throw new SecurityException("exec denied: " + cmd);
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
        for (int i = 0; i < readableRoots.size(); i++) {
            if (safeUnder(path, readableRoots.get(i), readableRealRoots.get(i))) {
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

    private boolean lexicallySafeRead(Path path, Path root) {
        if (!under(path, root)) {
            return false;
        }
        boolean alreadyResolving = Boolean.TRUE.equals(resolving.get());
        resolving.set(Boolean.TRUE);
        try {
            Path relative = root.relativize(path);
            Path current = root;
            if (Files.isSymbolicLink(current)) {
                return false;
            }
            for (Path component : relative) {
                current = current.resolve(component);
                if (Files.isSymbolicLink(current)) {
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
            if (existing == null || existing.equals(lexicalRoot)) {
                return existing != null;
            }
            return under(existing.toRealPath(), realRoot);
        } catch (Exception denied) {
            return false;
        } finally {
            resolving.remove();
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

    private static boolean under(Path path, Path root) {
        return path.equals(root) || path.startsWith(root);
    }
}
