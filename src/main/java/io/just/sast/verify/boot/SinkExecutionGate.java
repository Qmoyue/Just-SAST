package io.just.sast.verify.boot;

import java.io.File;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Bootstrap-visible state for the explicit REAL_SANITIZED verifier mode.
 *
 * <p>The agent is allowed to enter a target sink only after it has replaced the dangerous
 * arguments with fixed, type-correct values.  This class owns the small amount of state needed
 * to distinguish a target body/call from the historical canary and from a Just-owned adapter
 * effect.  It deliberately has no dependency on the scanner or on ASM.</p>
 */
public final class SinkExecutionGate {

    public static final String REAL_SANITIZED = "REAL_SANITIZED";
    private static final int MAX_SINKS = 64;
    private static final int MAX_NATIVE_LIBRARIES = 32;
    private static final int MAX_VALUE_LENGTH = 4096;
    private static final String SAFE_INPUT = "JUST_SAFE_INPUT";
    private static final String SAFE_CLASS = "java.lang.String";
    private static final InheritableThreadLocal<Boolean> ENTRY_CONTEXT =
            new InheritableThreadLocal<Boolean>();

    private static volatile boolean configured;
    private static volatile String mode = "";
    private static volatile String executionToken = "";
    private static volatile String entryClass = "";
    private static volatile String entryMethod = "";
    private static volatile String scratchRoot = "";
    private static volatile String nativeRoot = "";
    private static volatile String safeJavaExecutable = "";
    private static volatile Set<String> sinkIdentities = Collections.emptySet();
    private static volatile Map<String, String> nativeLibraries = Collections.emptyMap();
    private static volatile boolean nativeMapConfigured;
    private static volatile boolean bodyEntered;
    private static volatile boolean bodyReturned;
    private static volatile boolean callAttempted;
    private static volatile boolean callObserved;
    private static volatile boolean nestedBlocked;
    private static volatile boolean nativeLoadRequested;
    private static volatile boolean nativeLoadSucceeded;
    private static volatile boolean nativeCallObserved;
    private static volatile String nativeCallSpec = "";
    private static volatile int realSinkCalls;
    private static volatile String lastSanitizer = "";
    private static final ThreadLocal<Boolean> BODY_CONTEXT = new ThreadLocal<>();
    private static final ThreadLocal<String> PENDING_CALL = new ThreadLocal<>();
    private static final ThreadLocal<Boolean> NATIVE_LOAD_CONTEXT = new ThreadLocal<>();

    private static final Method SAFE_NOOP = findNoop();
    private static final Constructor<SafeObject> SAFE_CONSTRUCTOR = findSafeConstructor();

    private SinkExecutionGate() {
    }

    /** Agent-owned one-shot configuration. All input is bounded before it becomes global state. */
    public static synchronized void setExecution(String requestedMode,
                                                  String requestedEntryClass,
                                                  String requestedEntryMethod,
                                                  String requestedSinks,
                                                  String token,
                                                  String requestedScratchRoot,
                                                  String requestedJavaExecutable) {
        setExecution(requestedMode, requestedEntryClass, requestedEntryMethod,
                requestedSinks, token, requestedScratchRoot, requestedScratchRoot,
                requestedJavaExecutable);
    }

    /** Agent-only configuration with a separate read-only root for native fixtures. */
    public static synchronized void setExecution(String requestedMode,
                                                  String requestedEntryClass,
                                                  String requestedEntryMethod,
                                                  String requestedSinks,
                                                  String token,
                                                  String requestedScratchRoot,
                                                  String requestedNativeRoot,
                                                  String requestedJavaExecutable) {
        if (configured || !REAL_SANITIZED.equals(requestedMode) || blank(token)
                || blank(requestedEntryClass) || blank(requestedEntryMethod)) {
            return;
        }
        Set<String> parsed = parseSinks(requestedSinks);
        if (parsed.isEmpty()) {
            return;
        }
        mode = requestedMode;
        executionToken = token;
        entryClass = requestedEntryClass.replace('/', '.');
        entryMethod = requestedEntryMethod;
        scratchRoot = boundedPath(requestedScratchRoot);
        nativeRoot = boundedPath(requestedNativeRoot);
        safeJavaExecutable = boundedPath(requestedJavaExecutable);
        sinkIdentities = Collections.unmodifiableSet(parsed);
        configured = true;
    }

    /** Probe-owned native resource map. It can be installed once after agent premain. */
    public static synchronized void setNativeMap(String token, String encoded) {
        if (!configured || nativeMapConfigured || !sameToken(token)) {
            return;
        }
        installNativeMap(encoded);
    }

    /** Probe-only native map installation; the execution token never crosses the command line. */
    public static synchronized void setNativeMap(String encoded) {
        if (!configured || nativeMapConfigured || !probeCaller()) {
            return;
        }
        installNativeMap(encoded);
    }

    private static void installNativeMap(String encoded) {
        Map<String, String> parsed = new HashMap<String, String>();
        if (encoded != null && encoded.startsWith("v1,")) {
            String[] entries = encoded.substring(3).split(",", -1);
            for (String entry : entries) {
                if (parsed.size() >= MAX_NATIVE_LIBRARIES) {
                    break;
                }
                int equals = entry.indexOf('=');
                if (equals <= 0 || equals == entry.length() - 1) {
                    continue;
                }
                String name = decodeHex(entry.substring(0, equals));
                String path = decodeHex(entry.substring(equals + 1));
                if (blank(name) || blank(path) || path.length() > MAX_VALUE_LENGTH) {
                    continue;
                }
                String normalizedPath = normalizedPath(path);
                if (normalizedPath == null || !withinOwnedRoot(normalizedPath)) {
                    continue;
                }
                String key = nativeKey(name);
                if (!blank(key) && !parsed.containsKey(key)) {
                    parsed.put(key, normalizedPath);
                }
            }
        }
        nativeLibraries = Collections.unmodifiableMap(parsed);
        nativeMapConfigured = true;
    }

    public static boolean configured() {
        return configured && REAL_SANITIZED.equals(mode) && !executionToken.isEmpty();
    }

    /** Mark the verified entry frame so a callback on a child thread keeps the same proof. */
    public static void entryStart(String token) {
        if (sameToken(token) && entryStackFrame()) {
            ENTRY_CONTEXT.set(Boolean.TRUE);
        }
    }

    /** Clear only the current thread; an inherited callback context is intentionally retained. */
    public static void entryEnd(String token) {
        if (sameToken(token)) {
            ENTRY_CONTEXT.remove();
        }
    }

    /** Exact non-native sink method entry. The method body is now genuinely running. */
    public static void enter(String spec, String token) {
        if (!authorized(spec, token)) {
            return;
        }
        bodyEntered = true;
        BODY_CONTEXT.set(Boolean.TRUE);
        realSinkCalls++;
    }

    /** Record a normal return from the exact target sink body. */
    public static void bodyExit(String spec, String token) {
        if (authorized(spec, token) && Boolean.TRUE.equals(BODY_CONTEXT.get())) {
            bodyReturned = true;
            BODY_CONTEXT.remove();
        }
    }

    /** Exact sink call-site observation for native/abstract/JDK methods. */
    public static void beforeCall(String spec, String token) {
        if (!authorized(spec, token) || realSinkCalls >= 8
                || PENDING_CALL.get() != null) {
            return;
        }
        callAttempted = true;
        PENDING_CALL.set(spec);
        realSinkCalls++;
    }

    /** Record a target API only after the invocation returned normally. */
    public static void afterCall(String spec, String token) {
        if (!authorized(spec, token) || realSinkCalls >= 8
                || !spec.equals(PENDING_CALL.get())) {
            return;
        }
        callObserved = true;
        PENDING_CALL.remove();
        realSinkCalls++;
    }

    /** A native method call observed from the authenticated entry frame. */
    public static void nativeCall(String token) {
        nativeCall("", token);
    }

    /** A native method call observed after the transformer matched owner/name/descriptor. */
    public static void nativeCall(String spec, String token) {
        if (sameToken(token) && trustedEntryFrame()
                && nativeLoadSucceeded) {
            ENTRY_CONTEXT.set(Boolean.TRUE);
            nativeCallSpec = safeLabel(spec);
            nativeCallObserved = true;
        }
    }

    /**
     * Block a dangerous operation made by the target sink body. The latch survives target
     * catches, while the Error prevents ordinary catch(Exception) gadgets from continuing it.
     */
    public static void blockNested(String capability, String token) {
        if (sameToken(token) && trustedEntryFrame()) {
            nestedBlocked = true;
            throw new SinkReachedError("SAFE_NESTED_BLOCKED:" + safeLabel(capability));
        }
    }

    public static boolean bodyEntered() {
        return bodyEntered;
    }

    public static boolean bodyReturned() {
        return bodyReturned;
    }

    public static boolean callObserved() {
        return callObserved;
    }

    public static boolean callAttempted() {
        return callAttempted;
    }

    public static boolean nestedBlocked() {
        return nestedBlocked;
    }

    public static boolean nativeLoadRequested() {
        return nativeLoadRequested;
    }

    public static boolean nativeLoadSucceeded() {
        return nativeLoadSucceeded;
    }

    public static boolean nativeCallObserved() {
        return nativeCallObserved;
    }

    public static String nativeCallSpec() {
        return nativeCallSpec;
    }

    public static String sanitizer() {
        return lastSanitizer;
    }

    /** Replace a string argument with a fixed value. */
    public static String safeString(String ignored, String token) {
        requireToken(token);
        lastSanitizer = "STRING_FIXED";
        return SAFE_INPUT;
    }

    public static boolean safeBoolean(boolean ignored, String token) {
        requireToken(token);
        lastSanitizer = "BOOLEAN_FIXED_FALSE";
        return false;
    }

    public static byte safeByte(byte ignored, String token) {
        requireToken(token);
        lastSanitizer = "BYTE_FIXED_ZERO";
        return 0;
    }

    public static short safeShort(short ignored, String token) {
        requireToken(token);
        lastSanitizer = "SHORT_FIXED_ZERO";
        return 0;
    }

    public static int safeInt(int ignored, String token) {
        requireToken(token);
        lastSanitizer = "INT_FIXED_ZERO";
        return 0;
    }

    public static long safeLong(long ignored, String token) {
        requireToken(token);
        lastSanitizer = "LONG_FIXED_ZERO";
        return 0L;
    }

    public static float safeFloat(float ignored, String token) {
        requireToken(token);
        lastSanitizer = "FLOAT_FIXED_ZERO";
        return 0.0f;
    }

    public static double safeDouble(double ignored, String token) {
        requireToken(token);
        lastSanitizer = "DOUBLE_FIXED_ZERO";
        return 0.0d;
    }

    public static char safeChar(char ignored, String token) {
        requireToken(token);
        lastSanitizer = "CHAR_FIXED_ZERO";
        return 0;
    }

    /** Replace Runtime.exec's scalar command with the verifier-owned safe Java command. */
    public static String safeCommand(String ignored, String token) {
        requireToken(token);
        if (blank(safeJavaExecutable)) {
            throw new IllegalStateException("safe-java-executable-missing");
        }
        lastSanitizer = "COMMAND_FIXED_JAVA_VERSION";
        // Runtime.exec(String) tokenizes its input and does not provide a portable way to
        // quote an executable path.  Use the fixed JDK basename and let the child environment
        // expose only that JDK bin directory; the security/OS boundary checks the basename too.
        return javaExecutableName() + " -version";
    }

    /** Replace Runtime.exec's array command with a fixed two-element command. */
    public static String[] safeCommandArray(String[] ignored, String token) {
        requireToken(token);
        if (blank(safeJavaExecutable)) {
            throw new IllegalStateException("safe-java-executable-missing");
        }
        lastSanitizer = "COMMAND_ARRAY_FIXED_JAVA_VERSION";
        return new String[]{safeJavaExecutable, "-version"};
    }

    public static String[] safeEnvironment(String[] ignored, String token) {
        requireToken(token);
        lastSanitizer = "ENVIRONMENT_EMPTY";
        return new String[0];
    }

    public static File safeWorkingDirectory(File ignored, String token) {
        requireToken(token);
        lastSanitizer = "WORKING_DIRECTORY_DEFAULT";
        return null;
    }

    /** Mutate a ProcessBuilder receiver before the real start() body runs. */
    public static ProcessBuilder safeProcessBuilder(ProcessBuilder builder, String token) {
        requireToken(token);
        if (builder == null || blank(safeJavaExecutable)) {
            throw new IllegalStateException("safe-process-builder-unavailable");
        }
        builder.command(Arrays.asList(safeJavaExecutable, "-version"));
        builder.redirectInput(ProcessBuilder.Redirect.PIPE);
        builder.redirectOutput(ProcessBuilder.Redirect.DISCARD);
        builder.redirectError(ProcessBuilder.Redirect.DISCARD);
        lastSanitizer = "PROCESS_BUILDER_FIXED_JAVA_VERSION";
        return builder;
    }

    /** A scratch-only path for Files/FileOutputStream families. */
    public static Path safePath(Path ignored, String token) {
        requireToken(token);
        lastSanitizer = "PATH_FIXED_SCRATCH";
        return scratchPath();
    }

    public static String safeFilePath(String ignored, String token) {
        requireToken(token);
        lastSanitizer = "FILE_FIXED_SCRATCH";
        return scratchPath().toString();
    }

    public static File safeFile(File ignored, String token) {
        requireToken(token);
        lastSanitizer = "FILE_OBJECT_FIXED_SCRATCH";
        return scratchPath().toFile();
    }

    public static String safeClassName(String ignored, String token) {
        requireToken(token);
        lastSanitizer = "CLASS_NAME_FIXED_STRING";
        return SAFE_CLASS;
    }

    public static Class<?> safeClass(Object ignored, String token) {
        requireToken(token);
        lastSanitizer = "CLASS_FIXED_STRING";
        return String.class;
    }

    public static ClassLoader safeClassLoader(ClassLoader ignored, String token) {
        requireToken(token);
        lastSanitizer = "CLASS_LOADER_BOOTSTRAP";
        return null;
    }

    public static Object safeInvocationTarget(Object ignored, String token) {
        requireToken(token);
        lastSanitizer = "REFLECTION_TARGET_NULL";
        return null;
    }

    public static Method safeMethod(Object ignored, String token) {
        requireToken(token);
        if (SAFE_NOOP == null) {
            throw new IllegalStateException("safe-method-unavailable");
        }
        lastSanitizer = "METHOD_FIXED_NOOP";
        return SAFE_NOOP;
    }

    public static Constructor<?> safeConstructor(Object ignored, String token) {
        requireToken(token);
        if (SAFE_CONSTRUCTOR == null) {
            throw new IllegalStateException("safe-constructor-unavailable");
        }
        lastSanitizer = "CONSTRUCTOR_FIXED_SAFE_OBJECT";
        return SAFE_CONSTRUCTOR;
    }

    public static Object[] safeArguments(Object[] ignored, String token) {
        requireToken(token);
        lastSanitizer = "REFLECTION_ARGS_EMPTY";
        return new Object[0];
    }

    public static java.nio.file.OpenOption[] safeOpenOptions(
            java.nio.file.OpenOption[] ignored, String token) {
        requireToken(token);
        lastSanitizer = "OPEN_OPTIONS_EMPTY";
        return new java.nio.file.OpenOption[0];
    }

    public static int safeTimeout(int ignored, String token) {
        requireToken(token);
        lastSanitizer = "TIMEOUT_FIXED";
        return 50;
    }

    public static URL safeUrl(Object ignored, String token) {
        requireToken(token);
        try {
            lastSanitizer = "URL_FIXED_LOOPBACK";
            return new URL("http://127.0.0.1:1/just-safe");
        } catch (Exception failure) {
            throw new IllegalStateException("safe-url-unavailable", failure);
        }
    }

    public static java.net.Socket safeSocket(Object ignored, String token) {
        requireToken(token);
        try {
            lastSanitizer = "SOCKET_FIXED_LOOPBACK";
            return new java.net.Socket();
        } catch (Exception failure) {
            throw new IllegalStateException("safe-socket-unavailable", failure);
        }
    }

    public static InetSocketAddress safeSocketAddress(Object ignored, String token) {
        requireToken(token);
        lastSanitizer = "SOCKET_ADDRESS_FIXED_LOOPBACK";
        return new InetSocketAddress("127.0.0.1", 1);
    }

    /** Rewrite System.load's target to the verifier-owned extracted fixture. */
    public static String rewriteNativeLoad(String requested, String token) {
        requireToken(token);
        String path = firstNativePath();
        if (path == null) {
            throw new UnsatisfiedLinkError("native fixture not approved");
        }
        nativeLoadRequested = true;
        NATIVE_LOAD_CONTEXT.set(Boolean.TRUE);
        lastSanitizer = "NATIVE_EXTRACTED_ABSOLUTE_PATH";
        return path;
    }

    /** Rewrite System.loadLibrary's target to the verifier-owned fixture basename. */
    public static String safeNativeLibraryName(String ignored, String token) {
        requireToken(token);
        String path = firstNativePath();
        if (path == null) {
            throw new UnsatisfiedLinkError("native fixture not approved");
        }
        nativeLoadRequested = true;
        NATIVE_LOAD_CONTEXT.set(Boolean.TRUE);
        lastSanitizer = "NATIVE_FIXED_LIBRARY_NAME";
        List<String> keys = new ArrayList<String>(nativeLibraries.keySet());
        Collections.sort(keys);
        for (String key : keys) {
            String stem = nativeStem(key);
            if (!blank(stem) && path.equals(nativeLibraries.get(key))) {
                return stem;
            }
        }
        throw new UnsatisfiedLinkError("native fixture name unavailable");
    }

    /** Called only after System.load returns normally. */
    public static void nativeLoadSucceeded(String token) {
        if (sameToken(token) && trustedEntryFrame() && nativeLoadRequested
                && Boolean.TRUE.equals(NATIVE_LOAD_CONTEXT.get())) {
            nativeLoadSucceeded = true;
            NATIVE_LOAD_CONTEXT.remove();
        }
    }

    /** SecurityManager checkLink hook for pre-approved extracted paths. */
    public static boolean isApprovedNativePath(String requested) {
        if (!configured || !trustedEntryFrame() || requested == null) {
            return false;
        }
        String normalized = normalizedPath(requested);
        if (normalized != null) {
            for (String value : nativeLibraries.values()) {
                if (value.equals(normalized)) return true;
            }
        }
        String key = nativeKey(requested);
        boolean bareName = requested.indexOf('/') < 0 && requested.indexOf('\\') < 0
                && requested.indexOf('!') < 0 && !requested.startsWith("file:");
        if (bareName) {
            for (String approved : nativeLibraries.keySet()) {
                if (approved.equals(key)) return true;
            }
        }
        return false;
    }

    /** Allow only the scalar Runtime.exec form rewritten by safeCommand. */
    public static boolean isApprovedJavaCommand(String command) {
        if (!configured || !trustedEntryFrame() || blank(command)) {
            return false;
        }
        String value = command.trim();
        if (value.equals(javaExecutableName())) {
            return true;
        }
        String normalized = normalizedPath(value);
        return normalized != null && normalized.equals(normalizedPath(safeJavaExecutable));
    }

    /** Allow only the fixed harmless loopback endpoint used by URL/Socket probes. */
    public static boolean isApprovedLoopback(String host, int port) {
        return configured && trustedEntryFrame() && port == 1 && isLoopback(host);
    }

    /** Safe target for reflective Method.invoke. */
    public static void noop() {
    }

    /** Safe target for reflective Constructor.newInstance. */
    public static final class SafeObject {
        public SafeObject() {
        }
    }

    private static boolean authorized(String spec, String token) {
        return configured && REAL_SANITIZED.equals(mode) && sameToken(token)
                && exactSink(spec) && trustedEntryFrame();
    }

    private static boolean exactSink(String spec) {
        if (blank(spec)) {
            return false;
        }
        int first = spec.indexOf('#');
        int second = first < 0 ? -1 : spec.indexOf('#', first + 1);
        if (first <= 0 || second <= first + 1) {
            return false;
        }
        String owner = spec.substring(0, first).replace('/', '.');
        String method = spec.substring(first + 1, second);
        String descriptor = spec.substring(second + 1);
        for (String expected : sinkIdentities) {
            int expectedFirst = expected.indexOf('#');
            int expectedSecond = expectedFirst < 0 ? -1 : expected.indexOf('#', expectedFirst + 1);
            if (expectedFirst <= 0 || expectedSecond <= expectedFirst + 1) {
                continue;
            }
            String expectedOwner = expected.substring(0, expectedFirst).replace('/', '.');
            String expectedMethod = expected.substring(expectedFirst + 1, expectedSecond);
            String expectedDescriptor = expected.substring(expectedSecond + 1);
            if (owner.equals(expectedOwner) && method.equals(expectedMethod)
                    && (expectedDescriptor.isEmpty() || expectedDescriptor.equals(descriptor))) {
                return true;
            }
        }
        return false;
    }

    private static boolean trustedEntryFrame() {
        return entryFrame() || Boolean.TRUE.equals(ENTRY_CONTEXT.get());
    }

    private static boolean entryStackFrame() {
        StackTraceElement[] stack = new Throwable().getStackTrace();
        for (int i = 2; i < stack.length; i++) {
            StackTraceElement frame = stack[i];
            if (entryClass.equals(frame.getClassName())
                    && entryMethod.equals(frame.getMethodName())) {
                return true;
            }
            // A native library is often loaded from the entry class initializer before the
            // Java entry method is invoked. Only that exact initializer is accepted.
            if (entryClass.equals(frame.getClassName())
                    && "<clinit>".equals(frame.getMethodName())) {
                return true;
            }
        }
        return false;
    }

    private static boolean entryFrame() {
        return entryStackFrame();
    }

    private static boolean sameToken(String token) {
        return configured && token != null && executionToken.equals(token);
    }

    private static void requireToken(String token) {
        if (!sameToken(token)) {
            throw new SecurityException("safe sanitizer token mismatch");
        }
    }

    private static Path scratchPath() {
        if (blank(scratchRoot)) {
            throw new IllegalStateException("scratch-root-missing");
        }
        return Paths.get(scratchRoot).toAbsolutePath().normalize().resolve("just-real-sink.marker")
                .normalize();
    }

    private static Set<String> parseSinks(String encoded) {
        if (encoded == null || encoded.length() > MAX_VALUE_LENGTH * 2) {
            return Collections.emptySet();
        }
        Set<String> result = new HashSet<String>();
        for (String spec : encoded.split(",", -1)) {
            if (result.size() >= MAX_SINKS || !validSink(spec)) {
                continue;
            }
            result.add(spec);
        }
        return result;
    }

    private static boolean validSink(String spec) {
        if (blank(spec) || spec.length() > MAX_VALUE_LENGTH) {
            return false;
        }
        int first = spec.indexOf('#');
        int second = first < 0 ? -1 : spec.indexOf('#', first + 1);
        return first > 0 && second > first + 1 && second < spec.length() - 1;
    }

    private static String nativeKey(String requested) {
        if (requested == null) {
            return "";
        }
        String value = requested.replace('\\', '/');
        int bang = value.lastIndexOf('!');
        if (bang >= 0 && bang < value.length() - 1) {
            value = value.substring(bang + 1);
        }
        int slash = value.lastIndexOf('/');
        if (slash >= 0 && slash < value.length() - 1) {
            value = value.substring(slash + 1);
        }
        if (value.startsWith("file:")) {
            value = value.substring(5);
        }
        value = value.toLowerCase();
        if (value.endsWith(".dll") || value.endsWith(".dylib")) {
            return value;
        }
        if (value.endsWith(".so")) {
            return value;
        }
        if (value.endsWith(".so.1") || value.endsWith(".so.2")) {
            return value;
        }
        if (!value.isEmpty()) {
            return value;
        }
        return "";
    }

    private static String firstNativePath() {
        List<String> keys = new ArrayList<String>(nativeLibraries.keySet());
        Collections.sort(keys);
        for (String key : keys) {
            String value = nativeLibraries.get(key);
            if (!blank(value)) {
                return value;
            }
        }
        return null;
    }

    private static String nativeStem(String key) {
        if (blank(key)) {
            return "";
        }
        String value = key.toLowerCase();
        for (String suffix : new String[]{".dll", ".dylib", ".so.1", ".so.2", ".so"}) {
            if (value.endsWith(suffix)) {
                return value.substring(0, value.length() - suffix.length());
            }
        }
        return value;
    }

    private static String normalizedPath(String value) {
        if (blank(value) || value.length() > MAX_VALUE_LENGTH) {
            return null;
        }
        try {
            return Paths.get(value).toAbsolutePath().normalize().toString();
        } catch (RuntimeException failure) {
            return null;
        }
    }

    private static String boundedPath(String value) {
        return value == null || value.length() > MAX_VALUE_LENGTH ? "" : value;
    }

    private static boolean withinScratch(String value) {
        if (blank(value) || blank(scratchRoot)) return false;
        try {
            Path root = Paths.get(scratchRoot).toAbsolutePath().normalize();
            Path candidate = Paths.get(value).toAbsolutePath().normalize();
            return candidate.startsWith(root);
        } catch (RuntimeException failure) {
            return false;
        }
    }

    private static boolean withinOwnedRoot(String value) {
        if (withinScratch(value)) {
            return true;
        }
        if (blank(nativeRoot)) {
            return false;
        }
        try {
            Path root = Paths.get(nativeRoot).toAbsolutePath().normalize();
            Path candidate = Paths.get(value).toAbsolutePath().normalize();
            return candidate.startsWith(root);
        } catch (RuntimeException failure) {
            return false;
        }
    }

    private static boolean probeCaller() {
        StackTraceElement[] stack = new Throwable().getStackTrace();
        for (int i = 2; i < stack.length; i++) {
            String type = stack[i].getClassName();
            if ("io.just.sast.verify.ChainVerifyProbe".equals(type)
                    || "io.just.sast.verify.legacy.LegacyChainVerifyProbe".equals(type)) {
                return "configureNativeFixtures".equals(stack[i].getMethodName());
            }
        }
        return false;
    }

    private static String javaExecutableName() {
        String value = safeJavaExecutable.replace('\\', '/');
        int slash = value.lastIndexOf('/');
        return slash >= 0 ? value.substring(slash + 1) : value;
    }

    private static boolean isLoopback(String host) {
        if (host == null) {
            return false;
        }
        String value = host.trim();
        return "127.0.0.1".equals(value) || "localhost".equalsIgnoreCase(value)
                || "::1".equals(value) || "0:0:0:0:0:0:0:1".equals(value);
    }

    private static String decodeHex(String value) {
        if (value == null || value.length() == 0 || (value.length() & 1) != 0
                || value.length() > MAX_VALUE_LENGTH * 2) {
            return "";
        }
        byte[] bytes = new byte[value.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            int high = Character.digit(value.charAt(i * 2), 16);
            int low = Character.digit(value.charAt(i * 2 + 1), 16);
            if (high < 0 || low < 0) {
                return "";
            }
            bytes[i] = (byte) ((high << 4) | low);
        }
        return new String(bytes, StandardCharsets.UTF_8);
    }

    private static boolean blank(String value) {
        return value == null || value.length() == 0;
    }

    private static String safeLabel(String value) {
        if (value == null) {
            return "";
        }
        return value.replace('\r', '_').replace('\n', '_').replace('|', '_')
                .substring(0, Math.min(value.length(), 96));
    }

    private static Method findNoop() {
        try {
            return SinkExecutionGate.class.getDeclaredMethod("noop");
        } catch (Exception ignored) {
            return null;
        }
    }

    @SuppressWarnings("unchecked")
    private static Constructor<SafeObject> findSafeConstructor() {
        try {
            return SafeObject.class.getDeclaredConstructor();
        } catch (Exception ignored) {
            return null;
        }
    }
}
