package io.just.sast.verify;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import io.just.sast.util.ArchiveLimits;

/**
 * Policy boundary for optional sink adapters.
 *
 * <p>This class classifies sinks and owns the non-executing adapter policy.  The default policy
 * is {@link Mode#BOUNDARY}; the canary remains the only operation that enters the target call
 * boundary in that mode.  In the explicit {@link Mode#SAFE_EXEC} mode, {@link #observe} performs
 * only a fixed inert/mock operation owned by this class.  It never forwards target arguments,
 * invokes a target method, starts a process, opens a socket, loads code, or follows a
 * target-provided path.  {@link Mode#SAFE_REAL} is only a preflight contract: its permitted
 * decision is handed to the child bytecode agent, which invokes the exact target API/body with
 * fixed typed arguments under the authenticated OS runner.  A positive safe-real result is
 * callability/integrity evidence with {@code sink_distorted=true}; it is never RCE evidence.</p>
 */
public final class SafeSinkAdapter {

    public enum Mode {
        BOUNDARY,
        SAFE_EXEC,
        SAFE_REAL
    }

    /** Broad capability families used by the policy, independent of rule ids. */
    public enum Capability {
        COMMAND,
        FILE,
        NETWORK,
        DATA,
        /** Remote naming/RMI lookup remains canary-only even in SAFE_REAL. */
        REMOTE_LOOKUP,
        REFLECTION,
        CODE_EXECUTION,
        NATIVE,
        UNKNOWN
    }

    /** The only effects an adapter may claim without entering the target sink body. */
    public enum Disposition {
        CANARY_BOUNDARY,
        INERT_COMMAND,
        SCRATCH_FILESYSTEM,
        LOOPBACK_MOCK,
        IN_MEMORY,
        REAL_COMMAND,
        REAL_SCRATCH_FILESYSTEM,
        REAL_LOOPBACK,
        REAL_IN_MEMORY,
        /** The target method/call is allowed with a typed sanitizer, not an adapter effect. */
        REAL_TARGET_SINK,
        /** A real native fixture is loaded only from the child-owned scratch directory. */
        REAL_NATIVE_FIXTURE,
        DENIED
    }

    /** Explicit real-call families understood by the bytecode agent. */
    public enum RealSinkKind {
        APPLICATION_BODY,
        RUNTIME_EXEC,
        PROCESS_BUILDER_START,
        CLASS_FOR_NAME,
        CLASS_NEW_INSTANCE,
        METHOD_INVOKE,
        CONSTRUCTOR_NEW_INSTANCE,
        FILE_OUTPUT,
        URL_LOOPBACK,
        SOCKET_LOOPBACK,
        NATIVE_FIXTURE,
        UNSUPPORTED
    }

    /** Authorization result for the target-call path; it is not runtime evidence. */
    public record RealPlan(RealSinkKind kind, boolean permitted, String reason) {
        public RealPlan {
            kind = kind == null ? RealSinkKind.UNSUPPORTED : kind;
            reason = reason == null ? "" : reason;
        }
    }

    /** Sink metadata is intentionally value-only so the policy cannot invoke target objects. */
    public record Sink(String category, String owner, String method, String descriptor) {
        public Sink {
            category = normalize(category);
            owner = normalize(owner);
            method = normalize(method);
            descriptor = normalize(descriptor);
        }

        private static String normalize(String value) {
            return value == null ? "" : value.strip();
        }
    }

    /** Immutable per-attempt policy.  The scratch root is validated before construction. */
    public record Policy(Mode mode, Path scratchRoot, Set<Capability> adapterCapabilities) {
        public Policy {
            mode = mode == null ? Mode.BOUNDARY : mode;
            scratchRoot = scratchRoot == null ? null
                    : scratchRoot.toAbsolutePath().normalize();
            adapterCapabilities = adapterCapabilities == null
                    ? Set.of() : Set.copyOf(adapterCapabilities);
            if ((mode == Mode.SAFE_EXEC || mode == Mode.SAFE_REAL) && scratchRoot == null) {
                throw new IllegalArgumentException("safe sink mode requires a scratch root");
            }
        }

        public String digest() {
            // Do not include the random per-attempt path: the digest identifies the policy,
            // not a temporary directory name.  The adapter still receives the validated root.
            StringBuilder canonical = new StringBuilder("JUST_SAFE_SINK_POLICY_V1")
                    .append("|mode=").append(mode.name())
                    .append("|scratch=per-attempt-canonical");
            adapterCapabilities.stream().map(Enum::name).sorted()
                    .forEach(capability -> canonical.append("|adapter=").append(capability));
            return sha256(canonical.toString());
        }
    }

    /** A decision is an authorization result, not evidence that an effect happened. */
    public record Decision(Capability capability, Disposition disposition,
                           boolean permitted, boolean distorted,
                           String policyDigest, String reason) {
        public Decision {
            capability = capability == null ? Capability.UNKNOWN : capability;
            disposition = disposition == null ? Disposition.DENIED : disposition;
            policyDigest = policyDigest == null || policyDigest.isBlank()
                    ? "UNKNOWN" : policyDigest;
            reason = reason == null ? "" : reason;
        }

        /** True only when a safe adapter, not the target sink, owns the operation. */
        public boolean adapterSelected() {
            return permitted && disposition != Disposition.CANARY_BOUNDARY
                    && disposition != Disposition.DENIED
                    && disposition != Disposition.REAL_TARGET_SINK
                    && disposition != Disposition.REAL_NATIVE_FIXTURE;
        }

        /** True when the target API/body itself, rather than this adapter, will run. */
        public boolean targetSinkSelected() {
            return permitted && (disposition == Disposition.REAL_TARGET_SINK
                    || disposition == Disposition.REAL_NATIVE_FIXTURE);
        }
    }

    /** Result of policy preflight or a bounded adapter observation. */
    public record AdapterResult(Decision decision, boolean effectObserved, String effect) {
        public AdapterResult {
            decision = Objects.requireNonNull(decision, "decision");
            effect = effect == null ? "" : effect;
        }
    }

    private static final Set<Capability> DEFAULT_SAFE_CAPABILITIES = Set.of(
            Capability.COMMAND, Capability.FILE, Capability.NETWORK, Capability.DATA);

    private SafeSinkAdapter() {
    }

    /** Default production behavior: no target sink body is entered. */
    public static Policy boundary() {
        return new Policy(Mode.BOUNDARY, null, Set.of());
    }

    /** Create the explicit safe-exec policy after the per-attempt scratch directory exists. */
    public static Policy safeExecution(Path scratchRoot) {
        Path root = requireScratchRoot(scratchRoot);
        return new Policy(Mode.SAFE_EXEC, root, DEFAULT_SAFE_CAPABILITIES);
    }

    /**
     * Create the explicit adapter-owned effect policy. The parent verifier must additionally
     * require an authenticated {@code OS_STRICT} backend before this policy can reach a child.
     */
    public static Policy safeRealExecution(Path scratchRoot) {
        Path root = requireScratchRoot(scratchRoot);
        return new Policy(Mode.SAFE_REAL, root, DEFAULT_SAFE_CAPABILITIES);
    }

    public static String policyDigest(Mode mode) {
        return switch (mode == null ? Mode.BOUNDARY : mode) {
            case SAFE_EXEC -> new Policy(Mode.SAFE_EXEC, Path.of("."),
                    DEFAULT_SAFE_CAPABILITIES).digest();
            case SAFE_REAL -> new Policy(Mode.SAFE_REAL, Path.of("."),
                    DEFAULT_SAFE_CAPABILITIES).digest();
            case BOUNDARY -> boundary().digest();
        };
    }

    /** Stable digest of the adapter-owned effect label, never of target data. */
    public static String effectDigest(String effect) {
        return sha256(effect == null ? "" : effect);
    }

    /** Classify from a rule category first, then use conservative owner/name fallbacks. */
    public static Capability capabilityOf(Sink sink) {
        if (sink == null) {
            return Capability.UNKNOWN;
        }
        String category = sink.category().toLowerCase(Locale.ROOT);
        String owner = sink.owner().toLowerCase(Locale.ROOT);
        String method = sink.method().toLowerCase(Locale.ROOT);
        // Native loading is a stronger safety boundary than a user-provided category.  Keep
        // the API identity check ahead of generic CODE_EXEC labels so an imperfect/custom rule
        // cannot accidentally authorize a library load as a code-execution adapter effect.
        boolean nativeApi = (owner.equals("java/lang/system")
                || owner.equals("java/lang/runtime")
                || owner.endsWith("/runtime"))
                && (method.equals("load") || method.equals("loadlibrary"));
        if (nativeApi || containsAny(category, "native", "jni")) {
            return Capability.NATIVE;
        }
        if (containsAny(category, "template", "script", "spel", "expression", "code")) {
            return Capability.CODE_EXECUTION;
        }
        if (containsAny(category, "reflect", "classload")) {
            return Capability.REFLECTION;
        }
        if (containsAny(category, "command", "process", "exec")) {
            return Capability.COMMAND;
        }
        if (containsAny(category, "file", "path", "filesystem", "xxe")) {
            return Capability.FILE;
        }
        if (containsAny(category, "jndi", "ldap", "rmi", "jrmp", "remote-lookup",
                "remote_lookup")) {
            return Capability.REMOTE_LOOKUP;
        }
        if (containsAny(category, "ssrf", "network")) {
            return Capability.NETWORK;
        }
        if (containsAny(category, "sql", "database", "jdbc", "message", "jms")) {
            return Capability.DATA;
        }

        if (owner.contains("processbuilder") || owner.contains("runtime")
                || owner.endsWith("/processimpl") || method.equals("exec")) {
            return Capability.COMMAND;
        }
        if (owner.contains("file") || owner.contains("/files") || owner.contains("path")) {
            return Capability.FILE;
        }
        // RMI/JRMP/JNDI is a remote lookup boundary even when the rule category is generic.
        // Keep this check independent of the socket/url fallback: java/rmi/* classes do not
        // necessarily contain a socket-like owner token.
        if (owner.startsWith("java/rmi/") || owner.contains("/rmi/")
                || owner.contains("jrmp") || owner.contains("jndi")
                || owner.contains("naming")) {
            return Capability.REMOTE_LOOKUP;
        }
        if (owner.contains("socket") || owner.contains("url") || owner.contains("http")
                || owner.contains("naming") || owner.contains("jndi")) {
            if (owner.contains("rmi")) {
                return Capability.REMOTE_LOOKUP;
            }
            return Capability.NETWORK;
        }
        if (method.equals("invoke") && (owner.contains("method") || owner.contains("constructor"))) {
            return Capability.REFLECTION;
        }
        if (method.contains("loadlibrary") || method.equals("load")) {
            return Capability.NATIVE;
        }
        return Capability.UNKNOWN;
    }

    /**
     * Choose a safe strategy.  This is preflight only; a permitted decision is not an effect
     * and must not be reported as {@code SAFE_SINK_EXECUTED} by itself.
     */
    public static Decision decide(Policy policy, Sink sink) {
        if (policy == null) {
            return new Decision(capabilityOf(sink), Disposition.DENIED, false, true,
                    "UNKNOWN", "policy-missing");
        }
        Capability capability = capabilityOf(sink);
        if (policy.mode() == Mode.BOUNDARY) {
            return new Decision(capability, Disposition.CANARY_BOUNDARY, true, true,
                    policy.digest(), "default-boundary");
        }
        if (policy.mode() == Mode.SAFE_REAL) {
            RealPlan real = realPlan(sink);
            if (real.permitted()) {
                Disposition disposition = real.kind() == RealSinkKind.NATIVE_FIXTURE
                        ? Disposition.REAL_NATIVE_FIXTURE : Disposition.REAL_TARGET_SINK;
                return new Decision(capability, disposition, true, true, policy.digest(),
                        "real-sanitized:" + real.kind().name());
            }
            return new Decision(capability, Disposition.CANARY_BOUNDARY, true, true,
                    policy.digest(), "safe-sanitizer-unavailable:" + real.reason());
        }
        if (!policy.adapterCapabilities().contains(capability)) {
            // Unsupported families remain at the canary boundary; this is safer and more
            // useful than silently labeling a family as safe just because a policy exists.
            return new Decision(capability, Disposition.CANARY_BOUNDARY, true, true,
                    policy.digest(), "adapter-unavailable");
        }
        return new Decision(capability, dispositionOf(capability, policy.mode()), true, true,
                policy.digest(), "safe-adapter-preflight");
    }

    /**
     * Return only target calls for which the agent has a concrete, type-aware sanitizer.
     * Unknown overloads and remote/code-generation families stay at the canary boundary.
     */
    public static RealPlan realPlan(Sink sink) {
        if (sink == null || sink.owner().isEmpty() || sink.method().isEmpty()) {
            return new RealPlan(RealSinkKind.UNSUPPORTED, false, "sink-metadata-missing");
        }
        String owner = sink.owner().replace('.', '/');
        String method = sink.method();
        String descriptor = sink.descriptor();
        if (owner.equals("java/lang/Runtime") && method.equals("exec")
                && commandDescriptor(descriptor)) {
            return new RealPlan(RealSinkKind.RUNTIME_EXEC, true, "fixed-java-version-command");
        }
        if (owner.equals("java/lang/ProcessBuilder") && method.equals("start")
                && "()Ljava/lang/Process;".equals(descriptor)) {
            return new RealPlan(RealSinkKind.PROCESS_BUILDER_START, true,
                    "receiver-command-replaced-before-start");
        }
        if (owner.equals("java/lang/Class") && method.equals("forName")
                && classForNameDescriptor(descriptor)) {
            return new RealPlan(RealSinkKind.CLASS_FOR_NAME, true, "fixed-java-class");
        }
        if (owner.equals("java/lang/Class") && method.equals("newInstance")
                && "()Ljava/lang/Object;".equals(descriptor)) {
            return new RealPlan(RealSinkKind.CLASS_NEW_INSTANCE, true, "fixed-string-class");
        }
        if (owner.equals("java/lang/reflect/Method") && method.equals("invoke")
                && "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;".equals(descriptor)) {
            return new RealPlan(RealSinkKind.METHOD_INVOKE, true, "fixed-noop-method");
        }
        if (owner.equals("java/lang/reflect/Constructor") && method.equals("newInstance")
                && "([Ljava/lang/Object;)Ljava/lang/Object;".equals(descriptor)) {
            return new RealPlan(RealSinkKind.CONSTRUCTOR_NEW_INSTANCE, true,
                    "fixed-safe-constructor");
        }
        if ((owner.equals("java/nio/file/Files") && method.equals("newOutputStream")
                && fileOutputDescriptor(descriptor))
                || ((owner.equals("java/io/FileOutputStream")
                || owner.equals("java/io/FileWriter")) && method.equals("<init>")
                && fileConstructorDescriptor(descriptor))) {
            return new RealPlan(RealSinkKind.FILE_OUTPUT, true, "scratch-path");
        }
        if (owner.equals("java/net/URL")
                && (method.equals("openConnection") || method.equals("openStream"))
                && ("()Ljava/net/URLConnection;".equals(descriptor)
                || "()Ljava/io/InputStream;".equals(descriptor))) {
            return new RealPlan(RealSinkKind.URL_LOOPBACK, true, "fixed-loopback-url");
        }
        if (owner.equals("java/net/Socket") && method.equals("connect")
                && ("(Ljava/net/SocketAddress;)V".equals(descriptor)
                || "(Ljava/net/SocketAddress;I)V".equals(descriptor))) {
            return new RealPlan(RealSinkKind.SOCKET_LOOPBACK, true, "fixed-loopback-address");
        }
        if (owner.equals("java/lang/System") && (method.equals("load")
                || method.equals("loadLibrary")) && stringOnlyDescriptor(descriptor)) {
            return new RealPlan(RealSinkKind.NATIVE_FIXTURE, true,
                    "unique-extracted-native-fixture");
        }
        if (applicationOwner(owner) && safeApplicationDescriptor(descriptor)) {
            return new RealPlan(RealSinkKind.APPLICATION_BODY, true,
                    "typed-string-arguments-and-nested-effect-gate");
        }
        return new RealPlan(RealSinkKind.UNSUPPORTED, false, "safe-sanitizer-unavailable");
    }

    private static boolean applicationOwner(String owner) {
        return !(owner.startsWith("java/") || owner.startsWith("javax/")
                || owner.startsWith("jdk/") || owner.startsWith("sun/")
                || owner.startsWith("com/sun/") || owner.startsWith("io/just/sast/"));
    }

    private static boolean commandDescriptor(String descriptor) {
        return "(Ljava/lang/String;)Ljava/lang/Process;".equals(descriptor)
                || "([Ljava/lang/String;)Ljava/lang/Process;".equals(descriptor)
                || "(Ljava/lang/String;[Ljava/lang/String;)Ljava/lang/Process;".equals(descriptor)
                || "([Ljava/lang/String;[Ljava/lang/String;)Ljava/lang/Process;".equals(descriptor)
                || "(Ljava/lang/String;[Ljava/lang/String;Ljava/io/File;)Ljava/lang/Process;".equals(descriptor)
                || "([Ljava/lang/String;[Ljava/lang/String;Ljava/io/File;)Ljava/lang/Process;".equals(descriptor);
    }

    private static boolean classForNameDescriptor(String descriptor) {
        return "(Ljava/lang/String;)Ljava/lang/Class;".equals(descriptor)
                || "(Ljava/lang/String;ZLjava/lang/ClassLoader;)Ljava/lang/Class;".equals(descriptor);
    }

    private static boolean stringOnlyDescriptor(String descriptor) {
        return "(Ljava/lang/String;)V".equals(descriptor);
    }

    private static boolean fileOutputDescriptor(String descriptor) {
        return "(Ljava/nio/file/Path;[Ljava/nio/file/OpenOption;)Ljava/io/OutputStream;"
                .equals(descriptor);
    }

    private static boolean fileConstructorDescriptor(String descriptor) {
        return "(Ljava/lang/String;)V".equals(descriptor)
                || "(Ljava/io/File;)V".equals(descriptor)
                || "(Ljava/lang/String;Z)V".equals(descriptor)
                || "(Ljava/io/File;Z)V".equals(descriptor);
    }

    private static boolean safeApplicationDescriptor(String descriptor) {
        if (descriptor == null || descriptor.isEmpty() || !descriptor.startsWith("(")) {
            return false;
        }
        int end = descriptor.indexOf(')');
        if (end <= 0) {
            return false;
        }
        String args = descriptor.substring(1, end);
        for (int i = 0; i < args.length();) {
            char type = args.charAt(i++);
            if (type == 'L') {
                int semicolon = args.indexOf(';', i);
                if (semicolon < 0 || !"Ljava/lang/String;".equals(args.substring(i - 1,
                        semicolon + 1))) {
                    return false;
                }
                i = semicolon + 1;
            } else if (type == '[') {
                // The entry sanitizer currently replaces scalar String arguments only.  An
                // array, even String[], can carry a second-order command or reflection value;
                // fail closed until a typed array sanitizer exists for that exact sink family.
                return false;
            } else if ("ZBCSIJFD".indexOf(type) < 0) {
                return false;
            }
        }
        return end + 1 < descriptor.length() && validReturnDescriptor(descriptor, end + 1);
    }

    private static boolean validReturnDescriptor(String descriptor, int offset) {
        char type = descriptor.charAt(offset);
        if ("VZBCSIJFD".indexOf(type) >= 0) {
            return offset + 1 == descriptor.length();
        }
        if (type == 'L') {
            int semicolon = descriptor.indexOf(';', offset + 1);
            return semicolon == descriptor.length() - 1 && semicolon > offset + 1;
        }
        if (type == '[') {
            return false;
        }
        return false;
    }

    /** Apply a path-aware check without touching the target sink or the host filesystem. */
    public static AdapterResult preflight(Policy policy, Sink sink, Path requestedPath) {
        Decision decision = decide(policy, sink);
        if (decision.capability() == Capability.FILE && decision.adapterSelected()
                && requestedPath != null && !isWithinScratch(policy, requestedPath)) {
            decision = new Decision(decision.capability(), Disposition.DENIED, false, true,
                    decision.policyDigest(), "file-path-outside-scratch");
        }
        return new AdapterResult(decision, false, "NO_EFFECT_EXECUTED");
    }

    /**
     * Observe a canary-latched sink through the explicitly selected safe adapter.
     *
     * <p>The returned positive state means that the adapter observed its own fixed mock effect;
     * it is not evidence that the target sink body ran.  The method is intentionally small and
     * synchronous so the child probe can call it after the canary has unwound the target frame.
     * All data used by the effects below is fixed by Just.  In particular, command and network
     * capabilities are represented in memory rather than delegated to the host OS.</p>
     */
    public static AdapterResult observe(Policy policy, Sink sink, Path requestedPath) {
        return observe(policy, sink, requestedPath, null);
    }

    /**
     * Observe with a verifier-owned executable for the fixed command effect. The executable is
     * captured before target code loads; it is never obtained from target arguments or mutable
     * target properties.
     */
    static AdapterResult observe(Policy policy, Sink sink, Path requestedPath,
                                  Path fixedJavaExecutable) {
        AdapterResult preflight = preflight(policy, sink, requestedPath);
        Decision decision = preflight.decision();
        if (policy != null && policy.mode() == Mode.SAFE_REAL) {
            // SAFE_REAL is owned by the child agent.  Running an adapter here would make a
            // target call look real while leaving the target body untouched.
            return new AdapterResult(decision, false, "REAL_TARGET_REQUIRES_CHILD_AGENT");
        }
        if (!decision.adapterSelected()) {
            return preflight;
        }
        try {
            return switch (decision.disposition()) {
                case INERT_COMMAND -> observeInertCommand(decision);
                case SCRATCH_FILESYSTEM -> observeScratchFilesystem(policy, decision);
                case LOOPBACK_MOCK -> observeLoopbackMock(decision);
                case IN_MEMORY -> observeInMemory(decision);
                case REAL_COMMAND -> observeRealCommand(decision, fixedJavaExecutable);
                case REAL_SCRATCH_FILESYSTEM -> observeRealScratchFilesystem(policy, decision);
                case REAL_LOOPBACK -> observeRealLoopback(decision);
                case REAL_IN_MEMORY -> observeRealInMemory(decision);
                default -> preflight;
            };
        } catch (IOException | RuntimeException failure) {
            Decision failed = new Decision(decision.capability(), Disposition.DENIED, false, true,
                    decision.policyDigest(), "safe-effect-failed"
                            + (failure.getClass().getSimpleName().isBlank()
                            ? "" : ":" + failure.getClass().getSimpleName()));
            return new AdapterResult(failed, false, "NO_EFFECT_EXECUTED");
        }
    }

    /** Fixed command representation; no ProcessBuilder/Runtime API is reachable here. */
    private static AdapterResult observeInertCommand(Decision decision) {
        String fixedExecutable = "just-safe-command-canary";
        String fixedArgument = "inert";
        boolean observed = fixedExecutable.startsWith("just-safe-")
                && "inert".equals(fixedArgument);
        return new AdapterResult(decision, observed, "INERT_COMMAND_RECORDED");
    }

    /**
     * Write a fixed marker below the child-owned scratch root.  CREATE_NEW makes a target-side
     * pre-created marker a safe failure instead of silently treating it as an adapter effect.
     */
    private static AdapterResult observeScratchFilesystem(Policy policy, Decision decision)
            throws IOException {
        Path marker = policy.scratchRoot().resolve("just-safe-effect.marker");
        if (!isWithinScratch(policy, marker)) {
            Decision denied = new Decision(decision.capability(), Disposition.DENIED, false, true,
                    decision.policyDigest(), "file-path-outside-scratch");
            return new AdapterResult(denied, false, "NO_EFFECT_EXECUTED");
        }
        Files.writeString(marker, "JUST_SAFE_EFFECT\n", StandardCharsets.US_ASCII,
                java.nio.file.StandardOpenOption.CREATE_NEW,
                java.nio.file.StandardOpenOption.WRITE);
        return new AdapterResult(decision, true, "SCRATCH_MARKER_WRITTEN");
    }

    /** Loopback semantics are modeled as an in-memory request/response, never a real socket. */
    private static AdapterResult observeLoopbackMock(Decision decision) {
        byte[] request = "JUST_LOOPBACK_REQUEST".getBytes(StandardCharsets.US_ASCII);
        byte[] response = request.clone();
        return new AdapterResult(decision, java.util.Arrays.equals(request, response),
                "LOOPBACK_MOCK_IN_MEMORY");
    }

    /** Database/message-like effects use a fixed in-memory key/value exchange. */
    private static AdapterResult observeInMemory(Decision decision) {
        java.util.Map<String, String> fakeStore = new java.util.HashMap<>();
        fakeStore.put("just-safe-key", "JUST_SAFE_VALUE");
        return new AdapterResult(decision,
                "JUST_SAFE_VALUE".equals(fakeStore.get("just-safe-key")),
                "IN_MEMORY_VALUE_OBSERVED");
    }

    /**
     * Start only the verifier's own Java executable with a fixed {@code -version} argument.
     * This is a real process effect, but it is not the target command and carries no target
     * argument. The strict OS runner is the outer boundary; the Java permission gate is only
     * a second line of defense on runtimes that still support it.
     */
    private static AdapterResult observeRealCommand(Decision decision, Path executable)
            throws IOException {
        Path fixed = canonicalExecutable(executable);
        if (fixed == null) {
            return denied(decision, "fixed-helper-missing");
        }
        Process process = null;
        try {
            SandboxSecurityManager.beginSafeRealExec(fixed);
            process = new ProcessBuilder(fixed.toString(), "-version")
                    .redirectOutput(ProcessBuilder.Redirect.DISCARD)
                    .redirectError(ProcessBuilder.Redirect.DISCARD)
                    .start();
            boolean finished = process.waitFor(2L, TimeUnit.SECONDS);
            if (!finished) {
                process.destroyForcibly();
                return denied(decision, "fixed-helper-timeout");
            }
            return new AdapterResult(decision, process.exitValue() == 0,
                    process.exitValue() == 0
                            ? "REAL_FIXED_JAVA_COMMAND" : "REAL_FIXED_COMMAND_FAILED");
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            if (process != null) {
                process.destroyForcibly();
            }
            return denied(decision, "fixed-helper-interrupted");
        } finally {
            SandboxSecurityManager.endSafeRealExec();
        }
    }

    /** A real write remains confined to the already validated scratch root. */
    private static AdapterResult observeRealScratchFilesystem(Policy policy, Decision decision)
            throws IOException {
        AdapterResult result = observeScratchFilesystem(policy, decision);
        if (!result.effectObserved()) {
            return result;
        }
        return new AdapterResult(result.decision(), true, "REAL_SCRATCH_FILE_WRITE");
    }

    /**
     * A real loopback round trip uses literal loopback and fixed bytes. The OS runner must
     * expose only the loopback interface for this mode; no DNS or external address is used.
     */
    private static AdapterResult observeRealLoopback(Decision decision) throws IOException {
        byte[] request = "JUST_LOOPBACK_REQUEST".getBytes(StandardCharsets.US_ASCII);
        SandboxSecurityManager.beginSafeRealNetwork();
        try (java.net.ServerSocket server = new java.net.ServerSocket()) {
            server.bind(new java.net.InetSocketAddress(
                    java.net.InetAddress.getLoopbackAddress(), 0));
            try (java.net.Socket client = new java.net.Socket()) {
                client.connect(server.getLocalSocketAddress(), 500);
                try (java.net.Socket accepted = server.accept()) {
                    accepted.setSoTimeout(500);
                    client.setSoTimeout(500);
                    client.getOutputStream().write(request);
                    client.getOutputStream().flush();
                    byte[] received = accepted.getInputStream().readNBytes(request.length);
                    accepted.getOutputStream().write(received);
                    accepted.getOutputStream().flush();
                    byte[] echoed = client.getInputStream().readNBytes(request.length);
                    return new AdapterResult(decision,
                            java.util.Arrays.equals(request, received)
                                    && java.util.Arrays.equals(request, echoed),
                            "REAL_LOOPBACK_ROUND_TRIP");
                }
            }
        } finally {
            SandboxSecurityManager.endSafeRealNetwork();
        }
    }

    private static AdapterResult observeRealInMemory(Decision decision) {
        java.util.Map<String, String> store = new java.util.HashMap<>();
        store.put("just-safe-key", "JUST_SAFE_VALUE");
        return new AdapterResult(decision,
                "JUST_SAFE_VALUE".equals(store.get("just-safe-key")),
                "REAL_IN_MEMORY_VALUE");
    }

    private static AdapterResult denied(Decision decision, String reason) {
        Decision denied = new Decision(decision.capability(), Disposition.DENIED, false, true,
                decision.policyDigest(), reason);
        return new AdapterResult(denied, false, "NO_EFFECT_EXECUTED");
    }

    private static Path canonicalExecutable(Path executable) {
        if (executable == null) {
            return null;
        }
        try {
            Path path = executable.toAbsolutePath().normalize();
            // A trusted JDK launcher may be exposed through a managed directory
            // link (for example a Jabba java.home). Do not require toRealPath:
            // Windows can deny that metadata lookup while still allowing the
            // exact launcher to execute. The final object is still checked
            // without following a link/reparse point.
            if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)
                    || ArchiveLimits.isLinkOrReparsePoint(path)) {
                return null;
            }
            return path;
        } catch (RuntimeException failure) {
            return null;
        }
    }

    /** Canonical containment check for an adapter-provided file path. */
    public static boolean isWithinScratch(Policy policy, Path candidate) {
        if (policy == null || policy.scratchRoot() == null || candidate == null
                || (policy.mode() != Mode.SAFE_EXEC && policy.mode() != Mode.SAFE_REAL)) {
            return false;
        }
        try {
            Path root = requireScratchRoot(policy.scratchRoot());
            Path normalized = candidate.toAbsolutePath().normalize();
            if (!normalized.startsWith(root)) {
                return false;
            }
            if (Files.isSymbolicLink(normalized)) {
                return false;
            }
            if (Files.exists(normalized)) {
                return startsWithinRealRoot(root, normalized);
            }
            Path parent = normalized.getParent();
            if (parent == null) {
                return false;
            }
            if (ArchiveLimits.isLinkOrReparsePoint(parent)) {
                return false;
            }
            try {
                return parent.toRealPath().startsWith(root.toRealPath());
            } catch (java.nio.file.AccessDeniedException | SecurityException unavailable) {
                // The lexical root was already checked for links/reparse points. A Java
                // permission gate may deny the metadata lookup, so retain containment at the
                // already-normalized boundary rather than turning a safe scratch child into a
                // false negative; a real adapter must still run under the OS boundary.
                return normalized.startsWith(root);
            }
        } catch (IOException | RuntimeException failure) {
            return false;
        }
    }

    private static boolean startsWithinRealRoot(Path root, Path candidate) throws IOException {
        try {
            return candidate.toRealPath().startsWith(root.toRealPath());
        } catch (java.nio.file.AccessDeniedException | SecurityException unavailable) {
            return candidate.toAbsolutePath().normalize().startsWith(root);
        }
    }

    private static Path requireScratchRoot(Path scratchRoot) {
        if (scratchRoot == null) {
            throw new IllegalArgumentException("scratch root is required");
        }
        Path root = scratchRoot.toAbsolutePath().normalize();
        try {
            if (!Files.isDirectory(root) || ArchiveLimits.isLinkOrReparsePoint(root)) {
                throw new IllegalArgumentException("scratch root is not a real directory: " + root);
            }
            try {
                return root.toRealPath();
            } catch (java.nio.file.AccessDeniedException | SecurityException unavailable) {
                // A previously installed Java permission gate can deny the metadata probe
                // even though the parent created this fresh directory. Keep the already
                // absolute, non-reparse lexical root; actual adapter paths still go through
                // isWithinScratch(), which fails closed if its own safety checks are denied.
                return root;
            }
        } catch (IOException e) {
            throw new IllegalArgumentException("scratch root cannot be canonicalized: " + root, e);
        }
    }

    private static Disposition dispositionOf(Capability capability, Mode mode) {
        if (mode == Mode.SAFE_REAL) {
            return switch (capability) {
                case COMMAND -> Disposition.REAL_COMMAND;
                case FILE -> Disposition.REAL_SCRATCH_FILESYSTEM;
                case NETWORK -> Disposition.REAL_LOOPBACK;
                case DATA -> Disposition.REAL_IN_MEMORY;
                default -> Disposition.CANARY_BOUNDARY;
            };
        }
        return switch (capability) {
            case COMMAND -> Disposition.INERT_COMMAND;
            case FILE -> Disposition.SCRATCH_FILESYSTEM;
            case NETWORK -> Disposition.LOOPBACK_MOCK;
            case DATA -> Disposition.IN_MEMORY;
            default -> Disposition.CANARY_BOUNDARY;
        };
    }

    private static boolean containsAny(String value, String... needles) {
        for (String needle : needles) {
            if (value.contains(needle)) {
                return true;
            }
        }
        return false;
    }

    private static String sha256(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder result = new StringBuilder(digest.length * 2);
            for (byte current : digest) {
                result.append(String.format(Locale.ROOT, "%02x", current & 0xff));
            }
            return result.toString();
        } catch (NoSuchAlgorithmException impossible) {
            // SHA-256 is a required JDK primitive for policy/effect identity.  A hashCode
            // fallback would make two distinct observations share an apparently stable
            // identity and would undermine the high-confidence evidence contract.
            throw new IllegalStateException("required SHA-256 digest unavailable", impossible);
        }
    }
}
