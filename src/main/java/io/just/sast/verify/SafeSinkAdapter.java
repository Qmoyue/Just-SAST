package io.just.sast.verify;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

import io.just.sast.util.ArchiveLimits;

/**
 * Policy boundary for optional sink adapters.
 *
 * <p>This class deliberately does not invoke a target sink.  It classifies a sink, chooses a
 * safe observation strategy, and validates the only filesystem root an adapter may use.  The
 * default policy is {@link Mode#BOUNDARY}; the canary remains the only operation that enters
 * the target call boundary.  In the explicit {@link Mode#SAFE_EXEC} mode, {@link #observe}
 * performs only a fixed inert/mock operation owned by this class.  It never forwards target
 * arguments, invokes a target method, starts a process, opens a socket, loads code, or follows
 * a target-provided path.</p>
 */
public final class SafeSinkAdapter {

    public enum Mode {
        BOUNDARY,
        SAFE_EXEC
    }

    /** Broad capability families used by the policy, independent of rule ids. */
    public enum Capability {
        COMMAND,
        FILE,
        NETWORK,
        DATA,
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
        DENIED
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
            if (mode == Mode.SAFE_EXEC && scratchRoot == null) {
                throw new IllegalArgumentException("safe-exec requires a scratch root");
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
                    && disposition != Disposition.DENIED;
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

    public static String policyDigest(Mode mode) {
        return mode == Mode.SAFE_EXEC
                ? new Policy(Mode.SAFE_EXEC, Path.of("."), DEFAULT_SAFE_CAPABILITIES).digest()
                : boundary().digest();
    }

    /** Classify from a rule category first, then use conservative owner/name fallbacks. */
    public static Capability capabilityOf(Sink sink) {
        if (sink == null) {
            return Capability.UNKNOWN;
        }
        String category = sink.category().toLowerCase(Locale.ROOT);
        if (containsAny(category, "native", "jni")) {
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
        if (containsAny(category, "ssrf", "network", "jndi", "ldap", "rmi", "jrmp")) {
            return Capability.NETWORK;
        }
        if (containsAny(category, "sql", "database", "jdbc", "message", "jms")) {
            return Capability.DATA;
        }

        String owner = sink.owner().toLowerCase(Locale.ROOT);
        String method = sink.method().toLowerCase(Locale.ROOT);
        if (owner.contains("processbuilder") || owner.contains("runtime")
                || owner.endsWith("/processimpl") || method.equals("exec")) {
            return Capability.COMMAND;
        }
        if (owner.contains("file") || owner.contains("/files") || owner.contains("path")) {
            return Capability.FILE;
        }
        if (owner.contains("socket") || owner.contains("url") || owner.contains("http")
                || owner.contains("naming") || owner.contains("jndi")) {
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
        if (!policy.adapterCapabilities().contains(capability)) {
            // Unsupported families remain at the canary boundary; this is safer and more
            // useful than silently labeling a family as safe just because a policy exists.
            return new Decision(capability, Disposition.CANARY_BOUNDARY, true, true,
                    policy.digest(), "adapter-unavailable");
        }
        return new Decision(capability, dispositionOf(capability), true, true,
                policy.digest(), "safe-adapter-preflight");
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
        AdapterResult preflight = preflight(policy, sink, requestedPath);
        Decision decision = preflight.decision();
        if (!decision.adapterSelected()) {
            return preflight;
        }
        try {
            return switch (decision.disposition()) {
                case INERT_COMMAND -> observeInertCommand(decision);
                case SCRATCH_FILESYSTEM -> observeScratchFilesystem(policy, decision);
                case LOOPBACK_MOCK -> observeLoopbackMock(decision);
                case IN_MEMORY -> observeInMemory(decision);
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

    /** Canonical containment check for an adapter-provided file path. */
    public static boolean isWithinScratch(Policy policy, Path candidate) {
        if (policy == null || policy.scratchRoot() == null || candidate == null
                || policy.mode() != Mode.SAFE_EXEC) {
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

    private static Disposition dispositionOf(Capability capability) {
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
            return "sha256-unavailable-" + Integer.toHexString(value.hashCode());
        }
    }
}
