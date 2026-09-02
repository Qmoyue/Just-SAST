package io.just.sast.verify;

import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.platform.win32.BaseTSD;
import com.sun.jna.win32.StdCallLibrary;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.stream.Stream;

import io.just.sast.util.JustLogger;

/**
 * Selects the strongest small OS boundary that is available on the current host.
 *
 * <p>The JVM permission layer is deliberately not treated as an OS sandbox. On Windows the
 * parent owns a Job Object before it releases the child probe through the ready-file handshake;
 * on Linux a pre-existing bubblewrap installation can provide a read-only root, private PID and
 * network namespaces. A missing backend is a capability failure, never a reason to silently run
 * an untrusted target in the scanner JVM's process boundary.</p>
 */
public final class OsIsolation {

    /** Wire-level version of the child-side isolation attestation. */
    public static final String ATTESTATION_VERSION = "JUST_OS_ATTESTATION_V1";

    /** Capability levels are facts about the selected backend, not marketing labels. */
    public enum Level {
        NONE,
        PROCESS_RESOURCE,
        OS_NAMESPACE,
        OS_STRICT
    }

    private static final int PROCESS_TERMINATE = 0x0001;
    private static final int PROCESS_SET_QUOTA = 0x0100;
    private static final int PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    private static final int JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9;
    private static final int JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008;
    private static final int JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100;
    private static final int JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
    private static final int MAX_CHILD_PROCESSES = 64;
    private static final long MAX_PROCESS_MEMORY = 768L * 1024L * 1024L;
    private static final long MAX_ROOT_DIGEST_BYTES = 8L * 1024L * 1024L * 1024L;
    /** A capability probe is a bounded startup check, not a second verification job. */
    private static final long APP_CONTAINER_PROBE_TIMEOUT_MS = 4_000L;
    private static final long APP_CONTAINER_TERMINATION_GRACE_MS = 250L;
    private static final Set<String> STRICT_PRODUCTION_CAPABILITIES = Set.of(
            "runner_attestation", "process_tree", "resource_limits",
            "filesystem_policy", "network_policy");
    private static volatile boolean nativeLibrariesPrewarming;

    private OsIsolation() {
    }

    /** A selected launcher is immutable and safe to share between verification tasks. */
    public interface Backend {
        String id();

        boolean available();

        String reason();

        /** Wrap a child command when the backend needs a namespace launcher. */
        List<String> command(List<String> childCommand, Path scratchDirectory);

        /**
         * Wrap a child command with the requested network shape. The two-argument method is
         * retained for extensions; SAFE_REAL uses the explicit loopback variant so a backend
         * cannot accidentally widen a boundary merely because an adapter was enabled.
         */
        default List<String> command(List<String> childCommand, Path scratchDirectory,
                                     boolean loopbackOnly) {
            return command(childCommand, scratchDirectory);
        }

        /** Attach containment after start and before the child ready marker is released. */
        Session attach(Process process) throws IOException;

        /** Effective containment strength; old extension backends default to no OS claim. */
        default Level level() {
            return Level.NONE;
        }

        /** Stable capability names suitable for a report or policy audit. */
        default Set<String> capabilities() {
            return Set.of();
        }

        /** Version of the child-side proof contract, not a claim about sandbox strength. */
        default String attestationVersion() {
            return ATTESTATION_VERSION;
        }

        /** True only when all production preconditions have been checked by this backend. */
        default boolean productionReady() {
            return level() == Level.OS_STRICT
                    && capabilities().containsAll(STRICT_PRODUCTION_CAPABILITIES);
        }

        /** Digest of the immutable backend policy, excluding host-specific paths. */
        default String policyDigest() {
            List<String> names = new ArrayList<>(capabilities());
            Collections.sort(names);
            return digest(id() + "|" + level() + "|attestation="
                    + attestationVersion() + "|" + names);
        }
    }

    public interface Session extends AutoCloseable {
        String backend();

        void terminate();

        @Override
        void close();
    }

    public static Backend select() {
        return select(null);
    }

    /**
     * Warm only trusted Windows API bindings while the static pipeline is busy. This is an
     * optional latency optimization; strict selection still performs the authoritative broker
     * and token-attestation probe and never treats a completed warm-up as capability evidence.
     */
    public static void prewarmStrict() {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        if (!os.contains("win")) {
            return;
        }
        synchronized (OsIsolation.class) {
            if (nativeLibrariesPrewarming) {
                return;
            }
            nativeLibrariesPrewarming = true;
            Thread prewarm = new Thread(() -> {
                try {
                    Native.load("kernel32", WindowsAppContainerLauncherProbe.class);
                    Native.load("userenv", WindowsAppContainerLauncherProbe.class);
                    Native.load("advapi32", WindowsAppContainerLauncherProbe.class);
                } catch (Throwable ignored) {
                    // The real selection path remains authoritative and will report the exact
                    // failure. A failed optional warm-up must not change that result.
                }
            }, "just-os-native-prewarm");
            prewarm.setDaemon(true);
            prewarm.start();
        }
    }

    /** Select the strongest backend that can actually launch the current probe artifact. */
    public static Backend select(Path launcherJar) {
        return select(launcherJar, true);
    }

    /**
     * Select a backend for the requested evidence level. Ordinary canary/adapter verification
     * needs process-tree and resource containment, but it does not need to spend time proving an
     * AppContainer that it is not allowed to use. Strict requests (including SAFE_REAL) still
     * perform the complete AppContainer capability probe before any target class is loaded.
     */
    public static Backend select(Path launcherJar, boolean requireStrict) {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        if (os.contains("win")) {
            if (!requireStrict) {
                return WindowsJobBackend.create();
            }
            Backend strict = WindowsAppContainerBackend.create(launcherJar);
            if (strict.available()) return strict;
            return WindowsJobBackend.create(";strict-unavailable=" + strict.reason());
        }
        if (os.contains("linux")) {
            Backend nsjail = NsjailBackend.create();
            return nsjail.available() ? nsjail : BubblewrapBackend.create();
        }
        return unavailable("unsupported-os:" + os);
    }

    private static Backend unavailable(String reason) {
        return new Backend() {
            @Override
            public String id() {
                return "NONE";
            }

            @Override
            public boolean available() {
                return false;
            }

            @Override
            public String reason() {
                return reason;
            }

            @Override
            public List<String> command(List<String> childCommand, Path scratchDirectory) {
                return List.copyOf(childCommand);
            }

            @Override
            public Session attach(Process process) throws IOException {
                throw new IOException(reason);
            }

            @Override
            public Level level() {
                return Level.NONE;
            }

            @Override
            public Set<String> capabilities() {
                return Set.of();
            }
        };
    }

    /**
     * Strict Linux backend. The seccomp profile is intentionally provisioned by the host or
     * deployment image: a guessed allowlist for a JVM is less safe than refusing to start. The
     * profile content, rather than its absolute path, is part of the policy identity.
     */
    private static final class NsjailBackend implements Backend {
        private static final long MAX_PROFILE_BYTES = 1_048_576L;
        private final Path executable;
        private final Path seccompProfile;
        private final Path sandboxRoot;
        private final String policyDigest;

        private NsjailBackend(Path executable, Path seccompProfile, Path sandboxRoot,
                              String policyDigest) {
            this.executable = executable;
            this.seccompProfile = seccompProfile;
            this.sandboxRoot = sandboxRoot;
            this.policyDigest = policyDigest;
        }

        static Backend create() {
            Path executable = findExecutable("nsjail");
            if (executable == null) {
                return unavailable("nsjail-not-found");
            }
            String configured = System.getProperty("just.sandbox.nsjail.seccomp");
            if (configured == null || configured.isBlank()) {
                configured = System.getenv("JUST_NSAJAIL_SECCOMP_PROFILE");
            }
            if (configured == null || configured.isBlank()) {
                return unavailable("nsjail-seccomp-profile-not-configured");
            }
            String configuredRoot = System.getProperty("just.sandbox.nsjail.root");
            if (configuredRoot == null || configuredRoot.isBlank()) {
                configuredRoot = System.getenv("JUST_NSAJAIL_ROOT");
            }
            String rootDigest = System.getProperty("just.sandbox.nsjail.root-digest");
            if (rootDigest == null || rootDigest.isBlank()) {
                rootDigest = System.getenv("JUST_NSAJAIL_ROOT_DIGEST");
            }
            if (configuredRoot == null || configuredRoot.isBlank()
                    || rootDigest == null || !rootDigest.matches("[0-9a-fA-F]{64}")) {
                return unavailable("nsjail-prepared-root-not-configured");
            }
            try {
                Path profile = Path.of(configured).toAbsolutePath().normalize();
                Path root = Path.of(configuredRoot).toAbsolutePath().normalize();
                if (!Files.isRegularFile(profile) || ArchiveLink.isLink(profile)
                        || Files.size(profile) > MAX_PROFILE_BYTES
                        || !Files.isDirectory(root) || ArchiveLink.isLink(root)) {
                    return unavailable("nsjail-seccomp-profile-invalid");
                }
                byte[] contents = Files.readAllBytes(profile);
                String actualRootDigest = preparedRootDigest(root);
                if (!actualRootDigest.equalsIgnoreCase(rootDigest.trim())) {
                    return unavailable("nsjail-prepared-root-digest-mismatch");
                }
                if (!strictHostCapabilities() || !LinuxLandlock.hostAvailable()
                        || !executableAcceptsStrictFlags(executable)) {
                    return unavailable("nsjail-host-capabilities-unavailable");
                }
                        return new NsjailBackend(executable, profile, root,
                        digest("nsjail-v2|profile=" + hex(contents)
                                + "|root=" + actualRootDigest
                                + "|attestation=" + ATTESTATION_VERSION));
            } catch (IOException | RuntimeException failure) {
                return unavailable("nsjail-seccomp-profile-unreadable");
            }
        }

        /**
         * Presence of nsjail alone is insufficient: strict mode requires the kernel resources
         * that the command below asks it to enforce. This probe reads only host capability
         * metadata and runs nsjail's inert help path; it never loads a target artifact.
         */
        private static boolean strictHostCapabilities() {
            if (!Files.isDirectory(Path.of("/proc/self/ns"))) {
                return false;
            }
            for (String namespace : List.of("user", "mnt", "pid", "net", "ipc", "uts")) {
                if (!Files.exists(Path.of("/proc/self/ns", namespace))) {
                    return false;
                }
            }
            Path controllers = Path.of("/sys/fs/cgroup/cgroup.controllers");
            Path seccomp = Path.of("/proc/sys/kernel/seccomp/actions_avail");
            if (!Files.isRegularFile(controllers) || !Files.isReadable(controllers)
                    || !Files.isRegularFile(seccomp) || !Files.isReadable(seccomp)) {
                return false;
            }
            try {
                String available = Files.readString(controllers, StandardCharsets.US_ASCII);
                return List.of("cpu", "memory", "pids").stream().allMatch(available::contains)
                        && Files.readString(seccomp, StandardCharsets.US_ASCII).contains("kill_process");
            } catch (IOException | RuntimeException ignored) {
                return false;
            }
        }

        private static boolean executableAcceptsStrictFlags(Path executable) {
            Process process = null;
            try {
                process = new ProcessBuilder(executable.toString(), "--help")
                        .redirectErrorStream(true)
                        .start();
                if (!process.waitFor(2, TimeUnit.SECONDS)) {
                    process.destroyForcibly();
                    return false;
                }
                byte[] output;
                try (InputStream stream = process.getInputStream()) {
                    output = stream.readNBytes(64 * 1024);
                }
                if (process.exitValue() != 0) {
                    return false;
                }
                String help = new String(output, StandardCharsets.US_ASCII);
                for (String option : List.of("--disable_clone_newuser", "--disable_clone_newns",
                        "--disable_clone_newpid", "--disable_clone_newnet",
                        "--disable_clone_newipc", "--disable_clone_newuts", "--user",
                        "--group", "--bindmount_ro", "--bindmount", "--tmpfsmount",
                        "--cgroup_mem_max", "--cgroup_pids_max", "--cgroup_cpu_ms_per_sec",
                        "--use_cgroupv2", "--seccomp_policy", "--time_limit")) {
                    if (!help.contains(option)) {
                        return false;
                    }
                }
                return true;
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                if (process != null) {
                    process.destroyForcibly();
                }
                return false;
            } catch (IOException | RuntimeException ignored) {
                if (process != null) {
                    process.destroyForcibly();
                }
                return false;
            }
        }

        @Override
        public String id() {
            return "LINUX_NSJAIL_STRICT";
        }

        @Override
        public boolean available() {
            return true;
        }

        @Override
        public String reason() {
            return "nsjail namespace+cgroup+seccomp profile configured";
        }

        @Override
        public Level level() {
            return Level.OS_STRICT;
        }

        @Override
        public Set<String> capabilities() {
            return Set.of("user_namespace", "mount_namespace", "pid_namespace",
                    "network_namespace", "ipc_namespace", "uts_namespace", "readonly_root",
                    "scratch_write", "cgroup_v2_limits", "seccomp_allowlist", "landlock",
                    "no_new_privs", "parent_death_cleanup", "runner_attestation",
                    "process_tree", "resource_limits", "filesystem_policy", "network_policy");
        }

        @Override
        public String policyDigest() {
            return policyDigest;
        }

        @Override
        public List<String> command(List<String> childCommand, Path scratchDirectory) {
            return command(childCommand, scratchDirectory, false);
        }

        @Override
        public List<String> command(List<String> childCommand, Path scratchDirectory,
                                    boolean loopbackOnly) {
            String scratch = scratchDirectory.toAbsolutePath().normalize().toString();
            List<String> wrapped = new ArrayList<>();
            wrapped.add(executable.toString());
            wrapped.add("--mode");
            wrapped.add("o");
            wrapped.add("--quiet");
            // nsjail enables these namespaces by default. Its current CLI only exposes
            // disable_* switches; passing invented clone_new* flags would make the strict
            // launcher fail before it ever reaches the child.
            wrapped.add("--user");
            wrapped.add("65534");
            wrapped.add("--group");
            wrapped.add("65534");
            // SAFE_REAL network effects need a loopback-only interface. The default canary
            // path keeps loopback disabled, so enabling this is an explicit policy choice.
            if (!loopbackOnly) {
                wrapped.add("--iface_no_lo");
            }
            wrapped.add("--bindmount_ro");
            // Never expose the host root: read-only is not confidentiality. The prepared root
            // image must contain the runtime system libraries and directory layout; only the
            // explicitly mounted JDK, probe, target and scratch paths are visible to the child.
            wrapped.add(sandboxRoot + ":/");
            addRuntimeMounts(wrapped, childCommand, scratchDirectory);
            wrapped.add("--bindmount");
            wrapped.add(scratch + ":" + scratch);
            wrapped.add("--tmpfsmount");
            wrapped.add("/tmp");
            wrapped.add("--cwd");
            wrapped.add(scratch);
            wrapped.add("--hostname");
            wrapped.add("just-sandbox");
            wrapped.add("--rlimit_as");
            wrapped.add("768");
            wrapped.add("--rlimit_cpu");
            wrapped.add("8");
            wrapped.add("--rlimit_nofile");
            wrapped.add("128");
            wrapped.add("--rlimit_nproc");
            wrapped.add("64");
            wrapped.add("--cgroup_mem_max");
            wrapped.add(Long.toString(MAX_PROCESS_MEMORY));
            wrapped.add("--cgroup_pids_max");
            wrapped.add(Integer.toString(MAX_CHILD_PROCESSES));
            wrapped.add("--cgroup_cpu_ms_per_sec");
            wrapped.add("800");
            wrapped.add("--use_cgroupv2");
            wrapped.add("--seccomp_policy");
            wrapped.add(seccompProfile.toString());
            // Do not inherit JAVA_TOOL_OPTIONS, LD_PRELOAD, proxy credentials, or other
            // host-controlled variables into a production verification jail.
            wrapped.add("--time_limit");
            wrapped.add("8");
            wrapped.add("--");
            wrapped.addAll(childCommand);
            return List.copyOf(wrapped);
        }

        private static void addRuntimeMounts(List<String> wrapped, List<String> childCommand,
                                             Path scratchDirectory) {
            java.util.TreeSet<String> mounts = new java.util.TreeSet<>();
            Path scratch = scratchDirectory.toAbsolutePath().normalize();
            if (childCommand != null && !childCommand.isEmpty()) {
                Path java = existingPath(childCommand.get(0));
                if (java != null && java.getParent() != null && java.getParent().getParent() != null) {
                    mounts.add(java.getParent().getParent().toString());
                }
                for (String token : childCommand) {
                    for (String value : pathValues(token)) {
                        Path path = existingPath(value);
                        if (path == null || path.equals(scratch) || path.startsWith(scratch)) {
                            continue;
                        }
                        mounts.add(path.toString());
                    }
                }
            }
            mounts.remove(scratch.toString());
            for (String mount : mounts) {
                wrapped.add("--bindmount_ro");
                wrapped.add(mount + ":" + mount);
            }
        }

        private static List<String> pathValues(String token) {
            if (token == null || token.isBlank()) {
                return List.of();
            }
            List<String> values = new ArrayList<>();
            if (token.startsWith("-D") || token.startsWith("-javaagent:")) {
                int equals = token.indexOf('=');
                if (equals > 0) {
                    String property = token.substring(2, equals);
                    String value = token.substring(equals + 1);
                    String first = value.split("\\|", -1)[0];
                    if (property.endsWith("target-cp") || property.endsWith("class.path")) {
                        Collections.addAll(values, first.split(
                                java.util.regex.Pattern.quote(java.io.File.pathSeparator)));
                    } else {
                        values.add(first);
                    }
                }
                if (token.startsWith("-javaagent:")) {
                    String agent = token.substring("-javaagent:".length());
                    values.add(agent.split("=", 2)[0]);
                }
            } else if (token.contains(java.io.File.pathSeparator)) {
                Collections.addAll(values, token.split(
                        java.util.regex.Pattern.quote(java.io.File.pathSeparator)));
            } else if (token.startsWith("/")) {
                values.add(token);
            }
            return values;
        }

        private static Path existingPath(String value) {
            if (value == null || value.isBlank() || !value.startsWith("/")) {
                return null;
            }
            try {
                Path path = Path.of(value).toAbsolutePath().normalize();
                return (Files.exists(path) && !ArchiveLink.isLink(path)) ? path : null;
            } catch (RuntimeException ignored) {
                return null;
            }
        }

        @Override
        public Session attach(Process process) throws IOException {
            if (process == null || !process.isAlive()) {
                throw new IOException("nsjail-exited-before-ready");
            }
            return new Session() {
                @Override
                public String backend() {
                    return id();
                }

                @Override
                public void terminate() {
                    process.destroyForcibly();
                }

                @Override
                public void close() {
                    // nsjail owns the namespace/cgroup lifecycle and --mode o reaps the child.
                }
            };
        }
    }

    private static final class BubblewrapBackend implements Backend {
        private final Path executable;

        private BubblewrapBackend(Path executable) {
            this.executable = executable;
        }

        static Backend create() {
            String optIn = System.getProperty("just.sandbox.allow-namespace");
            if (optIn == null || optIn.isBlank()) {
                optIn = System.getenv("JUST_ALLOW_NAMESPACE_SANDBOX");
            }
            if (!Boolean.parseBoolean(optIn)) {
                return unavailable("bubblewrap-requires-explicit-opt-in");
            }
            Path executable = findExecutable("bwrap");
            return executable == null
                    ? unavailable("bubblewrap-not-found")
                    : new BubblewrapBackend(executable);
        }

        @Override
        public String id() {
            return "LINUX_BWRAP_NET_PID_RO_ROOT";
        }

        @Override
        public boolean available() {
            return true;
        }

        @Override
        public String reason() {
            return "bubblewrap executable present";
        }

        @Override
        public Level level() {
            return Level.OS_NAMESPACE;
        }

        @Override
        public Set<String> capabilities() {
            return Set.of("user_namespace", "mount_namespace", "pid_namespace",
                    "network_namespace", "ipc_namespace", "uts_namespace", "readonly_root",
                    "scratch_write", "parent_death_cleanup");
        }

        @Override
        public String policyDigest() {
            return digest("bwrap-v2|namespace|readonly-root|private-scratch|no-network|"
                    + "no-capabilities|attestation=" + attestationVersion());
        }

        @Override
        public List<String> command(List<String> childCommand, Path scratchDirectory) {
            return command(childCommand, scratchDirectory, false);
        }

        @Override
        public List<String> command(List<String> childCommand, Path scratchDirectory,
                                    boolean loopbackOnly) {
            String scratch = scratchDirectory.toAbsolutePath().normalize().toString();
            List<String> wrapped = new ArrayList<>();
            wrapped.add(executable.toString());
            // Keep the host root visible only read-only so the JDK and native loader remain
            // usable across distributions. The explicit scratch bind is the sole writable
            // tree; Java-level file policy still limits target reads to classpath/JDK roots.
            wrapped.add("--ro-bind");
            wrapped.add("/");
            wrapped.add("/");
            wrapped.add("--bind");
            wrapped.add(scratch);
            wrapped.add(scratch);
            wrapped.add("--proc");
            wrapped.add("/proc");
            wrapped.add("--dev");
            wrapped.add("/dev");
            // bwrap remains a no-network namespace. SAFE_REAL is rejected before launch
            // unless a strict backend is selected, so it must not widen this fallback.
            wrapped.add("--unshare-net");
            wrapped.add("--unshare-user");
            wrapped.add("--uid");
            wrapped.add("65534");
            wrapped.add("--gid");
            wrapped.add("65534");
            wrapped.add("--disable-setgroups");
            wrapped.add("--unshare-pid");
            wrapped.add("--unshare-ipc");
            wrapped.add("--unshare-uts");
            wrapped.add("--new-session");
            wrapped.add("--die-with-parent");
            wrapped.add("--cap-drop");
            wrapped.add("ALL");
            wrapped.add("--chdir");
            wrapped.add(scratch);
            wrapped.add("--");
            wrapped.addAll(childCommand);
            return List.copyOf(wrapped);
        }

        @Override
        public Session attach(Process process) throws IOException {
            if (process == null || !process.isAlive()) {
                throw new IOException("bubblewrap-exited-before-ready");
            }
            // bubblewrap's --die-with-parent and private PID namespace already cover the
            // process-tree boundary. The parent still performs the normal timeout cleanup.
            return new Session() {
                @Override
                public String backend() {
                    return id();
                }

                @Override
                public void terminate() {
                    process.destroyForcibly();
                }

                @Override
                public void close() {
                    // No host handle to release.
                }
            };
        }
    }

    private static final class WindowsJobBackend implements Backend {
        private final WindowsApi api;
        private final String reason;

        private WindowsJobBackend(WindowsApi api, String reason) {
            this.api = api;
            this.reason = reason;
        }

        static Backend create() {
            return create("");
        }

        static Backend create(String context) {
            try {
                return new WindowsJobBackend(
                        Native.load("kernel32", WindowsApi.class),
                        "kernel32 Job Object ready" + (context == null ? "" : context));
            } catch (Throwable failure) {
                return unavailable("windows-job-object-unavailable:"
                        + failure.getClass().getSimpleName());
            }
        }

        @Override
        public String id() {
            return "WINDOWS_JOB_OBJECT_JVM_POLICY";
        }

        @Override
        public boolean available() {
            return true;
        }

        @Override
        public String reason() {
            return reason;
        }

        @Override
        public Level level() {
            return Level.PROCESS_RESOURCE;
        }

        @Override
        public Set<String> capabilities() {
            return Set.of("process_tree", "memory_limit", "process_count", "kill_on_close");
        }

        @Override
        public String policyDigest() {
            return digest("windows-job-v1|process-tree|memory-limit|kill-on-close|jvm-policy|"
                    + "attestation=" + attestationVersion());
        }

        @Override
        public List<String> command(List<String> childCommand, Path scratchDirectory) {
            return List.copyOf(childCommand);
        }

        @Override
        public Session attach(Process process) throws IOException {
            return attachJob(process, id());
        }

        private Session attachJob(Process process, String sessionId) throws IOException {
            if (process == null || !process.isAlive()) {
                throw new IOException("child-exited-before-job-attachment");
            }
            Pointer job = api.CreateJobObjectW(null, null);
            if (isNull(job)) {
                throw win32("CreateJobObjectW");
            }
            boolean success = false;
            try {
                JobObjectExtendedLimitInformation limits = new JobObjectExtendedLimitInformation();
                limits.basic.limitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                        | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
                        | JOB_OBJECT_LIMIT_PROCESS_MEMORY;
                limits.basic.activeProcessLimit = MAX_CHILD_PROCESSES;
                limits.processMemoryLimit = new BaseTSD.SIZE_T(MAX_PROCESS_MEMORY);
                limits.write();
                if (!api.SetInformationJobObject(job, JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                        limits.getPointer(), limits.size())) {
                    throw win32("SetInformationJobObject");
                }
                Pointer child = api.OpenProcess(PROCESS_TERMINATE | PROCESS_SET_QUOTA
                        | PROCESS_QUERY_LIMITED_INFORMATION, false, (int) process.pid());
                if (isNull(child)) {
                    throw win32("OpenProcess");
                }
                try {
                    if (!api.AssignProcessToJobObject(job, child)) {
                        throw win32("AssignProcessToJobObject");
                    }
                } finally {
                    api.CloseHandle(child);
                }
                success = true;
                return new WindowsSession(api, job, sessionId);
            } finally {
                if (!success) {
                    api.TerminateJobObject(job, 1);
                    api.CloseHandle(job);
                }
            }
        }

        private IOException win32(String operation) {
            return new IOException(operation + " failed (win32=" + api.GetLastError() + ")");
        }
    }

    /**
     * Windows AppContainer broker.  The broker is launched with the scanner JDK and waits for
     * the parent ready marker; it then creates the target JVM with the AppContainer security
     * capability attribute before any target bytecode can run.
     */
    private static final class WindowsAppContainerBackend implements Backend {
        private static volatile Boolean appContainerProfileCapability;
        private static volatile String appContainerCapabilityReason = "not-probed";
        private final Path launcherJar;
        private final Path launcherJava;
        private final WindowsJobBackend jobs;

        private WindowsAppContainerBackend(Path launcherJar, Path launcherJava,
                                           WindowsJobBackend jobs) {
            this.launcherJar = launcherJar;
            this.launcherJava = launcherJava;
            this.jobs = jobs;
        }

        static Backend create(Path launcherJar) {
            if (launcherJar == null || !regularNonLink(launcherJar)) {
                return unavailable("windows-appcontainer-launcher-jar-missing");
            }
            Path java = currentJavaExecutable();
            if (java == null) {
                return unavailable("windows-appcontainer-scanner-java-missing");
            }
            try {
                // Loading these libraries is a capability probe only; no target process is
                // started until the parent attaches the broker Job Object.
                Native.load("kernel32", WindowsAppContainerLauncherProbe.class);
                Native.load("userenv", WindowsAppContainerLauncherProbe.class);
                Native.load("advapi32", WindowsAppContainerLauncherProbe.class);
                Boolean capability = appContainerProfileCapability;
                if (capability == null) {
                    synchronized (WindowsAppContainerBackend.class) {
                        capability = appContainerProfileCapability;
                        if (capability == null) {
                            ProbeResult probe = canCreateDisposableAppContainer(launcherJar, java);
                            capability = probe.available();
                            appContainerCapabilityReason = probe.reason();
                            appContainerProfileCapability = capability;
                        }
                    }
                }
                if (!Boolean.TRUE.equals(capability)) {
                    return unavailable("windows-appcontainer-"
                            + appContainerCapabilityReason);
                }
                Backend job = WindowsJobBackend.create();
                if (!job.available() || !(job instanceof WindowsJobBackend)) {
                    return unavailable("windows-job-object-unavailable");
                }
                return new WindowsAppContainerBackend(launcherJar, java,
                        (WindowsJobBackend) job);
            } catch (Throwable failure) {
                return unavailable("windows-appcontainer-api-unavailable:"
                        + failure.getClass().getSimpleName());
            }
        }

        @Override
        public String id() {
            return "WINDOWS_APPCONTAINER_STRICT";
        }

        @Override
        public boolean available() {
            return true;
        }

        @Override
        public String reason() {
            return "AppContainer pre-start token+ACL with Job Object broker";
        }

        @Override
        public Level level() {
            return Level.OS_STRICT;
        }

        @Override
        public Set<String> capabilities() {
            return Set.of("appcontainer", "low_integrity", "acl_default_deny",
                    "no_network_capability", "restricted_handle_inheritance", "process_tree",
                    "resource_limits", "filesystem_policy", "network_policy",
                    "runner_attestation");
        }

        @Override
        public String policyDigest() {
            return digest("windows-appcontainer-v1|pre-start-token|low-integrity|acl-default-deny|"
                    + "no-network-capability|handle-list|job-object|attestation="
                    + attestationVersion());
        }

        @Override
        public List<String> command(List<String> childCommand, Path scratchDirectory) {
            String readyFile = optionValue(childCommand, "-Djust.verify.isolation-ready=");
            String readyToken = optionValue(childCommand, "-Djust.verify.isolation-token=");
            if (readyFile.isBlank() || readyToken.isBlank()) {
                throw new IllegalArgumentException("windows-runner-ready-properties-missing");
            }
            List<String> wrapped = new ArrayList<>();
            wrapped.add(launcherJava.toString());
            wrapped.add("-Xmx96m");
            wrapped.add("-XX:+UseSerialGC");
            wrapped.add("-cp");
            wrapped.add(launcherJar.toString());
            wrapped.add(WindowsAppContainerLauncher.class.getName());
            wrapped.add("--ready-file");
            wrapped.add(readyFile);
            wrapped.add("--ready-token");
            wrapped.add(readyToken);
            wrapped.add("--cwd");
            wrapped.add(scratchDirectory.toAbsolutePath().normalize().toString());
            wrapped.add("--");
            wrapped.addAll(childCommand);
            return List.copyOf(wrapped);
        }

        @Override
        public Session attach(Process process) throws IOException {
            return jobs.attachJob(process, id());
        }

        private static String optionValue(List<String> command, String prefix) {
            if (command == null) return "";
            for (String token : command) {
                if (token != null && token.startsWith(prefix)) return token.substring(prefix.length());
            }
            return "";
        }

        /**
         * Probe the capability the broker actually needs, rather than treating a loadable DLL
         * as proof that AppContainer profiles can be provisioned for this user/session.  Some
         * Windows images expose userenv.dll but reject CreateAppContainerProfile with
         * ERROR_FILE_NOT_FOUND (for example when the profile service is unavailable).  A
         * backend selected after that probe is allowed to advertise OS_STRICT; the weaker Job
         * Object backend is deliberately returned by the caller otherwise.
         */
        private record ProbeResult(boolean available, String reason) {
            private ProbeResult {
                reason = reason == null || reason.isBlank() ? "unknown" : reason;
            }
        }

        private static ProbeResult canCreateDisposableAppContainer(Path launcherJar,
                                                                    Path launcherJava) {
            // The probe itself owns a short-lived broker process. Running it synchronously keeps
            // one lifecycle owner: on timeout runAppContainerProbe destroys the broker and
            // removes its scratch tree before selection returns. A daemon thread here could keep
            // provisioning an AppContainer after the parent had already reported it unavailable.
            return runAppContainerProbe(launcherJar, launcherJava);
        }

        /**
         * Profile creation alone is not a strict-runner proof.  It can succeed while the
         * security-capability process attribute, token construction, or ACL broker path is
         * unusable.  Launch the verifier-owned attestation helper through the same broker that
         * will be used for target probes; no target artifact or native code enters this check.
         */
        private static ProbeResult runAppContainerProbe(Path launcherJar, Path launcherJava) {
            Path root = null;
            Process broker = null;
            Session job = null;
            try {
                Path temp = Path.of(System.getProperty("java.io.tmpdir", "."))
                        .toAbsolutePath().normalize();
                if (!regularDirectory(temp)) {
                    return new ProbeResult(false, "temp-directory-unavailable");
                }
                root = Files.createTempDirectory(temp, "just-appcontainer-probe-");
                Path ready = root.resolve("ready");
                String token = "probe-" + UUID.randomUUID().toString().replace("-", "");
                List<String> command = List.of(
                        launcherJava.toString(), "-Xmx64m", "-Xss512k", "-cp",
                        launcherJar.toString(), WindowsAppContainerLauncher.class.getName(),
                        "--ready-file", ready.toString(), "--ready-token", token,
                        "--cwd", root.toString(), "--",
                        launcherJava.toString(), "-Xmx64m", "-Xss512k", "-cp",
                        launcherJar.toString(), WindowsAppContainerCapabilityProbe.class.getName());
                broker = new ProcessBuilder(command)
                        .directory(root.toFile())
                        .redirectErrorStream(true)
                        .start();
                Backend backend = WindowsJobBackend.create();
                if (!(backend instanceof WindowsJobBackend jobs) || !jobs.available()) {
                    return new ProbeResult(false, "job-object-unavailable");
                }
                job = jobs.attach(broker);
                Files.writeString(ready, token, StandardCharsets.US_ASCII,
                        java.nio.file.StandardOpenOption.CREATE_NEW,
                        java.nio.file.StandardOpenOption.WRITE);
                if (!broker.waitFor(APP_CONTAINER_PROBE_TIMEOUT_MS, TimeUnit.MILLISECONDS)) {
                    broker.destroyForcibly();
                    broker.waitFor(APP_CONTAINER_TERMINATION_GRACE_MS, TimeUnit.MILLISECONDS);
                    // The broker may still have a descendant holding stdout/stderr open after
                    // the parent is killed. Reading the pipe here can therefore turn a bounded
                    // capability probe into an unbounded wait; the timeout itself is sufficient
                    // evidence for a fail-closed selection.
                    JustLogger.debug("Windows AppContainer capability probe timed out");
                    return new ProbeResult(false, "broker-timeout");
                }
                String output = readProbeOutput(broker);
                int exit = broker.exitValue();
                if (exit == 0) {
                    return new ProbeResult(true, "ok");
                }
                JustLogger.debug("Windows AppContainer capability probe exit {}: {}", exit,
                        output);
                return new ProbeResult(false, "broker-exit-" + exit);
            } catch (Throwable failure) {
                JustLogger.debug("Windows AppContainer capability probe failed: {}",
                        failure.toString());
                return new ProbeResult(false, "probe-"
                        + failure.getClass().getSimpleName());
            } finally {
                if (job != null) {
                    job.close();
                }
                if (broker != null && broker.isAlive()) {
                    broker.destroyForcibly();
                }
                deleteTree(root);
            }
        }

        private static String readProbeOutput(Process process) {
            if (process == null) {
                return "";
            }
            try {
                byte[] bytes = process.getInputStream().readNBytes(512);
                String value = new String(bytes, StandardCharsets.UTF_8)
                        .replace('\r', ' ').replace('\n', ' ').trim();
                if (value.length() > 160) {
                    return value.substring(0, 160);
                }
                return value.replaceAll("[^A-Za-z0-9_:.()= -]", "_");
            } catch (IOException | RuntimeException ignored) {
                return "output-unavailable";
            }
        }

        private static boolean regularDirectory(Path path) {
            return path != null && Files.isDirectory(path, java.nio.file.LinkOption.NOFOLLOW_LINKS)
                    && !ArchiveLink.isLink(path);
        }

        private static void deleteTree(Path root) {
            if (root == null || !regularDirectory(root)) {
                return;
            }
            try (Stream<Path> paths = Files.walk(root)) {
                paths.sorted(Comparator.reverseOrder()).forEach(path -> {
                    try {
                        Files.deleteIfExists(path);
                    } catch (IOException ignored) {
                        // Capability failure remains fail-closed; cleanup is best effort.
                    }
                });
            } catch (IOException ignored) {
                // Do not turn an unavailable strict backend into a usable one.
            }
        }

    }

    /** Empty marker interface used only to probe JNA's native library loader without reflection. */
    private interface WindowsAppContainerLauncherProbe extends StdCallLibrary {
    }

    private static final class WindowsSession implements Session {
        private final WindowsApi api;
        private Pointer job;
        private final String sessionId;

        private WindowsSession(WindowsApi api, Pointer job, String sessionId) {
            this.api = api;
            this.job = job;
            this.sessionId = sessionId;
        }

        @Override
        public String backend() {
            return sessionId;
        }

        @Override
        public synchronized void terminate() {
            if (!isNull(job)) {
                api.TerminateJobObject(job, 1);
            }
        }

        @Override
        public synchronized void close() {
            if (!isNull(job)) {
                // KILL_ON_JOB_CLOSE also reaps descendants created before a timeout.
                api.CloseHandle(job);
                job = null;
            }
        }
    }

    private interface WindowsApi extends StdCallLibrary {
        Pointer CreateJobObjectW(Pointer attributes, Pointer name);

        boolean SetInformationJobObject(Pointer job, int informationClass,
                                         Pointer information, int informationLength);

        Pointer OpenProcess(int desiredAccess, boolean inheritHandle, int processId);

        boolean AssignProcessToJobObject(Pointer job, Pointer process);

        boolean TerminateJobObject(Pointer job, int exitCode);

        boolean CloseHandle(Pointer handle);

        int GetLastError();
    }

    private static boolean isNull(Pointer pointer) {
        return pointer == null || Pointer.nativeValue(pointer) == 0L;
    }

    public static final class IoCounters extends Structure {
        public long readOperationCount;
        public long writeOperationCount;
        public long otherOperationCount;
        public long readTransferCount;
        public long writeTransferCount;
        public long otherTransferCount;

        @Override
        protected List<String> getFieldOrder() {
            return List.of("readOperationCount", "writeOperationCount", "otherOperationCount",
                    "readTransferCount", "writeTransferCount", "otherTransferCount");
        }
    }

    public static final class JobObjectBasicLimitInformation extends Structure {
        public long perProcessUserTimeLimit;
        public long perJobUserTimeLimit;
        public int limitFlags;
        public BaseTSD.SIZE_T minimumWorkingSetSize = new BaseTSD.SIZE_T();
        public BaseTSD.SIZE_T maximumWorkingSetSize = new BaseTSD.SIZE_T();
        public int activeProcessLimit;
        public BaseTSD.ULONG_PTR affinity = new BaseTSD.ULONG_PTR();
        public int priorityClass;
        public int schedulingClass;

        @Override
        protected List<String> getFieldOrder() {
            return List.of("perProcessUserTimeLimit", "perJobUserTimeLimit", "limitFlags",
                    "minimumWorkingSetSize", "maximumWorkingSetSize", "activeProcessLimit",
                    "affinity", "priorityClass", "schedulingClass");
        }
    }

    public static final class JobObjectExtendedLimitInformation extends Structure {
        public JobObjectBasicLimitInformation basic = new JobObjectBasicLimitInformation();
        public IoCounters io = new IoCounters();
        public BaseTSD.SIZE_T processMemoryLimit = new BaseTSD.SIZE_T();
        public BaseTSD.SIZE_T jobMemoryLimit = new BaseTSD.SIZE_T();
        public BaseTSD.SIZE_T peakProcessMemoryUsed = new BaseTSD.SIZE_T();
        public BaseTSD.SIZE_T peakJobMemoryUsed = new BaseTSD.SIZE_T();

        @Override
        protected List<String> getFieldOrder() {
            return List.of("basic", "io", "processMemoryLimit", "jobMemoryLimit",
                    "peakProcessMemoryUsed", "peakJobMemoryUsed");
        }
    }

    private static Path findExecutable(String name) {
        String path = System.getenv("PATH");
        if (path == null || path.isBlank()) {
            return null;
        }
        for (String entry : path.split(java.util.regex.Pattern.quote(
                java.io.File.pathSeparator))) {
            if (entry.isBlank()) {
                continue;
            }
            try {
                for (String candidateName : executableNames(name)) {
                    Path candidate = Path.of(entry).resolve(candidateName).toAbsolutePath().normalize();
                    if (Files.isRegularFile(candidate) && Files.isExecutable(candidate)
                            && !ArchiveLink.isLink(candidate)) {
                        return candidate;
                    }
                }
            } catch (RuntimeException ignored) {
                // An invalid PATH entry does not disable other candidates.
            }
        }
        return null;
    }

    private static List<String> executableNames(String name) {
        if (name.endsWith(".exe")) {
            return List.of(name);
        }
        return isWindows() ? List.of(name, name + ".exe") : List.of(name);
    }

    private static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win");
    }

    private static Path currentJavaExecutable() {
        try {
            Path home = Path.of(System.getProperty("java.home", "."));
            Path candidate = home.resolve("bin").resolve("java.exe").toAbsolutePath().normalize();
            return regularNonLink(candidate) ? candidate : null;
        } catch (RuntimeException ignored) {
            return null;
        }
    }

    private static boolean regularNonLink(Path path) {
        try {
            return path != null && Files.isRegularFile(path, java.nio.file.LinkOption.NOFOLLOW_LINKS)
                    && !ArchiveLink.isLink(path);
        } catch (RuntimeException ignored) {
            return false;
        }
    }

    private static String digest(String value) {
        try {
            byte[] bytes = MessageDigest.getInstance("SHA-256")
                    .digest((value == null ? "" : value).getBytes(java.nio.charset.StandardCharsets.UTF_8));
            StringBuilder out = new StringBuilder(bytes.length * 2);
            for (byte item : bytes) {
                out.append(String.format(Locale.ROOT, "%02x", item & 0xff));
            }
            return out.toString();
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("required SHA-256 digest unavailable", impossible);
        }
    }

    /**
     * Compute a path-independent digest for a prepared root image.  The configured digest is a
     * claim supplied by the deployment, so strict mode verifies the image contents before using
     * it in the policy identity.  Symlinks/reparse points are rejected instead of being hashed as
     * aliases; otherwise a later target read could escape the image that was attested here.
     */
    static String preparedRootDigest(Path root) throws IOException {
        if (root == null || !Files.isDirectory(root, java.nio.file.LinkOption.NOFOLLOW_LINKS)
                || ArchiveLink.isLink(root)) {
            throw new IOException("prepared-root-not-directory");
        }
        List<Path> entries;
        try (Stream<Path> walk = Files.walk(root)) {
            entries = walk.sorted(Comparator.comparing(path -> relativePath(root, path))).toList();
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            long contentBytes = 0L;
            for (Path entry : entries) {
                if (ArchiveLink.isLink(entry)) {
                    throw new IOException("prepared-root-link:" + relativePath(root, entry));
                }
                BasicFileAttributes attributes = Files.readAttributes(entry,
                        BasicFileAttributes.class, java.nio.file.LinkOption.NOFOLLOW_LINKS);
                String relative = relativePath(root, entry);
                byte type = attributes.isDirectory() ? (byte) 'd'
                        : attributes.isRegularFile() ? (byte) 'f'
                        : attributes.isSymbolicLink() ? (byte) 'l' : (byte) 'o';
                updateDigest(digest, new byte[] {type});
                updateDigest(digest, relative.getBytes(StandardCharsets.UTF_8));
                updateDigest(digest, new byte[] {0});
                updateDigest(digest, Long.toString(attributes.size())
                        .getBytes(StandardCharsets.US_ASCII));
                updateDigest(digest, new byte[] {0});
                if (!attributes.isRegularFile()) {
                    continue;
                }
                if (attributes.size() > MAX_ROOT_DIGEST_BYTES - contentBytes) {
                    throw new IOException("prepared-root-too-large");
                }
                contentBytes += attributes.size();
                try (InputStream input = Files.newInputStream(entry)) {
                    byte[] buffer = new byte[64 * 1024];
                    int read;
                    while ((read = input.read(buffer)) >= 0) {
                        if (read > 0) {
                            digest.update(buffer, 0, read);
                        }
                    }
                }
            }
            return hex(digest.digest());
        } catch (NoSuchAlgorithmException impossible) {
            throw new IOException("SHA-256 unavailable", impossible);
        }
    }

    private static String relativePath(Path root, Path entry) {
        String relative = root.relativize(entry).toString().replace('\\', '/');
        return relative.isEmpty() ? "." : relative;
    }

    private static void updateDigest(MessageDigest digest, byte[] bytes) {
        digest.update(bytes, 0, bytes.length);
    }

    private static String hex(byte[] bytes) {
        StringBuilder out = new StringBuilder(bytes == null ? 0 : bytes.length * 2);
        if (bytes != null) {
            for (byte item : bytes) {
                out.append(String.format(Locale.ROOT, "%02x", item & 0xff));
            }
        }
        return out.toString();
    }

    /** Keep the optional dependency-free link check local to this backend. */
    private static final class ArchiveLink {
        private static boolean isLink(Path path) {
            return Files.isSymbolicLink(path) || (isWindows() && reparsePoint(path));
        }

        private static boolean reparsePoint(Path path) {
            try {
                return Boolean.TRUE.equals(Files.getAttribute(path, "dos:reparsePoint",
                        java.nio.file.LinkOption.NOFOLLOW_LINKS));
            } catch (IOException | RuntimeException ignored) {
                return false;
            }
        }
    }
}
