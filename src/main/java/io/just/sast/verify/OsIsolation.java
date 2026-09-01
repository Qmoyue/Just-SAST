package io.just.sast.verify;

import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.platform.win32.BaseTSD;
import com.sun.jna.win32.StdCallLibrary;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

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

    private OsIsolation() {
    }

    /** A selected launcher is immutable and safe to share between verification tasks. */
    public interface Backend {
        String id();

        boolean available();

        String reason();

        /** Wrap a child command when the backend needs a namespace launcher. */
        List<String> command(List<String> childCommand, Path scratchDirectory);

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

        /** True only when all production preconditions have been checked by this backend. */
        default boolean productionReady() {
            return level() == Level.OS_STRICT;
        }

        /** Digest of the immutable backend policy, excluding host-specific paths. */
        default String policyDigest() {
            List<String> names = new ArrayList<>(capabilities());
            Collections.sort(names);
            return digest(id() + "|" + level() + "|" + names);
        }
    }

    public interface Session extends AutoCloseable {
        String backend();

        void terminate();

        @Override
        void close();
    }

    public static Backend select() {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        if (os.contains("win")) {
            return WindowsJobBackend.create();
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
                if (!strictHostCapabilities() || !executableAcceptsStrictFlags(executable)) {
                    return unavailable("nsjail-host-capabilities-unavailable");
                }
                return new NsjailBackend(executable, profile, root,
                        digest("nsjail-v2|profile=" + hex(contents)
                                + "|root=" + rootDigest.toLowerCase(Locale.ROOT)));
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
                        .redirectOutput(ProcessBuilder.Redirect.DISCARD)
                        .start();
                if (!process.waitFor(2, TimeUnit.SECONDS)) {
                    process.destroyForcibly();
                    return false;
                }
                return process.exitValue() == 0;
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
                    "scratch_write", "cgroup_v2_limits", "seccomp_allowlist",
                    "no_new_privs", "parent_death_cleanup");
        }

        @Override
        public String policyDigest() {
            return policyDigest;
        }

        @Override
        public List<String> command(List<String> childCommand, Path scratchDirectory) {
            String scratch = scratchDirectory.toAbsolutePath().normalize().toString();
            List<String> wrapped = new ArrayList<>();
            wrapped.add(executable.toString());
            wrapped.add("--mode");
            wrapped.add("o");
            wrapped.add("--quiet");
            wrapped.add("--clone_newuser");
            wrapped.add("--clone_newns");
            wrapped.add("--clone_newpid");
            wrapped.add("--clone_newnet");
            wrapped.add("--clone_newipc");
            wrapped.add("--clone_newuts");
            wrapped.add("--uid");
            wrapped.add("65534");
            wrapped.add("--gid");
            wrapped.add("65534");
            wrapped.add("--disable_setgroups");
            wrapped.add("--iface_no_lo");
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
            wrapped.add("--seccomp_policy");
            wrapped.add(seccompProfile.toString());
            wrapped.add("--keep_env");
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
            return digest("bwrap-v2|namespace|readonly-root|private-scratch|no-network|no-capabilities");
        }

        @Override
        public List<String> command(List<String> childCommand, Path scratchDirectory) {
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
            try {
                return new WindowsJobBackend(
                        Native.load("kernel32", WindowsApi.class), "kernel32 Job Object ready");
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
            return digest("windows-job-v1|process-tree|memory-limit|kill-on-close|jvm-policy");
        }

        @Override
        public List<String> command(List<String> childCommand, Path scratchDirectory) {
            return List.copyOf(childCommand);
        }

        @Override
        public Session attach(Process process) throws IOException {
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
                return new WindowsSession(api, job);
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

    private static final class WindowsSession implements Session {
        private final WindowsApi api;
        private Pointer job;

        private WindowsSession(WindowsApi api, Pointer job) {
            this.api = api;
            this.job = job;
        }

        @Override
        public String backend() {
            return "WINDOWS_JOB_OBJECT_JVM_POLICY";
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
            return "sha256-unavailable";
        }
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
