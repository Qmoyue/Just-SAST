package io.just.sast.verify;

import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.platform.win32.BaseTSD;
import com.sun.jna.win32.StdCallLibrary;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

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
            return BubblewrapBackend.create();
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
        };
    }

    private static final class BubblewrapBackend implements Backend {
        private final Path executable;

        private BubblewrapBackend(Path executable) {
            this.executable = executable;
        }

        static Backend create() {
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
                Path candidate = Path.of(entry).resolve(name).toAbsolutePath().normalize();
                if (Files.isRegularFile(candidate) && Files.isExecutable(candidate)) {
                    return candidate;
                }
            } catch (RuntimeException ignored) {
                // An invalid PATH entry does not disable other candidates.
            }
        }
        return null;
    }
}
