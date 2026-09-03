package io.just.sast.verify;

import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.platform.win32.BaseTSD;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.win32.StdCallLibrary;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * The only built-in Windows boundary for dynamic verification.
 *
 * <p>A Job Object is process/resource containment, not a complete OS sandbox. The parent creates
 * and configures it, starts one child JVM, attaches that exact process, and only then releases
 * the authenticated ready handshake. The implementation intentionally exposes only the
 * process/resource contract required by the scanner.</p>
 */
public final class OsIsolation {

    /** Wire-level version of the parent-attached runner attestation. */
    public static final String ATTESTATION_VERSION = "JUST_OS_ATTESTATION_V3";

    /** Containment descriptions, not security-strength labels. */
    public enum Level {
        NONE,
        PROCESS_RESOURCE
    }

    /**
     * Resource observations returned by a live runner session.
     *
     * <p>A value of {@code -1} means that the selected platform API did not expose that
     * observation.  Unknown is deliberately different from zero: a zero-process or zero-memory
     * result is a real observation, while a missing query must remain visible in the report.</p>
     */
    public record ResourceMetrics(long peakRssMb, long peakJobMemoryMb, long userCpuMs,
                                  long totalProcesses, long activeProcesses) {
        public ResourceMetrics {
            peakRssMb = peakRssMb < 0L ? -1L : peakRssMb;
            peakJobMemoryMb = peakJobMemoryMb < 0L ? -1L : peakJobMemoryMb;
            userCpuMs = userCpuMs < 0L ? -1L : userCpuMs;
            totalProcesses = totalProcesses < 0L ? -1L : totalProcesses;
            activeProcesses = activeProcesses < 0L ? -1L : activeProcesses;
        }

        public static ResourceMetrics unknown() {
            return new ResourceMetrics(-1L, -1L, -1L, -1L, -1L);
        }
    }

    private static final int PROCESS_TERMINATE = 0x0001;
    private static final int PROCESS_QUERY_INFORMATION = 0x0400;
    private static final int PROCESS_SET_QUOTA = 0x0100;
    private static final int PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    private static final int JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9;
    private static final int JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION = 1;
    private static final int JOB_OBJECT_LIMIT_PROCESS_TIME = 0x00000002;
    private static final int JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008;
    private static final int JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100;
    private static final int JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
    private static final int MAX_CHILD_PROCESSES = 64;
    private static final long MAX_PROCESS_MEMORY = 768L * 1024L * 1024L;
    /** Seven seconds of per-process user CPU time, below the eight-second wall timeout. */
    private static final long MAX_PROCESS_USER_TIME = 7L * 10_000_000L;
    private static volatile Boolean jobConfigurationCapability;
    private static volatile String jobConfigurationReason = "not-probed";
    private static volatile boolean nativePrewarmed;
    private static volatile boolean processMemoryApiProbed;
    private static volatile WindowsMemoryApi processMemoryApi;

    private OsIsolation() {
    }

    /** Selected backend. Implementations must expose only claims they actually enforce. */
    public interface Backend {
        String id();

        boolean available();

        String reason();

        /** Job Object attaches after process creation, so its command is unchanged. */
        List<String> command(List<String> childCommand, Path scratchDirectory);

        /** Attach containment before the child is allowed to emit ready. */
        Session attach(Process process) throws IOException;

        default Level level() {
            return Level.NONE;
        }

        default Set<String> capabilities() {
            return Set.of();
        }

        default String attestationVersion() {
            return ATTESTATION_VERSION;
        }

        /** Production-ready means the Job Object contract is configured and attachable. */
        default boolean productionReady() {
            return available()
                    && level() == Level.PROCESS_RESOURCE
                    && capabilities().containsAll(Set.of(
                    "runner_attestation", "process_tree", "resource_limits",
                    "scratch_write", "cpu_time_limit", "memory_limit",
                    "active_process_limit", "kill_on_close", "wall_timeout"));
        }

        /** Stable policy identity; paths and host inventory never enter the digest. */
        default String policyDigest() {
            List<String> names = new ArrayList<>(capabilities());
            Collections.sort(names);
            return digest(id() + "|" + level() + "|attestation="
                    + attestationVersion() + "|" + names);
        }
    }

    public interface Session extends AutoCloseable {
        String backend();

        /** Return the live runner's best-effort resource counters before the handle is closed. */
        default ResourceMetrics metrics() {
            return ResourceMetrics.unknown();
        }

        void terminate();

        @Override
        void close();
    }

    public static Backend select() {
        return select(null);
    }

    /**
     * Select the single built-in backend. The artifact argument is retained so callers can keep
     * their selection lifecycle independent of the eventual child command; it is not used as a
     * capability claim and no artifact is loaded during selection.
     */
    public static Backend select(Path ignoredArtifact) {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        if (os.contains("win")) {
            return WindowsJobBackend.create();
        }
        if (os.contains("linux")) {
            return unavailable("linux-runner-not-configured");
        }
        return unavailable("unsupported-os:" + os);
    }

    /** Warm only the trusted kernel32 binding; the real configuration probe remains authoritative. */
    public static void prewarmJobObject() {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        if (!os.contains("win")) {
            return;
        }
        synchronized (OsIsolation.class) {
            if (nativePrewarmed) {
                return;
            }
            nativePrewarmed = true;
            Thread thread = new Thread(() -> {
                try {
                    Native.load("kernel32", WindowsApi.class);
                } catch (Throwable ignored) {
                    // select() reports the authoritative failure synchronously.
                }
            }, "just-job-object-prewarm");
            thread.setDaemon(true);
            thread.start();
        }
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
                return childCommand == null ? List.of() : List.copyOf(childCommand);
            }

            @Override
            public Session attach(Process process) throws IOException {
                throw new IOException(reason);
            }
        };
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
                WindowsApi api = Native.load("kernel32", WindowsApi.class);
                Boolean capability = jobConfigurationCapability;
                if (capability == null) {
                    synchronized (WindowsJobBackend.class) {
                        capability = jobConfigurationCapability;
                        if (capability == null) {
                            CapabilityProbe probe = probeConfiguration(api);
                            capability = probe.available();
                            jobConfigurationReason = probe.reason();
                            jobConfigurationCapability = capability;
                        }
                    }
                }
                if (!Boolean.TRUE.equals(capability)) {
                    return unavailable("windows-job-object-" + jobConfigurationReason);
                }
                return new WindowsJobBackend(api, "kernel32 Job Object configured");
            } catch (Throwable failure) {
                return unavailable("windows-job-object-unavailable:"
                        + failure.getClass().getSimpleName());
            }
        }

        private static CapabilityProbe probeConfiguration(WindowsApi api) {
            Pointer job = null;
            try {
                job = api.CreateJobObjectW(null, null);
                if (isNull(job)) {
                    return new CapabilityProbe(false, "create-failed-" + api.GetLastError());
                }
                configureJob(api, job);
                return new CapabilityProbe(true, "configured");
            } catch (IOException failure) {
                return new CapabilityProbe(false, sanitizeReason(failure.getMessage()));
            } catch (RuntimeException failure) {
                return new CapabilityProbe(false, failure.getClass().getSimpleName());
            } finally {
                if (!isNull(job)) {
                    api.CloseHandle(job);
                }
            }
        }

        private record CapabilityProbe(boolean available, String reason) {
            private CapabilityProbe {
                reason = reason == null || reason.isBlank() ? "unknown" : reason;
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
            return Set.of("runner_attestation", "process_tree", "resource_limits",
                    "scratch_write", "cpu_time_limit", "memory_limit", "active_process_limit",
                    "kill_on_close", "wall_timeout");
        }

        @Override
        public String policyDigest() {
            return digest("windows-job-v4|process-tree|memory=" + MAX_PROCESS_MEMORY
                    + "|cpu-user=" + MAX_PROCESS_USER_TIME + "|active=" + MAX_CHILD_PROCESSES
                    + "|kill-on-close|scratch|attestation=" + attestationVersion());
        }

        @Override
        public List<String> command(List<String> childCommand, Path scratchDirectory) {
            return childCommand == null ? List.of() : List.copyOf(childCommand);
        }

        @Override
        public Session attach(Process process) throws IOException {
            if (process == null || !process.isAlive()) {
                throw new IOException("child-exited-before-job-attachment");
            }
            Pointer job = api.CreateJobObjectW(null, null);
            if (isNull(job)) {
                throw win32(api, "CreateJobObjectW");
            }
            boolean success = false;
            Pointer child = null;
            try {
                configureJob(api, job);
                child = api.OpenProcess(PROCESS_TERMINATE | PROCESS_SET_QUOTA
                        | PROCESS_QUERY_INFORMATION
                        | PROCESS_QUERY_LIMITED_INFORMATION, false, (int) process.pid());
                if (isNull(child)) {
                    throw win32(api, "OpenProcess");
                }
                if (!api.AssignProcessToJobObject(job, child)) {
                    throw win32(api, "AssignProcessToJobObject");
                }
                WindowsSession session = new WindowsSession(api, job, child, id());
                success = true;
                return session;
            } finally {
                if (!success) {
                    if (!isNull(child)) {
                        api.CloseHandle(child);
                    }
                    api.TerminateJobObject(job, 1);
                    api.CloseHandle(job);
                }
            }
        }
    }

    private static void configureJob(WindowsApi api, Pointer job) throws IOException {
        JobObjectExtendedLimitInformation limits = new JobObjectExtendedLimitInformation();
        limits.basic.limitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                | JOB_OBJECT_LIMIT_PROCESS_TIME
                | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
                | JOB_OBJECT_LIMIT_PROCESS_MEMORY;
        limits.basic.perProcessUserTimeLimit = MAX_PROCESS_USER_TIME;
        limits.basic.activeProcessLimit = MAX_CHILD_PROCESSES;
        limits.processMemoryLimit = new BaseTSD.SIZE_T(MAX_PROCESS_MEMORY);
        limits.write();
        if (!api.SetInformationJobObject(job, JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                limits.getPointer(), limits.size())) {
            throw win32(api, "SetInformationJobObject");
        }
    }

    private static IOException win32(WindowsApi api, String operation) {
        return new IOException(operation + " failed (win32=" + api.GetLastError() + ")");
    }

    private static String sanitizeReason(String value) {
        if (value == null || value.isBlank()) {
            return "configuration-failed";
        }
        return value.replaceAll("[^A-Za-z0-9_.=:-]", "_");
    }

    private static final class WindowsSession implements Session {
        private final WindowsApi api;
        private Pointer job;
        private Pointer child;
        private final String sessionId;

        private WindowsSession(WindowsApi api, Pointer job, Pointer child, String sessionId) {
            this.api = api;
            this.job = job;
            this.child = child;
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
        public synchronized ResourceMetrics metrics() {
            if (isNull(job)) {
                return ResourceMetrics.unknown();
            }
            long peakMemoryMb = -1L;
            long peakRssMb = -1L;
            long userCpuMs = -1L;
            long totalProcesses = -1L;
            long activeProcesses = -1L;
            try {
                JobObjectExtendedLimitInformation memory =
                        new JobObjectExtendedLimitInformation();
                if (api.QueryInformationJobObject(job, JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                        memory.getPointer(), memory.size(), new IntByReference())) {
                    memory.read();
                    long bytes = sizeValue(memory.peakJobMemoryUsed);
                    if (bytes >= 0L) {
                        peakMemoryMb = bytes / (1024L * 1024L);
                    }
                }
                WindowsMemoryApi memoryApi = processMemoryApi();
                if (memoryApi != null && !isNull(child)) {
                    ProcessMemoryCounters counters = new ProcessMemoryCounters();
                    counters.cb = counters.size();
                    counters.write();
                    if (memoryApi.GetProcessMemoryInfo(child, counters.getPointer(), counters.size())) {
                        counters.read();
                        long bytes = sizeValue(counters.peakWorkingSetSize);
                        if (bytes >= 0L) {
                            peakRssMb = bytes / (1024L * 1024L);
                        }
                    }
                }
                JobObjectBasicAccountingInformation accounting =
                        new JobObjectBasicAccountingInformation();
                if (api.QueryInformationJobObject(job, JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION,
                        accounting.getPointer(), accounting.size(), new IntByReference())) {
                    accounting.read();
                    userCpuMs = hundredNanosToMillis(accounting.totalUserTime);
                    totalProcesses = Integer.toUnsignedLong(accounting.totalProcesses);
                    activeProcesses = Integer.toUnsignedLong(accounting.activeProcesses);
                }
            } catch (Throwable ignored) {
                // Resource telemetry is evidence about the runner, never a prerequisite for
                // deciding the already authenticated dynamic result.
            }
            return new ResourceMetrics(peakRssMb, peakMemoryMb, userCpuMs,
                    totalProcesses, activeProcesses);
        }

        @Override
        public synchronized void close() {
            if (!isNull(job)) {
                // KILL_ON_JOB_CLOSE reaps descendants created before a timeout.
                api.CloseHandle(job);
                job = null;
            }
            if (!isNull(child)) {
                api.CloseHandle(child);
                child = null;
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

        boolean QueryInformationJobObject(Pointer job, int informationClass,
                                           Pointer information, int informationLength,
                                           IntByReference returnLength);

        boolean CloseHandle(Pointer handle);

        Pointer GetCurrentProcess();

        int GetLastError();
    }

    private interface WindowsMemoryApi extends StdCallLibrary {
        boolean GetProcessMemoryInfo(Pointer process, Pointer counters, int size);
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

    public static final class JobObjectBasicAccountingInformation extends Structure {
        public long totalUserTime;
        public long totalKernelTime;
        public long thisPeriodTotalUserTime;
        public long thisPeriodTotalKernelTime;
        public int totalPageFaultCount;
        public int totalProcesses;
        public int activeProcesses;
        public int totalTerminatedProcesses;

        @Override
        protected List<String> getFieldOrder() {
            return List.of("totalUserTime", "totalKernelTime", "thisPeriodTotalUserTime",
                    "thisPeriodTotalKernelTime", "totalPageFaultCount", "totalProcesses",
                    "activeProcesses", "totalTerminatedProcesses");
        }
    }

    public static final class ProcessMemoryCounters extends Structure {
        public int cb;
        public int pageFaultCount;
        public BaseTSD.SIZE_T peakWorkingSetSize = new BaseTSD.SIZE_T();
        public BaseTSD.SIZE_T workingSetSize = new BaseTSD.SIZE_T();
        public BaseTSD.SIZE_T quotaPeakPagedPoolUsage = new BaseTSD.SIZE_T();
        public BaseTSD.SIZE_T quotaPagedPoolUsage = new BaseTSD.SIZE_T();
        public BaseTSD.SIZE_T quotaPeakNonPagedPoolUsage = new BaseTSD.SIZE_T();
        public BaseTSD.SIZE_T quotaNonPagedPoolUsage = new BaseTSD.SIZE_T();
        public BaseTSD.SIZE_T pagefileUsage = new BaseTSD.SIZE_T();
        public BaseTSD.SIZE_T peakPagefileUsage = new BaseTSD.SIZE_T();

        @Override
        protected List<String> getFieldOrder() {
            return List.of("cb", "pageFaultCount", "peakWorkingSetSize", "workingSetSize",
                    "quotaPeakPagedPoolUsage", "quotaPagedPoolUsage",
                    "quotaPeakNonPagedPoolUsage", "quotaNonPagedPoolUsage", "pagefileUsage",
                    "peakPagefileUsage");
        }
    }

    private static WindowsMemoryApi processMemoryApi() {
        if (processMemoryApiProbed) {
            return processMemoryApi;
        }
        synchronized (OsIsolation.class) {
            if (processMemoryApiProbed) {
                return processMemoryApi;
            }
            try {
                processMemoryApi = Native.load("psapi", WindowsMemoryApi.class);
            } catch (Throwable ignored) {
                processMemoryApi = null;
            } finally {
                processMemoryApiProbed = true;
            }
            return processMemoryApi;
        }
    }

    /** Current Windows process working-set observation, or {@code -1} when psapi is unavailable. */
    public static long currentProcessRssMb() {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        if (!os.contains("win")) {
            return -1L;
        }
        try {
            WindowsMemoryApi memoryApi = processMemoryApi();
            if (memoryApi == null) {
                return -1L;
            }
            WindowsApi kernel = Native.load("kernel32", WindowsApi.class);
            Pointer process = kernel.GetCurrentProcess();
            ProcessMemoryCounters counters = new ProcessMemoryCounters();
            counters.cb = counters.size();
            counters.write();
            if (!memoryApi.GetProcessMemoryInfo(process, counters.getPointer(), counters.size())) {
                return -1L;
            }
            counters.read();
            long bytes = sizeValue(counters.workingSetSize);
            return bytes < 0L ? -1L : bytes / (1024L * 1024L);
        } catch (Throwable ignored) {
            return -1L;
        }
    }

    private static long sizeValue(BaseTSD.SIZE_T value) {
        return value == null ? -1L : Math.max(0L, value.longValue());
    }

    private static long hundredNanosToMillis(long value) {
        return value < 0L ? -1L : value / 10_000L;
    }

    private static String digest(String value) {
        try {
            byte[] bytes = MessageDigest.getInstance("SHA-256")
                    .digest((value == null ? "" : value).getBytes(StandardCharsets.UTF_8));
            StringBuilder out = new StringBuilder(bytes.length * 2);
            for (byte item : bytes) {
                out.append(String.format(Locale.ROOT, "%02x", item & 0xff));
            }
            return out.toString();
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("required SHA-256 digest unavailable", impossible);
        }
    }
}
