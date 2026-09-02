package io.just.sast.verify;

import io.just.sast.util.ArchiveLimits;
import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.WString;
import com.sun.jna.platform.win32.WinBase;
import com.sun.jna.platform.win32.WinDef;
import com.sun.jna.platform.win32.WinNT;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.LongByReference;
import com.sun.jna.ptr.PointerByReference;
import com.sun.jna.win32.StdCallLibrary;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryFlag;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.UserPrincipal;
import java.nio.file.attribute.UserPrincipalLookupService;
import java.nio.file.Files;
import java.nio.file.FileVisitResult;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * Small Windows-only broker used by {@link OsIsolation}.
 *
 * <p>The broker itself is not the sandbox. It waits until the parent has attached the broker to a
 * kill-on-close Job Object, applies the per-run AppContainer ACL, and only then creates the target
 * JVM with {@code PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES}. The target therefore starts with
 * its final token and cannot inherit the scanner's process identity.</p>
 */
public final class WindowsAppContainerLauncher {

    private static final int EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
    private static final int CREATE_UNICODE_ENVIRONMENT = 0x00000400;
    private static final int STARTF_USESTDHANDLES = 0x00000100;
    private static final int PROC_THREAD_ATTRIBUTE_HANDLE_LIST = 0x00020002;
    private static final int PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 0x00020009;
    private static final int STD_INPUT_HANDLE = -10;
    private static final int STD_OUTPUT_HANDLE = -11;
    private static final int STD_ERROR_HANDLE = -12;
    private static final int WAIT_OBJECT_0 = 0;
    private static final int WAIT_TIMEOUT = 258;
    private static final int WAIT_FAILED = 0xffffffff;
    private static final int INFINITE = 0xffffffff;
    private static final int ERROR_INSUFFICIENT_BUFFER = 122;
    private static final int MAX_ARGUMENTS = 512;
    private static final int MAX_PATH_TEXT = 4096;
    private static final int MAX_ACCESS_TREE_ENTRIES = 250_000;
    private static final long READY_TIMEOUT_MS = 15_000L;
    private static final String ACL_MUTEX = "Local\\JustVerifyAclV1";

    private WindowsAppContainerLauncher() {
    }

    public static void main(String[] args) {
        int exit = 1;
        try {
            exit = run(args);
        } catch (Throwable failure) {
            System.err.println("JUST_WINDOWS_RUNNER_FAILED: "
                    + failure.getClass().getSimpleName() + ": " + clean(failure.getMessage()));
        }
        System.exit(exit);
    }

    private static int run(String[] args) throws Exception {
        Options options = Options.parse(args);
        if (!isWindows() || options.command.isEmpty()) {
            return 2;
        }
        validateOptions(options);

        ProcessApi processApi = Native.load("kernel32", ProcessApi.class);
        UserEnvApi userEnv = Native.load("userenv", UserEnvApi.class);
        SecurityApi security = Native.load("advapi32", SecurityApi.class);
        WinNT.HANDLE mutex = processApi.CreateMutexW(null, false, new WString(ACL_MUTEX));
        if (isNull(mutex)) {
            throw win32(processApi, "CreateMutexW");
        }
        boolean mutexHeld = false;
        Pointer appContainerSid = null;
        // AppContainer names follow the package identity character rules on current Windows
        // builds; keep the generated profile lower-case and below the documented length bound.
        WString profileName = new WString("justverify-" + processApi.GetCurrentProcessId()
                + "-" + UUID.randomUUID().toString().replace("-", ""));
        try {
            int wait = processApi.WaitForSingleObject(mutex, INFINITE);
            if (wait != WAIT_OBJECT_0) {
                throw win32(processApi, "WaitForSingleObject(acl-mutex)");
            }
            mutexHeld = true;
            appContainerSid = createProfile(userEnv, profileName);
            String sidName = sidString(security, appContainerSid);
            try (AclGuard acl = AclGuard.open(options, sidName)) {
                waitForParent(options.readyFile, options.readyToken);
                return createAndWait(processApi, security, appContainerSid, options);
            } finally {
                deleteProfile(userEnv, profileName);
                if (!isNull(appContainerSid)) {
                    security.FreeSid(appContainerSid);
                }
            }
        } finally {
            if (mutexHeld) {
                processApi.ReleaseMutex(mutex);
            }
            processApi.CloseHandle(mutex);
        }
    }

    private static Pointer createProfile(UserEnvApi userEnv, WString profileName) throws IOException {
        PointerByReference sid = new PointerByReference();
        int result = userEnv.CreateAppContainerProfile(profileName, profileName, profileName,
                null, 0, sid);
        if (result != 0 || isNull(sid.getValue())) {
            throw new IOException("CreateAppContainerProfile failed (hresult=" + result + ")");
        }
        return sid.getValue();
    }

    private static void deleteProfile(UserEnvApi userEnv, WString profileName) {
        userEnv.DeleteAppContainerProfile(profileName);
    }

    private static String sidString(SecurityApi security, Pointer sid) throws IOException {
        PointerByReference text = new PointerByReference();
        if (!security.ConvertSidToStringSid(new WinNT.PSID(sid), text) || isNull(text.getValue())) {
            throw new IOException("ConvertSidToStringSid failed");
        }
        try {
            return text.getValue().getWideString(0);
        } finally {
            security.LocalFree(text.getValue());
        }
    }

    private static int createAndWait(ProcessApi api, SecurityApi security, Pointer sid,
                                     Options options) throws IOException, InterruptedException {
        WinNT.HANDLE input = api.GetStdHandle(STD_INPUT_HANDLE);
        WinNT.HANDLE output = api.GetStdHandle(STD_OUTPUT_HANDLE);
        WinNT.HANDLE error = api.GetStdHandle(STD_ERROR_HANDLE);
        if (isNull(input) || isNull(output) || isNull(error)) {
            throw win32(api, "GetStdHandle");
        }

        WinNT.HANDLE[] handles = {input, output, error};
        Memory attributeList = null;
        Memory handleList = null;
        Memory securityCapabilities = null;
        Memory startup = null;
        WinBase.PROCESS_INFORMATION process = new WinBase.PROCESS_INFORMATION();
        try {
            LongByReference attributeBytes = new LongByReference();
            api.InitializeProcThreadAttributeList(null, 2, 0, attributeBytes);
            if (api.GetLastError() != ERROR_INSUFFICIENT_BUFFER
                    || attributeBytes.getValue() <= 0 || attributeBytes.getValue() > 64 * 1024) {
                throw win32(api, "InitializeProcThreadAttributeList(size)");
            }
            attributeList = new Memory(attributeBytes.getValue());
            if (!api.InitializeProcThreadAttributeList(attributeList, 2, 0, attributeBytes)) {
                throw win32(api, "InitializeProcThreadAttributeList");
            }

            SecurityCapabilities capabilities = new SecurityCapabilities(sid);
            securityCapabilities = capabilities.getPointerMemory();
            LongByReference ignored = new LongByReference();
            if (!api.UpdateProcThreadAttribute(attributeList, 0,
                    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, securityCapabilities,
                    securityCapabilities.size(), null, ignored)) {
                throw win32(api, "UpdateProcThreadAttribute(security)");
            }

            handleList = new Memory((long) handles.length * Native.POINTER_SIZE);
            for (int i = 0; i < handles.length; i++) {
                handleList.setPointer((long) i * Native.POINTER_SIZE, handles[i].getPointer());
            }
            if (!api.UpdateProcThreadAttribute(attributeList, 0,
                    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handleList, handleList.size(), null, ignored)) {
                throw win32(api, "UpdateProcThreadAttribute(handles)");
            }

            WinBase.STARTUPINFO base = new WinBase.STARTUPINFO();
            base.dwFlags = STARTF_USESTDHANDLES;
            base.hStdInput = input;
            base.hStdOutput = output;
            base.hStdError = error;
            int baseSize = base.size();
            base.cb = new WinDef.DWORD(baseSize + Native.POINTER_SIZE);
            base.write();
            startup = new Memory((long) baseSize + Native.POINTER_SIZE);
            startup.write(0, base.getPointer().getByteArray(0, baseSize), 0, baseSize);
            startup.setPointer(baseSize, attributeList);

            String commandLine = commandLine(options.command);
            char[] writableCommandLine = (commandLine + "\0").toCharArray();
            if (!api.CreateProcessW(new WString(options.command.get(0)), writableCommandLine,
                    null, null, true, EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
                    null, new WString(options.workingDirectory.toString()), startup, process)) {
                throw win32(api, "CreateProcessW(AppContainer)");
            }
            process.read();
            int wait = api.WaitForSingleObject(process.hProcess, 9_000);
            if (wait == WAIT_TIMEOUT) {
                api.TerminateProcess(process.hProcess, 124);
                throw new IOException("target-timeout");
            }
            if (wait != WAIT_OBJECT_0) {
                throw win32(api, "WaitForSingleObject(target)");
            }
            IntByReference code = new IntByReference();
            if (!api.GetExitCodeProcess(process.hProcess, code)) {
                throw win32(api, "GetExitCodeProcess");
            }
            return code.getValue();
        } finally {
            if (!isNull(process.hThread)) {
                api.CloseHandle(process.hThread);
            }
            if (!isNull(process.hProcess)) {
                api.CloseHandle(process.hProcess);
            }
            if (!isNull(attributeList)) {
                api.DeleteProcThreadAttributeList(attributeList);
            }
        }
    }

    private static void waitForParent(Path ready, String token) throws IOException, InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(READY_TIMEOUT_MS);
        while (System.nanoTime() < deadline) {
            if (Files.isRegularFile(ready, LinkOption.NOFOLLOW_LINKS)) {
                if (isReparse(ready) || Files.size(ready) > 128L) {
                    throw new IOException("parent-ready-file-invalid");
                }
                String value = Files.readString(ready, StandardCharsets.US_ASCII).trim();
                if (token.equals(value)) {
                    return;
                }
                throw new IOException("parent-ready-token-mismatch");
            }
            Thread.sleep(10L);
        }
        throw new IOException("parent-ready-timeout");
    }

    private static void validateOptions(Options options) throws IOException {
        if (options.readyToken.length() < 16 || options.readyToken.length() > 96
                || !options.readyToken.matches("[A-Za-z0-9-]+")) {
            throw new IOException("invalid-ready-token");
        }
        if (!Files.isDirectory(options.workingDirectory, LinkOption.NOFOLLOW_LINKS)
                || isReparse(options.workingDirectory)) {
            throw new IOException("invalid-working-directory");
        }
        if (!options.readyFile.startsWith(options.workingDirectory)
                || options.readyFile.equals(options.workingDirectory)
                || (Files.exists(options.readyFile, LinkOption.NOFOLLOW_LINKS)
                && (!Files.isRegularFile(options.readyFile, LinkOption.NOFOLLOW_LINKS)
                || isReparse(options.readyFile)))) {
            throw new IOException("invalid-ready-file");
        }
        Path executable = regularPath(Path.of(options.command.get(0)));
        if (executable == null || !("java.exe".equalsIgnoreCase(executable.getFileName().toString())
                || "java".equalsIgnoreCase(executable.getFileName().toString()))) {
            throw new IOException("target-command-is-not-java");
        }
        if (options.command.size() > MAX_ARGUMENTS) {
            throw new IOException("target-command-too-long");
        }
    }

    private static List<Path> accessiblePaths(Options options) throws IOException {
        Map<String, Path> paths = new LinkedHashMap<>();
        Path java = regularPath(Path.of(options.command.get(0)));
        if (java == null || java.getParent() == null || java.getParent().getParent() == null) {
            throw new IOException("target-java-home-missing");
        }
        paths.put(java.getParent().getParent().toString().toLowerCase(),
                java.getParent().getParent());
        paths.put(options.workingDirectory.toString().toLowerCase(), options.workingDirectory);

        for (int i = 0; i < options.command.size(); i++) {
            String token = options.command.get(i);
            if (("-cp".equals(token) || "--class-path".equals(token)) && i + 1 < options.command.size()) {
                addClassPath(paths, options.command.get(++i));
                continue;
            }
            if (token.startsWith("-javaagent:")) {
                addExistingOrParent(paths, token.substring("-javaagent:".length()).split("=", 2)[0]);
                continue;
            }
            if (token.startsWith("-D")) {
                int equals = token.indexOf('=');
                if (equals > 2) {
                    String key = token.substring(2, equals);
                    String value = token.substring(equals + 1);
                    if ("just.verify.target-cp".equals(key)
                            || "java.class.path".equals(key)
                            || "java.library.path".equals(key)) {
                        addClassPath(paths, value);
                    } else if (pathProperty(key)) {
                        addExistingOrParent(paths, value);
                    }
                }
            }
        }
        return new ArrayList<>(paths.values());
    }

    private static boolean pathProperty(String key) {
        return "java.io.tmpdir".equals(key) || "user.dir".equals(key)
                || "user.home".equals(key) || "java.util.prefs.userRoot".equals(key)
                || "java.util.prefs.systemRoot".equals(key) || "just.verify.result-file".equals(key)
                || "just.verify.isolation-ready".equals(key) || "just.verify.safe-scratch".equals(key)
                || "just.verify.safe-java".equals(key) || "just.verify.probe-jar".equals(key)
                || "just.verify.native-scratch".equals(key);
    }

    private static void addClassPath(Map<String, Path> paths, String value) throws IOException {
        if (value == null || value.length() > MAX_PATH_TEXT * 32) {
            throw new IOException("classpath-too-long");
        }
        for (String item : value.split(";", -1)) {
            if (!item.isBlank()) {
                addExistingOrParent(paths, item);
            }
        }
    }

    private static void addExistingOrParent(Map<String, Path> paths, String value) throws IOException {
        if (value == null || value.isBlank() || value.length() > MAX_PATH_TEXT
                || value.indexOf('\n') >= 0 || value.indexOf('\r') >= 0) {
            throw new IOException("invalid-access-path");
        }
        Path path = Path.of(value).toAbsolutePath().normalize();
        if (Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
            Path regular = regularPath(path);
            if (regular == null && !Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) {
                throw new IOException("access-path-is-not-regular");
            }
            path = regular == null ? path : regular;
        } else {
            path = path.getParent();
        }
        if (path == null || (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)
                && !Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS))) {
            throw new IOException("access-path-missing");
        }
        if (isReparse(path)) {
            throw new IOException("access-path-reparse-point");
        }
        paths.putIfAbsent(path.toString().toLowerCase(), path);
    }

    private static Path regularPath(Path path) {
        return Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) && !isReparse(path)
                ? path.toAbsolutePath().normalize() : null;
    }

    private static String commandLine(List<String> command) {
        StringBuilder result = new StringBuilder();
        for (String value : command) {
            if (result.length() > 0) result.append(' ');
            result.append(quote(value));
        }
        return result.toString();
    }

    private static String quote(String value) {
        if (value != null && !value.isEmpty() && value.indexOf(' ') < 0
                && value.indexOf('\t') < 0 && value.indexOf('"') < 0) {
            return value;
        }
        StringBuilder result = new StringBuilder("\"");
        int slashes = 0;
        for (int i = 0; i < value.length(); i++) {
            char current = value.charAt(i);
            if (current == '\\') {
                slashes++;
            } else if (current == '"') {
                result.append("\\".repeat(slashes * 2 + 1)).append('"');
                slashes = 0;
            } else {
                result.append("\\".repeat(slashes)).append(current);
                slashes = 0;
            }
        }
        result.append("\\".repeat(slashes * 2)).append('"');
        return result.toString();
    }

    private static boolean isReparse(Path path) {
        return ArchiveLimits.isLinkOrReparsePoint(path);
    }

    private static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase().contains("win");
    }

    private static boolean isNull(Pointer value) {
        return value == null || Pointer.nativeValue(value) == 0L;
    }

    private static boolean isNull(WinNT.HANDLE value) {
        return value == null || value.getPointer() == null
                || Pointer.nativeValue(value.getPointer()) == 0L;
    }

    private static IOException win32(ProcessApi api, String operation) {
        return new IOException(operation + " failed (win32=" + api.GetLastError() + ")");
    }

    private static String clean(String value) {
        if (value == null) return "";
        String result = value.replace('\r', ' ').replace('\n', ' ');
        return result.length() > 160 ? result.substring(0, 160) : result;
    }

    private static final class Options {
        private final Path readyFile;
        private final String readyToken;
        private final Path workingDirectory;
        private final List<String> command;

        private Options(Path readyFile, String readyToken, Path workingDirectory,
                        List<String> command) {
            this.readyFile = readyFile;
            this.readyToken = readyToken;
            this.workingDirectory = workingDirectory;
            this.command = command;
        }

        private static Options parse(String[] args) throws IOException {
            Path ready = null;
            String token = "";
            Path cwd = null;
            int separator = -1;
            for (int i = 0; i < args.length; i++) {
                if ("--".equals(args[i])) {
                    separator = i;
                    break;
                }
                if ("--ready-file".equals(args[i]) && i + 1 < args.length) ready = Path.of(args[++i]);
                else if ("--ready-token".equals(args[i]) && i + 1 < args.length) token = args[++i];
                else if ("--cwd".equals(args[i]) && i + 1 < args.length) cwd = Path.of(args[++i]);
                else throw new IOException("unknown-runner-option");
            }
            if (separator < 0 || ready == null || cwd == null || separator + 1 >= args.length) {
                throw new IOException("runner-options-missing");
            }
            List<String> command = List.of(java.util.Arrays.copyOfRange(args, separator + 1,
                    args.length));
            return new Options(ready.toAbsolutePath().normalize(), token,
                    cwd.toAbsolutePath().normalize(), command);
        }
    }

    private static final class SecurityCapabilities extends com.sun.jna.Structure {
        private Pointer appContainerSid;
        private Pointer capabilities;
        private int capabilityCount;
        private int reserved;

        private SecurityCapabilities(Pointer sid) {
            appContainerSid = sid;
            capabilities = null;
            capabilityCount = 0;
            reserved = 0;
            write();
        }

        private Memory getPointerMemory() {
            Memory result = new Memory(size());
            result.write(0, getPointer().getByteArray(0, size()), 0, size());
            return result;
        }

        @Override
        protected List<String> getFieldOrder() {
            return List.of("appContainerSid", "capabilities", "capabilityCount", "reserved");
        }
    }

    /** Save and restore only the ACL entries touched by this run. */
    private static final class AclGuard implements AutoCloseable {
        private final Map<Path, List<AclEntry>> originals;

        private AclGuard(Map<Path, List<AclEntry>> originals) {
            this.originals = originals;
        }

        private static AclGuard open(Options options, String sidName) throws IOException {
            UserPrincipalLookupService lookup = options.workingDirectory.getFileSystem()
                    .getUserPrincipalLookupService();
            UserPrincipal principal = lookup.lookupPrincipalByName(sidName);
            Map<Path, List<AclEntry>> originals = new LinkedHashMap<>();
            try {
                List<Path> accessible = accessiblePaths(options);
                validateAccessTrees(accessible);
                for (Path path : accessible) {
                    // Only the per-run scratch tree is writable.  The JDK, scanner JAR, target
                    // JARs and the parent traversal chain are read/execute inputs even though
                    // the target JVM needs to resolve classes from them.
                    boolean writable = path.startsWith(options.workingDirectory);
                    grant(path, principal, originals, writable, true);
                    for (Path parent = path.getParent(); parent != null; parent = parent.getParent()) {
                        if (!Files.exists(parent, LinkOption.NOFOLLOW_LINKS)) continue;
                        if (isReparse(parent)) throw new IOException("access-parent-reparse-point");
                        grantTraverse(parent, principal, originals);
                        if (parent.getParent() == null) break;
                    }
                }
                return new AclGuard(originals);
            } catch (IOException | RuntimeException failure) {
                restore(originals);
                if (failure instanceof IOException io) throw io;
                throw new IOException("appcontainer-acl-failed", failure);
            }
        }

        private static void grantTraverse(Path path, UserPrincipal principal,
                                           Map<Path, List<AclEntry>> originals) throws IOException {
            grant(path, principal, originals, false, false);
        }

        private static void grant(Path path, UserPrincipal principal,
                                  Map<Path, List<AclEntry>> originals,
                                  boolean writable, boolean inherit) throws IOException {
            AclFileAttributeView view = Files.getFileAttributeView(path, AclFileAttributeView.class,
                    LinkOption.NOFOLLOW_LINKS);
            if (view == null) throw new IOException("acl-view-unavailable");
            List<AclEntry> old = new ArrayList<>(view.getAcl());
            originals.putIfAbsent(path, old);
            Set<AclEntryPermission> permissions = Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)
                    ? directoryPermissions(writable, inherit) : filePermissions();
            Set<AclEntryFlag> flags = Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS) && inherit
                    ? EnumSet.of(AclEntryFlag.FILE_INHERIT, AclEntryFlag.DIRECTORY_INHERIT)
                    : EnumSet.noneOf(AclEntryFlag.class);
            for (AclEntry existing : old) {
                if (existing.type() == AclEntryType.ALLOW
                        && existing.principal().getName().equalsIgnoreCase(principal.getName())) {
                    if (existing.permissions().containsAll(permissions)
                            && existing.flags().containsAll(flags)) {
                        return;
                    }
                    throw new IOException("appcontainer-acl-conflict");
                }
            }
            AclEntry entry = AclEntry.newBuilder().setType(AclEntryType.ALLOW)
                    .setPrincipal(principal).setPermissions(permissions).setFlags(flags).build();
            List<AclEntry> updated = new ArrayList<>();
            updated.add(entry);
            updated.addAll(old);
            view.setAcl(updated);
        }

        private static Set<AclEntryPermission> filePermissions() {
            return EnumSet.of(AclEntryPermission.READ_DATA, AclEntryPermission.READ_ATTRIBUTES,
                    AclEntryPermission.READ_NAMED_ATTRS, AclEntryPermission.READ_ACL,
                    AclEntryPermission.EXECUTE, AclEntryPermission.SYNCHRONIZE);
        }

        private static Set<AclEntryPermission> directoryPermissions(boolean writable,
                                                                     boolean inherit) {
            if (!writable && !inherit) return EnumSet.of(AclEntryPermission.EXECUTE,
                    AclEntryPermission.READ_ATTRIBUTES, AclEntryPermission.READ_ACL,
                    AclEntryPermission.SYNCHRONIZE);
            if (!writable) return EnumSet.of(AclEntryPermission.LIST_DIRECTORY,
                    AclEntryPermission.READ_ATTRIBUTES, AclEntryPermission.READ_NAMED_ATTRS,
                    AclEntryPermission.READ_ACL, AclEntryPermission.EXECUTE,
                    AclEntryPermission.SYNCHRONIZE);
            return EnumSet.of(AclEntryPermission.READ_DATA, AclEntryPermission.WRITE_DATA,
                    AclEntryPermission.APPEND_DATA, AclEntryPermission.DELETE,
                    AclEntryPermission.DELETE_CHILD, AclEntryPermission.READ_ATTRIBUTES,
                    AclEntryPermission.WRITE_ATTRIBUTES, AclEntryPermission.READ_NAMED_ATTRS,
                    AclEntryPermission.WRITE_NAMED_ATTRS, AclEntryPermission.READ_ACL,
                    AclEntryPermission.EXECUTE, AclEntryPermission.SYNCHRONIZE);
        }

        @Override
        public void close() {
            restore(originals);
        }

        private static void restore(Map<Path, List<AclEntry>> originals) {
            List<Map.Entry<Path, List<AclEntry>>> entries = new ArrayList<>(originals.entrySet());
            for (int i = entries.size() - 1; i >= 0; i--) {
                Map.Entry<Path, List<AclEntry>> entry = entries.get(i);
                try {
                    AclFileAttributeView view = Files.getFileAttributeView(entry.getKey(),
                            AclFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
                    if (view != null) view.setAcl(entry.getValue());
                } catch (IOException | RuntimeException ignored) {
                    // The parent will report cleanup as best effort; do not hide the target result.
                }
            }
        }
    }

    /**
     * Validate every directory that will receive an inheritable package-SID ACE before changing
     * any ACL.  A non-following walk keeps junctions/reparse points from turning a seemingly
     * bounded classpath root into an arbitrary host tree.  Archive-sized bounds also prevent a
     * hostile directory classpath from making the broker spend unbounded time in ACL setup.
     */
    private static void validateAccessTrees(List<Path> roots) throws IOException {
        int[] count = {0};
        for (Path root : roots) {
            if (isReparse(root)) throw new IOException("access-root-reparse-point");
            if (Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS)) {
                Files.walkFileTree(root, new SimpleFileVisitor<Path>() {
                    @Override
                    public FileVisitResult preVisitDirectory(Path directory,
                                                              BasicFileAttributes attributes)
                            throws IOException {
                        visit(directory, attributes, true);
                        return FileVisitResult.CONTINUE;
                    }

                    @Override
                    public FileVisitResult visitFile(Path file, BasicFileAttributes attributes)
                            throws IOException {
                        visit(file, attributes, false);
                        return FileVisitResult.CONTINUE;
                    }

                    private void visit(Path path, BasicFileAttributes attributes,
                                       boolean directory) throws IOException {
                        if (++count[0] > MAX_ACCESS_TREE_ENTRIES) {
                            throw new IOException("access-tree-entry-limit");
                        }
                        if (isReparse(path) || attributes.isSymbolicLink()
                                || (!directory && !attributes.isRegularFile())) {
                            throw new IOException("access-tree-entry-not-regular");
                        }
                    }

                    @Override
                    public FileVisitResult visitFileFailed(Path file, IOException failure)
                            throws IOException {
                        throw new IOException("access-tree-walk-failed", failure);
                    }
                });
            } else if (!Files.isRegularFile(root, LinkOption.NOFOLLOW_LINKS)) {
                throw new IOException("access-root-not-regular");
            }
        }
    }

    private interface ProcessApi extends StdCallLibrary {
        WinNT.HANDLE CreateMutexW(Pointer attributes, boolean initialOwner, WString name);
        boolean ReleaseMutex(WinNT.HANDLE mutex);
        boolean InitializeProcThreadAttributeList(Pointer list, int count, int flags,
                                                   LongByReference size);
        boolean UpdateProcThreadAttribute(Pointer list, int flags, long attribute, Pointer value,
                                          long size, Pointer previous, LongByReference returnSize);
        void DeleteProcThreadAttributeList(Pointer list);
        WinNT.HANDLE GetStdHandle(int standardHandle);
        boolean CreateProcessW(WString applicationName, char[] commandLine, Pointer processAttributes,
                               Pointer threadAttributes, boolean inheritHandles, int creationFlags,
                               Pointer environment, WString currentDirectory, Pointer startupInfo,
                               WinBase.PROCESS_INFORMATION processInformation);
        int WaitForSingleObject(WinNT.HANDLE handle, int milliseconds);
        boolean GetExitCodeProcess(WinNT.HANDLE process, IntByReference exitCode);
        boolean TerminateProcess(WinNT.HANDLE process, int exitCode);
        boolean CloseHandle(WinNT.HANDLE handle);
        int GetLastError();
        int GetCurrentProcessId();
    }

    private interface UserEnvApi extends StdCallLibrary {
        int CreateAppContainerProfile(WString name, WString displayName, WString description,
                                      Pointer capabilities, int capabilityCount,
                                      PointerByReference sid);
        int DeleteAppContainerProfile(WString name);
    }

    private interface SecurityApi extends StdCallLibrary {
        boolean ConvertSidToStringSid(WinNT.PSID sid, PointerByReference stringSid);
        Pointer LocalFree(Pointer memory);
        Pointer FreeSid(Pointer sid);
    }
}
