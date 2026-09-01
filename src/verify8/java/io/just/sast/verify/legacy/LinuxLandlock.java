package io.just.sast.verify.legacy;

import com.sun.jna.Function;
import com.sun.jna.NativeLibrary;
import com.sun.jna.Structure;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;

/** Java 8-compatible child-side Landlock binding for the strict Linux runner. */
final class LinuxLandlock {

    private static final long SYS_CREATE_RULESET = 444L;
    private static final long SYS_ADD_RULE = 445L;
    private static final long SYS_RESTRICT_SELF = 446L;
    private static final long CREATE_RULESET_VERSION = 1L;
    private static final long RULE_TYPE_PATH_BENEATH = 1L;
    private static final int PR_SET_NO_NEW_PRIVS = 38;
    private static final int O_CLOEXEC = 0x80000;
    private static final int O_DIRECTORY = 0x10000;
    private static final int O_PATH = 0x200000;

    private static final long EXECUTE = 1L << 0;
    private static final long WRITE_FILE = 1L << 1;
    private static final long READ_FILE = 1L << 2;
    private static final long READ_DIR = 1L << 3;
    private static final long REMOVE_DIR = 1L << 4;
    private static final long REMOVE_FILE = 1L << 5;
    private static final long MAKE_CHAR = 1L << 6;
    private static final long MAKE_DIR = 1L << 7;
    private static final long MAKE_REG = 1L << 8;
    private static final long MAKE_SOCK = 1L << 9;
    private static final long MAKE_FIFO = 1L << 10;
    private static final long MAKE_BLOCK = 1L << 11;
    private static final long MAKE_SYM = 1L << 12;
    private static final long REFER = 1L << 13;
    private static final long TRUNCATE = 1L << 14;

    private LinuxLandlock() {
    }

    static boolean install(List<Path> writableRoots) {
        if (!isLinux() || !supportedArchitecture()
                || writableRoots == null || writableRoots.isEmpty()) {
            return false;
        }
        NativeLibrary libc = null;
        int ruleset = -1;
        try {
            for (Path root : writableRoots) {
                if (root == null || !Files.isDirectory(root) || Files.isSymbolicLink(root)) {
                    return false;
                }
            }
            libc = NativeLibrary.getInstance("c");
            Function syscall = libc.getFunction("syscall");
            Function open = libc.getFunction("open");
            Function close = libc.getFunction("close");
            Function prctl = libc.getFunction("prctl");
            long abi = invokeLong(syscall, SYS_CREATE_RULESET, null, 0L,
                    CREATE_RULESET_VERSION);
            if (abi < 3L) {
                return false;
            }
            long all = allFilesystemAccess(abi);
            RulesetAttr rules = new RulesetAttr(all);
            rules.write();
            ruleset = (int) invokeLong(syscall, SYS_CREATE_RULESET,
                    rules.getPointer(), (long) rules.size(), 0L);
            if (ruleset < 0) {
                return false;
            }
            if (invokeLong(prctl, (long) PR_SET_NO_NEW_PRIVS, 1L, 0L, 0L, 0L) != 0L) {
                return false;
            }
            int namespaceRoot = open(open, "/", O_PATH | O_CLOEXEC | O_DIRECTORY);
            if (namespaceRoot < 0 || !addPathRule(syscall, ruleset, namespaceRoot,
                    EXECUTE | READ_FILE | READ_DIR)) {
                close(close, namespaceRoot);
                return false;
            }
            close(close, namespaceRoot);
            for (Path root : writableRoots) {
                int fd = open(open, root.toAbsolutePath().normalize().toString(),
                        O_PATH | O_CLOEXEC | O_DIRECTORY);
                if (fd < 0 || !addPathRule(syscall, ruleset, fd, all)) {
                    close(close, fd);
                    return false;
                }
                close(close, fd);
            }
            return invokeLong(syscall, SYS_RESTRICT_SELF, (long) ruleset, 0L) == 0L;
        } catch (Throwable ignored) {
            return false;
        } finally {
            if (libc != null && ruleset >= 0) {
                try {
                    close(libc.getFunction("close"), ruleset);
                } catch (Throwable ignored) {
                    // A failed child is rejected by the parent protocol.
                }
            }
        }
    }

    private static boolean addPathRule(Function syscall, int ruleset, int parentFd,
                                       long allowedAccess) {
        PathBeneathAttr path = new PathBeneathAttr(allowedAccess, parentFd);
        path.write();
        return invokeLong(syscall, SYS_ADD_RULE, (long) ruleset, RULE_TYPE_PATH_BENEATH,
                path.getPointer(), 0L) == 0L;
    }

    private static long allFilesystemAccess(long abi) {
        long all = EXECUTE | WRITE_FILE | READ_FILE | READ_DIR | REMOVE_DIR | REMOVE_FILE
                | MAKE_CHAR | MAKE_DIR | MAKE_REG | MAKE_SOCK | MAKE_FIFO | MAKE_BLOCK
                | MAKE_SYM;
        if (abi >= 2L) {
            all |= REFER;
        }
        if (abi >= 3L) {
            all |= TRUNCATE;
        }
        return all;
    }

    private static int open(Function function, String path, int flags) {
        return ((Number) function.invoke(Integer.TYPE, new Object[]{path, flags})).intValue();
    }

    private static void close(Function function, int fd) {
        if (fd >= 0) {
            function.invoke(Integer.TYPE, new Object[]{fd});
        }
    }

    private static long invokeLong(Function function, Object... args) {
        return ((Number) function.invoke(Long.TYPE, args)).longValue();
    }

    private static boolean isLinux() {
        return System.getProperty("os.name", "")
                .toLowerCase(Locale.ROOT).contains("linux");
    }

    /** Syscall numbers above are Linux x86_64/aarch64 numbers, not portable JNA constants. */
    private static boolean supportedArchitecture() {
        String architecture = System.getProperty("os.arch", "")
                .toLowerCase(Locale.ROOT).replace('-', '_');
        return architecture.equals("amd64") || architecture.equals("x86_64")
                || architecture.equals("aarch64") || architecture.equals("arm64");
    }

    @Structure.FieldOrder({"handledAccessFs", "handledAccessNet"})
    private static final class RulesetAttr extends Structure {
        private long handledAccessFs;
        private long handledAccessNet;

        private RulesetAttr(long handledAccessFs) {
            this.handledAccessFs = handledAccessFs;
        }
    }

    @Structure.FieldOrder({"allowedAccess", "parentFd"})
    private static final class PathBeneathAttr extends Structure {
        private long allowedAccess;
        private int parentFd;

        private PathBeneathAttr(long allowedAccess, int parentFd) {
            this.allowedAccess = allowedAccess;
            this.parentFd = parentFd;
        }
    }
}
