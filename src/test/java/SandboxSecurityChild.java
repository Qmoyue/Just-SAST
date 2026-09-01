import io.just.sast.verify.SandboxSecurityManager;

import java.nio.file.Files;
import java.nio.file.Path;

/** Small forked JVM used by the sandbox contract test; it is intentionally package-less. */
@SuppressWarnings("removal")
public final class SandboxSecurityChild {

    private SandboxSecurityChild() {
    }

    public static void main(String[] args) throws Exception {
        Path writable = Path.of(args[0]);
        Path outside = Path.of(args[1]);
        SandboxSecurityManager.install(writable);
        result("inside-write", () -> Files.writeString(writable.resolve("child.txt"), "ok"));
        result("outside-read", () -> Files.readString(outside));
        result("exec", () -> new ProcessBuilder("cmd", "/c", "ver").start());
        result("network", () -> new java.net.Socket("example.invalid", 80));
        System.out.println("CHILD_DONE");
    }

    private static void result(String name, ThrowingAction action) {
        try {
            action.run();
            System.out.println(name + "=ALLOWED");
        } catch (Throwable error) {
            System.out.println(name + "=DENIED:" + error.getClass().getSimpleName());
        }
    }

    @FunctionalInterface
    private interface ThrowingAction {
        void run() throws Exception;
    }
}
