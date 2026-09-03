package io.just.sast.verify.legacy;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Java 8-compatible counterpart of the probe-side safe sink adapter.
 *
 * <p>This class is deliberately dependency-free because the legacy verifier JAR is launched
 * on the target runtime.  SAFE_EXEC performs fixed mock observations. SAFE_REAL performs only
 * adapter-owned fixed effects after a canary and is accepted by the parent only with an
 * authenticated process boundary
 * isolation; it never forwards target sink arguments.</p>
 */
final class LegacySafeSinkAdapter {

    private static final String POLICY_PREFIX =
            "JUST_SAFE_SINK_POLICY_V1|mode=";
    private static final String CAPABILITIES =
            "|scratch=per-attempt-canonical"
                    + "|adapter=COMMAND|adapter=DATA|adapter=FILE|adapter=NETWORK";

    private LegacySafeSinkAdapter() {
    }

    /** Java 8-compatible observation value; a boolean alone cannot carry an auditable effect. */
    static final class Observation {
        private final boolean observed;
        private final String effect;
        private final String reason;

        Observation(boolean observed, String effect, String reason) {
            this.observed = observed;
            this.effect = effect == null ? "" : effect;
            this.reason = reason == null ? "" : reason;
        }

        boolean observed() {
            return observed;
        }

        String effect() {
            return effect;
        }

        String reason() {
            return reason;
        }
    }

    static Observation observe(String mode, String disposition, String policyDigest,
                               Path scratchRoot) {
        return observe(mode, disposition, policyDigest, scratchRoot, null);
    }

    static Observation observe(String mode, String disposition, String policyDigest,
                               Path scratchRoot, Path fixedJavaExecutable) {
        if ((!("SAFE_EXEC".equals(mode) || "SAFE_REAL".equals(mode))) || disposition == null
                || "CANARY_BOUNDARY".equals(disposition) || "DENIED".equals(disposition)
                || !policyDigest(mode).equals(policyDigest)) {
            return no("policy-or-disposition-mismatch");
        }
        if ("SCRATCH_FILESYSTEM".equals(disposition)
                || "REAL_SCRATCH_FILESYSTEM".equals(disposition)) {
            return observeScratch(scratchRoot,
                    "REAL_SCRATCH_FILESYSTEM".equals(disposition)
                            ? "REAL_SCRATCH_FILE_WRITE" : "SCRATCH_MARKER_WRITTEN");
        }
        if ("SAFE_EXEC".equals(mode)) {
            // COMMAND, NETWORK and DATA are represented by fixed local values. No Runtime,
            // ProcessBuilder, Socket, DNS, class loading, or target argument is involved.
            if ("INERT_COMMAND".equals(disposition)) {
                return observed("INERT_COMMAND_RECORDED");
            }
            if ("LOOPBACK_MOCK".equals(disposition)) {
                return observed("LOOPBACK_MOCK_IN_MEMORY");
            }
            if ("IN_MEMORY".equals(disposition)) {
                return observed("IN_MEMORY_VALUE_OBSERVED");
            }
            return no("unsupported-safe-exec-disposition");
        }
        if ("REAL_COMMAND".equals(disposition)) {
            return observeRealCommand(fixedJavaExecutable);
        }
        if ("REAL_LOOPBACK".equals(disposition)) {
            return observeRealLoopback();
        }
        return "REAL_IN_MEMORY".equals(disposition)
                ? observed("REAL_IN_MEMORY_VALUE") : no("unsupported-safe-real-disposition");
    }

    static String policyDigest() {
        return policyDigest("SAFE_EXEC");
    }

    static String policyDigest(String mode) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest((POLICY_PREFIX + ("SAFE_REAL".equals(mode)
                            ? "SAFE_REAL" : "SAFE_EXEC") + CAPABILITIES)
                            .getBytes(StandardCharsets.UTF_8));
            StringBuilder result = new StringBuilder(digest.length * 2);
            for (byte current : digest) {
                result.append(String.format(java.util.Locale.ROOT, "%02x", current & 0xff));
            }
            return result.toString();
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("required SHA-256 digest unavailable", impossible);
        }
    }

    static String effectDigest(String effect) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest((effect == null ? "" : effect).getBytes(StandardCharsets.UTF_8));
            StringBuilder result = new StringBuilder(digest.length * 2);
            for (byte current : digest) {
                result.append(String.format(java.util.Locale.ROOT, "%02x", current & 0xff));
            }
            return result.toString();
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("required SHA-256 digest unavailable", impossible);
        }
    }

    private static Observation observeScratch(Path scratchRoot, String effect) {
        if (scratchRoot == null) {
            return no("scratch-root-missing");
        }
        try {
            Path lexical = scratchRoot.toAbsolutePath().normalize();
            if (!Files.isDirectory(lexical, LinkOption.NOFOLLOW_LINKS)
                    || isReparsePoint(lexical)) {
                return no("scratch-root-invalid");
            }
            Path root;
            try {
                root = lexical.toRealPath();
            } catch (SecurityException denied) {
                root = lexical;
            }
            Path marker = root.resolve("just-safe-effect.marker").normalize();
            if (!marker.startsWith(root) || Files.exists(marker, LinkOption.NOFOLLOW_LINKS)
                    || isReparsePoint(marker)) {
                return no("scratch-marker-invalid");
            }
            Files.write(marker, "JUST_SAFE_EFFECT\n".getBytes(StandardCharsets.US_ASCII),
                    StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
            return observed(effect);
        } catch (IOException | RuntimeException failure) {
            return no("scratch-write-failed");
        }
    }

    private static Observation observeRealCommand(Path executable) {
        if (executable == null) {
            return no("fixed-helper-missing");
        }
        Process process = null;
        try {
            Path fixed = executable.toAbsolutePath().normalize();
            if (!Files.isRegularFile(fixed, LinkOption.NOFOLLOW_LINKS)
                    || isReparsePoint(fixed)) {
                return no("fixed-helper-invalid");
            }
            LegacySandboxSecurityManager.beginSafeRealExec(fixed);
            process = new ProcessBuilder(fixed.toString(), "-version")
                    .redirectOutput(ProcessBuilder.Redirect.DISCARD)
                    .redirectError(ProcessBuilder.Redirect.DISCARD)
                    .start();
            if (!process.waitFor(2L, java.util.concurrent.TimeUnit.SECONDS)) {
                process.destroyForcibly();
                return no("fixed-helper-timeout");
            }
            return process.exitValue() == 0
                    ? observed("REAL_FIXED_JAVA_COMMAND") : no("fixed-helper-failed");
        } catch (Exception failure) {
            if (process != null) {
                process.destroyForcibly();
            }
            return no("fixed-helper-failed");
        } finally {
            LegacySandboxSecurityManager.endSafeRealExec();
        }
    }

    private static Observation observeRealLoopback() {
        byte[] request = "JUST_LOOPBACK_REQUEST".getBytes(StandardCharsets.US_ASCII);
        try {
            LegacySandboxSecurityManager.beginSafeRealNetwork();
            ServerSocket server = new ServerSocket();
            try {
                server.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
                Socket client = new Socket();
                try {
                    client.connect(server.getLocalSocketAddress(), 500);
                    Socket accepted = server.accept();
                    try {
                        accepted.setSoTimeout(500);
                        client.setSoTimeout(500);
                        client.getOutputStream().write(request);
                        client.getOutputStream().flush();
                        byte[] received = new byte[request.length];
                        int count = accepted.getInputStream().read(received);
                        accepted.getOutputStream().write(received, 0, Math.max(0, count));
                        accepted.getOutputStream().flush();
                        byte[] echoed = new byte[request.length];
                        int echoedCount = client.getInputStream().read(echoed);
                        return count == request.length && echoedCount == request.length
                                && java.util.Arrays.equals(request, received)
                                && java.util.Arrays.equals(request, echoed)
                                ? observed("REAL_LOOPBACK_ROUND_TRIP")
                                : no("loopback-round-trip-failed");
                    } finally {
                        accepted.close();
                    }
                } finally {
                    client.close();
                }
            } finally {
                server.close();
            }
        } catch (Exception failure) {
            return no("loopback-round-trip-failed");
        } finally {
            LegacySandboxSecurityManager.endSafeRealNetwork();
        }
    }

    private static Observation observed(String effect) {
        return new Observation(true, effect, "observed");
    }

    private static Observation no(String reason) {
        return new Observation(false, "NO_EFFECT_EXECUTED", reason);
    }

    private static boolean isReparsePoint(Path path) {
        if (path == null || Files.isSymbolicLink(path)) {
            return true;
        }
        try {
            return Boolean.TRUE.equals(Files.getAttribute(path, "dos:reparsePoint",
                    LinkOption.NOFOLLOW_LINKS));
        } catch (IOException | RuntimeException ignored) {
            return false;
        }
    }
}
