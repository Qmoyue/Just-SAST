package io.just.sast.verify.legacy;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Java 8-compatible counterpart of the probe-side safe sink adapter.
 *
 * <p>This class is deliberately dependency-free because the legacy verifier JAR is launched
 * on the target runtime.  It performs only fixed in-memory observations and one fixed marker
 * write below the child-owned scratch directory; it never calls target sink code or an OS
 * capability.</p>
 */
final class LegacySafeSinkAdapter {

    private static final String POLICY_CANONICAL =
            "JUST_SAFE_SINK_POLICY_V1|mode=SAFE_EXEC|scratch=per-attempt-canonical"
                    + "|adapter=COMMAND|adapter=DATA|adapter=FILE|adapter=NETWORK";

    private LegacySafeSinkAdapter() {
    }

    static boolean observe(String mode, String disposition, String policyDigest,
                           Path scratchRoot) {
        if (!"SAFE_EXEC".equals(mode) || disposition == null
                || "CANARY_BOUNDARY".equals(disposition) || "DENIED".equals(disposition)
                || !policyDigest().equals(policyDigest)) {
            return false;
        }
        if ("SCRATCH_FILESYSTEM".equals(disposition)) {
            return observeScratch(scratchRoot);
        }
        // COMMAND, NETWORK and DATA are represented by fixed local values. No Runtime,
        // ProcessBuilder, Socket, DNS, class loading, or target argument is involved.
        return "INERT_COMMAND".equals(disposition)
                || "LOOPBACK_MOCK".equals(disposition)
                || "IN_MEMORY".equals(disposition);
    }

    static String policyDigest() {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(POLICY_CANONICAL.getBytes(StandardCharsets.UTF_8));
            StringBuilder result = new StringBuilder(digest.length * 2);
            for (byte current : digest) {
                result.append(String.format(java.util.Locale.ROOT, "%02x", current & 0xff));
            }
            return result.toString();
        } catch (NoSuchAlgorithmException impossible) {
            return "sha256-unavailable";
        }
    }

    private static boolean observeScratch(Path scratchRoot) {
        if (scratchRoot == null) {
            return false;
        }
        try {
            Path lexical = scratchRoot.toAbsolutePath().normalize();
            if (!Files.isDirectory(lexical) || Files.isSymbolicLink(lexical)) {
                return false;
            }
            Path root = lexical.toRealPath();
            Path marker = root.resolve("just-safe-effect.marker").normalize();
            if (!marker.startsWith(root) || Files.exists(marker)
                    || Files.isSymbolicLink(marker)) {
                return false;
            }
            Files.write(marker, "JUST_SAFE_EFFECT\n".getBytes(StandardCharsets.US_ASCII),
                    StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
            return true;
        } catch (IOException | RuntimeException failure) {
            return false;
        }
    }
}
