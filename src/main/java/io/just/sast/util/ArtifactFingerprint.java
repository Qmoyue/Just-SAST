package io.just.sast.util;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Comparator;
import java.util.List;

/**
 * Deterministic identity for a scan artifact.
 *
 * <p>Files are hashed as-is.  Directory inputs are hashed as a sorted sequence of
 * normalized relative names, a zero separator, and file bytes.  Keeping this in one
 * utility makes the report identity and the child-verifier attestation use exactly the
 * same contract.</p>
 */
public final class ArtifactFingerprint {

    private static final int BUFFER_SIZE = 64 * 1024;

    private ArtifactFingerprint() {
    }

    public static String sha256(Path input) throws IOException {
        if (input == null) {
            throw new IOException("artifact-not-readable");
        }
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException impossible) {
            throw new IOException("sha256-unavailable", impossible);
        }
        if (ArchiveLimits.isLinkOrReparsePoint(input)) {
            throw new IOException("artifact-link-or-reparse-point");
        }
        if (Files.isRegularFile(input)) {
            updateDigest(digest, input);
        } else if (Files.isDirectory(input)) {
            List<Path> files;
            try (var walk = Files.walk(input)) {
                files = walk.filter(Files::isRegularFile)
                        .filter(path -> !ArchiveLimits.isLinkOrReparsePoint(path))
                        .sorted(Comparator.comparing(path -> relativeName(input, path)))
                        .toList();
            }
            for (Path file : files) {
                digest.update(relativeName(input, file).getBytes(StandardCharsets.UTF_8));
                digest.update((byte) 0);
                updateDigest(digest, file);
            }
        } else {
            throw new IOException("artifact-not-readable");
        }
        return hex(digest.digest());
    }

    private static String relativeName(Path root, Path file) {
        return root.relativize(file).toString().replace('\\', '/');
    }

    private static void updateDigest(MessageDigest digest, Path file) throws IOException {
        try (InputStream input = Files.newInputStream(file)) {
            byte[] buffer = new byte[BUFFER_SIZE];
            for (int read; (read = input.read(buffer)) >= 0; ) {
                if (read > 0) {
                    digest.update(buffer, 0, read);
                }
            }
        }
    }

    private static String hex(byte[] bytes) {
        StringBuilder result = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) {
            result.append(String.format(java.util.Locale.ROOT, "%02x", value & 0xff));
        }
        return result.toString();
    }
}
