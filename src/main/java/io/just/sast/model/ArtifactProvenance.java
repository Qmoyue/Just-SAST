package io.just.sast.model;

import java.util.Locale;
import java.util.Objects;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import io.just.sast.util.ArtifactFingerprint;
import io.just.sast.run.InputBudget;

/**
 * Stable, report-safe identity for one input artifact.
 *
 * <p>The model deliberately keeps a logical name rather than a workstation path.  A
 * SHA-256 (when available) is the authoritative content identity; callers must not use the
 * display name or origin as a cache key.</p>
 */
public record ArtifactProvenance(String logicalName, Role role, String sha256, long sizeBytes) {

    public enum Role {
        APPLICATION,
        DEPENDENCY,
        JDK,
        UNKNOWN
    }

    public ArtifactProvenance {
        logicalName = normalizeName(logicalName);
        role = role == null ? Role.UNKNOWN : role;
        sha256 = normalizeDigest(sha256);
        if (sizeBytes < -1L) {
            throw new IllegalArgumentException("sizeBytes must be -1 or non-negative");
        }
    }

    /** Construct a provenance value when the bytes or file size are not available. */
    public static ArtifactProvenance unknown(String logicalName, Role role) {
        return new ArtifactProvenance(logicalName, role, "UNKNOWN", -1L);
    }

    /** Resolve content identity without retaining the caller's absolute path. */
    public static ArtifactProvenance fromPath(Path path, Role role) throws IOException {
        return fromPath(path, role, InputBudget.defaults());
    }

    /** Resolve identity under the caller's immutable input policy. */
    public static ArtifactProvenance fromPath(Path path, Role role,
                                              InputBudget budget) throws IOException {
        InputBudget policy = budget == null ? InputBudget.defaults() : budget;
        return fromPath(path, role, policy, policy.tracker());
    }

    /** Resolve identity while charging the caller-owned aggregate tracker. */
    public static ArtifactProvenance fromPath(Path path, Role role,
                                              InputBudget budget,
                                              InputBudget.Tracker tracker) throws IOException {
        if (path == null) {
            throw new IOException("artifact path is null");
        }
        InputBudget policy = budget == null ? InputBudget.defaults() : budget;
        InputBudget.Tracker accounting = tracker == null ? policy.tracker() : tracker;
        String logicalName = path.getFileName() == null ? "<unknown>" : path.getFileName().toString();
        long size = Files.isRegularFile(path, java.nio.file.LinkOption.NOFOLLOW_LINKS)
                ? Files.size(path) : -1L;
        return new ArtifactProvenance(logicalName, role,
                ArtifactFingerprint.sha256(path, accounting), size);
    }

    /** Canonical identity used by caches and semantic digests. */
    public String identity() {
        return "artifact-v1|" + role.name() + "|" + logicalName + "|" + sha256 + "|" + sizeBytes;
    }

    /** True only for a validated lower-case SHA-256 digest. */
    public boolean hasContentDigest() {
        return !"UNKNOWN".equals(sha256);
    }

    private static String normalizeName(String value) {
        if (value == null || value.isBlank()) {
            return "<unknown>";
        }
        // Origins can contain nested-archive separators; preserve the logical suffix while
        // avoiding accidental CR/LF or surrounding whitespace in reports and cache keys.
        return value.trim().replace('\r', '_').replace('\n', '_');
    }

    private static String normalizeDigest(String value) {
        if (value == null || value.isBlank()) {
            return "UNKNOWN";
        }
        String normalized = value.trim().toUpperCase(Locale.ROOT);
        if ("UNKNOWN".equals(normalized)) {
            return normalized;
        }
        if (!normalized.matches("[0-9A-F]{64}")) {
            throw new IllegalArgumentException("sha256 must be a 64-character hexadecimal digest or UNKNOWN");
        }
        return normalized;
    }
}
