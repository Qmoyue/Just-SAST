package io.just.sast.model;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Objects;

/**
 * Immutable provenance for one class or archive member.
 *
 * <p>The value is deliberately separate from {@link ArtifactProvenance}: the latter identifies
 * a scan input, while this record identifies a member inside that input.  {@code source} and
 * {@code logicalArtifact} are logical origins, never absolute workstation paths.  A missing
 * digest or coordinate remains explicit instead of being inferred from a filename.</p>
 */
public record ArchiveMemberProvenance(String source, String archivePath, String sha256,
                                      Role role, String coordinate, String logicalArtifact,
                                      Kind kind) {

    public enum Role {
        ROOT,
        NESTED_LIBRARY,
        SHADED,
        JDK,
        EXPLICIT_DEPENDENCY
    }

    public enum Kind {
        CLASS,
        ARCHIVE
    }

    public ArchiveMemberProvenance {
        source = logicalOrigin(source, "source");
        archivePath = archivePath(archivePath);
        sha256 = normalizeDigest(sha256);
        role = Objects.requireNonNull(role, "artifact role");
        coordinate = optionalText(coordinate, "coordinate");
        logicalArtifact = logicalOrigin(logicalArtifact, "logical artifact");
        kind = Objects.requireNonNull(kind, "member kind");
    }

    /** Build a member identity from bytes already bounded and materialized by the frontend. */
    public static ArchiveMemberProvenance fromBytes(String logicalArtifact, String source,
                                                     String archivePath, byte[] bytes, Role role,
                                                     Kind kind) {
        Objects.requireNonNull(bytes, "member bytes");
        return new ArchiveMemberProvenance(source, archivePath, sha256(bytes), role, "",
                logicalArtifact, kind);
    }

    /** Build a root/direct member from the hash frozen at the scan input boundary. */
    public static ArchiveMemberProvenance fromKnownHash(String logicalArtifact, String source,
                                                         String archivePath, String sha256,
                                                         Role role, String coordinate, Kind kind) {
        return new ArchiveMemberProvenance(source, archivePath, sha256, role, coordinate,
                logicalArtifact, kind);
    }

    /** Return the same member with a coordinate proven by exact archive metadata. */
    public ArchiveMemberProvenance withCoordinate(String value) {
        return new ArchiveMemberProvenance(source, archivePath, sha256, role, value,
                logicalArtifact, kind);
    }

    /** Identity used when matching a callback-time class to its finalized metadata snapshot. */
    public String contentIdentity() {
        return "member-v1|" + logicalArtifact + "|" + source + "|" + archivePath + "|"
                + sha256 + "|" + role.name() + "|" + kind.name();
    }

    /** Stable identity including the optional exact coordinate. */
    public String identity() {
        return contentIdentity() + "|" + coordinate;
    }

    public String artifactRole() {
        return role.name();
    }

    public boolean hasContentDigest() {
        return !"UNKNOWN".equals(sha256);
    }

    /** Hash bytes already materialized under the caller's input budget. */
    public static String sha256Of(byte[] bytes) {
        Objects.requireNonNull(bytes, "member bytes");
        return sha256(bytes);
    }

    private static String sha256(byte[] bytes) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(bytes)).toUpperCase(Locale.ROOT);
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("sha256-unavailable", impossible);
        }
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
            throw new IllegalArgumentException(
                    "sha256 must be a 64-character hexadecimal digest or UNKNOWN");
        }
        return normalized;
    }

    private static String logicalOrigin(String value, String field) {
        String normalized = required(value, field).replace('\\', '/');
        int bang = normalized.indexOf('!');
        String root = bang < 0 ? normalized : normalized.substring(0, bang);
        String suffix = bang < 0 ? "" : normalized.substring(bang);
        if (!root.startsWith("jdk:") && !root.startsWith("<")) {
            int slash = root.lastIndexOf('/');
            if (slash >= 0) {
                root = root.substring(slash + 1);
            }
        }
        return required(root + suffix, field);
    }

    private static String archivePath(String value) {
        String normalized = required(value, "archive path").replace('\\', '/');
        if (normalized.startsWith("/") || normalized.matches("[A-Za-z]:/.*")
                || normalized.equals("..") || normalized.startsWith("../")
                || normalized.contains("/../") || normalized.endsWith("/..")) {
            throw new IllegalArgumentException("archive path must be relative");
        }
        return normalized;
    }

    private static String optionalText(String value, String field) {
        if (value == null || value.isBlank()) {
            return "";
        }
        return required(value, field);
    }

    private static String required(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " is required");
        }
        if (value.indexOf('\r') >= 0 || value.indexOf('\n') >= 0) {
            throw new IllegalArgumentException(field + " contains a line break");
        }
        return value.trim();
    }
}
