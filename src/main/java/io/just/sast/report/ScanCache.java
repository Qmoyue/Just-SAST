package io.just.sast.report;

import io.just.sast.util.ArchiveLimits;
import io.just.sast.util.ArtifactFingerprint;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;

/**
 * Explicit report-level incremental cache.
 *
 * <p>The cache is deliberately opt-in and lives outside the normal report directory. A hit
 * restores only an immutable report whose identity and completion sentinel were written last;
 * partial, cancelled, failed, timeout or truncated scans never become reusable entries.</p>
 */
public final class ScanCache {

    private static final String KEY_PATTERN = "[0-9a-f]{64}";
    private static final long MAX_SENTINEL_BYTES = 4096L;

    public record Preflight(String artifactHash, String dependencyIdentity,
                            List<String> dependencyHashes, String cacheKey) {
        public Preflight {
            dependencyHashes = dependencyHashes == null ? List.of() : List.copyOf(dependencyHashes);
        }
    }

    private ScanCache() {
    }

    /** Calculate all immutable inputs needed for a cache lookup before frontend parsing. */
    public static Preflight preflight(Path target, List<Path> dependencies, Path rules,
                                      Path jdkHome, boolean fast, boolean verify,
                                      int verifyBudget, boolean safeExec,
                                      boolean requireOsIsolation) throws IOException {
        return preflight(target, dependencies, rules, jdkHome, fast, verify, verifyBudget,
                safeExec, false, requireOsIsolation);
    }

    /** Preflight identity including the explicit adapter-owned SAFE_REAL mode. */
    public static Preflight preflight(Path target, List<Path> dependencies, Path rules,
                                      Path jdkHome, boolean fast, boolean verify,
                                      int verifyBudget, boolean safeExec, boolean safeReal,
                                      boolean requireOsIsolation) throws IOException {
        validateInput(target, true);
        if (dependencies != null) {
            for (Path dependency : dependencies) {
                validateInput(dependency, true);
            }
        }
        if (rules != null) {
            validateInput(rules, false);
        }
        if (jdkHome != null) {
            validateInput(jdkHome, true);
        }
        String artifactHash = ArtifactFingerprint.sha256(target);
        List<String> dependencyHashes = dependencyHashes(dependencies);
        String dependencyIdentity = dependencyIdentityFromHashes(dependencyHashes);
        String cacheKey = ScanIdentityWriter.cacheKey(artifactHash, dependencyIdentity, rules,
                jdkHome, fast, verify, verifyBudget, safeExec, safeReal,
                requireOsIsolation);
        return new Preflight(artifactHash, dependencyIdentity, dependencyHashes, cacheKey);
    }

    /** Direct dependency order is part of the identity because class shadowing is order-sensitive. */
    public static String dependencyIdentity(List<Path> dependencies) throws IOException {
        List<Path> values = dependencies == null ? List.of() : dependencies;
        return dependencyIdentityFromHashes(dependencyHashes(values));
    }

    /** Hash direct dependencies once; the same list can be reused by inventory generation. */
    public static List<String> dependencyHashes(List<Path> dependencies) throws IOException {
        List<Path> values = dependencies == null ? List.of() : dependencies;
        List<String> hashes = new java.util.ArrayList<>(values.size());
        for (Path dependency : values) {
            hashes.add(ArtifactFingerprint.sha256(dependency));
        }
        return List.copyOf(hashes);
    }

    public static String dependencyIdentityFromHashes(List<String> dependencyHashes) throws IOException {
        MessageDigest digest = sha256();
        List<String> values = dependencyHashes == null ? List.of() : dependencyHashes;
        for (int i = 0; i < values.size(); i++) {
            digest.update(("dependency[" + i + "]=").getBytes(StandardCharsets.UTF_8));
            digest.update((values.get(i) == null ? "UNAVAILABLE" : values.get(i))
                    .getBytes(StandardCharsets.US_ASCII));
            digest.update((byte) '\n');
        }
        return hex(digest.digest());
    }

    /** Restore a validated entry only into an absent or empty destination. */
    public static boolean restore(Path cacheRoot, String cacheKey, Path output) throws IOException {
        validateKey(cacheKey);
        Path root = prepareRoot(cacheRoot);
        Path destination = normalize(output);
        if (destination.startsWith(root)) {
            throw new IOException("cache output must be outside cache root");
        }
        Path entry = root.resolve(cacheKey);
        if (!validEntry(entry, cacheKey)) {
            return false;
        }
        if (Files.exists(destination, LinkOption.NOFOLLOW_LINKS)) {
            if (ArchiveLimits.isLinkOrReparsePoint(destination)
                    || !Files.isDirectory(destination, LinkOption.NOFOLLOW_LINKS)) {
                throw new IOException("cache output is not a real directory: " + destination);
            }
            try (var children = Files.list(destination)) {
                if (children.findAny().isPresent()) {
                    return false;
                }
            }
        }
        Files.createDirectories(destination);
        copyTree(entry, destination, false);
        Path event = destination.resolve("meta").resolve("cache-event.json");
        AtomicFiles.writeUtf8(event, "{\"schema_version\":1,\"event\":\"hit\","
                + "\"cache_key\":\"" + cacheKey + "\"}\n");
        return true;
    }

    /** Store a complete report. Existing valid entries are immutable and are never overwritten. */
    public static boolean store(Path cacheRoot, String cacheKey, Path output,
                                ScanStatistics statistics) throws IOException {
        validateKey(cacheKey);
        if (!cacheable(statistics)) {
            return false;
        }
        Path root = prepareRoot(cacheRoot);
        Path source = normalize(output);
        if (!Files.isDirectory(source, LinkOption.NOFOLLOW_LINKS)
                || ArchiveLimits.isLinkOrReparsePoint(source)) {
            throw new IOException("cache source is not a real directory: " + source);
        }
        Path sourceIdentity = source.resolve("meta").resolve("scan-identity.json");
        if (!regular(sourceIdentity)
                || !Files.readString(sourceIdentity, StandardCharsets.UTF_8)
                .contains("\"cache_key\":\"" + cacheKey + "\"")) {
            // Inputs may have changed between the preflight and the end of the scan. Do not
            // publish a report under a stale key; the next invocation will rebuild it.
            return false;
        }
        if (source.startsWith(root)) {
            throw new IOException("cache source must be outside cache root");
        }
        Path entry = root.resolve(cacheKey);
        if (validEntry(entry, cacheKey)) {
            return false;
        }
        Path staging = root.resolve("." + cacheKey + ".staging-"
                + Long.toUnsignedString(System.nanoTime()));
        if (Files.exists(staging, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("cache staging path already exists");
        }
        try {
            Files.createDirectories(staging);
            copyTree(source, staging, true);
            Path sentinel = staging.resolve("meta").resolve("cache-complete.json");
            AtomicFiles.writeUtf8(sentinel, "{\"schema_version\":1,\"cache_key\":\""
                    + cacheKey + "\",\"completeness\":\"COMPLETE\"}\n");
            if (Files.exists(entry, LinkOption.NOFOLLOW_LINKS)) {
                return false;
            }
            try {
                Files.move(staging, entry, StandardCopyOption.ATOMIC_MOVE);
            } catch (java.nio.file.AtomicMoveNotSupportedException unsupported) {
                Files.move(staging, entry);
            }
            return true;
        } finally {
            if (Files.exists(staging, LinkOption.NOFOLLOW_LINKS)) {
                deleteTree(staging);
            }
        }
    }

    /** Cacheability gate: only complete semantic reports with no negative dynamic terminal exist. */
    public static boolean cacheable(ScanStatistics statistics) {
        if (statistics == null || !"COMPLETE".equals(statistics.completeness())
                || !"COMPLETE".equals(statistics.chainProofCompleteness())) {
            return false;
        }
        if (statistics.dynamicVerification() == null) {
            return true;
        }
        return statistics.dynamicVerification().statusCounts().keySet().stream().noneMatch(
                status -> switch (status) {
                    case "PARTIAL", "FAILED", "TIMEOUT", "UNTESTABLE", "UNKNOWN" -> true;
                    default -> false;
        });
    }

    /** Record a path-free cache event beside a report; this file is excluded from cache copies. */
    public static void recordEvent(Path output, String cacheKey, String event) throws IOException {
        validateKey(cacheKey);
        Path root = normalize(output);
        Path meta = root.resolve("meta").normalize();
        if (!meta.startsWith(root) || !Files.isDirectory(meta, LinkOption.NOFOLLOW_LINKS)
                || ArchiveLimits.isLinkOrReparsePoint(meta)) {
            throw new IOException("report metadata directory is not safe");
        }
        String value = event == null || event.isBlank() ? "unknown" : event;
        if (!value.matches("[A-Za-z0-9_-]+")) {
            throw new IOException("invalid cache event");
        }
        AtomicFiles.writeUtf8(meta.resolve("cache-event.json"),
                "{\"schema_version\":1,\"event\":\"" + value
                        + "\",\"cache_key\":\"" + cacheKey + "\"}\n");
    }

    private static Path prepareRoot(Path input) throws IOException {
        if (input == null) {
            throw new IOException("cache directory is required");
        }
        Path root = normalize(input);
        if (Files.exists(root, LinkOption.NOFOLLOW_LINKS)
                && (ArchiveLimits.isLinkOrReparsePoint(root)
                || !Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS))) {
            throw new IOException("cache directory is not a real directory: " + root);
        }
        Files.createDirectories(root);
        if (ArchiveLimits.isLinkOrReparsePoint(root)
                || !Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("cache directory is not a real directory: " + root);
        }
        return root;
    }

    private static boolean validEntry(Path entry, String key) throws IOException {
        if (!Files.isDirectory(entry, LinkOption.NOFOLLOW_LINKS)
                || ArchiveLimits.isLinkOrReparsePoint(entry)) {
            return false;
        }
        Path identity = entry.resolve("meta").resolve("scan-identity.json");
        Path sentinel = entry.resolve("meta").resolve("cache-complete.json");
        if (!regular(identity) || !regular(sentinel)
                || Files.size(sentinel) > MAX_SENTINEL_BYTES) {
            return false;
        }
        String content = Files.readString(sentinel, StandardCharsets.UTF_8);
        return content.contains("\"cache_key\":\"" + key + "\"")
                && content.contains("\"completeness\":\"COMPLETE\"")
                && Files.readString(identity, StandardCharsets.UTF_8)
                .contains("\"cache_key\":\"" + key + "\"");
    }

    private static boolean regular(Path path) {
        return Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)
                && !ArchiveLimits.isLinkOrReparsePoint(path);
    }

    private static void copyTree(Path source, Path destination, boolean skipCacheEvent)
            throws IOException {
        List<Path> paths;
        try (var walk = Files.walk(source)) {
            paths = walk.sorted(Comparator.comparing(Path::toString)).toList();
        }
        for (Path path : paths) {
            if (ArchiveLimits.isLinkOrReparsePoint(path)) {
                throw new IOException("cache tree contains link or reparse point");
            }
            Path relative = source.relativize(path);
            if (skipCacheEvent && relative.toString().replace('\\', '/')
                    .equals("meta/cache-event.json")) {
                continue;
            }
            Path target = destination.resolve(relative).normalize();
            if (!target.startsWith(destination)) {
                throw new IOException("cache tree escapes destination");
            }
            if (Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) {
                Files.createDirectories(target);
            } else if (Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
                Files.createDirectories(target.getParent());
                Files.copy(path, target, StandardCopyOption.REPLACE_EXISTING);
            } else {
                throw new IOException("cache tree contains unsupported entry");
            }
        }
    }

    private static void deleteTree(Path root) throws IOException {
        if (!Files.exists(root, LinkOption.NOFOLLOW_LINKS)) {
            return;
        }
        List<Path> paths;
        try (var walk = Files.walk(root)) {
            paths = walk.sorted(Comparator.reverseOrder()).toList();
        }
        for (Path path : paths) {
            if (ArchiveLimits.isLinkOrReparsePoint(path) || Files.isRegularFile(path,
                    LinkOption.NOFOLLOW_LINKS) || Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) {
                Files.deleteIfExists(path);
            }
        }
    }

    private static void validateKey(String key) throws IOException {
        if (key == null || !key.matches(KEY_PATTERN)) {
            throw new IOException("invalid cache key");
        }
    }

    private static Path normalize(Path path) throws IOException {
        if (path == null) {
            throw new IOException("path is required");
        }
        return path.toAbsolutePath().normalize();
    }

    private static void validateInput(Path path, boolean allowDirectory) throws IOException {
        Path normalized = normalize(path);
        if (!Files.exists(normalized, LinkOption.NOFOLLOW_LINKS)
                || ArchiveLimits.isLinkOrReparsePoint(normalized)
                || (!Files.isRegularFile(normalized, LinkOption.NOFOLLOW_LINKS)
                && !(allowDirectory && Files.isDirectory(normalized, LinkOption.NOFOLLOW_LINKS)))) {
            throw new IOException("cache input is not a supported real path");
        }
    }

    private static MessageDigest sha256() throws IOException {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException impossible) {
            throw new IOException("sha256-unavailable", impossible);
        }
    }

    private static String hex(byte[] bytes) {
        StringBuilder value = new StringBuilder(bytes.length * 2);
        for (byte item : bytes) {
            value.append(String.format(Locale.ROOT, "%02x", item & 0xff));
        }
        return value.toString();
    }
}
