package io.just.sast.report;

import io.just.sast.util.ArchiveLimits;
import io.just.sast.util.ArtifactFingerprint;
import io.just.sast.util.IoUtil;
import io.just.sast.run.InputBudget;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.BasicFileAttributes;
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
    private static final long MAX_IDENTITY_BYTES = 1L * 1024 * 1024;

    /** Package-local deterministic seam for the hostile restore-parent replacement contract. */
    @FunctionalInterface
    interface RestoreCommitHook {
        void beforeCommit() throws IOException;
    }

    public record Preflight(String artifactHash, String dependencyIdentity,
                            List<String> dependencyHashes, String cacheKey) {
        public Preflight {
            dependencyHashes = dependencyHashes == null ? List.of() : List.copyOf(dependencyHashes);
        }
    }

    /** Immutable NOFOLLOW identity snapshot for every directory in a path chain. */
    record DirectoryChainSnapshot(List<DirectoryIdentity> components) {
        DirectoryChainSnapshot {
            components = List.copyOf(components);
        }
    }

    private record DirectoryIdentity(Path path, BasicFileAttributes attributes) {
    }

    private ScanCache() {
    }

    /** Calculate all immutable inputs needed for a cache lookup before frontend parsing. */
    public static Preflight preflight(Path target, List<Path> dependencies, Path rules,
                                      Path jdkHome, boolean fast, String mode) throws IOException {
        return preflight(target, dependencies, rules, jdkHome, fast, mode,
                InputBudget.defaults(), "");
    }

    /** Preflight identity including the path-free dependency-environment identity. */
    public static Preflight preflight(Path target, List<Path> dependencies, Path rules,
                                      Path jdkHome, boolean fast, String mode,
                                      String dependencyEnvironmentIdentity) throws IOException {
        return preflight(target, dependencies, rules, jdkHome, fast, mode,
                InputBudget.defaults(), dependencyEnvironmentIdentity);
    }

    /** Preflight identity under an explicit immutable input policy. */
    public static Preflight preflight(Path target, List<Path> dependencies, Path rules,
                                      Path jdkHome, boolean fast, String mode,
                                      InputBudget budget) throws IOException {
        return preflight(target, dependencies, rules, jdkHome, fast, mode,
                budget, "");
    }

    /** Preflight with an explicit immutable dependency graph/environment identity. */
    public static Preflight preflight(Path target, List<Path> dependencies, Path rules,
                                      Path jdkHome, boolean fast, String mode,
                                      InputBudget budget,
                                      String dependencyEnvironmentIdentity) throws IOException {
        InputBudget policy = budget == null ? InputBudget.defaults() : budget;
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
            validateJdkHome(jdkHome);
        }
        InputBudget.Tracker sharedTracker = policy.tracker();
        String artifactHash = ArtifactFingerprint.sha256(target, sharedTracker);
        List<String> dependencyHashes = dependencyHashes(dependencies, sharedTracker);
        String dependencyIdentity = dependencyIdentityFromHashes(dependencyHashes,
                dependencyEnvironmentIdentity);
        String cacheKey = ScanIdentityWriter.cacheKey(artifactHash, dependencyIdentity, rules,
                jdkHome, fast, mode, policy);
        return new Preflight(artifactHash, dependencyIdentity, dependencyHashes, cacheKey);
    }

    /** Direct dependency order is part of the identity because class shadowing is order-sensitive. */
    public static String dependencyIdentity(List<Path> dependencies) throws IOException {
        List<Path> values = dependencies == null ? List.of() : dependencies;
        return dependencyIdentityFromHashes(dependencyHashes(values));
    }

    /** Direct dependency identity plus an explicit path-free environment graph identity. */
    public static String dependencyIdentity(List<Path> dependencies,
                                            String dependencyEnvironmentIdentity) throws IOException {
        List<Path> values = dependencies == null ? List.of() : dependencies;
        return dependencyIdentityFromHashes(dependencyHashes(values), dependencyEnvironmentIdentity);
    }

    /** Hash direct dependencies once; the same list can be reused by inventory generation. */
    public static List<String> dependencyHashes(List<Path> dependencies) throws IOException {
        return dependencyHashes(dependencies, InputBudget.defaults());
    }

    /** Hash direct dependencies with an explicit immutable input policy. */
    public static List<String> dependencyHashes(List<Path> dependencies,
                                                InputBudget budget) throws IOException {
        InputBudget policy = budget == null ? InputBudget.defaults() : budget;
        return dependencyHashes(dependencies, policy.tracker());
    }

    /** Hash dependencies against a caller-owned tracker shared with the target artifact. */
    public static List<String> dependencyHashes(List<Path> dependencies,
                                                InputBudget.Tracker tracker) throws IOException {
        InputBudget.Tracker shared = tracker == null
                ? InputBudget.defaults().tracker() : tracker;
        List<Path> values = dependencies == null ? List.of() : dependencies;
        List<String> hashes = new java.util.ArrayList<>(values.size());
        for (Path dependency : values) {
            hashes.add(ArtifactFingerprint.sha256(dependency, shared));
        }
        return List.copyOf(hashes);
    }

    public static String dependencyIdentityFromHashes(List<String> dependencyHashes) throws IOException {
        return dependencyIdentityFromHashes(dependencyHashes, "");
    }

    /** Include effective-POM/scope/source semantics in the dependency cache identity. */
    public static String dependencyIdentityFromHashes(List<String> dependencyHashes,
                                                      String dependencyEnvironmentIdentity)
            throws IOException {
        MessageDigest digest = sha256();
        List<String> values = dependencyHashes == null ? List.of() : dependencyHashes;
        for (int i = 0; i < values.size(); i++) {
            digest.update(("dependency[" + i + "]=").getBytes(StandardCharsets.UTF_8));
            digest.update((values.get(i) == null ? "UNAVAILABLE" : values.get(i))
                    .getBytes(StandardCharsets.US_ASCII));
            digest.update((byte) '\n');
        }
        if (dependencyEnvironmentIdentity != null
                && !dependencyEnvironmentIdentity.isBlank()) {
            digest.update("dependency-environment=".getBytes(StandardCharsets.UTF_8));
            digest.update(dependencyEnvironmentIdentity.getBytes(StandardCharsets.US_ASCII));
            digest.update((byte) '\n');
        }
        return hex(digest.digest());
    }

    /** Restore a validated entry only into an absent or empty destination. */
    public static boolean restore(Path cacheRoot, String cacheKey, Path output) throws IOException {
        return restore(cacheRoot, cacheKey, output, InputBudget.defaults());
    }

    /** Restore a cache entry while charging every copied file to one caller-owned budget. */
    public static boolean restore(Path cacheRoot, String cacheKey, Path output,
                                  InputBudget budget) throws IOException {
        return restoreInternal(cacheRoot, cacheKey, output, budget, null);
    }

    /**
     * Contract-only restore seam.  The hook runs after the staged copy and immediately before
     * the destination swap, allowing the hostile consumer test to replace the output parent
     * deterministically.  Production callers always use {@link #restore(Path, String, Path,
     * InputBudget)} and therefore supply no hook.
     */
    static boolean restoreForContract(Path cacheRoot, String cacheKey, Path output,
                                      RestoreCommitHook hook) throws IOException {
        return restoreInternal(cacheRoot, cacheKey, output, InputBudget.defaults(), hook);
    }

    private static boolean restoreInternal(Path cacheRoot, String cacheKey, Path output,
                                           InputBudget budget,
                                           RestoreCommitHook beforeCommit) throws IOException {
        validateKey(cacheKey);
        InputBudget policy = budget == null ? InputBudget.defaults() : budget;
        InputBudget.Tracker tracker = policy.tracker();
        Path root = prepareRoot(cacheRoot);
        Path destination = normalize(output);
        if (destination.startsWith(root)) {
            throw new IOException("cache output must be outside cache root");
        }
        Path entry = root.resolve(cacheKey);
        if (!validEntry(entry, cacheKey, policy, tracker)) {
            return false;
        }
        boolean destinationExisted = Files.exists(destination, LinkOption.NOFOLLOW_LINKS);
        if (destinationExisted) {
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
        Path parent = destination.getParent();
        createDirectoryTree(parent, "cache output parent");
        DirectoryChainSnapshot parentSnapshot = snapshotDirectoryChain(parent);
        verifyDirectoryChain(parentSnapshot);
        Path staging = parent.resolve("." + destination.getFileName()
                + ".staging-" + Long.toUnsignedString(System.nanoTime())).normalize();
        if (!staging.startsWith(parent)
                || Files.exists(staging, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("cache restore staging path is unsafe");
        }
        createDirectoryTree(staging, "cache restore staging");
        Path backup = null;
        boolean committed = false;
        try {
            copyTree(entry, staging, false, policy, tracker);
            Path event = staging.resolve("meta").resolve("cache-event.json");
            AtomicFiles.writeUtf8(event, "{\"schema_version\":1,\"event\":\"hit\","
                    + "\"cache_key\":\"" + cacheKey + "\"}\n");
            if (beforeCommit != null) {
                beforeCommit.beforeCommit();
            }
            verifyDirectoryChain(parentSnapshot);
            if (destinationExisted) {
                // Re-check the precondition immediately before the swap.  A concurrent writer
                // filling the previously-empty directory must not be replaced silently.
                try (var children = Files.list(destination)) {
                    if (children.findAny().isPresent()
                            || ArchiveLimits.isLinkOrReparsePoint(destination)) {
                        throw new IOException("cache output changed during restore");
                    }
                }
                verifyDirectoryChain(parentSnapshot);
                backup = parent.resolve("." + destination.getFileName()
                        + ".backup-" + Long.toUnsignedString(System.nanoTime())).normalize();
                if (!backup.startsWith(parent)
                        || Files.exists(backup, LinkOption.NOFOLLOW_LINKS)) {
                    throw new IOException("cache restore backup path is unsafe");
                }
                moveNoReplace(destination, backup);
            }
            verifyDirectoryChain(parentSnapshot);
            moveNoReplace(staging, destination);
            committed = true;
            if (backup != null) {
                deleteTree(backup);
                backup = null;
            }
            return true;
        } finally {
            if (!committed && backup != null
                    && !Files.exists(destination, LinkOption.NOFOLLOW_LINKS)) {
                try {
                    moveNoReplace(backup, destination);
                    backup = null;
                } catch (IOException ignored) {
                    // Preserve the original restore failure; the backup remains visible for
                    // operator recovery instead of being recursively deleted.
                }
            }
            if (backup != null && committed) {
                deleteQuietly(backup);
            }
            if (Files.exists(staging, LinkOption.NOFOLLOW_LINKS)) {
                deleteTree(staging);
            }
        }
    }

    /** Store a complete report. Existing valid entries are immutable and are never overwritten. */
    public static boolean store(Path cacheRoot, String cacheKey, Path output,
                                ScanStatistics statistics) throws IOException {
        return store(cacheRoot, cacheKey, output, statistics, InputBudget.defaults());
    }

    /** Store a complete report while charging the staged copy to one explicit budget. */
    public static boolean store(Path cacheRoot, String cacheKey, Path output,
                                ScanStatistics statistics, InputBudget budget) throws IOException {
        validateKey(cacheKey);
        if (!cacheable(statistics)) {
            return false;
        }
        InputBudget policy = budget == null ? InputBudget.defaults() : budget;
        InputBudget.Tracker tracker = policy.tracker();
        Path root = prepareRoot(cacheRoot);
        Path source = normalize(output);
        if (!Files.isDirectory(source, LinkOption.NOFOLLOW_LINKS)
                || ArchiveLimits.isLinkOrReparsePoint(source)) {
            throw new IOException("cache source is not a real directory: " + source);
        }
        DirectoryChainSnapshot sourceSnapshot = snapshotDirectoryChain(source);
        Path sourceIdentity = source.resolve("meta").resolve("scan-identity.json");
        if (!regular(sourceIdentity)
                || !readMetadata(sourceIdentity, MAX_IDENTITY_BYTES, policy, tracker)
                .contains("\"cache_key\":\"" + cacheKey + "\"")) {
            // Inputs may have changed between the preflight and the end of the scan. Do not
            // publish a report under a stale key; the next invocation will rebuild it.
            return false;
        }
        verifyDirectoryChain(sourceSnapshot);
        if (source.startsWith(root)) {
            throw new IOException("cache source must be outside cache root");
        }
        Path entry = root.resolve(cacheKey);
        if (validEntry(entry, cacheKey, policy, tracker)) {
            return false;
        }
        Path staging = root.resolve("." + cacheKey + ".staging-"
                + Long.toUnsignedString(System.nanoTime()));
        if (Files.exists(staging, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("cache staging path already exists");
        }
        try {
            createDirectoryTree(staging, "cache staging");
            copyTree(source, staging, true, policy, tracker);
            verifyDirectoryChain(sourceSnapshot);
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
        return statistics != null && statistics.runOutcome().cacheable();
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
        createDirectoryTree(root, "cache directory");
        if (ArchiveLimits.isLinkOrReparsePoint(root)
                || !Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("cache directory is not a real directory: " + root);
        }
        return root;
    }

    private static boolean validEntry(Path entry, String key, InputBudget policy,
                                      InputBudget.Tracker tracker) throws IOException {
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
        String content = readMetadata(sentinel, MAX_SENTINEL_BYTES, policy, tracker);
        return content.contains("\"cache_key\":\"" + key + "\"")
                && content.contains("\"completeness\":\"COMPLETE\"")
                && readMetadata(identity, MAX_IDENTITY_BYTES, policy, tracker)
                .contains("\"cache_key\":\"" + key + "\"");
    }

    /** Read small cache metadata with the caller's aggregate budget and a source snapshot. */
    private static String readMetadata(Path file, long maxBytes, InputBudget policy,
                                        InputBudget.Tracker tracker) throws IOException {
        if (!regular(file)) {
            throw new IOException("cache metadata is not a real file: " + file);
        }
        ArchiveLimits.FileReadSnapshot snapshot = ArchiveLimits.snapshotRegularFile(
                file, policy, "CACHE_METADATA");
        BasicFileAttributes before = snapshot.fileAttributes();
        long remaining = tracker.remainingReadBytes();
        long limit = Math.min(maxBytes, Math.min(policy.maxEntryBytes(), remaining));
        if (before.size() > maxBytes || before.size() > policy.maxEntryBytes()
                || before.size() > limit) {
            throw new IOException("CACHE_METADATA_INPUT_LIMIT:" + maxBytes);
        }
        byte[] bytes;
        try (IoUtil.OpenedInput opened = IoUtil.openRegularFile(file, "CACHE_METADATA");
             var input = opened.stream()) {
            bytes = IoUtil.readAll(input, limit, tracker);
        }
        ArchiveLimits.verifyRegularFileUnchanged(snapshot, "CACHE_METADATA");
        return new String(bytes, StandardCharsets.UTF_8);
    }

    private static boolean regular(Path path) {
        return Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)
                && !ArchiveLimits.isLinkOrReparsePoint(path);
    }

    private static void copyTree(Path source, Path destination, boolean skipCacheEvent,
                                 InputBudget policy, InputBudget.Tracker tracker)
            throws IOException {
        DirectoryChainSnapshot sourceSnapshot = snapshotDirectoryChain(source);
        DirectoryChainSnapshot destinationSnapshot = snapshotDirectoryChain(destination);
        List<Path> paths;
        List<Path> collected = new java.util.ArrayList<>();
        try (var walk = Files.walk(source)) {
            var iterator = walk.iterator();
            while (iterator.hasNext()) {
                tracker.checkTime();
                if (collected.size() >= policy.maxArchiveEntries()) {
                    throw new IOException("cache copy entry count exceeds limit: "
                            + policy.maxArchiveEntries());
                }
                collected.add(iterator.next());
            }
        }
        verifyDirectoryChain(sourceSnapshot);
        verifyDirectoryChain(destinationSnapshot);
        paths = collected.stream().sorted(Comparator.comparing(Path::toString)).toList();
        for (Path path : paths) {
            tracker.checkTime();
            if (ArchiveLimits.isLinkOrReparsePoint(path)) {
                throw new IOException("cache tree contains link or reparse point");
            }
            Path relative = source.relativize(path);
            if (relative.toString().isEmpty()) {
                continue;
            }
            String relativeName = relative.toString().replace('\\', '/');
            if (!ArchiveLimits.safeEntryName(relativeName, policy)) {
                throw new IOException("cache tree contains unsafe entry: " + relativeName);
            }
            if (skipCacheEvent && relative.toString().replace('\\', '/')
                    .equals("meta/cache-event.json")) {
                continue;
            }
            Path target = destination.resolve(relative).normalize();
            if (!target.startsWith(destination)) {
                throw new IOException("cache tree escapes destination");
            }
            if (Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) {
                tracker.observeFile(relativeName, 0L);
                createDirectoryTree(target, "cache destination directory");
                if (!Files.isDirectory(target, LinkOption.NOFOLLOW_LINKS)
                        || ArchiveLimits.isLinkOrReparsePoint(target)) {
                    throw new IOException("cache destination parent is not a real directory");
                }
            } else if (Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
                long size = Files.size(path);
                tracker.observeFile(relativeName, size);
                createDirectoryTree(target.getParent(), "cache destination parent");
                if (ArchiveLimits.isLinkOrReparsePoint(target.getParent())
                        || !Files.isDirectory(target.getParent(), LinkOption.NOFOLLOW_LINKS)) {
                    throw new IOException("cache destination parent is not a real directory");
                }
                DirectoryChainSnapshot sourceParentSnapshot = snapshotDirectoryChain(
                        path.getParent());
                DirectoryChainSnapshot targetParentSnapshot = snapshotDirectoryChain(
                        target.getParent());
                verifyDirectoryChain(sourceParentSnapshot);
                verifyDirectoryChain(targetParentSnapshot);
                copyFileBounded(path, target, policy, tracker, sourceParentSnapshot,
                        targetParentSnapshot);
                verifyDirectoryChain(sourceParentSnapshot);
                verifyDirectoryChain(targetParentSnapshot);
            } else {
                throw new IOException("cache tree contains unsupported entry");
            }
        }
        verifyDirectoryChain(sourceSnapshot);
        verifyDirectoryChain(destinationSnapshot);
    }

    private static void copyFileBounded(Path source, Path target, InputBudget policy,
                                        InputBudget.Tracker tracker,
                                        DirectoryChainSnapshot sourceParentSnapshot,
                                        DirectoryChainSnapshot targetParentSnapshot)
            throws IOException {
        if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) {
            if (ArchiveLimits.isLinkOrReparsePoint(target)
                    || !Files.isRegularFile(target, LinkOption.NOFOLLOW_LINKS)) {
                throw new IOException("cache destination file is not a real file");
            }
            throw new IOException("cache destination file already exists");
        }
        ArchiveLimits.FileReadSnapshot sourceSnapshot = ArchiveLimits.snapshotRegularFile(
                source, policy, "CACHE_SOURCE");
        BasicFileAttributes before = sourceSnapshot.fileAttributes();
        if (!before.isRegularFile() || ArchiveLimits.isLinkOrReparsePoint(source)) {
            throw new IOException("cache source file is not a real file");
        }
        verifyDirectoryChain(sourceParentSnapshot);
        verifyDirectoryChain(targetParentSnapshot);
        long limit = Math.min(policy.maxEntryBytes(), tracker.remainingReadBytes());
        try (IoUtil.OpenedInput opened = IoUtil.openRegularFile(source, "CACHE_SOURCE");
             var input = opened.stream();
             var output = Files.newOutputStream(target, StandardOpenOption.CREATE_NEW,
                     StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS)) {
            byte[] buffer = new byte[8192];
            long total = 0L;
            for (int read; ; ) {
                tracker.checkTime();
                read = tracker.readBounded(input, buffer, 0, buffer.length, limit - total,
                        "cache copy bytes exceed limit: " + limit);
                if (read < 0) {
                    break;
                }
                if (read == 0) {
                    int one = tracker.readByteBounded(input, limit - total,
                            "cache copy bytes exceed limit: " + limit);
                    if (one < 0) {
                        break;
                    }
                    buffer[0] = (byte) one;
                    output.write(buffer, 0, 1);
                    total++;
                    continue;
                }
                if (read > limit - total) {
                    throw new IOException("cache copy bytes exceed limit: " + limit);
                }
                output.write(buffer, 0, read);
                total += read;
            }
        }
        try {
            ArchiveLimits.verifyRegularFileUnchanged(sourceSnapshot, "CACHE_SOURCE");
        } catch (IOException changed) {
            throw new IOException("cache source changed during copy", changed);
        }
        if (!Files.isRegularFile(target, LinkOption.NOFOLLOW_LINKS)
                || ArchiveLimits.isLinkOrReparsePoint(target)) {
            throw new IOException("cache destination file changed during copy");
        }
        verifyDirectoryChain(sourceParentSnapshot);
        verifyDirectoryChain(targetParentSnapshot);
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

    private static void moveNoReplace(Path source, Path destination) throws IOException {
        try {
            Files.move(source, destination, StandardCopyOption.ATOMIC_MOVE);
        } catch (java.nio.file.AtomicMoveNotSupportedException unsupported) {
            Files.move(source, destination);
        }
    }

    private static void deleteQuietly(Path path) {
        try {
            deleteTree(path);
        } catch (IOException ignored) {
            // Cleanup is best effort after a successful commit; never turn a valid cache hit
            // into a false miss solely because a stale backup could not be removed.
        }
    }

    /** Capture every real directory component without following links/reparse points. */
    private static DirectoryChainSnapshot snapshotDirectoryChain(Path directory)
            throws IOException {
        if (directory == null) {
            throw new IOException("cache directory identity is missing");
        }
        Path normalized = directory.toAbsolutePath().normalize();
        Path root = normalized.getRoot();
        if (root == null) {
            throw new IOException("cache directory identity has no filesystem root");
        }
        List<DirectoryIdentity> components = new java.util.ArrayList<>();
        Path current = root;
        components.add(new DirectoryIdentity(current, readDirectoryIdentity(current)));
        for (Path component : normalized) {
            current = current.resolve(component);
            components.add(new DirectoryIdentity(current, readDirectoryIdentity(current)));
        }
        return new DirectoryChainSnapshot(components);
    }

    /** Verify a previously captured chain and fail closed on disappearance or replacement. */
    private static void verifyDirectoryChain(DirectoryChainSnapshot snapshot) throws IOException {
        if (snapshot == null || snapshot.components().isEmpty()) {
            throw new IOException("CACHE_DIRECTORY_CHANGED_DURING_COPY");
        }
        for (DirectoryIdentity expected : snapshot.components()) {
            try {
                BasicFileAttributes current = readDirectoryIdentity(expected.path());
                if (!sameDirectoryIdentity(expected.attributes(), current)) {
                    throw new IOException("CACHE_DIRECTORY_CHANGED_DURING_COPY: "
                            + expected.path());
                }
            } catch (IOException failure) {
                if (failure.getMessage() != null
                        && failure.getMessage().startsWith("CACHE_DIRECTORY_CHANGED_DURING_COPY")) {
                    throw failure;
                }
                throw new IOException("CACHE_DIRECTORY_CHANGED_DURING_COPY: "
                        + expected.path(), failure);
            }
        }
    }

    private static BasicFileAttributes readDirectoryIdentity(Path path) throws IOException {
        BasicFileAttributes attributes = Files.readAttributes(path, BasicFileAttributes.class,
                LinkOption.NOFOLLOW_LINKS);
        if (!attributes.isDirectory() || ArchiveLimits.isLinkOrReparsePoint(path)) {
            throw new IOException("cache directory is not a real directory: " + path);
        }
        return attributes;
    }

    private static boolean sameDirectoryIdentity(BasicFileAttributes expected,
                                                  BasicFileAttributes current) {
        return expected.isDirectory() == current.isDirectory()
                && expected.creationTime().equals(current.creationTime())
                && sameFileKey(expected, current);
    }

    private static boolean sameFileKey(BasicFileAttributes first,
                                       BasicFileAttributes second) {
        if (first.fileKey() != null || second.fileKey() != null) {
            return first.fileKey() != null && second.fileKey() != null
                    && first.fileKey().equals(second.fileKey());
        }
        return first.creationTime().toMillis() == 0L && second.creationTime().toMillis() == 0L
                || first.creationTime().equals(second.creationTime());
    }

    /** Package-local hostile contract seam; production cache paths use the private snapshot. */
    static DirectoryChainSnapshot snapshotDirectoryChainForContract(Path directory)
            throws IOException {
        return snapshotDirectoryChain(directory);
    }

    /** Package-local hostile contract seam; production cache paths use the private verifier. */
    static void verifyDirectoryChainForContract(DirectoryChainSnapshot snapshot)
            throws IOException {
        verifyDirectoryChain(snapshot);
    }

    /** Create a directory tree without following a link/reparse point at any component. */
    private static void createDirectoryTree(Path directory, String label) throws IOException {
        if (directory == null) {
            throw new IOException(label + " is missing");
        }
        Path normalized = directory.toAbsolutePath().normalize();
        Path current = normalized.getRoot();
        if (current == null) {
            throw new IOException(label + " has no filesystem root");
        }
        if (ArchiveLimits.isLinkOrReparsePoint(current)) {
            throw new IOException(label + " root is a link or reparse point");
        }
        for (Path component : normalized) {
            current = current.resolve(component);
            if (Files.exists(current, LinkOption.NOFOLLOW_LINKS)) {
                if (!Files.isDirectory(current, LinkOption.NOFOLLOW_LINKS)
                        || ArchiveLimits.isLinkOrReparsePoint(current)) {
                    throw new IOException(label + " is not a real directory: " + current);
                }
            } else {
                try {
                    Files.createDirectory(current);
                } catch (java.nio.file.FileAlreadyExistsException raced) {
                    if (!Files.isDirectory(current, LinkOption.NOFOLLOW_LINKS)
                            || ArchiveLimits.isLinkOrReparsePoint(current)) {
                        throw new IOException(label + " changed during creation: " + current,
                                raced);
                    }
                }
            }
            if (!Files.isDirectory(current, LinkOption.NOFOLLOW_LINKS)
                    || ArchiveLimits.isLinkOrReparsePoint(current)) {
                throw new IOException(label + " changed during creation: " + current);
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

    /**
     * JDK homes are trusted toolchain aliases, unlike artifact/rule inputs.  The frontend and
     * identity writer both resolve a managed symlink/junction to its concrete home before
     * opening release metadata or JRT files; cache preflight must use the same boundary or a
     * platform-specific alias fails before the actual scan can start.
     */
    private static void validateJdkHome(Path path) throws IOException {
        Path normalized = normalize(path);
        if (!Files.isDirectory(normalized)) {
            throw new IOException("cache JDK home is not a directory: " + normalized);
        }
        Path effective = normalized;
        if (ArchiveLimits.isLinkOrReparsePoint(normalized)) {
            try {
                Path linkTarget = Files.readSymbolicLink(normalized);
                effective = (linkTarget.isAbsolute()
                        ? linkTarget : normalized.getParent().resolve(linkTarget))
                        .toAbsolutePath().normalize();
                if (!Files.isDirectory(effective)
                        || ArchiveLimits.isLinkOrReparsePoint(effective)) {
                    throw new IOException("cache JDK home target is not a safe directory: "
                            + effective);
                }
            } catch (IOException | RuntimeException failure) {
                try {
                    effective = normalized.toRealPath();
                } catch (IOException | RuntimeException realPathFailure) {
                    realPathFailure.addSuppressed(failure);
                    throw new IOException("cache JDK home alias cannot be resolved: " + normalized,
                            realPathFailure);
                }
            }
        }
        if (!Files.isDirectory(effective)
                || ArchiveLimits.isLinkOrReparsePoint(effective)) {
            throw new IOException("cache JDK home is not a safe directory: " + effective);
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
