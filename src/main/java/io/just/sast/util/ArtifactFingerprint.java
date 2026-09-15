package io.just.sast.util;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Comparator;
import java.util.List;
import io.just.sast.run.InputBudget;

/**
 * Deterministic identity for a scan artifact.
 *
 * <p>Files are hashed as-is.  Directory inputs are hashed as a sorted sequence of
 * normalized relative names, a zero separator, and file bytes.  Keeping this in one
 * utility makes report identity, cache identity and input provenance use exactly the same
 * contract.</p>
 */
public final class ArtifactFingerprint {

    private static final int BUFFER_SIZE = 64 * 1024;

    /** Snapshot captured during the bounded directory walk and checked before hashing. */
    record PathSnapshot(Path path, BasicFileAttributes attributes, boolean directory) {
    }

    /** Package-local directory snapshot used by the hostile replacement contract. */
    record DirectorySnapshot(List<PathSnapshot> components) {
        DirectorySnapshot {
            components = List.copyOf(components);
        }
    }

    private ArtifactFingerprint() {
    }

    public static String sha256(Path input) throws IOException {
        return sha256(input, InputBudget.defaults());
    }

    /** Hash an artifact under an explicit, versioned input policy. */
    public static String sha256(Path input, InputBudget budget) throws IOException {
        InputBudget policy = budget == null ? InputBudget.defaults() : budget;
        return sha256(input, policy.tracker());
    }

    /**
     * Hash an artifact while charging bytes to a caller-owned tracker.  This is used by
     * inventory/cache preflights so a target plus all dependencies cannot each reset the
     * aggregate input budget.
     */
    public static String sha256(Path input, InputBudget.Tracker tracker) throws IOException {
        if (input == null) {
            throw new IOException("artifact-not-readable");
        }
        InputBudget.Tracker accounting = tracker == null ? InputBudget.defaults().tracker() : tracker;
        InputBudget policy = accounting.budget();
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException impossible) {
            throw new IOException("sha256-unavailable", impossible);
        }
        ArchiveLimits.checkPathAncestors(input, policy);
        if (ArchiveLimits.isLinkOrReparsePoint(input)) {
            throw new IOException("artifact-link-or-reparse-point");
        }
        if (Files.isRegularFile(input, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
            ArchiveLimits.checkContainerSize(input, policy);
            updateDigest(digest, input, accounting, true, policy.maxPhysicalBytes(), null);
        } else if (Files.isDirectory(input, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
            List<PathSnapshot> files;
            List<PathSnapshot> directories;
            Path root = input.toAbsolutePath().normalize();
            files = new java.util.ArrayList<>();
            directories = new java.util.ArrayList<>();
            PathSnapshot rootSnapshot = snapshot(root, true);
            directories.add(rootSnapshot);
            try (var walk = Files.walk(root)) {
                var iterator = walk.iterator();
                while (iterator.hasNext()) {
                    accounting.checkTime();
                    Path file = iterator.next();
                    if (ArchiveLimits.isLinkOrReparsePoint(file)) {
                        throw new IOException("filesystem tree contains link or reparse point: "
                                + root.relativize(file));
                    }
                    if (root.equals(file)) {
                        continue;
                    }
                    Path normalized = file.toAbsolutePath().normalize();
                    if (!normalized.startsWith(root)) {
                        throw new IOException("filesystem path escapes input root");
                    }
                    String relative = relativeName(root, normalized);
                    if (!ArchiveLimits.safeEntryName(relative, policy)
                            || normalized.getNameCount() - root.getNameCount() > policy.maxPathDepth()) {
                        throw new IOException("unsafe filesystem entry: " + relative);
                    }
                    BasicFileAttributes attributes = readSnapshotAttributes(normalized);
                    if (attributes.isDirectory()) {
                        accounting.observeFile(relative, 0L);
                        directories.add(new PathSnapshot(normalized, attributes, true));
                        continue;
                    }
                    if (attributes.isRegularFile()) {
                        accounting.observeFile(relative, attributes.size());
                        files.add(new PathSnapshot(normalized, attributes, false));
                        continue;
                    }
                    // Never open special files, but count them against the bounded walk so a
                    // tree full of sockets/devices cannot evade the entry cap.
                    accounting.observeFile(relative, 0L);
                    if (relative.codePointCount(0, relative.length()) > policy.maxPathChars()) {
                        throw new IOException("filesystem path depth exceeds limit: "
                                + policy.maxPathDepth());
                    }
                }
            }
            assertUnchanged(rootSnapshot);
            for (PathSnapshot directory : directories) {
                assertUnchanged(directory);
            }
            files.sort(Comparator.comparing(snapshot -> relativeName(root, snapshot.path())));
            for (PathSnapshot file : files) {
                Path normalized = file.path();
                String relative = relativeName(root, normalized);
                digest.update(relative.getBytes(StandardCharsets.UTF_8));
                digest.update((byte) 0);
                updateDigest(digest, normalized, accounting, false, policy.maxEntryBytes(),
                        file.attributes());
            }
            assertUnchanged(rootSnapshot);
            for (PathSnapshot directory : directories) {
                assertUnchanged(directory);
            }
        } else {
            throw new IOException("artifact-not-readable");
        }
        return hex(digest.digest());
    }

    private static String relativeName(Path root, Path file) {
        return root.relativize(file).toString().replace('\\', '/');
    }

    private static PathSnapshot snapshot(Path path, boolean directory) throws IOException {
        BasicFileAttributes attributes = readSnapshotAttributes(path);
        if (directory != attributes.isDirectory()) {
            throw new IOException("artifact-directory-identity-invalid");
        }
        return new PathSnapshot(path, attributes, directory);
    }

    private static DirectorySnapshot snapshotDirectory(Path root) throws IOException {
        if (root == null) {
            throw new IOException("artifact-directory-identity-invalid");
        }
        Path normalizedRoot = root.toAbsolutePath().normalize();
        if (!Files.isDirectory(normalizedRoot, java.nio.file.LinkOption.NOFOLLOW_LINKS)
                || ArchiveLimits.isLinkOrReparsePoint(normalizedRoot)) {
            throw new IOException("artifact-directory-identity-invalid");
        }
        List<PathSnapshot> components = new java.util.ArrayList<>();
        try (var walk = Files.walk(normalizedRoot)) {
            var iterator = walk.iterator();
            while (iterator.hasNext()) {
                Path path = iterator.next().toAbsolutePath().normalize();
                if (!path.startsWith(normalizedRoot)) {
                    throw new IOException("filesystem path escapes input root");
                }
                BasicFileAttributes attributes = readSnapshotAttributes(path);
                components.add(new PathSnapshot(path, attributes, attributes.isDirectory()));
            }
        }
        components.sort(Comparator.comparing(PathSnapshot::path));
        return new DirectorySnapshot(components);
    }

    private static void verifyDirectorySnapshot(DirectorySnapshot snapshot) throws IOException {
        if (snapshot == null || snapshot.components().isEmpty()) {
            throw new IOException("artifact-directory-changed-during-hash");
        }
        for (PathSnapshot component : snapshot.components()) {
            assertUnchanged(component);
        }
    }

    private static BasicFileAttributes readSnapshotAttributes(Path path) throws IOException {
        BasicFileAttributes attributes = Files.readAttributes(path, BasicFileAttributes.class,
                java.nio.file.LinkOption.NOFOLLOW_LINKS);
        if (ArchiveLimits.isLinkOrReparsePoint(path)) {
            throw new IOException("artifact-file-became-link");
        }
        return attributes;
    }

    private static void assertUnchanged(PathSnapshot snapshot) throws IOException {
        BasicFileAttributes current = readSnapshotAttributes(snapshot.path());
        BasicFileAttributes expected = snapshot.attributes();
        boolean sameKey = sameFileKey(expected, current);
        if (snapshot.directory() != current.isDirectory()
                || !sameKey
                || (!snapshot.directory() && expected.size() != current.size())
                || (!snapshot.directory()
                && !expected.lastModifiedTime().equals(current.lastModifiedTime()))) {
            throw new IOException("artifact-directory-changed-during-hash");
        }
    }

    private static void updateDigest(MessageDigest digest, Path file,
                                     InputBudget.Tracker tracker, boolean container,
                                     long limit, BasicFileAttributes expected) throws IOException {
        BasicFileAttributes before = Files.readAttributes(file, BasicFileAttributes.class,
                java.nio.file.LinkOption.NOFOLLOW_LINKS);
        if (!before.isRegularFile() || ArchiveLimits.isLinkOrReparsePoint(file)) {
            throw new IOException("artifact-file-became-link");
        }
        if (expected != null && !sameIdentity(expected, before)) {
            throw new IOException("artifact-file-changed-before-hash");
        }
        try (InputStream input = IoUtil.openNoFollow(file, "ARTIFACT")) {
            byte[] buffer = new byte[BUFFER_SIZE];
            long total = 0L;
            int emptyReads = 0;
            for (int read; ; ) {
                tracker.checkTime();
                read = container
                        ? tracker.readContainerBounded(input, buffer, 0, buffer.length,
                        limit - total, "artifact bytes exceed limit: " + limit)
                        : tracker.readBounded(input, buffer, 0, buffer.length, limit - total,
                        "artifact bytes exceed limit: " + limit);
                if (read < 0) {
                    break;
                }
                if (read == 0) {
                    if (++emptyReads > 1024) {
                        throw new IOException("artifact stream made no progress");
                    }
                    int one = container
                            ? tracker.readContainerByteBounded(input, limit - total,
                            "artifact bytes exceed limit: " + limit)
                            : tracker.readByteBounded(input, limit - total,
                            "artifact bytes exceed limit: " + limit);
                    if (one < 0) {
                        break;
                    }
                    buffer[0] = (byte) one;
                    digest.update(buffer, 0, 1);
                    total++;
                    continue;
                }
                emptyReads = 0;
                if (read > limit - total) {
                    throw new IOException("artifact bytes exceed limit: " + limit);
                }
                digest.update(buffer, 0, read);
                total += read;
            }
            if (total == 0L && Files.size(file) > 0L) {
                throw new IOException("artifact stream made no progress");
            }
        }
        BasicFileAttributes after = Files.readAttributes(file, BasicFileAttributes.class,
                java.nio.file.LinkOption.NOFOLLOW_LINKS);
        if (!after.isRegularFile() || ArchiveLimits.isLinkOrReparsePoint(file)
                || !sameIdentity(before, after)) {
            throw new IOException("artifact-changed-during-hash");
        }
    }

    private static boolean sameIdentity(BasicFileAttributes first,
                                        BasicFileAttributes second) {
        return first.isRegularFile() == second.isRegularFile()
                && first.isDirectory() == second.isDirectory()
                && first.size() == second.size()
                && first.lastModifiedTime().equals(second.lastModifiedTime())
                && sameFileKey(first, second);
    }

    private static boolean sameFileKey(BasicFileAttributes first,
                                       BasicFileAttributes second) {
        if (first.fileKey() != null || second.fileKey() != null) {
            return first.fileKey() != null && second.fileKey() != null
                    && first.fileKey().equals(second.fileKey());
        }
        // Windows providers may not expose fileKey for directories. Creation time is the
        // remaining stable identity signal for replacement of an otherwise same-shaped tree;
        // treat a non-zero value as authoritative while retaining compatibility with providers
        // that report the epoch sentinel for both snapshots.
        var firstCreated = first.creationTime();
        var secondCreated = second.creationTime();
        return firstCreated.toMillis() == 0L && secondCreated.toMillis() == 0L
                || firstCreated.equals(secondCreated);
    }

    private static String hex(byte[] bytes) {
        StringBuilder result = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) {
            result.append(String.format(java.util.Locale.ROOT, "%02x", value & 0xff));
        }
        return result.toString();
    }

    /** Package-local hostile contract seam; production hashing uses the same identity checks. */
    static DirectorySnapshot snapshotDirectoryForContract(Path root) throws IOException {
        return snapshotDirectory(root);
    }

    /** Package-local hostile contract seam; production hashing uses the same identity checks. */
    static void verifyDirectoryForContract(DirectorySnapshot snapshot) throws IOException {
        verifyDirectorySnapshot(snapshot);
    }
}
