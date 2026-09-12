package io.just.sast.verify;

import io.just.sast.run.InputBudget;
import io.just.sast.util.ArchiveLimits;

import java.io.IOException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Comparator;
import java.util.UUID;

/**
 * Bounded owner for verifier scratch directories.
 *
 * <p>A Job Object constrains process resources, not the filesystem.  This helper therefore
 * keeps the parent/child directory creation no-follow, measures child output with the same
 * versioned {@link InputBudget}, and refuses to walk links, special files, excessive depth or
 * unbounded entry/byte counts.  It is deliberately small: it does not claim a provider
 * independent no-race filesystem sandbox; the remaining provider race is surfaced by callers.
 */
final class VerificationScratch {

    private static final String ROOT_PREFIX = "just-verify-";
    /** A private generation marker makes replacement of a scratch root observable even when
     * a Windows provider reports the same coarse creation/file-key metadata for a fast
     * delete-and-recreate operation.  Job Objects do not protect the filesystem, so this is
     * only an integrity signal, not a sandbox boundary. */
    private static final String ROOT_MARKER = ".just-root-generation";
    private static final int MAX_DELETE_ENTRIES = 250_000;

    private VerificationScratch() {
    }

    record TreeUsage(long entries, long bytes, boolean limitExceeded) {
        TreeUsage {
            entries = Math.max(0L, entries);
            bytes = Math.max(0L, bytes);
        }
    }

    /** One NOFOLLOW entry identity retained across the bounded scratch observation. */
    record EntrySnapshot(Path path, BasicFileAttributes attributes) {
        EntrySnapshot {
            path = path == null ? null : path.toAbsolutePath().normalize();
            if (attributes == null) {
                throw new IllegalArgumentException("scratch entry attributes are required");
            }
        }
    }

    /** Create a per-attempt root below a validated system temporary directory. */
    static Path createRoot(InputBudget budget) throws IOException {
        InputBudget policy = budget == null ? InputBudget.defaults() : budget;
        Path configured;
        try {
            configured = Path.of(System.getProperty("java.io.tmpdir", "."));
        } catch (RuntimeException invalid) {
            throw new IOException("VERIFY_SCRATCH_PARENT_INVALID", invalid);
        }
        Path parent = configured.toAbsolutePath().normalize();
        ensureDirectory(parent, policy, "VERIFY_SCRATCH_PARENT");
        BasicFileAttributes before = attributes(parent);
        Path created = Files.createTempDirectory(parent, ROOT_PREFIX);
        boolean valid = false;
        try {
            Path normalized = created.toAbsolutePath().normalize();
            if (!normalized.startsWith(parent) || !Files.isDirectory(normalized,
                    LinkOption.NOFOLLOW_LINKS) || ArchiveLimits.isLinkOrReparsePoint(normalized)
                    || normalized.getNameCount() - parent.getNameCount() > 1) {
                throw new IOException("VERIFY_SCRATCH_ROOT_INVALID");
            }
            createRootMarker(normalized);
            BasicFileAttributes after = attributes(parent);
            if (!sameDirectory(before, after)) {
                throw new IOException("VERIFY_SCRATCH_PARENT_CHANGED");
            }
            valid = true;
            return normalized;
        } finally {
            if (!valid) {
                deleteTree(created);
            }
        }
    }

    /** Create one named child directory without following an existing link/reparse point. */
    static Path createChild(Path parent, String name, InputBudget budget) throws IOException {
        InputBudget policy = budget == null ? InputBudget.defaults() : budget;
        if (parent == null || name == null || name.isBlank()
                || name.equals(".") || name.equals("..")
                || name.indexOf('/') >= 0 || name.indexOf('\\') >= 0
                || name.codePointCount(0, name.length()) > policy.maxPathChars()) {
            throw new IOException("VERIFY_SCRATCH_CHILD_NAME_INVALID");
        }
        Path normalizedParent = parent.toAbsolutePath().normalize();
        ensureDirectory(normalizedParent, policy, "VERIFY_SCRATCH_PARENT");
        Path child = normalizedParent.resolve(name).normalize();
        if (!child.startsWith(normalizedParent)
                || child.getNameCount() - normalizedParent.getNameCount() > 1) {
            throw new IOException("VERIFY_SCRATCH_CHILD_ESCAPE");
        }
        if (Files.exists(child, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("VERIFY_SCRATCH_CHILD_EXISTS");
        }
        try {
            Files.createDirectory(child);
        } catch (FileAlreadyExistsException raced) {
            throw new IOException("VERIFY_SCRATCH_CHILD_EXISTS", raced);
        }
        if (!Files.isDirectory(child, LinkOption.NOFOLLOW_LINKS)
                || ArchiveLimits.isLinkOrReparsePoint(child)) {
            throw new IOException("VERIFY_SCRATCH_CHILD_INVALID");
        }
        return child;
    }

    static TreeUsage measure(Path root, InputBudget budget) throws IOException {
        InputBudget policy = budget == null ? InputBudget.defaults() : budget;
        return measure(root, policy, policy.tracker());
    }

    /** Measure a tree with a caller-owned tracker; no path is followed during the walk. */
    static TreeUsage measure(Path root, InputBudget policy, InputBudget.Tracker tracker)
            throws IOException {
        InputBudget effective = policy == null ? InputBudget.defaults() : policy;
        InputBudget.Tracker accounting = tracker == null ? effective.tracker() : tracker;
        if (root == null) {
            throw new IOException("VERIFY_SCRATCH_ROOT_MISSING");
        }
        Path normalized = root.toAbsolutePath().normalize();
        ArchiveLimits.DirectoryReadSnapshot rootSnapshot = ArchiveLimits.snapshotDirectory(
                normalized, effective, "VERIFY_SCRATCH_ROOT");
        RootMarkerSnapshot markerSnapshot = snapshotRootMarker(normalized);
        long entries = 0L;
        long bytes = 0L;
        try (var walk = Files.walk(normalized)) {
            var iterator = walk.iterator();
            while (iterator.hasNext()) {
                accounting.checkTime();
                Path item = iterator.next();
                if (!item.toAbsolutePath().normalize().startsWith(normalized)) {
                    throw new IOException("VERIFY_SCRATCH_PATH_ESCAPE");
                }
                if (++entries > effective.maxArchiveEntries()) {
                    throw new IOException("VERIFY_SCRATCH_ENTRY_LIMIT:" +
                            effective.maxArchiveEntries());
                }
                Path relative = normalized.relativize(item);
                if (relative.getNameCount() > effective.maxPathDepth()) {
                    throw new IOException("VERIFY_SCRATCH_PATH_DEPTH_LIMIT:" +
                            effective.maxPathDepth());
                }
                if (ArchiveLimits.isLinkOrReparsePoint(item)) {
                    throw new IOException("VERIFY_SCRATCH_LINK_OR_REPARSE");
                }
                EntrySnapshot entrySnapshot = snapshotEntry(item);
                BasicFileAttributes attrs = entrySnapshot.attributes();
                if (attrs.isDirectory()) {
                    // The root is already accounted by the caller's scratch operation. Child
                    // directories must still consume the aggregate filesystem-entry budget;
                    // otherwise a directory-only tree can bypass the shared cap while files
                    // use observeFile() below.
                    try {
                        accounting.observeFilesystemEntry();
                    } catch (IOException failure) {
                        throw scratchBudgetFailure(failure, effective);
                    }
                    verifyEntryUnchanged(entrySnapshot);
                    continue;
                }
                if (!attrs.isRegularFile()) {
                    throw new IOException("VERIFY_SCRATCH_SPECIAL_FILE");
                }
                try {
                    accounting.observeFile(relative.toString(), attrs.size());
                } catch (IOException failure) {
                    throw scratchBudgetFailure(failure, effective);
                }
                if (attrs.size() > effective.maxEntryBytes()
                        || bytes > effective.maxUncompressedBytes() - attrs.size()) {
                    throw new IOException("VERIFY_SCRATCH_BYTE_LIMIT:" +
                            effective.maxUncompressedBytes());
                }
                bytes += attrs.size();
                verifyEntryUnchanged(entrySnapshot);
            }
        }
        ArchiveLimits.verifyDirectoryUnchanged(rootSnapshot, "VERIFY_SCRATCH_ROOT");
        verifyRootMarker(markerSnapshot);
        return new TreeUsage(entries, bytes, false);
    }

    /** Best-effort no-follow cleanup. Returns false when a bound or filesystem check fails. */
    static boolean deleteTree(Path root) {
        if (root == null) {
            return true;
        }
        Path normalized;
        try {
            normalized = root.toAbsolutePath().normalize();
            if (!Files.exists(normalized, LinkOption.NOFOLLOW_LINKS)) {
                return true;
            }
            if (ArchiveLimits.isLinkOrReparsePoint(normalized)) {
                return Files.deleteIfExists(normalized);
            }
            java.util.List<Path> paths = new java.util.ArrayList<>();
            try (var walk = Files.walk(normalized)) {
                var iterator = walk.iterator();
                while (iterator.hasNext()) {
                    if (paths.size() >= MAX_DELETE_ENTRIES) {
                        return false;
                    }
                    Path item = iterator.next().toAbsolutePath().normalize();
                    if (!item.startsWith(normalized)) {
                        return false;
                    }
                    paths.add(item);
                }
            }
            paths.sort(Comparator.reverseOrder());
            for (Path item : paths) {
                if (ArchiveLimits.isLinkOrReparsePoint(item)
                        || Files.isRegularFile(item, LinkOption.NOFOLLOW_LINKS)
                        || Files.isDirectory(item, LinkOption.NOFOLLOW_LINKS)) {
                    Files.deleteIfExists(item);
                } else {
                    return false;
                }
            }
            return !Files.exists(normalized, LinkOption.NOFOLLOW_LINKS);
        } catch (IOException | RuntimeException failure) {
            return false;
        }
    }

    private static void ensureDirectory(Path directory, InputBudget policy, String label)
            throws IOException {
        Path normalized = directory.toAbsolutePath().normalize();
        Path current = normalized.getRoot();
        if (current == null || ArchiveLimits.isLinkOrReparsePoint(current)) {
            throw new IOException(label + "_ROOT_INVALID");
        }
        for (Path component : normalized) {
            current = current.resolve(component);
            if (Files.exists(current, LinkOption.NOFOLLOW_LINKS)) {
                if (ArchiveLimits.isLinkOrReparsePoint(current)
                        || !Files.isDirectory(current, LinkOption.NOFOLLOW_LINKS)) {
                    throw new IOException(label + "_COMPONENT_INVALID");
                }
            } else {
                try {
                    Files.createDirectory(current);
                } catch (FileAlreadyExistsException raced) {
                    if (ArchiveLimits.isLinkOrReparsePoint(current)
                            || !Files.isDirectory(current, LinkOption.NOFOLLOW_LINKS)) {
                        throw new IOException(label + "_COMPONENT_RACE", raced);
                    }
                }
            }
            if (ArchiveLimits.isLinkOrReparsePoint(current)
                    || !Files.isDirectory(current, LinkOption.NOFOLLOW_LINKS)) {
                throw new IOException(label + "_COMPONENT_CHANGED");
            }
        }
        if (normalized.getNameCount() > policy.maxPathDepth()) {
            throw new IOException(label + "_PATH_DEPTH_LIMIT");
        }
    }

    private static BasicFileAttributes attributes(Path path) throws IOException {
        return Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
    }

    private static EntrySnapshot snapshotEntry(Path path) throws IOException {
        if (path == null) {
            throw new IOException("VERIFY_SCRATCH_ENTRY_MISSING");
        }
        Path normalized = path.toAbsolutePath().normalize();
        if (ArchiveLimits.isLinkOrReparsePoint(normalized)) {
            throw new IOException("VERIFY_SCRATCH_LINK_OR_REPARSE");
        }
        BasicFileAttributes entry = attributes(normalized);
        if (!entry.isDirectory() && !entry.isRegularFile()) {
            throw new IOException("VERIFY_SCRATCH_SPECIAL_FILE");
        }
        return new EntrySnapshot(normalized, entry);
    }

    private static void verifyEntryUnchanged(EntrySnapshot snapshot) throws IOException {
        if (snapshot == null || snapshot.path() == null) {
            throw new IOException("VERIFY_SCRATCH_ENTRY_CHANGED_DURING_READ");
        }
        try {
            Path path = snapshot.path();
            if (ArchiveLimits.isLinkOrReparsePoint(path)) {
                throw new IOException("VERIFY_SCRATCH_ENTRY_CHANGED_DURING_READ");
            }
            BasicFileAttributes current = attributes(path);
            if (!sameEntryIdentity(snapshot.attributes(), current)) {
                throw new IOException("VERIFY_SCRATCH_ENTRY_CHANGED_DURING_READ");
            }
        } catch (IOException failure) {
            if (failure.getMessage() != null
                    && failure.getMessage().startsWith("VERIFY_SCRATCH_ENTRY_CHANGED_DURING_READ")) {
                throw failure;
            }
            throw new IOException("VERIFY_SCRATCH_ENTRY_CHANGED_DURING_READ", failure);
        }
    }

    private static boolean sameEntryIdentity(BasicFileAttributes before,
                                              BasicFileAttributes after) {
        if (before == null || after == null
                || before.isDirectory() != after.isDirectory()
                || before.isRegularFile() != after.isRegularFile()
                || !before.creationTime().equals(after.creationTime())
                || !sameFileKey(before, after)) {
            return false;
        }
        if (before.isRegularFile()) {
            return before.size() == after.size()
                    && before.lastModifiedTime().equals(after.lastModifiedTime());
        }
        // Directory mtimes change whenever a child is created or removed.  They are content
        // signals, not identities, and therefore are intentionally excluded here.
        return true;
    }

    private static IOException scratchBudgetFailure(IOException failure, InputBudget policy) {
        String message = failure.getMessage() == null ? "" : failure.getMessage();
        if (message.contains("entry count")) {
            return new IOException("VERIFY_SCRATCH_ENTRY_LIMIT:" + policy.maxArchiveEntries(),
                    failure);
        }
        if (message.contains("uncompressed") || message.contains("filesystem entry")) {
            return new IOException("VERIFY_SCRATCH_BYTE_LIMIT:" + policy.maxUncompressedBytes(),
                    failure);
        }
        return failure;
    }

    private static boolean sameDirectory(BasicFileAttributes before, BasicFileAttributes after) {
        return before != null && after != null && before.isDirectory() && after.isDirectory()
                && before.creationTime().equals(after.creationTime())
                && sameFileKey(before, after);
    }

    private static boolean sameFileKey(BasicFileAttributes before,
                                       BasicFileAttributes after) {
        if (before.fileKey() != null || after.fileKey() != null) {
            return before.fileKey() != null && after.fileKey() != null
                    && before.fileKey().equals(after.fileKey());
        }
        return before.creationTime().equals(after.creationTime());
    }

    /** Package-local hostile contract seam; production measurement uses the same root guard. */
    static ArchiveLimits.DirectoryReadSnapshot snapshotRootForContract(Path root)
            throws IOException {
        Path normalized = root == null ? null : root.toAbsolutePath().normalize();
        // The contract seam uses the same generation marker as production scratch roots.  The
        // test removes the root through deleteTree so the marker is removed with it before the
        // replacement is created.
        createRootMarker(normalized);
        return ArchiveLimits.snapshotDirectory(normalized, InputBudget.defaults(),
                "VERIFY_SCRATCH_ROOT");
    }

    /** Package-local hostile contract seam; production measurement uses the same root guard. */
    static void verifyRootSnapshotForContract(ArchiveLimits.DirectoryReadSnapshot snapshot)
            throws IOException {
        ArchiveLimits.verifyDirectoryUnchanged(snapshot, "VERIFY_SCRATCH_ROOT");
        verifyRootMarker(snapshot == null ? null : snapshot.directory());
    }

    /** Package-local hostile contract seam; production measurement uses the same entry guard. */
    static EntrySnapshot snapshotEntryForContract(Path path) throws IOException {
        return snapshotEntry(path);
    }

    /** Package-local hostile contract seam; production measurement uses the same entry guard. */
    static void verifyEntryForContract(EntrySnapshot snapshot) throws IOException {
        verifyEntryUnchanged(snapshot);
    }

    private record RootMarkerSnapshot(Path path, String token) {
    }

    private static void createRootMarker(Path root) throws IOException {
        if (root == null || !Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS)
                || ArchiveLimits.isLinkOrReparsePoint(root)) {
            throw new IOException("VERIFY_SCRATCH_ROOT_INVALID");
        }
        Path marker = root.resolve(ROOT_MARKER).normalize();
        if (!marker.startsWith(root) || marker.getNameCount() - root.getNameCount() != 1) {
            throw new IOException("VERIFY_SCRATCH_ROOT_MARKER_INVALID");
        }
        if (Files.exists(marker, LinkOption.NOFOLLOW_LINKS)) {
            if (!Files.isRegularFile(marker, LinkOption.NOFOLLOW_LINKS)
                    || ArchiveLimits.isLinkOrReparsePoint(marker)) {
                throw new IOException("VERIFY_SCRATCH_ROOT_MARKER_INVALID");
            }
            return;
        }
        try {
            Files.writeString(marker, UUID.randomUUID().toString(),
                    java.nio.charset.StandardCharsets.US_ASCII,
                    java.nio.file.StandardOpenOption.CREATE_NEW,
                    java.nio.file.StandardOpenOption.WRITE);
        } catch (FileAlreadyExistsException raced) {
            throw new IOException("VERIFY_SCRATCH_ROOT_MARKER_CHANGED", raced);
        }
    }

    private static RootMarkerSnapshot snapshotRootMarker(Path root) throws IOException {
        Path normalized = root == null ? null : root.toAbsolutePath().normalize();
        if (normalized == null) {
            throw new IOException("VERIFY_SCRATCH_ROOT_MARKER_MISSING");
        }
        Path marker = normalized.resolve(ROOT_MARKER).normalize();
        if (!marker.startsWith(normalized) || !Files.isRegularFile(marker,
                LinkOption.NOFOLLOW_LINKS) || ArchiveLimits.isLinkOrReparsePoint(marker)) {
            return null;
        }
        return new RootMarkerSnapshot(marker, Files.readString(marker,
                java.nio.charset.StandardCharsets.US_ASCII));
    }

    private static void verifyRootMarker(RootMarkerSnapshot snapshot) throws IOException {
        if (snapshot == null) {
            return;
        }
        try {
            Path path = snapshot.path();
            if (path == null || ArchiveLimits.isLinkOrReparsePoint(path)
                    || !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
                throw new IOException("VERIFY_SCRATCH_ROOT_CHANGED_DURING_READ");
            }
            String current = Files.readString(path, java.nio.charset.StandardCharsets.US_ASCII);
            if (!snapshot.token().equals(current)) {
                throw new IOException("VERIFY_SCRATCH_ROOT_CHANGED_DURING_READ");
            }
        } catch (IOException failure) {
            if (failure.getMessage() != null
                    && failure.getMessage().startsWith("VERIFY_SCRATCH_ROOT_CHANGED_DURING_READ")) {
                throw failure;
            }
            throw new IOException("VERIFY_SCRATCH_ROOT_CHANGED_DURING_READ", failure);
        }
    }

    private static void verifyRootMarker(Path root) throws IOException {
        RootMarkerSnapshot snapshot = snapshotRootMarker(root);
        if (snapshot == null) {
            throw new IOException("VERIFY_SCRATCH_ROOT_CHANGED_DURING_READ");
        }
        verifyRootMarker(snapshot);
    }
}
