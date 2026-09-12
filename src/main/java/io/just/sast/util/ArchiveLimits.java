package io.just.sast.util;

import io.just.sast.run.InputBudget;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipException;

/**
 * Shared archive limits for the static frontend and the dynamic classpath expander.
 * Values are deliberately conservative but large enough for ordinary fat JAR/WAR inputs.
 */
public final class ArchiveLimits {

    /** Compatibility aliases; the versioned policy owner is {@link InputBudget}. */
    public static final int MAX_ENTRIES = InputBudget.defaults().maxArchiveEntries();
    public static final long MAX_ENTRY_UNCOMPRESSED_BYTES = InputBudget.defaults().maxEntryBytes();
    public static final long MAX_TOTAL_UNCOMPRESSED_BYTES = InputBudget.defaults().maxUncompressedBytes();
    public static final long MAX_TOTAL_COMPRESSED_BYTES = InputBudget.defaults().maxCompressedBytes();
    public static final long MAX_COMPRESSION_RATIO = InputBudget.defaults().maxCompressionRatio();
    public static final int MAX_NESTING = InputBudget.defaults().maxArchiveNesting();

    private ArchiveLimits() {
    }

    /**
     * Strength of the identity a provider exposes for a bounded observation.  This is a
     * disclosure axis, not a claim that a path read is an atomic filesystem transaction.
     */
    public enum IdentityStrength {
        /** The provider is immutable (currently the JDK jrt image). */
        IMMUTABLE_PROVIDER,
        /** A stable provider file key is available in addition to size/timestamps. */
        FILE_KEY_METADATA,
        /** Only metadata is available; equal metadata does not prove equal content. */
        METADATA_ONLY
    }

    /**
     * Immutable identity captured before a bounded regular-file read.  The parent directory
     * identities are retained as well as the file identity: NOFOLLOW on the final component
     * does not stop a provider from redirecting an ancestor between preflight and open.
     */
    public record FileReadSnapshot(Path file, BasicFileAttributes fileAttributes,
                                   List<PathIdentity> ancestors) {
        public FileReadSnapshot {
            file = file == null ? null : file.toAbsolutePath().normalize();
            ancestors = ancestors == null ? List.of() : List.copyOf(ancestors);
        }

        /** Disclose the strongest identity signal available for this file provider. */
        public IdentityStrength identityStrength() {
            return ArchiveLimits.identityStrength(file, fileAttributes);
        }
    }

    /** One NOFOLLOW directory identity in a file-read path chain. */
    public record PathIdentity(Path path, BasicFileAttributes attributes) {
        public PathIdentity {
            path = path == null ? null : path.toAbsolutePath().normalize();
            if (attributes == null) {
                throw new IllegalArgumentException("path identity attributes are required");
            }
        }
    }

    /** Immutable identity for a bounded directory observation, including its parent chain. */
    public record DirectoryReadSnapshot(Path directory, BasicFileAttributes directoryAttributes,
                                        List<PathIdentity> ancestors) {
        public DirectoryReadSnapshot {
            directory = directory == null ? null : directory.toAbsolutePath().normalize();
            ancestors = ancestors == null ? List.of() : List.copyOf(ancestors);
        }

        /**
         * Typed capability for directory observations.  The snapshot brackets a bounded walk,
         * but the portable NIO API does not guarantee an atomic parent-relative directory open
         * on every provider; consumers must not infer one from a successful snapshot.
         */
        public IoUtil.OpenCapability openCapability() {
            return IoUtil.OpenCapability.SNAPSHOT_BRACKETED;
        }

        /** Typed reason why this directory snapshot is not a provider-atomic open. */
        public IoUtil.ProviderAtomicStatus providerAtomicStatus() {
            return IoUtil.ProviderAtomicStatus.from(openCapability());
        }

        /** Disclose the strongest identity signal available for this directory provider. */
        public IdentityStrength identityStrength() {
            return ArchiveLimits.identityStrength(directory, directoryAttributes);
        }
    }

    /** Determine provider identity strength without following a path or inventing a digest. */
    public static IdentityStrength identityStrength(Path path, BasicFileAttributes attributes) {
        if (path != null) {
            try {
                String scheme = path.getFileSystem().provider().getScheme();
                if ("jrt".equalsIgnoreCase(scheme)) {
                    return IdentityStrength.IMMUTABLE_PROVIDER;
                }
            } catch (RuntimeException ignored) {
                // Fall through to the observable file-key/metadata signals.
            }
        }
        return attributes != null && attributes.fileKey() != null
                ? IdentityStrength.FILE_KEY_METADATA : IdentityStrength.METADATA_ONLY;
    }

    /**
     * A ZipFile bracketed by the same immutable file/parent snapshot used by regular streams.
     * {@link ZipFile} accepts only a path and therefore cannot provide a portable atomic
     * parent-handle open.  This adapter narrows the race window by checking immediately before
     * and after construction and verifies the identity again when the handle closes; callers
     * can keep the limitation explicit instead of treating a plain path open as a sandbox.
     */
    public static final class ZipFileHandle implements AutoCloseable {
        private final ZipFile zip;
        private final FileReadSnapshot snapshot;
        private final String reason;
        private boolean closed;

        private ZipFileHandle(ZipFile zip, FileReadSnapshot snapshot, String reason) {
            this.zip = zip;
            this.snapshot = snapshot;
            this.reason = reason;
        }

        public ZipFile zip() {
            if (closed) {
                throw new IllegalStateException("ZIP_HANDLE_CLOSED");
            }
            return zip;
        }

        public FileReadSnapshot snapshot() {
            return snapshot;
        }

        /** The Java NIO provider does not promise an atomic parent-relative ZipFile open. */
        public boolean providerAtomicOpen() {
            return providerAtomicStatus().supportsAtomicOpen();
        }

        /**
         * Typed capability for the archive open.  The handle is bracketed by a before/after
         * identity snapshot, but {@link ZipFile} only accepts a path and therefore cannot
         * promise an atomic parent-relative open on every provider.
         */
        public IoUtil.OpenCapability openCapability() {
            return IoUtil.OpenCapability.SNAPSHOT_BRACKETED;
        }

        /** Typed reason why ZipFile path construction is only snapshot-bracketed. */
        public IoUtil.ProviderAtomicStatus providerAtomicStatus() {
            return IoUtil.ProviderAtomicStatus.from(openCapability());
        }

        @Override
        public synchronized void close() throws IOException {
            if (closed) {
                return;
            }
            closed = true;
            IOException failure = null;
            try {
                zip.close();
            } catch (IOException closeFailure) {
                failure = closeFailure;
            }
            try {
                verifyRegularFileUnchanged(snapshot, reason);
            } catch (IOException identityFailure) {
                if (failure == null) {
                    failure = identityFailure;
                } else {
                    failure.addSuppressed(identityFailure);
                }
            }
            if (failure != null) {
                throw failure;
            }
        }
    }

    /**
     * Open a ZIP/JAR from a caller-captured snapshot.  The returned handle must be closed so
     * the post-read identity check runs even when the consumer aborts early.
     */
    public static ZipFileHandle openZipFile(FileReadSnapshot snapshot, String reason)
            throws IOException {
        String code = stableReason(reason);
        if (snapshot == null || snapshot.file() == null) {
            throw new IOException(code + "_NULL_SNAPSHOT");
        }
        verifyRegularFileUnchanged(snapshot, code);
        ZipFile zip;
        try {
            zip = new ZipFile(snapshot.file().toFile(), ZipFile.OPEN_READ);
        } catch (ZipException corrupt) {
            // Preserve the JDK's typed archive-corruption signal.  Archive consumers can
            // retain already-emitted facts and classify malformed central directories as a
            // stable PARTIAL result instead of turning every malformed input into an
            // untyped open failure.
            throw corrupt;
        } catch (IOException | RuntimeException failure) {
            throw new IOException(code + "_OPEN_FAILED", failure);
        }
        try {
            // ZipFile has no portable parent-relative constructor.  Verify immediately after
            // opening so a provider replacement between preflight and construction fails
            // before any central-directory bytes are consumed.
            verifyRegularFileUnchanged(snapshot, code);
            return new ZipFileHandle(zip, snapshot, code);
        } catch (IOException | RuntimeException failure) {
            try {
                zip.close();
            } catch (IOException closeFailure) {
                failure.addSuppressed(closeFailure);
            }
            throw failure;
        }
    }

    /** Convenience overload which captures the file/parent snapshot before opening. */
    public static ZipFileHandle openZipFile(Path file, InputBudget budget, String reason)
            throws IOException {
        InputBudget policy = budget == null ? InputBudget.defaults() : budget;
        return openZipFile(snapshotRegularFile(file, policy, reason), reason);
    }

    /** Capture a real directory and all parent components without following links. */
    public static DirectoryReadSnapshot snapshotDirectory(Path directory, InputBudget budget,
                                                           String reason) throws IOException {
        InputBudget policy = budget == null ? InputBudget.defaults() : budget;
        String code = stableReason(reason);
        if (directory == null) {
            throw new IOException(code + "_NOT_DIRECTORY");
        }
        Path normalized;
        try {
            normalized = directory.toAbsolutePath().normalize();
        } catch (RuntimeException invalidPath) {
            throw new IOException(code + "_NOT_DIRECTORY", invalidPath);
        }
        checkPathAncestors(normalized, policy);
        Path root = normalized.getRoot();
        if (root == null) {
            throw new IOException(code + "_NOT_DIRECTORY");
        }
        List<PathIdentity> ancestors = snapshotAncestors(normalized, code);
        BasicFileAttributes attributes = readDirectoryIdentity(normalized, code);
        return new DirectoryReadSnapshot(normalized, attributes, ancestors);
    }

    /** Verify that a previously captured directory and all parent components are unchanged. */
    public static void verifyDirectoryUnchanged(DirectoryReadSnapshot snapshot, String reason)
            throws IOException {
        String code = stableReason(reason);
        if (snapshot == null || snapshot.directory() == null
                || snapshot.directoryAttributes() == null) {
            throw new IOException(code + "_CHANGED_DURING_READ");
        }
        try {
            for (PathIdentity expected : snapshot.ancestors()) {
                BasicFileAttributes current = readDirectoryIdentity(expected.path(), code);
                if (!sameDirectoryIdentity(expected.attributes(), current)) {
                    throw new IOException(code + "_CHANGED_DURING_READ");
                }
            }
            BasicFileAttributes current = readDirectoryIdentity(snapshot.directory(), code);
            if (!sameDirectoryIdentity(snapshot.directoryAttributes(), current)) {
                throw new IOException(code + "_CHANGED_DURING_READ");
            }
        } catch (IOException failure) {
            if (failure.getMessage() != null
                    && failure.getMessage().startsWith(code + "_CHANGED_DURING_READ")) {
                throw failure;
            }
            throw new IOException(code + "_CHANGED_DURING_READ", failure);
        }
    }

    /**
     * Capture a regular file and every existing directory component without following links.
     * The returned snapshot is intended to bracket one bounded read; it is not a content hash.
     */
    public static FileReadSnapshot snapshotRegularFile(Path file, InputBudget budget,
                                                        String reason) throws IOException {
        InputBudget policy = budget == null ? InputBudget.defaults() : budget;
        String code = stableReason(reason);
        if (file == null) {
            throw new IOException(code + "_NOT_REGULAR");
        }
        Path normalized;
        try {
            normalized = file.toAbsolutePath().normalize();
        } catch (RuntimeException invalidPath) {
            throw new IOException(code + "_NOT_REGULAR", invalidPath);
        }
        checkPathAncestors(normalized, policy);
        Path root = normalized.getRoot();
        if (root == null) {
            throw new IOException(code + "_NOT_REGULAR");
        }
        List<PathIdentity> ancestors = new ArrayList<>();
        Path current = root;
        ancestors.add(new PathIdentity(current, readDirectoryIdentity(current, code)));
        for (Path component : normalized) {
            current = current.resolve(component);
            if (current.equals(normalized)) {
                break;
            }
            ancestors.add(new PathIdentity(current, readDirectoryIdentity(current, code)));
        }
        BasicFileAttributes attributes = readRegularIdentity(normalized, code);
        return new FileReadSnapshot(normalized, attributes, ancestors);
    }

    /** Verify that a previously captured file and all of its parent directories are unchanged. */
    public static void verifyRegularFileUnchanged(FileReadSnapshot snapshot, String reason)
            throws IOException {
        String code = stableReason(reason);
        if (snapshot == null || snapshot.file() == null || snapshot.fileAttributes() == null) {
            throw new IOException(code + "_CHANGED_DURING_READ");
        }
        try {
            for (PathIdentity expected : snapshot.ancestors()) {
                BasicFileAttributes current = readDirectoryIdentity(expected.path(), code);
                if (!sameDirectoryIdentity(expected.attributes(), current)) {
                    throw new IOException(code + "_CHANGED_DURING_READ");
                }
            }
            BasicFileAttributes current = readRegularIdentity(snapshot.file(), code);
            if (!sameRegularFileIdentity(snapshot.fileAttributes(), current)) {
                throw new IOException(code + "_CHANGED_DURING_READ");
            }
        } catch (IOException failure) {
            if (failure.getMessage() != null
                    && failure.getMessage().startsWith(code + "_CHANGED_DURING_READ")) {
                throw failure;
            }
            throw new IOException(code + "_CHANGED_DURING_READ", failure);
        }
    }

    private static BasicFileAttributes readDirectoryIdentity(Path path, String code)
            throws IOException {
        try {
            BasicFileAttributes attributes = Files.readAttributes(path, BasicFileAttributes.class,
                    LinkOption.NOFOLLOW_LINKS);
            if (!attributes.isDirectory() || isLinkOrReparsePoint(path)) {
                throw new IOException(code + "_NOT_REGULAR");
            }
            return attributes;
        } catch (IOException | RuntimeException failure) {
            if (failure.getMessage() != null && failure.getMessage().startsWith(code + "_")) {
                throw failure;
            }
            throw new IOException(code + "_NOT_REGULAR", failure);
        }
    }

    private static BasicFileAttributes readRegularIdentity(Path path, String code)
            throws IOException {
        try {
            BasicFileAttributes attributes = Files.readAttributes(path, BasicFileAttributes.class,
                    LinkOption.NOFOLLOW_LINKS);
            if (!attributes.isRegularFile() || isLinkOrReparsePoint(path)) {
                throw new IOException(code + "_NOT_REGULAR");
            }
            return attributes;
        } catch (IOException | RuntimeException failure) {
            if (failure.getMessage() != null && failure.getMessage().startsWith(code + "_")) {
                throw failure;
            }
            throw new IOException(code + "_NOT_REGULAR", failure);
        }
    }

    private static List<PathIdentity> snapshotAncestors(Path normalized, String code)
            throws IOException {
        Path root = normalized.getRoot();
        List<PathIdentity> ancestors = new ArrayList<>();
        Path current = root;
        ancestors.add(new PathIdentity(current, readDirectoryIdentity(current, code)));
        for (Path component : normalized) {
            current = current.resolve(component);
            if (current.equals(normalized)) {
                break;
            }
            ancestors.add(new PathIdentity(current, readDirectoryIdentity(current, code)));
        }
        return List.copyOf(ancestors);
    }

    /** Compare directory identity without using mutable directory mtime as an identity key. */
    public static boolean sameDirectoryIdentity(BasicFileAttributes expected,
                                                 BasicFileAttributes current) {
        return expected != null && current != null
                && expected.isDirectory() == current.isDirectory()
                && expected.creationTime().equals(current.creationTime())
                && sameFileKey(expected, current);
    }

    /** Compare regular-file identity and content-relevant metadata for one bounded read. */
    public static boolean sameRegularFileIdentity(BasicFileAttributes expected,
                                                   BasicFileAttributes current) {
        return expected != null && current != null
                && expected.isRegularFile() == current.isRegularFile()
                && expected.size() == current.size()
                && expected.creationTime().equals(current.creationTime())
                && expected.lastModifiedTime().equals(current.lastModifiedTime())
                && sameFileKey(expected, current);
    }

    private static boolean sameFileKey(BasicFileAttributes first,
                                       BasicFileAttributes second) {
        if (first.fileKey() != null || second.fileKey() != null) {
            return first.fileKey() != null && second.fileKey() != null
                    && first.fileKey().equals(second.fileKey());
        }
        // Some Windows providers omit fileKey.  Creation time is the remaining stable
        // replacement signal; permit an epoch sentinel only when both sides report it.
        return first.creationTime().toMillis() == 0L && second.creationTime().toMillis() == 0L
                || first.creationTime().equals(second.creationTime());
    }

    private static String stableReason(String reason) {
        if (reason == null || reason.isBlank()) {
            return "INPUT_FILE";
        }
        StringBuilder result = new StringBuilder(reason.length());
        for (int i = 0; i < reason.length(); i++) {
            char value = reason.charAt(i);
            result.append(Character.isLetterOrDigit(value) || value == '_' ? value : '_');
        }
        return result.toString();
    }

    /**
     * Check the physical container before opening it. ZIP central-directory sizes are
     * attacker-controlled metadata and may be absent or deliberately understated; the
     * physical file-size guard closes the gap for top-level inputs and classpath expansion.
     */
    public static void checkContainerSize(Path container) throws IOException {
        checkContainerSize(container, InputBudget.defaults());
    }

    /** Check one physical container against an explicit versioned input policy. */
    public static void checkContainerSize(Path container, InputBudget budget) throws IOException {
        if (container == null) {
            throw new IOException("archive container is null");
        }
        InputBudget policy = budget == null ? InputBudget.defaults() : budget;
        long size = Files.size(container);
        if (size > policy.maxPhysicalBytes()) {
            throw new IOException("archive physical compressed bytes exceed limit: "
                    + policy.maxPhysicalBytes());
        }
    }

    /** Return true for symbolic links and Windows reparse points without following them. */
    public static boolean isLinkOrReparsePoint(Path path) {
        if (path == null || Files.isSymbolicLink(path)) {
            return path != null;
        }
        try {
            return Boolean.TRUE.equals(Files.getAttribute(path, "dos:reparsePoint",
                    LinkOption.NOFOLLOW_LINKS));
        } catch (UnsupportedOperationException | IOException | SecurityException
                 | IllegalArgumentException ignored) {
            // Unix providers do not expose the DOS attribute; symbolic-link detection above
            // remains the portable check. Callers still use real-path containment where it is
            // available before opening untrusted files.
            return false;
        }
    }

    /**
     * Validate every existing component of a filesystem input without following links.
     *
     * <p>Checking only the final file is insufficient when an attacker can replace a parent
     * directory or supply a symlinked report/JAR root.  The check stops at the first missing
     * component (the caller will report a normal missing-input error) and fails closed on
     * provider/permission errors.  It is intentionally a policy helper rather than a resolver:
     * no real-path fallback is used and the caller still performs its own before/after snapshot
     * around the actual read.</p>
     */
    public static void checkPathAncestors(Path path, InputBudget budget) throws IOException {
        if (path == null) {
            throw new IOException("input path is null");
        }
        InputBudget policy = budget == null ? InputBudget.defaults() : budget;
        Path normalized;
        try {
            normalized = path.toAbsolutePath().normalize();
        } catch (RuntimeException invalidPath) {
            throw new IOException("input path is invalid", invalidPath);
        }
        String text = normalized.toString();
        if (text.codePointCount(0, text.length()) > policy.maxPathChars()
                || normalized.getNameCount() > policy.maxPathDepth()) {
            throw new IOException("input path exceeds policy bounds");
        }
        Path root = normalized.getRoot();
        if (root == null) {
            throw new IOException("input path has no root");
        }
        Path current = root;
        if (isLinkOrReparsePoint(current)) {
            throw new IOException("input path root is a link or reparse point");
        }
        for (Path component : normalized) {
            current = current.resolve(component);
            BasicFileAttributes attributes;
            try {
                attributes = Files.readAttributes(current, BasicFileAttributes.class,
                        LinkOption.NOFOLLOW_LINKS);
            } catch (NoSuchFileException missing) {
                break;
            } catch (IOException | RuntimeException failure) {
                throw new IOException("input path component cannot be inspected", failure);
            }
            if (isLinkOrReparsePoint(current)) {
                throw new IOException("input path contains a link or reparse point: "
                        + current.getFileName());
            }
            if (!current.equals(normalized) && !attributes.isDirectory()) {
                throw new IOException("input path ancestor is not a directory");
            }
        }
    }

    /** Reject absolute and parent-traversal archive names before resolving them. */
    public static boolean safeEntryName(String name) {
        return safeEntryName(name, InputBudget.defaults());
    }

    /** Reject unsafe names using the explicit path-length policy. */
    public static boolean safeEntryName(String name, InputBudget budget) {
        InputBudget policy = budget == null ? InputBudget.defaults() : budget;
        if (name == null || name.isBlank() || name.indexOf('\0') >= 0
                || name.startsWith("/") || name.startsWith("\\")
                || name.matches("^[A-Za-z]:.*")) {
            return false;
        }
        if (name.codePointCount(0, name.length()) > policy.maxPathChars()) {
            return false;
        }
        String normalized = name.replace('\\', '/');
        // Directory entries conventionally end with a slash. The slash itself is
        // harmless; empty path components inside the name are not.
        while (normalized.endsWith("/")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        if (normalized.isBlank()) {
            return false;
        }
        String[] components = normalized.split("/", -1);
        if (components.length > policy.maxPathDepth()) {
            return false;
        }
        for (String component : components) {
            if (component.isEmpty() || ".".equals(component) || "..".equals(component)) {
                return false;
            }
        }
        return true;
    }

    /** Declared ZIP sizes are advisory; unknown sizes are checked while bytes are read. */
    public static boolean safeCompressionRatio(long compressed, long uncompressed) {
        if (uncompressed < 0 || compressed < 0) {
            return true;
        }
        if (uncompressed == 0) {
            return true;
        }
        if (compressed == 0) {
            return uncompressed <= 1024;
        }
        return InputBudget.defaults().safeCompressionRatio(compressed, uncompressed);
    }

    /**
     * Mutable accounting for one archive expansion. Declared ZIP sizes and bytes actually
     * read are tracked independently: a corrupt archive must not bypass the read limit by
     * lying in its central directory, while a conservative declared-size cap rejects an
     * archive before it is expanded.
     */
    public static final class Tracker extends InputBudget.Tracker {
        public Tracker() {
            super(InputBudget.defaults());
        }
    }
}
