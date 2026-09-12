package io.just.sast.util;

import io.just.sast.run.InputBudget;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.channels.Channels;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.SecureDirectoryStream;
import java.nio.file.StandardOpenOption;
import java.util.Set;

/** IO 工具。 */
public final class IoUtil {

    /** 单条目读取上限（64MB）：防 zip 炸弹单条目 OOM。 */
    private static final long MAX_ENTRY_BYTES = ArchiveLimits.MAX_ENTRY_UNCOMPRESSED_BYTES;

    private IoUtil() {}

    /**
     * Capability of one bounded regular-file open.  A secure-directory handle protects the
     * parent chain on providers which implement {@link SecureDirectoryStream}; the fallback
     * protects only the final component with {@link LinkOption#NOFOLLOW_LINKS}.  Callers must
     * retain their before/after identity snapshot in either case because Java's portable NIO
     * API does not make a preflight and open operation atomic on every provider.
     */
    public enum OpenCapability {
        SECURE_PARENT_HANDLE,
        FINAL_COMPONENT_NOFOLLOW,
        /** An immutable virtual provider (currently the JDK jrt image) owns the path. */
        IMMUTABLE_PROVIDER,
        /**
         * The consumer supplied an identity snapshot around a provider path open, but the
         * provider does not expose a parent-relative atomic handle (for example
         * {@link java.util.zip.ZipFile}).  This is deliberately a capability value rather than
         * a boolean so reports cannot mistake snapshot protection for atomicity.
         */
        SNAPSHOT_BRACKETED
    }

    /**
     * Typed disclosure of whether a provider/open path supplies atomic parent protection.
     * This is deliberately separate from {@link OpenCapability}: the latter describes the
     * primitive used for this particular stream, while this enum gives reports a stable,
     * closed-set reason for an atomicity limitation.  In particular, a successful snapshot
     * check must never be mistaken for a provider-atomic open.
     */
    public enum ProviderAtomicStatus {
        /** A secure parent-relative handle protects the complete open/read lifetime. */
        ATOMIC_PARENT_HANDLE(true, false, "PROVIDER_PARENT_HANDLE"),
        /** An immutable virtual provider has no mutable path race to guard. */
        IMMUTABLE_PROVIDER(true, true, "IMMUTABLE_PROVIDER"),
        /** A path-only provider is bracketed by identity snapshots, not atomically opened. */
        SNAPSHOT_ONLY_PATH_OPEN(false, false, "PROVIDER_PATH_ONLY_SNAPSHOT"),
        /** The provider exposes only final-component NOFOLLOW protection. */
        FINAL_COMPONENT_ONLY(false, false, "PROVIDER_NOFOLLOW_FINAL_COMPONENT");

        private final boolean supportsAtomicOpen;
        private final boolean immutable;
        private final String reasonCode;

        ProviderAtomicStatus(boolean supportsAtomicOpen, boolean immutable, String reasonCode) {
            this.supportsAtomicOpen = supportsAtomicOpen;
            this.immutable = immutable;
            this.reasonCode = reasonCode;
        }

        public boolean supportsAtomicOpen() {
            return supportsAtomicOpen;
        }

        /** Whether the result is strong because the provider itself is immutable. */
        public boolean immutable() {
            return immutable;
        }

        /** Stable machine-readable explanation used by reports and input inventories. */
        public String reasonCode() {
            return reasonCode;
        }

        public static ProviderAtomicStatus from(OpenCapability capability) {
            if (capability == null) {
                throw new IllegalArgumentException("open capability is required");
            }
            return switch (capability) {
                case SECURE_PARENT_HANDLE -> ATOMIC_PARENT_HANDLE;
                case IMMUTABLE_PROVIDER -> IMMUTABLE_PROVIDER;
                case SNAPSHOT_BRACKETED -> SNAPSHOT_ONLY_PATH_OPEN;
                case FINAL_COMPONENT_NOFOLLOW -> FINAL_COMPONENT_ONLY;
            };
        }
    }

    /**
     * One bounded input together with the provider capability used to open it.  The parent
     * directory stream is kept alive for secure-directory opens until the input is closed;
     * this makes the capability claim true for the entire read rather than just the initial
     * channel creation.
     */
    public static final class OpenedInput implements AutoCloseable {
        private final InputStream stream;
        private final OpenCapability capability;
        private final AutoCloseable scope;

        private OpenedInput(InputStream stream, OpenCapability capability,
                            AutoCloseable scope) {
            if (stream == null || capability == null) {
                throw new IllegalArgumentException("opened input and capability are required");
            }
            this.stream = stream;
            this.capability = capability;
            this.scope = scope;
        }

        public InputStream stream() {
            return stream;
        }

        public OpenCapability capability() {
            return capability;
        }

        /** Typed atomicity/immutability disclosure for this provider open. */
        public ProviderAtomicStatus providerAtomicStatus() {
            return ProviderAtomicStatus.from(capability);
        }

        @Override
        public void close() throws IOException {
            IOException failure = null;
            try {
                stream.close();
            } catch (IOException closeFailure) {
                failure = closeFailure;
            }
            if (scope != null) {
                try {
                    scope.close();
                } catch (Exception closeFailure) {
                    IOException wrapped = closeFailure instanceof IOException io
                            ? io : new IOException("INPUT_PARENT_SCOPE_CLOSE_FAILED", closeFailure);
                    if (failure == null) {
                        failure = wrapped;
                    } else {
                        failure.addSuppressed(wrapped);
                    }
                }
            }
            if (failure != null) {
                throw failure;
            }
        }
    }

    /**
     * Open a regular filesystem file with the strongest no-follow primitive offered by the
     * active provider.  Providers exposing {@link SecureDirectoryStream} receive a channel
     * opened relative to a live parent handle; other providers use the strict final-component
     * {@link #openNoFollow(Path, String)} path.  The latter is intentionally observable through
     * {@link OpenedInput#capability()} and is not presented as an atomic parent open.
     */
    public static OpenedInput openRegularFile(Path path, String reason) throws IOException {
        if (path == null) {
            throw new IOException(stableReason(reason) + "_NULL_PATH");
        }
        String code = stableReason(reason);
        Path normalized;
        try {
            normalized = path.toAbsolutePath().normalize();
        } catch (RuntimeException invalid) {
            throw new IOException(code + "_INVALID_PATH", invalid);
        }
        try {
            var attributes = Files.readAttributes(normalized,
                    java.nio.file.attribute.BasicFileAttributes.class,
                    LinkOption.NOFOLLOW_LINKS);
            if (!attributes.isRegularFile()) {
                throw new IOException(code + "_NOT_REGULAR");
            }
            if (ArchiveLimits.isLinkOrReparsePoint(normalized)) {
                throw new IOException(code + "_LINK");
            }
        } catch (IOException | RuntimeException failure) {
            if (failure instanceof IOException io && io.getMessage() != null
                    && io.getMessage().startsWith(code + "_")) {
                throw io;
            }
            throw new IOException(code + "_OPEN_FAILED", failure);
        }

        Path parent = normalized.getParent();
        Path fileName = normalized.getFileName();
        if (parent != null && fileName != null) {
            DirectoryStream<Path> directory = null;
            boolean handedOff = false;
            try {
                directory = Files.newDirectoryStream(parent);
                if (directory instanceof SecureDirectoryStream<?>) {
                    @SuppressWarnings("unchecked")
                    SecureDirectoryStream<Path> secure =
                            (SecureDirectoryStream<Path>) directory;
                    SeekableByteChannel channel = null;
                    try {
                        Set<OpenOption> options = Set.of(StandardOpenOption.READ,
                                LinkOption.NOFOLLOW_LINKS);
                        channel = secure.newByteChannel(fileName, options);
                        handedOff = true;
                        return new OpenedInput(Channels.newInputStream(channel),
                                OpenCapability.SECURE_PARENT_HANDLE, directory);
                    } catch (UnsupportedOperationException unsupported) {
                        // The provider advertises SecureDirectoryStream but not a secure
                        // regular-file channel.  Fall through to the strict leaf open and
                        // expose that weaker capability to the caller.
                        if (channel != null) {
                            try {
                                channel.close();
                            } catch (IOException ignored) {
                                // The fallback below is the useful failure boundary.
                            }
                        }
                    } catch (IOException failure) {
                        if (channel != null) {
                            try {
                                channel.close();
                            } catch (IOException ignored) {
                                failure.addSuppressed(ignored);
                            }
                        }
                        throw failure;
                    }
                }
            } catch (NoSuchFileException missingParent) {
                // Let the strict leaf open return the provider's ordinary missing-input
                // reason; this is not a capability failure.
            } catch (UnsupportedOperationException unsupported) {
                // Provider does not support directory streams; use the strict leaf open.
            } finally {
                if (directory != null && !handedOff) {
                    try {
                        directory.close();
                    } catch (IOException ignored) {
                        // The fallback open below will surface a useful failure if needed.
                    }
                }
            }
        }
        return new OpenedInput(openNoFollow(normalized, reason),
                OpenCapability.FINAL_COMPONENT_NOFOLLOW, null);
    }

    /**
     * Open one regular file from an immutable virtual provider such as {@code jrt:/}.
     *
     * <p>The JRT provider intentionally rejects {@link LinkOption#NOFOLLOW_LINKS}; routing it
     * through {@link #openRegularFile(Path, String)} would turn a provider capability into an
     * opaque failure.  This adapter is deliberately scheme-gated and reports the stronger
     * immutable-provider capability.  It must not be used for ordinary filesystem paths, where
     * callers need the parent-handle/final-component contract above.</p>
     */
    public static OpenedInput openImmutableProviderFile(Path path, String reason)
            throws IOException {
        if (path == null) {
            throw new IOException(stableReason(reason) + "_NULL_PATH");
        }
        String code = stableReason(reason);
        String scheme;
        try {
            scheme = path.getFileSystem().provider().getScheme();
        } catch (RuntimeException invalid) {
            throw new IOException(code + "_PROVIDER_UNAVAILABLE", invalid);
        }
        if (!"jrt".equalsIgnoreCase(scheme)) {
            throw new IOException(code + "_IMMUTABLE_PROVIDER_REQUIRED");
        }
        try {
            var attributes = Files.readAttributes(path,
                    java.nio.file.attribute.BasicFileAttributes.class);
            if (!attributes.isRegularFile()) {
                throw new IOException(code + "_NOT_REGULAR");
            }
            return new OpenedInput(Files.newInputStream(path),
                    OpenCapability.IMMUTABLE_PROVIDER, null);
        } catch (IOException | RuntimeException failure) {
            if (failure instanceof IOException io && io.getMessage() != null
                    && io.getMessage().startsWith(code + "_")) {
                throw io;
            }
            throw new IOException(code + "_OPEN_FAILED", failure);
        }
    }

    /**
     * Open one filesystem input without following the final link component.
     *
     * <p>This is deliberately a strict adapter rather than a portability shim: a provider
     * which cannot honour {@link LinkOption#NOFOLLOW_LINKS} must surface a stable failure to
     * the caller.  Callers that operate on an immutable virtual provider (for example JRT)
     * keep their explicit provider-specific fallback and must not route it through this API.
     * The returned stream still has to be bracketed by the caller's identity snapshot; Java's
     * portable NIO API cannot promise an atomic preflight-and-open handle by itself.</p>
     */
    public static InputStream openNoFollow(Path path) throws IOException {
        return openNoFollow(path, "INPUT");
    }

    /** Open one filesystem input with a stable reason-code prefix on provider failure. */
    public static InputStream openNoFollow(Path path, String reason) throws IOException {
        if (path == null) {
            throw new IOException(stableReason(reason) + "_NULL_PATH");
        }
        String code = stableReason(reason);
        try {
            return Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS);
        } catch (UnsupportedOperationException unsupported) {
            throw new IOException(code + "_NOFOLLOW_UNSUPPORTED", unsupported);
        } catch (SecurityException denied) {
            throw new IOException(code + "_OPEN_DENIED", denied);
        } catch (RuntimeException invalid) {
            throw new IOException(code + "_OPEN_FAILED", invalid);
        }
    }

    public static byte[] readAll(InputStream in) throws IOException {
        return readAll(in, MAX_ENTRY_BYTES);
    }

    /** Read one stream with an explicit byte budget. */
    public static byte[] readAll(InputStream in, long limit) throws IOException {
        return readAll(in, limit, null);
    }

    /**
     * Read one stream with both a local byte cap and an optional shared input tracker.
     *
     * <p>The tracker is updated per successful read rather than after the whole allocation, so
     * a caller cannot bypass the aggregate budget with a stream whose declared size is unknown.
     * A bounded no-progress counter also turns a broken/hostile stream into a deterministic
     * rejection instead of an infinite loop.</p>
     */
    public static byte[] readAll(InputStream in, long limit, InputBudget.Tracker tracker)
            throws IOException {
        if (in == null || limit < 0) {
            throw new IllegalArgumentException("input and non-negative limit are required");
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream(4096);
        byte[] buffer = new byte[8192];
        long total = 0;
        int emptyReads = 0;
        while (true) {
            if (tracker != null) {
                tracker.checkTime();
            }
            long localRemaining = limit - total;
            int request = localRemaining > Integer.MAX_VALUE
                    ? buffer.length : (int) Math.min((long) buffer.length, localRemaining);
            int n;
            if (tracker != null) {
                n = tracker.readBounded(in, buffer, 0, request, localRemaining,
                        "条目超过单条目上限 " + limit + " 字节");
            } else {
                if (request == 0) {
                    // An exact-boundary stream is valid when the next read is EOF. Probe one
                    // byte so a stream with additional data is rejected without materializing a
                    // large post-budget buffer.
                    int one = in.read(buffer, 0, 1);
                    if (one < 0) {
                        break;
                    }
                    if (one == 0) {
                        throw new IOException("INPUT_STREAM_NO_PROGRESS");
                    }
                    throw new IOException("条目超过单条目上限 " + limit + " 字节");
                }
                n = in.read(buffer, 0, request);
            }
            if (n < 0) {
                break;
            }
            if (n == 0) {
                // InputStream is allowed to make a zero-byte progress report. Fall back to
                // one byte so a hostile/custom stream cannot spin this bounded reader forever.
                if (++emptyReads > 1024) {
                    throw new IOException("INPUT_STREAM_NO_PROGRESS");
                }
                int one = tracker == null
                        ? in.read() : tracker.readByteBounded(in, localRemaining,
                        "条目超过单条目上限 " + limit + " 字节");
                if (one < 0) {
                    break;
                }
                if (total >= limit) {
                    throw new IOException("条目超过单条目上限 " + limit + " 字节");
                }
                out.write(one);
                total++;
                continue;
            }
            emptyReads = 0;
            if (n > limit - total) {
                throw new IOException("条目超过单条目上限 " + limit + " 字节");
            }
            out.write(buffer, 0, n);
            total += n;
            if (tracker == null) {
                // The no-tracker overload remains a local-only compatibility reader.
            }
        }
        return out.toByteArray();
    }

    private static String stableReason(String reason) {
        if (reason == null || reason.isBlank()) {
            return "INPUT";
        }
        StringBuilder result = new StringBuilder(reason.length());
        for (int i = 0; i < reason.length(); i++) {
            char value = reason.charAt(i);
            result.append(Character.isLetterOrDigit(value) || value == '_' ? value : '_');
        }
        return result.toString().toUpperCase(java.util.Locale.ROOT);
    }
}
