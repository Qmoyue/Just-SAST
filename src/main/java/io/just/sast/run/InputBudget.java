package io.just.sast.run;

import java.io.IOException;
import java.util.zip.ZipEntry;

/**
 * Versioned limits shared by every untrusted input parser.
 *
 * <p>The object is immutable and deliberately contains policy only; mutable accounting lives in
 * {@link Tracker}.  A caller may use {@link #defaults()} for the product contract or construct a
 * smaller budget in a hostile/contract test.  Archive consumers must share one tracker for the
 * whole expansion so nested entries cannot reset the total byte or entry budget.</p>
 */
public record InputBudget(
        String schemaVersion,
        long maxPhysicalBytes,
        long maxCompressedBytes,
        long maxUncompressedBytes,
        long maxEntryBytes,
        long maxCompressionRatio,
        int maxArchiveEntries,
        int maxArchiveNesting,
        int maxClassEntries,
        long maxRuleInputBytes,
        int maxRuleCodePoints,
        int maxRuleAliases,
        int maxRuleNestingDepth,
        int maxRuleDocuments,
        int maxRuleCount,
        int maxRuleCollectionItems,
        int maxRuleNodes,
        int maxRuleScalarChars,
        int maxPathChars,
        long maxParseMillis) {

    public static final String SCHEMA_VERSION = "JUST-INPUT-BUDGET-V1";

    private static final InputBudget DEFAULT = new InputBudget(
            SCHEMA_VERSION,
            256L * 1024 * 1024,
            256L * 1024 * 1024,
            512L * 1024 * 1024,
            64L * 1024 * 1024,
            1_000L,
            250_000,
            4,
            100_000,
            16L * 1024 * 1024,
            4_000_000,
            64,
            64,
            1,
            4_096,
            4_096,
            100_000,
            16_384,
            4_096,
            300_000L);

    public InputBudget {
        schemaVersion = schemaVersion == null || schemaVersion.isBlank()
                ? SCHEMA_VERSION : schemaVersion.trim();
        if (!SCHEMA_VERSION.equals(schemaVersion)) {
            throw new IllegalArgumentException("unsupported input budget schema: " + schemaVersion);
        }
        requirePositive(maxPhysicalBytes, "maxPhysicalBytes");
        requirePositive(maxCompressedBytes, "maxCompressedBytes");
        requirePositive(maxUncompressedBytes, "maxUncompressedBytes");
        requirePositive(maxEntryBytes, "maxEntryBytes");
        requirePositive(maxCompressionRatio, "maxCompressionRatio");
        requirePositive(maxArchiveEntries, "maxArchiveEntries");
        requireNonNegative(maxArchiveNesting, "maxArchiveNesting");
        requirePositive(maxClassEntries, "maxClassEntries");
        requirePositive(maxRuleInputBytes, "maxRuleInputBytes");
        requirePositive(maxRuleCodePoints, "maxRuleCodePoints");
        requireNonNegative(maxRuleAliases, "maxRuleAliases");
        requireNonNegative(maxRuleNestingDepth, "maxRuleNestingDepth");
        requirePositive(maxRuleDocuments, "maxRuleDocuments");
        requirePositive(maxRuleCount, "maxRuleCount");
        requirePositive(maxRuleCollectionItems, "maxRuleCollectionItems");
        requirePositive(maxRuleNodes, "maxRuleNodes");
        requirePositive(maxRuleScalarChars, "maxRuleScalarChars");
        requirePositive(maxPathChars, "maxPathChars");
        requirePositive(maxParseMillis, "maxParseMillis");
    }

    public static InputBudget defaults() {
        return DEFAULT;
    }

    /**
     * Derived component-depth guard for filesystem/archive paths.  Keeping it derived from the
     * versioned path-character limit avoids a second uncoordinated policy knob while bounding
     * recursive directory walks and normalized output trees.
     */
    public int maxPathDepth() {
        return Math.max(16, Math.min(512, maxPathChars));
    }

    public Tracker tracker() {
        return new Tracker(this);
    }

    /** Return a copy with archive dimensions overridden, preserving every rule/path limit. */
    public InputBudget withArchiveLimits(long physicalBytes, long compressedBytes,
                                         long uncompressedBytes, long entryBytes,
                                         int archiveEntries, int archiveNesting,
                                         int classEntries) {
        return new InputBudget(schemaVersion, physicalBytes, compressedBytes, uncompressedBytes,
                entryBytes, maxCompressionRatio, archiveEntries, archiveNesting, classEntries,
                maxRuleInputBytes, maxRuleCodePoints, maxRuleAliases, maxRuleNestingDepth,
                maxRuleDocuments, maxRuleCount, maxRuleCollectionItems, maxRuleNodes,
                maxRuleScalarChars, maxPathChars, maxParseMillis);
    }

    /** Return a copy with only the bounded rule-stream input size changed. */
    public InputBudget withRuleInputBytes(long ruleInputBytes) {
        return new InputBudget(schemaVersion, maxPhysicalBytes, maxCompressedBytes,
                maxUncompressedBytes, maxEntryBytes, maxCompressionRatio, maxArchiveEntries,
                maxArchiveNesting, maxClassEntries, ruleInputBytes, maxRuleCodePoints,
                maxRuleAliases, maxRuleNestingDepth, maxRuleDocuments, maxRuleCount,
                maxRuleCollectionItems, maxRuleNodes, maxRuleScalarChars, maxPathChars,
                maxParseMillis);
    }

    /**
     * Declared ZIP sizes are advisory.  Unknown sizes are accepted here and are bounded while
     * bytes are read through {@link #remainingReadBytes()} and {@link #recordRead(long)}.
     */
    public boolean safeCompressionRatio(long compressed, long uncompressed) {
        if (uncompressed < 0 || compressed < 0 || uncompressed == 0) {
            return true;
        }
        if (compressed == 0) {
            // Preserve the historical allowance for tiny zero-byte metadata entries; a
            // compressed-size sentinel is not a usable ratio denominator.
            return uncompressed <= 1_024L;
        }
        if (compressed > Long.MAX_VALUE / maxCompressionRatio) {
            return true;
        }
        return uncompressed <= compressed * maxCompressionRatio
                || uncompressed <= maxCompressionRatio;
    }

    /** Stable machine-readable policy receipt, independent of local paths. */
    public String toCanonicalJson() {
        return "{\"schema_version\":\"" + escape(schemaVersion)
                + "\",\"max_physical_bytes\":" + maxPhysicalBytes
                + ",\"max_compressed_bytes\":" + maxCompressedBytes
                + ",\"max_uncompressed_bytes\":" + maxUncompressedBytes
                + ",\"max_entry_bytes\":" + maxEntryBytes
                + ",\"max_compression_ratio\":" + maxCompressionRatio
                + ",\"max_archive_entries\":" + maxArchiveEntries
                + ",\"max_archive_nesting\":" + maxArchiveNesting
                + ",\"max_class_entries\":" + maxClassEntries
                + ",\"max_rule_input_bytes\":" + maxRuleInputBytes
                + ",\"max_rule_code_points\":" + maxRuleCodePoints
                + ",\"max_rule_aliases\":" + maxRuleAliases
                + ",\"max_rule_nesting_depth\":" + maxRuleNestingDepth
                + ",\"max_rule_documents\":" + maxRuleDocuments
                + ",\"max_rule_count\":" + maxRuleCount
                + ",\"max_rule_collection_items\":" + maxRuleCollectionItems
                + ",\"max_rule_nodes\":" + maxRuleNodes
                + ",\"max_rule_scalar_chars\":" + maxRuleScalarChars
                + ",\"max_path_chars\":" + maxPathChars
                + ",\"max_parse_millis\":" + maxParseMillis + "}";
    }

    /** Mutable accounting shared by a complete archive expansion. */
    public static class Tracker {
        private final InputBudget budget;
        private int entries;
        private long compressedBytes;
        private long declaredUncompressedBytes;
        private long readUncompressedBytes;
        private long readContainerBytes;
        private long ruleNodes;
        private long ruleCollectionItems;
        private long ruleScalarChars;
        // The parse clock is intentionally pausable at a proven input-free phase boundary.
        // Byte/entry accounting remains in this tracker; only wall time spent solving an
        // already-frozen model is excluded from the input parser budget.
        private long activeStartedNanos = System.nanoTime();
        private long accumulatedActiveNanos;
        private boolean timePaused;

        public Tracker(InputBudget budget) {
            this.budget = budget == null ? InputBudget.defaults() : budget;
        }

        public InputBudget budget() {
            return budget;
        }

        public synchronized void observe(ZipEntry entry) throws IOException {
            checkTime();
            if (entry == null) {
                throw new IOException("null archive entry");
            }
            if (++entries > budget.maxArchiveEntries()) {
                throw new IOException("archive entry count exceeds limit: "
                        + budget.maxArchiveEntries());
            }
            long compressed = entry.getCompressedSize();
            long uncompressed = entry.getSize();
            if (compressed >= 0) {
                if (compressed > budget.maxCompressedBytes() - compressedBytes) {
                    throw new IOException("archive compressed bytes exceed limit");
                }
                compressedBytes += compressed;
            }
            if (uncompressed > budget.maxEntryBytes()) {
                throw new IOException("archive entry exceeds limit: " + entry.getName());
            }
            if (!budget.safeCompressionRatio(compressed, uncompressed)) {
                throw new IOException("archive compression ratio exceeds limit: " + entry.getName());
            }
            if (uncompressed >= 0) {
                if (uncompressed > budget.maxUncompressedBytes() - declaredUncompressedBytes) {
                    throw new IOException("archive declared bytes exceed limit");
                }
                declaredUncompressedBytes += uncompressed;
            }
        }

        /** Account for one directory/file entry without pretending it is compressed data. */
        public synchronized void observeFile(String name, long size) throws IOException {
            checkTime();
            observeFilesystemEntry();
            if (name == null || name.isBlank()) {
                throw new IOException("null filesystem entry");
            }
            if (size < 0L || size > budget.maxEntryBytes()) {
                throw new IOException("filesystem entry exceeds limit: " + name);
            }
            if (size > budget.maxUncompressedBytes() - declaredUncompressedBytes) {
                throw new IOException("filesystem declared bytes exceed limit");
            }
            declaredUncompressedBytes += size;
        }

        /**
         * Account for a walked directory entry without charging bytes.  Directory consumers
         * call this during discovery and charge regular-file bytes exactly once when opening
         * the selected class.  Keeping the entry increment in the shared tracker prevents a
         * second artifact from obtaining a fresh directory-walk allowance.
         */
        public synchronized void observeFilesystemEntry() throws IOException {
            checkTime();
            if (++entries > budget.maxArchiveEntries()) {
                throw new IOException("archive entry count exceeds limit: "
                        + budget.maxArchiveEntries());
            }
        }

        public synchronized long remainingReadBytes() {
            long remaining = budget.maxUncompressedBytes() - readUncompressedBytes
                    - readContainerBytes;
            return Math.max(0L, remaining);
        }

        /**
         * Clamp one {@link java.io.InputStream} request to both the caller's local limit and
         * the scan-wide aggregate budget.  Consumers must use the returned length when calling
         * {@code read(buffer, 0, length)} and then account the actual positive result with
         * {@link #recordRead(long)} or {@link #recordContainerRead(long)}.  Returning zero is a
         * boundary signal; callers should perform a one-byte EOF probe rather than issuing an
         * unbounded read that could materialize bytes after the budget is exhausted.
         *
         * <p>This is intentionally a sizing primitive rather than a reservation.  Production
         * parser streams are consumed serially; callers that parallelize reads still have to
         * serialize the corresponding record operation or use an independent bounded tracker.</p>
         */
        public synchronized int boundedReadSize(long localRemaining, int requested)
                throws IOException {
            checkTime();
            return boundedReadSizeLocked(localRemaining, requested);
        }

        /**
         * Read one bounded stream chunk and account the actual bytes while holding the tracker
         * monitor.  Keeping sizing, the provider read and accounting in one operation prevents
         * parallel input/report consumers from all observing the same aggregate remainder and
         * then physically reading past it before {@link #recordRead(long)} can reject the second
         * result.  The stream call is intentionally inside this narrow monitor: untrusted input
         * accounting is correctness-critical, and serialising only the bounded read (not graph
         * solving or rendering) is the predictable fail-closed trade-off.
         */
        public synchronized int readBounded(java.io.InputStream input, byte[] buffer,
                                            int offset, int length, long localRemaining)
                throws IOException {
            return readBounded(input, buffer, offset, length, localRemaining,
                    "INPUT_READ_LIMIT:" + Math.max(0L, localRemaining));
        }

        /** Read one bounded stream chunk with a caller-specific stable overflow reason. */
        public synchronized int readBounded(java.io.InputStream input, byte[] buffer,
                                            int offset, int length, long localRemaining,
                                            String overflowReason) throws IOException {
            validateBuffer(input, buffer, offset, length);
            checkTime();
            int request = boundedReadSizeLocked(localRemaining, length);
            if (request == 0) {
                int probe = input.read(buffer, offset, 1);
                if (probe < 0) {
                    return -1;
                }
                if (probe == 0) {
                    throw new IOException("INPUT_STREAM_NO_PROGRESS");
                }
                throw new IOException(stableReadReason(overflowReason));
            }
            int count = input.read(buffer, offset, request);
            if (count < 0) {
                return -1;
            }
            if (count > request) {
                throw new IOException("INPUT_READ_PROVIDER_OVERRUN");
            }
            if (count > 0) {
                readUncompressedBytes += count;
            }
            return count;
        }

        /** Read one byte under the aggregate budget without a separate record race. */
        public synchronized int readByteBounded(java.io.InputStream input, long localRemaining,
                                                String overflowReason) throws IOException {
            if (input == null || localRemaining < 0L) {
                throw new IOException("INPUT_READ_ARGUMENT_INVALID");
            }
            checkTime();
            int request = boundedReadSizeLocked(localRemaining, 1);
            if (request == 0) {
                int probe = input.read();
                if (probe < 0) {
                    return -1;
                }
                throw new IOException(stableReadReason(overflowReason));
            }
            int value = input.read();
            if (value >= 0) {
                readUncompressedBytes++;
            }
            return value;
        }

        /** Read a container chunk and charge it to the container side of the shared budget. */
        public synchronized int readContainerBounded(java.io.InputStream input, byte[] buffer,
                                                      int offset, int length,
                                                      String overflowReason) throws IOException {
            return readContainerBounded(input, buffer, offset, length, Long.MAX_VALUE,
                    overflowReason);
        }

        /** Read a container chunk with both a local physical cap and aggregate accounting. */
        public synchronized int readContainerBounded(java.io.InputStream input, byte[] buffer,
                                                      int offset, int length, long localRemaining,
                                                      String overflowReason) throws IOException {
            validateBuffer(input, buffer, offset, length);
            checkTime();
            int request = boundedReadSizeLocked(localRemaining, length);
            if (request == 0) {
                int probe = input.read(buffer, offset, 1);
                if (probe < 0) {
                    return -1;
                }
                if (probe == 0) {
                    throw new IOException("INPUT_STREAM_NO_PROGRESS");
                }
                throw new IOException(stableReadReason(overflowReason));
            }
            int count = input.read(buffer, offset, request);
            if (count < 0) {
                return -1;
            }
            if (count > request) {
                throw new IOException("INPUT_READ_PROVIDER_OVERRUN");
            }
            if (count > 0) {
                readContainerBytes += count;
            }
            return count;
        }

        /** Read one container byte under the aggregate budget. */
        public synchronized int readContainerByteBounded(java.io.InputStream input,
                                                          String overflowReason)
                throws IOException {
            return readContainerByteBounded(input, Long.MAX_VALUE, overflowReason);
        }

        /** Read one container byte with a local physical cap and aggregate accounting. */
        public synchronized int readContainerByteBounded(java.io.InputStream input,
                                                          long localRemaining,
                                                          String overflowReason)
                throws IOException {
            if (input == null) {
                throw new IOException("INPUT_READ_ARGUMENT_INVALID");
            }
            checkTime();
            int request = boundedReadSizeLocked(localRemaining, 1);
            if (request == 0) {
                int probe = input.read();
                if (probe < 0) {
                    return -1;
                }
                throw new IOException(stableReadReason(overflowReason));
            }
            int value = input.read();
            if (value >= 0) {
                readContainerBytes++;
            }
            return value;
        }

        /** Skip bounded container bytes while charging the actual skipped amount. */
        public synchronized long skipContainerBounded(java.io.InputStream input, long requested)
                throws IOException {
            if (input == null || requested < 0L) {
                throw new IOException("INPUT_READ_ARGUMENT_INVALID");
            }
            checkTime();
            int request = boundedReadSizeLocked(Long.MAX_VALUE,
                    (int) Math.min(requested, Integer.MAX_VALUE));
            if (request == 0) {
                return 0L;
            }
            long skipped = input.skip(request);
            if (skipped < 0L || skipped > request) {
                throw new IOException("INPUT_READ_PROVIDER_OVERRUN");
            }
            if (skipped > 0L) {
                readContainerBytes += skipped;
            }
            return skipped;
        }

        public synchronized void recordRead(long bytes) throws IOException {
            checkTime();
            if (bytes < 0 || bytes > remainingReadBytes()) {
                throw new IOException("archive bytes read exceed limit");
            }
            readUncompressedBytes += bytes;
        }

        public synchronized void recordContainerRead(long bytes) throws IOException {
            checkTime();
            if (bytes < 0 || bytes > remainingReadBytes()) {
                throw new IOException("archive container bytes read exceed limit");
            }
            readContainerBytes += bytes;
        }

        public synchronized int entries() {
            return entries;
        }

        public synchronized long compressedBytes() {
            return compressedBytes;
        }

        public synchronized long declaredUncompressedBytes() {
            return declaredUncompressedBytes;
        }

        public synchronized long readUncompressedBytes() {
            return readUncompressedBytes;
        }

        public synchronized long readContainerBytes() {
            return readContainerBytes;
        }

        /** Account parser nodes across the complete rule document, including aliases. */
        public synchronized void recordRuleNode() throws IOException {
            checkTime();
            if (++ruleNodes > budget.maxRuleNodes()) {
                throw new IOException("RULE_TOTAL_NODE_LIMIT:" + budget.maxRuleNodes());
            }
        }

        /** Account map/list members across the complete rule document. */
        public synchronized void recordRuleCollectionItem() throws IOException {
            checkTime();
            if (++ruleCollectionItems > budget.maxRuleCollectionItems()) {
                throw new IOException("RULE_TOTAL_COLLECTION_LIMIT:"
                        + budget.maxRuleCollectionItems());
            }
        }

        /** Bound aggregate scalar materialization by the rule input budget. */
        public synchronized void recordRuleScalarChars(long chars) throws IOException {
            checkTime();
            if (chars < 0 || chars > (long) budget.maxRuleCodePoints() - ruleScalarChars) {
                throw new IOException("RULE_TOTAL_SCALAR_CHAR_LIMIT:"
                        + budget.maxRuleCodePoints());
            }
            if (chars > budget.maxRuleInputBytes() - ruleScalarChars) {
                throw new IOException("RULE_TOTAL_SCALAR_LIMIT:" + budget.maxRuleInputBytes());
            }
            ruleScalarChars += chars;
        }

        public synchronized InputBudgetResult result() {
            long consumed = Math.max(readUncompressedBytes, readContainerBytes) == 0
                    ? 0L : readUncompressedBytes + readContainerBytes;
            if (consumed > budget.maxUncompressedBytes()) {
                return InputBudgetResult.exhausted(budget.maxUncompressedBytes(), consumed,
                        "ARCHIVE_UNCOMPRESSED_BYTES_CAP");
            }
            return InputBudgetResult.within(budget.maxUncompressedBytes(), consumed);
        }

        /**
         * Stop charging wall time while downstream code consumes an immutable, already-parsed
         * model.  This does not reset bytes, entries, or any other aggregate accounting.  The
         * caller may only use this at a phase boundary where the downstream operation cannot
         * reopen untrusted input; input readers continue to call {@link #checkTime()} normally
         * before and after the boundary.
         */
        public synchronized void pauseTime() {
            if (!timePaused) {
                accumulateActiveTime(System.nanoTime());
                timePaused = true;
            }
        }

        /** Resume the shared parse clock for a subsequent bounded input phase. */
        public synchronized void resumeTime() {
            if (timePaused) {
                activeStartedNanos = System.nanoTime();
                timePaused = false;
            }
        }

        /** Fail closed when a parser makes no progress or spends too long in allocation/IO. */
        public void checkTime() throws IOException {
            long elapsed = elapsedMillis();
            if (elapsed > budget.maxParseMillis()) {
                throw new IOException("INPUT_PARSE_TIME_CAP:" + budget.maxParseMillis());
            }
        }

        public synchronized long elapsedMillis() {
            long elapsedNanos = accumulatedActiveNanos;
            if (!timePaused) {
                elapsedNanos = saturatedAdd(elapsedNanos,
                        Math.max(0L, System.nanoTime() - activeStartedNanos));
            }
            return Math.max(0L, elapsedNanos / 1_000_000L);
        }

        private void accumulateActiveTime(long nowNanos) {
            saturatedAddInPlace(Math.max(0L, nowNanos - activeStartedNanos));
        }

        private void saturatedAddInPlace(long deltaNanos) {
            accumulatedActiveNanos = saturatedAdd(accumulatedActiveNanos, deltaNanos);
        }

        private static long saturatedAdd(long left, long right) {
            if (right <= 0L || Long.MAX_VALUE - left < right) {
                return right <= 0L ? left : Long.MAX_VALUE;
            }
            return left + right;
        }

        private int boundedReadSizeLocked(long localRemaining, int requested)
                throws IOException {
            if (localRemaining < 0L || requested < 0) {
                throw new IOException("INPUT_READ_ARGUMENT_INVALID");
            }
            if (localRemaining == 0L || requested == 0) {
                return 0;
            }
            long aggregate = remainingReadBytes();
            long allowed = Math.min(localRemaining, aggregate);
            if (allowed <= 0L) {
                return 0;
            }
            return (int) Math.min((long) requested,
                    Math.min(allowed, (long) Integer.MAX_VALUE));
        }

        private static void validateBuffer(java.io.InputStream input, byte[] buffer,
                                           int offset, int length) throws IOException {
            if (input == null || buffer == null) {
                throw new IOException("INPUT_READ_ARGUMENT_INVALID");
            }
            if (offset < 0 || length < 0 || offset > buffer.length - length) {
                throw new IOException("INPUT_READ_ARGUMENT_INVALID");
            }
        }

        private static String stableReadReason(String reason) {
            if (reason == null || reason.isBlank()) {
                return "INPUT_READ_LIMIT";
            }
            return reason;
        }
    }

    private static void requirePositive(long value, String name) {
        if (value <= 0L) {
            throw new IllegalArgumentException(name + " must be positive");
        }
    }

    private static void requirePositive(int value, String name) {
        if (value <= 0) {
            throw new IllegalArgumentException(name + " must be positive");
        }
    }

    private static void requireNonNegative(int value, String name) {
        if (value < 0) {
            throw new IllegalArgumentException(name + " must be non-negative");
        }
    }

    private static String escape(String value) {
        return value == null ? "" : value.replace("\\", "\\\\")
                .replace("\"", "\\\"").replace("\r", "\\r").replace("\n", "\\n");
    }
}
