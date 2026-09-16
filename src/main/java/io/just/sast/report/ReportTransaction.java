package io.just.sast.report;

import io.just.sast.run.InputBudget;
import io.just.sast.util.ArchiveLimits;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Owns the run-level report publication boundary.
 *
 * <p>Reporters may keep their existing single-file atomic writes, but a scan must never expose
 * a mixture of files from two runs.  A transaction therefore writes a complete layout below a
 * unique sibling staging directory and swaps that directory into place only after the state
 * marker has become {@code COMPLETE}.  The default is deliberately non-overwriting; callers
 * must opt into the recoverable directory swap explicitly.</p>
 */
public final class ReportTransaction implements AutoCloseable {

    public enum State { WRITING, COMPLETE, FAILED }

    /** Closed recovery classifications; no caller should infer state from free-form text. */
    public enum RecoveryStatus {
        TARGET_COMPLETE,
        COMPLETE_STAGING,
        WRITING_STAGING,
        FAILED_STAGING,
        BACKUP_PRESENT,
        INVALID_STAGING,
        UNSAFE_ORPHAN
    }

    /**
     * Closed, non-mutating recovery policy exposed to callers.  There is intentionally no
     * publish/delete/restore action here: recovery reconciliation is an observation boundary,
     * and any future mutating operation must be a separately authorized owner.
     */
    public enum RecoveryAction {
        NO_ACTION,
        RETAIN_FOR_AUDIT,
        MANUAL_REVIEW_REQUIRED,
        DO_NOT_MUTATE;

        public boolean mayMutate() {
            return false;
        }
    }

    /** One bounded, path-scoped recovery observation. */
    public record RecoveryEntry(Path path, RecoveryStatus status, String reasonCode) {
        public RecoveryEntry {
            path = path == null ? null : path.toAbsolutePath().normalize();
            if (status == null) {
                throw new IllegalArgumentException("recovery status is required");
            }
            reasonCode = reasonCode == null || reasonCode.isBlank()
                    ? status.name() : reasonCode;
        }
    }

    /** Typed policy projection for one recovery observation. */
    public record RecoveryDecision(Path path, RecoveryStatus status, RecoveryAction action,
                                   String reasonCode) {
        public RecoveryDecision {
            path = path == null ? null : path.toAbsolutePath().normalize();
            if (status == null || action == null) {
                throw new IllegalArgumentException("recovery status and action are required");
            }
            reasonCode = reasonCode == null || reasonCode.isBlank()
                    ? status.name() : reasonCode;
            if (action.mayMutate()) {
                throw new IllegalArgumentException("recovery action must remain non-mutating");
            }
        }
    }

    /** Read-only reconciliation result. It never publishes an orphan automatically. */
    public record RecoveryReport(Path target, List<RecoveryEntry> entries) {
        public RecoveryReport {
            target = target == null ? null : target.toAbsolutePath().normalize();
            entries = entries == null ? List.of() : List.copyOf(entries);
        }

        public boolean hasOrphans() {
            return !entries.isEmpty();
        }

        /** Return the stable, non-mutating action projection in observation order. */
        public List<RecoveryDecision> decisions() {
            return entries.stream().map(ReportTransaction::toDecision).toList();
        }
    }

    /** Thrown when a caller did not explicitly authorize replacing an existing report. */
    public static final class OutputExistsException extends IOException {
        public OutputExistsException(Path output) {
            super("report output already exists; explicit overwrite is required: " + output);
        }
    }

    private static final AtomicLong COUNTER = new AtomicLong();
    private static final int MAX_DELETE_DEPTH = 256;
    private static final int MAX_RECOVERY_SIBLINGS = 64;
    private static final long MAX_RECOVERY_STATE_BYTES = 4096L;
    private static final InputBudget PATH_POLICY = InputBudget.defaults();
    private static final String SCHEMA = "just-run-v1";
    private static final String PROCESS_TOKEN = Long.toUnsignedString(
            ProcessHandle.current().pid(), 36);

    private final Path target;
    private final Path staging;
    private final Path runState;
    private final ReportLayout layout;
    private final boolean overwrite;
    private final ArchiveLimits.DirectoryReadSnapshot parentSnapshot;
    private final String runId;
    private State state = State.WRITING;
    private boolean committed;

    private ReportTransaction(Path target, Path staging, ReportLayout layout,
                              boolean overwrite,
                              ArchiveLimits.DirectoryReadSnapshot parentSnapshot,
                              String runId) {
        this.target = target;
        this.staging = staging;
        this.runState = staging.resolve("run.json");
        this.layout = layout;
        this.overwrite = overwrite;
        this.parentSnapshot = parentSnapshot;
        this.runId = runId;
    }

    /** Begin a non-overwriting transaction. */
    public static ReportTransaction begin(Path output) throws IOException {
        return begin(output, false);
    }

    /** Begin a transaction; replacement of an existing output requires {@code overwrite}. */
    public static ReportTransaction begin(Path output, boolean overwrite) throws IOException {
        Path target = normalizeOutput(output);
        Path parent = target.getParent();
        if (parent == null) {
            throw new IOException("report output has no parent: " + output);
        }
        ReportLayout.ensureDirectory(parent);
        rejectUnsafePath(target, "report output");
        boolean exists = Files.exists(target, LinkOption.NOFOLLOW_LINKS);
        if (exists) {
            if (!Files.isDirectory(target, LinkOption.NOFOLLOW_LINKS)
                    || ArchiveLimits.isLinkOrReparsePoint(target)) {
                throw new IOException("report output is not a real directory: " + target);
            }
            if (!overwrite) {
                throw new OutputExistsException(target);
            }
        }

        Path staging = createStagingDirectory(parent, target.getFileName().toString());
        try {
            ReportLayout layout = ReportLayout.create(staging);
            // The staging mkdir intentionally changes the parent's directory timestamp.  Capture
            // the post-create identity and verify that exact identity immediately before swap;
            // provider-specific atomic directory handles remain a separate capability gap.
            ArchiveLimits.DirectoryReadSnapshot parentSnapshot =
                    ArchiveLimits.snapshotDirectory(parent, PATH_POLICY,
                            "REPORT_TRANSACTION_PARENT");
            String runId = PROCESS_TOKEN + "-" + Long.toUnsignedString(
                    COUNTER.incrementAndGet(), 36);
            ReportTransaction transaction = new ReportTransaction(target, staging, layout,
                    overwrite, parentSnapshot, runId);
            transaction.writeState(State.WRITING);
            return transaction;
        } catch (IOException | RuntimeException failure) {
            // Keep a visible, bounded recovery directory when possible.  It is never published
            // as the requested output and therefore cannot look like a complete report.
            try {
                AtomicFiles.writeUtf8(staging.resolve("run.json"), stateJson(
                        PROCESS_TOKEN, State.FAILED));
            } catch (IOException ignored) {
                // The original construction error is the useful failure; no unsafe cleanup is
                // attempted on a provider that already rejected the staging boundary.
            }
            throw failure;
        }
    }

    /**
     * Reconcile abandoned run siblings without mutating or publishing them. A complete
     * staging tree is reported as recoverable, while WRITING/FAILED or malformed trees remain
     * explicitly classified. Callers that want to publish a complete orphan must perform an
     * explicit, separately audited recovery action; ordinary scans never auto-promote it.
     */
    public static RecoveryReport reconcileRecovery(Path output) throws IOException {
        Path target = normalizeOutput(output);
        Path parent = target.getParent();
        if (parent == null) {
            throw new IOException("report recovery output has no parent: " + output);
        }
        if (!Files.isDirectory(parent, LinkOption.NOFOLLOW_LINKS)
                || ArchiveLimits.isLinkOrReparsePoint(parent)) {
            throw new IOException("report recovery parent is not a real directory: " + parent);
        }
        rejectUnsafePath(target, "report recovery output");
        List<RecoveryEntry> entries = new ArrayList<>();
        if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) {
            if (!Files.isDirectory(target, LinkOption.NOFOLLOW_LINKS)
                    || ArchiveLimits.isLinkOrReparsePoint(target)) {
                entries.add(new RecoveryEntry(target, RecoveryStatus.UNSAFE_ORPHAN,
                        "REPORT_RECOVERY_TARGET_UNSAFE"));
            } else {
                try {
                    String state = readRunState(target);
                    if (parseState(state) == State.COMPLETE && validStateDocument(state)
                            && hasCompleteLayout(target)) {
                        entries.add(new RecoveryEntry(target, RecoveryStatus.TARGET_COMPLETE,
                                "REPORT_RECOVERY_TARGET_COMPLETE"));
                    } else {
                        entries.add(new RecoveryEntry(target, RecoveryStatus.INVALID_STAGING,
                                "REPORT_RECOVERY_TARGET_INCOMPLETE"));
                    }
                } catch (IOException | RuntimeException failure) {
                    entries.add(new RecoveryEntry(target, RecoveryStatus.INVALID_STAGING,
                            "REPORT_RECOVERY_TARGET_UNREADABLE"));
                }
            }
        }
        String name = target.getFileName().toString();
        String stagingPrefix = "." + name + ".staging-";
        String backupPrefix = "." + name + ".backup-";
        List<Path> siblings;
        try (var stream = Files.list(parent)) {
            siblings = stream.filter(path -> {
                        String child = path.getFileName().toString();
                        return child.startsWith(stagingPrefix) || child.startsWith(backupPrefix);
                    })
                    .sorted(Comparator.comparing(path -> path.getFileName().toString()))
                    .toList();
        }
        if (siblings.size() > MAX_RECOVERY_SIBLINGS) {
            throw new IOException("REPORT_RECOVERY_SIBLING_LIMIT:" + MAX_RECOVERY_SIBLINGS);
        }
        for (Path sibling : siblings) {
            boolean staging = sibling.getFileName().toString().startsWith(stagingPrefix);
            entries.add(inspectRecoverySibling(sibling, staging));
        }
        return new RecoveryReport(target, entries);
    }

    public ReportLayout layout() {
        return layout;
    }

    public Path stagingRoot() {
        return staging;
    }

    public Path runStateFile() {
        return runState;
    }

    public State state() {
        return state;
    }

    /** Publish the entire report tree, or leave the old tree untouched on failure. */
    public synchronized void commit() throws IOException {
        if (committed) {
            throw new IOException("report transaction is already committed");
        }
        if (state != State.WRITING) {
            throw new IOException("report transaction is not writable: " + state);
        }
        verifyStagingLayout();
        ArchiveLimits.verifyDirectoryUnchanged(parentSnapshot, "REPORT_TRANSACTION_PARENT");
        rejectUnsafePath(target, "report output");

        Path backup = null;
        try {
            writeState(State.COMPLETE);
            if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) {
                if (!overwrite) {
                    throw new OutputExistsException(target);
                }
                if (!Files.isDirectory(target, LinkOption.NOFOLLOW_LINKS)
                        || ArchiveLimits.isLinkOrReparsePoint(target)) {
                    throw new IOException("report output changed to an unsafe path: " + target);
                }
                backup = uniqueSibling(target.getParent(), target.getFileName() + ".backup-");
                moveNoReplace(target, backup);
            }
            moveNoReplace(staging, target);
            committed = true;
            state = State.COMPLETE;
            if (backup != null) {
                try {
                    deleteTreeNoFollow(backup);
                } catch (IOException cleanupFailure) {
                    // The new tree is already complete.  Keep the guarded backup for recovery
                    // rather than turning a successful publication into an ambiguous failure.
                }
            }
        } catch (IOException failure) {
            if (backup != null && !Files.exists(target, LinkOption.NOFOLLOW_LINKS)) {
                try {
                    moveNoReplace(backup, target);
                    backup = null;
                } catch (IOException ignored) {
                    // Keep the backup visible for operator recovery; preserve original failure.
                }
            }
            writeFailedBestEffort();
            throw failure;
        }
    }

    /** Mark an uncommitted staging tree failed; it remains available for crash/recovery review. */
    @Override
    public synchronized void close() {
        if (!committed && state != State.FAILED) {
            writeFailedBestEffort();
        }
    }

    private void writeState(State next) throws IOException {
        AtomicFiles.writeUtf8(runState, stateJson(runId, next));
        state = next;
    }

    private void writeFailedBestEffort() {
        try {
            if (Files.isDirectory(staging, LinkOption.NOFOLLOW_LINKS)
                    && !ArchiveLimits.isLinkOrReparsePoint(staging)) {
                writeState(State.FAILED);
            } else {
                state = State.FAILED;
            }
        } catch (IOException ignored) {
            state = State.FAILED;
        }
    }

    private static RecoveryEntry inspectRecoverySibling(Path sibling, boolean staging) {
        try {
            if (!Files.isDirectory(sibling, LinkOption.NOFOLLOW_LINKS)
                    || ArchiveLimits.isLinkOrReparsePoint(sibling)) {
                return new RecoveryEntry(sibling, RecoveryStatus.UNSAFE_ORPHAN,
                        "REPORT_RECOVERY_ORPHAN_UNSAFE");
            }
            String stateText = readRunState(sibling);
            State state = parseState(stateText);
            if (state == null || !validStateDocument(stateText)) {
                return new RecoveryEntry(sibling, RecoveryStatus.INVALID_STAGING,
                        "REPORT_RECOVERY_STATE_INVALID");
            }
            if (staging && state == State.COMPLETE && !hasCompleteLayout(sibling)) {
                return new RecoveryEntry(sibling, RecoveryStatus.INVALID_STAGING,
                        "REPORT_RECOVERY_LAYOUT_INVALID");
            }
            if (!staging) {
                return new RecoveryEntry(sibling, RecoveryStatus.BACKUP_PRESENT,
                        "REPORT_RECOVERY_BACKUP_PRESENT");
            }
            return new RecoveryEntry(sibling,
                    state == State.COMPLETE ? RecoveryStatus.COMPLETE_STAGING
                            : state == State.FAILED ? RecoveryStatus.FAILED_STAGING
                            : RecoveryStatus.WRITING_STAGING,
                    state == State.COMPLETE ? "REPORT_RECOVERY_COMPLETE_STAGING"
                            : state == State.FAILED ? "REPORT_RECOVERY_FAILED_STAGING"
                            : "REPORT_RECOVERY_WRITING_STAGING");
        } catch (IOException | RuntimeException failure) {
            return new RecoveryEntry(sibling, RecoveryStatus.INVALID_STAGING,
                    "REPORT_RECOVERY_STATE_UNREADABLE");
        }
    }

    private static RecoveryDecision toDecision(RecoveryEntry entry) {
        RecoveryAction action;
        String reasonCode;
        switch (entry.status()) {
            case TARGET_COMPLETE -> {
                action = RecoveryAction.NO_ACTION;
                reasonCode = "REPORT_RECOVERY_TARGET_ALREADY_COMPLETE";
            }
            case COMPLETE_STAGING -> {
                action = RecoveryAction.MANUAL_REVIEW_REQUIRED;
                reasonCode = "REPORT_RECOVERY_COMPLETE_STAGING_NOT_AUTO_PUBLISHED";
            }
            case WRITING_STAGING -> {
                action = RecoveryAction.RETAIN_FOR_AUDIT;
                reasonCode = "REPORT_RECOVERY_WRITING_STAGING_RETAINED";
            }
            case FAILED_STAGING -> {
                action = RecoveryAction.RETAIN_FOR_AUDIT;
                reasonCode = "REPORT_RECOVERY_FAILED_STAGING_RETAINED";
            }
            case BACKUP_PRESENT -> {
                action = RecoveryAction.MANUAL_REVIEW_REQUIRED;
                reasonCode = "REPORT_RECOVERY_BACKUP_NOT_AUTO_RESTORED";
            }
            case INVALID_STAGING -> {
                action = RecoveryAction.DO_NOT_MUTATE;
                reasonCode = "REPORT_RECOVERY_INVALID_DO_NOT_MUTATE";
            }
            case UNSAFE_ORPHAN -> {
                action = RecoveryAction.DO_NOT_MUTATE;
                reasonCode = "REPORT_RECOVERY_UNSAFE_DO_NOT_MUTATE";
            }
            default -> throw new IllegalStateException("unhandled recovery status: "
                    + entry.status());
        }
        return new RecoveryDecision(entry.path(), entry.status(), action, reasonCode);
    }

    private static String readRunState(Path root) throws IOException {
        Path normalizedRoot = root.toAbsolutePath().normalize();
        Path state = normalizedRoot.resolve("run.json").normalize();
        if (!state.startsWith(normalizedRoot)
                || !Files.isRegularFile(state, LinkOption.NOFOLLOW_LINKS)
                || ArchiveLimits.isLinkOrReparsePoint(state)) {
            throw new IOException("REPORT_RECOVERY_STATE_MISSING");
        }
        ArchiveLimits.FileReadSnapshot snapshot = ArchiveLimits.snapshotRegularFile(
                state, PATH_POLICY, "REPORT_RECOVERY_STATE");
        if (snapshot.fileAttributes().size() > MAX_RECOVERY_STATE_BYTES) {
            throw new IOException("REPORT_RECOVERY_STATE_LIMIT:" + MAX_RECOVERY_STATE_BYTES);
        }
        byte[] bytes;
        try (io.just.sast.util.IoUtil.OpenedInput opened =
                     io.just.sast.util.IoUtil.openRegularFile(state, "REPORT_RECOVERY_STATE")) {
            bytes = io.just.sast.util.IoUtil.readAll(opened.stream(), MAX_RECOVERY_STATE_BYTES);
        }
        ArchiveLimits.verifyRegularFileUnchanged(snapshot, "REPORT_RECOVERY_STATE");
        return new String(bytes, StandardCharsets.UTF_8);
    }

    private static State parseState(String text) {
        if (text == null) {
            return null;
        }
        for (State candidate : State.values()) {
            if (text.contains("\"state\":\"" + candidate.name() + "\"")) {
                return candidate;
            }
        }
        return null;
    }

    private static boolean validStateDocument(String text) {
        return text != null && text.contains("\"schema_version\":\"" + SCHEMA + "\"")
                && text.contains("\"run_id\":\"");
    }

    private static boolean hasCompleteLayout(Path root) {
        if (root == null || !Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS)
                || ArchiveLimits.isLinkOrReparsePoint(root)) {
            return false;
        }
        for (String child : new String[] {"evidence", "meta"}) {
            Path directory = root.resolve(child);
            if (!Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)
                    || ArchiveLimits.isLinkOrReparsePoint(directory)) {
                return false;
            }
        }
        Path state = root.resolve("run.json");
        return Files.isRegularFile(state, LinkOption.NOFOLLOW_LINKS)
                && !ArchiveLimits.isLinkOrReparsePoint(state);
    }

    private void verifyStagingLayout() throws IOException {
        rejectUnsafePath(staging, "report staging");
        if (!Files.isDirectory(staging, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("report staging is missing: " + staging);
        }
        for (Path directory : new Path[] { layout.evidence(), layout.meta() }) {
            rejectUnsafePath(directory, "report staging directory");
            if (!Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)) {
                throw new IOException("report staging directory is missing: " + directory);
            }
        }
        if (!Files.isRegularFile(runState, LinkOption.NOFOLLOW_LINKS)
                || ArchiveLimits.isLinkOrReparsePoint(runState)) {
            throw new IOException("report run state is not a regular file");
        }
    }

    private static Path normalizeOutput(Path output) throws IOException {
        if (output == null) {
            throw new IOException("report output is required");
        }
        try {
            return output.toAbsolutePath().normalize();
        } catch (RuntimeException invalid) {
            throw new IOException("report output path is invalid", invalid);
        }
    }

    private static void rejectUnsafePath(Path path, String label) throws IOException {
        if (path == null || ArchiveLimits.isLinkOrReparsePoint(path)) {
            throw new IOException(label + " cannot be a link or reparse point: " + path);
        }
    }

    private static Path createStagingDirectory(Path parent, String name) throws IOException {
        for (int attempt = 0; attempt < 32; attempt++) {
            Path candidate = uniqueSibling(parent, "." + name + ".staging-");
            try {
                Files.createDirectory(candidate);
                return candidate;
            } catch (FileAlreadyExistsException collision) {
                // CREATE_NEW-style collision retry; no existing directory is reused.
            }
        }
        throw new IOException("unable to allocate unique report staging directory");
    }

    private static Path uniqueSibling(Path parent, String prefix) throws IOException {
        if (parent == null || prefix == null || prefix.isBlank()) {
            throw new IOException("invalid report sibling path");
        }
        long counter = COUNTER.incrementAndGet();
        Path candidate = parent.resolve(prefix + PROCESS_TOKEN + "-"
                + Long.toUnsignedString(System.nanoTime(), 36) + "-"
                + Long.toUnsignedString(counter, 36)).toAbsolutePath().normalize();
        if (!candidate.startsWith(parent.toAbsolutePath().normalize())) {
            throw new IOException("report sibling escapes parent");
        }
        return candidate;
    }

    private static void moveNoReplace(Path source, Path target) throws IOException {
        try {
            Files.move(source, target, StandardCopyOption.ATOMIC_MOVE);
        } catch (java.nio.file.AtomicMoveNotSupportedException unsupported) {
            Files.move(source, target);
        }
    }

    private static String stateJson(String runId, State state) {
        return "{\"schema_version\":\"" + SCHEMA + "\",\"run_id\":\""
                + runId + "\",\"state\":\"" + state.name() + "\"}\n";
    }

    /** Delete only the moved-aside tree, never following symlinks/reparse points. */
    private static void deleteTreeNoFollow(Path root) throws IOException {
        if (!Files.exists(root, LinkOption.NOFOLLOW_LINKS)) {
            return;
        }
        Files.walkFileTree(root, java.util.EnumSet.noneOf(java.nio.file.FileVisitOption.class),
                MAX_DELETE_DEPTH, new SimpleFileVisitor<>() {
                    @Override
                    public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs)
                            throws IOException {
                        if (ArchiveLimits.isLinkOrReparsePoint(dir)) {
                            Files.deleteIfExists(dir);
                            return FileVisitResult.SKIP_SUBTREE;
                        }
                        return FileVisitResult.CONTINUE;
                    }

                    @Override
                    public FileVisitResult visitFile(Path file, BasicFileAttributes attrs)
                            throws IOException {
                        Files.deleteIfExists(file);
                        return FileVisitResult.CONTINUE;
                    }

                    @Override
                    public FileVisitResult postVisitDirectory(Path dir, IOException failure)
                            throws IOException {
                        if (failure != null) {
                            throw failure;
                        }
                        Files.deleteIfExists(dir);
                        return FileVisitResult.CONTINUE;
                    }
                });
    }
}
