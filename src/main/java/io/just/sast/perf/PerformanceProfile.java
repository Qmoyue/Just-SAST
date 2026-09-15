package io.just.sast.perf;

import io.just.sast.util.ArchiveLimits;
import io.just.sast.run.InputBudget;
import io.just.sast.util.IoUtil;

import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.Properties;
import java.util.Set;

/**
 * Host-local performance gate configuration.
 *
 * <p>The file intentionally contains only numeric limits.  It is a deployment profile, not a
 * baseline snapshot: input identity, JDK, rules and CLI options still come from the command and
 * are recorded by the scan itself.  Keeping this parser separate makes the gate testable without
 * starting a scan and prevents a malformed profile from silently disabling a release check.</p>
 */
public final class PerformanceProfile {

    private static final long MAX_BYTES = 64L * 1024L;
    private static final Set<String> KEYS = Set.of(
            "wall_p50_ms", "wall_p95_ms", "static_p50_ms", "static_p95_ms",
            "filter_p50_ms", "filter_p95_ms");

    public record Limits(long wallP50Ms, long wallP95Ms,
                         long staticP50Ms, long staticP95Ms,
                         long filterP50Ms, long filterP95Ms) {
        public Limits {
            wallP50Ms = nonNegative(wallP50Ms, "wall_p50_ms");
            wallP95Ms = nonNegative(wallP95Ms, "wall_p95_ms");
            staticP50Ms = nonNegative(staticP50Ms, "static_p50_ms");
            staticP95Ms = nonNegative(staticP95Ms, "static_p95_ms");
            filterP50Ms = nonNegative(filterP50Ms, "filter_p50_ms");
            filterP95Ms = nonNegative(filterP95Ms, "filter_p95_ms");
        }

        /** A profile with no enabled dimension cannot act as a release gate. */
        public boolean hasEnabledLimit() {
            return wallP50Ms > 0L || wallP95Ms > 0L
                    || staticP50Ms > 0L || staticP95Ms > 0L
                    || filterP50Ms > 0L || filterP95Ms > 0L;
        }
    }

    private PerformanceProfile() {
    }

    /** Read a UTF-8 Java-properties profile without following links or accepting unknown keys. */
    public static Limits read(Path file) throws IOException {
        return read(file, InputBudget.defaults());
    }

    /** Read a profile under the same immutable input policy used by scan configuration. */
    public static Limits read(Path file, InputBudget budget) throws IOException {
        InputBudget policy = budget == null ? InputBudget.defaults() : budget;
        Path normalized = validateFile(file, policy);
        ArchiveLimits.FileReadSnapshot snapshot = ArchiveLimits.snapshotRegularFile(
                normalized, policy, "PERFORMANCE_PROFILE");
        Properties properties = new Properties();
        InputBudget.Tracker tracker = policy.tracker();
        byte[] source;
        try (IoUtil.OpenedInput opened = IoUtil.openRegularFile(normalized,
                "PERFORMANCE_PROFILE");
             java.io.InputStream input = opened.stream()) {
            source = IoUtil.readAll(input, Math.min(MAX_BYTES, policy.maxEntryBytes()), tracker);
        } catch (IOException failure) {
            if (isInputLimitFailure(failure)) {
                throw new IOException("PERFORMANCE_PROFILE_INPUT_LIMIT", failure);
            }
            if (failure instanceof NoSuchFileException) {
                throw new IOException("PERFORMANCE_PROFILE_CHANGED_DURING_READ", failure);
            }
            throw new IOException("PERFORMANCE_PROFILE_READ_FAILED", failure);
        }
        ArchiveLimits.verifyRegularFileUnchanged(snapshot, "PERFORMANCE_PROFILE");
        try (Reader reader = new StringReader(new String(source, StandardCharsets.UTF_8))) {
            properties.load(reader);
        }
        Set<String> unknown = new LinkedHashSet<>();
        for (String key : properties.stringPropertyNames()) {
            if (!KEYS.contains(key)) {
                unknown.add(key);
            }
        }
        if (!unknown.isEmpty()) {
            throw new IOException("unknown performance profile key(s): " + unknown);
        }
        Limits limits = new Limits(value(properties, "wall_p50_ms"),
                value(properties, "wall_p95_ms"),
                value(properties, "static_p50_ms"),
                value(properties, "static_p95_ms"),
                value(properties, "filter_p50_ms"),
                value(properties, "filter_p95_ms"));
        if (!limits.hasEnabledLimit()) {
            throw new IOException("performance profile enables no limit");
        }
        return limits;
    }

    private static Path validateFile(Path file, InputBudget budget) throws IOException {
        if (file == null) {
            throw new IOException("performance profile is missing");
        }
        Path normalized = file.toAbsolutePath().normalize();
        ArchiveLimits.checkPathAncestors(normalized, budget);
        if (normalized.toString().codePointCount(0, normalized.toString().length())
                > budget.maxPathChars()) {
            throw new IOException("performance profile path is too long");
        }
        if (!Files.isRegularFile(normalized, LinkOption.NOFOLLOW_LINKS)
                || ArchiveLimits.isLinkOrReparsePoint(normalized)) {
            throw new IOException("performance profile is not a regular non-link file");
        }
        long size = Files.size(normalized);
        if (size > MAX_BYTES || size > budget.maxPhysicalBytes()
                || size > budget.maxEntryBytes()) {
            throw new IOException("performance profile is too large");
        }
        return normalized;
    }

    private static long value(Properties properties, String key) throws IOException {
        String text = properties.getProperty(key);
        if (text == null || text.isBlank()) {
            return 0L;
        }
        try {
            long value = Long.parseLong(text.strip());
            return nonNegative(value, key);
        } catch (NumberFormatException failure) {
            throw new IOException("invalid performance profile value for " + key, failure);
        }
    }

    private static boolean isInputLimitFailure(IOException failure) {
        String message = failure.getMessage();
        return message != null && (message.startsWith("条目超过单条目上限")
                || message.startsWith("archive bytes read exceed limit")
                || message.startsWith("archive container bytes read exceed limit")
                || message.startsWith("INPUT_STREAM_NO_PROGRESS")
                || message.startsWith("INPUT_PARSE_TIME_CAP"));
    }

    /** Package-local hostile contract seam; production reads use the same identity checks. */
    static ArchiveLimits.FileReadSnapshot snapshotForContract(Path file) throws IOException {
        return ArchiveLimits.snapshotRegularFile(file, InputBudget.defaults(),
                "PERFORMANCE_PROFILE");
    }

    /** Package-local hostile contract seam; production reads use the same identity checks. */
    static void verifySnapshotForContract(ArchiveLimits.FileReadSnapshot snapshot)
            throws IOException {
        ArchiveLimits.verifyRegularFileUnchanged(snapshot, "PERFORMANCE_PROFILE");
    }

    private static long nonNegative(long value, String key) {
        if (value < 0L) {
            throw new IllegalArgumentException(key + " must be non-negative");
        }
        return value;
    }
}
