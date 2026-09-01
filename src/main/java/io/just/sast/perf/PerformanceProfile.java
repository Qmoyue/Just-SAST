package io.just.sast.perf;

import io.just.sast.util.ArchiveLimits;

import java.io.IOException;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
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
            "dynamic_p50_ms", "dynamic_p95_ms");

    public record Limits(long wallP50Ms, long wallP95Ms,
                         long staticP50Ms, long staticP95Ms,
                         long dynamicP50Ms, long dynamicP95Ms) {
        public Limits {
            wallP50Ms = nonNegative(wallP50Ms, "wall_p50_ms");
            wallP95Ms = nonNegative(wallP95Ms, "wall_p95_ms");
            staticP50Ms = nonNegative(staticP50Ms, "static_p50_ms");
            staticP95Ms = nonNegative(staticP95Ms, "static_p95_ms");
            dynamicP50Ms = nonNegative(dynamicP50Ms, "dynamic_p50_ms");
            dynamicP95Ms = nonNegative(dynamicP95Ms, "dynamic_p95_ms");
        }

        /** A profile with no enabled dimension cannot act as a release gate. */
        public boolean hasEnabledLimit() {
            return wallP50Ms > 0L || wallP95Ms > 0L
                    || staticP50Ms > 0L || staticP95Ms > 0L
                    || dynamicP50Ms > 0L || dynamicP95Ms > 0L;
        }
    }

    private PerformanceProfile() {
    }

    /** Read a UTF-8 Java-properties profile without following links or accepting unknown keys. */
    public static Limits read(Path file) throws IOException {
        Path normalized = validateFile(file);
        Properties properties = new Properties();
        try (Reader reader = Files.newBufferedReader(normalized, StandardCharsets.UTF_8)) {
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
                value(properties, "dynamic_p50_ms"),
                value(properties, "dynamic_p95_ms"));
        if (!limits.hasEnabledLimit()) {
            throw new IOException("performance profile enables no limit");
        }
        return limits;
    }

    private static Path validateFile(Path file) throws IOException {
        if (file == null) {
            throw new IOException("performance profile is missing");
        }
        Path normalized = file.toAbsolutePath().normalize();
        if (!Files.isRegularFile(normalized, LinkOption.NOFOLLOW_LINKS)
                || ArchiveLimits.isLinkOrReparsePoint(normalized)) {
            throw new IOException("performance profile is not a regular non-link file");
        }
        if (Files.size(normalized) > MAX_BYTES) {
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

    private static long nonNegative(long value, String key) {
        if (value < 0L) {
            throw new IllegalArgumentException(key + " must be non-negative");
        }
        return value;
    }
}
