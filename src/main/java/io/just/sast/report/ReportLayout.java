package io.just.sast.report;

import io.just.sast.util.ArchiveLimits;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;

/**
 * 扫描产物的唯一目录契约。
 *
 * <p>生产扫描按使用者任务分为 findings、verification、evidence 和 meta；flat
 * 只作为 reporter 旧 API 的兼容适配，不被 ScanPipeline 使用。</p>
 */
public record ReportLayout(Path root, Path findings, Path verification,
                           Path evidence, Path meta) {

    public ReportLayout {
        root = root.toAbsolutePath().normalize();
        findings = findings.toAbsolutePath().normalize();
        verification = verification.toAbsolutePath().normalize();
        evidence = evidence.toAbsolutePath().normalize();
        meta = meta.toAbsolutePath().normalize();
    }

    public static ReportLayout create(Path root) throws IOException {
        Path normalized = root.toAbsolutePath().normalize();
        Path findings = normalized.resolve("findings");
        Path verification = normalized.resolve("verification");
        Path evidence = normalized.resolve("evidence");
        Path meta = normalized.resolve("meta");
        ensureDirectory(normalized);
        ensureDirectory(findings);
        ensureDirectory(verification);
        ensureDirectory(evidence);
        ensureDirectory(meta);
        return new ReportLayout(normalized, findings, verification, evidence, meta);
    }

    /** Compatibility layout for direct reporter callers and older integrations. */
    public static ReportLayout flat(Path root) throws IOException {
        Path normalized = root.toAbsolutePath().normalize();
        ensureDirectory(normalized);
        return new ReportLayout(normalized, normalized, normalized, normalized, normalized);
    }

    private static void ensureDirectory(Path directory) throws IOException {
        if (Files.exists(directory, LinkOption.NOFOLLOW_LINKS)
                && (ArchiveLimits.isLinkOrReparsePoint(directory)
                || !Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS))) {
            throw new IOException("report directory is not a real directory: " + directory);
        }
        Files.createDirectories(directory);
        if (ArchiveLimits.isLinkOrReparsePoint(directory)
                || !Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("report directory is not a real directory: " + directory);
        }
    }
}
