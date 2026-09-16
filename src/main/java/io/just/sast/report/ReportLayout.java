package io.just.sast.report;

import io.just.sast.util.ArchiveLimits;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;

/**
 * 扫描产物的唯一目录契约。
 *
 * <p>生产扫描按使用者任务分为两个主报告和 evidence/meta 追溯目录。可选格式也属于
 * evidence，不创建第二个 findings 目录；flat 只供直接 reporter 调用。</p>
 */
public record ReportLayout(Path root, Path evidence, Path meta) {

    public ReportLayout {
        root = root.toAbsolutePath().normalize();
        evidence = evidence.toAbsolutePath().normalize();
        meta = meta.toAbsolutePath().normalize();
    }

    public static ReportLayout create(Path root) throws IOException {
        Path normalized = root.toAbsolutePath().normalize();
        Path evidence = normalized.resolve("evidence");
        Path meta = normalized.resolve("meta");
        ensureDirectory(normalized);
        ensureDirectory(evidence);
        ensureDirectory(meta);
        return new ReportLayout(normalized, evidence, meta);
    }

    /** Compatibility layout for direct reporter callers and older integrations. */
    public static ReportLayout flat(Path root) throws IOException {
        Path normalized = root.toAbsolutePath().normalize();
        ensureDirectory(normalized);
        return new ReportLayout(normalized, normalized, normalized);
    }

    /** Create each parent component without following a link/reparse point. */
    static void ensureDirectory(Path directory) throws IOException {
        if (directory == null) {
            throw new IOException("report directory is missing");
        }
        Path normalized = directory.toAbsolutePath().normalize();
        Path current = normalized.getRoot();
        if (current == null || ArchiveLimits.isLinkOrReparsePoint(current)) {
            throw new IOException("report directory root is unsafe: " + directory);
        }
        for (Path component : normalized) {
            current = current.resolve(component);
            if (Files.exists(current, LinkOption.NOFOLLOW_LINKS)) {
                if (ArchiveLimits.isLinkOrReparsePoint(current)
                        || !Files.isDirectory(current, LinkOption.NOFOLLOW_LINKS)) {
                    throw new IOException("report directory is not a real directory: " + current);
                }
            } else {
                try {
                    Files.createDirectory(current);
                } catch (java.nio.file.FileAlreadyExistsException raced) {
                    if (ArchiveLimits.isLinkOrReparsePoint(current)
                            || !Files.isDirectory(current, LinkOption.NOFOLLOW_LINKS)) {
                        throw new IOException("report directory is not a real directory: "
                                + current, raced);
                    }
                }
            }
            if (ArchiveLimits.isLinkOrReparsePoint(current)
                    || !Files.isDirectory(current, LinkOption.NOFOLLOW_LINKS)) {
                throw new IOException("report directory changed during creation: " + current);
            }
        }
    }
}
