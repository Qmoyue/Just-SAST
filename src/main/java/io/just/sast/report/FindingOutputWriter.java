package io.just.sast.report;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Objects;

/** Writes the canonical typed finding snapshot used by migrated report consumers. */
public final class FindingOutputWriter {

    public Path write(ReportLayout layout, FindingOutputReader.Snapshot snapshot) throws IOException {
        Objects.requireNonNull(layout, "layout");
        Objects.requireNonNull(snapshot, "snapshot");
        Path path = layout.meta().resolve("finding-output.json");
        AtomicFiles.writeUtf8(path, snapshot.toCanonicalJson() + "\n");
        return path;
    }
}
