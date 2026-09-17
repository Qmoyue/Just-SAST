package io.just.sast.report;

import java.io.IOException;
import java.util.Objects;

/** Writes report.json and report.md from one immutable V2 projection. */
public final class ConciseReportWriter {

    public static final String SCHEMA_VERSION = ConciseReportProjection.SCHEMA_VERSION;

    public void write(ReportLayout layout, String mode,
                      FindingOutputReader.Snapshot snapshot,
                      ScanStatistics statistics) throws IOException {
        Objects.requireNonNull(layout, "report layout");
        ConciseReportProjection projection = ConciseReportProjection.from(mode, snapshot,
                statistics);
        AtomicFiles.writeUtf8(layout.root().resolve("report.json"), projection.toJson() + "\n");
        AtomicFiles.writeUtf8(layout.root().resolve("report.md"), projection.toMarkdown());
    }
}
