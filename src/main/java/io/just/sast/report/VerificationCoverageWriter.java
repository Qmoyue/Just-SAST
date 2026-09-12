package io.just.sast.report;

import io.just.sast.blackboard.VerificationCoverage;

import java.io.IOException;

/** Writes the typed finding-group to dynamic-plan coverage contract as metadata. */
public final class VerificationCoverageWriter {

    public void write(ReportLayout layout, VerificationCoverage coverage) throws IOException {
        if (layout == null || coverage == null) {
            throw new IOException("verification coverage report requires layout and coverage");
        }
        AtomicFiles.writeUtf8(layout.meta().resolve("verification-coverage.json"),
                coverage.toCanonicalJson() + "\n");
    }
}
