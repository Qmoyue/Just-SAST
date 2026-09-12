package io.just.sast.report;

import io.just.sast.analysis.entry.ApplicationChainEvidence;

import java.io.IOException;

/** Publishes the typed application-chain join product as an atomic metadata artifact. */
public final class ApplicationChainEvidenceWriter {

    public void write(ReportLayout layout, ApplicationChainEvidence evidence) throws IOException {
        if (layout == null || evidence == null) {
            throw new IOException("application-chain evidence report requires layout and evidence");
        }
        AtomicFiles.writeUtf8(layout.meta().resolve("application-chain-evidence.json"),
                evidence.toCanonicalJson() + "\n");
    }
}
