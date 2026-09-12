package io.just.sast.report;

import io.just.sast.config.RuleSchemaV2;
import io.just.sast.config.RuleSet;

import java.io.IOException;
import java.nio.file.Path;

/**
 * Writes the v1/v2 rules migration shadow next to a scan's metadata.  This is deliberately an
 * additive artifact: findings.json and the other user-facing legacy renderers remain unchanged
 * until P1.7 promotes the typed reader.  Every rule carries explicit difference categories and
 * the document has a deterministic digest for CI diffing.
 */
public final class RuleSchemaShadowWriter {

    public Path write(ReportLayout layout, RuleSet legacyRules) throws IOException {
        if (layout == null) {
            throw new IOException("report layout is null");
        }
        RuleSchemaV2.Shadow shadow = RuleSchemaV2.shadow(legacyRules);
        String json = shadow.toCanonicalJson() + "\n";
        Path path = layout.meta().resolve("rules-v2-shadow.json");
        AtomicFiles.writeUtf8(path, json);
        return path;
    }
}
