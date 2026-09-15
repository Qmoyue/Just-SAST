package io.just.sast.report;

import io.just.sast.util.InputDigestVerification;

import java.io.IOException;

/** Publishes scan input before/after digest evidence without embedding local paths. */
public final class InputDigestWriter {

    public void write(ReportLayout layout, InputDigestVerification verification) throws IOException {
        if (layout == null || verification == null) {
            throw new IOException("input digest report requires layout and digest snapshot");
        }
        StringBuilder json = new StringBuilder(512);
        json.append("{\n")
                .append("  \"schema_version\":1,\n")
                .append("  \"status\":\"").append(esc(verification.status())).append("\",\n")
                .append("  \"target\":{\"before\":\"")
                .append(esc(verification.targetBefore())).append("\",\"after\":\"")
                .append(esc(verification.targetAfter())).append("\"},\n")
                .append("  \"dependencies\":[");
        for (int i = 0; i < verification.dependencyBefore().size(); i++) {
            if (i > 0) json.append(',');
            String before = verification.dependencyBefore().get(i);
            String after = i < verification.dependencyAfter().size()
                    ? verification.dependencyAfter().get(i) : "UNKNOWN";
            json.append("{\"index\":").append(i)
                    .append(",\"before\":\"").append(esc(before))
                    .append("\",\"after\":\"").append(esc(after)).append("\"}");
        }
        json.append("],\n  \"reasons\":[");
        for (int i = 0; i < verification.reasons().size(); i++) {
            if (i > 0) json.append(',');
            json.append('"').append(esc(verification.reasons().get(i))).append('"');
        }
        json.append("]\n}\n");
        AtomicFiles.writeUtf8(layout.meta().resolve("input-digest.json"), json.toString());
    }

    private static String esc(String value) {
        return value == null ? "" : value.replace("\\", "\\\\")
                .replace("\"", "\\\"").replace("\r", "\\r").replace("\n", "\\n");
    }
}
