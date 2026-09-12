package io.just.sast.blackboard;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/** Package-private canonicalization shared by the evidence IDs and graph. */
final class EvidenceIdSupport {
    private EvidenceIdSupport() {
    }

    static String id(String prefix, String... parts) {
        StringBuilder canonical = new StringBuilder();
        for (String part : parts) {
            String value = part == null ? "<null>" : part;
            canonical.append(value.length()).append(':').append(value).append('|');
        }
        return prefix + '-' + sha256(canonical.toString());
    }

    static String requireId(String prefix, String value) {
        if (value == null || !value.matches(prefix + "-[0-9a-f]{64}")) {
            throw new IllegalArgumentException(prefix + " must be a lowercase SHA-256 id: " + value);
        }
        return value;
    }

    static String requireText(String field, String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
        return value.trim();
    }

    static String normalize(String value) {
        return value == null || value.isBlank() ? "UNKNOWN" : value.trim();
    }

    static String sha256(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] bytes = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder result = new StringBuilder(bytes.length * 2);
            for (byte current : bytes) {
                result.append(String.format(java.util.Locale.ROOT, "%02x", current & 0xff));
            }
            return result.toString();
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
    }

    static String json(String value) {
        String text = value == null ? "" : value;
        StringBuilder result = new StringBuilder(text.length() + 8);
        for (int i = 0; i < text.length(); i++) {
            char current = text.charAt(i);
            switch (current) {
                case '"' -> result.append("\\\"");
                case '\\' -> result.append("\\\\");
                case '\b' -> result.append("\\b");
                case '\f' -> result.append("\\f");
                case '\n' -> result.append("\\n");
                case '\r' -> result.append("\\r");
                case '\t' -> result.append("\\t");
                default -> {
                    if (current < 0x20) {
                        result.append(String.format(java.util.Locale.ROOT, "\\u%04x", (int) current));
                    } else {
                        result.append(current);
                    }
                }
            }
        }
        return result.toString();
    }
}
