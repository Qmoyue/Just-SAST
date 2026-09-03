package io.just.sast.report;

import io.just.sast.util.ArchiveLimits;
import io.just.sast.util.ArtifactFingerprint;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Locale;

/** Writes the path-free identity used to invalidate future incremental caches. */
public final class ScanIdentityWriter {

    public static final String ENGINE_VERSION = "0.2.0";

    public String write(ReportLayout layout, String artifactHash, String dependencyHash,
                        Path rules, Path jdkHome, int targetMajorVersion,
                        boolean fast, boolean verify, int verifyBudget, boolean safeExec,
                        boolean requireOsIsolation) throws IOException {
        return write(layout, artifactHash, dependencyHash, dependencyHash, rules, jdkHome,
                targetMajorVersion, fast, verify, verifyBudget, safeExec,
                false, requireOsIsolation);
    }

    /**
     * Write the final identity while keeping the cache input identity separate from the
     * generated inventory's own hash. The former can be calculated before analysis; the latter
     * is useful for auditing the published SBOM and may include platform entries discovered
     * only after the frontend has identified the target class version.
     */
    public String write(ReportLayout layout, String artifactHash, String dependencyIdentityHash,
                        String inventoryHash, Path rules, Path jdkHome, int targetMajorVersion,
                        boolean fast, boolean verify, int verifyBudget, boolean safeExec,
                        boolean requireOsIsolation) throws IOException {
        return write(layout, artifactHash, dependencyIdentityHash, inventoryHash, rules, jdkHome,
                targetMajorVersion, fast, verify, verifyBudget, safeExec, false,
                requireOsIsolation);
    }

    public String write(ReportLayout layout, String artifactHash, String dependencyIdentityHash,
                        String inventoryHash, Path rules, Path jdkHome, int targetMajorVersion,
                        boolean fast, boolean verify, int verifyBudget, boolean safeExec,
                        boolean safeReal, boolean requireOsIsolation) throws IOException {
        String rulesHash = rulesHash(rules);
        String jdkIdentity = jdkIdentity(jdkHome, targetMajorVersion);
        String parameters = "fast=" + fast + ";verify=" + verify + ";verify_budget="
                + Math.max(0, verifyBudget) + ";safe_exec=" + safeExec
                + ";safe_real=" + safeReal
                + ";os_isolation=" + requireOsIsolation;
        String canonical = String.join("\n", ENGINE_VERSION, value(artifactHash),
                value(dependencyIdentityHash), rulesHash, jdkIdentity, parameters);
        String cacheKey = digest(canonical);
        String json = "{\n"
                + "  \"schema_version\":1,\n"
                + "  \"engine_version\":\"" + json(ENGINE_VERSION) + "\",\n"
                + "  \"cache_key\":\"" + json(cacheKey) + "\",\n"
                + "  \"artifact_sha256\":\"" + json(value(artifactHash)) + "\",\n"
                + "  \"dependency_identity_sha256\":\""
                + json(value(dependencyIdentityHash)) + "\",\n"
                + "  \"dependency_inventory_sha256\":\"" + json(value(inventoryHash)) + "\",\n"
                + "  \"rules_sha256\":\"" + json(rulesHash) + "\",\n"
                + "  \"jdk_identity\":\"" + json(jdkIdentity) + "\",\n"
                + "  \"target_major_version\":" + Math.max(0, targetMajorVersion) + ",\n"
                + "  \"parameters\":\"" + json(parameters) + "\"\n"
                + "}\n";
        AtomicFiles.writeUtf8(layout.meta().resolve("scan-identity.json"), json);
        return cacheKey;
    }

    /** Compute the same path-free key used by the published identity before static analysis. */
    public static String cacheKey(String artifactHash, String dependencyIdentityHash,
                                  Path rules, Path jdkHome,
                                  boolean fast, boolean verify, int verifyBudget,
                                  boolean safeExec, boolean requireOsIsolation) throws IOException {
        return cacheKey(artifactHash, dependencyIdentityHash, rules, jdkHome, fast, verify,
                verifyBudget, safeExec, false, requireOsIsolation);
    }

    /** Compute a cache identity that includes the explicit SAFE_REAL adapter mode. */
    public static String cacheKey(String artifactHash, String dependencyIdentityHash,
                                  Path rules, Path jdkHome,
                                  boolean fast, boolean verify, int verifyBudget,
                                  boolean safeExec, boolean safeReal,
                                  boolean requireOsIsolation) throws IOException {
        String parameters = "fast=" + fast + ";verify=" + verify + ";verify_budget="
                + Math.max(0, verifyBudget) + ";safe_exec=" + safeExec
                + ";safe_real=" + safeReal
                + ";os_isolation=" + requireOsIsolation;
        String canonical = String.join("\n", ENGINE_VERSION, value(artifactHash),
                value(dependencyIdentityHash), rulesHash(rules), jdkIdentity(jdkHome, 0),
                parameters);
        return digest(canonical);
    }

    static String rulesHash(Path rules) throws IOException {
        if (rules != null) {
            return ArtifactFingerprint.sha256(rules);
        }
        try (InputStream input = ScanIdentityWriter.class
                .getResourceAsStream("/rules/default-rules.yaml")) {
            if (input == null) {
                throw new IOException("default rules resource missing");
            }
            return digest(input, 2L * 1024L * 1024L);
        }
    }

    static String jdkIdentity(Path jdkHome, int targetMajorVersion) throws IOException {
        Path selectedHome = jdkHome;
        if (selectedHome == null) {
            selectedHome = Paths.get(System.getProperty("java.home", "."));
        }
        Path release = selectedHome.toAbsolutePath().normalize().resolve("release");
        if (Files.isRegularFile(release) && !ArchiveLimits.isLinkOrReparsePoint(release)) {
            // The artifact digest already binds the target classfile major version. Keeping the
            // JDK identity independent of the frontend's discovered major lets cache lookup
            // happen before parsing without weakening invalidation.
            return "release-sha256=" + ArtifactFingerprint.sha256(release);
        }
        return "runtime-feature=" + Runtime.version().feature()
                + ";requested=" + (jdkHome == null ? "runtime" : "requested");
    }

    private static String digest(InputStream input, long limit) throws IOException {
        MessageDigest digest = sha256();
        byte[] buffer = new byte[16 * 1024];
        long total = 0L;
        for (int read; (read = input.read(buffer)) >= 0; ) {
            if (read == 0) {
                continue;
            }
            if (read > limit - total) {
                throw new IOException("identity input exceeds limit");
            }
            digest.update(buffer, 0, read);
            total += read;
        }
        return hex(digest.digest());
    }

    private static String digest(String value) {
        MessageDigest digest = sha256();
        digest.update(value.getBytes(StandardCharsets.UTF_8));
        return hex(digest.digest());
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("sha256-unavailable", impossible);
        }
    }

    private static String hex(byte[] bytes) {
        StringBuilder value = new StringBuilder(bytes.length * 2);
        for (byte item : bytes) {
            value.append(String.format(Locale.ROOT, "%02x", item & 0xff));
        }
        return value.toString();
    }

    private static String value(String value) {
        return value == null || value.isBlank() ? "UNKNOWN" : value;
    }

    private static String json(String value) {
        return value == null ? "" : value.replace("\\", "\\\\")
                .replace("\"", "\\\"").replace("\r", "\\r").replace("\n", "\\n");
    }
}
