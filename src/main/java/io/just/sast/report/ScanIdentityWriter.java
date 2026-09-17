package io.just.sast.report;

import io.just.sast.util.ArchiveLimits;
import io.just.sast.util.ArtifactFingerprint;
import io.just.sast.config.RuleSchemaV2;
import io.just.sast.model.JdkSourceInfo;
import io.just.sast.run.InputBudget;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Locale;

/** Writes the path-free identity used to invalidate future incremental caches. */
public final class ScanIdentityWriter {

    public static final String ENGINE_VERSION = "0.2.1";
    public static final String FILTER_SEMANTICS_VERSION = "bounded-static-filter-v1";

    public String write(ReportLayout layout, String artifactHash, String dependencyHash,
                        Path rules, Path jdkHome, int targetMajorVersion,
                        boolean fast, String mode) throws IOException {
        return write(layout, artifactHash, dependencyHash, dependencyHash, rules, jdkHome,
                targetMajorVersion, fast, mode, InputBudget.defaults(),
                InputBudget.defaults().tracker(), null);
    }

    /**
     * Write the final identity while keeping the cache input identity separate from the
     * generated inventory's own hash. The former can be calculated before analysis; the latter
     * is useful for auditing the published SBOM and may include platform entries discovered
     * only after the frontend has identified the target class version.
     */
    public String write(ReportLayout layout, String artifactHash, String dependencyIdentityHash,
                        String inventoryHash, Path rules, Path jdkHome, int targetMajorVersion,
                        boolean fast, String mode) throws IOException {
        return write(layout, artifactHash, dependencyIdentityHash, inventoryHash, rules, jdkHome,
                targetMajorVersion, fast, mode, InputBudget.defaults(),
                InputBudget.defaults().tracker(), null);
    }

    public String write(ReportLayout layout, String artifactHash, String dependencyIdentityHash,
                        String inventoryHash, Path rules, Path jdkHome, int targetMajorVersion,
                        boolean fast, String mode, InputBudget budget) throws IOException {
        InputBudget policy = budget == null ? InputBudget.defaults() : budget;
        return write(layout, artifactHash, dependencyIdentityHash, inventoryHash, rules, jdkHome,
                targetMajorVersion, fast, mode, policy, policy.tracker(), null);
    }

    /** Write identity with an explicit input-policy version/digest for cache invalidation. */
    public String write(ReportLayout layout, String artifactHash, String dependencyIdentityHash,
                        String inventoryHash, Path rules, Path jdkHome, int targetMajorVersion,
                        boolean fast, String mode, InputBudget budget,
                        InputBudget.Tracker tracker) throws IOException {
        InputBudget policy = budget == null ? InputBudget.defaults() : budget;
        return write(layout, artifactHash, dependencyIdentityHash, inventoryHash, rules, jdkHome,
                targetMajorVersion, fast, mode, policy, tracker, null);
    }

    /**
     * Write identity with explicit, path-free evidence for the JDK image/provider selected by
     * the frontend. The source information is additive metadata; cache-key compatibility is
     * still governed by the release digest and input-policy parameters above.
     */
    public String write(ReportLayout layout, String artifactHash, String dependencyIdentityHash,
                        String inventoryHash, Path rules, Path jdkHome, int targetMajorVersion,
                        boolean fast, String mode, InputBudget budget,
                        InputBudget.Tracker tracker, JdkSourceInfo sourceInfo) throws IOException {
        InputBudget policy = budget == null ? InputBudget.defaults() : budget;
        InputBudget.Tracker accounting = tracker == null ? policy.tracker() : tracker;
        String selectedMode = modeValue(mode);
        JdkSourceInfo selectedSource = sourceInfo == null
                ? new JdkSourceInfo(JdkSourceInfo.ImageKind.UNKNOWN, 0) : sourceInfo;
        String rulesHash = rulesHash(rules, policy, accounting);
        String jdkIdentity = jdkIdentity(jdkHome, targetMajorVersion, policy, accounting);
        String parameters = parameters(fast, selectedMode, policy);
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
                + "  \"rules_schema_version\":\"" + json(RuleSchemaV2.SCHEMA_VERSION) + "\",\n"
                + "  \"rules_semantics_version\":\"" + json(RuleSchemaV2.SEMANTICS_VERSION) + "\",\n"
                + "  \"jdk_identity\":\"" + json(jdkIdentity) + "\",\n"
                + "  \"jdk_source_kind\":\"" + json(selectedSource.imageKind().name()) + "\",\n"
                + "  \"jdk_provider\":\"" + json(selectedSource.provider()) + "\",\n"
                + "  \"jdk_runtime_delegated\":" + selectedSource.runtimeDelegated() + ",\n"
                + "  \"jdk_source_feature\":" + selectedSource.feature() + ",\n"
                + "  \"target_major_version\":" + Math.max(0, targetMajorVersion) + ",\n"
                + "  \"mode\":\"" + json(selectedMode) + "\",\n"
                + "  \"filter_semantics_version\":\""
                + json(FILTER_SEMANTICS_VERSION) + "\",\n"
                + "  \"parameters\":\"" + json(parameters) + "\"\n"
                + "}\n";
        AtomicFiles.writeUtf8(layout.meta().resolve("scan-identity.json"), json);
        return cacheKey;
    }

    /** Compute the same path-free key used by the published identity before static analysis. */
    public static String cacheKey(String artifactHash, String dependencyIdentityHash,
                                  Path rules, Path jdkHome,
                                  boolean fast, String mode) throws IOException {
        return cacheKey(artifactHash, dependencyIdentityHash, rules, jdkHome, fast, mode,
                InputBudget.defaults());
    }

    /** Compute a cache key including the explicit input-policy version/digest. */
    public static String cacheKey(String artifactHash, String dependencyIdentityHash,
                                  Path rules, Path jdkHome,
                                  boolean fast, String mode, InputBudget budget) throws IOException {
        InputBudget policy = budget == null ? InputBudget.defaults() : budget;
        InputBudget.Tracker tracker = policy.tracker();
        String parameters = parameters(fast, modeValue(mode), policy);
        String canonical = String.join("\n", ENGINE_VERSION, value(artifactHash),
                value(dependencyIdentityHash), rulesHash(rules, policy, tracker),
                jdkIdentity(jdkHome, 0, policy, tracker),
                parameters);
        return digest(canonical);
    }

    private static String parameters(boolean fast, String mode, InputBudget policy) {
        return "rules_schema=" + RuleSchemaV2.SCHEMA_VERSION
                + ";rules_semantics=" + RuleSchemaV2.SEMANTICS_VERSION
                + ";input_budget_schema=" + policy.schemaVersion()
                + ";input_budget_digest=" + digest(policy.toCanonicalJson())
                + ";fast=" + fast + ";mode=" + mode
                + ";filter_semantics=" + FILTER_SEMANTICS_VERSION;
    }

    private static String modeValue(String mode) {
        if ("component".equals(mode) || "application".equals(mode)) {
            return mode;
        }
        throw new IllegalArgumentException("scan mode is invalid: " + mode);
    }

    static String rulesHash(Path rules) throws IOException {
        return rulesHash(rules, InputBudget.defaults());
    }

    static String rulesHash(Path rules, InputBudget budget) throws IOException {
        InputBudget policy = budget == null ? InputBudget.defaults() : budget;
        return rulesHash(rules, policy, policy.tracker());
    }

    static String rulesHash(Path rules, InputBudget budget,
                            InputBudget.Tracker tracker) throws IOException {
        InputBudget policy = budget == null ? InputBudget.defaults() : budget;
        InputBudget.Tracker accounting = tracker == null ? policy.tracker() : tracker;
        if (rules != null) {
            return ArtifactFingerprint.sha256(rules, accounting);
        }
        try (InputStream input = ScanIdentityWriter.class
                .getResourceAsStream("/rules/default-rules.yaml")) {
            if (input == null) {
                throw new IOException("default rules resource missing");
            }
            return digest(input, Math.min(2L * 1024L * 1024L,
                    policy.maxRuleInputBytes()), accounting);
        }
    }

    static String jdkIdentity(Path jdkHome, int targetMajorVersion) throws IOException {
        return jdkIdentity(jdkHome, targetMajorVersion, InputBudget.defaults());
    }

    static String jdkIdentity(Path jdkHome, int targetMajorVersion, InputBudget budget) throws IOException {
        InputBudget policy = budget == null ? InputBudget.defaults() : budget;
        return jdkIdentity(jdkHome, targetMajorVersion, policy, policy.tracker());
    }

    static String jdkIdentity(Path jdkHome, int targetMajorVersion, InputBudget budget,
                              InputBudget.Tracker tracker) throws IOException {
        InputBudget policy = budget == null ? InputBudget.defaults() : budget;
        InputBudget.Tracker accounting = tracker == null ? policy.tracker() : tracker;
        Path selectedHome = jdkHome;
        if (selectedHome == null) {
            selectedHome = Paths.get(System.getProperty("java.home", "."));
        }
        selectedHome = selectedHome.toAbsolutePath().normalize();
        if (ArchiveLimits.isLinkOrReparsePoint(selectedHome)) {
            // Jabba's `default` selector is commonly a junction. Mirror the target-source
            // resolver so the identity is bound to the same concrete home that supplies bytes.
            try {
                Path linkTarget = Files.readSymbolicLink(selectedHome);
                selectedHome = (linkTarget.isAbsolute()
                        ? linkTarget : selectedHome.getParent().resolve(linkTarget))
                        .toAbsolutePath().normalize();
            } catch (IOException | RuntimeException linkReadFailure) {
                try {
                    selectedHome = selectedHome.toRealPath();
                } catch (IOException | RuntimeException realPathFailure) {
                    realPathFailure.addSuppressed(linkReadFailure);
                    throw new IOException("JDK home real path cannot be resolved: " + selectedHome,
                            realPathFailure);
                }
            }
            if (!Files.isDirectory(selectedHome)
                    || ArchiveLimits.isLinkOrReparsePoint(selectedHome)) {
                throw new IOException("JDK home real path is not a safe directory: "
                        + selectedHome);
            }
        }
        Path release = firstRegularFile(selectedHome.resolve("release"),
                selectedHome.resolve("jre").resolve("release"));
        if (release != null) {
            // The artifact digest already binds the target classfile major version. Keeping the
            // JDK identity independent of the frontend's discovered major lets cache lookup
            // happen before parsing without weakening invalidation.
            return "release-sha256=" + ArtifactFingerprint.sha256(release, accounting);
        }
        Path rtJar = firstRegularFile(selectedHome.resolve("jre").resolve("lib").resolve("rt.jar"),
                selectedHome.resolve("lib").resolve("rt.jar"));
        if (rtJar != null) {
            StringBuilder legacyIdentity = new StringBuilder("legacy-rt-jar\n");
            Path libDir = rtJar.getParent();
            for (String name : List.of("rt.jar", "jce.jar", "jsse.jar", "charsets.jar",
                    "resources.jar")) {
                Path jar = libDir.resolve(name);
                if (Files.isRegularFile(jar, java.nio.file.LinkOption.NOFOLLOW_LINKS)
                        && !ArchiveLimits.isLinkOrReparsePoint(jar)) {
                    legacyIdentity.append(name).append('=')
                            .append(ArtifactFingerprint.sha256(jar, accounting)).append('\n');
                }
            }
            return "legacy-sha256=" + digest(legacyIdentity.toString());
        }
        if (jdkHome != null) {
            throw new IOException("--jdk-home has no readable release or rt.jar: " + selectedHome);
        }
        return "runtime-feature=" + Runtime.version().feature()
                + ";requested=runtime";
    }

    private static Path firstRegularFile(Path... candidates) {
        for (Path candidate : candidates) {
            if (Files.isRegularFile(candidate, java.nio.file.LinkOption.NOFOLLOW_LINKS)
                    && !ArchiveLimits.isLinkOrReparsePoint(candidate)) {
                return candidate;
            }
        }
        return null;
    }

    private static String digest(InputStream input, long limit) throws IOException {
        return digest(input, limit, InputBudget.defaults().tracker());
    }

    private static String digest(InputStream input, long limit,
                                 InputBudget.Tracker tracker) throws IOException {
        MessageDigest digest = sha256();
        byte[] buffer = new byte[16 * 1024];
        long total = 0L;
        for (int read; ; ) {
            tracker.checkTime();
            read = tracker.readBounded(input, buffer, 0, buffer.length, limit - total,
                    "identity input exceeds limit");
            if (read < 0) {
                break;
            }
            if (read == 0) {
                int one = tracker.readByteBounded(input, limit - total,
                        "identity input exceeds limit");
                if (one < 0) {
                    break;
                }
                digest.update((byte) one);
                total++;
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
