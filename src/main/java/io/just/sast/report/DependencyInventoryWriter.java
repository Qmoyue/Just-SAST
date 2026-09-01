package io.just.sast.report;

import io.just.sast.util.ArchiveLimits;
import io.just.sast.util.ArtifactFingerprint;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Writes a deterministic dependency inventory and a conservative CycloneDX BOM.
 *
 * <p>This is an inventory boundary, not a vulnerability database.  A component is identified
 * by its content hash when available; unreadable inputs stay visible with an explicit error
 * marker.  Source labels intentionally use target/dependency ordinals rather than absolute
 * local paths so reports can be compared and shared safely.</p>
 */
public final class DependencyInventoryWriter {

    private static final Pattern VERSIONED_NAME = Pattern.compile(
            "^(.+?)-((?:\\d+)(?:\\.[0-9A-Za-z]+)+(?:[-._][0-9A-Za-z]+)*)$");
    private static final long MAX_PROPERTIES_BYTES = 256L * 1024L;

    private record Component(String ref, String kind, String group, String name, String version,
                             String hash, String source, String parentRef, String error) {
    }

    public String write(ReportLayout layout, Path target, List<Path> dependencies,
                        String targetHash, int targetMajorVersion) throws IOException {
        return write(layout, target, dependencies, targetHash, targetMajorVersion, null);
    }

    /** Reuse hashes gathered by an optional cache preflight instead of reading dependencies twice. */
    public String write(ReportLayout layout, Path target, List<Path> dependencies,
                        String targetHash, int targetMajorVersion,
                        List<String> knownDependencyHashes) throws IOException {
        Map<String, Component> components = new TreeMap<>();
        addDirect(components, target, "application", "target", targetHash, "");
        List<Path> deps = dependencies == null ? List.of() : dependencies;
        for (int i = 0; i < deps.size(); i++) {
            Path dependency = deps.get(i);
            String knownHash = knownDependencyHashes != null && i < knownDependencyHashes.size()
                    ? knownDependencyHashes.get(i) : null;
            addDirect(components, dependency, "direct", "dependency-" + (i + 1), knownHash, "");
        }
        addPlatform(components, targetMajorVersion);

        List<Component> ordered = components.values().stream().toList();
        String csv = csvContent(ordered);
        AtomicFiles.writeUtf8(layout.evidence().resolve("dependencies.csv"), csv);
        AtomicFiles.writeUtf8(layout.meta().resolve("dependencies.sbom.json"),
                bomJson(ordered, targetHash));
        return digest(csv);
    }

    private void addDirect(Map<String, Component> components, Path input, String kind,
                           String source, String knownHash, String parentRef) {
        if (input == null) {
            return;
        }
        String hash = knownHash;
        String error = "";
        if (hash == null || hash.isBlank()) {
            try {
                hash = ArtifactFingerprint.sha256(input);
            } catch (IOException | RuntimeException failure) {
                error = errorCode(failure);
            }
        }
        String fallback = digest("component|" + source + "|" + String.valueOf(input.getFileName()));
        String ref = ref(hash, fallback);
        Coordinates coordinates = coordinates(input);
        put(components, new Component(ref, kind, coordinates.group(), coordinates.name(),
                coordinates.version(), normalizeHash(hash), source, parentRef, error));
        String nestedError = addNested(components, input, ref);
        if (!nestedError.isBlank()) {
            Component current = components.get(ref);
            if (current != null && current.error().isBlank()) {
                components.put(ref, new Component(current.ref(), current.kind(), current.group(),
                        current.name(), current.version(), current.hash(), current.source(),
                        current.parentRef(), nestedError));
            }
        }
    }

    private String addNested(Map<String, Component> components, Path input, String parentRef) {
        if (!Files.isRegularFile(input) || ArchiveLimits.isLinkOrReparsePoint(input)) {
            return "";
        }
        try {
            ArchiveLimits.checkContainerSize(input);
            List<ZipEntry> entries = new ArrayList<>();
            ArchiveLimits.Tracker tracker = new ArchiveLimits.Tracker();
            try (ZipFile zip = new ZipFile(input.toFile())) {
                var iterator = zip.entries();
                while (iterator.hasMoreElements()) {
                    ZipEntry entry = iterator.nextElement();
                    if (!ArchiveLimits.safeEntryName(entry.getName())) {
                        throw new IOException("unsafe archive entry");
                    }
                    tracker.observe(entry);
                    if (!entry.isDirectory() && isNestedLibrary(entry.getName())) {
                        entries.add(entry);
                    }
                }
                entries.sort(Comparator.comparing(ZipEntry::getName));
                for (ZipEntry entry : entries) {
                    String nestedHash;
                    try (InputStream stream = zip.getInputStream(entry)) {
                        nestedHash = boundedDigest(stream, tracker);
                    }
                    Coordinates coordinates = coordinates(Path.of(entry.getName()));
                    String ref = ref(nestedHash,
                            digest("nested|" + parentRef + "|" + entry.getName()));
                    put(components, new Component(ref, "nested", coordinates.group(),
                            coordinates.name(), coordinates.version(), nestedHash,
                            "nested:" + entry.getName(), parentRef, ""));
                }
            }
            return "";
        } catch (IOException | RuntimeException ignored) {
            // The main scan remains useful when an optional nested library is malformed. The
            // parent component already records its own hash/error; no guessed dependency is
            // emitted from an unsafe archive.
            return errorCode(ignored);
        }
    }

    private static void addPlatform(Map<String, Component> components, int major) {
        if (major <= 0) {
            return;
        }
        String version = Integer.toString(Math.max(1, major - 44));
        String ref = "jdk:feature:" + version;
        put(components, new Component(ref, "platform", "jdk", "java-runtime", version,
                "", "target-jdk", "", ""));
    }

    private static void put(Map<String, Component> components, Component component) {
        Component previous = components.get(component.ref());
        if (previous == null) {
            components.put(component.ref(), component);
            return;
        }
        // Same bytes may be supplied both directly and through a fat archive. Preserve the
        // strongest relationship deterministically without duplicating a BOM component.
        String source = previous.source().compareTo(component.source()) <= 0
                ? previous.source() : component.source();
        String kind = previous.kind().compareTo(component.kind()) <= 0
                ? previous.kind() : component.kind();
        components.put(component.ref(), new Component(component.ref(), kind,
                first(previous.group(), component.group()), first(previous.name(), component.name()),
                first(previous.version(), component.version()), component.hash(), source,
                first(previous.parentRef(), component.parentRef()), first(previous.error(), component.error())));
    }

    private static String first(String left, String right) {
        return left != null && !left.isBlank() ? left : right == null ? "" : right;
    }

    private static String boundedDigest(InputStream input, ArchiveLimits.Tracker tracker)
            throws IOException {
        MessageDigest digest = sha256();
        byte[] buffer = new byte[16 * 1024];
        long total = 0L;
        long limit = Math.min(ArchiveLimits.MAX_ENTRY_UNCOMPRESSED_BYTES,
                tracker.remainingReadBytes());
        for (int read; (read = input.read(buffer)) >= 0; ) {
            if (read == 0) {
                continue;
            }
            if (read > limit - total) {
                throw new IOException("nested dependency exceeds inventory limit");
            }
            digest.update(buffer, 0, read);
            total += read;
        }
        tracker.recordRead(total);
        return hex(digest.digest());
    }

    private static Coordinates coordinates(Path input) {
        String name = input == null || input.getFileName() == null
                ? "unknown" : input.getFileName().toString();
        if (name.endsWith(".jar")) {
            name = name.substring(0, name.length() - 4);
        }
        String group = "";
        String artifact = name;
        String version = "unknown";
        try {
            if (Files.isRegularFile(input) && !ArchiveLimits.isLinkOrReparsePoint(input)) {
                try (ZipFile zip = new ZipFile(input.toFile())) {
                    ZipEntry properties = zip.stream()
                            .filter(entry -> entry.getName().startsWith("META-INF/maven/")
                                    && entry.getName().endsWith("/pom.properties"))
                            .sorted(Comparator.comparing(ZipEntry::getName))
                            .findFirst().orElse(null);
                    if (properties != null && properties.getSize() >= 0
                            && properties.getSize() <= MAX_PROPERTIES_BYTES) {
                        java.util.Properties values = new java.util.Properties();
                        try (InputStream stream = zip.getInputStream(properties)) {
                            values.load(stream);
                        }
                        group = value(values.getProperty("groupId"));
                        artifact = value(values.getProperty("artifactId"));
                        version = value(values.getProperty("version"));
                    }
                }
            }
        } catch (IOException | RuntimeException ignored) {
            // Filename coordinates remain useful and are explicitly marked unknown when not
            // present in the artifact metadata.
        }
        if (group.isBlank() || artifact.equals("unknown")) {
            Matcher matcher = VERSIONED_NAME.matcher(artifact);
            if (matcher.matches()) {
                artifact = matcher.group(1);
                if (version.equals("unknown")) {
                    version = matcher.group(2);
                }
            }
        }
        return new Coordinates(group, artifact, version);
    }

    private record Coordinates(String group, String name, String version) {
    }

    private static String value(String value) {
        return value == null ? "" : value.trim();
    }

    private static String normalizeHash(String hash) {
        return hash == null || hash.isBlank() ? "UNAVAILABLE" : hash;
    }

    private static String ref(String hash, String fallback) {
        return hash != null && !hash.isBlank() && !hash.startsWith("UNAVAILABLE")
                ? "sha256:" + hash : "unavailable:" + fallback;
    }

    private static String errorCode(Throwable failure) {
        // Do not copy provider/error messages into a shareable report: they often contain the
        // user's absolute input path. The class is enough to explain an inventory gap; the
        // scanner's normal diagnostics retain the detailed local failure separately.
        return "UNAVAILABLE:" + (failure == null ? "unknown" : failure.getClass().getSimpleName());
    }

    private static boolean isNestedLibrary(String name) {
        return (name.startsWith("BOOT-INF/lib/") || name.startsWith("WEB-INF/lib/"))
                && name.endsWith(".jar") && !name.endsWith("/");
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("sha256-unavailable", impossible);
        }
    }

    private static String digest(String value) {
        MessageDigest digest = sha256();
        digest.update((value == null ? "" : value).getBytes(StandardCharsets.UTF_8));
        return hex(digest.digest());
    }

    private static String hex(byte[] bytes) {
        StringBuilder result = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) {
            result.append(String.format(Locale.ROOT, "%02x", value & 0xff));
        }
        return result.toString();
    }

    private static String csvContent(List<Component> components) {
        StringBuilder csv = new StringBuilder("bom_ref,kind,group,name,version,sha256,source,parent_ref,error\n");
        for (Component component : components) {
            csv.append(csv(component.ref())).append(',')
                    .append(csv(component.kind())).append(',')
                    .append(csv(component.group())).append(',')
                    .append(csv(component.name())).append(',')
                    .append(csv(component.version())).append(',')
                    .append(csv(component.hash())).append(',')
                    .append(csv(component.source())).append(',')
                    .append(csv(component.parentRef())).append(',')
                    .append(csv(component.error())).append('\n');
        }
        return csv.toString();
    }

    private static String csv(String value) {
        String safe = value == null ? "" : value;
        return "\"" + safe.replace("\"", "\"\"").replace("\r", " ").replace("\n", " ") + "\"";
    }

    private static String bomJson(List<Component> components, String targetHash) {
        String serial = "urn:uuid:" + UUID.nameUUIDFromBytes(
                (targetHash == null ? "" : targetHash).getBytes(StandardCharsets.UTF_8));
        StringBuilder json = new StringBuilder("{\n")
                .append("  \"bomFormat\":\"CycloneDX\",\n")
                .append("  \"specVersion\":\"1.5\",\n")
                .append("  \"serialNumber\":\"").append(json(serial)).append("\",\n")
                .append("  \"version\":1,\n  \"metadata\":{\"tools\":[{\"vendor\":\"Just\",\"name\":\"just-sast\",\"version\":\"0.2.0\"}]},\n")
                .append("  \"components\":[\n");
        for (int i = 0; i < components.size(); i++) {
            if (i > 0) {
                json.append(",\n");
            }
            Component component = components.get(i);
            json.append("    {\"type\":\"").append(json(componentType(component.kind())))
                    .append("\",\"bom-ref\":\"").append(json(component.ref()))
                    .append("\",\"group\":\"").append(json(component.group()))
                    .append("\",\"name\":\"").append(json(component.name()))
                    .append("\",\"version\":\"").append(json(component.version()))
                    .append("\",\"scope\":\"").append(json(scope(component.kind())))
                    .append("\",\"properties\":[{\"name\":\"just:kind\",\"value\":\"")
                    .append(json(component.kind())).append("\"},{\"name\":\"just:source\",\"value\":\"")
                    .append(json(component.source())).append("\"}");
            if (!component.error().isBlank()) {
                json.append(",{\"name\":\"just:error\",\"value\":\"")
                        .append(json(component.error())).append("\"}");
            }
            json.append(']');
            if (!component.hash().isBlank() && !"UNAVAILABLE".equals(component.hash())) {
                json.append(",\"hashes\":[{\"alg\":\"SHA-256\",\"content\":\"")
                        .append(json(component.hash())).append("\"}]");
            }
            if (!component.parentRef().isBlank()) {
                json.append(",\"pedigree\":{\"ancestors\":[{\"bom-ref\":\"")
                        .append(json(component.parentRef())).append("\"}]}");
            }
            json.append('}');
        }
        return json.append("\n  ]\n}\n").toString();
    }

    private static String scope(String kind) {
        return "platform".equals(kind) ? "excluded" : "required";
    }

    private static String componentType(String kind) {
        return switch (kind == null ? "" : kind) {
            case "application" -> "application";
            case "platform" -> "platform";
            default -> "library";
        };
    }

    private static String json(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\r", "\\r").replace("\n", "\\n");
    }
}
