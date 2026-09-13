package io.just.sast.report;

import io.just.sast.util.ArchiveLimits;
import io.just.sast.util.ArtifactFingerprint;
import io.just.sast.model.ArtifactProvenance;
import io.just.sast.model.DependencyGraph;
import io.just.sast.run.InputBudget;

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
                             String hash, String source, String parentRef, String error,
                             String errorDetail, int inputIndex, ArtifactProvenance provenance) {
        private Component {
            if (provenance == null) {
                throw new IllegalArgumentException("component provenance is required");
            }
        }
    }

    private record NestedFailure(String code, String detail) {
    }

    public String write(ReportLayout layout, Path target, List<Path> dependencies,
                        String targetHash, int targetMajorVersion) throws IOException {
        return write(layout, target, dependencies, targetHash, targetMajorVersion, null,
                InputBudget.defaults());
    }

    /** Reuse hashes gathered by an optional cache preflight instead of reading dependencies twice. */
    public String write(ReportLayout layout, Path target, List<Path> dependencies,
                        String targetHash, int targetMajorVersion,
                        List<String> knownDependencyHashes) throws IOException {
        return write(layout, target, dependencies, targetHash, targetMajorVersion,
                knownDependencyHashes, InputBudget.defaults());
    }

    /** Write inventory while sharing one versioned budget across target and dependencies. */
    public String write(ReportLayout layout, Path target, List<Path> dependencies,
                        String targetHash, int targetMajorVersion,
                        List<String> knownDependencyHashes, InputBudget budget) throws IOException {
        return write(layout, target, dependencies, targetHash, targetMajorVersion,
                knownDependencyHashes, budget,
                (budget == null ? InputBudget.defaults() : budget).tracker());
    }

    /**
     * Write inventory while charging all target/dependency/nested reads to a caller-owned
     * tracker.  This overload is used by preflight/hostile callers that need one aggregate
     * budget across multiple optional report consumers; the policy and tracker must describe
     * the same immutable {@link InputBudget}.
     */
    public String write(ReportLayout layout, Path target, List<Path> dependencies,
                        String targetHash, int targetMajorVersion,
                        List<String> knownDependencyHashes, InputBudget budget,
                        InputBudget.Tracker tracker) throws IOException {
        DependencyGraph graph = build(target, dependencies, targetHash, targetMajorVersion,
                knownDependencyHashes, budget, tracker);
        return write(layout, graph, targetHash);
    }

    /**
     * Build the immutable actual-input graph before frontend/analysis consumes it.  This is the
     * only owner of direct, embedded and platform inventory relationships; report writers only
     * serialize the returned snapshot.
     */
    public DependencyGraph build(Path target, List<Path> dependencies,
                                 String targetHash, int targetMajorVersion,
                                 List<String> knownDependencyHashes, InputBudget budget,
                                 InputBudget.Tracker tracker) throws IOException {
        return build(target, dependencies, targetHash, targetMajorVersion,
                knownDependencyHashes, null, budget, tracker);
    }

    /**
     * Build an actual-input graph while reusing the provenance values frozen by the scan
     * boundary.  The extra list is deliberately explicit: graph nodes must not grow a second
     * path-derived identity after the frontend has established the scan inputs.
     */
    public DependencyGraph build(Path target, List<Path> dependencies,
                                 String targetHash, int targetMajorVersion,
                                 List<String> knownDependencyHashes,
                                 List<ArtifactProvenance> inputProvenance,
                                 InputBudget budget, InputBudget.Tracker tracker) throws IOException {
        if (target == null) {
            throw new IOException("dependency graph target is required");
        }
        InputBudget policy = budget == null ? InputBudget.defaults() : budget;
        InputBudget.Tracker sharedBudget = tracker == null ? policy.tracker() : tracker;
        Map<String, Component> components = new TreeMap<>();
        List<Path> deps = dependencies == null ? List.of() : dependencies;
        int directCount = deps.size() + 1;
        if (inputProvenance != null && inputProvenance.size() < directCount) {
            throw new IOException("dependency graph provenance is missing direct inputs");
        }
        ArtifactProvenance applicationProvenance = inputProvenance == null
                ? derivedProvenance(target, ArtifactProvenance.Role.APPLICATION, targetHash)
                : inputProvenance.get(0);
        addDirect(components, target, "application", "target", targetHash, "", sharedBudget,
                policy, 0, applicationProvenance);
        for (int i = 0; i < deps.size(); i++) {
            Path dependency = deps.get(i);
            String knownHash = knownDependencyHashes != null && i < knownDependencyHashes.size()
                    ? knownDependencyHashes.get(i) : null;
            ArtifactProvenance dependencyProvenance = inputProvenance == null
                    ? derivedProvenance(dependency, ArtifactProvenance.Role.DEPENDENCY, knownHash)
                    : inputProvenance.get(i + 1);
            addDirect(components, dependency, "direct", "dependency-" + (i + 1), knownHash, "",
                    sharedBudget, policy, i + 1, dependencyProvenance);
        }
        ArtifactProvenance jdkProvenance = inputProvenance == null ? null
                : inputProvenance.stream()
                .filter(value -> value != null && value.role() == ArtifactProvenance.Role.JDK)
                .findFirst().orElse(null);
        addPlatform(components, targetMajorVersion, jdkProvenance);
        return graphOf(components.values().stream().toList());
    }

    /** Serialize an input graph without reopening any target or dependency path. */
    public String write(ReportLayout layout, DependencyGraph graph, String targetHash)
            throws IOException {
        if (layout == null || graph == null) {
            throw new IOException("dependency inventory requires layout and graph");
        }
        List<DependencyGraph.Node> ordered = graph.nodes().values().stream()
                .sorted(Comparator.comparing(DependencyGraph.Node::ref)).toList();
        String csv = csvContent(ordered);
        AtomicFiles.writeUtf8(layout.evidence().resolve("dependencies.csv"), csv);
        AtomicFiles.writeUtf8(layout.meta().resolve("dependencies.sbom.json"),
                bomJson(ordered, targetHash));
        return digest(csv);
    }

    private void addDirect(Map<String, Component> components, Path input, String kind,
                           String source, String knownHash, String parentRef,
                           InputBudget.Tracker budget, InputBudget policy, int inputIndex,
                           ArtifactProvenance provenance) {
        if (input == null) {
            return;
        }
        String hash = knownHash;
        String error = "";
        if (hash == null || hash.isBlank()) {
            try {
                hash = ArtifactFingerprint.sha256(input, budget);
            } catch (IOException | RuntimeException failure) {
                error = errorCode(failure);
            }
        }
        String fallback = digest("component|" + source + "|" + String.valueOf(input.getFileName()));
        String ref = uniqueDirectRef(components, ref(hash, fallback), inputIndex);
        Coordinates coordinates = coordinates(input, policy, budget);
        put(components, new Component(ref, kind, coordinates.group(), coordinates.name(),
                coordinates.version(), normalizeHash(hash), source, parentRef, error, "",
                inputIndex, provenance));
        NestedFailure nestedFailure = addNested(components, input, ref, budget, policy);
        if (nestedFailure != null) {
            Component current = components.get(ref);
            if (current != null && current.error().isBlank()) {
                components.put(ref, new Component(current.ref(), current.kind(), current.group(),
                        current.name(), current.version(), current.hash(), current.source(),
                        current.parentRef(), nestedFailure.code(), nestedFailure.detail(),
                        current.inputIndex(), current.provenance()));
            }
        }
    }

    private NestedFailure addNested(Map<String, Component> components, Path input, String parentRef,
                                    InputBudget.Tracker tracker, InputBudget policy) {
        if (!Files.isRegularFile(input) || ArchiveLimits.isLinkOrReparsePoint(input)) {
            return null;
        }
        try {
            ArchiveLimits.checkContainerSize(input, policy);
            List<ZipEntry> entries = new ArrayList<>();
            Map<String, Integer> seenNames = new LinkedHashMap<>();
            int ordinal = 0;
            ArchiveLimits.FileReadSnapshot snapshot = ArchiveLimits.snapshotRegularFile(
                    input, policy, "INVENTORY_ARCHIVE");
            try (ArchiveLimits.ZipFileHandle handle = ArchiveLimits.openZipFile(snapshot,
                    "INVENTORY_ARCHIVE")) {
                ZipFile zip = handle.zip();
                var iterator = zip.entries();
                while (iterator.hasMoreElements()) {
                    ZipEntry entry = iterator.nextElement();
                    if (entry == null) {
                        throw new IOException("ARCHIVE_DUPLICATE_ENTRY");
                    }
                    ordinal++;
                    Integer firstOrdinal = seenNames.putIfAbsent(entry.getName(), ordinal);
                    if (firstOrdinal != null) {
                        return new NestedFailure("ARCHIVE_DUPLICATE_ENTRY",
                                duplicateEntryDetail(entry.getName(), firstOrdinal, ordinal,
                                        policy));
                    }
                    if (!ArchiveLimits.safeEntryName(entry.getName(), policy)) {
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
                    Coordinates coordinates = coordinates(Path.of(entry.getName()), policy, tracker);
                    String ref = uniqueEmbeddedRef(components, ref(nestedHash,
                            digest("nested|" + parentRef + "|" + entry.getName())),
                            parentRef, entry.getName());
                    put(components, new Component(ref, "nested", coordinates.group(),
                            coordinates.name(), coordinates.version(), nestedHash,
                            "nested:" + entry.getName(), parentRef, "", "", -1,
                            new ArtifactProvenance("nested:" + entry.getName(),
                                    ArtifactProvenance.Role.DEPENDENCY, nestedHash,
                                    entry.getSize() < 0L ? -1L : entry.getSize())));
                }
            }
            return null;
        } catch (IOException | RuntimeException ignored) {
            // The main scan remains useful when an optional nested library is malformed. The
            // parent component already records its own hash/error; no guessed dependency is
            // emitted from an unsafe archive.
            return new NestedFailure(errorCode(ignored), "");
        }
    }

    private static void addPlatform(Map<String, Component> components, int major,
                                    ArtifactProvenance provenance) {
        if (major <= 0) {
            return;
        }
        String version = Integer.toString(Math.max(1, major - 44));
        String ref = "jdk:feature:" + version;
        put(components, new Component(ref, "platform", "jdk", "java-runtime", version,
                "", "target-jdk", "", "", "", -1,
                provenance == null ? ArtifactProvenance.unknown("jdk:feature:" + version,
                        ArtifactProvenance.Role.JDK) : provenance));
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
                first(previous.parentRef(), component.parentRef()),
                first(previous.error(), component.error()),
                first(previous.errorDetail(), component.errorDetail()),
                previous.inputIndex() >= 0 ? previous.inputIndex() : component.inputIndex(),
                previous.provenance().hasContentDigest() ? previous.provenance()
                        : component.provenance()));
    }

    private static String first(String left, String right) {
        return left != null && !left.isBlank() ? left : right == null ? "" : right;
    }

    /**
     * Return bounded, delimiter-safe detail for the first duplicate central-directory name.
     * Archive names are input data, so unsafe names are not echoed into a shareable report;
     * safe names are escaped and capped while ordinal information remains deterministic.
     */
    private static String duplicateEntryDetail(String name, int firstOrdinal,
                                                int duplicateOrdinal, InputBudget policy) {
        String display = ArchiveLimits.safeEntryName(name, policy)
                ? escapeDetail(name, 512) : "<unsafe-entry-name>";
        return "name=" + display + ";firstOrdinal=" + firstOrdinal
                + ";duplicateOrdinal=" + duplicateOrdinal;
    }

    private static String escapeDetail(String value, int maxChars) {
        if (value == null || value.isEmpty()) {
            return "<empty>";
        }
        StringBuilder result = new StringBuilder(Math.min(maxChars, value.length() + 8));
        int count = 0;
        for (int offset = 0; offset < value.length() && count < maxChars; ) {
            int codePoint = value.codePointAt(offset);
            offset += Character.charCount(codePoint);
            String escaped;
            if (codePoint == '\\') {
                escaped = "\\\\";
            } else if (codePoint == '=' || codePoint == ';') {
                escaped = String.format(Locale.ROOT, "\\u%04x", codePoint);
            } else if (Character.isISOControl(codePoint)) {
                escaped = String.format(Locale.ROOT, "\\u%04x", codePoint);
            } else {
                escaped = new String(Character.toChars(codePoint));
            }
            if (result.length() + escaped.length() > maxChars) {
                result.append("...");
                break;
            }
            result.append(escaped);
            count++;
        }
        return result.toString();
    }

    private static String boundedDigest(InputStream input, InputBudget.Tracker tracker)
            throws IOException {
        MessageDigest digest = sha256();
        byte[] buffer = new byte[16 * 1024];
        long total = 0L;
        long limit = Math.min(tracker.budget().maxEntryBytes(),
                tracker.remainingReadBytes());
        for (int read; ; ) {
            tracker.checkTime();
            read = tracker.readBounded(input, buffer, 0, buffer.length, limit - total,
                    "nested dependency exceeds inventory limit");
            if (read < 0) {
                break;
            }
            if (read == 0) {
                int one = tracker.readByteBounded(input, limit - total,
                        "nested dependency exceeds inventory limit");
                if (one < 0) {
                    break;
                }
                digest.update((byte) one);
                total++;
                continue;
            }
            if (read > limit - total) {
                throw new IOException("nested dependency exceeds inventory limit");
            }
            digest.update(buffer, 0, read);
            total += read;
        }
        return hex(digest.digest());
    }

    private static Coordinates coordinates(Path input, InputBudget policy,
                                           InputBudget.Tracker tracker) {
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
                ArchiveLimits.FileReadSnapshot snapshot = ArchiveLimits.snapshotRegularFile(
                        input, policy, "INVENTORY_COORDINATES");
                try (ArchiveLimits.ZipFileHandle handle = ArchiveLimits.openZipFile(snapshot,
                        "INVENTORY_COORDINATES")) {
                    ZipFile zip = handle.zip();
                    ZipEntry properties = zip.stream()
                            .filter(entry -> entry.getName().startsWith("META-INF/maven/")
                                    && entry.getName().endsWith("/pom.properties"))
                            .sorted(Comparator.comparing(ZipEntry::getName))
                            .findFirst().orElse(null);
                    long cap = Math.min(MAX_PROPERTIES_BYTES, policy.maxEntryBytes());
                    if (properties != null && properties.getSize() >= 0
                            && properties.getSize() <= cap) {
                        java.util.Properties values = new java.util.Properties();
                        try (InputStream stream = zip.getInputStream(properties)) {
                            values.load(new java.io.StringReader(new String(
                                    io.just.sast.util.IoUtil.readAll(stream, cap, tracker),
                                    StandardCharsets.UTF_8)));
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
        return hash != null && hash.matches("[0-9a-fA-F]{64}")
                ? hash.toLowerCase(Locale.ROOT) : "UNAVAILABLE";
    }

    private static String ref(String hash, String fallback) {
        return hash != null && hash.matches("[0-9a-fA-F]{64}")
                ? "sha256:" + hash.toLowerCase(Locale.ROOT) : "unavailable:" + fallback;
    }

    private static String uniqueDirectRef(Map<String, Component> components, String base,
                                          int inputIndex) {
        if (!components.containsKey(base)) {
            return base;
        }
        String qualified = base + "|input:" + inputIndex;
        if (components.containsKey(qualified)) {
            throw new IllegalStateException("duplicate direct artifact reference: " + qualified);
        }
        return qualified;
    }

    private static String uniqueEmbeddedRef(Map<String, Component> components, String base,
                                            String parentRef, String entryName) {
        if (!components.containsKey(base)) {
            return base;
        }
        String qualified = base + "|embedded:" + digest(parentRef + "|" + entryName);
        if (components.containsKey(qualified)) {
            throw new IllegalStateException("duplicate embedded artifact reference: " + qualified);
        }
        return qualified;
    }

    private static ArtifactProvenance derivedProvenance(Path input,
                                                        ArtifactProvenance.Role role,
                                                        String hash) {
        String normalized = hash != null && hash.matches("[0-9a-fA-F]{64}")
                ? hash : "UNKNOWN";
        String logicalName = input == null || input.getFileName() == null
                ? "<unknown>" : input.getFileName().toString();
        return new ArtifactProvenance(logicalName, role, normalized, -1L);
    }

    /**
     * Project only a closed set of parser boundary reasons into the shareable inventory.  The
     * provider exception class remains the fallback so local paths and free-form messages never
     * leak into a deterministic report, while known archive failures retain actionable detail.
     */
    static String errorCode(Throwable failure) {
        // Do not copy provider/error messages into a shareable report: they often contain the
        // user's absolute input path. The class is enough to explain an inventory gap; the
        // scanner's normal diagnostics retain the detailed local failure separately.  A closed
        // reason allowlist is safe to expose and makes duplicate/hostile archive details useful.
        String message = failure == null ? "" : String.valueOf(failure.getMessage());
        for (String reason : List.of(
                "ARCHIVE_DUPLICATE_ENTRY",
                "ARCHIVE_CORRUPT",
                "ARCHIVE_ENTRY_READ_CAP",
                "ARCHIVE_UNCOMPRESSED_BYTES_CAP",
                "ARCHIVE_COMPRESSED_BYTES_CAP",
                "ARCHIVE_PHYSICAL_BYTES_CAP",
                "ARCHIVE_ENTRY_COUNT_CAP",
                "INPUT_PARSE_TIME_CAP",
                "INPUT_STREAM_NO_PROGRESS")) {
            if (message.contains(reason)) {
                return reason;
            }
        }
        if (failure instanceof java.util.zip.ZipException) {
            return "ARCHIVE_CORRUPT";
        }
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

    private static DependencyGraph graphOf(List<Component> components) {
        List<DependencyGraph.Node> nodes = new ArrayList<>(components.size());
        List<DependencyGraph.Edge> edges = new ArrayList<>();
        for (Component component : components) {
            ArtifactProvenance.Role role = switch (component.kind()) {
                case "application" -> ArtifactProvenance.Role.APPLICATION;
                case "platform" -> ArtifactProvenance.Role.JDK;
                default -> ArtifactProvenance.Role.DEPENDENCY;
            };
            String hash = component.hash() != null
                    && component.hash().matches("[0-9a-fA-F]{64}")
                    ? component.hash() : "UNKNOWN";
            DependencyGraph.Source source = switch (component.kind()) {
                case "application" -> DependencyGraph.Source.ACTUAL_APPLICATION;
                case "nested" -> DependencyGraph.Source.ACTUAL_EMBEDDED;
                case "direct" -> DependencyGraph.Source.ACTUAL_EXPLICIT;
                case "platform" -> DependencyGraph.Source.JDK;
                default -> throw new IllegalStateException("unknown inventory component kind: "
                        + component.kind());
            };
            String type = "platform".equals(component.kind()) ? "jrt" : "jar";
            ArtifactProvenance provenance = component.provenance();
            if (!provenance.hasContentDigest() && !"UNKNOWN".equals(hash)) {
                provenance = new ArtifactProvenance(provenance.logicalName(), role, hash,
                        provenance.sizeBytes());
            }
            nodes.add(new DependencyGraph.Node(component.ref(), provenance, source,
                    DependencyGraph.Deployment.ACTUAL_DISTRIBUTION, component.group(),
                    component.name(), component.version(), type, "", component.source(),
                    component.parentRef(), component.error(), component.errorDetail(),
                    component.inputIndex()));
            if (!component.parentRef().isBlank()) {
                edges.add(new DependencyGraph.Edge(component.parentRef(), component.ref(),
                        "embedded", "archive-entry"));
            }
        }
        return new DependencyGraph(nodes, edges, Map.of());
    }

    private static String inventoryKind(DependencyGraph.Source source) {
        return switch (source) {
            case ACTUAL_APPLICATION -> "application";
            case ACTUAL_EMBEDDED -> "nested";
            case ACTUAL_EXPLICIT -> "direct";
            case JDK -> "platform";
            case POM_DERIVED, CACHE, REMOTE -> "derived";
        };
    }

    private static String inventoryHash(DependencyGraph.Node node) {
        String hash = node.provenance().sha256();
        return "UNKNOWN".equals(hash) ? "UNAVAILABLE" : hash.toLowerCase(Locale.ROOT);
    }

    private static String csvContent(List<DependencyGraph.Node> nodes) {
        StringBuilder csv = new StringBuilder(
                "bom_ref,kind,group,name,version,sha256,source,parent_ref,error,error_detail\n");
        for (DependencyGraph.Node node : nodes) {
            csv.append(csv(node.ref())).append(',')
                    .append(csv(inventoryKind(node.source()))).append(',')
                    .append(csv(node.group())).append(',')
                    .append(csv(node.name())).append(',')
                    .append(csv(node.version())).append(',')
                    .append(csv(inventoryHash(node))).append(',')
                    .append(csv(node.sourceDetail())).append(',')
                    .append(csv(node.parentRef())).append(',')
                    .append(csv(node.error())).append(',')
                    .append(csv(node.errorDetail())).append('\n');
        }
        return csv.toString();
    }

    private static String csv(String value) {
        String safe = value == null ? "" : value;
        return "\"" + safe.replace("\"", "\"\"").replace("\r", " ").replace("\n", " ") + "\"";
    }

    private static String bomJson(List<DependencyGraph.Node> nodes, String targetHash) {
        String serial = "urn:uuid:" + UUID.nameUUIDFromBytes(
                (targetHash == null ? "" : targetHash).getBytes(StandardCharsets.UTF_8));
        StringBuilder json = new StringBuilder("{\n")
                .append("  \"bomFormat\":\"CycloneDX\",\n")
                .append("  \"specVersion\":\"1.5\",\n")
                .append("  \"serialNumber\":\"").append(json(serial)).append("\",\n")
                .append("  \"version\":1,\n  \"metadata\":{\"tools\":[{\"vendor\":\"Just\",\"name\":\"just-sast\",\"version\":\"0.2.0\"}]},\n")
                .append("  \"components\":[\n");
        for (int i = 0; i < nodes.size(); i++) {
            if (i > 0) {
                json.append(",\n");
            }
            DependencyGraph.Node node = nodes.get(i);
            String kind = inventoryKind(node.source());
            json.append("    {\"type\":\"").append(json(componentType(kind)))
                    .append("\",\"bom-ref\":\"").append(json(node.ref()))
                    .append("\",\"group\":\"").append(json(node.group()))
                    .append("\",\"name\":\"").append(json(node.name()))
                    .append("\",\"version\":\"").append(json(node.version()))
                    .append("\",\"scope\":\"").append(json(scope(kind)))
                    .append("\",\"properties\":[{\"name\":\"just:kind\",\"value\":\"")
                    .append(json(kind)).append("\"},{\"name\":\"just:source\",\"value\":\"")
                    .append(json(node.sourceDetail())).append("\"}");
            if (!node.error().isBlank()) {
                json.append(",{\"name\":\"just:error\",\"value\":\"")
                        .append(json(node.error())).append("\"}");
            }
            if (!node.errorDetail().isBlank()) {
                json.append(",{\"name\":\"just:error-detail\",\"value\":\"")
                        .append(json(node.errorDetail())).append("\"}");
            }
            json.append(']');
            String hash = inventoryHash(node);
            if (!"UNAVAILABLE".equals(hash)) {
                json.append(",\"hashes\":[{\"alg\":\"SHA-256\",\"content\":\"")
                        .append(json(hash)).append("\"}]");
            }
            if (!node.parentRef().isBlank()) {
                json.append(",\"pedigree\":{\"ancestors\":[{\"bom-ref\":\"")
                        .append(json(node.parentRef())).append("\"}]}");
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
