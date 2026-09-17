package io.just.sast.frontend.asm;

import io.just.sast.model.ArchiveMetadata;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.TreeMap;
import java.util.jar.Attributes;
import java.util.jar.Manifest;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parser for bounded archive metadata bytes selected by {@link JarReader}.
 *
 * <p>This is a deliberately small parser for the formats emitted by Java/Maven and Spring
 * Boot. It never evaluates YAML, expands a class path, opens a path from metadata, or guesses
 * coordinates. Malformed optional metadata remains visible as a typed completeness reason.</p>
 */
public final class ArchiveMetadataParser {
    private static final String MANIFEST = "META-INF/MANIFEST.MF";
    private static final String POM_PREFIX = "META-INF/maven/";
    private static final String POM_SUFFIX = "/pom.properties";
    private static final Pattern POM_PATH = Pattern.compile(
            "^META-INF/maven/([^/]+)/([^/]+)/pom\\.properties$");
    private static final int MAX_METADATA_LINES = 4096;

    private ArchiveMetadataParser() {
    }

    /** Return whether a path is one of the bounded metadata files this parser owns. */
    public static boolean isMetadataPath(String path) {
        String normalized = normalizePath(path);
        String lower = normalized.toLowerCase(java.util.Locale.ROOT);
        return MANIFEST.equalsIgnoreCase(normalized)
                || "classpath.idx".equals(lower)
                || "boot-inf/classpath.idx".equals(lower)
                || "layers.idx".equals(lower)
                || "boot-inf/layers.idx".equals(lower)
                || (normalized.startsWith(POM_PREFIX) && normalized.endsWith(POM_SUFFIX));
    }

    /** Parse selected metadata entry bytes in deterministic archive-path order. */
    public static ArchiveMetadata parse(String origin, Map<String, byte[]> entries) {
        if (origin == null || origin.isBlank()) {
            throw new IllegalArgumentException("archive metadata origin is required");
        }
        Map<String, byte[]> ordered = new TreeMap<>();
        if (entries != null) {
            for (Map.Entry<String, byte[]> entry : entries.entrySet()) {
                String path = normalizePath(entry.getKey());
                if (isMetadataPath(path)) {
                    if (entry.getValue() == null) {
                        throw new IllegalArgumentException("metadata bytes are required: " + path);
                    }
                    ordered.put(path, entry.getValue().clone());
                }
            }
        }
        Map<String, String> manifest = new LinkedHashMap<>();
        List<String> classpath = new ArrayList<>();
        List<ArchiveMetadata.LayerEntry> layers = new ArrayList<>();
        List<ArchiveMetadata.PomProperties> poms = new ArrayList<>();
        LinkedHashSet<String> reasons = new LinkedHashSet<>();
        for (Map.Entry<String, byte[]> entry : ordered.entrySet()) {
            String path = entry.getKey();
            byte[] bytes = entry.getValue();
            String lower = path.toLowerCase(java.util.Locale.ROOT);
            try {
                if (MANIFEST.equalsIgnoreCase(path)) {
                    parseManifest(bytes, manifest);
                } else if ("classpath.idx".equals(lower)
                        || "boot-inf/classpath.idx".equals(lower)) {
                    parseClasspathIndex(bytes, classpath, reasons);
                } else if ("layers.idx".equals(lower)
                        || "boot-inf/layers.idx".equals(lower)) {
                    parseLayersIndex(bytes, layers, reasons);
                } else if (path.startsWith(POM_PREFIX) && path.endsWith(POM_SUFFIX)) {
                    parsePomProperties(path, bytes, poms, reasons);
                }
            } catch (IOException | RuntimeException failure) {
                reasons.add(metadataFailure(path));
            }
        }
        return new ArchiveMetadata(origin, manifest, classpath, layers, poms,
                new ArrayList<>(reasons));
    }

    private static void parseManifest(byte[] bytes, Map<String, String> output)
            throws IOException {
        Manifest manifest = new Manifest(new ByteArrayInputStream(bytes));
        for (Map.Entry<Object, Object> entry : manifest.getMainAttributes().entrySet()) {
            Attributes.Name name = (Attributes.Name) entry.getKey();
            String value = String.valueOf(entry.getValue()).trim();
            if (value.isBlank() || value.indexOf('\r') >= 0 || value.indexOf('\n') >= 0) {
                throw new IOException("manifest attribute is invalid");
            }
            output.put(name.toString(), value);
        }
    }

    private static void parseClasspathIndex(byte[] bytes, List<String> output,
                                            LinkedHashSet<String> reasons) {
        String text = new String(bytes, StandardCharsets.UTF_8);
        String[] lines = text.split("\\r?\\n", -1);
        if (lines.length > MAX_METADATA_LINES) {
            reasons.add("CLASSPATH_INDEX_CAP");
            return;
        }
        for (String line : lines) {
            if (line.isBlank()) {
                continue;
            }
            String value = listScalar(line);
            if (value == null) {
                reasons.add("CLASSPATH_INDEX_INVALID");
            } else {
                output.add(value);
            }
        }
    }

    private static void parseLayersIndex(byte[] bytes, List<ArchiveMetadata.LayerEntry> output,
                                         LinkedHashSet<String> reasons) {
        String text = new String(bytes, StandardCharsets.UTF_8);
        String[] lines = text.split("\\r?\\n", -1);
        if (lines.length > MAX_METADATA_LINES) {
            reasons.add("LAYERS_INDEX_CAP");
            return;
        }
        String currentLayer = null;
        for (String line : lines) {
            if (line.isBlank()) {
                continue;
            }
            String trimmed = line.trim();
            if (trimmed.startsWith("- ") && trimmed.endsWith(":")) {
                String layer = scalar(trimmed.substring(2, trimmed.length() - 1));
                if (layer == null) {
                    reasons.add("LAYERS_INDEX_INVALID");
                    currentLayer = null;
                } else {
                    currentLayer = layer;
                }
                continue;
            }
            if (trimmed.startsWith("- ") && currentLayer != null) {
                String path = scalar(trimmed.substring(2));
                if (path == null) {
                    reasons.add("LAYERS_INDEX_INVALID");
                } else {
                    output.add(new ArchiveMetadata.LayerEntry(currentLayer, path));
                }
                continue;
            }
            reasons.add("LAYERS_INDEX_INVALID");
        }
    }

    private static void parsePomProperties(String path, byte[] bytes,
                                            List<ArchiveMetadata.PomProperties> output,
                                            LinkedHashSet<String> reasons) throws IOException {
        Matcher matcher = POM_PATH.matcher(path);
        if (!matcher.matches()) {
            reasons.add("POM_PROPERTIES_PATH_INVALID");
            return;
        }
        Properties values = new Properties();
        values.load(new ByteArrayInputStream(bytes));
        String groupId = property(values, "groupId");
        String artifactId = property(values, "artifactId");
        String version = property(values, "version");
        if (groupId == null || artifactId == null || version == null
                || !matcher.group(1).equals(groupId)
                || !matcher.group(2).equals(artifactId)) {
            reasons.add("POM_PROPERTIES_INVALID");
            return;
        }
        output.add(new ArchiveMetadata.PomProperties(path, groupId, artifactId, version));
    }

    private static String property(Properties values, String key) {
        String value = values.getProperty(key);
        if (value == null) {
            return null;
        }
        String normalized = value.trim();
        return normalized.isBlank() || normalized.indexOf('\r') >= 0
                || normalized.indexOf('\n') >= 0 ? null : normalized;
    }

    private static String listScalar(String line) {
        String trimmed = line.trim();
        if (!trimmed.startsWith("- ")) {
            return null;
        }
        return scalar(trimmed.substring(2));
    }

    private static String scalar(String value) {
        String trimmed = value == null ? "" : value.trim();
        if (trimmed.length() < 2) {
            return trimmed.isBlank() ? null : trimmed;
        }
        char first = trimmed.charAt(0);
        char last = trimmed.charAt(trimmed.length() - 1);
        if (first == '"' || first == '\'') {
            if (last != first) {
                return null;
            }
            String inner = trimmed.substring(1, trimmed.length() - 1);
            if (first == '\'' && inner.contains("'")) {
                return null;
            }
            if (first == '"' && (inner.contains("\\n") || inner.contains("\\r"))) {
                return null;
            }
            return inner.isBlank() ? null : inner;
        }
        if (trimmed.indexOf(' ') >= 0 || trimmed.indexOf('\t') >= 0
                || trimmed.indexOf('#') >= 0 || trimmed.indexOf(':') >= 0) {
            return null;
        }
        return trimmed;
    }

    private static String metadataFailure(String path) {
        String lower = path.toLowerCase(java.util.Locale.ROOT);
        if (MANIFEST.equalsIgnoreCase(path)) {
            return "MANIFEST_INVALID";
        }
        if (lower.endsWith("classpath.idx")) {
            return "CLASSPATH_INDEX_INVALID";
        }
        if (lower.endsWith("layers.idx")) {
            return "LAYERS_INDEX_INVALID";
        }
        return "POM_PROPERTIES_INVALID";
    }

    private static String normalizePath(String path) {
        if (path == null) {
            return "";
        }
        return path.replace('\\', '/').trim();
    }
}
