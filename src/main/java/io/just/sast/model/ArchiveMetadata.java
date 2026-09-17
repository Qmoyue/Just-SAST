package io.just.sast.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Immutable metadata facts recovered from one logical archive.
 *
 * <p>The model keeps deployment metadata separate from class facts.  A coordinate is present
 * only when a structurally valid {@code pom.properties} supplied all three Maven identity
 * fields and agreed with its exact archive path.</p>
 */
public record ArchiveMetadata(String origin, Map<String, String> manifestAttributes,
                              List<String> classpathEntries, List<LayerEntry> layerEntries,
                              List<PomProperties> pomProperties,
                              List<String> completenessReasons) {

    public record LayerEntry(String layer, String path) {
        public LayerEntry {
            layer = required(layer, "layer");
            path = required(path, "layer path");
        }
    }

    public record PomProperties(String path, String groupId, String artifactId, String version) {
        public PomProperties {
            path = required(path, "pom.properties path");
            groupId = required(groupId, "pom.properties groupId");
            artifactId = required(artifactId, "pom.properties artifactId");
            version = required(version, "pom.properties version");
        }

        public String coordinate() {
            return groupId + ':' + artifactId + ':' + version;
        }
    }

    public ArchiveMetadata {
        origin = required(origin, "archive metadata origin");
        manifestAttributes = immutableAttributes(manifestAttributes);
        classpathEntries = immutableStrings(classpathEntries, "classpath entry");
        layerEntries = immutableLayers(layerEntries);
        pomProperties = immutablePoms(pomProperties);
        completenessReasons = immutableReasons(completenessReasons);
    }

    public static ArchiveMetadata empty(String origin) {
        return new ArchiveMetadata(origin, Map.of(), List.of(), List.of(), List.of(), List.of());
    }

    private static Map<String, String> immutableAttributes(Map<String, String> values) {
        if (values == null || values.isEmpty()) {
            return Map.of();
        }
        Map<String, String> copy = new java.util.TreeMap<>();
        for (Map.Entry<String, String> entry : values.entrySet()) {
            String key = required(entry.getKey(), "manifest attribute name");
            String value = required(entry.getValue(), "manifest attribute value");
            copy.put(key, value);
        }
        return Collections.unmodifiableMap(new LinkedHashMap<>(copy));
    }

    private static List<String> immutableStrings(List<String> values, String field) {
        if (values == null || values.isEmpty()) {
            return List.of();
        }
        List<String> copy = new ArrayList<>(values.size());
        for (String value : values) {
            copy.add(required(value, field));
        }
        return List.copyOf(copy);
    }

    private static List<LayerEntry> immutableLayers(List<LayerEntry> values) {
        if (values == null || values.isEmpty()) {
            return List.of();
        }
        List<LayerEntry> copy = new ArrayList<>(values.size());
        for (LayerEntry value : values) {
            copy.add(Objects.requireNonNull(value, "layer entry"));
        }
        return List.copyOf(copy);
    }

    private static List<PomProperties> immutablePoms(List<PomProperties> values) {
        if (values == null || values.isEmpty()) {
            return List.of();
        }
        List<PomProperties> copy = new ArrayList<>(values.size());
        for (PomProperties value : values) {
            copy.add(Objects.requireNonNull(value, "pom.properties"));
        }
        copy.sort(Comparator.comparing(PomProperties::path));
        return List.copyOf(copy);
    }

    private static List<String> immutableReasons(List<String> values) {
        if (values == null || values.isEmpty()) {
            return List.of();
        }
        LinkedHashSet<String> copy = new LinkedHashSet<>();
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                copy.add(value.trim());
            }
        }
        return copy.stream().sorted().toList();
    }

    private static String required(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " is required");
        }
        if (value.indexOf('\r') >= 0 || value.indexOf('\n') >= 0) {
            throw new IllegalArgumentException(field + " contains a line break");
        }
        return value.trim();
    }
}
