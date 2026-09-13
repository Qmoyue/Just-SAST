package io.just.sast.model;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Immutable dependency/input graph shared by frontend, analysis identity and reports.
 *
 * <p>The graph distinguishes bytes that are part of the actual distribution from a dependency
 * environment derived later from a POM.  A report writer may serialize this value, but it must
 * not rediscover coordinates, ownership or conflict state from paths.</p>
 */
public final class DependencyGraph {
    public static final int MODEL_VERSION = 1;

    public enum Source {
        ACTUAL_APPLICATION,
        ACTUAL_EMBEDDED,
        ACTUAL_EXPLICIT,
        POM_DERIVED,
        CACHE,
        REMOTE,
        JDK
    }

    public enum Deployment {
        ACTUAL_DISTRIBUTION,
        DECLARED_ENVIRONMENT,
        UNKNOWN
    }

    public enum Resolution {
        SELECTED,
        CONFLICT,
        UNRESOLVED
    }

    public record Node(String ref, ArtifactProvenance provenance, Source source,
                       Deployment deployment, String group, String name, String version,
                       String type, String classifier, String sourceDetail, String parentRef,
                       String error, String errorDetail, int inputIndex, String scope,
                       boolean optional, Resolution resolution, String resolutionReason) {
        public Node {
            requireText(ref, "ref");
            provenance = Objects.requireNonNull(provenance, "provenance");
            source = Objects.requireNonNull(source, "source");
            deployment = Objects.requireNonNull(deployment, "deployment");
            requireValue(group, "group");
            requireText(name, "name");
            requireText(version, "version");
            requireText(type, "type");
            requireValue(classifier, "classifier");
            requireValue(sourceDetail, "sourceDetail");
            requireValue(parentRef, "parentRef");
            requireValue(error, "error");
            requireValue(errorDetail, "errorDetail");
            requireValue(scope, "scope");
            resolution = Objects.requireNonNull(resolution, "resolution");
            requireValue(resolutionReason, "resolutionReason");
            if (inputIndex < -1) {
                throw new IllegalArgumentException("inputIndex must be -1 or non-negative");
            }
        }

        /** Compatibility form for actual-input nodes that predate Maven graph metadata. */
        public Node(String ref, ArtifactProvenance provenance, Source source,
                    Deployment deployment, String group, String name, String version,
                    String type, String classifier, String sourceDetail, String parentRef,
                    String error, String errorDetail, int inputIndex) {
            this(ref, provenance, source, deployment, group, name, version, type, classifier,
                    sourceDetail, parentRef, error, errorDetail, inputIndex, "", false,
                    Resolution.SELECTED, "");
        }
    }

    public record Edge(String fromRef, String toRef, String kind, String reason) {
        public Edge {
            requireText(fromRef, "fromRef");
            requireText(toRef, "toRef");
            requireText(kind, "kind");
            requireText(reason, "reason");
            if (fromRef.equals(toRef)) {
                throw new IllegalArgumentException("dependency graph edge cannot self-reference");
            }
        }
    }

    public record ClassOwner(String className, String selectedRef, List<String> candidateRefs,
                             Resolution resolution, boolean applicationOwned) {
        public ClassOwner {
            requireText(className, "className");
            requireValue(selectedRef, "selectedRef");
            candidateRefs = candidateRefs == null ? List.of() : List.copyOf(candidateRefs);
            if (candidateRefs.stream().anyMatch(ref -> ref == null || ref.isBlank())) {
                throw new IllegalArgumentException("candidateRefs must not contain blank values");
            }
            resolution = Objects.requireNonNull(resolution, "resolution");
            if (!selectedRef.isBlank() && !candidateRefs.contains(selectedRef)) {
                throw new IllegalArgumentException("selectedRef must be one of candidateRefs");
            }
            if (applicationOwned && selectedRef.isBlank()) {
                throw new IllegalArgumentException("application-owned class needs a selected artifact");
            }
        }
    }

    private final Map<String, Node> nodes;
    private final List<Edge> edges;
    private final Map<String, ClassOwner> classOwners;
    private final String semanticDigest;

    public DependencyGraph(List<Node> nodes, List<Edge> edges,
                           Map<String, ClassOwner> classOwners) {
        LinkedHashMap<String, Node> nodeCopy = new LinkedHashMap<>();
        if (nodes == null) {
            throw new IllegalArgumentException("dependency graph nodes are required");
        }
        for (Node node : nodes) {
            Objects.requireNonNull(node, "dependency graph node");
            if (nodeCopy.putIfAbsent(node.ref(), node) != null) {
                throw new IllegalArgumentException("duplicate dependency graph ref: " + node.ref());
            }
        }
        List<Edge> edgeCopy = edges == null ? List.of() : List.copyOf(edges);
        for (Edge edge : edgeCopy) {
            if (!nodeCopy.containsKey(edge.fromRef()) || !nodeCopy.containsKey(edge.toRef())) {
                throw new IllegalArgumentException("dependency graph edge references an unknown node");
            }
        }
        LinkedHashMap<String, ClassOwner> ownerCopy = new LinkedHashMap<>();
        if (classOwners != null) {
            for (Map.Entry<String, ClassOwner> entry : classOwners.entrySet()) {
                String className = requireText(entry.getKey(), "class owner key");
                ClassOwner owner = Objects.requireNonNull(entry.getValue(), "class owner");
                if (!className.equals(owner.className())) {
                    throw new IllegalArgumentException("class owner key does not match class name");
                }
                if (!owner.selectedRef().isBlank() && !nodeCopy.containsKey(owner.selectedRef())) {
                    throw new IllegalArgumentException("class owner selects an unknown artifact");
                }
                for (String candidate : owner.candidateRefs()) {
                    if (!nodeCopy.containsKey(candidate)) {
                        throw new IllegalArgumentException("class owner has an unknown candidate");
                    }
                }
                ownerCopy.put(className, owner);
            }
        }
        this.nodes = Collections.unmodifiableMap(nodeCopy);
        this.edges = edgeCopy;
        this.classOwners = Collections.unmodifiableMap(ownerCopy);
        this.semanticDigest = computeSemanticDigest();
    }

    public static DependencyGraph empty() {
        return new DependencyGraph(List.of(), List.of(), Map.of());
    }

    public Map<String, Node> nodes() {
        return nodes;
    }

    public List<Edge> edges() {
        return edges;
    }

    public Map<String, ClassOwner> classOwners() {
        return classOwners;
    }

    public Optional<Node> node(String ref) {
        return ref == null ? Optional.empty() : Optional.ofNullable(nodes.get(ref));
    }

    public Optional<ClassOwner> classOwner(String className) {
        return className == null ? Optional.empty() : Optional.ofNullable(classOwners.get(className));
    }

    public boolean applicationOwned(String className) {
        return classOwner(className).map(ClassOwner::applicationOwned).orElse(false);
    }

    public boolean hasConflicts() {
        return classOwners.values().stream().anyMatch(owner -> owner.resolution() != Resolution.SELECTED)
                || nodes.values().stream().anyMatch(node -> node.resolution() != Resolution.SELECTED)
                || nodes.values().stream().anyMatch(node -> !node.error().isBlank());
    }

    public String semanticDigest() {
        return semanticDigest;
    }

    /** Return the same graph with a new immutable class-ownership snapshot. */
    public DependencyGraph withClassOwners(Map<String, ClassOwner> owners) {
        return new DependencyGraph(new ArrayList<>(nodes.values()), edges, owners);
    }

    /**
     * Bind frontend class winners to the actual direct input ordinals.  Only the frontend may
     * supply this map; a class name alone is never enough to claim application ownership.
     */
    public DependencyGraph bindClassOwners(Map<String, Integer> primaryIndexes,
                                           Map<String, List<Integer>> duplicateIndexes,
                                           Set<String> applicationClassNames) {
        return bindClassOwners(primaryIndexes, duplicateIndexes, Map.of(),
                applicationClassNames);
    }

    /**
     * Bind owners with embedded archive provenance captured by the frontend.  A nested class is
     * read from the same outer target input ordinal as the application, so an ordinal alone
     * cannot represent an app-versus-embedded duplicate.
     */
    public DependencyGraph bindClassOwners(Map<String, Integer> primaryIndexes,
                                           Map<String, List<Integer>> duplicateIndexes,
                                           Map<String, List<String>> artifactDetails,
                                           Set<String> applicationClassNames) {
        if (primaryIndexes == null || applicationClassNames == null) {
            throw new IllegalArgumentException("frontend ownership inputs are required");
        }
        Map<String, ClassOwner> owners = new LinkedHashMap<>();
        for (Map.Entry<String, Integer> entry : primaryIndexes.entrySet()) {
            String className = requireText(entry.getKey(), "class owner key");
            Integer primaryIndex = Objects.requireNonNull(entry.getValue(), "primary artifact index");
            if (primaryIndex < 0) {
                throw new IllegalArgumentException("primary artifact index must be non-negative");
            }
            LinkedHashSet<Integer> indexes = new LinkedHashSet<>();
            indexes.add(primaryIndex);
            List<Integer> duplicates = duplicateIndexes == null
                    ? List.of() : duplicateIndexes.getOrDefault(className, List.of());
            for (Integer duplicate : duplicates) {
                if (duplicate == null || duplicate < 0) {
                    throw new IllegalArgumentException("duplicate artifact index is invalid");
                }
                indexes.add(duplicate);
            }
            List<String> candidates = indexes.stream()
                    .flatMap(index -> nodes.values().stream()
                            .filter(node -> node.inputIndex() == index)
                            .sorted(Comparator.comparing(Node::ref)))
                    .map(Node::ref)
                    .distinct()
                    .collect(java.util.stream.Collectors.toCollection(ArrayList::new));
            List<String> details = artifactDetails == null
                    ? List.of() : artifactDetails.getOrDefault(className, List.of());
            boolean unresolvedDetail = false;
            for (String detail : details) {
                if (detail == null || detail.isBlank()) {
                    throw new IllegalArgumentException("embedded artifact detail is invalid");
                }
                List<String> embeddedCandidates = nodes.values().stream()
                        .filter(node -> node.source() == Source.ACTUAL_EMBEDDED
                                && node.sourceDetail().equals(detail))
                        .sorted(Comparator.comparing(Node::ref))
                        .map(Node::ref)
                        .toList();
                if (embeddedCandidates.isEmpty()) {
                    unresolvedDetail = true;
                } else {
                    embeddedCandidates.stream().filter(ref -> !candidates.contains(ref))
                            .forEach(candidates::add);
                }
            }
            if (candidates.isEmpty()) {
                throw new IllegalArgumentException("class owner has no corresponding artifact: "
                        + className);
            }
            String selected = candidates.get(0);
            boolean applicationOwned = applicationClassNames.contains(className)
                    && nodes.get(selected).source() == Source.ACTUAL_APPLICATION;
            Resolution resolution = unresolvedDetail ? Resolution.UNRESOLVED
                    : candidates.size() > 1 ? Resolution.CONFLICT : Resolution.SELECTED;
            owners.put(className, new ClassOwner(className, selected, candidates,
                    resolution, applicationOwned));
        }
        return withClassOwners(owners);
    }

    private String computeSemanticDigest() {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            update(digest, "dependency-graph-v" + MODEL_VERSION);
            nodes.values().stream().sorted(Comparator.comparing(Node::ref)).forEach(node -> {
                update(digest, "node=" + node.ref());
                update(digest, "provenance=" + node.provenance().identity());
                update(digest, "source=" + node.source() + ":" + node.deployment());
                update(digest, "coordinates=" + node.group() + ':' + node.name() + ':'
                        + node.version() + ':' + node.type() + ':' + node.classifier());
                update(digest, "source-detail=" + node.sourceDetail());
                update(digest, "parent=" + node.parentRef());
                update(digest, "error=" + node.error() + ':' + node.errorDetail());
                update(digest, "input-index=" + node.inputIndex());
                update(digest, "scope=" + node.scope() + ":optional=" + node.optional());
                update(digest, "resolution=" + node.resolution() + ':' + node.resolutionReason());
            });
            edges.stream().sorted(Comparator.comparing(Edge::fromRef)
                    .thenComparing(Edge::toRef).thenComparing(Edge::kind)
                    .thenComparing(Edge::reason)).forEach(edge -> update(digest,
                            "edge=" + edge.fromRef() + '>' + edge.toRef() + ':'
                                    + edge.kind() + ':' + edge.reason()));
            classOwners.values().stream().sorted(Comparator.comparing(ClassOwner::className))
                    .forEach(owner -> update(digest, "class=" + owner.className() + ':'
                            + owner.selectedRef() + ':' + owner.candidateRefs() + ':'
                            + owner.resolution() + ':' + owner.applicationOwned()));
            return hex(digest.digest());
        } catch (NoSuchAlgorithmException impossible) {
            throw new AssertionError(impossible);
        }
    }

    private static String requireText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " is required");
        }
        return value;
    }

    private static void requireValue(String value, String field) {
        if (value == null) {
            throw new IllegalArgumentException(field + " must not be null");
        }
    }

    private static void update(MessageDigest digest, String value) {
        digest.update(value.getBytes(StandardCharsets.UTF_8));
        digest.update((byte) '\n');
    }

    private static String hex(byte[] bytes) {
        StringBuilder result = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) {
            result.append(String.format("%02x", value & 0xff));
        }
        return result.toString();
    }
}
