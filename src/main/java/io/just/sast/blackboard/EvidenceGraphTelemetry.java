package io.just.sast.blackboard;

import java.lang.management.ManagementFactory;
import java.lang.management.ThreadMXBean;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.function.Supplier;

/**
 * Bounded, deterministic telemetry for the immutable evidence graph.
 *
 * <p>The JVM does not expose a portable retained-size API.  The per-node value
 * therefore has an explicit {@code retainedBytesEstimate} name and status; it
 * must never be reported as process RSS.  RSS and process-tree values remain
 * owned by the external performance runner.  Construction CPU is sampled with
 * {@link ThreadMXBean} when the current JVM supports it.</p>
 */
public final class EvidenceGraphTelemetry {

    public static final String SCHEMA = "evidence-graph-telemetry-v1";
    public static final String RETAINED_SIZE_STATUS = "ESTIMATED_STRUCTURAL";
    public static final String RSS_STATUS = "NOT_OBSERVED_EXTERNAL_RUNNER";

    private static final long OBJECT_HEADER_BYTES = 16L;
    private static final long REFERENCE_BYTES = 8L;
    private static final long STRING_HEADER_BYTES = 24L;
    private static final long MAP_HEADER_BYTES = 48L;
    private static final long MAP_ENTRY_BYTES = 32L;
    private static final long LIST_HEADER_BYTES = 24L;
    private static final long LIST_ENTRY_BYTES = 8L;

    private EvidenceGraphTelemetry() {
    }

    /** One immutable node measurement; the byte counts are deterministic estimates. */
    public record NodeMeasurement(String id, EvidenceNode.NodeKind kind, long serializedBytes,
                                  long canonicalBytes, long retainedBytesEstimate) {
        public NodeMeasurement {
            id = Objects.requireNonNull(id, "id");
            kind = Objects.requireNonNull(kind, "kind");
            requireNonNegative(serializedBytes, "serializedBytes");
            requireNonNegative(canonicalBytes, "canonicalBytes");
            requireNonNegative(retainedBytesEstimate, "retainedBytesEstimate");
        }
    }

    /** One immutable edge measurement; edges are included in graph retained bytes. */
    public record EdgeMeasurement(String id, EvidenceEdge.Kind kind, long serializedBytes,
                                  long canonicalBytes, long retainedBytesEstimate) {
        public EdgeMeasurement {
            id = Objects.requireNonNull(id, "id");
            kind = Objects.requireNonNull(kind, "kind");
            requireNonNegative(serializedBytes, "serializedBytes");
            requireNonNegative(canonicalBytes, "canonicalBytes");
            requireNonNegative(retainedBytesEstimate, "retainedBytesEstimate");
        }
    }

    /**
     * Full graph measurement.  A negative construction value means that the
     * graph was measured after construction (or CPU sampling was unavailable).
     */
    public record Measurement(String schema, String graphDigest, int nodeCount, int edgeCount,
                              long serializedBytes, long retainedBytesEstimate,
                              long constructionWallNanos, long constructionCpuNanos,
                              String constructionCpuStatus, String retainedSizeStatus,
                              long rssBytes, String rssStatus, List<NodeMeasurement> nodes,
                              List<EdgeMeasurement> edges) {
        public Measurement {
            schema = Objects.requireNonNull(schema, "schema");
            graphDigest = Objects.requireNonNull(graphDigest, "graphDigest");
            if (nodeCount < 0 || edgeCount < 0) {
                throw new IllegalArgumentException("graph counts must be non-negative");
            }
            requireNonNegative(serializedBytes, "serializedBytes");
            requireNonNegative(retainedBytesEstimate, "retainedBytesEstimate");
            requireSentinelOrNonNegative(constructionWallNanos, "constructionWallNanos");
            requireSentinelOrNonNegative(constructionCpuNanos, "constructionCpuNanos");
            constructionCpuStatus = Objects.requireNonNull(constructionCpuStatus,
                    "constructionCpuStatus");
            retainedSizeStatus = Objects.requireNonNull(retainedSizeStatus,
                    "retainedSizeStatus");
            requireSentinelOrNonNegative(rssBytes, "rssBytes");
            rssStatus = Objects.requireNonNull(rssStatus, "rssStatus");
            nodes = List.copyOf(Objects.requireNonNull(nodes, "nodes"));
            edges = List.copyOf(Objects.requireNonNull(edges, "edges"));
            if (nodes.size() != nodeCount || edges.size() != edgeCount) {
                throw new IllegalArgumentException("measurement counts do not match details");
            }
        }

        public boolean hasConstructionCpu() {
            return constructionCpuNanos >= 0L && "OBSERVED".equals(constructionCpuStatus);
        }

        public String toCanonicalJson() {
            int capacity = (int) Math.min(Integer.MAX_VALUE - 8L,
                    Math.max(256L, 256L + serializedBytes));
            StringBuilder json = new StringBuilder(capacity)
                    .append("{\"schema\":\"").append(EvidenceIdSupport.json(schema))
                    .append("\",\"graphDigest\":\"")
                    .append(EvidenceIdSupport.json(graphDigest))
                    .append("\",\"nodeCount\":").append(nodeCount)
                    .append(",\"edgeCount\":").append(edgeCount)
                    .append(",\"serializedBytes\":").append(serializedBytes)
                    .append(",\"retainedBytesEstimate\":").append(retainedBytesEstimate)
                    .append(",\"constructionWallNanos\":").append(constructionWallNanos)
                    .append(",\"constructionCpuNanos\":").append(constructionCpuNanos)
                    .append(",\"constructionCpuStatus\":\"")
                    .append(EvidenceIdSupport.json(constructionCpuStatus))
                    .append("\",\"retainedSizeStatus\":\"")
                    .append(EvidenceIdSupport.json(retainedSizeStatus))
                    .append("\",\"rssBytes\":").append(rssBytes)
                    .append(",\"rssStatus\":\"")
                    .append(EvidenceIdSupport.json(rssStatus)).append("\",\"nodes\":[");
            for (int index = 0; index < nodes.size(); index++) {
                if (index > 0) {
                    json.append(',');
                }
                NodeMeasurement node = nodes.get(index);
                json.append("{\"id\":\"").append(EvidenceIdSupport.json(node.id()))
                        .append("\",\"kind\":\"").append(node.kind())
                        .append("\",\"serializedBytes\":").append(node.serializedBytes())
                        .append(",\"canonicalBytes\":").append(node.canonicalBytes())
                        .append(",\"retainedBytesEstimate\":")
                        .append(node.retainedBytesEstimate()).append('}');
            }
            json.append("],\"edges\":[");
            for (int index = 0; index < edges.size(); index++) {
                if (index > 0) {
                    json.append(',');
                }
                EdgeMeasurement edge = edges.get(index);
                json.append("{\"id\":\"").append(EvidenceIdSupport.json(edge.id()))
                        .append("\",\"kind\":\"").append(edge.kind())
                        .append("\",\"serializedBytes\":").append(edge.serializedBytes())
                        .append(",\"canonicalBytes\":").append(edge.canonicalBytes())
                        .append(",\"retainedBytesEstimate\":")
                        .append(edge.retainedBytesEstimate()).append('}');
            }
            return json.append("]}").toString();
        }
    }

    /** Ratios used for a typed-vs-baseline characterization; RSS is optional and explicit. */
    public record OverheadComparison(double wallRatio, double cpuRatio, double retainedRatio,
                                     double serializedRatio, double rssRatio,
                                     boolean rssComparable, boolean withinLimit,
                                     String status) {
        public OverheadComparison {
            requireRatio(wallRatio, "wallRatio");
            requireRatio(cpuRatio, "cpuRatio");
            requireRatio(retainedRatio, "retainedRatio");
            requireRatio(serializedRatio, "serializedRatio");
            requireRatio(rssRatio, "rssRatio");
            status = Objects.requireNonNull(status, "status");
        }
    }

    /** Measure an already-built graph; construction CPU/wall are intentionally unavailable. */
    public static Measurement measure(EvidenceGraph graph) {
        return measureGraph(Objects.requireNonNull(graph, "graph"), -1L, -1L, "NOT_OBSERVED");
    }

    /**
     * Build and measure a graph in one call.  The supplier must be side-effect free;
     * this method exists for characterization and must not execute target code.
     */
    public static Measurement measure(Supplier<EvidenceGraph> factory) {
        Objects.requireNonNull(factory, "factory");
        ThreadMXBean bean = ManagementFactory.getThreadMXBean();
        boolean cpuSupported = bean.isCurrentThreadCpuTimeSupported();
        long cpuStart = cpuSupported ? bean.getCurrentThreadCpuTime() : -1L;
        long wallStart = System.nanoTime();
        EvidenceGraph graph = Objects.requireNonNull(factory.get(), "factory result");
        long wallNanos = nonNegativeDelta(System.nanoTime(), wallStart);
        long cpuNanos = cpuSupported
                ? nonNegativeDelta(bean.getCurrentThreadCpuTime(), cpuStart) : -1L;
        return measureGraph(graph, wallNanos, cpuNanos,
                cpuSupported ? "OBSERVED" : "NOT_SUPPORTED");
    }

    /** Compare two measurements without inventing an RSS value when the runner did not observe it. */
    public static OverheadComparison compare(Measurement baseline, Measurement typed,
                                             double maxRatio) {
        Objects.requireNonNull(baseline, "baseline");
        Objects.requireNonNull(typed, "typed");
        if (!(maxRatio >= 1.0d) || Double.isInfinite(maxRatio) || Double.isNaN(maxRatio)) {
            throw new IllegalArgumentException("maxRatio must be finite and >= 1.0");
        }
        double wall = ratio(baseline.constructionWallNanos(), typed.constructionWallNanos());
        double cpu = ratio(baseline.constructionCpuNanos(), typed.constructionCpuNanos());
        double retained = ratio(baseline.retainedBytesEstimate(), typed.retainedBytesEstimate());
        double serialized = ratio(baseline.serializedBytes(), typed.serializedBytes());
        boolean rssComparable = baseline.rssBytes() > 0L && typed.rssBytes() > 0L;
        double rss = rssComparable ? ratio(baseline.rssBytes(), typed.rssBytes()) : -1.0d;
        boolean comparable = wall >= 0.0d && retained >= 0.0d;
        boolean within = comparable && wall <= maxRatio && retained <= maxRatio
                && (!rssComparable || rss <= maxRatio);
        String status = within ? "PASS" : comparable ? "OVER_LIMIT" : "NOT_COMPARABLE";
        return new OverheadComparison(wall, cpu, retained, serialized, rss, rssComparable,
                within, status);
    }

    private static Measurement measureGraph(EvidenceGraph graph, long wallNanos, long cpuNanos,
                                            String cpuStatus) {
        ArrayList<NodeMeasurement> nodes = new ArrayList<>(graph.nodes().size());
        long retained = LIST_HEADER_BYTES;
        for (EvidenceNode node : graph.nodes()) {
            String serialized = node.toCanonicalJson();
            String canonical = node.canonical();
            NodeMeasurement measurement = new NodeMeasurement(node.id(), node.nodeKind(),
                    utf8Bytes(serialized), utf8Bytes(canonical), estimateNode(node));
            nodes.add(measurement);
            retained = safeAdd(retained, measurement.retainedBytesEstimate());
        }
        ArrayList<EdgeMeasurement> edges = new ArrayList<>(graph.edges().size());
        retained = safeAdd(retained, LIST_HEADER_BYTES);
        for (EvidenceEdge edge : graph.edges()) {
            String serialized = edge.toCanonicalJson();
            String canonical = edge.canonical();
            EdgeMeasurement measurement = new EdgeMeasurement(edge.id(), edge.kind(),
                    utf8Bytes(serialized), utf8Bytes(canonical), estimateEdge(edge));
            edges.add(measurement);
            retained = safeAdd(retained, measurement.retainedBytesEstimate());
        }
        retained = safeAdd(retained, safeMultiply(graph.nodes().size() + graph.edges().size(),
                REFERENCE_BYTES));
        return new Measurement(SCHEMA, graph.canonicalDigest(), graph.nodes().size(),
                graph.edges().size(), utf8Bytes(graph.toCanonicalJson()), retained, wallNanos,
                cpuNanos, cpuStatus, RETAINED_SIZE_STATUS, -1L, RSS_STATUS, nodes, edges);
    }

    private static long estimateNode(EvidenceNode node) {
        long size = OBJECT_HEADER_BYTES + stringBytes(node.id());
        if (node instanceof EvidenceAtom atom) {
            size = safeAdd(size, stringBytes(atom.artifactDigest()));
            size = safeAdd(size, stringBytes(atom.owner()));
            size = safeAdd(size, stringBytes(atom.member()));
            size = safeAdd(size, stringBytes(atom.evidenceCode()));
            size = safeAdd(size, mapBytes(atom.attributes()));
        } else if (node instanceof EntryChainJoinEvidence join) {
            size = safeAdd(size, stringBytes(join.applicationChainId().value()));
            size = safeAdd(size, stringBytes(join.applicationEntryAtomId()));
            size = safeAdd(size, stringBytes(join.applicationSiteAtomId()));
            size = safeAdd(size, stringBytes(join.dependencySegmentId().value()));
            size = safeAdd(size, stringBytes(join.valueFlow().name()));
            size = safeAdd(size, stringBytes(join.objectIdentity().name()));
            size = safeAdd(size, stringBytes(join.callbackSemantics().name()));
            size = safeAdd(size, stringBytes(join.runtimeTypeProof().name()));
            size = safeAdd(size, stringBytes(join.artifactCompatibility().name()));
            size = safeAdd(size, stringBytes(join.filterDominance().name()));
            size = safeAdd(size, stringBytes(join.constructionConstraint().name()));
            size = safeAdd(size, listBytes(join.bridgeEvidenceIds()));
        } else if (node instanceof BridgeEvidence bridge) {
            size = safeAdd(size, stringBytes(bridge.fromAtomId()));
            size = safeAdd(size, stringBytes(bridge.toAtomId()));
            size = safeAdd(size, stringBytes(bridge.protocol()));
            size = safeAdd(size, stringBytes(bridge.kind().name()));
            size = safeAdd(size, stringBytes(bridge.status().name()));
        }
        return align8(size);
    }

    private static long estimateEdge(EvidenceEdge edge) {
        long size = OBJECT_HEADER_BYTES + stringBytes(edge.id()) + stringBytes(edge.fromId())
                + stringBytes(edge.toId()) + stringBytes(edge.kind().name())
                + stringBytes(edge.reasonCode());
        return align8(size);
    }

    private static long mapBytes(java.util.Map<String, String> values) {
        long size = MAP_HEADER_BYTES;
        for (var entry : values.entrySet()) {
            size = safeAdd(size, MAP_ENTRY_BYTES + stringBytes(entry.getKey())
                    + stringBytes(entry.getValue()));
        }
        return align8(size);
    }

    private static long listBytes(List<String> values) {
        return align8(safeAdd(LIST_HEADER_BYTES,
                safeAdd(safeMultiply(values.size(), LIST_ENTRY_BYTES), values.stream()
                        .mapToLong(EvidenceGraphTelemetry::stringBytes).reduce(0L,
                                EvidenceGraphTelemetry::safeAdd))));
    }

    private static long stringBytes(String value) {
        if (value == null) {
            return 0L;
        }
        return align8(safeAdd(STRING_HEADER_BYTES, safeMultiply(value.length(), 2L)));
    }

    private static long utf8Bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8).length;
    }

    private static double ratio(long baseline, long typed) {
        if (baseline <= 0L || typed < 0L) {
            return -1.0d;
        }
        return (double) typed / (double) baseline;
    }

    private static long nonNegativeDelta(long end, long start) {
        return end >= start && start >= 0L ? end - start : -1L;
    }

    private static long safeMultiply(long left, long right) {
        if (left <= 0L || right <= 0L) {
            return 0L;
        }
        if (left > Long.MAX_VALUE / right) {
            return Long.MAX_VALUE;
        }
        return left * right;
    }

    private static long safeAdd(long left, long right) {
        if (right > 0L && left > Long.MAX_VALUE - right) {
            return Long.MAX_VALUE;
        }
        return left + right;
    }

    private static long align8(long value) {
        if (value >= Long.MAX_VALUE - 7L) {
            return Long.MAX_VALUE;
        }
        return (value + 7L) & ~7L;
    }

    private static void requireNonNegative(long value, String field) {
        if (value < 0L) {
            throw new IllegalArgumentException(field + " must be non-negative");
        }
    }

    private static void requireSentinelOrNonNegative(long value, String field) {
        if (value < -1L) {
            throw new IllegalArgumentException(field + " must be -1 or non-negative");
        }
    }

    private static void requireRatio(double value, String field) {
        if (value < -1.0d || Double.isNaN(value) || Double.isInfinite(value)) {
            throw new IllegalArgumentException(field + " must be -1 or finite non-negative");
        }
    }
}
