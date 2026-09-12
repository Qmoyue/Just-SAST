package io.just.sast.blackboard;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.function.IntSupplier;
import java.util.function.Supplier;

/**
 * Immutable startup snapshot of knowledge-source phase and product contracts.
 *
 * <p>ServiceLoader order is deliberately absent from this model.  A product requirement is
 * satisfiable only when a producer is in an earlier phase or has a strictly lower priority in
 * the same phase.  Equal-priority same-phase producers are rejected instead of being resolved
 * by an incidental id or registration order.  Sources that leave both product sets empty are
 * compatibility extensions; they retain the old event-only contract but cannot silently claim
 * a product dependency.</p>
 */
public final class PhaseGraph {

    /** Captured, side-effect-free source metadata used by both validation and dispatch. */
    public record Node(String sourceId, Phase phase, int priority,
                       Set<EventType> interests,
                       Set<RunProduct> requiresProducts,
                       Set<RunProduct> providesProducts) {
        public Node {
            sourceId = sourceId == null ? "" : sourceId;
            interests = immutableEnumSet(interests, EventType.class);
            requiresProducts = immutableEnumSet(requiresProducts, RunProduct.class);
            providesProducts = immutableEnumSet(providesProducts, RunProduct.class);
        }

        /** A source explicitly participates in typed product scheduling. */
        public boolean declaresProducts() {
            return !requiresProducts.isEmpty() || !providesProducts.isEmpty();
        }
    }

    /** Stable validation result; errors are closed reason-code-prefixed strings. */
    public record Validation(boolean valid, List<String> errors,
                             Set<RunProduct> initialProducts,
                             Set<RunProduct> resolvedProducts,
                             String digest) {
        public Validation {
            errors = errors == null ? List.of() : List.copyOf(errors);
            initialProducts = immutableEnumSet(initialProducts, RunProduct.class);
            resolvedProducts = immutableEnumSet(resolvedProducts, RunProduct.class);
            digest = digest == null || digest.isBlank() ? "" : digest;
        }
    }

    private final List<Node> nodes;
    private final List<String> metadataErrors;
    private final String digest;
    private final Map<String, Node> byId;
    private final Map<String, KnowledgeSource> sourcesById;

    private PhaseGraph(List<Node> nodes, List<String> metadataErrors,
                       Map<String, KnowledgeSource> sourcesById) {
        this.nodes = List.copyOf(nodes);
        this.metadataErrors = List.copyOf(metadataErrors);
        Map<String, Node> index = new LinkedHashMap<>();
        for (Node node : this.nodes) {
            index.putIfAbsent(node.sourceId(), node);
        }
        this.byId = Collections.unmodifiableMap(index);
        this.sourcesById = Collections.unmodifiableMap(new LinkedHashMap<>(sourcesById));
        this.digest = digest(this.nodes, this.metadataErrors);
    }

    /** Capture source metadata once, without invoking any source during validation later. */
    public static PhaseGraph from(List<KnowledgeSource> sources) {
        List<Node> captured = new ArrayList<>();
        List<String> metadataErrors = new ArrayList<>();
        Map<String, KnowledgeSource> bindings = new LinkedHashMap<>();
        if (sources != null) {
            for (int index = 0; index < sources.size(); index++) {
                KnowledgeSource source = sources.get(index);
                String fallbackId = "<source-" + index + ">";
                if (source == null) {
                    captured.add(new Node(fallbackId, null, 0, Set.of(), Set.of(), Set.of()));
                    metadataErrors.add("NULL_SOURCE:" + fallbackId);
                    continue;
                }
                String id = capture(source::id, fallbackId, "ID_ACCESS:" + fallbackId,
                        metadataErrors);
                Phase phase = capture(source::phase, null, "PHASE_ACCESS:" + id,
                        metadataErrors);
                int priority = captureInt(source::priority, 0, "PRIORITY_ACCESS:" + id,
                        metadataErrors);
                Set<EventType> interests = captureSet(source::interests, "INTERESTS_ACCESS:" + id,
                        metadataErrors);
                Set<RunProduct> requires = captureSet(source::requiresProducts,
                        "REQUIRES_ACCESS:" + id, metadataErrors);
                Set<RunProduct> provides = captureSet(source::providesProducts,
                        "PROVIDES_ACCESS:" + id, metadataErrors);
                captured.add(new Node(id, phase, priority, interests, requires, provides));
                bindings.putIfAbsent(id, source);
            }
        }
        captured.sort((left, right) -> {
            int phase = Integer.compare(phaseOrdinal(left.phase()), phaseOrdinal(right.phase()));
            if (phase != 0) return phase;
            int priority = Integer.compare(left.priority(), right.priority());
            if (priority != 0) return priority;
            return left.sourceId().compareTo(right.sourceId());
        });
        return new PhaseGraph(captured, metadataErrors, bindings);
    }

    public List<Node> nodes() {
        return nodes;
    }

    public List<String> sourceIds() {
        return nodes.stream().map(Node::sourceId).toList();
    }

    public Node node(String sourceId) {
        return byId.get(sourceId);
    }

    /** Package-private binding used by the controller; metadata was already captured in from(). */
    KnowledgeSource source(String sourceId) {
        return sourcesById.get(sourceId);
    }

    public String digest() {
        return digest;
    }

    /** Whether a requirement can be produced before this node within the same phase. */
    public boolean hasEarlierProducer(Node consumer, RunProduct product) {
        if (consumer == null || product == null) return false;
        for (Node candidate : nodes) {
            if (!candidate.providesProducts().contains(product)) continue;
            if (compareOrder(candidate, consumer) < 0) return true;
        }
        return false;
    }

    /** Validate metadata, product availability/order, ownership and dependency cycles. */
    public Validation validate() {
        List<String> errors = new ArrayList<>(metadataErrors);
        Set<RunProduct> initial = EnumSet.noneOf(RunProduct.class);
        for (RunProduct product : RunProduct.values()) {
            if (product.initiallyAvailable()) initial.add(product);
        }
        Set<RunProduct> resolved = EnumSet.copyOf(initial);
        Set<String> ids = new HashSet<>();
        Map<RunProduct, List<Node>> producers = new EnumMapBuilder().map();

        for (Node node : nodes) {
            if (node.sourceId().isBlank()) errors.add("BLANK_SOURCE_ID");
            if (!ids.add(node.sourceId())) errors.add("DUPLICATE_SOURCE_ID:" + node.sourceId());
            if (node.phase() == null) errors.add("NULL_PHASE:" + node.sourceId());
            if (node.priority() < 0) errors.add("NEGATIVE_PRIORITY:" + node.sourceId());
            if (node.declaresProducts()) {
                EventType expected = expectedEvent(node.phase());
                if (expected == null || !node.interests().contains(expected)) {
                    errors.add("PHASE_EVENT_MISMATCH:" + node.sourceId() + ":"
                            + (expected == null ? "UNKNOWN" : expected));
                }
            }
            for (RunProduct product : node.providesProducts()) {
                producers.computeIfAbsent(product, ignored -> new ArrayList<>()).add(node);
            }
        }

        for (Map.Entry<RunProduct, List<Node>> entry : producers.entrySet()) {
            RunProduct product = entry.getKey();
            List<Node> owners = entry.getValue();
            if (!product.appendOnly() && owners.size() > 1) {
                errors.add("DUPLICATE_PRODUCT_OWNER:" + product.name() + ":"
                        + owners.stream().map(Node::sourceId).sorted().toList());
            }
        }

        for (Node consumer : nodes) {
            for (RunProduct required : consumer.requiresProducts()) {
                if (initial.contains(required)) continue;
                List<Node> candidates = producers.getOrDefault(required, List.of());
                if (candidates.isEmpty()) {
                    errors.add("MISSING_PRODUCT:" + consumer.sourceId() + ":" + required.name());
                    continue;
                }
                boolean available = false;
                for (Node producer : candidates) {
                    int order = compareOrder(producer, consumer);
                    if (order < 0) {
                        if (consumer.phase() == Phase.ANALYSIS
                                && producer.phase() == Phase.ANALYSIS) {
                            // ANALYSIS is dispatched in parallel; a same-phase product edge
                            // would race regardless of priority and cannot be fail-closed.
                            errors.add("PARALLEL_PRODUCT_DEPENDENCY:" + consumer.sourceId()
                                    + ":" + required.name());
                            continue;
                        }
                        available = true;
                        break;
                    }
                }
                if (available) {
                    // The product becomes available for later nodes in this deterministic order.
                    resolved.add(required);
                } else {
                    errors.add("PRODUCT_ORDER_UNDECLARED:" + consumer.sourceId() + ":"
                            + required.name());
                }
            }
        }
        // Report the complete statically declared product vocabulary, while availability/order
        // errors above remain tied to the consumer that introduced the invalid edge.
        for (Map.Entry<RunProduct, List<Node>> entry : producers.entrySet()) {
            if (!entry.getValue().isEmpty()) {
                resolved.add(entry.getKey());
            }
        }

        detectCycles(producers, errors);
        return new Validation(errors.isEmpty(), errors, initial, resolved, digest);
    }

    private void detectCycles(Map<RunProduct, List<Node>> producers, List<String> errors) {
        Map<String, Set<String>> edges = new TreeMap<>();
        for (Node consumer : nodes) {
            for (RunProduct required : consumer.requiresProducts()) {
                List<Node> candidates = producers.getOrDefault(required, List.of());
                boolean hasOrderedProducer = candidates.stream()
                        .anyMatch(producer -> compareOrder(producer, consumer) < 0);
                for (Node producer : candidates) {
                    // Add only producers that can actually satisfy this consumer.  Later
                    // append-only contributors are not dependencies and must not manufacture
                    // a false cycle (e.g. calibration pruner -> later safe-config).
                    if (producer.sourceId().equals(consumer.sourceId())) continue;
                    if (hasOrderedProducer && compareOrder(producer, consumer) >= 0) continue;
                    edges.computeIfAbsent(consumer.sourceId(), ignored -> new TreeSet<>())
                            .add(producer.sourceId());
                }
            }
        }
        Set<String> visiting = new HashSet<>();
        Set<String> visited = new HashSet<>();
        for (String id : edges.keySet()) {
            if (hasCycle(id, edges, visiting, visited, new ArrayDeque<>())) {
                errors.add("PRODUCT_CYCLE:" + id);
            }
        }
    }

    private boolean hasCycle(String id, Map<String, Set<String>> edges, Set<String> visiting,
                              Set<String> visited, ArrayDeque<String> path) {
        if (visiting.contains(id)) return true;
        if (!visited.add(id)) return false;
        visiting.add(id);
        path.addLast(id);
        for (String next : edges.getOrDefault(id, Set.of())) {
            if (hasCycle(next, edges, visiting, visited, path)) return true;
        }
        path.removeLast();
        visiting.remove(id);
        return false;
    }

    /** Strict phase/priority ordering; equal priority never satisfies a dependency. */
    private static int compareOrder(Node producer, Node consumer) {
        int phase = Integer.compare(phaseOrdinal(producer.phase()), phaseOrdinal(consumer.phase()));
        if (phase != 0) return phase;
        return Integer.compare(producer.priority(), consumer.priority());
    }

    private static EventType expectedEvent(Phase phase) {
        if (phase == null) return null;
        return switch (phase) {
            case ANALYSIS -> EventType.SCAN_START;
            case COMPOSITION -> EventType.SCAN_ANALYZED;
            case CALIBRATION -> EventType.SCAN_COMPLETE;
        };
    }

    private static int phaseOrdinal(Phase phase) {
        return phase == null ? Integer.MAX_VALUE : phase.ordinal();
    }

    private static String digest(List<Node> nodes, List<String> metadataErrors) {
        StringBuilder canonical = new StringBuilder("phase-graph-v1\n");
        for (Node node : nodes) {
            canonical.append(node.sourceId()).append('|')
                    .append(node.phase() == null ? "<null>" : node.phase().name()).append('|')
                    .append(node.priority()).append('|')
                    .append(names(node.interests())).append('|')
                    .append(names(node.requiresProducts())).append('|')
                    .append(names(node.providesProducts())).append('\n');
        }
        metadataErrors.stream().sorted().forEach(error -> canonical.append("error|").append(error).append('\n'));
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(canonical.toString().getBytes(StandardCharsets.UTF_8));
            StringBuilder result = new StringBuilder(digest.length * 2);
            for (byte value : digest) result.append(String.format("%02x", value));
            return result.toString();
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 unavailable", impossible);
        }
    }

    private static String names(Set<?> values) {
        return values.stream().map(Object::toString).sorted().reduce((left, right) -> left + "," + right)
                .orElse("");
    }

    private static <E extends Enum<E>> Set<E> immutableEnumSet(Set<E> values, Class<E> type) {
        EnumSet<E> result = EnumSet.noneOf(type);
        if (values != null) {
            for (E value : values) if (value != null) result.add(value);
        }
        return Collections.unmodifiableSet(result);
    }

    private static <T> T capture(Supplier<T> supplier, T fallback, String error,
                                 List<String> errors) {
        try {
            T value = supplier.get();
            return value == null ? fallback : value;
        } catch (Throwable failure) {
            errors.add(error + ":" + failure.getClass().getSimpleName());
            return fallback;
        }
    }

    private static int captureInt(IntSupplier supplier, int fallback, String error,
                                 List<String> errors) {
        try {
            return supplier.getAsInt();
        } catch (Throwable failure) {
            errors.add(error + ":" + failure.getClass().getSimpleName());
            return fallback;
        }
    }

    private static <E> Set<E> captureSet(Supplier<Set<E>> supplier, String error,
                                         List<String> errors) {
        try {
            Set<E> value = supplier.get();
            return value == null ? Set.of() : Set.copyOf(value);
        } catch (Throwable failure) {
            errors.add(error + ":" + failure.getClass().getSimpleName());
            return Set.of();
        }
    }

    /** Small typed map factory to avoid exposing a mutable EnumMap from the public API. */
    private static final class EnumMapBuilder {
        private final Map<RunProduct, List<Node>> map = new java.util.EnumMap<>(RunProduct.class);

        Map<RunProduct, List<Node>> map() {
            return map;
        }
    }
}
