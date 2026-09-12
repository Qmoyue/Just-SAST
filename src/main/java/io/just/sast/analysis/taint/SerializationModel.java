package io.just.sast.analysis.taint;

import io.just.sast.config.Rule;

import java.util.Locale;
import java.util.Objects;
import java.util.Optional;

/**
 * Typed serialization boundaries shared by origin and reachability analyses.
 *
 * <p>This class is deliberately a pure classifier.  It does not inspect a graph, create a
 * synthetic root, or decide whether a candidate is an application finding.  The caller still
 * has to join the boundary to an application entry and a terminal impact.  In particular, a
 * conditional/second-deserialization source is never treated as an external root by this
 * model.</p>
 */
public final class SerializationModel {
    private SerializationModel() {
    }

    public enum Direction {
        DESERIALIZE,
        SERIALIZE,
        LIFECYCLE
    }

    public enum BoundaryKind {
        OIS_READ,
        FRAMEWORK_SOURCE,
        SECOND_DESERIALIZE,
        MAGIC_ENTRY
    }

    /** A normalized, path-independent description of one serialization boundary. */
    public record Boundary(BoundaryKind kind,
                           Direction direction,
                           boolean externalInput,
                           String ruleId,
                           String bridge,
                           String entryKind,
                           String owner,
                           String name,
                           String descriptor) {
        public Boundary {
            kind = Objects.requireNonNull(kind, "kind");
            direction = Objects.requireNonNull(direction, "direction");
            ruleId = token(ruleId);
            bridge = token(bridge);
            entryKind = token(entryKind);
            owner = token(owner);
            name = token(name);
            descriptor = token(descriptor);
            if (externalInput && kind == BoundaryKind.SECOND_DESERIALIZE) {
                throw new IllegalArgumentException("second deserialize cannot be an external root");
            }
        }

        public boolean requiresTaintedInput() {
            return kind == BoundaryKind.SECOND_DESERIALIZE;
        }

        public String canonical() {
            return "serialization-v1|" + kind + "|" + direction + "|external=" + externalInput
                    + "|" + ruleId + "|" + bridge + "|" + entryKind + "|" + owner + "|"
                    + name + "|" + descriptor;
        }
    }

    /** Classify an OIS read call without depending on graph/node classes. */
    public static boolean isOisRead(String owner, String name, String descriptor) {
        if (!"java/io/ObjectInputStream".equals(owner) || name == null) {
            return false;
        }
        return "readObject".equals(name) || "readUnshared".equals(name)
                || "readFields".equals(name);
    }

    /** Convert a source rule to a boundary; all non-serialize bridges preserve legacy semantics. */
    public static Optional<Boundary> source(Rule.SourceRule source,
                                            String owner, String name, String descriptor) {
        if (source == null) {
            return Optional.empty();
        }
        String bridge = normalizeBridge(source.bridge());
        Direction direction = directionForBridge(bridge);
        boolean unconditional = source.tainted() == null || source.tainted().isEmpty();
        boolean external = direction == Direction.DESERIALIZE && unconditional;
        BoundaryKind kind = direction == Direction.DESERIALIZE && !external
                ? BoundaryKind.SECOND_DESERIALIZE : BoundaryKind.FRAMEWORK_SOURCE;
        return Optional.of(new Boundary(kind, direction, external,
                source.id(), bridge, "", owner, name, descriptor));
    }

    /**
     * Convert an entry rule only when it is an independent deserialization callback.  Proxy
     * callbacks and serialized trigger methods are activated by an object graph and therefore
     * remain non-root semantics.
     */
    public static Optional<Boundary> magicEntry(Rule.MagicEntryRule entry,
                                                String owner, String name, String descriptor) {
        if (entry == null || !"deserialize".equalsIgnoreCase(entry.direction())) {
            return Optional.empty();
        }
        String kind = token(entry.entryKind());
        if ("proxyInvoke".equals(kind) || isSerializedTrigger(kind)) {
            return Optional.empty();
        }
        return Optional.of(new Boundary(BoundaryKind.MAGIC_ENTRY, Direction.DESERIALIZE, false,
                entry.id(), "deserialize", kind, owner, name, descriptor));
    }

    private static boolean isSerializedTrigger(String kind) {
        return "hashCode".equals(kind) || "equals".equals(kind) || "compareTo".equals(kind)
                || "compare".equals(kind) || "toString".equals(kind);
    }

    private static Direction directionForBridge(String bridge) {
        return "serialize".equals(bridge) ? Direction.SERIALIZE : Direction.DESERIALIZE;
    }

    private static String normalizeBridge(String value) {
        return token(value).toLowerCase(Locale.ROOT);
    }

    private static String token(String value) {
        if (value == null || value.isBlank()) {
            return "";
        }
        return value.trim().replace('\r', '_').replace('\n', '_').replace('|', '_');
    }
}
