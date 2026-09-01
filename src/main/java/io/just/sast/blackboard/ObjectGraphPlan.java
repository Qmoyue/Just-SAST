package io.just.sast.blackboard;

import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Declarative, bounded object-shape evidence used by the safe verifier.
 *
 * <p>This is a description of a candidate graph, not a payload.  Nodes are allocated without
 * invoking target constructors by the child probe; proxy nodes are created by the probe's
 * already guarded JDK proxy factory.  Values are deliberately small and typed so a rule cannot
 * smuggle an executable expression into the verifier protocol.</p>
 */
public record ObjectGraphPlan(List<Node> nodes, List<FieldAssignment> fields) {

    /**
     * Shape-only construction evidence.  It deliberately does not claim that a target class
     * can be instantiated on the selected JDK: that fact is established by the isolated
     * verifier.  The summary is nevertheless useful before dynamic verification because it
     * catches dangling references and field owners without loading or executing target code.
     */
    public record ShapeSummary(int nodeCount, int fieldCount, int referenceCount,
                               int resolvedReferenceCount, int fieldOwnersResolved,
                               int fieldOwnersUnresolved, boolean valid, List<String> reasons) {
        public ShapeSummary {
            nodeCount = Math.max(0, nodeCount);
            fieldCount = Math.max(0, fieldCount);
            referenceCount = Math.max(0, referenceCount);
            resolvedReferenceCount = Math.max(0,
                    Math.min(referenceCount, resolvedReferenceCount));
            fieldOwnersResolved = Math.max(0, fieldOwnersResolved);
            fieldOwnersUnresolved = Math.max(0, fieldOwnersUnresolved);
            reasons = reasons == null ? List.of() : List.copyOf(reasons);
        }

        public String status() {
            return valid ? "SHAPE_VALID" : "SHAPE_PARTIAL";
        }
    }

    public enum NodeKind {
        ALLOCATE,
        PROXY,
        /** A probe-owned handler invokes only the declared target/interface method. */
        REFLECTIVE_PROXY,
        CONSTRUCTOR
    }

    public enum ValueKind {
        REF,
        CLASS,
        STRING,
        INT,
        LONG,
        BOOLEAN,
        NULL
    }

    public record Value(ValueKind kind, String value) {
        public Value {
            kind = kind == null ? ValueKind.NULL : kind;
            value = value == null ? "" : value;
            if (value.length() > 512) {
                throw new IllegalArgumentException("object-graph value is too long");
            }
        }

        public static Value ref(String id) {
            return new Value(ValueKind.REF, id);
        }

        public static Value classValue(String name) {
            return new Value(ValueKind.CLASS, name);
        }
    }

    public record Node(String id, String type, NodeKind kind, List<Value> arguments) {
        public Node {
            id = requireText(id, "node id");
            type = requireText(type, "node type");
            kind = kind == null ? NodeKind.ALLOCATE : kind;
            arguments = arguments == null ? List.of() : List.copyOf(arguments);
            if (arguments.size() > 16) {
                throw new IllegalArgumentException("object-graph constructor has too many arguments");
            }
        }
    }

    public record FieldAssignment(String owner, String field, List<Value> values) {
        public FieldAssignment {
            owner = requireText(owner, "field owner");
            field = requireText(field, "field name");
            values = values == null ? List.of() : List.copyOf(values);
            if (values.isEmpty() || values.size() > 32) {
                throw new IllegalArgumentException("object-graph field must have 1..32 values");
            }
        }
    }

    public ObjectGraphPlan {
        nodes = nodes == null ? List.of() : List.copyOf(nodes);
        fields = fields == null ? List.of() : List.copyOf(fields);
        if (nodes.size() > 64 || fields.size() > 128) {
            throw new IllegalArgumentException("object-graph plan exceeds bounded size");
        }
        Set<String> ids = new HashSet<>();
        for (Node node : nodes) {
            if (node == null || !ids.add(node.id())) {
                throw new IllegalArgumentException("object-graph node id is null or duplicated");
            }
        }
    }

    public boolean isEmpty() {
        return nodes.isEmpty() && fields.isEmpty();
    }

    /**
     * Validate only the declarative graph shape.  References may point to the implicit
     * {@code entry} binding even when a hand-authored plan omits an explicit entry node; this
     * mirrors the probe's construction contract.  Reasons are sorted to keep report output
     * deterministic regardless of list traversal order.
     */
    public ShapeSummary shapeSummary() {
        Set<String> ids = new HashSet<>();
        for (Node node : nodes) {
            if (node != null) {
                ids.add(node.id());
            }
        }
        Set<String> validReferences = new HashSet<>(ids);
        validReferences.add("entry");
        Set<String> reasons = new LinkedHashSet<>();
        int references = 0;
        int resolvedReferences = 0;
        for (Node node : nodes) {
            if (node == null) {
                reasons.add("NULL_NODE");
                continue;
            }
            for (Value value : node.arguments()) {
                if (value != null && value.kind() == ValueKind.REF) {
                    references++;
                    if (validReferences.contains(value.value())) {
                        resolvedReferences++;
                    } else {
                        reasons.add("MISSING_REFERENCE:" + value.value());
                    }
                }
            }
        }
        int ownersResolved = 0;
        int ownersUnresolved = 0;
        for (FieldAssignment assignment : fields) {
            if (assignment == null) {
                ownersUnresolved++;
                reasons.add("NULL_FIELD_ASSIGNMENT");
                continue;
            }
            if (validReferences.contains(assignment.owner())) {
                ownersResolved++;
            } else {
                ownersUnresolved++;
                reasons.add("MISSING_FIELD_OWNER:" + assignment.owner());
            }
            for (Value value : assignment.values()) {
                if (value != null && value.kind() == ValueKind.REF) {
                    references++;
                    if (validReferences.contains(value.value())) {
                        resolvedReferences++;
                    } else {
                        reasons.add("MISSING_REFERENCE:" + value.value());
                    }
                }
            }
        }
        List<String> stableReasons = new java.util.ArrayList<>(reasons);
        stableReasons.sort(String::compareTo);
        return new ShapeSummary(nodes.size(), fields.size(), references, resolvedReferences,
                ownersResolved, ownersUnresolved, stableReasons.isEmpty(), stableReasons);
    }

    /** Stable length-prefixed wire form for the isolated probe. */
    public String encodedForProbe() {
        StringBuilder out = new StringBuilder("v1;");
        out.append('N').append(nodes.size()).append(';');
        for (Node node : nodes) {
            append(out, node.id());
            append(out, node.type());
            append(out, node.kind().name());
            out.append(node.arguments().size()).append(';');
            for (Value value : node.arguments()) {
                append(out, value.kind().name());
                append(out, value.value());
            }
        }
        out.append('F').append(fields.size()).append(';');
        for (FieldAssignment assignment : fields) {
            append(out, assignment.owner());
            append(out, assignment.field());
            out.append(assignment.values().size()).append(';');
            for (Value value : assignment.values()) {
                append(out, value.kind().name());
                append(out, value.value());
            }
        }
        return out.toString();
    }

    /** Human/report identity; the protocol form is already deterministic and bounded. */
    public String fingerprint() {
        return encodedForProbe();
    }

    private static void append(StringBuilder out, String value) {
        String safe = value == null ? "" : value;
        out.append(safe.length()).append(':').append(safe);
    }

    private static String requireText(String value, String label) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(label + " must not be blank");
        }
        return value;
    }
}
