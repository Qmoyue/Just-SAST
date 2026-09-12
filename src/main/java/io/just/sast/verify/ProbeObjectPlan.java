package io.just.sast.verify;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Bounded, immutable interpreter input for a rule-declared object shape.
 *
 * <p>The parser is deliberately independent of the scanner's {@code ObjectGraphPlan} model so
 * the child probe can remain a small Java 17/legacy-compatible runtime.  It only decodes data;
 * allocation, reflection and field writes remain explicit interpreter operations in the probe.
 * Invalid or over-budget input returns {@code null} and is reported as a partial path.</p>
 */
final class ProbeObjectPlan {

    enum NodeKind { ALLOCATE, PROXY, REFLECTIVE_PROXY, CONSTRUCTOR }

    static final class Value {
        final String kind;
        final String value;

        Value(String kind, String value) {
            this.kind = kind == null ? "" : kind;
            this.value = value == null ? "" : value;
        }
    }

    static final class Node {
        final String id;
        final String type;
        final NodeKind kind;
        final List<Value> arguments;

        Node(String id, String type, NodeKind kind, List<Value> arguments) {
            this.id = id == null ? "" : id;
            this.type = type == null ? "" : type;
            this.kind = kind;
            this.arguments = List.copyOf(arguments == null ? List.of() : arguments);
        }
    }

    static final class Field {
        final String owner;
        final String field;
        final List<Value> values;

        Field(String owner, String field, List<Value> values) {
            this.owner = owner == null ? "" : owner;
            this.field = field == null ? "" : field;
            this.values = List.copyOf(values == null ? List.of() : values);
        }
    }

    final List<Node> nodes;
    final List<Field> fields;

    private ProbeObjectPlan(List<Node> nodes, List<Field> fields) {
        this.nodes = List.copyOf(nodes == null ? List.of() : nodes);
        this.fields = List.copyOf(fields == null ? List.of() : fields);
    }

    boolean isEmpty() {
        return nodes.isEmpty() && fields.isEmpty();
    }

    /** Parse the ObjectGraphPlan v1 count/length-prefixed representation. */
    static ProbeObjectPlan parse(String encoded) {
        if (encoded == null || encoded.isEmpty()) {
            return new ProbeObjectPlan(List.of(), List.of());
        }
        try {
            Cursor cursor = new Cursor(encoded);
            if (!cursor.take("v1;") || !cursor.take('N')) {
                return null;
            }
            int nodeCount = cursor.count();
            if (!cursor.take(';') || nodeCount < 0 || nodeCount > 64) {
                return null;
            }
            List<Node> nodes = new ArrayList<>(nodeCount);
            Set<String> ids = new HashSet<>();
            for (int i = 0; i < nodeCount; i++) {
                String id = cursor.text();
                String type = cursor.text();
                String kindText = cursor.text();
                int argCount = cursor.count();
                if (id == null || type == null || kindText == null || argCount < 0 || argCount > 16
                        || !cursor.take(';') || !ids.add(id)) {
                    return null;
                }
                NodeKind kind;
                try {
                    kind = NodeKind.valueOf(kindText);
                } catch (IllegalArgumentException invalidKind) {
                    return null;
                }
                List<Value> arguments = new ArrayList<>(argCount);
                for (int a = 0; a < argCount; a++) {
                    String valueKind = cursor.text();
                    String value = cursor.text();
                    if (valueKind == null || value == null || !validValueKind(valueKind)) {
                        return null;
                    }
                    arguments.add(new Value(valueKind, value));
                }
                nodes.add(new Node(id, type, kind, arguments));
            }
            if (!cursor.take('F')) {
                return null;
            }
            int fieldCount = cursor.count();
            if (!cursor.take(';') || fieldCount < 0 || fieldCount > 128) {
                return null;
            }
            List<Field> fields = new ArrayList<>(fieldCount);
            for (int i = 0; i < fieldCount; i++) {
                String owner = cursor.text();
                String field = cursor.text();
                int valueCount = cursor.count();
                if (owner == null || field == null || valueCount <= 0 || valueCount > 32
                        || !cursor.take(';')) {
                    return null;
                }
                List<Value> values = new ArrayList<>(valueCount);
                for (int v = 0; v < valueCount; v++) {
                    String valueKind = cursor.text();
                    String value = cursor.text();
                    if (valueKind == null || value == null || !validValueKind(valueKind)) {
                        return null;
                    }
                    values.add(new Value(valueKind, value));
                }
                fields.add(new Field(owner, field, values));
            }
            return cursor.atEnd() ? new ProbeObjectPlan(nodes, fields) : null;
        } catch (RuntimeException malformed) {
            return null;
        }
    }

    private static boolean validValueKind(String kind) {
        return "REF".equals(kind) || "CLASS".equals(kind) || "STRING".equals(kind)
                || "INT".equals(kind) || "LONG".equals(kind) || "BOOLEAN".equals(kind)
                || "NULL".equals(kind);
    }

    /** Small allocation-bounded parser kept independent from any target class. */
    private static final class Cursor {
        private final String input;
        private int offset;

        private Cursor(String input) {
            this.input = input;
        }

        private boolean take(String value) {
            if (!input.startsWith(value, offset)) {
                return false;
            }
            offset += value.length();
            return true;
        }

        private boolean take(char value) {
            if (offset >= input.length() || input.charAt(offset) != value) {
                return false;
            }
            offset++;
            return true;
        }

        private int count() {
            int start = offset;
            while (offset < input.length() && Character.isDigit(input.charAt(offset))) {
                offset++;
            }
            if (start == offset || offset >= input.length()) {
                throw new IllegalArgumentException("missing count");
            }
            return Integer.parseInt(input.substring(start, offset));
        }

        private String text() {
            int length = count();
            if (!take(':') || length < 0 || length > 512 || offset + length > input.length()) {
                throw new IllegalArgumentException("invalid text");
            }
            String value = input.substring(offset, offset + length);
            offset += length;
            return value;
        }

        private boolean atEnd() {
            return offset == input.length();
        }
    }
}
