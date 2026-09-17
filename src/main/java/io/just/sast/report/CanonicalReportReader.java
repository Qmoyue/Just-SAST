package io.just.sast.report;

import io.just.sast.run.InputBudget;
import io.just.sast.util.ArchiveLimits;
import io.just.sast.chain.ChainIds;
import io.just.sast.util.IoUtil;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/** Reads the stable JUST-REPORT-V2 finding array for downstream static consumers. */
public final class CanonicalReportReader {

    public record ChainRecord(String id, String chainKey, String ruleId, String category, String severity,
                              String entryClass, String entryMethod, String entryDescriptor,
                              String entryKind, String sinkClass, String sinkMethod,
                              String sinkDescriptor, String rawSemantic, boolean exported) {

        public ChainRecord {
            id = required(id, "id");
            chainKey = chainKey == null ? "" : chainKey;
            ruleId = required(ruleId, "rule_id");
            category = required(category, "category");
            severity = required(severity, "severity");
            entryClass = required(entryClass, "entry.class");
            entryMethod = required(entryMethod, "entry.method");
            entryDescriptor = required(entryDescriptor, "entry.descriptor");
            entryKind = required(entryKind, "entry.kind");
            sinkClass = required(sinkClass, "sink.class");
            sinkMethod = required(sinkMethod, "sink.method");
            sinkDescriptor = required(sinkDescriptor, "sink.descriptor");
            rawSemantic = required(rawSemantic, "chain semantic");
        }

        public String identity() {
            return ChainIdentity.of(ruleId, entryClass, entryMethod, entryDescriptor, entryKind,
                    sinkClass, sinkMethod, sinkDescriptor);
        }

        /** Stable identity that keeps distinct path/object variants independently addressable. */
        public String variantIdentity() {
            return ChainIdentity.variantOf(identity(), chainKey);
        }

        public String semanticFingerprint() {
            return rawSemantic;
        }

        private static String required(String value, String name) {
            if (value == null) {
                throw new IllegalArgumentException("canonical report field is null: " + name);
            }
            return value;
        }
    }

    public record Snapshot(String schemaVersion, List<ChainRecord> chains) {
        public Snapshot {
            if (!ConciseReportProjection.SCHEMA_VERSION.equals(schemaVersion)) {
                throw new IllegalArgumentException("unsupported canonical report schema: "
                        + schemaVersion);
            }
            chains = List.copyOf(Objects.requireNonNull(chains, "canonical chains"));
        }

        /** Stable digest of the chain evidence, independent of report summary timing. */
        public String digest() {
            List<ChainRecord> ordered = new ArrayList<>(chains);
            ordered.sort(Comparator.comparing(ChainRecord::variantIdentity)
                    .thenComparing(ChainRecord::id));
            StringBuilder canonical = new StringBuilder();
            for (ChainRecord chain : ordered) {
                canonical.append(chain.variantIdentity()).append('\n')
                        .append(chain.semanticFingerprint()).append('\n');
            }
            return ChainIds.sha256(canonical.toString());
        }
    }

    public Snapshot read(Path file, InputBudget budget, InputBudget.Tracker tracker)
            throws IOException {
        Objects.requireNonNull(file, "file");
        InputBudget policy = Objects.requireNonNull(budget, "budget");
        InputBudget.Tracker accounting = Objects.requireNonNull(tracker, "tracker");
        ArchiveLimits.checkPathAncestors(file, policy);
        if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)
                || ArchiveLimits.isLinkOrReparsePoint(file)) {
            throw new IOException("canonical report is not a safe regular file: "
                    + file.toAbsolutePath());
        }
        ArchiveLimits.FileReadSnapshot snapshot = ArchiveLimits.snapshotRegularFile(
                file, policy, "CANONICAL_REPORT_INPUT");
        long limit = Math.min(policy.maxEntryBytes(), accounting.remainingReadBytes());
        if (snapshot.fileAttributes().size() > policy.maxEntryBytes()
                || snapshot.fileAttributes().size() > limit) {
            throw new IOException("CANONICAL_REPORT_INPUT_LIMIT:" + policy.maxEntryBytes());
        }
        byte[] bytes;
        try (IoUtil.OpenedInput opened = IoUtil.openRegularFile(file, "CANONICAL_REPORT_INPUT")) {
            bytes = IoUtil.readAll(opened.stream(), limit, accounting);
        }
        ArchiveLimits.verifyRegularFileUnchanged(snapshot, "CANONICAL_REPORT_INPUT");
        try {
            return parse(new String(bytes, StandardCharsets.UTF_8));
        } catch (IllegalArgumentException failure) {
            throw new IOException("CANONICAL_REPORT_INVALID:" + failure.getMessage(), failure);
        }
    }

    private static Snapshot parse(String text) {
        Node root = new Parser(text).parseDocument();
        ObjectNode object = object(root, "root");
        String schema = requiredString(required(object, "schema_version"), "schema_version");
        requireFields(object, "root", "schema_version", "mode", "result", "findings",
                "provenance");
        String mode = requiredString(required(object, "mode"), "mode");
        if (!"component".equals(mode) && !"application".equals(mode)) {
            throw new IllegalArgumentException("unsupported report mode: " + mode);
        }
        ObjectNode result = object(required(object, "result"), "result");
        requireFields(result, "result", "outcome", "coverage", "candidates", "exported",
                "limits");
        String outcome = requiredString(required(result, "outcome"), "result.outcome");
        if (!Set.of("FINDINGS_AVAILABLE", "NO_FINDINGS", "FAILED", "UNSUPPORTED")
                .contains(outcome)) {
            throw new IllegalArgumentException("unsupported result outcome: " + outcome);
        }
        String coverage = requiredString(required(result, "coverage"), "result.coverage");
        if (!Set.of("COMPLETE", "BOUNDED", "UNKNOWN").contains(coverage)) {
            throw new IllegalArgumentException("unsupported result coverage: " + coverage);
        }
        Long candidates = optionalNonNegativeInteger(result, "candidates", "result.candidates");
        Long exported = optionalNonNegativeInteger(result, "exported", "result.exported");
        if (candidates != null && exported != null && exported > candidates) {
            throw new IllegalArgumentException("result exported count exceeds candidates");
        }
        optionalLimits(result, "limits", "result.limits");
        ObjectNode provenance = object(required(object, "provenance"), "provenance");
        requireFields(provenance, "provenance", "artifact_sha256", "detail");
        requiredString(required(provenance, "artifact_sha256"), "provenance.artifact_sha256");
        requiredString(required(provenance, "detail"), "provenance.detail");
        ArrayNode chains = array(required(object, "findings"), "findings");
        List<ChainRecord> records = new ArrayList<>();
        Map<String, ChainRecord> byIdentity = new LinkedHashMap<>();
        Set<String> ids = new java.util.HashSet<>();
        for (Node node : chains.values()) {
            ObjectNode item = object(node, "findings[]");
            requireFields(item, "findings[]", "id", "status", "entry", "impact", "graph",
                    "proof", "limits");
            String id = requiredString(required(item, "id"), "findings[].id");
            if (!ids.add(id)) {
                throw new IllegalArgumentException("duplicate finding id: " + id);
            }
            String status = requiredString(required(item, "status"), "findings[].status");
            if (!Set.of("COMPLETE", "PARTIAL", "UNKNOWN").contains(status)) {
                throw new IllegalArgumentException("unsupported finding status: " + status);
            }
            ObjectNode entry = object(required(item, "entry"), "entry");
            requireFields(entry, "entry", "owner", "method", "descriptor", "kind", "role");
            ObjectNode impact = object(required(item, "impact"), "impact");
            requireFields(impact, "impact", "owner", "method", "descriptor", "kind", "role");
            ArrayNode graph = array(required(item, "graph"), "graph");
            if (graph.values().isEmpty()) {
                throw new IllegalArgumentException("finding graph must not be empty");
            }
            for (Node graphNode : graph.values()) {
                ObjectNode graphObject = object(graphNode, "graph[]");
                requireFields(graphObject, "graph[]", "role", "label");
                String role = requiredString(required(graphObject, "role"), "graph[].role");
                if (!Set.of("ENTRY", "SITE", "SOURCE", "DESERIALIZE", "CALLBACK", "BRIDGE",
                        "STEP", "IMPACT", "BOUNDARY").contains(role)) {
                    throw new IllegalArgumentException("unsupported graph role: " + role);
                }
                requiredString(required(graphObject, "label"), "graph[].label");
            }
            ObjectNode proof = object(required(item, "proof"), "proof");
            requireFields(proof, "proof", "entry", "site", "input", "callback", "bridge",
                    "terminal", "feasibility");
            for (String key : List.of("entry", "site", "input", "callback", "bridge",
                    "terminal", "feasibility")) {
                requiredString(required(proof, key), "proof." + key);
            }
            List<String> findingLimits = optionalLimits(item, "limits", "findings[].limits");
            if ("COMPLETE".equals(status) && !findingLimits.isEmpty()) {
                throw new IllegalArgumentException("complete finding has proof limits");
            }
            if (!"COMPLETE".equals(status) && findingLimits.isEmpty()) {
                throw new IllegalArgumentException("incomplete finding needs a named proof limit");
            }
            ChainRecord record = new ChainRecord(
                    id, id, "JUST-REPORT-V2", "FINDING", status,
                    requiredString(required(entry, "owner"), "entry.owner"),
                    requiredString(required(entry, "method"), "entry.method"),
                    requiredString(required(entry, "descriptor"), "entry.descriptor"),
                    optionalString(entry, "kind"),
                    requiredString(required(impact, "owner"), "impact.owner"),
                    requiredString(required(impact, "method"), "impact.method"),
                    requiredString(required(impact, "descriptor"), "impact.descriptor"),
                    canonicalWithoutId(item),
                    true);
            if (byIdentity.put(record.variantIdentity(), record) != null) {
                throw new IllegalArgumentException("duplicate canonical chain identity: "
                        + record.variantIdentity());
            }
            records.add(record);
        }
        return new Snapshot(schema, records);
    }

    private static void requireFields(ObjectNode object, String name, String... allowed) {
        java.util.Set<String> fields = Set.of(allowed);
        for (String key : object.fields().keySet()) {
            if (!fields.contains(key)) {
                throw new IllegalArgumentException("unexpected field in " + name + ": " + key);
            }
        }
        for (String key : allowed) {
            if (!key.equals("kind") && !key.equals("role") && !key.equals("limits")
                    && !key.equals("candidates") && !key.equals("exported")
                    && !object.fields().containsKey(key)) {
                throw new IllegalArgumentException("missing field: " + name + "." + key);
            }
        }
    }

    private static String optionalString(ObjectNode object, String key) {
        Node value = object.fields().get(key);
        return value == null ? "" : requiredString(value, key);
    }

    private static List<String> optionalLimits(ObjectNode object, String key, String name) {
        Node value = object.fields().get(key);
        if (value == null) {
            return List.of();
        }
        ArrayNode array = array(value, name);
        if (array.values().isEmpty()) {
            throw new IllegalArgumentException("limits must not be empty: " + name);
        }
        Set<String> seen = new java.util.HashSet<>();
        List<String> limits = new ArrayList<>();
        for (Node item : array.values()) {
            String limit = requiredString(item, name + "[]");
            if (!seen.add(limit)) {
                throw new IllegalArgumentException("duplicate limit: " + name + "=" + limit);
            }
            limits.add(limit);
        }
        return List.copyOf(limits);
    }

    private static Long optionalNonNegativeInteger(ObjectNode object, String key, String name) {
        Node value = object.fields().get(key);
        if (value == null) {
            return null;
        }
        if (!(value instanceof ScalarNode scalar)
                || !scalar.raw().matches("0|[1-9][0-9]*")) {
            throw new IllegalArgumentException("expected non-negative integer: " + name);
        }
        try {
            return Long.parseLong(scalar.raw());
        } catch (NumberFormatException failure) {
            throw new IllegalArgumentException("integer out of range: " + name, failure);
        }
    }

    private static String requiredString(Node node, String name) {
        String value = string(node, name);
        if (value.isBlank()) {
            throw new IllegalArgumentException("expected non-blank string: " + name);
        }
        return value;
    }

    private static Node required(ObjectNode object, String key) {
        Node value = object.fields().get(key);
        if (value == null) {
            throw new IllegalArgumentException("missing field: " + key);
        }
        return value;
    }

    private static ObjectNode object(Node node, String name) {
        if (!(node instanceof ObjectNode value)) {
            throw new IllegalArgumentException("expected object: " + name);
        }
        return value;
    }

    private static ArrayNode array(Node node, String name) {
        if (!(node instanceof ArrayNode value)) {
            throw new IllegalArgumentException("expected array: " + name);
        }
        return value;
    }

    private static String string(Node node, String name) {
        if (!(node instanceof StringNode value)) {
            throw new IllegalArgumentException("expected string: " + name);
        }
        return value.value();
    }

    private static String canonicalWithoutId(ObjectNode object) {
        StringBuilder result = new StringBuilder("{");
        object.fields().entrySet().stream()
                .filter(entry -> !"id".equals(entry.getKey()))
                .sorted(Map.Entry.comparingByKey())
                .forEachOrdered(new java.util.function.Consumer<>() {
                    private boolean first = true;

                    @Override
                    public void accept(Map.Entry<String, Node> entry) {
                        if (!first) {
                            result.append(',');
                        }
                        first = false;
                        result.append(quote(entry.getKey())).append(':')
                                .append(canonical(entry.getValue()));
                    }
                });
        return result.append('}').toString();
    }

    private static String canonical(Node node) {
        if (node instanceof StringNode value) {
            return quote(value.value());
        }
        if (node instanceof ScalarNode value) {
            return value.raw();
        }
        if (node instanceof ArrayNode value) {
            StringBuilder result = new StringBuilder("[");
            for (int i = 0; i < value.values().size(); i++) {
                if (i > 0) {
                    result.append(',');
                }
                result.append(canonical(value.values().get(i)));
            }
            return result.append(']').toString();
        }
        ObjectNode value = (ObjectNode) node;
        StringBuilder result = new StringBuilder("{");
        value.fields().entrySet().stream().sorted(Map.Entry.comparingByKey())
                .forEachOrdered(new java.util.function.Consumer<>() {
                    private boolean first = true;

                    @Override
                    public void accept(Map.Entry<String, Node> entry) {
                        if (!first) {
                            result.append(',');
                        }
                        first = false;
                        result.append(quote(entry.getKey())).append(':')
                                .append(canonical(entry.getValue()));
                    }
                });
        return result.append('}').toString();
    }

    private static String quote(String value) {
        StringBuilder result = new StringBuilder(value.length() + 2).append('"');
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            switch (ch) {
                case '"' -> result.append("\\\"");
                case '\\' -> result.append("\\\\");
                case '\b' -> result.append("\\b");
                case '\f' -> result.append("\\f");
                case '\n' -> result.append("\\n");
                case '\r' -> result.append("\\r");
                case '\t' -> result.append("\\t");
                default -> {
                    if (ch < 0x20) {
                        result.append(String.format(java.util.Locale.ROOT, "\\u%04x", (int) ch));
                    } else {
                        result.append(ch);
                    }
                }
            }
        }
        return result.append('"').toString();
    }

    private interface Node {
        String raw();
    }

    private record ObjectNode(Map<String, Node> fields, String raw) implements Node {
    }

    private record ArrayNode(List<Node> values, String raw) implements Node {
    }

    private record StringNode(String value, String raw) implements Node {
    }

    private record ScalarNode(String raw) implements Node {
    }

    private static final class Parser {
        private static final java.util.regex.Pattern NUMBER = java.util.regex.Pattern.compile(
                "-?(?:0|[1-9][0-9]*)(?:\\.[0-9]+)?(?:[eE][+-]?[0-9]+)?");
        private final String text;
        private int position;

        private Parser(String text) {
            this.text = Objects.requireNonNull(text, "text");
        }

        private Node parseDocument() {
            skipWhitespace();
            Node value = parseValue();
            skipWhitespace();
            if (position != text.length()) {
                fail("trailing data");
            }
            return value;
        }

        private Node parseValue() {
            skipWhitespace();
            if (position >= text.length()) {
                fail("unexpected end of input");
            }
            char ch = text.charAt(position);
            return switch (ch) {
                case '{' -> parseObject();
                case '[' -> parseArray();
                case '"' -> parseString();
                case 't' -> parseLiteral("true");
                case 'f' -> parseLiteral("false");
                case 'n' -> parseLiteral("null");
                default -> (ch == '-' || Character.isDigit(ch)) ? parseNumber()
                        : fail("unexpected value");
            };
        }

        private ObjectNode parseObject() {
            int start = position++;
            Map<String, Node> fields = new LinkedHashMap<>();
            skipWhitespace();
            if (consume('}')) {
                return new ObjectNode(Map.copyOf(fields), text.substring(start, position));
            }
            while (true) {
                skipWhitespace();
                Node keyNode = parseString();
                String key = ((StringNode) keyNode).value();
                skipWhitespace();
                expect(':');
                Node value = parseValue();
                if (fields.put(key, value) != null) {
                    fail("duplicate object field: " + key);
                }
                skipWhitespace();
                if (consume('}')) {
                    return new ObjectNode(Map.copyOf(fields), text.substring(start, position));
                }
                expect(',');
            }
        }

        private ArrayNode parseArray() {
            int start = position++;
            List<Node> values = new ArrayList<>();
            skipWhitespace();
            if (consume(']')) {
                return new ArrayNode(List.copyOf(values), text.substring(start, position));
            }
            while (true) {
                values.add(parseValue());
                skipWhitespace();
                if (consume(']')) {
                    return new ArrayNode(List.copyOf(values), text.substring(start, position));
                }
                expect(',');
            }
        }

        private StringNode parseString() {
            int start = position;
            expect('"');
            StringBuilder value = new StringBuilder();
            while (position < text.length()) {
                char ch = text.charAt(position++);
                if (ch == '"') {
                    return new StringNode(value.toString(), text.substring(start, position));
                }
                if (ch < 0x20) {
                    fail("control character in string");
                }
                if (ch != '\\') {
                    value.append(ch);
                    continue;
                }
                if (position >= text.length()) {
                    fail("unterminated escape");
                }
                char escape = text.charAt(position++);
                switch (escape) {
                    case '"', '\\', '/' -> value.append(escape);
                    case 'b' -> value.append('\b');
                    case 'f' -> value.append('\f');
                    case 'n' -> value.append('\n');
                    case 'r' -> value.append('\r');
                    case 't' -> value.append('\t');
                    case 'u' -> value.append(parseUnicode());
                    default -> fail("invalid string escape");
                }
            }
            fail("unterminated string");
            return null;
        }

        private char parseUnicode() {
            if (position + 4 > text.length()) {
                fail("short unicode escape");
            }
            int value = 0;
            for (int i = 0; i < 4; i++) {
                int digit = Character.digit(text.charAt(position++), 16);
                if (digit < 0) {
                    fail("invalid unicode escape");
                }
                value = value * 16 + digit;
            }
            return (char) value;
        }

        private ScalarNode parseLiteral(String literal) {
            int start = position;
            if (!text.startsWith(literal, position)) {
                fail("invalid literal");
            }
            position += literal.length();
            return new ScalarNode(text.substring(start, position));
        }

        private ScalarNode parseNumber() {
            int start = position;
            while (position < text.length()) {
                char ch = text.charAt(position);
                if (Character.isDigit(ch) || ch == '-' || ch == '+' || ch == '.'
                        || ch == 'e' || ch == 'E') {
                    position++;
                } else {
                    break;
                }
            }
            String raw = text.substring(start, position);
            if (!NUMBER.matcher(raw).matches()) {
                fail("invalid number");
            }
            return new ScalarNode(raw);
        }

        private void skipWhitespace() {
            while (position < text.length()) {
                char ch = text.charAt(position);
                if (ch != ' ' && ch != '\t' && ch != '\r' && ch != '\n') {
                    return;
                }
                position++;
            }
        }

        private boolean consume(char expected) {
            if (position < text.length() && text.charAt(position) == expected) {
                position++;
                return true;
            }
            return false;
        }

        private void expect(char expected) {
            if (!consume(expected)) {
                fail("expected '" + expected + "'");
            }
        }

        private <T> T fail(String message) {
            throw new IllegalArgumentException(message + " at " + position);
        }
    }
}
