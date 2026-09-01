package io.just.sast.report;

import io.just.sast.blackboard.Chain;
import io.just.sast.chain.ChainIds;
import io.just.sast.util.ArchiveLimits;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.LinkOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * Emits baseline and suppression decisions without removing findings or evidence.
 *
 * <p>Selectors are semantic identities, {@code sha256:<identity digest>}, or
 * {@code rule:<rule_id>}. Unknown selectors are retained as UNUSED/INVALID so a typo cannot
 * silently create a false clean scan. This writer intentionally has no connection to a CVE
 * database or a runtime sink.</p>
 */
public final class BaselineSuppressionWriter {

    private static final long MAX_BASELINE_BYTES = 16L * 1024L * 1024L;
    private static final long MAX_SUPPRESSION_BYTES = 2L * 1024L * 1024L;

    private record Row(String identity, Chain chain, String status) {
    }

    private record Selector(String raw, String kind, String value) {
    }

    public void write(ReportLayout layout, Path baseline, Path suppressions,
                      List<Chain> chains, Map<String, String> calibrations) throws IOException {
        if (baseline == null && suppressions == null) {
            return;
        }
        Map<String, Chain> current = new TreeMap<>();
        for (Chain chain : chains == null ? List.<Chain>of() : chains) {
            if (chain != null) {
                current.putIfAbsent(identity(chain), chain);
            }
        }
        Set<String> old = baseline == null ? Set.of() : readBaseline(baseline);
        List<Selector> selectors = suppressions == null ? List.of() : readSelectors(suppressions);
        Set<String> usedSelectors = new LinkedHashSet<>();
        List<Row> rows = new ArrayList<>();
        for (Map.Entry<String, Chain> entry : current.entrySet()) {
            boolean baselineMatch = old.contains(entry.getKey());
            boolean suppressionMatch = matches(entry.getKey(), entry.getValue(), selectors, usedSelectors);
            String status = suppressionMatch
                    ? baselineMatch ? "SUPPRESSED_BASELINE" : "SUPPRESSED_NEW"
                    : baselineMatch ? "UNCHANGED" : "NEW";
            rows.add(new Row(entry.getKey(), entry.getValue(), status));
        }
        for (String removed : new TreeSet<>(old)) {
            if (!current.containsKey(removed)) {
                rows.add(new Row(removed, null, "REMOVED"));
            }
        }
        rows.sort(Comparator.comparing(Row::identity));
        writeCsv(layout.evidence().resolve("baseline.csv"), rows);
        AtomicFiles.writeUtf8(layout.meta().resolve("baseline.json"), json(rows, old,
                selectors, usedSelectors, baseline != null));
    }

    static String identity(Chain chain) {
        return String.join("|", safe(chain.ruleId()), safe(chain.entryClass()),
                safe(chain.entryMethod()), safe(entryDescriptor(chain)), safe(chain.entryKind()),
                safe(chain.sinkClass()), safe(chain.sinkMethod()), safe(sinkDescriptor(chain)));
    }

    private static Set<String> readBaseline(Path baseline) throws IOException {
        Path csv = baseline;
        if (Files.isDirectory(baseline)) {
            csv = baseline.resolve("findings").resolve("findings.csv");
            if (!Files.exists(csv)) {
                csv = baseline.resolve("findings.csv");
            }
        }
        if (!Files.isRegularFile(csv, LinkOption.NOFOLLOW_LINKS)
                || ArchiveLimits.isLinkOrReparsePoint(csv)
                || Files.size(csv) > MAX_BASELINE_BYTES) {
            throw new IOException("baseline findings.csv not found: " + baseline.toAbsolutePath());
        }
        List<String> lines = Files.readAllLines(csv, StandardCharsets.UTF_8);
        List<String> header = null;
        Map<String, Integer> indexes = new LinkedHashMap<>();
        Set<String> identities = new TreeSet<>();
        for (String line : lines) {
            List<String> fields = parseCsv(line);
            if (fields.isEmpty()) {
                continue;
            }
            if (header == null) {
                header = fields;
                for (String name : List.of("rule_id", "entry_class", "entry_method",
                        "entry_descriptor", "entry_kind", "sink_class", "sink_method",
                        "sink_descriptor")) {
                    int index = fields.indexOf(name);
                    if (index < 0) {
                        throw new IOException("baseline findings.csv missing column: " + name);
                    }
                    indexes.put(name, index);
                }
                continue;
            }
            if (indexes.values().stream().anyMatch(index -> index >= fields.size())) {
                throw new IOException("baseline findings.csv has a short row");
            }
            identities.add(String.join("|", fields.get(indexes.get("rule_id")),
                    fields.get(indexes.get("entry_class")), fields.get(indexes.get("entry_method")),
                    fields.get(indexes.get("entry_descriptor")), fields.get(indexes.get("entry_kind")),
                    fields.get(indexes.get("sink_class")), fields.get(indexes.get("sink_method")),
                    fields.get(indexes.get("sink_descriptor"))));
        }
        return Set.copyOf(identities);
    }

    private static List<Selector> readSelectors(Path file) throws IOException {
        if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)
                || ArchiveLimits.isLinkOrReparsePoint(file)
                || Files.size(file) > MAX_SUPPRESSION_BYTES) {
            throw new IOException("suppression file is not a safe regular file: "
                    + file.toAbsolutePath());
        }
        List<Selector> result = new ArrayList<>();
        for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
            String value = line.strip();
            if (value.isEmpty() || value.startsWith("#")) {
                continue;
            }
            if (value.startsWith("rule:") && value.length() > "rule:".length()) {
                result.add(new Selector(value, "rule", value.substring("rule:".length())));
            } else if (value.matches("sha256:[0-9a-fA-F]{64}")) {
                result.add(new Selector(value, "sha256", value.substring("sha256:".length()).toLowerCase()));
            } else if (value.contains("|") && !value.contains("\r") && !value.contains("\n")) {
                result.add(new Selector(value, "identity", value));
            } else {
                result.add(new Selector(value, "invalid", value));
            }
        }
        result.sort(Comparator.comparing(Selector::raw));
        return List.copyOf(result);
    }

    private static boolean matches(String identity, Chain chain, List<Selector> selectors,
                                   Set<String> used) {
        String digest = ChainIds.sha256(identity);
        for (Selector selector : selectors) {
            boolean match = switch (selector.kind()) {
                case "identity" -> selector.value().equals(identity);
                case "sha256" -> selector.value().equalsIgnoreCase(digest);
                case "rule" -> selector.value().equals(safe(chain.ruleId()));
                default -> false;
            };
            if (match) {
                used.add(selector.raw());
                return true;
            }
        }
        return false;
    }

    private static void writeCsv(Path path, List<Row> rows) throws IOException {
        StringBuilder csv = new StringBuilder(
                "identity_sha256,status,rule_id,entry_class,entry_method,entry_descriptor,entry_kind,"
                        + "sink_class,sink_method,sink_descriptor\n");
        for (Row row : rows) {
            Chain chain = row.chain();
            csv.append(csv(ChainIds.sha256(row.identity()))).append(',')
                    .append(csv(row.status())).append(',')
                    .append(csv(chain == null ? "" : chain.ruleId())).append(',')
                    .append(csv(chain == null ? "" : chain.entryClass())).append(',')
                    .append(csv(chain == null ? "" : chain.entryMethod())).append(',')
                    .append(csv(chain == null ? "" : entryDescriptor(chain))).append(',')
                    .append(csv(chain == null ? "" : chain.entryKind())).append(',')
                    .append(csv(chain == null ? "" : chain.sinkClass())).append(',')
                    .append(csv(chain == null ? "" : chain.sinkMethod())).append(',')
                    .append(csv(chain == null ? "" : sinkDescriptor(chain))).append('\n');
        }
        AtomicFiles.writeUtf8(path, csv.toString());
    }

    private static String json(List<Row> rows, Set<String> old, List<Selector> selectors,
                               Set<String> used, boolean hasBaseline) {
        long added = rows.stream().filter(row -> "NEW".equals(row.status())
                || "SUPPRESSED_NEW".equals(row.status())).count();
        long unchanged = rows.stream().filter(row -> "UNCHANGED".equals(row.status())
                || "SUPPRESSED_BASELINE".equals(row.status())).count();
        long removed = rows.stream().filter(row -> "REMOVED".equals(row.status())).count();
        StringBuilder json = new StringBuilder("{\n")
                .append("  \"schema_version\":1,\"baseline_supplied\":").append(hasBaseline)
                .append(",\"added\":").append(added)
                .append(",\"unchanged\":").append(unchanged)
                .append(",\"removed\":").append(removed)
                .append(",\"suppression_count\":").append(selectors.size())
                .append(",\"suppression_used\":").append(used.size())
                .append(",\"suppression_unused\":[");
        boolean first = true;
        for (Selector selector : selectors) {
            if (used.contains(selector.raw())) {
                continue;
            }
            if (!first) {
                json.append(',');
            }
            first = false;
            json.append('"').append(json(selector.raw())).append('"');
        }
        return json.append("]\n}\n").toString();
    }

    private static String entryDescriptor(Chain chain) {
        for (var hop : chain.hops()) {
            if (hop.kind() == io.just.sast.blackboard.HopKind.ENTRY && hop.desc() != null) {
                return hop.desc();
            }
        }
        return "";
    }

    private static String sinkDescriptor(Chain chain) {
        if (chain.sinkDescriptor() != null && !chain.sinkDescriptor().isBlank()) {
            return chain.sinkDescriptor();
        }
        for (var hop : chain.hops()) {
            if (safe(chain.sinkClass()).equals(safe(hop.toOwner()))
                    && safe(chain.sinkMethod()).equals(safe(hop.toName()))
                    && hop.desc() != null && !hop.desc().isBlank()) {
                return hop.desc();
            }
        }
        return "";
    }

    private static String safe(String value) {
        return value == null ? "" : value;
    }

    private static String csv(String value) {
        return "\"" + safe(value).replace("\"", "\"\"")
                .replace("\r", " ").replace("\n", " ") + "\"";
    }

    private static String json(String value) {
        return safe(value).replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\r", "\\r").replace("\n", "\\n");
    }

    private static List<String> parseCsv(String line) throws IOException {
        List<String> fields = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        boolean quoted = false;
        boolean started = false;
        for (int i = 0; i < line.length(); i++) {
            char value = line.charAt(i);
            if (quoted) {
                if (value == '"') {
                    if (i + 1 < line.length() && line.charAt(i + 1) == '"') {
                        current.append('"');
                        i++;
                    } else {
                        quoted = false;
                    }
                } else {
                    current.append(value);
                }
            } else if (value == '"') {
                quoted = true;
                started = true;
            } else if (value == ',') {
                fields.add(current.toString());
                current.setLength(0);
                started = false;
            } else {
                if (value == '\uFEFF' && fields.isEmpty() && current.length() == 0) {
                    continue;
                }
                current.append(value);
                started = true;
            }
        }
        if (quoted) {
            throw new IOException("baseline CSV has an unterminated quote");
        }
        if (started || !fields.isEmpty()) {
            fields.add(current.toString());
        }
        return fields;
    }
}
