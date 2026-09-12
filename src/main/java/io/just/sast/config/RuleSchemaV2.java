package io.just.sast.config;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Typed, deterministic projection of the legacy rule catalog.
 *
 * <p>Rule matching remains owned by {@link RuleEngine}; this class only describes rule data and
 * its semantic axes.  The projection is deliberately lossless with respect to rule identity and
 * category while leaving unknown semantic classifications explicit instead of guessing a chain
 * edge.  It is therefore safe to use as a schema/digest boundary during the v1 to v2 migration.
 */
public final class RuleSchemaV2 {

    public static final String SCHEMA_VERSION = "JUST-RULES-D002-V2";
    /** Bump when the v1 compatibility classification changes without a rule-file edit. */
    public static final String SEMANTICS_VERSION = "1";
    private static final Pattern ID = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._-]{0,127}");

    public enum RuleKind { SINK, MAGIC_ENTRY, SOURCE, MODEL, CHAIN_FRAGMENT }

    public enum Capability {
        REFLECTION, CLASS_LOADING, PROCESS, NETWORK, JDBC, JNDI, DESERIALIZATION,
        EXPRESSION, NATIVE, FILE, UNKNOWN
    }

    public enum Bridge {
        DESERIALIZE, SERIALIZE, JNDI_RMI, JDBC_DRIVER, REFLECTION, CONFIGURATION,
        SECOND_DESERIALIZATION, UNKNOWN
    }

    public enum Boundary {
        APPLICATION_ENTRY, DESERIALIZATION, BINDING, LOOKUP, CONFIGURATION,
        CAPABILITY, TERMINAL, UNKNOWN
    }

    public enum Terminal {
        COMMAND_EXEC, CLASS_DEFINITION, FILE_WRITE, FILE_READ, NETWORK_SEND, CODE_EXEC,
        SQL_EXEC, NATIVE_LOAD, DESERIALIZATION, UNKNOWN
    }

    public enum Source {
        EXTERNAL_INPUT, DESERIALIZATION, SERIALIZATION, APPLICATION, ENVIRONMENT, UNKNOWN
    }

    public enum Filter {
        SAFE_CONFIG, OBJECT_INPUT_FILTER, TYPE_ALLOWLIST, NONE, UNKNOWN
    }

    public enum Callback {
        READ_OBJECT, READ_RESOLVE, READ_EXTERNAL, VALIDATE_OBJECT, WRITE_OBJECT,
        WRITE_REPLACE, FINALIZE, PROXY_INVOKE, HASH_CODE, EQUALS, COMPARE, TO_STRING,
        REFLECTIVE, BEAN_PROPERTY, METHOD_SUMMARY, UNKNOWN
    }

    /** The seven semantic axes are data; solver and report code must not infer them from text. */
    public record Semantics(Set<Capability> capability, Set<Bridge> bridge,
                            Set<Boundary> boundary, Set<Terminal> terminal,
                            Set<Source> source, Set<Filter> filter,
                            Set<Callback> callback) {
        public Semantics {
            capability = immutableEnumSet(capability, Capability.class);
            bridge = immutableEnumSet(bridge, Bridge.class);
            boundary = immutableEnumSet(boundary, Boundary.class);
            terminal = immutableEnumSet(terminal, Terminal.class);
            source = immutableEnumSet(source, Source.class);
            filter = immutableEnumSet(filter, Filter.class);
            callback = immutableEnumSet(callback, Callback.class);
        }

        public boolean hasAnyAxis() {
            return !(capability.isEmpty() && bridge.isEmpty() && boundary.isEmpty()
                    && terminal.isEmpty() && source.isEmpty() && filter.isEmpty()
                    && callback.isEmpty());
        }
    }

    /** One schema-v2 rule definition; matching payload remains in the legacy Rule object. */
    public record Definition(String id, RuleKind kind, String category, String severity,
                             Semantics semantics) {
        public Definition {
            if (id == null || !ID.matcher(id).matches()) {
                throw new IllegalArgumentException("rule id is invalid: " + id);
            }
            kind = kind == null ? RuleKind.MODEL : kind;
            category = category == null ? "" : category;
            severity = severity == null ? "" : severity.toUpperCase(Locale.ROOT);
            semantics = semantics == null
                    ? new Semantics(Set.of(), Set.of(), Set.of(), Set.of(), Set.of(), Set.of(), Set.of())
                    : semantics;
            if (!semantics.hasAnyAxis()) {
                throw new IllegalArgumentException("rule semantics must identify at least one axis: " + id);
            }
        }

        public String toCanonicalJson() {
            return definitionJson(this);
        }
    }

    /** A sorted, immutable catalog with a stable schema digest for cache/report provenance. */
    public record Catalog(String schemaVersion, List<Definition> rules) {
        public Catalog {
            if (!SCHEMA_VERSION.equals(schemaVersion)) {
                throw new IllegalArgumentException("unsupported rules schema: " + schemaVersion);
            }
            List<Definition> sorted = new ArrayList<>(rules == null ? List.of() : rules);
            sorted.sort(java.util.Comparator.comparing(Definition::id));
            Set<String> ids = new HashSet<>();
            for (Definition definition : sorted) {
                if (!ids.add(definition.id())) {
                    throw new IllegalArgumentException("duplicate schema-v2 rule id: " + definition.id());
                }
            }
            rules = List.copyOf(sorted);
        }

        public String toCanonicalJson() {
            StringBuilder json = new StringBuilder("{\"schema_version\":\"")
                    .append(escape(schemaVersion)).append("\",\"rules\":[");
            for (int i = 0; i < rules.size(); i++) {
                if (i > 0) {
                    json.append(',');
                }
                json.append(rules.get(i).toCanonicalJson());
            }
            return json.append("]}").toString();
        }

        public String digest() {
            return sha256(toCanonicalJson());
        }
    }

    /**
     * A deterministic migration record used during the shadow period.  It deliberately keeps
     * the legacy kind/role and the typed definition side by side, so a reader cannot silently
     * reinterpret a v1 terminal as a v2 capability (or vice versa).
     */
    public record ShadowRecord(String id, String legacyKind, String legacyRole,
                               boolean legacyTerminal, int legacyCount, Definition typed,
                               List<String> differences) {
        public ShadowRecord {
            if (id == null || id.isBlank() || typed == null || !id.equals(typed.id())
                    || legacyCount < 1) {
                throw new IllegalArgumentException("shadow record identity mismatch: " + id);
            }
            legacyKind = legacyKind == null ? "unknown" : legacyKind;
            legacyRole = legacyRole == null ? "NONE" : legacyRole;
            List<String> sorted = new ArrayList<>(differences == null ? List.of() : differences);
            sorted.removeIf(value -> value == null || value.isBlank());
            sorted.sort(String::compareTo);
            differences = List.copyOf(sorted.isEmpty() ? List.of("NO_DIFFERENCE") : sorted);
        }

        public String toCanonicalJson() {
            StringBuilder json = new StringBuilder("{\"id\":\"")
                    .append(escape(id)).append("\",\"legacy_kind\":\"")
                    .append(escape(legacyKind)).append("\",\"legacy_role\":\"")
                    .append(escape(legacyRole)).append("\",\"legacy_terminal\":")
                    .append(legacyTerminal).append(",\"legacy_count\":")
                    .append(legacyCount).append(",\"typed\":")
                    .append(typed.toCanonicalJson()).append(",\"differences\":[");
            for (int i = 0; i < differences.size(); i++) {
                if (i > 0) {
                    json.append(',');
                }
                json.append('"').append(escape(differences.get(i))).append('"');
            }
            return json.append("]}").toString();
        }
    }

    /** Stable report-side shadow document; it is additive and never changes findings wire data. */
    public record Shadow(String schemaVersion, List<ShadowRecord> records) {
        public static final String SCHEMA_VERSION = "JUST-RULES-D002-V2-SHADOW-1";

        public Shadow {
            if (!SCHEMA_VERSION.equals(schemaVersion)) {
                throw new IllegalArgumentException("unsupported shadow schema: " + schemaVersion);
            }
            List<ShadowRecord> sorted = new ArrayList<>(records == null ? List.of() : records);
            sorted.sort(java.util.Comparator.comparing(ShadowRecord::id));
            Set<String> ids = new HashSet<>();
            for (ShadowRecord record : sorted) {
                if (!ids.add(record.id())) {
                    throw new IllegalArgumentException("duplicate shadow rule id: " + record.id());
                }
            }
            records = List.copyOf(sorted);
        }

        public Map<String, Integer> differenceCounts() {
            Map<String, Integer> counts = new java.util.TreeMap<>();
            for (ShadowRecord record : records) {
                for (String difference : record.differences()) {
                    counts.merge(difference, 1, Integer::sum);
                }
            }
            return Collections.unmodifiableMap(counts);
        }

        public String toCanonicalJson() {
            StringBuilder json = new StringBuilder("{\"schema_version\":\"")
                    .append(escape(schemaVersion)).append("\",\"rules_schema_version\":\"")
                    .append(escape(RuleSchemaV2.SCHEMA_VERSION)).append("\",\"rules\":[");
            for (int i = 0; i < records.size(); i++) {
                if (i > 0) {
                    json.append(',');
                }
                json.append(records.get(i).toCanonicalJson());
            }
            json.append("],\"difference_counts\":{");
            List<Map.Entry<String, Integer>> counts = new ArrayList<>(differenceCounts().entrySet());
            for (int i = 0; i < counts.size(); i++) {
                if (i > 0) {
                    json.append(',');
                }
                Map.Entry<String, Integer> entry = counts.get(i);
                json.append('"').append(escape(entry.getKey())).append("\":")
                        .append(entry.getValue());
            }
            return json.append("}}").toString();
        }

        public String digest() {
            return sha256(toCanonicalJson());
        }
    }

    private RuleSchemaV2() {
    }

    /** Adapt every legacy rule in a RuleSet; no rule is silently dropped. */
    public static Catalog adapt(RuleSet rules) {
        if (rules == null) {
            return new Catalog(SCHEMA_VERSION, List.of());
        }
        List<Definition> definitions = new ArrayList<>();
        rules.sinks().forEach(rule -> definitions.add(adapt(rule)));
        rules.magicEntries().forEach(rule -> definitions.add(adapt(rule)));
        rules.sources().forEach(rule -> definitions.add(adapt(rule)));
        rules.models().forEach(rule -> definitions.add(adapt(rule)));
        rules.fragments().forEach(rule -> definitions.add(adapt(rule)));
        return new Catalog(SCHEMA_VERSION, definitions);
    }

    /** Build the old/new shadow without changing the legacy RuleSet or report format. */
    public static Shadow shadow(RuleSet rules) {
        if (rules == null) {
            return new Shadow(Shadow.SCHEMA_VERSION, List.of());
        }
        Map<String, List<ShadowRecord>> grouped = new java.util.TreeMap<>();
        rules.sinks().forEach(rule -> addShadow(grouped, rule, "sink",
                rule.role().name(), rule.terminal()));
        rules.magicEntries().forEach(rule -> addShadow(grouped, rule, "magic-entry",
                "NONE", false));
        rules.sources().forEach(rule -> addShadow(grouped, rule, "source",
                "NONE", false));
        rules.models().forEach(rule -> addShadow(grouped, rule, "model",
                "NONE", false));
        rules.fragments().forEach(rule -> addShadow(grouped, rule, "chain-fragment",
                "NONE", false));
        List<ShadowRecord> records = new ArrayList<>(grouped.size());
        for (List<ShadowRecord> candidates : grouped.values()) {
            candidates.sort(java.util.Comparator.comparing(ShadowRecord::toCanonicalJson));
            ShadowRecord selected = candidates.get(0);
            if (candidates.size() > 1) {
                List<String> differences = new ArrayList<>(selected.differences());
                differences.add("V1_DUPLICATE_ID");
                selected = new ShadowRecord(selected.id(), selected.legacyKind(),
                        selected.legacyRole(), selected.legacyTerminal(), candidates.size(),
                        selected.typed(), differences);
            }
            records.add(selected);
        }
        return new Shadow(Shadow.SCHEMA_VERSION, records);
    }

    private static void addShadow(Map<String, List<ShadowRecord>> grouped, Rule rule,
                                  String kind, String role, boolean terminal) {
        ShadowRecord candidate = shadow(rule, adapt(rule), kind, role, terminal, 1);
        grouped.computeIfAbsent(candidate.id(), ignored -> new ArrayList<>()).add(candidate);
    }

    private static ShadowRecord shadow(Rule rule, Definition definition, String kind,
                                       String role, boolean terminal, int legacyCount) {
        List<String> differences = new ArrayList<>();
        Semantics semantics = definition.semantics();
        if (!semantics.capability().isEmpty()) differences.add("V2_CAPABILITY_CLASSIFIED");
        if (!semantics.bridge().isEmpty()) differences.add("V2_BRIDGE_CLASSIFIED");
        if (!semantics.boundary().isEmpty()) differences.add("V2_BOUNDARY_CLASSIFIED");
        if (!semantics.terminal().isEmpty()) differences.add("V2_TERMINAL_CLASSIFIED");
        if (!semantics.source().isEmpty()) differences.add("V2_SOURCE_CLASSIFIED");
        if (!semantics.filter().isEmpty() && !semantics.filter().equals(Set.of(Filter.NONE))) {
            differences.add("V2_FILTER_CLASSIFIED");
        }
        if (!semantics.callback().isEmpty()) differences.add("V2_CALLBACK_CLASSIFIED");
        boolean typedTerminal = !semantics.terminal().isEmpty();
        if (rule instanceof Rule.SinkRule) {
            if (terminal && !typedTerminal) {
                differences.add("SINK_TERMINAL_RECLASSIFIED_TO_CAPABILITY");
            } else if (!terminal && typedTerminal) {
                differences.add("SINK_CAPABILITY_RECLASSIFIED_TO_TERMINAL");
            } else if (terminal == typedTerminal) {
                differences.add("SINK_TERMINAL_ROLE_PRESERVED");
            }
        }
        return new ShadowRecord(definition.id(), kind, role, terminal, legacyCount,
                definition, differences);
    }

    public static Definition adapt(Rule rule) {
        if (rule == null) {
            throw new IllegalArgumentException("rule must not be null");
        }
        if (rule instanceof Rule.SinkRule sink) {
            Capability capability = capabilityFor(sink.category(), sink.call().ownerType(),
                    sink.call().name().pattern());
            boolean intermediate = isIntermediateBoundary(sink.category(), sink.call().ownerType(),
                    sink.call().name().pattern());
            Set<Terminal> terminal = sink.terminal() && !intermediate
                    ? Set.of(terminalFor(sink.category(), sink.call().ownerType(),
                    sink.call().name().pattern())) : Set.of();
            Set<Boundary> boundary = Set.of(intermediate
                    ? intermediateBoundary(sink.category(), sink.call().ownerType(),
                    sink.call().name().pattern())
                    : sink.terminal()
                    ? Boundary.TERMINAL : Boundary.CAPABILITY);
            Set<Bridge> bridge = bridgeFor(sink.category(), sink.call().ownerType(),
                    sink.call().name().pattern());
            return new Definition(sink.id(), RuleKind.SINK, sink.category(), sink.severity(),
                    new Semantics(Set.of(capability), bridge, boundary, terminal, Set.of(),
                            Set.of(Filter.NONE), Set.of(callbackFor(sink.call().name().pattern()))));
        }
        if (rule instanceof Rule.MagicEntryRule entry) {
            Callback callback = callbackFor(entry.entryKind());
            Boundary boundary = "deserialize".equals(entry.direction())
                    ? Boundary.DESERIALIZATION : Boundary.UNKNOWN;
            return new Definition(entry.id(), RuleKind.MAGIC_ENTRY, "", "",
                    new Semantics(Set.of(), Set.of(), Set.of(boundary), Set.of(), Set.of(),
                            Set.of(Filter.NONE), Set.of(callback)));
        }
        if (rule instanceof Rule.SourceRule source) {
            boolean deserialize = "deserialize".equalsIgnoreCase(source.bridge());
            Set<Bridge> bridge = Set.of(deserialize ? Bridge.DESERIALIZE : Bridge.SERIALIZE);
            Set<Boundary> boundary = Set.of(deserialize
                    ? Boundary.DESERIALIZATION : Boundary.BINDING);
            Set<Source> sourceAxis = Set.of(deserialize
                    ? Source.DESERIALIZATION : Source.SERIALIZATION);
            Set<Filter> filters = source.safeConfig() == null
                    ? Set.of(Filter.NONE) : Set.of(Filter.SAFE_CONFIG);
            return new Definition(source.id(), RuleKind.SOURCE, "", "",
                    new Semantics(Set.of(Capability.DESERIALIZATION), bridge, boundary, Set.of(),
                            sourceAxis, filters, Set.of(Callback.BEAN_PROPERTY)));
        }
        if (rule instanceof Rule.ModelRule model) {
            return new Definition(model.id(), RuleKind.MODEL, "", "",
                    new Semantics(Set.of(), Set.of(), Set.of(), Set.of(), Set.of(),
                            Set.of(Filter.NONE), Set.of(Callback.METHOD_SUMMARY)));
        }
        Rule.FragmentRule fragment = (Rule.FragmentRule) rule;
        Capability capability = capabilityFor("", fragment.sinkOwner(), fragment.sinkName());
        return new Definition(fragment.id(), RuleKind.CHAIN_FRAGMENT, "", "",
                new Semantics(Set.of(capability), Set.of(), Set.of(Boundary.CAPABILITY),
                        Set.of(terminalFor("", fragment.sinkOwner(), fragment.sinkName())), Set.of(),
                        Set.of(Filter.NONE), Set.of(callbackFor(fragment.entryKind()))));
    }

    /** Typed sink role used by application-chain admission; legacy v1 roles remain unchanged. */
    public static boolean isIntermediateSink(Rule.SinkRule sink) {
        return sink != null && isIntermediateBoundary(sink.category(), sink.call().ownerType(),
                sink.call().name().pattern());
    }

    /** A sink is terminal only when its v1 terminal bit is not a known bridge/capability edge. */
    public static boolean isTerminalSink(Rule.SinkRule sink) {
        return sink != null && sink.terminal() && !isIntermediateSink(sink);
    }

    /** Stable typed bridge classification for protocol-aware composition. */
    public static Set<Bridge> bridgesFor(Rule.SinkRule sink) {
        if (sink == null) {
            return Set.of();
        }
        return bridgeFor(sink.category(), sink.call().ownerType(), sink.call().name().pattern());
    }

    private static Capability capabilityFor(String category, String owner, String method) {
        String value = lower(category) + " " + lower(owner) + " " + lower(method);
        if (value.contains("reflect") || value.contains("methodhandle")
                || value.contains("introspector")) {
            return Capability.REFLECTION;
        }
        if (value.contains("classload") || value.contains("defineclass")
                || value.contains("forname") || value.contains("templatesimpl")) {
            return Capability.CLASS_LOADING;
        }
        if (isCommandLike(category, owner, method)) {
            return Capability.PROCESS;
        }
        if (isJdbcLike(category, owner, method)) {
            return Capability.JDBC;
        }
        if (value.contains("jndi") || value.contains("naming") || value.contains("rmi")) {
            return Capability.JNDI;
        }
        if (value.contains("ssrf") || value.contains("socket") || value.contains("http")
                || value.contains("url")) {
            return Capability.NETWORK;
        }
        if (value.contains("deserialize") || value.contains("serialization")) {
            return Capability.DESERIALIZATION;
        }
        if (value.contains("native") || value.contains("loadlibrary")) {
            return Capability.NATIVE;
        }
        if (value.contains("file") || value.contains("path")) {
            return Capability.FILE;
        }
        if (value.contains("spel") || value.contains("ognl") || value.contains("groovy")
                || value.contains("mvel") || value.contains("expression")
                || value.contains("script")) {
            return Capability.EXPRESSION;
        }
        return Capability.UNKNOWN;
    }

    private static Terminal terminalFor(String category, String owner, String method) {
        String value = lower(category) + " " + lower(owner) + " " + lower(method);
        if (isCommandLike(category, owner, method)) {
            return Terminal.COMMAND_EXEC;
        }
        if (value.contains("defineclass") || value.contains("templatesimpl")) {
            return Terminal.CLASS_DEFINITION;
        }
        if (value.contains("file_write") || value.contains("fileoutput")
                || value.contains("newoutput") || value.contains("delete")) {
            return Terminal.FILE_WRITE;
        }
        if (value.contains("file_read") || value.contains("fileinput")
                || value.contains("readallbytes") || value.contains("readstring")
                || value.contains("readalllines")) {
            return Terminal.FILE_READ;
        }
        if (value.contains("ssrf") || value.contains("socket") || value.contains("http")
                || value.contains("url") || value.contains("jndi") || value.contains("naming")) {
            return Terminal.NETWORK_SEND;
        }
        if (value.contains("sqli") || value.contains("statement") || value.contains("jdbc")) {
            return Terminal.SQL_EXEC;
        }
        if (value.contains("native") || value.contains("loadlibrary")) {
            return Terminal.NATIVE_LOAD;
        }
        if (value.contains("deserial")) {
            return Terminal.DESERIALIZATION;
        }
        if (value.contains("code_exec") || value.contains("spel") || value.contains("ognl")
                || value.contains("groovy") || value.contains("mvel") || value.contains("script")) {
            return Terminal.CODE_EXEC;
        }
        return Terminal.UNKNOWN;
    }

    private static boolean isCommandLike(String category, String owner, String method) {
        String c = lower(category);
        String o = lower(owner);
        String m = lower(method);
        return c.contains("command") || c.contains("process")
                || o.contains("processbuilder") || o.contains("processimpl")
                || o.contains("unixprocess")
                || (o.contains("runtime") && (m.equals("exec") || m.equals("load")))
                || (m.equals("exec") && !c.contains("code_exec"));
    }

    private static Set<Bridge> bridgeFor(String category, String owner, String method) {
        String c = lower(category);
        String o = lower(owner);
        String m = lower(method);
        String value = c + " " + o + " " + m;
        if (isJdbcLike(category, owner, method)) {
            return Set.of(Bridge.JDBC_DRIVER);
        }
        if (value.contains("jndi") || value.contains("naming") || value.contains("rmi")
                || value.contains("lookup") || value.contains("directorymanager")) {
            return Set.of(Bridge.JNDI_RMI);
        }
        if (value.contains("deserialize") || value.contains("serialization")
                || value.contains("readobject") || value.contains("readvalue")
                || value.contains("fromxml") || value.contains("unmarshal")) {
            return Set.of(Bridge.DESERIALIZE);
        }
        if (value.contains("reflect") || value.contains("methodhandle")
                || value.contains("proxy") || value.contains("invoke")) {
            return Set.of(Bridge.REFLECTION);
        }
        return Set.of();
    }

    private static boolean isJdbcLike(String category, String owner, String method) {
        String c = lower(category);
        String o = lower(owner);
        String m = lower(method);
        return c.contains("jdbc") || c.contains("sqli") || o.startsWith("java/sql/")
                || o.contains("/jdbc/")
                || (o.contains("driver") && (m.contains("connect") || m.contains("getconnection")))
                || m.contains("getconnection");
    }

    private static Callback callbackFor(String value) {
        String kind = lower(value);
        if (kind.contains("readobjectno")) return Callback.READ_OBJECT;
        if (kind.contains("readobject")) return Callback.READ_OBJECT;
        if (kind.contains("readresolve")) return Callback.READ_RESOLVE;
        if (kind.contains("readexternal")) return Callback.READ_EXTERNAL;
        if (kind.contains("validateobject")) return Callback.VALIDATE_OBJECT;
        if (kind.contains("writeobject")) return Callback.WRITE_OBJECT;
        if (kind.contains("writereplace")) return Callback.WRITE_REPLACE;
        if (kind.contains("finalize")) return Callback.FINALIZE;
        if (kind.contains("proxyinvoke")) return Callback.PROXY_INVOKE;
        if (kind.contains("hashcode")) return Callback.HASH_CODE;
        if (kind.contains("equals")) return Callback.EQUALS;
        if (kind.contains("compare")) return Callback.COMPARE;
        if (kind.contains("tostring")) return Callback.TO_STRING;
        if (kind.contains("invoke") || kind.contains("reflect")) return Callback.REFLECTIVE;
        return Callback.UNKNOWN;
    }

    /**
     * Legacy v1 rules default every sink to TERMINAL.  This compatibility projection must not
     * turn a lookup, deserializer, reflective dispatcher or builder configuration call into a
     * false terminal.  The classification is intentionally API/category based (not benchmark,
     * project or class-list based) and remains visible as an inferred v2 semantic axis until
     * those rules carry explicit metadata.
     */
    private static boolean isIntermediateBoundary(String category, String owner, String method) {
        String value = lower(category) + " " + lower(owner) + " " + lower(method);
        if (isJdbcLike(category, owner, method)) {
            return true;
        }
        if (value.contains("jndi") || value.contains("naming") || value.contains("lookup")
                || value.contains("rmi") || value.contains("ldap")
                || value.contains("directorymanager")) {
            return true;
        }
        if (value.contains("deserialize") || value.contains("serialization")
                || value.contains("readobject") || value.contains("readvalue")
                || value.contains("fromxml") || value.contains("unmarshal")) {
            return true;
        }
        if (value.contains("reflect") || value.contains("methodhandle")
                || value.contains("proxy") || value.contains("introspector")
                || value.contains("getenginebyname") || value.contains("class.forname")
                || value.contains("forname") || value.contains("newinstance")
                || (value.contains("classloader") && !value.contains("defineclass"))
                || (value.contains("processbuilder") && !value.contains("start"))) {
            return true;
        }
        return value.contains("parseexpression") || value.contains("spel-parse")
                || value.contains("el-factory") || value.contains("setcommand")
                || (value.contains("commandline") && (value.contains("parse")
                || value.contains("addarguments")));
    }

    private static Boundary intermediateBoundary(String category, String owner, String method) {
        String value = lower(category) + " " + lower(owner) + " " + lower(method);
        if (isJdbcLike(category, owner, method)) {
            return Boundary.LOOKUP;
        }
        if (value.contains("jndi") || value.contains("naming") || value.contains("lookup")
                || value.contains("rmi") || value.contains("ldap")
                || value.contains("directorymanager")) {
            return Boundary.LOOKUP;
        }
        if (value.contains("deserialize") || value.contains("serialization")
                || value.contains("readobject") || value.contains("readvalue")
                || value.contains("fromxml") || value.contains("unmarshal")) {
            return Boundary.DESERIALIZATION;
        }
        return Boundary.CAPABILITY;
    }

    private static String definitionJson(Definition definition) {
        StringBuilder json = new StringBuilder("{\"id\":\"")
                .append(escape(definition.id())).append("\",\"kind\":\"")
                .append(definition.kind()).append("\",\"category\":\"")
                .append(escape(definition.category())).append("\",\"severity\":\"")
                .append(escape(definition.severity())).append("\",\"semantics\":{");
        Semantics s = definition.semantics();
        appendAxis(json, "capability", s.capability());
        appendAxis(json, "bridge", s.bridge());
        appendAxis(json, "boundary", s.boundary());
        appendAxis(json, "terminal", s.terminal());
        appendAxis(json, "source", s.source());
        appendAxis(json, "filter", s.filter());
        appendAxis(json, "callback", s.callback());
        return json.append("}}").toString();
    }

    private static void appendAxis(StringBuilder json, String name, Collection<? extends Enum<?>> values) {
        if (json.charAt(json.length() - 1) != '{') {
            json.append(',');
        }
        json.append('"').append(name).append("\":[");
        List<String> names = values.stream().map(Enum::name).sorted().toList();
        for (int i = 0; i < names.size(); i++) {
            if (i > 0) json.append(',');
            json.append('"').append(names.get(i)).append('"');
        }
        json.append(']');
    }

    private static <E extends Enum<E>> Set<E> immutableEnumSet(Set<E> values, Class<E> type) {
        if (values == null || values.isEmpty()) {
            return Set.of();
        }
        EnumSet<E> copy = EnumSet.noneOf(type);
        copy.addAll(values);
        return Collections.unmodifiableSet(copy);
    }

    private static String lower(String value) {
        return value == null ? "" : value.toLowerCase(Locale.ROOT);
    }

    private static String escape(String value) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '\\' -> out.append("\\\\");
                case '"' -> out.append("\\\"");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20) out.append(String.format("\\u%04x", (int) c));
                    else out.append(c);
                }
            }
        }
        return out.toString();
    }

    private static String sha256(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                hex.append(String.format("%02x", b));
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 unavailable", impossible);
        }
    }
}
