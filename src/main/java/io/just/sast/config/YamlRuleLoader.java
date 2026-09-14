package io.just.sast.config;

import io.just.sast.blackboard.ObjectGraphPlan;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;
import org.yaml.snakeyaml.inspector.UnTrustedTagInspector;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.IdentityHashMap;
import io.just.sast.blackboard.SinkRisk;
import io.just.sast.run.InputBudget;
import io.just.sast.util.IoUtil;

/** YAML 规则 → RuleSet。 */
public final class YamlRuleLoader {

    /** Rule files are configuration, not an unbounded data interchange format. */
    /** Compatibility aliases; all limits are supplied by the versioned InputBudget. */
    static final int MAX_CODE_POINTS = InputBudget.defaults().maxRuleCodePoints();
    static final int MAX_ALIASES = InputBudget.defaults().maxRuleAliases();
    static final int MAX_NESTING_DEPTH = InputBudget.defaults().maxRuleNestingDepth();
    static final int MAX_DOCUMENTS = InputBudget.defaults().maxRuleDocuments();
    static final int MAX_RULES = InputBudget.defaults().maxRuleCount();
    static final int MAX_COLLECTION_ITEMS = InputBudget.defaults().maxRuleCollectionItems();
    static final int MAX_NODES = InputBudget.defaults().maxRuleNodes();
    static final int MAX_SCALAR_CHARS = InputBudget.defaults().maxRuleScalarChars();
    static final long MAX_INPUT_BYTES = InputBudget.defaults().maxRuleInputBytes();

    private static final Set<String> ROOT_KEYS = Set.of("rules", "schema_version");
    private static final Set<String> COMMON_RULE_KEYS = Set.of("id", "kind");
    private static final Set<String> SINK_KEYS = Set.of("id", "kind", "category", "severity",
            "match", "tainted", "role", "sinkRole", "sink_risk", "sinkRisk");
    private static final Set<String> ENTRY_KEYS = Set.of("id", "kind", "entryKind", "direction", "match");
    private static final Set<String> SOURCE_KEYS = Set.of("id", "kind", "bridge", "match", "safe-config", "tainted");
    private static final Set<String> MODEL_KEYS = Set.of("id", "kind", "match", "actions");
    private static final Set<String> FRAGMENT_KEYS = Set.of("id", "kind", "entryClass", "entryKind",
            "entryMethod", "entryDescriptor", "activation", "sinkOwner", "sinkName",
            "sinkDescriptor", "hops", "construction", "direct");
    private static final Set<String> CONDITION_KEYS = Set.of("id", "kind", "match", "condition");
    private static final Set<String> CALL_KEYS = Set.of("owner", "name", "descriptor");
    private static final Set<String> METHOD_KEYS = Set.of("name", "descriptor", "access");
    private static final Set<String> CLASS_KEYS = Set.of("implements");
    private static final Set<String> SAFE_CONFIG_KEYS = Set.of("owner", "methods", "safe-value");
    private static final Set<String> HOP_KEYS = Set.of("class", "method", "field");
    private static final Set<String> CONSTRUCTION_KEYS = Set.of("nodes", "fields");
    private static final Set<String> NODE_KEYS = Set.of("id", "type", "kind", "args");
    private static final Set<String> FIELD_KEYS = Set.of("owner", "field", "values", "value");
    private static final Set<String> VALUE_KEYS = Set.of("ref", "class", "string", "int", "long", "boolean", "null");

    @SuppressWarnings("unchecked")
    public RuleSet load(InputStream in) throws IOException {
        return load(in, InputBudget.defaults());
    }

    /** Load rules with one explicit, versioned input policy. */
    @SuppressWarnings("unchecked")
    public RuleSet load(InputStream in, InputBudget budget) throws IOException {
        return load(in, budget, null);
    }

    /**
     * Load rules while charging a caller-owned tracker.  A scan parses the target, dependencies,
     * JDK classes and rules as one untrusted input set; creating a fresh tracker here would let a
     * large rule file reset the aggregate byte/time allowance after archive parsing.  The
     * source-compatible overload above deliberately retains its bounded local tracker for
     * library callers that do not have a scan capability context.
     */
    @SuppressWarnings("unchecked")
    public RuleSet load(InputStream in, InputBudget budget, InputBudget.Tracker tracker)
            throws IOException {
        if (in == null) {
            throw new IOException("规则流为空");
        }
        InputBudget requested = budget == null ? InputBudget.defaults() : budget;
        InputBudget policy = tracker == null ? requested : tracker.budget();
        InputBudget.Tracker parseBudget = tracker == null ? policy.tracker() : tracker;
        LoaderOptions options = new LoaderOptions();
        options.setCodePointLimit(policy.maxRuleCodePoints());
        options.setMaxAliasesForCollections(policy.maxRuleAliases());
        options.setNestingDepthLimit(policy.maxRuleNestingDepth());
        options.setAllowDuplicateKeys(false);
        options.setWarnOnDuplicateKeys(false);
        options.setAllowRecursiveKeys(false);
        options.setTagInspector(new UnTrustedTagInspector());
        Object root;
        try {
            byte[] source;
            try {
                source = IoUtil.readAll(in, policy.maxRuleInputBytes(), parseBudget);
            } catch (IOException oversized) {
                throw new IOException("RULE_INPUT_BYTES_LIMIT:" + policy.maxRuleInputBytes(),
                        oversized);
            }
            parseBudget.checkTime();
            Iterable<Object> documents = new Yaml(new SafeConstructor(options)).loadAll(
                    new java.io.ByteArrayInputStream(source));
            java.util.Iterator<Object> iterator = documents.iterator();
            if (!iterator.hasNext()) {
                throw new IOException("RULE_YAML_EMPTY");
            }
            root = iterator.next();
            parseBudget.checkTime();
            if (iterator.hasNext()) {
                throw new IOException("RULE_DOCUMENT_LIMIT:" + policy.maxRuleDocuments());
            }
        } catch (IOException failure) {
            throw failure;
        } catch (RuntimeException failure) {
            // Do not expose SnakeYAML/provider messages as a report-facing contract.  The
            // concrete exception remains available as a cause for --debug diagnostics.
            throw new IOException("RULE_YAML_REJECTED:" + failure.getClass().getSimpleName(), failure);
        }
        if (!(root instanceof Map<?, ?> map)) {
            throw new IOException("规则格式错误：顶层必须是 map");
        }
        validateTree(map, "root", policy, parseBudget);
        rejectUnknownKeys(map, ROOT_KEYS, "root");
        Object schemaValue = map.get("schema_version");
        if (schemaValue != null && !(schemaValue instanceof String)) {
            throw new IOException("RULE_SCHEMA_VERSION_TYPE");
        }
        String schemaVersion = schemaValue == null ? RuleSet.YAML_SCHEMA_VERSION
                : ((String) schemaValue).trim();
        if (!RuleSet.YAML_SCHEMA_VERSION.equals(schemaVersion)) {
            throw new IOException("RULE_SCHEMA_VERSION_UNSUPPORTED:" + schemaVersion);
        }
        Object rulesObj = map.get("rules");
        if (!(rulesObj instanceof List<?> list)) {
            throw new IOException("规则格式错误：缺少 rules 列表");
        }
        if (list.size() > policy.maxRuleCount()) {
            throw new IOException("RULE_COUNT_LIMIT:" + policy.maxRuleCount());
        }
        List<Rule.SinkRule> sinks = new ArrayList<>();
        List<Rule.MagicEntryRule> entries = new ArrayList<>();
        List<Rule.SourceRule> sources = new ArrayList<>();
        List<Rule.ModelRule> models = new ArrayList<>();
        List<Rule.FragmentRule> fragments = new ArrayList<>();
        List<Rule.ConditionRule> conditions = new ArrayList<>();
        java.util.Set<String> seenIds = new java.util.HashSet<>();
        for (Object item : list) {
            parseBudget.checkTime();
            if (!(item instanceof Map<?, ?> ruleMap)) {
                throw new IOException("规则格式错误：rules 列表元素必须是 map，实际 " + item);
            }
            String kind = str(ruleMap, "kind");
            String id = str(ruleMap, "id");
            if (id == null || kind == null) {
                throw new IOException("规则缺少 id/kind 字段（静默跳过会掩盖拼写错误）: " + ruleMap);
            }
            if (!Set.of("sink", "magic-entry", "source", "model", "chain-fragment", "condition").contains(kind)) {
                throw new IOException("未知规则 kind: " + kind
                        + "（规则 " + id + "；合法值 sink/magic-entry/source/model/chain-fragment/condition）");
            }
            validateRuleKeys(ruleMap, kind, id);
            if (!seenIds.add(id)) {
                throw new IOException("规则 id 重复: " + id + "（重复规则互相遮蔽，历史事故：基准规则双 FRAG-CC1）");
            }
            try {
                switch (kind) {
                    case "sink" -> sinks.add(parseSink(id, ruleMap));
                    case "magic-entry" -> entries.add(parseEntry(id, ruleMap));
                    case "source" -> sources.add(parseSource(id, ruleMap));
                    case "model" -> models.add(parseModel(id, ruleMap));
                    case "chain-fragment" -> fragments.add(parseFragment(id, ruleMap));
                    case "condition" -> conditions.add(parseCondition(id, ruleMap));
                    default -> throw new IOException("未知规则 kind: " + kind + "（规则 " + id
                            + "；合法值 sink/magic-entry/source/model/chain-fragment/condition）");
                }
            } catch (ClassCastException | IllegalArgumentException e) {
                throw new IOException("规则 " + id + " 字段类型或匹配表达式错误: " + e.getMessage(), e);
            }
        }
        parseBudget.checkTime();
        return new RuleSet(List.copyOf(sinks), List.copyOf(entries), List.copyOf(sources),
                List.copyOf(models), List.copyOf(fragments), List.copyOf(conditions), schemaVersion);
    }

    private static void validateRuleKeys(Map<?, ?> map, String kind, String id) throws IOException {
        Set<String> allowed = switch (kind) {
            case "sink" -> SINK_KEYS;
            case "magic-entry" -> ENTRY_KEYS;
            case "source" -> SOURCE_KEYS;
            case "model" -> MODEL_KEYS;
            case "chain-fragment" -> FRAGMENT_KEYS;
            case "condition" -> CONDITION_KEYS;
            default -> COMMON_RULE_KEYS;
        };
        rejectUnknownKeys(map, allowed, "rule " + id);
    }

    private static void rejectUnknownKeys(Map<?, ?> map, Set<String> allowed, String context)
            throws IOException {
        for (Object key : map.keySet()) {
            if (!(key instanceof String name)) {
                throw new IOException("RULE_KEY_TYPE:" + context);
            }
            if (!allowed.contains(name)) {
                throw new IOException("RULE_UNKNOWN_KEY:" + context + ":" + name);
            }
        }
    }

    /** Bound aliases/collections after construction as a second line of defence. */
    private static void validateTree(Object value, String context, InputBudget budget,
                                     InputBudget.Tracker parseBudget)
            throws IOException {
        IdentityHashMap<Object, Boolean> seen = new IdentityHashMap<>();
        int[] nodes = {0};
        validateTree(value, context, 0, seen, nodes, budget, parseBudget);
    }

    private static void validateTree(Object value, String context, int depth,
                                     IdentityHashMap<Object, Boolean> seen, int[] nodes,
                                     InputBudget budget, InputBudget.Tracker parseBudget)
            throws IOException {
        parseBudget.checkTime();
        parseBudget.recordRuleNode();
        if (++nodes[0] > budget.maxRuleNodes()) {
            throw new IOException("RULE_NODE_LIMIT:" + budget.maxRuleNodes());
        }
        if (depth > budget.maxRuleNestingDepth()) {
            throw new IOException("RULE_NESTING_LIMIT:" + budget.maxRuleNestingDepth());
        }
        if (value == null || value instanceof Number || value instanceof Boolean) {
            return;
        }
        if (value instanceof String text) {
            int scalarChars = text.codePointCount(0, text.length());
            parseBudget.recordRuleScalarChars(scalarChars);
            if (scalarChars > budget.maxRuleScalarChars()) {
                throw new IOException("RULE_SCALAR_LIMIT:" + budget.maxRuleScalarChars());
            }
            return;
        }
        if (seen.put(value, Boolean.TRUE) != null) {
            return;
        }
        if (value instanceof Map<?, ?> map) {
            if (map.size() > budget.maxRuleCollectionItems()) {
                throw new IOException("RULE_MAP_LIMIT:" + budget.maxRuleCollectionItems() + ":" + context);
            }
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                parseBudget.recordRuleCollectionItem();
                validateTree(entry.getKey(), context + ".key", depth + 1, seen, nodes, budget,
                        parseBudget);
                validateTree(entry.getValue(), context, depth + 1, seen, nodes, budget,
                        parseBudget);
            }
            return;
        }
        if (value instanceof List<?> list) {
            if (list.size() > budget.maxRuleCollectionItems()) {
                throw new IOException("RULE_LIST_LIMIT:" + budget.maxRuleCollectionItems() + ":" + context);
            }
            for (Object item : list) {
                parseBudget.recordRuleCollectionItem();
                validateTree(item, context, depth + 1, seen, nodes, budget, parseBudget);
            }
            return;
        }
        throw new IOException("RULE_VALUE_TYPE:" + context);
    }

    @SuppressWarnings("unchecked")
    private Rule.SinkRule parseSink(String id, Map<?, ?> ruleMap) throws IOException {
        Map<?, ?> match = requiredMap(ruleMap, "match", ruleMap.get("kind") + " 规则 " + id + " 缺少 match 块",
                ruleMap.get("kind") + " 规则 " + id + " 的 match 必须是 map");
        rejectUnknownKeys(match, Set.of("call"), "sink rule " + id + " match");
        Map<?, ?> call = requiredMap(match, "call", "sink 规则 " + id + " 缺少 match.call",
                "sink 规则 " + id + " 的 match.call 必须是 map");
        rejectUnknownKeys(call, CALL_KEYS, "sink rule " + id + " call");
        Rule.CallMatcher callMatcher = new Rule.CallMatcher(
                matchOf(call.get("owner")),
                matchOf(call.get("name")),
                matchNullable(call.get("descriptor")));
        List<Rule.TaintedPos> tainted = new ArrayList<>();
        Object taintedObj = ruleMap.get("tainted");
        if (!(taintedObj instanceof List<?> taintedList) || taintedList.isEmpty()) {
            throw new IOException("sink 规则 " + id + " 缺少非空 tainted 列表");
        }
        for (Object t : taintedList) {
            if (!(t instanceof Map<?, ?> pos)) {
                throw new IOException("sink 规则 " + id + " 的 tainted 项必须是 map");
            }
            rejectUnknownKeys(pos, Set.of("receiver", "arg"), "sink rule " + id + " tainted");
            boolean receiver = Boolean.TRUE.equals(pos.get("receiver"));
            Object arg = pos.get("arg");
            if (receiver == (arg != null)) {
                throw new IOException("sink 规则 " + id + " 的 tainted 项必须恰好指定 receiver 或 arg");
            }
            if (receiver) {
                tainted.add(Rule.TaintedPos.Receiver.INSTANCE);
            } else if (arg instanceof Number n && n.intValue() >= 0) {
                tainted.add(new Rule.TaintedPos.Arg(n.intValue()));
            } else {
                throw new IOException("sink 规则 " + id + " 的 arg 必须是非负整数");
            }
        }
        String category = requiredString(ruleMap, "category", "sink 规则 " + id + " 缺少 category");
        String severity = requiredString(ruleMap, "severity", "sink 规则 " + id + " 缺少 severity");
        Object roleValue = ruleMap.containsKey("role") ? ruleMap.get("role") : ruleMap.get("sinkRole");
        Rule.SinkRole role;
        try {
            role = Rule.SinkRole.parse(roleValue == null ? null : roleValue.toString());
        } catch (IllegalArgumentException invalidRole) {
            throw new IOException("sink 规则 " + id + " 的 role 无效: " + invalidRole.getMessage(), invalidRole);
        }
        Object riskValue = ruleMap.containsKey("sink_risk")
                ? ruleMap.get("sink_risk") : ruleMap.get("sinkRisk");
        SinkRisk sinkRisk;
        try {
            sinkRisk = riskValue == null
                    ? SinkRisk.infer(category, callMatcher.ownerType(), callMatcher.name().pattern())
                    : SinkRisk.parse(riskValue.toString());
        } catch (IllegalArgumentException invalidRisk) {
            throw new IOException("sink 规则 " + id + " 的 sink_risk 无效: "
                    + invalidRisk.getMessage(), invalidRisk);
        }
        return new Rule.SinkRule(id, category, severity,
                callMatcher, List.copyOf(tainted), role, sinkRisk);
    }

    private static String requiredString(Map<?, ?> map, String key, String message) throws IOException {
        String value = str(map, key);
        if (value == null || value.isBlank()) {
            throw new IOException(message);
        }
        return value;
    }

    private static Map<?, ?> requiredMap(Map<?, ?> map, String key,
                                         String missingMessage, String typeMessage) throws IOException {
        Object value = map.get(key);
        if (value == null) {
            throw new IOException(missingMessage);
        }
        if (!(value instanceof Map<?, ?> nested)) {
            throw new IOException(typeMessage);
        }
        return nested;
    }

    @SuppressWarnings("unchecked")
    private Rule.MagicEntryRule parseEntry(String id, Map<?, ?> ruleMap) throws IOException {
        Map<?, ?> match = requiredMap(ruleMap, "match", "magic-entry 规则 " + id + " 缺少 match 块",
                "magic-entry 规则 " + id + " 的 match 必须是 map");
        rejectUnknownKeys(match, Set.of("method", "class"), "magic-entry rule " + id + " match");
        Map<?, ?> method = requiredMap(match, "method", "magic-entry 规则 " + id + " 缺少 match.method",
                "magic-entry 规则 " + id + " 的 match.method 必须是 map");
        rejectUnknownKeys(method, METHOD_KEYS, "magic-entry rule " + id + " method");
        Rule.MethodMatcher methodMatcher = new Rule.MethodMatcher(
                matchOf(method.get("name")),
                matchNullable(method.get("descriptor")),
                "private".equalsIgnoreCase(str(method, "access")));
        String implementsType = null;
        Object cls = match.get("class");
        if (cls != null && !(cls instanceof Map<?, ?>)) {
            throw new IOException("magic-entry 规则 " + id + " 的 match.class 必须是 map");
        }
        if (cls instanceof Map<?, ?> classMap && classMap.get("implements") != null) {
            rejectUnknownKeys(classMap, CLASS_KEYS, "magic-entry rule " + id + " class");
            implementsType = requiredString(classMap, "implements",
                    "magic-entry 规则 " + id + " 的 class.implements 不能为空");
        } else if (cls instanceof Map<?, ?> classMap) {
            rejectUnknownKeys(classMap, CLASS_KEYS, "magic-entry rule " + id + " class");
        }
        String entryKind = requiredString(ruleMap, "entryKind", "magic-entry 规则 " + id + " 缺少 entryKind");
        String direction = str(ruleMap, "direction");
        if (direction != null && !direction.equalsIgnoreCase("deserialize")
                && !direction.equalsIgnoreCase("serialize")
                && !direction.equalsIgnoreCase("lifecycle")) {
            throw new IOException("magic-entry 规则 " + id
                    + " 的 direction 只能是 deserialize/serialize/lifecycle");
        }
        return new Rule.MagicEntryRule(id, entryKind, methodMatcher, implementsType, direction);
    }

    @SuppressWarnings("unchecked")
    private Rule.SourceRule parseSource(String id, Map<?, ?> ruleMap) throws IOException {
        Map<?, ?> match = requiredMap(ruleMap, "match", "source 规则 " + id + " 缺少 match 块",
                "source 规则 " + id + " 的 match 必须是 map");
        rejectUnknownKeys(match, Set.of("call"), "source rule " + id + " match");
        Map<?, ?> call = requiredMap(match, "call", "source 规则 " + id + " 缺少 match.call",
                "source 规则 " + id + " 的 match.call 必须是 map");
        rejectUnknownKeys(call, CALL_KEYS, "source rule " + id + " call");
        Rule.CallMatcher callMatcher = new Rule.CallMatcher(
                matchOf(call.get("owner")),
                matchOf(call.get("name")),
                matchNullable(call.get("descriptor")));
        Rule.SafeConfigDecl safeConfig = null;
        Object safeObj = ruleMap.get("safe-config");
        if (safeObj != null && !(safeObj instanceof Map<?, ?>)) {
            throw new IOException("source 规则 " + id + " 的 safe-config 必须是 map");
        }
        if (safeObj instanceof Map<?, ?> safeMap) {
            rejectUnknownKeys(safeMap, SAFE_CONFIG_KEYS, "source rule " + id + " safe-config");
            Match safeOwner = matchOf(safeMap.get("owner"));
            Set<String> methods = new java.util.HashSet<>();
            if (safeMap.get("methods") instanceof List<?> methodList) {
                for (Object m : methodList) {
                    methods.add(m.toString());
                }
            }
            if (methods.isEmpty()) {
                throw new IOException("source 规则 " + id + " 的 safe-config.methods 为空");
            }
            Object safeValue = safeMap.get("safe-value");
            if (safeValue != null && !(safeValue instanceof Boolean)) {
                throw new IOException("source 规则 " + id + " 的 safe-config.safe-value 必须是 boolean");
            }
            Boolean safeBool = safeValue instanceof Boolean b ? b : null;
            safeConfig = new Rule.SafeConfigDecl(safeOwner, Set.copyOf(methods), safeBool);
        }
        String bridge = requiredString(ruleMap, "bridge", "source 规则 " + id + " 缺少 bridge");
        if (!"serialize".equalsIgnoreCase(bridge) && !"deserialize".equalsIgnoreCase(bridge)) {
            throw new IOException("source 规则 " + id + " 的 bridge 只能是 serialize 或 deserialize");
        }
        List<Rule.TaintedPos> tainted = parseOptionalTainted(ruleMap, "source 规则 " + id);
        return new Rule.SourceRule(id, bridge, callMatcher, safeConfig, tainted);
    }

    private Rule.ConditionRule parseCondition(String id, Map<?, ?> ruleMap) throws IOException {
        Map<?, ?> match = requiredMap(ruleMap, "match", "condition 规则 " + id + " 缺少 match 块",
                "condition 规则 " + id + " 的 match 必须是 map");
        rejectUnknownKeys(match, Set.of("class"), "condition rule " + id + " match");
        Match targetClass = matchOf(match.get("class"));
        Map<?, ?> condition = requiredMap(ruleMap, "condition",
                "condition 规则 " + id + " 缺少 condition 块",
                "condition 规则 " + id + " 的 condition 必须是 map");
        String type = requiredString(condition, "type", "condition 规则 " + id + " 缺少 condition.type")
                .toLowerCase(java.util.Locale.ROOT);
        return switch (type) {
            case "serialization-guard" -> parseSerializationGuard(id, targetClass, condition);
            case "serializable" -> parseSerializableRequirement(id, targetClass, condition);
            case "property-filter" -> parsePropertyFilter(id, targetClass, condition);
            default -> throw new IOException("condition 规则 " + id + " 的 type 无效: " + type);
        };
    }

    private Rule.ConditionRule parseSerializationGuard(String id, Match targetClass,
                                                        Map<?, ?> condition) throws IOException {
        rejectUnknownKeys(condition, Set.of("type", "call", "property"),
                "condition rule " + id + " serialization-guard");
        Map<?, ?> call = requiredMap(condition, "call", "condition 规则 " + id + " 缺少 guard call",
                "condition 规则 " + id + " 的 guard call 必须是 map");
        rejectUnknownKeys(call, CALL_KEYS, "condition rule " + id + " guard call");
        Rule.CallMatcher guard = new Rule.CallMatcher(matchOf(call.get("owner")),
                matchOf(call.get("name")), matchNullable(call.get("descriptor")));
        Map<?, ?> property = requiredMap(condition, "property",
                "condition 规则 " + id + " 缺少 property",
                "condition 规则 " + id + " 的 property 必须是 map");
        rejectUnknownKeys(property, Set.of("key", "required"),
                "condition rule " + id + " property");
        return new Rule.ConditionRule(id, targetClass,
                new Rule.SerializationGuard(guard,
                        requiredString(property, "key", "condition 规则 " + id + " 缺少 property.key"),
                        requiredString(property, "required",
                                "condition 规则 " + id + " 缺少 property.required")));
    }

    private Rule.ConditionRule parseSerializableRequirement(String id, Match targetClass,
                                                             Map<?, ?> condition) throws IOException {
        rejectUnknownKeys(condition, Set.of("type", "interface"),
                "condition rule " + id + " serializable");
        return new Rule.ConditionRule(id, targetClass,
                new Rule.SerializableRequirement(requiredString(condition, "interface",
                        "condition 规则 " + id + " 缺少 interface")));
    }

    private Rule.ConditionRule parsePropertyFilter(String id, Match targetClass,
                                                   Map<?, ?> condition) throws IOException {
        rejectUnknownKeys(condition, Set.of("type", "registration", "field", "blocked-value"),
                "condition rule " + id + " property-filter");
        Map<?, ?> registration = requiredMap(condition, "registration",
                "condition 规则 " + id + " 缺少 registration",
                "condition 规则 " + id + " 的 registration 必须是 map");
        rejectUnknownKeys(registration, Set.of("owner", "method", "marker"),
                "condition rule " + id + " registration");
        Rule.PropertyFilterDecl filter = new Rule.PropertyFilterDecl(
                matchOf(registration.get("owner")), matchOf(registration.get("method")),
                matchOf(registration.get("marker")),
                requiredString(condition, "field", "condition 规则 " + id + " 缺少 field"),
                requiredString(condition, "blocked-value",
                        "condition 规则 " + id + " 缺少 blocked-value"));
        return new Rule.ConditionRule(id, targetClass, filter);
    }

    /** source 的 tainted 为空表示无条件入口；出现该字段时必须是非空位置列表。 */
    private static List<Rule.TaintedPos> parseOptionalTainted(Map<?, ?> ruleMap, String context)
            throws IOException {
        Object raw = ruleMap.get("tainted");
        if (raw == null) {
            return List.of();
        }
        if (!(raw instanceof List<?> list) || list.isEmpty()) {
            throw new IOException(context + " 的 tainted 必须是非空列表");
        }
        List<Rule.TaintedPos> result = new ArrayList<>(list.size());
        Set<String> seen = new java.util.HashSet<>();
        for (Object item : list) {
            if (!(item instanceof Map<?, ?> position)) {
                throw new IOException(context + " 的 tainted 项必须是 map");
            }
            rejectUnknownKeys(position, Set.of("receiver", "arg"), context + " tainted");
            boolean receiver = Boolean.TRUE.equals(position.get("receiver"));
            Object arg = position.get("arg");
            if (receiver == (arg != null)) {
                throw new IOException(context + " 的 tainted 项必须恰好指定 receiver 或 arg");
            }
            if (receiver) {
                if (!seen.add("receiver")) {
                    throw new IOException(context + " 的 tainted 位置重复: receiver");
                }
                result.add(Rule.TaintedPos.Receiver.INSTANCE);
            } else if (arg instanceof Number number && number.intValue() >= 0) {
                String key = "arg" + number.intValue();
                if (!seen.add(key)) {
                    throw new IOException(context + " 的 tainted 位置重复: " + key);
                }
                result.add(new Rule.TaintedPos.Arg(number.intValue()));
            } else {
                throw new IOException(context + " 的 tainted arg 必须是非负整数");
            }
        }
        return List.copyOf(result);
    }

    @SuppressWarnings("unchecked")
    private Rule.ModelRule parseModel(String id, Map<?, ?> ruleMap) throws IOException {
        Map<?, ?> match = requiredMap(ruleMap, "match", "model 规则 " + id + " 缺少 match 块",
                "model 规则 " + id + " 的 match 必须是 map");
        rejectUnknownKeys(match, Set.of("call"), "model rule " + id + " match");
        Map<?, ?> call = requiredMap(match, "call", "model 规则 " + id + " 缺少 match.call",
                "model 规则 " + id + " 的 match.call 必须是 map");
        rejectUnknownKeys(call, CALL_KEYS, "model rule " + id + " call");
        Rule.CallMatcher callMatcher = new Rule.CallMatcher(
                matchOf(call.get("owner")),
                matchOf(call.get("name")),
                matchNullable(call.get("descriptor")));
        Map<String, List<String>> actions = new LinkedHashMap<>();
        Object actionsObj = ruleMap.get("actions");
        if (!(actionsObj instanceof Map<?, ?> actionsMap) || actionsMap.isEmpty()) {
            throw new IOException("model 规则 " + id + " 缺少非空 actions 映射");
        }
        rejectUnknownKeys(actionsMap, Set.of("this", "return"), "model rule " + id + " actions");
        List<Map.Entry<?, ?>> actionEntries = new ArrayList<>(actionsMap.entrySet());
        actionEntries.sort(java.util.Comparator.comparing(e -> String.valueOf(e.getKey())));
        for (Map.Entry<?, ?> e : actionEntries) {
            if (e.getKey() == null) {
                throw new IOException("model 规则 " + id + " 的 action 目标不能为空");
            }
            String target = e.getKey().toString();
            if (!("this".equals(target) || "return".equals(target))) {
                throw new IOException("model 规则 " + id + " 的 action 目标只能是 this/return");
            }
            if (!(e.getValue() instanceof List<?> srcList) || srcList.isEmpty()) {
                throw new IOException("model 规则 " + id + " 的 action 来源必须是非空列表");
            }
            List<String> sources = new ArrayList<>();
            for (Object s : srcList) {
                if (s == null) {
                    throw new IOException("model 规则 " + id + " 的来源不能为空");
                }
                String source = s.toString();
                if (!ModelSource.isValid(source)) {
                    throw new IOException("model 规则 " + id
                            + " 的来源必须是 this、argN 或 element(this/argN)");
                }
                sources.add(source);
            }
            actions.put(target, List.copyOf(sources));
        }
        return new Rule.ModelRule(id, callMatcher,
                Collections.unmodifiableMap(new LinkedHashMap<>(actions)));
    }

    @SuppressWarnings("unchecked")
    private Rule.FragmentRule parseFragment(String id, Map<?, ?> ruleMap) throws IOException {
        String entryClass = str(ruleMap, "entryClass");
        String entryKind = str(ruleMap, "entryKind");
        String entryMethod = str(ruleMap, "entryMethod");
        String entryDescriptor = str(ruleMap, "entryDescriptor");
        String activation = str(ruleMap, "activation");
        String sinkOwner = str(ruleMap, "sinkOwner");
        String sinkName = str(ruleMap, "sinkName");
        String sinkDescriptor = str(ruleMap, "sinkDescriptor");
        boolean directTerminal = false;
        if (ruleMap.containsKey("direct")) {
            Object rawDirect = ruleMap.get("direct");
            if (rawDirect instanceof Boolean value) {
                directTerminal = value;
            } else if (rawDirect instanceof String value
                    && ("true".equalsIgnoreCase(value.trim())
                    || "false".equalsIgnoreCase(value.trim()))) {
                directTerminal = Boolean.parseBoolean(value.trim());
            } else {
                throw new IOException("chain-fragment 规则 " + id + " 的 direct 必须是布尔值");
            }
        }
        List<Rule.HopSpec> hops = new ArrayList<>();
        Object rawHops = ruleMap.get("hops");
        if (!(rawHops instanceof List<?> hopList)) {
            throw new IOException("chain-fragment 规则 " + id + " 的 hops 必须是列表");
        }
        for (Object h : hopList) {
            if (!(h instanceof Map<?, ?> hm)) {
                throw new IOException("chain-fragment 规则 " + id + " 的 hop 必须是映射");
            }
            rejectUnknownKeys(hm, HOP_KEYS, "chain-fragment rule " + id + " hop");
            String cls = requireText(hm, "class", "chain-fragment 规则 " + id);
            String method = requireText(hm, "method", "chain-fragment 规则 " + id);
            String field = str(hm, "field");
            hops.add(new Rule.HopSpec(cls, method, field));
        }
        if (isBlank(entryClass) || isBlank(sinkOwner) || isBlank(sinkName)
                || (!directTerminal && hops.isEmpty())) {
            throw new IOException("chain-fragment 规则 " + id
                    + " 缺少 entryClass/sinkOwner/sinkName/hops（direct 终端可为空 hops）");
        }
        if (directTerminal && (!hops.isEmpty() || isBlank(entryMethod)
                || isBlank(entryDescriptor) || isBlank(sinkDescriptor)
                || !entryClass.equals(sinkOwner) || !entryMethod.equals(sinkName)
                || !entryDescriptor.equals(sinkDescriptor))) {
            throw new IOException("chain-fragment 规则 " + id
                    + " 的 direct 终端必须以完整且相同的 entry/sink 描述符声明");
        }
        ObjectGraphPlan constructionPlan = parseConstructionPlan(id, ruleMap.get("construction"));
        return new Rule.FragmentRule(id, entryClass, entryKind == null ? "readObject" : entryKind,
                List.copyOf(hops), sinkOwner, sinkName, sinkDescriptor, entryMethod,
                entryDescriptor, activation, constructionPlan, directTerminal);
    }

    /**
     * Parse the bounded object-shape DSL used by safe verification.  It intentionally has no
     * expression/evaluation form: nodes are allocate/proxy/constructor records and field values
     * are typed literals or references to another node.
     */
    private static ObjectGraphPlan parseConstructionPlan(String id, Object raw) throws IOException {
        if (raw == null) {
            return null;
        }
        if (!(raw instanceof Map<?, ?> plan)) {
            throw new IOException("chain-fragment 规则 " + id + " 的 construction 必须是映射");
        }
        rejectUnknownKeys(plan, CONSTRUCTION_KEYS, "chain-fragment rule " + id + " construction");
        List<ObjectGraphPlan.Node> nodes = new ArrayList<>();
        Object rawNodes = plan.get("nodes");
        if (rawNodes != null) {
            if (!(rawNodes instanceof List<?> list)) {
                throw new IOException("chain-fragment 规则 " + id + " 的 construction.nodes 必须是列表");
            }
            for (Object rawNode : list) {
                if (!(rawNode instanceof Map<?, ?> node)) {
                    throw new IOException("chain-fragment 规则 " + id + " 的 construction node 必须是映射");
                }
                rejectUnknownKeys(node, NODE_KEYS, "chain-fragment rule " + id + " construction node");
                String nodeId = requireText(node, "id", "chain-fragment 规则 " + id + " construction node");
                String type = requireText(node, "type", "chain-fragment 规则 " + id + " construction node");
                String kindText = str(node, "kind");
                ObjectGraphPlan.NodeKind kind;
                try {
                    kind = kindText == null ? ObjectGraphPlan.NodeKind.ALLOCATE
                            : ObjectGraphPlan.NodeKind.valueOf(kindText.trim().toUpperCase(java.util.Locale.ROOT));
                } catch (IllegalArgumentException invalidKind) {
                    throw new IOException("chain-fragment 规则 " + id + " construction node kind 无效: "
                            + kindText, invalidKind);
                }
                nodes.add(new ObjectGraphPlan.Node(nodeId, type, kind,
                        parseValues(id, node.get("args"), "construction node args", true)));
            }
        }
        List<ObjectGraphPlan.FieldAssignment> fields = new ArrayList<>();
        Object rawFields = plan.get("fields");
        if (rawFields != null) {
            if (!(rawFields instanceof List<?> list)) {
                throw new IOException("chain-fragment 规则 " + id + " 的 construction.fields 必须是列表");
            }
            for (Object rawField : list) {
                if (!(rawField instanceof Map<?, ?> field)) {
                    throw new IOException("chain-fragment 规则 " + id + " 的 construction field 必须是映射");
                }
                rejectUnknownKeys(field, FIELD_KEYS, "chain-fragment rule " + id + " construction field");
                String owner = requireText(field, "owner", "chain-fragment 规则 " + id + " construction field");
                String name = requireText(field, "field", "chain-fragment 规则 " + id + " construction field");
                Object rawValues = field.containsKey("values") ? field.get("values") : field.get("value");
                List<ObjectGraphPlan.Value> values = parseValues(id, rawValues,
                        "construction field values", false);
                fields.add(new ObjectGraphPlan.FieldAssignment(owner, name, values));
            }
        }
        if (nodes.isEmpty() && fields.isEmpty()) {
            throw new IOException("chain-fragment 规则 " + id + " 的 construction 不能为空");
        }
        try {
            return new ObjectGraphPlan(nodes, fields);
        } catch (IllegalArgumentException invalidPlan) {
            throw new IOException("chain-fragment 规则 " + id + " 的 construction 无效: "
                    + invalidPlan.getMessage(), invalidPlan);
        }
    }

    private static List<ObjectGraphPlan.Value> parseValues(String id, Object raw,
                                                            String label, boolean optional)
            throws IOException {
        if (raw == null) {
            if (optional) {
                return List.of();
            }
            throw new IOException("chain-fragment 规则 " + id + " 的 " + label + " 缺失");
        }
        List<?> items;
        if (raw instanceof List<?> list) {
            items = list;
        } else if (!optional) {
            items = List.of(raw);
        } else {
            throw new IOException("chain-fragment 规则 " + id + " 的 " + label + " 必须是列表");
        }
        List<ObjectGraphPlan.Value> values = new ArrayList<>(items.size());
        for (Object item : items) {
            if (!(item instanceof Map<?, ?> value)) {
                throw new IOException("chain-fragment 规则 " + id + " 的 construction value 必须是映射");
            }
            rejectUnknownKeys(value, VALUE_KEYS, "chain-fragment rule " + id + " construction value");
            List<ObjectGraphPlan.ValueKind> kinds = new ArrayList<>();
            ObjectGraphPlan.Value parsed = null;
            for (ObjectGraphPlan.ValueKind kind : ObjectGraphPlan.ValueKind.values()) {
                String key = switch (kind) {
                    case REF -> "ref";
                    case CLASS -> "class";
                    case STRING -> "string";
                    case INT -> "int";
                    case LONG -> "long";
                    case BOOLEAN -> "boolean";
                    case NULL -> "null";
                };
                if (!value.containsKey(key)) {
                    continue;
                }
                kinds.add(kind);
                Object rawValue = value.get(key);
                if (kind == ObjectGraphPlan.ValueKind.NULL) {
                    parsed = new ObjectGraphPlan.Value(kind, "");
                } else if (rawValue == null) {
                    throw new IOException("chain-fragment 规则 " + id + " 的 construction " + key
                            + " value 不能为空");
                } else {
                    parsed = new ObjectGraphPlan.Value(kind, rawValue.toString());
                }
            }
            if (kinds.size() != 1 || parsed == null) {
                throw new IOException("chain-fragment 规则 " + id
                        + " 的 construction value 必须恰好指定 ref/class/string/int/long/boolean/null");
            }
            values.add(parsed);
        }
        if (values.isEmpty() && !optional) {
            throw new IOException("chain-fragment 规则 " + id + " 的 " + label + " 不能为空");
        }
        return List.copyOf(values);
    }

    private static Match matchOf(Object raw) throws IOException {
        if (raw == null) {
            throw new IOException("匹配值缺失");
        }
        return Match.of(raw.toString());
    }

    private static Match matchNullable(Object raw) {
        return raw == null ? null : Match.of(raw.toString());
    }

    private static String str(Map<?, ?> map, String key) {
        Object v = map.get(key);
        return v != null ? v.toString() : null;
    }

    private static String requireText(Map<?, ?> map, String key, String context) throws IOException {
        String value = str(map, key);
        if (isBlank(value)) {
            throw new IOException(context + " 缺少 " + key);
        }
        return value;
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
