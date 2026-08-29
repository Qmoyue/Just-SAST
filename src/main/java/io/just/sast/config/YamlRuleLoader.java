package io.just.sast.config;

import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** YAML 规则 → RuleSet。 */
public final class YamlRuleLoader {

    @SuppressWarnings("unchecked")
    public RuleSet load(InputStream in) throws IOException {
        if (in == null) {
            throw new IOException("规则流为空");
        }
        Object root = new Yaml(new SafeConstructor(new LoaderOptions())).load(in);
        if (!(root instanceof Map<?, ?> map)) {
            throw new IOException("规则格式错误：顶层必须是 map");
        }
        Object rulesObj = map.get("rules");
        if (!(rulesObj instanceof List<?> list)) {
            throw new IOException("规则格式错误：缺少 rules 列表");
        }
        List<Rule.SinkRule> sinks = new ArrayList<>();
        List<Rule.MagicEntryRule> entries = new ArrayList<>();
        List<Rule.SourceRule> sources = new ArrayList<>();
        List<Rule.ModelRule> models = new ArrayList<>();
        List<Rule.FragmentRule> fragments = new ArrayList<>();
        java.util.Set<String> seenIds = new java.util.HashSet<>();
        for (Object item : list) {
            if (!(item instanceof Map<?, ?> ruleMap)) {
                throw new IOException("规则格式错误：rules 列表元素必须是 map，实际 " + item);
            }
            String kind = str(ruleMap, "kind");
            String id = str(ruleMap, "id");
            if (id == null || kind == null) {
                throw new IOException("规则缺少 id/kind 字段（静默跳过会掩盖拼写错误）: " + ruleMap);
            }
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
                    default -> throw new IOException("未知规则 kind: " + kind + "（规则 " + id
                            + "；合法值 sink/magic-entry/source/model/chain-fragment）");
                }
            } catch (ClassCastException | IllegalArgumentException e) {
                throw new IOException("规则 " + id + " 字段类型或匹配表达式错误: " + e.getMessage(), e);
            }
        }
        return new RuleSet(List.copyOf(sinks), List.copyOf(entries), List.copyOf(sources),
                List.copyOf(models), List.copyOf(fragments));
    }

    @SuppressWarnings("unchecked")
    private Rule.SinkRule parseSink(String id, Map<?, ?> ruleMap) throws IOException {
        Map<?, ?> match = requiredMap(ruleMap, "match", ruleMap.get("kind") + " 规则 " + id + " 缺少 match 块",
                ruleMap.get("kind") + " 规则 " + id + " 的 match 必须是 map");
        Map<?, ?> call = requiredMap(match, "call", "sink 规则 " + id + " 缺少 match.call",
                "sink 规则 " + id + " 的 match.call 必须是 map");
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
        return new Rule.SinkRule(id, category, severity,
                callMatcher, List.copyOf(tainted));
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
        Map<?, ?> method = requiredMap(match, "method", "magic-entry 规则 " + id + " 缺少 match.method",
                "magic-entry 规则 " + id + " 的 match.method 必须是 map");
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
            implementsType = requiredString(classMap, "implements",
                    "magic-entry 规则 " + id + " 的 class.implements 不能为空");
        }
        return new Rule.MagicEntryRule(id,
                requiredString(ruleMap, "entryKind", "magic-entry 规则 " + id + " 缺少 entryKind"),
                methodMatcher, implementsType);
    }

    @SuppressWarnings("unchecked")
    private Rule.SourceRule parseSource(String id, Map<?, ?> ruleMap) throws IOException {
        Map<?, ?> match = requiredMap(ruleMap, "match", "source 规则 " + id + " 缺少 match 块",
                "source 规则 " + id + " 的 match 必须是 map");
        Map<?, ?> call = requiredMap(match, "call", "source 规则 " + id + " 缺少 match.call",
                "source 规则 " + id + " 的 match.call 必须是 map");
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
        return new Rule.SourceRule(id, bridge, callMatcher, safeConfig);
    }

    @SuppressWarnings("unchecked")
    private Rule.ModelRule parseModel(String id, Map<?, ?> ruleMap) throws IOException {
        Map<?, ?> match = requiredMap(ruleMap, "match", "model 规则 " + id + " 缺少 match 块",
                "model 规则 " + id + " 的 match 必须是 map");
        Map<?, ?> call = requiredMap(match, "call", "model 规则 " + id + " 缺少 match.call",
                "model 规则 " + id + " 的 match.call 必须是 map");
        Rule.CallMatcher callMatcher = new Rule.CallMatcher(
                matchOf(call.get("owner")),
                matchOf(call.get("name")),
                matchNullable(call.get("descriptor")));
        Map<String, List<String>> actions = new HashMap<>();
        Object actionsObj = ruleMap.get("actions");
        if (!(actionsObj instanceof Map<?, ?> actionsMap) || actionsMap.isEmpty()) {
            throw new IOException("model 规则 " + id + " 缺少非空 actions 映射");
        }
        for (Map.Entry<?, ?> e : actionsMap.entrySet()) {
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
                if (!("this".equals(source) || source.matches("arg[0-9]+"))) {
                    throw new IOException("model 规则 " + id + " 的来源必须是 this 或 argN");
                }
                sources.add(source);
            }
            actions.put(target, List.copyOf(sources));
        }
        return new Rule.ModelRule(id, callMatcher, Map.copyOf(actions));
    }

    @SuppressWarnings("unchecked")
    private Rule.FragmentRule parseFragment(String id, Map<?, ?> ruleMap) throws IOException {
        String entryClass = str(ruleMap, "entryClass");
        String entryKind = str(ruleMap, "entryKind");
        String sinkOwner = str(ruleMap, "sinkOwner");
        String sinkName = str(ruleMap, "sinkName");
        String sinkDescriptor = str(ruleMap, "sinkDescriptor");
        List<Rule.HopSpec> hops = new ArrayList<>();
        Object rawHops = ruleMap.get("hops");
        if (!(rawHops instanceof List<?> hopList)) {
            throw new IOException("chain-fragment 规则 " + id + " 的 hops 必须是列表");
        }
        for (Object h : hopList) {
            if (!(h instanceof Map<?, ?> hm)) {
                throw new IOException("chain-fragment 规则 " + id + " 的 hop 必须是映射");
            }
            String cls = requireText(hm, "class", "chain-fragment 规则 " + id);
            String method = requireText(hm, "method", "chain-fragment 规则 " + id);
            String field = str(hm, "field");
            hops.add(new Rule.HopSpec(cls, method, field));
        }
        if (isBlank(entryClass) || isBlank(sinkOwner) || isBlank(sinkName) || hops.isEmpty()) {
            throw new IOException("chain-fragment 规则 " + id + " 缺少 entryClass/sinkOwner/sinkName/hops");
        }
        return new Rule.FragmentRule(id, entryClass, entryKind == null ? "readObject" : entryKind,
                List.copyOf(hops), sinkOwner, sinkName, sinkDescriptor);
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
