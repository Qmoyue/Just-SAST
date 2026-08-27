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
            switch (kind) {
                case "sink" -> sinks.add(parseSink(id, ruleMap));
                case "magic-entry" -> entries.add(parseEntry(id, ruleMap));
                case "source" -> sources.add(parseSource(id, ruleMap));
                case "model" -> models.add(parseModel(id, ruleMap));
                case "chain-fragment" -> fragments.add(parseFragment(id, ruleMap));
                default -> throw new IOException("未知规则 kind: " + kind + "（规则 " + id
                        + "；合法值 sink/magic-entry/source/model/chain-fragment）");
            }
        }
        return new RuleSet(List.copyOf(sinks), List.copyOf(entries), List.copyOf(sources),
                List.copyOf(models), List.copyOf(fragments));
    }

    @SuppressWarnings("unchecked")
    private Rule.SinkRule parseSink(String id, Map<?, ?> ruleMap) throws IOException {
        Map<?, ?> match = (Map<?, ?>) ruleMap.get("match");
        if (match == null) {
            throw new IOException(ruleMap.get("kind") + " 规则 " + id + " 缺少 match 块");
        }
        Map<?, ?> call = (Map<?, ?>) match.get("call");
        if (call == null) {
            throw new IOException("sink 规则 " + id + " 缺少 match.call");
        }
        Rule.CallMatcher callMatcher = new Rule.CallMatcher(
                matchOf(call.get("owner")),
                matchOf(call.get("name")),
                matchNullable(call.get("descriptor")));
        List<Rule.TaintedPos> tainted = new ArrayList<>();
        Object taintedObj = ruleMap.get("tainted");
        if (taintedObj instanceof List<?> taintedList) {
            for (Object t : taintedList) {
                if (t instanceof Map<?, ?> pos) {
                    if (pos.get("receiver") instanceof Boolean b && b) {
                        tainted.add(Rule.TaintedPos.Receiver.INSTANCE);
                    } else if (pos.get("arg") instanceof Number n) {
                        tainted.add(new Rule.TaintedPos.Arg(n.intValue()));
                    }
                }
            }
        }
        return new Rule.SinkRule(id, str(ruleMap, "category"), str(ruleMap, "severity"),
                callMatcher, List.copyOf(tainted));
    }

    @SuppressWarnings("unchecked")
    private Rule.MagicEntryRule parseEntry(String id, Map<?, ?> ruleMap) throws IOException {
        Map<?, ?> match = (Map<?, ?>) ruleMap.get("match");
        if (match == null) {
            throw new IOException("magic-entry 规则 " + id + " 缺少 match 块");
        }
        Map<?, ?> method = (Map<?, ?>) match.get("method");
        if (method == null) {
            throw new IOException("magic-entry 规则 " + id + " 缺少 match.method");
        }
        Rule.MethodMatcher methodMatcher = new Rule.MethodMatcher(
                matchOf(method.get("name")),
                matchNullable(method.get("descriptor")),
                "private".equalsIgnoreCase(str(method, "access")));
        String implementsType = null;
        Object cls = match.get("class");
        if (cls instanceof Map<?, ?> classMap && classMap.get("implements") != null) {
            implementsType = classMap.get("implements").toString();
        }
        return new Rule.MagicEntryRule(id, str(ruleMap, "entryKind"), methodMatcher, implementsType);
    }

    @SuppressWarnings("unchecked")
    private Rule.SourceRule parseSource(String id, Map<?, ?> ruleMap) throws IOException {
        Map<?, ?> match = (Map<?, ?>) ruleMap.get("match");
        if (match == null) {
            throw new IOException(ruleMap.get("kind") + " 规则 " + id + " 缺少 match 块");
        }
        Map<?, ?> call = (Map<?, ?>) match.get("call");
        if (call == null) {
            throw new IOException("source 规则 " + id + " 缺少 match.call");
        }
        Rule.CallMatcher callMatcher = new Rule.CallMatcher(
                matchOf(call.get("owner")),
                matchOf(call.get("name")),
                matchNullable(call.get("descriptor")));
        Rule.SafeConfigDecl safeConfig = null;
        Object safeObj = ruleMap.get("safe-config");
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
            Boolean safeBool = safeValue instanceof Boolean b ? b : null;
            safeConfig = new Rule.SafeConfigDecl(safeOwner, Set.copyOf(methods), safeBool);
        }
        return new Rule.SourceRule(id, str(ruleMap, "bridge"), callMatcher, safeConfig);
    }

    @SuppressWarnings("unchecked")
    private Rule.ModelRule parseModel(String id, Map<?, ?> ruleMap) throws IOException {
        Map<?, ?> match = (Map<?, ?>) ruleMap.get("match");
        if (match == null) {
            throw new IOException(ruleMap.get("kind") + " 规则 " + id + " 缺少 match 块");
        }
        Map<?, ?> call = (Map<?, ?>) match.get("call");
        if (call == null) {
            throw new IOException("model 规则 " + id + " 缺少 match.call");
        }
        Rule.CallMatcher callMatcher = new Rule.CallMatcher(
                matchOf(call.get("owner")),
                matchOf(call.get("name")),
                matchNullable(call.get("descriptor")));
        Map<String, List<String>> actions = new HashMap<>();
        Object actionsObj = ruleMap.get("actions");
        if (actionsObj instanceof Map<?, ?> actionsMap) {
            for (Map.Entry<?, ?> e : actionsMap.entrySet()) {
                String target = e.getKey().toString();
                List<String> sources = new ArrayList<>();
                if (e.getValue() instanceof List<?> srcList) {
                    for (Object s : srcList) {
                        sources.add(s.toString());
                    }
                }
                actions.put(target, List.copyOf(sources));
            }
        }
        return new Rule.ModelRule(id, callMatcher, Map.copyOf(actions));
    }

    @SuppressWarnings("unchecked")
    private Rule.FragmentRule parseFragment(String id, Map<?, ?> ruleMap) throws IOException {
        String entryClass = str(ruleMap, "entryClass");
        String entryKind = str(ruleMap, "entryKind");
        String sinkOwner = str(ruleMap, "sinkOwner");
        String sinkName = str(ruleMap, "sinkName");
        List<Rule.HopSpec> hops = new ArrayList<>();
        if (ruleMap.get("hops") instanceof List<?> hopList) {
            for (Object h : hopList) {
                if (h instanceof Map<?, ?> hm) {
                    hops.add(new Rule.HopSpec(str(hm, "class"), str(hm, "method"), str(hm, "field")));
                }
            }
        }
        if (entryClass == null || sinkOwner == null || sinkName == null || hops.isEmpty()) {
            throw new IOException("chain-fragment 规则 " + id + " 缺少 entryClass/sinkOwner/sinkName/hops");
        }
        return new Rule.FragmentRule(id, entryClass, entryKind == null ? "readObject" : entryKind,
                List.copyOf(hops), sinkOwner, sinkName);
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
}
