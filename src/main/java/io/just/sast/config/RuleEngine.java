package io.just.sast.config;

import io.just.sast.analysis.hierarchy.ClassHierarchy;
import io.just.sast.cpg.graph.Node;

import java.lang.reflect.Modifier;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * 规则匹配引擎（每 RuleSet 一个实例，经黑板分发，缓存随实例生命周期——无跨扫描脏缓存）。
 * 匹配结果按 (owner|name|desc) 缓存；sink/source/model 支持 owner 层次命中
 * （调用点 owner 为规则 owner 的子类型/实现类时命中，由 ClassHierarchy 判定）；
 * magic-entry 含 implementsType 层次校验与 privateOnly 过滤（access 经 ClassHierarchy 解析）。
 */
public final class RuleEngine {

    private final RuleSet rules;
    private final ClassHierarchy hierarchy;
    private final Map<String, Optional<Rule.SinkRule>> sinkCache = new java.util.concurrent.ConcurrentHashMap<>();
    private final Map<String, Optional<Rule.MagicEntryRule>> entryCache = new java.util.concurrent.ConcurrentHashMap<>();
    private final Map<String, Optional<Rule.SourceRule>> sourceCache = new java.util.concurrent.ConcurrentHashMap<>();
    private final Map<String, Optional<Rule.ModelRule>> modelCache = new java.util.concurrent.ConcurrentHashMap<>();

    public RuleEngine(RuleSet rules, ClassHierarchy hierarchy) {
        this.rules = rules == null ? RuleSet.EMPTY : rules;
        this.hierarchy = Objects.requireNonNull(hierarchy, "hierarchy");
    }

    /** 编译后的规则集（框架包前缀等派生数据的来源）。 */
    public RuleSet rules() {
        return rules;
    }

    public Optional<Rule.SinkRule> matchingSink(Node call) {
        if (call == null) {
            return Optional.empty();
        }
        return matchingSink(call.strProp("owner"), call.strProp("name"), call.strProp("desc"));
    }

    /** 精确匹配 + 层次命中（调用点 owner 为规则 owner 子类型/实现类时命中）。 */
    public Optional<Rule.SinkRule> matchingSink(String owner, String name, String desc) {
        String cacheKey = cacheKey(owner, name, desc);
        return sinkCache.computeIfAbsent(cacheKey, k -> {
            Rule.SinkRule best = null;
            int bestScore = -1;
            for (Rule.SinkRule rule : rules.sinks()) {
                int score = callScore(rule.call(), owner, name, desc);
                if (score > bestScore || (score == bestScore && score >= 0
                        && best != null && rule.id().compareTo(best.id()) < 0)) {
                    best = rule;
                    bestScore = score;
                }
            }
            return best == null ? Optional.empty() : Optional.of(best);
        });
    }

    /** 匹配 magic-entry 规则（含 implementsType 层次校验与 privateOnly 过滤）。 */
    public Optional<Rule.MagicEntryRule> matchingEntry(String owner, String name, String desc) {
        String cacheKey = cacheKey(owner, name, desc);
        return entryCache.computeIfAbsent(cacheKey, k -> {
            Rule.MagicEntryRule best = null;
            int bestScore = -1;
            for (Rule.MagicEntryRule rule : rules.magicEntries()) {
                if (rule == null || rule.method() == null) {
                    continue;
                }
                if (!rule.method().matches(name, desc)) {
                    continue;
                }
                if (rule.method().privateOnly() && !isPrivate(owner, name, desc)) {
                    continue;
                }
                if (rule.implementsType() == null || hierarchy.isSubtypeOf(owner, rule.implementsType())) {
                    int score = methodScore(rule.method()) + (rule.implementsType() == null ? 0 : 4);
                    if (score > bestScore || (score == bestScore && best != null
                            && rule.id().compareTo(best.id()) < 0)) {
                        best = rule;
                        bestScore = score;
                    }
                }
            }
            return best == null ? Optional.empty() : Optional.of(best);
        });
    }

    /** 匹配 source 规则（框架桥接用，层次命中）。 */
    public Optional<Rule.SourceRule> matchingSource(String owner, String name, String desc) {
        String cacheKey = cacheKey(owner, name, desc);
        return sourceCache.computeIfAbsent(cacheKey, k -> {
            Rule.SourceRule best = null;
            int bestScore = -1;
            for (Rule.SourceRule rule : rules.sources()) {
                int score = callScore(rule.call(), owner, name, desc);
                if (score > bestScore || (score == bestScore && score >= 0
                        && best != null && rule.id().compareTo(best.id()) < 0)) {
                    best = rule;
                    bestScore = score;
                }
            }
            return best == null ? Optional.empty() : Optional.of(best);
        });
    }

    /** 匹配 model 规则（层次命中），供污点引擎消费。 */
    public Optional<Rule.ModelRule> matchingModel(String owner, String name, String desc) {
        String cacheKey = cacheKey(owner, name, desc);
        return modelCache.computeIfAbsent(cacheKey, k -> {
            Rule.ModelRule best = null;
            int bestScore = -1;
            for (Rule.ModelRule rule : rules.models()) {
                int score = callScore(rule.call(), owner, name, desc);
                if (score > bestScore || (score == bestScore && score >= 0
                        && best != null && rule.id().compareTo(best.id()) < 0)) {
                    best = rule;
                    bestScore = score;
                }
            }
            return best == null ? Optional.empty() : Optional.of(best);
        });
    }

    /**
     * Returns a deterministic specificity score, or -1 for no match. Exact owner/name/
     * descriptor matches outrank regex and hierarchy matches, so a broad rule cannot silently
     * hide a narrower rule merely because it appears earlier in YAML.
     */
    private int callScore(Rule.CallMatcher call, String owner, String name, String desc) {
        if (call == null || call.owner() == null || call.name() == null
                || owner == null || name == null) {
            return -1;
        }
        boolean literalOwner = !call.owner().isRegex();
        boolean exactOwner = literalOwner && call.owner().pattern().equals(owner);
        if (exactOwner) {
            if (!call.matchesRest(name, desc)) {
                return -1;
            }
        } else if (literalOwner) {
            if (!call.matchesRest(name, desc) || !hierarchy.isSubtypeOf(owner, call.ownerType())) {
                return -1;
            }
        } else {
            if (!call.owner().matches(owner) || !call.matchesRest(name, desc)) {
                return -1;
            }
        }
        // A regex match is direct but broad; it must not outrank a literal hierarchy
        // constraint merely because the owner happened to match the pattern. Exact literal
        // owner > literal subtype > regex owner is the stable specificity order.
        int score = exactOwner ? 100 : literalOwner ? 40 : 20;
        score += call.owner().isRegex() ? 1 : 16;
        score += call.name().isRegex() ? 2 : 16;
        if (call.descriptor() != null) {
            score += call.descriptor().isRegex() ? 2 : 12;
        }
        return score;
    }

    private static int methodScore(Rule.MethodMatcher method) {
        return (method.name().isRegex() ? 2 : 16)
                + (method.descriptor() == null ? 0
                : (method.descriptor().isRegex() ? 2 : 12));
    }

    private String cacheKey(String owner, String name, String desc) {
        // Lazy JDK loading changes CHA dispatch. Include the monotonic revision so a previous
        // negative result cannot survive the arrival of a more precise hierarchy fact.
        return hierarchy.revision() + "|" + owner + "|" + name + "|" + desc;
    }

    private boolean isPrivate(String owner, String name, String desc) {
        ClassHierarchy h = hierarchy;
        var cls = h.classInfo(owner);
        var method = cls != null ? cls.method(name, desc) : null;
        return method != null && Modifier.isPrivate(method.access());
    }
}
