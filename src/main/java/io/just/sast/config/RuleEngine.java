package io.just.sast.config;

import io.just.sast.analysis.hierarchy.ClassHierarchy;
import io.just.sast.cpg.graph.Node;

import java.lang.reflect.Modifier;
import java.util.HashMap;
import java.util.Map;
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
        this.rules = rules;
        this.hierarchy = hierarchy;
    }

    public Optional<Rule.SinkRule> matchingSink(Node call) {
        return matchingSink(call.strProp("owner"), call.strProp("name"), call.strProp("desc"));
    }

    /** 精确匹配 + 层次命中（调用点 owner 为规则 owner 子类型/实现类时命中）。 */
    public Optional<Rule.SinkRule> matchingSink(String owner, String name, String desc) {
        String cacheKey = owner + "|" + name + "|" + desc;
        return sinkCache.computeIfAbsent(cacheKey, k -> {
            for (Rule.SinkRule rule : rules.sinks()) {
                if (matchesCall(rule.call(), owner, name, desc)) {
                    return Optional.of(rule);
                }
            }
            return Optional.empty();
        });
    }

    /** 匹配 magic-entry 规则（含 implementsType 层次校验与 privateOnly 过滤）。 */
    public Optional<Rule.MagicEntryRule> matchingEntry(String owner, String name, String desc) {
        String cacheKey = owner + "|" + name + "|" + desc;
        return entryCache.computeIfAbsent(cacheKey, k -> {
            for (Rule.MagicEntryRule rule : rules.magicEntries()) {
                if (!rule.method().matches(name, desc)) {
                    continue;
                }
                if (rule.method().privateOnly() && !isPrivate(owner, name, desc)) {
                    continue;
                }
                if (rule.implementsType() == null || hierarchy.isSubtypeOf(owner, rule.implementsType())) {
                    return Optional.of(rule);
                }
            }
            return Optional.empty();
        });
    }

    /** 匹配 source 规则（框架桥接用，层次命中）。 */
    public Optional<Rule.SourceRule> matchingSource(String owner, String name, String desc) {
        String cacheKey = owner + "|" + name + "|" + desc;
        return sourceCache.computeIfAbsent(cacheKey, k -> {
            for (Rule.SourceRule rule : rules.sources()) {
                if (matchesCall(rule.call(), owner, name, desc)) {
                    return Optional.of(rule);
                }
            }
            return Optional.empty();
        });
    }

    /** 匹配 model 规则（层次命中），供污点引擎消费。 */
    public Optional<Rule.ModelRule> matchingModel(String owner, String name, String desc) {
        String cacheKey = owner + "|" + name + "|" + desc;
        return modelCache.computeIfAbsent(cacheKey, k -> {
            for (Rule.ModelRule rule : rules.models()) {
                if (matchesCall(rule.call(), owner, name, desc)) {
                    return Optional.of(rule);
                }
            }
            return Optional.empty();
        });
    }

    /** 精确 owner 命中，或 owner 为字面量类型名时层次命中（子类型/实现类调用点）。 */
    private boolean matchesCall(Rule.CallMatcher call, String owner, String name, String desc) {
        if (call.matches(owner, name, desc)) {
            return true;
        }
        String ownerType = call.ownerType();
        return ownerType != null && call.matchesRest(name, desc) && hierarchy.isSubtypeOf(owner, ownerType);
    }

    private boolean isPrivate(String owner, String name, String desc) {
        ClassHierarchy h = hierarchy;
        var cls = h.classInfo(owner);
        var method = cls != null ? cls.method(name, desc) : null;
        return method != null && Modifier.isPrivate(method.access());
    }
}
