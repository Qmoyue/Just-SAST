package io.just.sast.config;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** 编译后的规则集。 */
public record RuleSet(List<Rule.SinkRule> sinks, List<Rule.MagicEntryRule> magicEntries,
                      List<Rule.SourceRule> sources, List<Rule.ModelRule> models,
                      List<Rule.FragmentRule> fragments) {

    public RuleSet {
        sinks = sinks == null ? List.of() : List.copyOf(sinks);
        magicEntries = magicEntries == null ? List.of() : List.copyOf(magicEntries);
        sources = sources == null ? List.of() : List.copyOf(sources);
        models = models == null ? List.of() : List.copyOf(models);
        fragments = fragments == null ? List.of() : List.copyOf(fragments);
    }

    /** A non-fatal rule quality finding; loading remains strict for structural errors. */
    public record LintIssue(String code, String ruleId, String message) {
    }

    /**
     * Check direct-constructor rule sets as well as YAML-loaded sets. The loader rejects
     * malformed types, while this pass catches maintainability hazards that are legal YAML:
     * exact overlaps, broad regexes, missing descriptors and invalid semantic positions.
     * Callers may surface these as warnings or fail a CI rule-lint job; scanning does not
     * silently change matching semantics because of a warning.
     */
    public List<LintIssue> lint() {
        List<LintIssue> issues = new ArrayList<>();
        Map<String, String> ids = new HashMap<>();
        for (Rule.SinkRule rule : sinks) {
            checkId(rule, ids, issues);
            checkCall(rule.id(), rule.call(), issues);
            checkSink(rule, issues);
        }
        for (Rule.MagicEntryRule rule : magicEntries) {
            checkId(rule, ids, issues);
            if (rule.entryKind() == null || rule.entryKind().isBlank()) {
                issues.add(issue("ENTRY_KIND_MISSING", rule.id(), "entryKind is blank"));
            }
            if (rule.method() == null) {
                issues.add(issue("METHOD_MATCH_MISSING", rule.id(), "method matcher is null"));
            } else {
                checkMatch("entry.name", rule.id(), rule.method().name(), false, issues);
                checkDescriptor("entry.descriptor", rule.id(), rule.method().descriptor(), issues);
            }
            if (rule.direction() == null || (!rule.direction().equals("deserialize")
                    && !rule.direction().equals("serialize")
                    && !rule.direction().equals("lifecycle"))) {
                issues.add(issue("ENTRY_DIRECTION_INVALID", rule.id(),
                        "direction must be deserialize/serialize/lifecycle"));
            }
        }
        for (Rule.SourceRule rule : sources) {
            checkId(rule, ids, issues);
            checkCall(rule.id(), rule.call(), issues);
            if (rule.bridge() == null || (!rule.bridge().equalsIgnoreCase("serialize")
                    && !rule.bridge().equalsIgnoreCase("deserialize"))) {
                issues.add(issue("SOURCE_BRIDGE_INVALID", rule.id(),
                        "bridge must be serialize or deserialize"));
            }
            checkSource(rule, issues);
        }
        for (Rule.ModelRule rule : models) {
            checkId(rule, ids, issues);
            checkCall(rule.id(), rule.call(), issues);
            checkModel(rule, issues);
        }
        for (Rule.FragmentRule rule : fragments) {
            checkId(rule, ids, issues);
            if (blank(rule.entryClass()) || blank(rule.entryKind()) || blank(rule.sinkOwner())
                    || blank(rule.sinkName()) || rule.hops() == null || rule.hops().isEmpty()) {
                issues.add(issue("FRAGMENT_SHAPE_INVALID", rule.id(),
                        "entry, sink and at least one hop are required"));
            }
            if (!blank(rule.sinkDescriptor()) && (!rule.sinkDescriptor().startsWith("(")
                    || !rule.sinkDescriptor().contains(")"))) {
                issues.add(issue("DESCRIPTOR_INVALID", rule.id(),
                        "fragment.sinkDescriptor is not a JVM method descriptor"));
            }
        }
        checkExactOverlaps("sink", sinks.stream().map(Rule.SinkRule::id).toList(),
                sinks.stream().map(Rule.SinkRule::call).toList(), issues);
        checkExactOverlaps("source", sources.stream().map(Rule.SourceRule::id).toList(),
                sources.stream().map(Rule.SourceRule::call).toList(), issues);
        checkExactOverlaps("model", models.stream().map(Rule.ModelRule::id).toList(),
                models.stream().map(Rule.ModelRule::call).toList(), issues);
        return List.copyOf(issues);
    }

    private static void checkId(Rule rule, Map<String, String> ids, List<LintIssue> issues) {
        if (rule == null || blank(rule.id())) {
            issues.add(issue("RULE_ID_MISSING", "", "rule id is blank"));
            return;
        }
        String previous = ids.putIfAbsent(rule.id(), rule.id());
        if (previous != null) {
            issues.add(issue("RULE_ID_DUPLICATE", rule.id(), "rule id appears more than once"));
        }
    }

    private static void checkCall(String id, Rule.CallMatcher call, List<LintIssue> issues) {
        if (call == null) {
            issues.add(issue("CALL_MATCH_MISSING", id, "call matcher is null"));
            return;
        }
        checkMatch("call.owner", id, call.owner(), false, issues);
        checkMatch("call.name", id, call.name(), false, issues);
        checkDescriptor("call.descriptor", id, call.descriptor(), issues);
    }

    private static void checkSink(Rule.SinkRule rule, List<LintIssue> issues) {
        if (blank(rule.category()) || !rule.category().matches("[A-Za-z][A-Za-z0-9_]{1,63}")) {
            issues.add(issue("SINK_CATEGORY_INVALID", rule.id(), "category must be a short identifier"));
        }
        if (blank(rule.severity()) || !Set.of("LOW", "MEDIUM", "HIGH", "CRITICAL")
                .contains(rule.severity().toUpperCase(java.util.Locale.ROOT))) {
            issues.add(issue("SINK_SEVERITY_INVALID", rule.id(),
                    "severity must be LOW/MEDIUM/HIGH/CRITICAL"));
        }
        if (rule.tainted() == null || rule.tainted().isEmpty()) {
            issues.add(issue("SINK_TAINTED_MISSING", rule.id(), "at least one tainted position is required"));
            return;
        }
        Set<String> positions = new HashSet<>();
        for (Rule.TaintedPos position : rule.tainted()) {
            String key;
            if (position instanceof Rule.TaintedPos.Arg arg) {
                if (arg.index() < 0) {
                    issues.add(issue("SINK_TAINTED_INDEX_INVALID", rule.id(),
                            "argument index must be non-negative"));
                }
                key = "arg" + arg.index();
            } else if (position instanceof Rule.TaintedPos.Receiver) {
                key = "receiver";
            } else {
                key = String.valueOf(position);
            }
            if (!positions.add(key)) {
                issues.add(issue("SINK_TAINTED_DUPLICATE", rule.id(),
                        "tainted position appears more than once: " + key));
            }
        }
    }

    private static void checkSource(Rule.SourceRule rule, List<LintIssue> issues) {
        if (rule.tainted() == null) {
            issues.add(issue("SOURCE_TAINTED_NULL", rule.id(),
                    "source tainted positions must be non-null; use an empty list for an unconditional source"));
            return;
        }
        Set<String> positions = new HashSet<>();
        for (Rule.TaintedPos position : rule.tainted()) {
            String key;
            if (position instanceof Rule.TaintedPos.Arg arg) {
                if (arg.index() < 0) {
                    issues.add(issue("SOURCE_TAINTED_INDEX_INVALID", rule.id(),
                            "argument index must be non-negative"));
                }
                key = "arg" + arg.index();
            } else if (position instanceof Rule.TaintedPos.Receiver) {
                key = "receiver";
            } else {
                key = String.valueOf(position);
            }
            if (!positions.add(key)) {
                issues.add(issue("SOURCE_TAINTED_DUPLICATE", rule.id(),
                        "tainted position appears more than once: " + key));
            }
        }
    }

    private static void checkModel(Rule.ModelRule rule, List<LintIssue> issues) {
        if (rule.actions() == null || rule.actions().isEmpty()) {
            issues.add(issue("MODEL_ACTIONS_MISSING", rule.id(), "actions must not be empty"));
            return;
        }
        for (Map.Entry<String, List<String>> entry : rule.actions().entrySet()) {
            if (!("this".equals(entry.getKey()) || "return".equals(entry.getKey()))) {
                issues.add(issue("MODEL_TARGET_INVALID", rule.id(), "target must be this or return"));
            }
            if (entry.getValue() == null || entry.getValue().isEmpty()) {
                issues.add(issue("MODEL_SOURCES_MISSING", rule.id(), "action sources must not be empty"));
            } else {
                for (String source : entry.getValue()) {
                    if (!ModelSource.isValid(source)) {
                        issues.add(issue("MODEL_SOURCE_INVALID", rule.id(),
                                "source must be this, argN, or element(this/argN)"));
                    }
                }
            }
        }
    }

    private static void checkMatch(String label, String id, Match match, boolean allowNull,
                                   List<LintIssue> issues) {
        if (match == null) {
            if (!allowNull) {
                issues.add(issue("MATCH_MISSING", id, label + " is null"));
            }
        } else if (blank(match.pattern())) {
            issues.add(issue("MATCH_BLANK", id, label + " is blank"));
        } else if (match.isRegex()) {
            String regex = match.pattern().substring(1).trim();
            if (match.pattern().length() > 256 || ".*".equals(regex) || ".+".equals(regex)
                    || "[^/]+".equals(regex)) {
                issues.add(issue("MATCH_TOO_BROAD", id,
                        label + " regex is too broad for an auditable rule"));
            }
        }
    }

    private static void checkDescriptor(String label, String id, Match descriptor,
                                        List<LintIssue> issues) {
        if (descriptor == null) {
            return;
        }
        checkMatch(label, id, descriptor, true, issues);
        if (!descriptor.isRegex() && !blank(descriptor.pattern())
                && (!descriptor.pattern().startsWith("(") || !descriptor.pattern().contains(")"))) {
            issues.add(issue("DESCRIPTOR_INVALID", id, label + " is not a JVM method descriptor"));
        }
    }

    private static void checkExactOverlaps(String kind, List<String> ids,
                                           List<Rule.CallMatcher> calls,
                                           List<LintIssue> issues) {
        Map<String, String> seen = new HashMap<>();
        for (int i = 0; i < calls.size(); i++) {
            Rule.CallMatcher call = calls.get(i);
            if (call == null || call.owner() == null || call.name() == null
                    || call.owner().isRegex() || call.name().isRegex()
                    || (call.descriptor() != null && call.descriptor().isRegex())) {
                continue;
            }
            String key = call.owner().pattern() + "#" + call.name().pattern() + "#"
                    + (call.descriptor() == null ? "*" : call.descriptor().pattern());
            String previous = seen.putIfAbsent(key, ids.get(i));
            if (previous != null && !previous.equals(ids.get(i))) {
                issues.add(issue("EXACT_OVERLAP", ids.get(i),
                        kind + " call matcher overlaps " + previous + ": " + key));
            }
        }
    }

    private static boolean blank(String value) {
        return value == null || value.isBlank();
    }

    private static LintIssue issue(String code, String id, String message) {
        return new LintIssue(code, id == null ? "" : id, message);
    }

    public static final RuleSet EMPTY = new RuleSet(List.of(), List.of(), List.of(), List.of(), List.of());
}
