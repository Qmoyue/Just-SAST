package io.just.sast.config;

import java.util.List;

/** 编译后的规则集。 */
public record RuleSet(List<Rule.SinkRule> sinks, List<Rule.MagicEntryRule> magicEntries,
                      List<Rule.SourceRule> sources, List<Rule.ModelRule> models,
                      List<Rule.FragmentRule> fragments) {

    public static final RuleSet EMPTY = new RuleSet(List.of(), List.of(), List.of(), List.of(), List.of());
}
