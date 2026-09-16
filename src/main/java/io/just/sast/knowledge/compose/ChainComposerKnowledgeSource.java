package io.just.sast.knowledge.compose;

import io.just.sast.blackboard.Blackboard;
import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.Event;
import io.just.sast.blackboard.EventType;
import io.just.sast.blackboard.HopKind;
import io.just.sast.blackboard.KnowledgeSource;
import io.just.sast.blackboard.Phase;
import io.just.sast.blackboard.RunProduct;
import io.just.sast.analysis.entry.ApplicationEntryIndex;
import io.just.sast.config.Rule;
import io.just.sast.config.RuleSchemaV2;
import io.just.sast.run.InputBudget;
import io.just.sast.util.ArchiveLimits;
import io.just.sast.util.ChainMaterializer;
import io.just.sast.util.JustLogger;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Enumeration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Supplier;
import java.util.zip.ZipFile;

/**
 * 语义链组装（COMPOSITION 阶段）。
 * 将不同引擎产出的完整链通过**语义桥接**组装成多级完整攻击路径。
 *
 * 四种桥接（均为语义级，非调用图相邻）：
 * 1. INVOKE 桥：前段链 sink = Method.invoke → 可调用后段链 entry 的任意公共方法
 * 2. TRIGGER 桥：前段链路径含 HashMap/HashSet/Hashtable → 反序列化时调 key.hashCode/toString → 触发后段
 * 3. TEMPLATE 桥：前段链路径含 TemplatesImpl → 后段 entry 触发 getOutputProperties/newTransformer
 * 4. DESER 桥：前段 sink 为二次反序列化（DESERIALIZE 类别，SignedObject.getObject /
 *    SerializationUtils.deserialize 等）→ 前段产物字节流再被反序列化，触发后段机制入口
 *
 * 不在调用图上找相邻方法（结构级），而是验证前段 sink 能否**语义上**触发后段 entry
 * （Method.invoke 可调任意公共方法、HashMap 反序列化调 hashCode、TemplatesImpl 的 getter
 * 加载字节码、SignedObject 模式的嵌套反序列化）。
 */
public final class ChainComposerKnowledgeSource implements KnowledgeSource {

    private static final int MAX_COMPOSED = 400;
    /**
     * Reserve a small, deterministic frontier for application-rooted multi-segment
     * composition before the broad compatibility pass.  A single raw sink can otherwise
     * consume the entire global cap and leave a second-deserialization bridge invisible.
     */
    private static final int MAX_APPLICATION_PRIORITY_COMPOSED = 256;
    private static final int MAX_APPLICATION_PRIORITY_OVERLAP = 128;
    private static final int MAX_APPLICATION_PRIORITY_FRONTS = 64;
    private static final int MAX_APPLICATION_PRIORITY_BACKS = 32;
    private static final int MAX_APPLICATION_COMPOSITION_DEPTH = 3;
    /**
     * A composed path contains both semantic bridge hops and the concrete front/back traces.
     * The old bound of 16 discarded otherwise bounded application chains as soon as a
     * deserializer prefix was joined to a normal 8–12-hop gadget.  Keep the path finite, but
     * leave room for the full typed prefix/suffix rather than silently dropping the terminal.
     */
    private static final int MAX_HOPS = 64;
    private static final int MAX_SOURCE_HOSTS = 1000;

    /**
     * A source host gets one deterministic candidate per round.  The old nested attempt
     * loop retried the same host/candidate product after every rejected or duplicate pair,
     * which made a large dependency graph spend minutes in an effectively quadratic scan.
     * The bound is deliberately tied to the existing composition budget, not exposed as a
     * target-specific tuning knob.
     */
    private static final int MAX_SOURCE_ROUNDS = MAX_COMPOSED;

    /** 哈希触发容器：其反序列化机制以元素/键回调 hashCode/equals/compareTo。 */
    private static final Set<String> TRIGGER_CONTAINERS = Set.of(
            "java/util/Map", "java/util/Collection", "java/util/Set", "java/util/List",
            "java/util/HashMap", "java/util/HashSet", "java/util/Hashtable",
            "java/util/LinkedHashMap", "java/util/LinkedHashSet",
            "java/util/TreeMap", "java/util/TreeSet", "java/util/concurrent/PriorityQueue");
    private static final List<String> PUBLIC_ENTRY_KINDS = List.of(
            "readObject", "readResolve", "readObjectNoData", "readExternal",
            "hashCode", "equals", "compareTo", "compare", "toString",
            "proxyInvoke", "validateObject", "secondDeserialization");
    private static final Set<String> SERIALIZATION_CALLBACK_ENTRY_KINDS = Set.of(
            "readObject", "readResolve", "readObjectNoData", "readExternal", "validateObject");
    private static final List<String> TRIGGER_ENTRY_KINDS = List.of(
            "hashCode", "equals", "compareTo", "compare", "toString");
    /** 桥接类型。 */
    enum Bridge { INVOKE, TRIGGER, TEMPLATE, DESER, JNDI_RMI, JDBC_XML }

    private record DeserHost(String owner, String method, String descriptor,
                             String frameOwner, String frameMethod, String frameDescriptor) {
    }

    /** Build-local key for the immutable terminal-admission cache. */
    private record TerminalAdmissionKey(String owner, String name, String descriptor) {
    }

    /** Build-local key for typed continuation rule/endpoint lookup. */
    private record ContinuationAdmissionKey(String ruleId, String owner, String name,
                                            String descriptor) {
    }

    private record FrontFeatures(boolean invoke, String triggerContainer,
                                 boolean template, boolean deserialize, boolean jndiRmi,
                                 boolean jdbc) {
    }

    @Override
    public String id() {
        return "chain-composer";
    }

    @Override
    public Set<EventType> interests() {
        return Set.of(EventType.SCAN_ANALYZED);
    }

    @Override
    public Phase phase() {
        return Phase.COMPOSITION;
    }

    @Override
    public int priority() {
        return 200;
    }

    @Override
    public Set<RunProduct> requiresProducts() {
        return Set.of(RunProduct.ANALYSIS_CHAINS, RunProduct.COMPOSED_CHAINS);
    }

    @Override
    public Set<RunProduct> providesProducts() {
        return Set.of(RunProduct.COMPOSED_CHAINS);
    }

    @Override
    public void init(Blackboard blackboard) {
        // Composition is event-owned; all semantic reads use the Blackboard supplied to
        // onEvent so one source instance cannot retain scope/rules from another run.
    }

    private int applicationFrontPriority(Blackboard target, Chain chain) {
        if (target == null || chain == null || target.applicationEntryIndex() == null) {
            return 0;
        }
        String descriptor = entryDescriptor(chain);
        String key = chain.entryClass() + "#" + chain.entryMethod() + descriptor;
        var index = target.applicationEntryIndex();
        int score = index.isApplicationEntryMethod(key) ? 1_000 : 0;
        if (index.isExternalEntryMethod(key)) {
            score += 4_096;
        }
        if (index.routeBindingsFor(key).stream()
                .anyMatch(binding -> binding != null && binding.externalControlProven())) {
            score += 8_192;
        } else if (!index.routeBindingsFor(key).isEmpty()) {
            score += 4_096;
        }
        if (!index.serviceEndpointsFor(key).isEmpty()) {
            score += 2_048;
        }
        if (index.isApplicationOwner(chain.entryClass())) {
            score += 64;
        }
        // A typed nested-deserialization endpoint is the next composition frontier.  Keep one
        // such application prefix ahead of ordinary source-host variants so its deserialized
        // object can still request the bounded terminal-suffix pass.  The predicate uses the
        // protocol endpoint and explicit fragment activation marker; it does not name a gadget
        // or benchmark class.
        if (isTypedNestedDeserializationFront(chain)) {
            score += 1_024;
        }
        if ("source".equals(chain.entryKind()) || "deserialize".equals(chain.entryKind())) {
            score += 16;
        }
        // A capability is a continuation frontier, not a completed product.  When several
        // source-host variants share one application root, selecting a terminal variant first
        // can consume the one-per-root slot and hide the capability that still needs an
        // INVOKE/DESER bridge.  Keep continuation endpoints ahead of terminal variants while
        // retaining deterministic ordering among endpoints of the same semantic kind.
        if ("CAPABILITY".equalsIgnoreCase(chain.sinkRole())) {
            score += 2_048;
        }
        if (chain.unresolvedHops() == 0) {
            score += 4;
        }
        return score;
    }

    private static int terminalBackPriority(Chain chain) {
        if (chain == null) {
            return 0;
        }
        int score = chain.terminalSink() ? 1_000 : 0;
        if ("TERMINAL".equalsIgnoreCase(chain.sinkRole())) {
            score += 256;
        }
        if (chain.unresolvedHops() == 0) {
            score += 32;
        }
        score += switch (chain.severity() == null ? "" : chain.severity()) {
            case "CRITICAL" -> 16;
            case "HIGH" -> 8;
            case "MEDIUM" -> 2;
            default -> 0;
        };
        // Shorter terminal suffixes are easier to join within the finite hop budget.  The
        // stable key tie-break below still preserves deterministic ordering among equals.
        return score - Math.min(128, chain.hops().size());
    }

    @Override
    public void onEvent(Blackboard bb, Event event) {
        if (event.type() != EventType.SCAN_ANALYZED) {
            return;
        }
        boolean applicationScoped = defaultApplicationCompositionScope(bb);
        Blackboard.CompositionInputs initialInputs = bb.compositionInputsLazy();
        Map<TerminalAdmissionKey, ApplicationEntryIndex.TerminalDecision> terminalAdmissionCache =
                new HashMap<>();
        Map<ContinuationAdmissionKey, Boolean> continuationAdmissionCache = new HashMap<>();
        Map<String, FrontFeatures> frontFeaturesCache = new HashMap<>();
        // A known application scope has typed frontiers for every demand-driven pass; only
        // the legacy/unknown-scope path needs the broad compatibility union.  Avoid building
        // that union merely to derive the finite-input guard below.
        List<Chain> compatibilityInputs = applicationScoped ? List.of()
                : initialInputs.compatibilityAll();
        List<Chain> chains = new ArrayList<>(applicationScoped
                ? applicationFrontInputs(initialInputs) : compatibilityInputs);
        // The composition budget is a semantic safety bound, not a product top-k.  Spend its
        // first slots on chains that already have an application execution root so a dependency
        // gadget cannot exhaust the frontier before the application prefix is joined.  The
        // score is derived solely from the typed application index and chain shape; it never
        // inspects benchmark names, fixture classes or expected answers.
        chains.sort(java.util.Comparator
                .comparingInt((Chain chain) -> applicationFrontPriority(bb, chain)).reversed()
                .thenComparing(Chain::key));
        int initialCompositionCount = applicationScoped
                ? distinctCompositionInputCount(initialInputs) : compatibilityInputs.size();
        if (initialCompositionCount < 2) {
            return;
        }
        // In a known application scope, the default product is demand-driven at the
        // composition boundary itself: only an application-owned execution prefix may spend
        // the front budget, and only a public dependency suffix with a typed indexed terminal
        // may spend the back budget.  The raw chain store remains available to the explicit
        // gadget-kernel/compatibility path and to the application-hosted bridge pass below;
        // default composition must not materialize dependency-only fronts and then hope the
        // report boundary removes them later.
        List<Chain> defaultFronts = applicationScoped
                ? chains.stream().filter(chain -> isApplicationFront(bb, chain)).toList() : chains;
        boolean initialBackDemand = !applicationScoped
                || hasApplicationBackDemand(bb, defaultFronts, frontFeaturesCache);
        List<Chain> defaultBackCandidates = applicationScoped
                ? defaultSuffixCandidates(bb, initialInputs, terminalAdmissionCache,
                        continuationAdmissionCache, initialBackDemand)
                : chains;
        List<Chain> publicEntries = defaultBackCandidates.stream()
                .filter(chain -> isPublicEntry(chain) || isDeclaredDirectFragment(chain))
                .sorted(java.util.Comparator
                        .comparingInt((Chain chain) -> terminalBackPriority(chain)).reversed()
                        .thenComparing(Chain::key))
                .toList();
        List<Chain> triggerEntries = defaultBackCandidates.stream()
                .filter(chain -> isTriggerEntry(chain.entryKind()))
                .toList();
        List<Chain> templateEntries = defaultBackCandidates.stream()
                .filter(chain -> isTemplateTrigger(chain.entryMethod()))
                .toList();
        List<Chain> fragmentEntries = defaultBackCandidates.stream()
                .filter(ChainComposerKnowledgeSource::isDeclaredFragment)
                .toList();
        JustLogger.info("链组装候选：原始 {}，默认前缀 {}，terminal 后缀 {}，公共入口 {}，触发入口 {}，模板入口 {}",
                chains.size(), defaultFronts.size(), defaultBackCandidates.size(),
                publicEntries.size(), triggerEntries.size(), templateEntries.size());

        int composed = composeApplicationPriority(bb, defaultFronts, publicEntries,
                fragmentEntries, frontFeaturesCache);
        for (Chain front : defaultFronts) {
            if (composed >= MAX_COMPOSED) {
                bb.markIncomplete("COMPOSITION_CHAIN_CAP:" + MAX_COMPOSED);
                break;
            }
            FrontFeatures features = frontFeaturesCached(bb, front, frontFeaturesCache);
            if (!features.invoke() && features.triggerContainer() == null
                    && !features.template() && !features.deserialize() && !features.jndiRmi()
                    && !features.jdbc()) {
                continue;
            }
            // Only inspect chains that can satisfy at least one bridge precondition.  This
            // preserves the old semanticBridge checks while avoiding the full chain×chain
            // product for ordinary, non-bridgeable candidates.
            List<Chain> candidates = candidateBacks(features, publicEntries,
                    triggerEntries, templateEntries, fragmentEntries);
            for (Chain back : candidates) {
                if (composed >= MAX_COMPOSED || front == back) {
                    continue;
                }
                Bridge bridge = semanticBridge(bb, features, front, back);
                if (bridge == null) {
                    continue;
                }
                // 防环：back 的 entry 不在 front 的路径上
                if (onPath(front, back.entryClass())) {
                    continue;
                }
                Chain merged = admitComposed(bb, composedProducer(front, back, bridge));
                if (merged != null) {
                    composed++;
                }
            }
        }
        Blackboard.CompositionInputs sourceInputs = bb.compositionInputsLazy();
        int sourceCompositionCount = distinctCompositionInputCount(sourceInputs);
        JustLogger.info("链组装语义阶段完成：产链 {}，默认链 {}，组合输入 {}", composed,
                bb.chains().size(), sourceCompositionCount);
        // 源宿主桥使用含本轮 INVOKE/DESER 合成链的新快照——完整链（多段桥接产物）也能再挂源宿主；
        // 图不可用（最小夹具）时宿主扫描无从进行，跳过该桥
        int sourceComposed = bb.graph() != null
                ? composeSourceHosted(bb, sourceInputs) : 0;
        // Source-hosted chains are discovered by the same composition phase and therefore
        // were not present in the first application-priority snapshot.  Re-admit the fresh
        // snapshot once so an application-owned OIS/framework host can continue through the
        // exact callback overlap to a secondary deserializer and its terminal suffix.  The
        // pass has the same finite frontier and deterministic root grouping; it is not an
        // unbounded fixed-point loop.
        int postSourceApplication = 0;
        if (bb.graph() != null && sourceComposed > 0) {
            Blackboard.CompositionInputs refreshedInputs = bb.compositionInputsLazy();
            List<Chain> refreshed = applicationScoped
                    ? applicationFrontInputs(refreshedInputs) : refreshedInputs.compatibilityAll();
            // Keep the same direct-add compatibility boundary as the initial pass.  Solver
            // suffixes normally live in the typed continuation stores, while older callers may
            // still publish a dependency suffix through addChain before this follow-up round.
            List<Chain> refreshedBacks = applicationScoped
                    ? defaultSuffixCandidates(bb, refreshedInputs, terminalAdmissionCache,
                            continuationAdmissionCache,
                            hasApplicationBackDemand(bb, refreshed, frontFeaturesCache)) : refreshed;
            List<Chain> refreshedPublicEntries = refreshedBacks.stream()
                    .filter(chain -> isPublicEntry(chain) || isDeclaredDirectFragment(chain))
                    .sorted(java.util.Comparator
                            .comparingInt((Chain chain) -> terminalBackPriority(chain)).reversed()
                            .thenComparing(Chain::key))
                    .toList();
            List<Chain> refreshedFragmentEntries = refreshedBacks.stream()
                    .filter(ChainComposerKnowledgeSource::isDeclaredFragment)
                    .toList();
            postSourceApplication = composeApplicationPriority(bb, refreshed,
                    refreshedPublicEntries, refreshedFragmentEntries, frontFeaturesCache);
        }
        JustLogger.info("链组装：语义桥接产链 {} 条（源宿主容器触发 {} 条，源宿主后应用续接 {} 条）",
                composed, sourceComposed, postSourceApplication);
    }

    private boolean defaultApplicationCompositionScope(Blackboard target) {
        return target != null && target.applicationEntryIndex() != null
                && target.applicationEntryIndex().applicationScopeKnown();
    }

    /**
     * Project the two stores that can own an application prefix without materializing the
     * dependency suffix store.  A capability that still needs an INVOKE/DESER bridge is a
     * legitimate application frontier even when the solver keeps it in the bridge store; the
     * final {@link #isApplicationFront(Blackboard, Chain)} admission still rejects dependency
     * owners and unreachable helpers.
     */
    private List<Chain> applicationFrontInputs(Blackboard.CompositionInputs inputs) {
        if (inputs == null) {
            return List.of();
        }
        Map<String, Chain> unique = new java.util.TreeMap<>();
        if (inputs.applicationChains() != null) {
            inputs.applicationChains().forEach(chain -> unique.putIfAbsent(chain.key(), chain));
        }
        if (inputs.bridgeContinuations() != null) {
            inputs.bridgeContinuations().forEach(chain -> unique.putIfAbsent(chain.key(), chain));
        }
        return List.copyOf(unique.values());
    }

    /** Avoid materializing any deferred suffix when the current application frontier has no
     * typed bridge capability that could consume a back.  Source-host trigger demand is handled
     * separately after this pass and may still request trigger endpoints. */
    private boolean hasApplicationBackDemand(Blackboard target, List<Chain> fronts,
                                             Map<String, FrontFeatures> frontFeaturesCache) {
        if (target == null || fronts == null || fronts.isEmpty()) {
            return false;
        }
        for (Chain front : fronts) {
            FrontFeatures features = frontFeaturesCached(target, front, frontFeaturesCache);
            if (features.invoke() || features.deserialize() || features.triggerContainer() != null
                    || features.template() || features.jndiRmi() || features.jdbc()) {
                return true;
            }
        }
        return false;
    }

    /**
     * Application-first composition pass.  This is deliberately a semantic frontier rather
     * than a benchmark fixture: application execution roots are selected from the typed
     * application index, terminal backs are ordered by rule role/category, and each root gets
     * a bounded number of independent suffix families.  Newly composed DESER chains are fed
     * through one more bounded round so a Method.invoke → ObjectUtil.deserialize prefix can
     * continue to the actual terminal (for example TemplatesImpl) instead of stopping at the
     * first capability/bridge.  The broad pass below still runs for compatibility and kernel
     * callers; this pass only reserves coverage for roots that would otherwise be starved by
     * the global composition cap.
     */
    private int composeApplicationPriority(Blackboard target, List<Chain> chains,
                                           List<Chain> publicEntries,
                                           List<Chain> fragmentEntries,
                                           Map<String, FrontFeatures> frontFeaturesCache) {
        if (chains == null || chains.isEmpty() || publicEntries == null || publicEntries.isEmpty()) {
            return 0;
        }
        List<Chain> eligibleFronts = chains.stream()
                .filter(chain -> isApplicationFront(target, chain))
                .filter(chain -> {
                    FrontFeatures features = frontFeaturesCached(target, chain, frontFeaturesCache);
                    return features.invoke() || features.deserialize()
                            || features.triggerContainer() != null
                            || features.template() || features.jndiRmi() || features.jdbc();
                })
                .sorted(java.util.Comparator
                        .comparingInt((Chain chain) -> frontBridgePriority(
                                frontFeaturesCached(target, chain, frontFeaturesCache)))
                        .reversed()
                        .thenComparing(java.util.Comparator
                                .comparingInt((Chain chain) -> applicationFrontPriority(target, chain))
                                .reversed())
                        .thenComparing(Chain::key))
                .toList();
        List<Chain> fronts = selectApplicationFronts(target, eligibleFronts, frontFeaturesCache);
        if (fronts.isEmpty()) {
            return 0;
        }
        long eligibleExternal = eligibleFronts.stream()
                .filter(chain -> hasExternalBoundary(target, chain)).count();
        long selectedExternal = fronts.stream()
                .filter(chain -> hasExternalBoundary(target, chain)).count();
        long eligibleDeserializeCapability = eligibleFronts.stream()
                .filter(ChainComposerKnowledgeSource::isDeserializationCapability).count();
        long selectedDeserializeCapability = fronts.stream()
                .filter(ChainComposerKnowledgeSource::isDeserializationCapability).count();
        long selectedExternalDeserializeCapability = fronts.stream()
                .filter(chain -> hasExternalBoundary(target, chain))
                .filter(ChainComposerKnowledgeSource::isDeserializationCapability).count();
        JustLogger.info("链组装应用边界前缀：候选外部 {}，有限前沿外部 {}（候选 {}，前沿 {}），"
                        + "反序列化能力候选 {}，前沿 {}，外部前沿 {}",
                eligibleExternal, selectedExternal, eligibleFronts.size(), fronts.size(),
                eligibleDeserializeCapability, selectedDeserializeCapability,
                selectedExternalDeserializeCapability);
        Set<Chain> allBacks = new LinkedHashSet<>();
        if (publicEntries != null) {
            allBacks.addAll(publicEntries);
        }
        if (fragmentEntries != null) {
            allBacks.addAll(fragmentEntries);
        }
        List<Chain> backs = allBacks.stream()
                .sorted(java.util.Comparator
                        .comparingInt((Chain chain) -> applicationBackPriority(chain)).reversed()
                        .thenComparing(Chain::key))
                .limit(MAX_APPLICATION_PRIORITY_BACKS)
                .toList();
        List<Chain> overlapBacks = backs.stream()
                .filter(chain -> isSecondaryDeserializationBack(target, chain))
                .toList();
        long secondaryBacks = backs.stream()
                .filter(chain -> isDeclaredSecondaryDeserializationFragment(chain)).count();
        JustLogger.info("链组装二次反序列化后缀：候选 {}，有限后缀 {}，重叠后缀 {}",
                publicEntries.stream().filter(chain ->
                        isDeclaredSecondaryDeserializationFragment(chain)).count(),
                secondaryBacks, overlapBacks.size());
        int composed = 0;
        Set<String> seenFrontDepth = new HashSet<>();
        List<ComposedDepth> frontier = new ArrayList<>();
        // A reflective capability can be the last observable sink of an application prefix
        // even though the same callback method is the entry of a dependency deserializer
        // suffix.  This is a typed overlap, not an arbitrary class-name join: both sides must
        // share the exact callback method, and the back side must be a public terminal
        // DESERIALIZE chain.  Schedule it before the ordinary INVOKE product so a noisy
        // capability frontier cannot starve the secondary-deserialization continuation.
        int overlapAdded = 0;
        for (int round = 0; round < overlapBacks.size()
                && composed < MAX_APPLICATION_PRIORITY_COMPOSED
                && overlapAdded < MAX_APPLICATION_PRIORITY_OVERLAP; round++) {
            for (int frontIndex = 0; frontIndex < fronts.size()
                    && composed < MAX_APPLICATION_PRIORITY_COMPOSED
                    && overlapAdded < MAX_APPLICATION_PRIORITY_OVERLAP; frontIndex++) {
                Chain front = fronts.get(frontIndex);
                Chain back = overlapBacks.get(Math.floorMod(round + frontIndex,
                        overlapBacks.size()));
                Chain merged = admitComposed(target,
                        composeIfOverlapping(target, front, back, seenFrontDepth));
                if (merged == null) {
                    continue;
                }
                composed++;
                overlapAdded++;
                frontier.add(new ComposedDepth(merged, 1));
            }
        }
        // Continue the overlap frontier before spending the remaining reserved slots on
        // unrelated one-step capability products.  Otherwise a large Method.invoke family
        // can fill the finite cap and prevent ObjectUtil/SignedObject-style suffixes from
        // reaching their actual terminal sink.
        for (int depth = 1; depth < MAX_APPLICATION_COMPOSITION_DEPTH
                && !frontier.isEmpty() && composed < MAX_APPLICATION_PRIORITY_COMPOSED; depth++) {
            List<ComposedDepth> next = new ArrayList<>();
            for (ComposedDepth item : frontier) {
                if (item.depth() != depth || composed >= MAX_APPLICATION_PRIORITY_COMPOSED) {
                    continue;
                }
                FrontFeatures features = frontFeaturesCached(target, item.chain(),
                        frontFeaturesCache);
                if (!features.deserialize() && !features.invoke() && !features.jndiRmi()) {
                    continue;
                }
                for (Chain back : backs) {
                    if (composed >= MAX_APPLICATION_PRIORITY_COMPOSED) {
                        break;
                    }
                    Chain merged = admitComposed(target,
                            composeIfBridgeable(target, item.chain(), back, seenFrontDepth,
                                    frontFeaturesCache));
                    if (merged == null) {
                        continue;
                    }
                    composed++;
                    next.add(new ComposedDepth(merged, depth + 1));
                }
            }
            frontier = next;
        }
        // Round-robin roots, not back-first: one noisy root cannot exhaust the reserved
        // frontier before every application entry has a chance to acquire a suffix.  Leave a
        // bounded continuation reserve so a newly-created DESER capability can consume one
        // more typed suffix in the finite-depth pass below.
        int ordinaryCompositionLimit = Math.max(composed,
                MAX_APPLICATION_PRIORITY_COMPOSED - MAX_APPLICATION_PRIORITY_FRONTS);
        List<ComposedDepth> ordinaryFrontier = new ArrayList<>();
        for (int round = 0; round < backs.size() && composed < ordinaryCompositionLimit;
             round++) {
            for (int frontIndex = 0; frontIndex < fronts.size()
                    && composed < ordinaryCompositionLimit; frontIndex++) {
                Chain front = fronts.get(frontIndex);
                Chain back = backs.get(Math.floorMod(round + frontIndex, backs.size()));
                Chain merged = admitComposed(target,
                        composeIfBridgeable(target, front, back, seenFrontDepth,
                                frontFeaturesCache));
                if (merged == null) {
                    continue;
                }
                composed++;
                ordinaryFrontier.add(new ComposedDepth(merged, 1));
            }
        }
        // Ordinary bridge products are also typed frontiers.  Expand them after the reserved
        // one-step pass so a DESER front can consume a declared secondary-deserialization
        // capability and then a terminal suffix without reopening an unbounded fixed point.
        for (int depth = 1; depth < MAX_APPLICATION_COMPOSITION_DEPTH
                && !ordinaryFrontier.isEmpty()
                && composed < MAX_APPLICATION_PRIORITY_COMPOSED; depth++) {
            List<ComposedDepth> next = new ArrayList<>();
            for (ComposedDepth item : ordinaryFrontier) {
                if (item.depth() != depth || composed >= MAX_APPLICATION_PRIORITY_COMPOSED) {
                    continue;
                }
                FrontFeatures features = frontFeaturesCached(target, item.chain(),
                        frontFeaturesCache);
                if (!features.deserialize() && !features.invoke() && !features.jndiRmi()) {
                    continue;
                }
                for (Chain back : backs) {
                    if (composed >= MAX_APPLICATION_PRIORITY_COMPOSED) {
                        break;
                    }
                    Chain merged = admitComposed(target,
                            composeIfBridgeable(target, item.chain(), back, seenFrontDepth,
                                    frontFeaturesCache));
                    if (merged == null) {
                        continue;
                    }
                    composed++;
                    next.add(new ComposedDepth(merged, depth + 1));
                }
            }
            ordinaryFrontier = next;
        }
        return composed;
    }

    private boolean hasExternalBoundary(Blackboard target, Chain chain) {
        if (target == null || chain == null || target.applicationEntryIndex() == null) {
            return false;
        }
        String key = chain.entryClass() + "#" + chain.entryMethod() + entryDescriptor(chain);
        var index = target.applicationEntryIndex();
        return index.isExternalEntryMethod(key)
                || index.routeBindingsFor(key).stream()
                .anyMatch(binding -> binding != null && binding.externalControlProven())
                || !index.serviceEndpointsFor(key).isEmpty();
    }

    private static boolean isDeserializationCapability(Chain chain) {
        return chain != null && "DESERIALIZE".equalsIgnoreCase(chain.category())
                && "CAPABILITY".equalsIgnoreCase(chain.sinkRole());
    }

    /**
     * Select at most the bounded number of application prefixes while giving every distinct
     * execution root one representative before filling remaining slots with higher-quality
     * variants.  A chain count cap alone lets one controller or source host crowd out another
     * root, which is precisely how a generated source-hosted prefix can disappear from the
     * continuation pass.
     */
    private List<Chain> selectApplicationFronts(Blackboard target, List<Chain> eligible,
                                                Map<String, FrontFeatures> frontFeaturesCache) {
        if (eligible == null || eligible.isEmpty()) {
            return List.of();
        }
        List<Chain> selected = new ArrayList<>(Math.min(MAX_APPLICATION_PRIORITY_FRONTS,
                eligible.size()));
        // Preserve one representative for every typed bridge family before filling the
        // bounded frontier by root/quality order.  A high-volume INVOKE or DESER family must
        // not consume all reserved slots before a JDBC/JNDI continuation gets a chance to
        // meet its declarative suffix.  The family is a semantic capability axis, not an
        // artifact or rule-name special case.
        for (String family : List.of("jdbc", "jndi", "deserialize", "invoke", "template",
                "trigger")) {
            for (Chain chain : eligible) {
                if (!selected.contains(chain)
                        && supportsBridgeFamily(target, chain, family, frontFeaturesCache)) {
                    selected.add(chain);
                    break;
                }
            }
            if (selected.size() >= MAX_APPLICATION_PRIORITY_FRONTS) {
                break;
            }
        }
        Set<String> roots = new LinkedHashSet<>();
        for (Chain chain : eligible) {
            if (selected.size() >= MAX_APPLICATION_PRIORITY_FRONTS) {
                break;
            }
            if (selected.contains(chain)) {
                roots.add(applicationRootKey(chain));
                continue;
            }
            if (roots.add(applicationRootKey(chain))) {
                selected.add(chain);
            }
        }
        if (selected.size() < MAX_APPLICATION_PRIORITY_FRONTS) {
            for (Chain chain : eligible) {
                if (selected.size() >= MAX_APPLICATION_PRIORITY_FRONTS
                        || selected.contains(chain)) {
                    continue;
                }
                selected.add(chain);
            }
        }
        return List.copyOf(selected);
    }

    private boolean supportsBridgeFamily(Blackboard target, Chain chain, String family,
                                         Map<String, FrontFeatures> frontFeaturesCache) {
        FrontFeatures features = frontFeaturesCached(target, chain, frontFeaturesCache);
        return switch (family) {
            case "jdbc" -> features.jdbc();
            case "jndi" -> features.jndiRmi();
            case "deserialize" -> features.deserialize();
            case "invoke" -> features.invoke();
            case "template" -> features.template();
            case "trigger" -> features.triggerContainer() != null;
            default -> false;
        };
    }

    private static String applicationRootKey(Chain chain) {
        if (chain == null) {
            return "<null>";
        }
        return chain.entryClass() + "#" + chain.entryMethod() + entryDescriptor(chain);
    }

    /**
     * Order frontiers by the typed bridge they can actually consume.  A capability role alone
     * is too broad: a large class-loading/trigger frontier can still crowd out an INVOKE
     * frontier that has a public-entry continuation.  This rank is semantic and independent of
     * artifact names; the existing provenance/risk score remains the tie breaker within a
     * bridge family.
     */
    private static int frontBridgePriority(FrontFeatures features) {
        if (features == null) {
            return 0;
        }
        if (features.invoke()) {
            return 6;
        }
        if (features.deserialize()) {
            return 5;
        }
        if (features.jndiRmi() || features.jdbc()) {
            return 4;
        }
        if (features.template()) {
            return 3;
        }
        return features.triggerContainer() == null ? 0 : 2;
    }

    private record ComposedDepth(Chain chain, int depth) {
    }

    private boolean isApplicationFront(Blackboard target, Chain chain) {
        if (target == null || chain == null) {
            return false;
        }
        // A declared secondary-deserialization fragment is a typed continuation endpoint.  An
        // application-owned helper may appear in the same artifact, but it must not consume
        // the finite application-prefix budget as if it were an external execution root.
        if (isDeclaredSecondaryDeserializationFragment(chain)) {
            return false;
        }
        if (target.applicationEntryIndex() == null
                || !target.applicationEntryIndex().applicationScopeKnown()) {
            return applicationFrontPriority(target, chain) > 0;
        }
        String descriptor = entryDescriptor(chain);
        String key = chain.entryClass() + "#" + chain.entryMethod() + descriptor;
        var index = target.applicationEntryIndex();
        if (!index.isApplicationOwner(chain.entryClass())) {
            return false;
        }
        // A reverse chain may start at an application-owned helper rather than at the
        // externally reachable root.  The immutable entry-forward slice is the typed
        // admission for that prefix; it is deliberately narrower than owner/classpath
        // membership and therefore cannot admit a dependency-only front.
        return index.isApplicationEntryMethod(key) || index.isEntryForwardReachable(key)
                || index.isApplicationBindingCallback(chain.entryClass(), chain.entryMethod(),
                descriptor);
    }

    /**
     * A default composition back must be either a dependency/JDK suffix whose actual sink is
     * already present in the immutable terminal-impact index and sink-reverse slice, or an
     * explicitly typed bridge/continuation whose eventual terminal is expected in a later
     * bounded composition round.  The latter keeps lookup/JDBC/reflection/second-deserialize
     * continuation alive without allowing the intermediate node to become a terminal finding.
     */
    private boolean isDefaultSuffixCandidate(Blackboard target, Chain chain,
                                             Map<TerminalAdmissionKey,
                                                     ApplicationEntryIndex.TerminalDecision>
                                                     terminalAdmissionCache,
                                             Map<ContinuationAdmissionKey, Boolean>
                                                     continuationAdmissionCache) {
        if (chain == null || (!isPublicEntry(chain) && !isDeclaredContinuationFragment(chain)
                && !isDeclaredDirectFragment(chain)
                && !isDeclaredSecondaryDeserializationFragment(chain))
                || target == null || target.applicationEntryIndex() == null) {
            return false;
        }
        var index = target.applicationEntryIndex();
        if (!index.applicationScopeKnown()) {
            return false;
        }
        if (isDeclaredSecondaryDeserializationFragment(chain)) {
            return true;
        }
        if (index.isApplicationOwner(chain.entryClass())) {
            return false;
        }
        if (isDeclaredContinuationFragment(chain)) {
            return true;
        }
        if (isDeclaredDirectFragment(chain)) {
            return chain.unresolvedHops() == 0 && activationAllows(chain, "invoke");
        }
        var decision = terminalAdmission(index, chain, terminalAdmissionCache);
        if (decision.admitted()) {
            return index.isSinkReverseReachable(decision.hostMethodKey());
        }
        return decision.status() == ApplicationEntryIndex.TerminalStatus.INTERMEDIATE_ONLY
                && typedContinuationSink(target, chain, continuationAdmissionCache);
    }

    private boolean isDefaultSuffixCandidate(
            Blackboard target, Blackboard.DeferredDependencySuffix deferred,
            Map<TerminalAdmissionKey, ApplicationEntryIndex.TerminalDecision>
                    terminalAdmissionCache) {
        if (target == null || deferred == null || target.applicationEntryIndex() == null) {
            return false;
        }
        ApplicationEntryIndex index = target.applicationEntryIndex();
        ApplicationEntryIndex.ProducerCandidate candidate = deferred.candidate();
        if (!index.applicationScopeKnown() || index.isApplicationOwner(candidate.entryOwner())
                || (!isPublicEntry(candidate.entryKind())
                && !isDeclaredDirectCandidate(candidate))) {
            return false;
        }
        ApplicationEntryIndex.TerminalDecision decision = terminalAdmission(index,
                candidate.terminalOwner(), candidate.terminalName(),
                candidate.terminalDescriptor(), terminalAdmissionCache);
        return decision.admitted() && index.isSinkReverseReachable(decision.hostMethodKey());
    }

    /**
     * Filter the typed composition owners before constructing a compatibility union.  The
     * application scope already has an indexed terminal/backward boundary, so application
     * chains that cannot serve as dependency/bridge backs must not be copied into a global
     * list only to be discarded by the predicate afterwards.  Inserting stores in the same
     * order as CompositionInputs.compatibilityAll() preserves direct addChain compatibility and duplicate
     * key precedence for the remaining candidates.
     */
    private List<Chain> defaultSuffixCandidates(Blackboard target,
                                                 Blackboard.CompositionInputs inputs,
                                                 Map<TerminalAdmissionKey,
                                                         ApplicationEntryIndex.TerminalDecision>
                                                         terminalAdmissionCache,
                                                 Map<ContinuationAdmissionKey, Boolean>
                                                         continuationAdmissionCache,
                                                 boolean allowDeferredMaterialization) {
        if (target == null || inputs == null) {
            return List.of();
        }
        Map<String, Chain> unique = new java.util.TreeMap<>();
        addDefaultSuffixCandidates(unique, target, inputs.applicationChains(),
                terminalAdmissionCache, continuationAdmissionCache);
        addDefaultSuffixCandidates(unique, target, inputs.bridgeContinuations(),
                terminalAdmissionCache, continuationAdmissionCache);
        addDefaultSuffixCandidates(unique, target, inputs.dependencySuffixes(),
                terminalAdmissionCache, continuationAdmissionCache);
        if (allowDeferredMaterialization) {
            addDeferredDefaultSuffixCandidates(unique, target, inputs, terminalAdmissionCache);
        }
        return List.copyOf(unique.values());
    }

    /** Resolve deferred suffix endpoints only after the typed composition filter accepts them. */
    private void addDeferredDefaultSuffixCandidates(
            Map<String, Chain> unique, Blackboard target,
            List<Blackboard.DeferredDependencySuffix> candidates,
            Map<TerminalAdmissionKey, ApplicationEntryIndex.TerminalDecision>
                    terminalAdmissionCache) {
        if (target == null || candidates == null) {
            return;
        }
        for (Blackboard.DeferredDependencySuffix deferred : candidates) {
            if (!isDefaultSuffixCandidate(target, deferred, terminalAdmissionCache)) {
                continue;
            }
            ApplicationEntryIndex.ProducerAdmissionDecision demandDecision =
                    target.applicationEntryIndex().producerAdmission(deferred.candidate());
            Blackboard.SolverAdmissionResult result =
                    target.materializeDeferredDependencySuffix(deferred, demandDecision);
            if (result.accepted()) {
                unique.putIfAbsent(result.chain().key(), result.chain());
            }
        }
    }

    private void addDeferredDefaultSuffixCandidates(
            Map<String, Chain> unique, Blackboard target,
            Blackboard.CompositionInputs inputs,
            Map<TerminalAdmissionKey, ApplicationEntryIndex.TerminalDecision>
                    terminalAdmissionCache) {
        if (target == null || inputs == null || target.applicationEntryIndex() == null) {
            return;
        }
        ApplicationEntryIndex index = target.applicationEntryIndex();
        List<Blackboard.DeferredDependencySuffix> demanded = new ArrayList<>();
        Set<Blackboard.DeferredDependencySuffix> seen =
                java.util.Collections.newSetFromMap(new java.util.IdentityHashMap<>());
        // Walk the immutable terminal-demand owner first, then use the deferred terminal
        // index to retrieve only endpoint candidates whose exact terminal is both indexed and
        // reverse-reachable.  Identity tracking deliberately preserves distinct suppliers
        // that share the same cheap ProducerCandidate endpoint.
        for (ApplicationEntryIndex.TerminalImpact impact : index.terminalDemandImpacts()) {
            for (Blackboard.DeferredDependencySuffix deferred :
                    inputs.deferredDependencySuffixesForTerminal(impact.owner(), impact.name(),
                            impact.descriptor())) {
                if (seen.add(deferred)) {
                    demanded.add(deferred);
                }
            }
        }
        // A descriptor-free endpoint is admitted by the index's name lookup.  It has no exact
        // terminal-map key, so retain that small compatibility subset from the entry-kind
        // buckets without reopening a full list scan for normal descriptor-bearing candidates.
        for (String entryKind : PUBLIC_ENTRY_KINDS) {
            for (Blackboard.DeferredDependencySuffix deferred :
                    inputs.deferredDependencySuffixesForEntryKind(entryKind)) {
                if (deferred.candidate().terminalDescriptor().isBlank() && seen.add(deferred)) {
                    demanded.add(deferred);
                }
            }
        }
        addDeferredDefaultSuffixCandidates(unique, target, demanded, terminalAdmissionCache);
    }

    private void addDefaultSuffixCandidates(Map<String, Chain> unique, Blackboard target,
                                            List<Chain> candidates,
                                            Map<TerminalAdmissionKey,
                                                    ApplicationEntryIndex.TerminalDecision>
                                                    terminalAdmissionCache,
                                            Map<ContinuationAdmissionKey, Boolean>
                                                    continuationAdmissionCache) {
        if (candidates == null) {
            return;
        }
        for (Chain chain : candidates) {
            if (isDefaultSuffixCandidate(target, chain, terminalAdmissionCache,
                    continuationAdmissionCache)) {
                unique.putIfAbsent(chain.key(), chain);
            }
        }
    }

    /** Resolve one immutable terminal decision at most once per composition build. */
    private static ApplicationEntryIndex.TerminalDecision terminalAdmission(
            ApplicationEntryIndex index, Chain chain,
            Map<TerminalAdmissionKey, ApplicationEntryIndex.TerminalDecision> cache) {
        return terminalAdmission(index, chain.sinkClass(), chain.sinkMethod(),
                chain.sinkDescriptor(), cache);
    }

    private static ApplicationEntryIndex.TerminalDecision terminalAdmission(
            ApplicationEntryIndex index, String owner, String name, String descriptor,
            Map<TerminalAdmissionKey, ApplicationEntryIndex.TerminalDecision> cache) {
        TerminalAdmissionKey key = new TerminalAdmissionKey(
                owner == null ? "" : owner,
                name == null ? "" : name,
                descriptor == null ? "" : descriptor);
        if (cache != null) {
            ApplicationEntryIndex.TerminalDecision cached = cache.get(key);
            if (cached != null) {
                return cached;
            }
        }
        ApplicationEntryIndex.TerminalDecision decision = index.terminalAdmission(
                key.owner(), key.name(), key.descriptor());
        if (cache != null) {
            cache.put(key, decision);
        }
        return decision;
    }

    private boolean typedContinuationSink(Blackboard target, Chain chain,
                                         Map<ContinuationAdmissionKey, Boolean> cache) {
        if (chain == null || target == null) {
            return false;
        }
        ContinuationAdmissionKey key = new ContinuationAdmissionKey(
                chain.ruleId() == null ? "" : chain.ruleId(),
                chain.sinkClass() == null ? "" : chain.sinkClass(),
                chain.sinkMethod() == null ? "" : chain.sinkMethod(),
                chain.sinkDescriptor() == null ? "" : chain.sinkDescriptor());
        if (cache != null) {
            Boolean cached = cache.get(key);
            if (cached != null) {
                return cached;
            }
        }
        Rule.SinkRule sink = target.rules().sinks().stream()
                .filter(rule -> rule != null && rule.id().equals(key.ruleId()))
                .findFirst()
                .orElseGet(() -> target.ruleEngine()
                        .matchingSink(key.owner(), key.name(), key.descriptor())
                        .orElse(null));
        boolean result = sink != null && !RuleSchemaV2.isTerminalSink(sink)
                && !RuleSchemaV2.bridgesFor(sink).isEmpty();
        if (cache != null) {
            cache.put(key, result);
        }
        return result;
    }

    private int applicationBackPriority(Chain chain) {
        int score = terminalBackPriority(chain);
        if (chain == null) {
            return score;
        }
        if (isDeclaredSecondaryDeserializationFragment(chain)) {
            // A capability fragment is not a terminal suffix, but it is the typed continuation
            // that a DESERIALIZE front must consume before any terminal back can be reached.
            score += 2_000;
        }
        // A terminal deserialization is a typed continuation point, not merely an effect;
        // reserve it ahead of unrelated file/reflective terminals so nested input can be
        // composed in the next round.  Rule category/role is data-driven and applies equally
        // to any framework's secondary input API.
        if ("DESERIALIZE".equalsIgnoreCase(chain.category())) {
            score += 320;
        }
        if ("CODE_EXEC".equalsIgnoreCase(chain.category())) {
            score += 160;
        }
        if ("JNDI".equalsIgnoreCase(chain.category()) || "JDBC".equalsIgnoreCase(chain.category())) {
            score += 120;
        }
        // Declarative fragments are typed knowledge-source outputs.  Give their immutable
        // endpoints a bounded scheduling preference so a large raw sink frontier cannot starve
        // a reusable suffix that carries an explicit callback/bridge identity.  This is
        // provenance-based and applies to every fragment rule, not to a fixture or class name.
        if (isFragmentChain(chain)) {
            score += 384;
        }
        return score;
    }

    private ComposedProducer composeIfBridgeable(Blackboard target, Chain front, Chain back,
                                                 Set<String> seenFrontDepth,
                                                 Map<String, FrontFeatures> frontFeaturesCache) {
        if (front == null || back == null || front == back || onPath(front, back.entryClass())) {
            return null;
        }
        FrontFeatures features = frontFeaturesCached(target, front, frontFeaturesCache);
        Bridge bridge = semanticBridge(target, features, front, back);
        if (bridge == null) {
            return null;
        }
        String dedupe = front.key() + "|" + back.key() + "|" + bridge.name();
        if (!seenFrontDepth.add(dedupe)) {
            return null;
        }
        return composedProducer(front, back, bridge);
    }

    /**
     * Join an application prefix to a secondary-deserialization suffix at an exact callback
     * method already present in the prefix.  Reflection is often modeled as a capability sink
     * before the more precise converter/deserializer path is discovered; requiring an exact
     * callback overlap preserves that value/object identity without allowing unrelated gadget
     * roots to enter the default application result.
     */
    private ComposedProducer composeIfOverlapping(Blackboard target, Chain front, Chain back,
                                                  Set<String> seenFrontDepth) {
        if (front == null || back == null || front == back
                || !isSecondaryDeserializationBack(target, back)) {
            return null;
        }
        int suffixStart = overlapSuffixStart(front, back);
        if (suffixStart < 0) {
            return null;
        }
        String dedupe = "overlap|" + front.key() + "|" + back.key();
        if (!seenFrontDepth.add(dedupe)) {
            return null;
        }
        return composedProducer(front, back, () -> composeOverlap(front, back, suffixStart));
    }

    private boolean isSecondaryDeserializationBack(Blackboard target, Chain chain) {
        if (isDeclaredSecondaryDeserializationFragment(chain)) {
            return true;
        }
        if (chain == null || !chain.terminalSink()
                || !"DESERIALIZE".equalsIgnoreCase(chain.category())
                || !isPublicEntry(chain)) {
            return false;
        }
        if (target == null || target.applicationEntryIndex() == null
                || !target.applicationEntryIndex().applicationScopeKnown()) {
            return true;
        }
        // A suffix that is already rooted in another application entry is a separate product
        // candidate, not a dependency continuation of this application prefix.
        return !target.applicationEntryIndex().isApplicationOwner(chain.entryClass());
    }

    /** Return the first hop after the shared callback in sink-to-entry hop order. */
    private static int overlapSuffixStart(Chain front, Chain back) {
        if (front == null || back == null || front.hops().isEmpty()) {
            return -1;
        }
        String owner = back.entryClass();
        String name = back.entryMethod();
        String descriptor = entryDescriptor(back);
        // A callback method appears as the from-side of its outgoing trace hop.  Prefer that
        // exact boundary and choose the occurrence nearest the application ENTRY so recursive
        // wildcard paths do not make an earlier loop the splice point.
        for (int i = front.hops().size() - 1; i >= 0; i--) {
            ChainHop hop = front.hops().get(i);
            if (sameMethod(hop.fromOwner(), hop.fromName(), owner, name)
                    && descriptorCompatible(descriptor, hop.desc())) {
                int suffix = i + 1;
                return containsEntryFrom(front, suffix) ? suffix : -1;
            }
        }
        // Some field/dispatch traces expose the callback only as the to-side endpoint.  Keep
        // that hop so the displayed path still contains the caller→callback boundary.
        for (int i = front.hops().size() - 1; i >= 0; i--) {
            ChainHop hop = front.hops().get(i);
            if (sameMethod(hop.toOwner(), hop.toName(), owner, name)
                    && descriptorCompatible(descriptor, hop.desc())) {
                return containsEntryFrom(front, i) ? i : -1;
            }
        }
        return -1;
    }

    private static boolean containsEntryFrom(Chain chain, int start) {
        if (chain == null || start < 0 || start > chain.hops().size()) {
            return false;
        }
        for (int i = start; i < chain.hops().size(); i++) {
            if (chain.hops().get(i).kind() == HopKind.ENTRY) {
                return true;
            }
        }
        return false;
    }

    private static boolean descriptorCompatible(String expected, String actual) {
        return expected == null || expected.isBlank() || actual == null || actual.isBlank()
                || expected.equals(actual);
    }

    private static boolean sameMethod(String owner, String name, String expectedOwner,
                                      String expectedName) {
        return expectedOwner != null && expectedOwner.equals(owner)
                && expectedName != null && expectedName.equals(name);
    }

    private static Chain composeOverlap(Chain front, Chain back, int suffixStart) {
        int backEntry = -1;
        for (int i = back.hops().size() - 1; i >= 0; i--) {
            if (back.hops().get(i).kind() == HopKind.ENTRY) {
                backEntry = i;
                break;
            }
        }
        int backEnd = backEntry < 0 ? back.hops().size() : backEntry;
        List<ChainHop> hops = new ArrayList<>(backEnd
                + 1 + Math.max(0, front.hops().size() - suffixStart));
        hops.addAll(back.hops().subList(0, backEnd));
        // The shared callback is the typed bridge boundary.  A self-dispatch hop is used so
        // reports/evidence can distinguish this continuation from an ordinary call-graph edge
        // without inventing a target method or dropping the exact overlap identity.
        hops.add(new ChainHop(back.entryClass(), back.entryMethod(),
                back.entryClass(), back.entryMethod(), HopKind.VIRTUAL_DISPATCH, null,
                "bridge-second-deserialization-overlap", entryDescriptor(back), null));
        hops.addAll(front.hops().subList(suffixStart, front.hops().size()));
        if (hops.size() > MAX_HOPS) {
            return null;
        }
        return new Chain(back.ruleId(), back.category(), back.severity(),
                front.entryClass(), front.entryMethod(), front.entryKind(),
                back.sinkClass(), back.sinkMethod(), hops,
                front.unresolvedHops() + back.unresolvedHops(), back.sinkDescriptor(),
                back.sinkRole(), constructionPlanOf(back, front), back.sinkRisk());
    }

    /**
     * 源宿主容器触发桥：方法 M 体内含反序列化源调用（OIS 读取或 bridge:deserialize 框架源），
     * 且操作哈希触发容器（Map/Set 的 add/put/iterator）——容器反序列化机制以攻击者数据回调
     * 元素 hashCode/equals/compareTo（如 HashSet.readObject → HashMap.hash → 元素 hashCode）。
     * 此类方法直接作为触发容器桥的前段宿主，与 trigger-entry 后段链组装成完整攻击路径。
     */
    private int composeSourceHosted(Blackboard target, Blackboard.CompositionInputs inputs) {
        if (target == null || inputs == null) {
            return 0;
        }
        Map<String, DeserHost> discoveredHosts = scanHosts(target);
        Set<String> primaryClasses = primaryArtifactClasses(target);
        int composed = 0;
        List<Map.Entry<String, DeserHost>> hosts = new ArrayList<>(discoveredHosts.entrySet());
        // A dependency/JDK trigger is only a product candidate after it is attached to a
        // deserialization host owned by the target application.  The application index is
        // the typed admission boundary: it proves that the host is reachable from an
        // application execution root in the bounded forward slice.  Kernel/compatibility
        // callers without a known scope retain the historical bounded composition path.
        if (target.applicationEntryIndex().applicationScopeKnown()) {
            var index = target.applicationEntryIndex();
            boolean hasApplicationRootInForwardSlice = index.applicationEntries().stream()
                    .anyMatch(entry -> index.isEntryForwardReachable(entry.methodKey()));
            hosts.removeIf(entry -> !applicationAnchoredHost(target, entry.getValue(),
                    hasApplicationRootInForwardSlice));
            if (hosts.isEmpty()) {
                target.markIncomplete("SOURCE_HOST_NO_APPLICATION_ANCHOR");
            }
        }
        // Deferred trigger payloads are a demand frontier, not a compatibility snapshot.
        // Do not materialize them until at least one concrete source host survived the typed
        // application-anchor filter; a graph-less/minimal or unanchored scan has no consumer.
        List<Chain> chains = hosts.isEmpty() ? List.of()
                : sourceHostedTriggerInputs(target, inputs);
        // The caller now supplies a typed, deduplicated trigger frontier only after at least
        // one host demand survives. Retain the complete capability/risk/key ordering here,
        // but do not copy every non-trigger chain into an ordered/rest pair before filtering.
        List<Chain> triggerChains = chains.stream()
                .sorted(java.util.Comparator
                                 .comparingInt((Chain chain) -> triggerPriority(chain,
                                 primaryClasses)).reversed()
                        .thenComparingInt(Chain::unresolvedHops)
                        .thenComparingInt(chain -> chain.hops().size())
                        .thenComparing(Chain::key))
                .toList();
        Map<String, List<Chain>> triggerChainsByHost = new HashMap<>();
        for (Map.Entry<String, DeserHost> host : hosts) {
            DeserHost hostRef = host.getValue();
            List<Chain> applicable = triggerChains;
            if (isObjectInputStreamFrame(target, hostRef)) {
                var hostMethod = target.originSupport().methodOf(hostRef.owner(),
                        hostRef.method(), hostRef.descriptor());
                // Graph-only compatibility callers do not carry method bytecode/CFG facts.
                // They cannot satisfy the typed element proof, but they also cannot be used as
                // production evidence; retain their historical bounded composition behavior.
                // A real loaded host, by contrast, must pass the concrete element gate.
                // Root-object OIS callbacks do not have a container element to bind, so they
                // retain the serialization mechanism frontier.  Apply the type gate only
                // after the immutable provenance layer has proved a standard-container
                // element access; otherwise a direct HashMap/HashCode callback is erased.
                if (hostMethod != null && target.originSupport()
                        .hasDeserializedContainerElementAccess(hostMethod)) {
                    Set<String> elementTypes = target.originSupport()
                            .deserializedContainerElementTypes(hostMethod);
                    // A proven container read with no concrete CHECKCAST is still a real
                    // deserialization boundary; its element type is UNKNOWN, not negative
                    // evidence.  Apply the bounded type filter only when the provenance layer
                    // has an actual finite type set.  This keeps typed pruning useful without
                    // erasing externally assembled Serializable/Proxy containers.
                    if (!elementTypes.isEmpty()) {
                        applicable = triggerChains.stream()
                                .filter(chain -> triggerMatchesDeserializedElement(target, chain,
                                        elementTypes))
                                .toList();
                    }
                }
            }
            triggerChainsByHost.put(host.getKey(), applicable);
        }
        // The source-host product is bounded by design. A lexical host order lets a large
        // dependency surface consume the whole first round before an application-defined
        // deserialization boundary gets a chance to attach a fragment. Put primary-artifact
        // hosts first, then retain stable key order inside each group. This is provenance
        // scheduling, not a class/package special case.
        hosts.sort(java.util.Comparator
                .comparing((Map.Entry<String, DeserHost> entry) ->
                        !primaryClasses.contains(entry.getValue().owner()))
                .thenComparing(Map.Entry::getKey));
        // The old back-chain-first loop let one popular library entry consume the whole
        // source-host budget.  Round-robin scheduling is still deterministic and bounded,
        // but gives each independently discovered deserialization host a chance to attach a
        // semantically valid trigger chain before filling the remaining budget.
        int rounds = 0;
        boolean roundLimitReached = false;
        for (int round = 0; round < MAX_SOURCE_ROUNDS
                && composed < MAX_COMPOSED && !triggerChains.isEmpty(); round++) {
            rounds++;
            boolean emittedInRound = false;
            for (int hostIndex = 0; hostIndex < hosts.size() && composed < MAX_COMPOSED; hostIndex++) {
                Map.Entry<String, DeserHost> host = hosts.get(hostIndex);
                // Advance the trigger frontier by round and host index.  Each host gets one
                // new deterministic pair per round; unlike the former inner retry loop this
                // cannot rescan the whole trigger list for every host in every round.
                DeserHost hostRef = host.getValue();
                List<Chain> applicableTriggers = triggerChainsByHost.getOrDefault(host.getKey(),
                        List.of());
                if (applicableTriggers.isEmpty()) {
                    continue;
                }
                int backIndex = Math.floorMod(round + hostIndex, applicableTriggers.size());
                Chain back = applicableTriggers.get(backIndex);
                String hostClass = hostRef.owner();
                String hostMethod = hostRef.method();
                // 防环：后段入口类不得就是宿主自身（宿主内自触发无源语义）
                if (back.entryClass().equals(hostClass)) {
                    continue;
                }
                int sourceHopCount = sourceHostedHopCount(back);
                if (sourceHopCount > MAX_HOPS) {
                    continue;
                }
                SourceHostedProducer producer = sourceHostedProducer(back, hostClass, hostMethod,
                        "source", hostRef.descriptor(), sourceHopCount, true,
                        () -> sourceHostedHops(back, hostRef, hostClass, hostMethod));
                if (producer == null) {
                    continue;
                }
                Chain merged = admitSourceHostedChain(target, producer);
                if (merged != null) {
                    // The typed admission owner has already routed the product.  Notes are
                    // owned by the default/calibration stores; calling this unconditionally
                    // is equivalent for bridge/suffix/kernel routes and avoids a full snapshot
                    // scan of target.chains() for every accepted source-host candidate.
                    target.chainNote(merged.key(), "pattern:src-container-trigger");
                    composed++;
                    emittedInRound = true;
                }
            }
            if (!emittedInRound) {
                break;
            }
        }
        roundLimitReached = rounds >= MAX_SOURCE_ROUNDS;
        if (composed < MAX_COMPOSED && !triggerChains.isEmpty()
                && !hosts.isEmpty() && roundLimitReached) {
            // If the bounded frontier was exhausted before the normal composition cap,
            // expose the bound in completeness metadata instead of silently dropping pairs.
            target.markIncomplete("SOURCE_HOST_SCHEDULING_CAP:" + MAX_SOURCE_ROUNDS);
        }
        if (composed >= MAX_COMPOSED) {
            target.markIncomplete("COMPOSITION_SOURCE_CHAIN_CAP:" + MAX_COMPOSED);
        }
        return composed;
    }

    private boolean isObjectInputStreamFrame(Blackboard target, DeserHost host) {
        if (target == null || host == null || host.frameOwner() == null) {
            return false;
        }
        return target.ruleEngine().isSubtypeOf(host.frameOwner(),
                "java/io/ObjectInputStream")
                && ("readObject".equals(host.frameMethod())
                || "readUnshared".equals(host.frameMethod())
                || "readFields".equals(host.frameMethod()));
    }

    private boolean triggerMatchesDeserializedElement(Blackboard target, Chain chain,
                                                      Set<String> elementTypes) {
        if (target == null || chain == null || elementTypes == null || elementTypes.isEmpty()
                || chain.entryClass() == null || isPlatformOwner(chain.entryClass())) {
            return false;
        }
        for (String elementType : elementTypes) {
            if (elementType != null && (elementType.equals(chain.entryClass())
                    || target.hierarchy().isSubtypeOf(elementType, chain.entryClass()))) {
                return true;
            }
        }
        return false;
    }

    private static boolean isPlatformOwner(String owner) {
        return owner != null && (owner.startsWith("java/") || owner.startsWith("javax/")
                || owner.startsWith("sun/") || owner.startsWith("jdk/")
                || owner.startsWith("com/sun/"));
    }

    /**
     * Source-host composition only consumes trigger-entry chains.  Build that frontier from
     * the typed stores directly so ordinary application products are not first copied into a
     * compatibility union and discarded by the final entry-kind predicate.  Store insertion
     * order mirrors CompositionInputs.compatibilityAll(), retaining direct addChain compatibility and
     * deterministic duplicate-key precedence.
     */
    private List<Chain> sourceHostedTriggerInputs(Blackboard target,
                                                  Blackboard.CompositionInputs inputs) {
        if (inputs == null) {
            return List.of();
        }
        Map<String, Chain> unique = new java.util.TreeMap<>();
        // The application store may still contain direct addChain compatibility data.  In a
        // known application scope only its application-owned trigger roots belong to this
        // store's source-host projection; dependency callbacks have a separate typed bridge
        // owner and are admitted from bridgeContinuations below.  Without this boundary a
        // dependency trigger manually published through the compatibility API can masquerade
        // as an application source-host root and consume the same finite scheduling budget.
        addTriggerInputs(unique, inputs.applicationChains(), target, true);
        addTriggerInputs(unique, inputs.bridgeContinuations(), target, false);
        // In a known application scope a dependency trigger is only an intermediate runtime
        // mechanism, never an application object identity.  The serialized element callback
        // candidates live in the kernel store until a real application OIS host consumes them.
        // Keeping dependency suffixes in this product was the source of arbitrary
        // ConcurrentHashMap/Boot callback pairs in the demo application report.
        if (target == null || target.applicationEntryIndex() == null
                || !target.applicationEntryIndex().applicationScopeKnown()) {
            addTriggerInputs(unique, inputs.dependencySuffixes(), target, false);
        }
        if (target != null && target.applicationEntryIndex() != null
                && target.applicationEntryIndex().applicationScopeKnown()) {
            for (Chain chain : target.kernelOnlyChains()) {
                if (isTriggerEntry(chain.entryKind())
                        && target.applicationEntryIndex().isApplicationOwner(chain.entryClass())
                        && target.hierarchy().isSerializable(chain.entryClass())
                        && chain.unresolvedHops() == 0) {
                    unique.putIfAbsent(chain.key(), chain);
                }
            }
        }
        if (target != null) {
            for (String entryKind : TRIGGER_ENTRY_KINDS) {
                for (Blackboard.DeferredDependencySuffix deferred :
                        inputs.deferredDependencySuffixesForEntryKind(entryKind)) {
                    ApplicationEntryIndex.ProducerAdmissionDecision demandDecision =
                            target.applicationEntryIndex().producerAdmission(deferred.candidate());
                    Blackboard.SolverAdmissionResult result =
                            target.materializeDeferredDependencySuffix(deferred, demandDecision);
                    if (result.accepted() && isTriggerEntry(result.chain().entryKind())) {
                        unique.putIfAbsent(result.chain().key(), result.chain());
                    }
                }
            }
        }
        return List.copyOf(unique.values());
    }

    private void addTriggerInputs(Map<String, Chain> unique, List<Chain> candidates,
                                  Blackboard target, boolean applicationStore) {
        if (candidates == null) {
            return;
        }
        for (Chain chain : candidates) {
            if (isTriggerEntry(chain.entryKind())
                    && (!applicationStore || target == null || target.applicationEntryIndex() == null
                    || !target.applicationEntryIndex().applicationScopeKnown()
                    || target.applicationEntryIndex().isApplicationOwner(chain.entryClass()))) {
                unique.putIfAbsent(chain.key(), chain);
            }
        }
    }

    private int distinctCompositionInputCount(Blackboard.CompositionInputs inputs) {
        if (inputs == null) {
            return 0;
        }
        Set<String> keys = new HashSet<>();
        addCompositionKeys(keys, inputs.applicationChains());
        addCompositionKeys(keys, inputs.bridgeContinuations());
        addCompositionKeys(keys, inputs.dependencySuffixes());
        if (inputs.deferredDependencySuffixes() != null) {
            for (Blackboard.DeferredDependencySuffix deferred :
                    inputs.deferredDependencySuffixes()) {
                ApplicationEntryIndex.ProducerCandidate candidate = deferred.candidate();
                keys.add("<deferred>|" + candidate.entryMethodKey() + "|"
                        + candidate.terminalOwner() + "#" + candidate.terminalName()
                        + candidate.terminalDescriptor());
            }
        }
        return keys.size();
    }

    private void addCompositionKeys(Set<String> keys, List<Chain> candidates) {
        if (candidates == null) {
            return;
        }
        for (Chain chain : candidates) {
            if (chain != null) {
                keys.add(chain.key());
            }
        }
    }

    /**
     * Publish a source-hosted endpoint through the event-owned typed admission boundary.
     * Keeping the target explicit prevents a stale source field from silently routing a
     * candidate to another Blackboard when a source is exercised in isolation or replayed.
     */
    boolean admitSourceHosted(Blackboard target, SourceHostedProducer producer,
                              Supplier<Chain> materializer) {
        return admitSourceHostedChain(target, producer, materializer) != null;
    }

    private Chain admitSourceHostedChain(Blackboard target, SourceHostedProducer producer) {
        if (producer == null) {
            return null;
        }
        return admitSourceHostedChain(target, producer, producer.materializer());
    }

    private Chain admitSourceHostedChain(Blackboard target, SourceHostedProducer producer,
                                         Supplier<Chain> materializer) {
        if (target == null || producer == null || materializer == null) {
            return null;
        }
        return admitEagerCompositionCandidate(target, producer.candidate(), materializer);
    }

    /**
     * Shared eager-composition boundary for source-hosted and composed products.  Both callers
     * need a concrete chain in the current round; a deferred suffix must remain in the typed
     * frontier until an application-backed consumer requests it.
     */
    private Chain admitEagerCompositionCandidate(
            Blackboard target, ApplicationEntryIndex.ProducerCandidate candidate,
            Supplier<Chain> materializer) {
        if (target == null || candidate == null || materializer == null
                || target.applicationEntryIndex() == null) {
            return null;
        }
        ApplicationEntryIndex.ProducerAdmissionDecision decision =
                target.applicationEntryIndex().producerAdmission(candidate);
        if (!decision.materializationPolicy().materializesImmediately()) {
            return null;
        }
        Blackboard.SolverAdmissionResult result =
                target.admitSolverCandidate(candidate, materializer);
        return result.accepted() ? result.chain() : null;
    }

    /**
     * Build only the source-host endpoint; the concrete bridge hops remain behind the supplier
     * until the central application-demand owner accepts the candidate.
     */
    static SourceHostedProducer sourceHostedProducer(Chain back, String hostOwner,
                                                      String hostMethod, String hostEntryKind,
                                                      String hostDescriptor, int hopCount,
                                                      boolean continuationEvidence,
                                                      Supplier<List<ChainHop>> hopMaterializer) {
        if (back == null || hostOwner == null || hostOwner.isBlank()
                || hostMethod == null || hostMethod.isBlank()) {
            return null;
        }
        if (hopCount < 0 || hopCount > MAX_HOPS || hopMaterializer == null) {
            return null;
        }
        boolean declaredFragmentContinuation = isDeclaredStaticFragmentTerminal(back);
        ApplicationEntryIndex.ProducerCandidate candidate =
                new ApplicationEntryIndex.ProducerCandidate(back.ruleId(), back.category(),
                        back.severity(), hostOwner, hostMethod, hostDescriptor, hostEntryKind,
                        back.sinkClass(), back.sinkMethod(), back.sinkDescriptor(),
                        back.sinkRole(), back.sinkRisk(),
                        continuationEvidence, declaredFragmentContinuation,
                        declaredFragmentContinuation);
        Supplier<Chain> materializer = () -> {
            List<ChainHop> hops = hopMaterializer.get();
            if (hops == null || hops.size() != hopCount || hops.size() > MAX_HOPS) {
                return null;
            }
            List<ChainHop> immutableHops = List.copyOf(hops);
            return new Chain(candidate.ruleId(), candidate.category(), candidate.severity(),
                    candidate.entryOwner(), candidate.entryName(), candidate.entryKind(),
                    candidate.terminalOwner(), candidate.terminalName(), immutableHops,
                    back.unresolvedHops(), candidate.terminalDescriptor(), candidate.terminalRole(),
                    constructionPlanOf(back, null), candidate.sinkRisk());
        };
        return new SourceHostedProducer(candidate, materializer);
    }

    private static int sourceHostedHopCount(Chain back) {
        if (back == null || back.hops() == null) {
            return -1;
        }
        return Math.max(0, back.hops().size() - 1) + 3;
    }

    private static List<ChainHop> sourceHostedHops(Chain back, DeserHost hostRef,
                                                   String hostClass, String hostMethod) {
        List<ChainHop> hops = new ArrayList<>(sourceHostedHopCount(back));
        for (int i = 0; i < back.hops().size() - 1; i++) {
            hops.add(back.hops().get(i));
        }
        // 机制桥接跳：反序列化框架的容器/bean 机制以攻击者数据回调后段入口
        // （OIS: HashSet.readObject→HashMap.hash；Kryo: MapSerializer.read→put；
        //   fastjson: JavaBeanDeserializer→setter——框架管线语义，非调用图相邻）
        hops.add(new ChainHop(hostRef.frameOwner(), hostRef.frameMethod(),
                back.entryClass(), back.entryMethod(),
                HopKind.VIRTUAL_DISPATCH, null, "bridge-trigger-src",
                entryDescriptor(back), null));
        hops.add(new ChainHop(hostClass, hostMethod, hostRef.frameOwner(), hostRef.frameMethod(),
                HopKind.DIRECT_CALL, null, "bridge-source-deserialize",
                hostRef.frameDescriptor(), null));
        hops.add(new ChainHop(hostClass, hostMethod, hostClass, hostMethod,
                HopKind.ENTRY, null, "source", hostRef.descriptor(), null));
        return hops;
    }

    /** Typed source-host endpoint plus deferred composition payload. */
    record SourceHostedProducer(ApplicationEntryIndex.ProducerCandidate candidate,
                                Supplier<Chain> materializer) {
        SourceHostedProducer {
            candidate = Objects.requireNonNull(candidate, "candidate");
            materializer = ChainMaterializer.memoize(Objects.requireNonNull(materializer, "materializer"));
        }
    }

    private boolean applicationAnchoredHost(Blackboard target, DeserHost host,
                                           boolean hasApplicationRootInForwardSlice) {
        if (target == null || host == null || target.applicationEntryIndex() == null) {
            return false;
        }
        var index = target.applicationEntryIndex();
        if (!index.applicationScopeKnown() || !index.allowsDependencyExpansion()) {
            return false;
        }
        String key = host.owner() + "#" + host.method() + host.descriptor();
        return index.isApplicationOwner(host.owner())
                && index.isEntryForwardReachable(key)
                && hasApplicationRootInForwardSlice;
    }

    /**
     * Rank trigger fragments for the bounded source-host product.  Application provenance
     * is a universal signal: when a finite composition budget is unavoidable, a real class
     * from the primary artifact must not be displaced by a dependency's earlier sort key.
     * Callback semantics then prefer the most broadly realizable container trigger, with
     * resolved/short paths as deterministic tie breakers.  No package, class, or benchmark
     * name is consulted.
     */
    private int triggerPriority(Chain chain, Set<String> primaryClasses) {
        int score = 0;
        if (primaryClasses.contains(chain.entryClass())) {
            score += 32;
        }
        score += switch (chain.entryKind()) {
            case "hashCode" -> 12;
            case "equals" -> 10;
            case "compareTo" -> 8;
            case "compare" -> 7;
            case "toString" -> 5;
            default -> 0;
        };
        if (chain.hops().stream().anyMatch(hop -> "fragment".equals(hop.reason()))) {
            score += 8;
        }
        if (chain.unresolvedHops() == 0) {
            score += 4;
        }
        // A bounded source-host frontier should spend its first probes on the most
        // security-relevant continuation, not on whichever library happens to sort first.
        // This is expressed as capability-family risk (the same semantic categories used by
        // rules/reports), never as a package, benchmark, or gadget-name preference.
        score += triggerRiskScore(chain);
        return score;
    }

    private static int triggerRiskScore(Chain chain) {
        String sinkClass = chain.sinkClass() == null ? "" : chain.sinkClass();
        String category = chain.category() == null ? "" : chain.category();
        int score = switch (category) {
            case "JNDI", "REFLECTIVE_INVOKE" -> 12;
            case "CODE_EXEC" -> 8;
            case "DESERIALIZE" -> 6;
            default -> 0;
        };
        if (sinkClass.startsWith("javax/naming/") || sinkClass.contains("/jndi/")) {
            score += 8;
        } else if (sinkClass.startsWith("java/lang/Runtime")
                || sinkClass.startsWith("java/lang/ProcessBuilder")) {
            score += 8;
        } else if (sinkClass.startsWith("java/lang/reflect/")
                || sinkClass.startsWith("com/sun/org/apache/xalan")
                || sinkClass.startsWith("javax/xml/transform")) {
            score += 6;
        } else if (sinkClass.startsWith("java/net/")) {
            score += 3;
        }
        score += switch (chain.severity() == null ? "" : chain.severity()) {
            case "CRITICAL" -> 4;
            case "HIGH" -> 3;
            case "MEDIUM" -> 1;
            default -> 0;
        };
        return score;
    }

    /** Read only primary-artifact class names; nested dependency jars are intentionally excluded. */
    private Set<String> primaryArtifactClasses(Blackboard target) {
        if (target == null || target.scanInputs() == null) {
            return Set.of();
        }
        // The frontend already observed the target artifact while building the immutable
        // program model.  Reuse that ownership set when available instead of opening the
        // target a second time merely to prioritize source-host pairs.  Compatibility
        // blackboards without scope metadata retain the bounded legacy discovery below.
        if (target.scanInputs().applicationScopeKnown()) {
            return Set.copyOf(target.scanInputs().applicationClassNames());
        }
        Set<String> result = new LinkedHashSet<>();
        Path artifact = target.scanInputs().target();
        try {
            InputBudget.Tracker tracker = target.scanInputs().inputTracker();
            InputBudget policy = tracker == null ? InputBudget.defaults() : tracker.budget();
            result.addAll(boundedPrimaryArtifactClasses(artifact, policy, tracker));
        } catch (IOException e) {
            JustLogger.debug("读取主工件类归属失败，源宿主调度退回稳定排序: {}", e.getMessage());
        }
        return Set.copyOf(result);
    }

    /**
     * Bounded primary-artifact class-name discovery used only for deterministic source-host
     * prioritisation.  It deliberately excludes nested dependency jars and never affects chain
     * truth.  The helper is package-visible so the hostile-input contract can exercise the same
     * boundary without constructing a complete Blackboard.
     */
    static Set<String> boundedPrimaryArtifactClasses(Path target, InputBudget budget)
            throws IOException {
        InputBudget policy = budget == null ? InputBudget.defaults() : budget;
        return boundedPrimaryArtifactClasses(target, policy, policy.tracker());
    }

    /**
     * Discover primary-artifact classes while charging a caller-owned tracker.  Composition is
     * an optional priority hint, but it still reads attacker-controlled paths; accepting a
     * tracker from the scan boundary prevents this helper from resetting the aggregate entry,
     * byte and time budget after identity/frontend work.  The tracker policy is authoritative so
     * a mismatched convenience policy cannot widen the caller's limits.
     */
    static Set<String> boundedPrimaryArtifactClasses(Path target, InputBudget budget,
                                                      InputBudget.Tracker tracker)
            throws IOException {
        if (target == null) {
            throw new IOException("primary artifact is null");
        }
        InputBudget requested = budget == null ? InputBudget.defaults() : budget;
        InputBudget.Tracker accounting = tracker == null ? requested.tracker() : tracker;
        InputBudget policy = accounting.budget();
        Path root = target.toAbsolutePath().normalize();
        if (ArchiveLimits.isLinkOrReparsePoint(root)) {
            throw new IOException("primary artifact is a link or reparse point");
        }
        Set<String> result = new TreeSet<>();
        if (Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS)) {
            ArchiveLimits.DirectoryReadSnapshot snapshot = ArchiveLimits.snapshotDirectory(
                    root, policy, "PRIMARY_ARTIFACT");
            IOException failure = null;
            try (var stream = Files.walk(root)) {
                var iterator = stream.iterator();
                while (iterator.hasNext()) {
                    accounting.checkTime();
                    Path path = iterator.next();
                    Path normalized = path.toAbsolutePath().normalize();
                    if (!normalized.startsWith(root)
                            || ArchiveLimits.isLinkOrReparsePoint(path)) {
                        throw new IOException("primary artifact tree contains link or escapes root");
                    }
                    Path relativePath = root.relativize(normalized);
                    String relative = relativePath.toString().replace(File.separatorChar, '/');
                    BasicFileAttributes attributes = Files.readAttributes(path,
                            BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
                    if (relativePath.getNameCount() > policy.maxPathDepth()) {
                        throw new IOException("primary artifact path depth exceeds limit: "
                                + policy.maxPathDepth());
                    }
                    String accountingName = relative.isBlank() ? "<root>" : relative;
                    accounting.observeFile(accountingName,
                            attributes.isRegularFile() ? attributes.size() : 0L);
                    verifyPrimaryArtifactEntry(path, attributes);
                    if (attributes.isRegularFile()) {
                        String className = primaryClassName(relative);
                        if (className != null && result.size() < policy.maxClassEntries()) {
                            result.add(className);
                        } else if (className != null) {
                            throw new IOException("primary artifact class count exceeds limit: "
                                    + policy.maxClassEntries());
                        }
                    }
                }
            } catch (IOException readFailure) {
                failure = readFailure;
            }
            try {
                ArchiveLimits.verifyDirectoryUnchanged(snapshot, "PRIMARY_ARTIFACT");
            } catch (IOException identityFailure) {
                if (failure == null) {
                    failure = identityFailure;
                } else {
                    failure.addSuppressed(identityFailure);
                }
            }
            if (failure != null) {
                throw failure;
            }
        } else if (Files.isRegularFile(root, LinkOption.NOFOLLOW_LINKS)) {
            ArchiveLimits.FileReadSnapshot snapshot = ArchiveLimits.snapshotRegularFile(
                    root, policy, "PRIMARY_ARTIFACT");
            IOException failure = null;
            try {
                ArchiveLimits.checkContainerSize(root, policy);
                String name = root.getFileName().toString().toLowerCase(java.util.Locale.ROOT);
                if (name.endsWith(".class")) {
                    accounting.observeFile(root.getFileName().toString(),
                            snapshot.fileAttributes().size());
                    result.add(root.getFileName().toString().replaceFirst("\\.class$", ""));
                } else {
                    try (ArchiveLimits.ZipFileHandle handle = ArchiveLimits.openZipFile(snapshot,
                            "PRIMARY_ARTIFACT")) {
                        ZipFile jar = handle.zip();
                        Enumeration<? extends java.util.zip.ZipEntry> entries = jar.entries();
                        Set<String> seen = new HashSet<>();
                        while (entries.hasMoreElements()) {
                            accounting.checkTime();
                            java.util.zip.ZipEntry entry = entries.nextElement();
                            if (entry == null || !seen.add(entry.getName())
                                    || !ArchiveLimits.safeEntryName(entry.getName(), policy)) {
                                throw new IOException("invalid or duplicate primary archive entry");
                            }
                            accounting.observe(entry);
                            String className = primaryClassName(entry.getName());
                            if (className != null && result.size() < policy.maxClassEntries()) {
                                result.add(className);
                            } else if (className != null) {
                                throw new IOException("primary artifact class count exceeds limit: "
                                        + policy.maxClassEntries());
                            }
                        }
                    }
                }
            } catch (IOException readFailure) {
                failure = readFailure;
            }
            if (failure != null) {
                throw failure;
            }
        } else {
            throw new IOException("primary artifact is not a regular file or directory");
        }
        return Collections.unmodifiableSet(result);
    }

    /** Re-read one discovered entry so a replacement cannot silently influence prioritisation. */
    private static void verifyPrimaryArtifactEntry(Path path,
                                                   BasicFileAttributes before) throws IOException {
        if (path == null || before == null || ArchiveLimits.isLinkOrReparsePoint(path)) {
            throw new IOException("PRIMARY_ARTIFACT_CHANGED_DURING_READ");
        }
        BasicFileAttributes after = Files.readAttributes(path,
                BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        boolean same = before.isDirectory()
                ? ArchiveLimits.sameDirectoryIdentity(before, after)
                : ArchiveLimits.sameRegularFileIdentity(before, after);
        if (!same || ArchiveLimits.isLinkOrReparsePoint(path)) {
            throw new IOException("PRIMARY_ARTIFACT_CHANGED_DURING_READ");
        }
    }

    /** Package-local hostile contract seam; production discovery uses the same directory guard. */
    static ArchiveLimits.DirectoryReadSnapshot snapshotPrimaryArtifactForContract(Path target,
                                                                                    InputBudget budget)
            throws IOException {
        return ArchiveLimits.snapshotDirectory(target, budget, "PRIMARY_ARTIFACT");
    }

    /** Package-local hostile contract seam; production discovery uses the same directory guard. */
    static void verifyPrimaryArtifactDirectoryForContract(
            ArchiveLimits.DirectoryReadSnapshot snapshot) throws IOException {
        ArchiveLimits.verifyDirectoryUnchanged(snapshot, "PRIMARY_ARTIFACT");
    }

    /** Package-local hostile contract seam; production discovery uses the same entry guard. */
    static void verifyPrimaryArtifactEntryForContract(Path path,
                                                       BasicFileAttributes before)
            throws IOException {
        verifyPrimaryArtifactEntry(path, before);
    }

    /** Package-local hostile contract seam; production archive reads use the same file guard. */
    static ArchiveLimits.FileReadSnapshot snapshotPrimaryArtifactFileForContract(Path target,
                                                                                   InputBudget budget)
            throws IOException {
        return ArchiveLimits.snapshotRegularFile(target, budget, "PRIMARY_ARTIFACT");
    }

    /** Package-local hostile contract seam; production archive reads use the same file guard. */
    static void verifyPrimaryArtifactFileForContract(ArchiveLimits.FileReadSnapshot snapshot)
            throws IOException {
        ArchiveLimits.verifyRegularFileUnchanged(snapshot, "PRIMARY_ARTIFACT");
    }

    private static String primaryClassName(String entry) {
        if (entry == null || !entry.endsWith(".class") || entry.startsWith("META-INF/")) {
            return null;
        }
        for (String prefix : List.of("BOOT-INF/classes/", "WEB-INF/classes/")) {
            if (entry.startsWith(prefix)) {
                return entry.substring(prefix.length(), entry.length() - 6);
            }
        }
        if (entry.startsWith("BOOT-INF/lib/") || entry.startsWith("WEB-INF/lib/")) {
            return null;
        }
        return entry.substring(0, entry.length() - 6);
    }

    /**
     * Read the immutable source-host projection built by {@link ApplicationEntryIndex}.
     * Source/rule matching and subtype-aware ObjectInputStream recognition belong to that
     * index owner; composition must not rescan raw CPG calls and reconstruct a second site
     * model for every event.  The finite host cap remains local to this composition consumer.
     */
    private Map<String, DeserHost> scanHosts(Blackboard target) {
        if (target == null || target.applicationEntryIndex() == null) {
            return Map.of();
        }
        Map<String, DeserHost> hosts = new java.util.TreeMap<>();
        for (ApplicationEntryIndex.DeserializeHost sourceHost
                : target.applicationEntryIndex().deserializeHosts()) {
            if (sourceHost == null) {
                continue;
            }
            if (hosts.size() >= MAX_SOURCE_HOSTS) {
                target.markIncomplete("SOURCE_HOST_CAP:" + MAX_SOURCE_HOSTS);
                continue;
            }
            // ApplicationEntryIndex already owns the JDK/plumbing and same-package filters;
            // this consumer only applies its local cap and converts the immutable projection.
            hosts.putIfAbsent(sourceHost.hostMethodKey(),
                    new DeserHost(sourceHost.hostOwner(), sourceHost.hostName(),
                            sourceHost.hostDescriptor(), sourceHost.frameOwner(),
                            sourceHost.frameMethod(), sourceHost.frameDescriptor()));
        }
        return Map.copyOf(hosts);
    }

    private static boolean isPublicEntry(Chain chain) {
        return isPublicEntry(chain.entryKind())
                || ("deserialize".equals(chain.entryKind())
                && chain.hops().stream().anyMatch(hop -> hop.kind() == HopKind.ENTRY
                && "framework-bean-input".equals(hop.reason())));
    }

    private FrontFeatures frontFeatures(Blackboard target, Chain front) {
        String frontSink = front.sinkClass() + "." + front.sinkMethod();
        return new FrontFeatures(
                "java/lang/reflect/Method.invoke".equals(frontSink),
                triggerContainerOnPath(front),
                onPath(front, "com/sun/org/apache/xalan/internal/xsltc/trax/TemplatesImpl"),
                "DESERIALIZE".equals(front.category()),
                isJndiRmiBridge(target, front),
                isJdbcDriverBridge(target, front));
    }

    /**
     * Reuse one front capability projection for the bounded application-priority pass.
     *
     * <p>The projection is event-local: a reused source instance must observe a new
     * Blackboard/ruleset on the next event, while repeated consumers in one pass avoid
     * rescanning the same chain hops and rule bridge metadata.</p>
     */
    private FrontFeatures frontFeaturesCached(Blackboard target, Chain front,
                                              Map<String, FrontFeatures> cache) {
        if (front == null) {
            return new FrontFeatures(false, null, false, false, false, false);
        }
        if (cache == null || front.key() == null || front.key().isBlank()) {
            return frontFeatures(target, front);
        }
        FrontFeatures cached = cache.get(front.key());
        if (cached != null) {
            return cached;
        }
        FrontFeatures computed = frontFeatures(target, front);
        cache.put(front.key(), computed);
        return computed;
    }

    /** Resolve the rule's typed bridge axis; a legacy JNDI terminal bit alone is insufficient. */
    private boolean isJndiRmiBridge(Blackboard target, Chain front) {
        if (front == null || target == null) {
            return false;
        }
        Rule.SinkRule sink = target.rules().sinks().stream()
                .filter(rule -> rule.id().equals(front.ruleId()))
                .findFirst().orElseGet(() -> target.ruleEngine()
                        .matchingSink(front.sinkClass(), front.sinkMethod(), front.sinkDescriptor())
                        .orElse(null));
        boolean result = sink != null && RuleSchemaV2.bridgesFor(sink)
                .contains(RuleSchemaV2.Bridge.JNDI_RMI)
                && !RuleSchemaV2.isTerminalSink(sink);
        return result;
    }

    /** JDBC connect/getConnection is an intermediate protocol boundary, never a terminal. */
    private boolean isJdbcDriverBridge(Blackboard target, Chain front) {
        if (front == null || target == null) {
            return false;
        }
        Rule.SinkRule sink = target.rules().sinks().stream()
                .filter(rule -> rule != null && rule.id().equals(front.ruleId()))
                .findFirst().orElseGet(() -> target.ruleEngine()
                        .matchingSink(front.sinkClass(), front.sinkMethod(), front.sinkDescriptor())
                        .orElse(null));
        return sink != null && RuleSchemaV2.bridgesFor(sink)
                .contains(RuleSchemaV2.Bridge.JDBC_DRIVER)
                && !RuleSchemaV2.isTerminalSink(sink);
    }

    private static boolean isDeclaredFragment(Chain chain) {
        return chain != null && chain.constructionPlan() != null
                && !chain.constructionPlan().isEmpty()
                && isFragmentChain(chain);
    }

    /**
     * A rule-owned static continuation is admitted by its declaration, not by a class-name
     * branch in the composer.  The fragment must carry a bounded valid construction shape,
     * resolve all declared hops, and end in a terminal sink role.  Its activation axis is
     * consumed by the semantic bridge that selects it (invoke, JDBC, deserialize, and so on).
     */
    private static boolean isDeclaredContinuationFragment(Chain chain) {
        return isDeclaredFragment(chain)
                && chain.unresolvedHops() == 0
                && chain.constructionPlan().shapeSummary().valid()
                && chain.terminalSink()
                && chain.sinkClass() != null && !chain.sinkClass().isBlank()
                && chain.sinkMethod() != null && !chain.sinkMethod().isBlank();
    }

    /** Exact minimal receiver endpoint; unlike a generic public entry it is invoke-only. */
    private static boolean isDeclaredDirectFragment(Chain chain) {
        if (!isDeclaredFragment(chain)
                || !"reflectiveTarget".equals(chain.entryKind())
                || !chain.entryClass().equals(chain.sinkClass())
                || !chain.entryMethod().equals(chain.sinkMethod())
                || !chain.sinkDescriptor().equals(entryDescriptor(chain))
                || chain.hops().size() != 1
                || chain.hops().get(0).kind() != HopKind.ENTRY
                || !activationAllows(chain, "invoke")
                || chain.constructionPlan() == null
                || !chain.constructionPlan().shapeSummary().valid()) {
            return false;
        }
        return chain.constructionPlan().nodes().stream().anyMatch(node -> node != null
                && "entry".equals(node.id()) && chain.entryClass().equals(node.type()));
    }

    /**
     * Deferred candidates expose only endpoint metadata.  Keep a declaration-backed direct
     * endpoint in the demand frontier without pretending that the endpoint itself is an
     * application entry; the later semantic bridge still requires the proven source/callback
     * facts from the application front.
     */
    private static boolean isDeclaredDirectCandidate(
            ApplicationEntryIndex.ProducerCandidate candidate) {
        return candidate != null && candidate.declaredFragmentContinuation()
                && "reflectiveTarget".equals(candidate.entryKind())
                && candidate.entryOwner().equals(candidate.terminalOwner())
                && candidate.entryName().equals(candidate.terminalName())
                && candidate.entryDescriptor().equals(candidate.terminalDescriptor());
    }

    private static boolean isDeclaredStaticFragmentTerminal(Chain chain) {
        return isDeclaredContinuationFragment(chain) || isDeclaredDirectFragment(chain)
                || isDeclaredSecondaryDeserializationFragment(chain);
    }

    /**
     * A secondary-deserialization fragment is a typed continuation even when its first sink is
     * the capability-shaped ObjectInput.readObject rather than a terminal impact.  The fragment
     * producer has already proved the concrete nested stream endpoint from bytecode; this
     * predicate only preserves that declaration through application composition. It is
     * independent of artifact ownership so an application-packaged helper can serve the same
     * semantic role as a library helper.
     */
    private static boolean isDeclaredSecondaryDeserializationFragment(Chain chain) {
        return chain != null
                && "secondDeserialization".equals(chain.entryKind())
                && isFragmentChain(chain)
                && chain.unresolvedHops() == 0
                && ("java/io/ObjectInput".equals(chain.sinkClass())
                || "java/io/ObjectInputStream".equals(chain.sinkClass()))
                && "readObject".equals(chain.sinkMethod())
                && activationAllows(chain, "deserialize");
    }

    private static boolean isFragmentChain(Chain chain) {
        return chain != null && chain.hops().stream().anyMatch(hop -> hop != null
                && ("fragment".equals(hop.reason())
                || (hop.reason() != null && hop.reason().startsWith("fragment-activation-"))));
    }

    private static boolean isTypedNestedDeserializationFront(Chain chain) {
        if (chain == null || !"DESERIALIZE".equalsIgnoreCase(chain.category())
                || !"readObject".equals(chain.sinkMethod())) {
            return false;
        }
        if (!"java/io/ObjectInput".equals(chain.sinkClass())
                && !"java/io/ObjectInputStream".equals(chain.sinkClass())) {
            return false;
        }
        return chain.hops().stream().anyMatch(hop -> hop != null && hop.reason() != null
                && hop.reason().startsWith("fragment-activation-"));
    }

    /**
     * A declarative fragment may require one concrete activation mechanism.  The marker is
     * carried by the fragment hops so the immutable Chain model does not need a second mutable
     * rule side table.  Older fragments have no marker and retain their unrestricted behavior.
     */
    private static boolean activationAllows(Chain chain, String activation) {
        if (chain == null || activation == null || activation.isBlank()) {
            return false;
        }
        String required = null;
        for (ChainHop hop : chain.hops()) {
            if (hop == null || hop.reason() == null
                    || !hop.reason().startsWith("fragment-activation-")) {
                continue;
            }
            String value = hop.reason().substring("fragment-activation-".length());
            if (required != null && !required.equals(value)) {
                return false;
            }
            required = value;
        }
        return required == null || required.equals(activation);
    }

    private static boolean hasExplicitFragmentActivation(Chain chain, String activation) {
        if (chain == null || activation == null || activation.isBlank()) {
            return false;
        }
        String marker = "fragment-activation-" + activation;
        return chain.hops().stream().anyMatch(hop -> hop != null && marker.equals(hop.reason()));
    }

    /**
     * A serialization callback is entered by the serialization mechanism, not by an
     * arbitrary reflective Method value. The fallback invoke bridge has no receiver/name
     * identity, so accepting these entries would turn a generic Method.invoke capability into
     * an unrelated deserialization suffix. A declared fragment may opt in explicitly when its
     * contract really models a reflective selection of that callback.
     */
    private static boolean isSerializationCallbackEntry(Chain chain) {
        if (chain == null || !SERIALIZATION_CALLBACK_ENTRY_KINDS.contains(chain.entryKind())) {
            return false;
        }
        String descriptor = entryDescriptor(chain);
        return switch (chain.entryKind()) {
            case "readObject" -> "(Ljava/io/ObjectInputStream;)V".equals(descriptor);
            case "readExternal" -> "(Ljava/io/ObjectInput;)V".equals(descriptor);
            case "readResolve" -> "()Ljava/lang/Object;".equals(descriptor);
            case "readObjectNoData", "validateObject" -> "()V".equals(descriptor);
            default -> false;
        };
    }

    private List<Chain> candidateBacks(FrontFeatures features, List<Chain> publicEntries,
                                       List<Chain> triggerEntries, List<Chain> templateEntries,
                                       List<Chain> fragmentEntries) {
        if ((features.invoke() || features.deserialize()) && features.triggerContainer() == null
                && !features.template()) {
            return publicEntries;
        }
        Set<Chain> candidates = new LinkedHashSet<>();
        if (features.invoke() || features.deserialize()) {
            candidates.addAll(publicEntries);
        }
        if (features.triggerContainer() != null) {
            candidates.addAll(triggerEntries);
        }
        if (features.template()) {
            candidates.addAll(templateEntries);
        }
        if (features.jndiRmi()) {
            candidates.addAll(fragmentEntries);
        }
        if (features.jdbc()) {
            candidates.addAll(fragmentEntries);
        }
        return candidates.isEmpty() ? List.of() : List.copyOf(candidates);
    }

    /** 判断前段链的 sink 能否语义上触发后段链的 entry。 */
    private Bridge semanticBridge(Blackboard target, FrontFeatures features, Chain front,
                                  Chain back) {
        String backKind = back.entryKind();
        String backEntry = back.entryClass() + "." + back.entryMethod();

        // 1. INVOKE 桥：前段 sink 是 Method.invoke → 可调任意公共方法
        // The direct Templates endpoint is narrower than that generic rule: the front must
        // carry both the deserialization source and serialized-container callback facts, so a
        // standalone reflective capability cannot manufacture an impact chain.
        if (features.invoke() && isDeclaredDirectFragment(back)
                && isDeserializationDrivenInvokeFront(front)
                && activationAllows(back, "invoke")) {
            return Bridge.INVOKE;
        }
        if (features.invoke()
                && isPublicEntry(back)
                && activationAllows(back, "invoke")
                && (!isSerializationCallbackEntry(back)
                || hasExplicitFragmentActivation(back, "invoke"))
                // activationAllows rejects a fragment that explicitly declares another axis;
                // an unmarked fragment is the rule's reusable, activation-agnostic object
                // graph and remains eligible for a typed public-method bridge.
                ) {
            return Bridge.INVOKE;
        }

        // 2. TRIGGER 桥：前段路径含触发容器，且后段入口类可放入容器的 key/元素槽
        // （有序容器 TreeMap/PriorityQueue 的槽位要求 Comparable——不可比较的入口类放不进去，
        //   桥不成立；HashMap/HashSet/Hashtable 的 key 槽为 Object 不限）
        if (features.triggerContainer() != null && isTriggerEntry(backKind)
                && keySlotAccepts(target, features.triggerContainer(), back.entryClass())) {
            return Bridge.TRIGGER;
        }

        // 3. TEMPLATE 桥：前段路径含 TemplatesImpl → 后段 entry 触发其 getter
        if (features.template()
                && isTemplateTrigger(backEntry)) {
            return Bridge.TEMPLATE;
        }

        // 4. DESER 桥：前段 sink 是二次反序列化 → 其产物字节流再被反序列化，触发后段机制入口
        if (features.deserialize() && isPublicEntry(back)
                && activationAllows(back, "deserialize")) {
            return Bridge.DESER;
        }

        // JNDI lookup returns a remote reference/object; the RMI response can re-enter an
        // object graph and invoke a declared callback fragment.  Require a versioned fragment
        // construction plan and a callback-shaped entry so an arbitrary lookup chain cannot
        // be paired with an unrelated sink by class-name coincidence.
        if (features.jndiRmi() && isDeclaredFragment(back)
                && isPublicEntry(back) && back.unresolvedHops() == 0) {
            return Bridge.JNDI_RMI;
        }

        // JDBC connect selects an implementation whose configuration may instantiate a
        // declarative XML context.  The fragment is accepted only when its exact static
        // class-definition boundary and bounded object shape were materialized above.
        if (features.jdbc() && isDeclaredContinuationFragment(back)
                && activationAllows(back, "jdbc")) {
            return Bridge.JDBC_XML;
        }
        return null;
    }

    private static boolean isDeserializationDrivenInvokeFront(Chain front) {
        if (front == null) {
            return false;
        }
        boolean source = false;
        boolean callback = false;
        for (ChainHop hop : front.hops()) {
            if (hop == null || hop.reason() == null) {
                continue;
            }
            String reason = hop.reason();
            source |= "bridge-source-deserialize".equals(reason)
                    || reason.startsWith("bridge-source-");
            callback |= "bridge-trigger-src".equals(reason)
                    || reason.startsWith("serialized-trigger");
        }
        return source && callback;
    }

    private static boolean isPublicEntry(String entryKind) {
        return PUBLIC_ENTRY_KINDS.contains(entryKind);
    }

    private static boolean isTriggerEntry(String entryKind) {
        return TRIGGER_ENTRY_KINDS.contains(entryKind);
    }

    private static boolean isTemplateTrigger(String entryMethod) {
        return entryMethod.contains("getOutputProperties") || entryMethod.contains("newTransformer");
    }

    private static String entryDescriptor(Chain chain) {
        for (ChainHop hop : chain.hops()) {
            if (hop.kind() == HopKind.ENTRY && hop.desc() != null) {
                return hop.desc();
            }
        }
        return "";
    }

    /** 前段链路径经过的触发容器（HashMap/HashSet/Hashtable/TreeMap/TreeSet/PriorityQueue），无则 null。 */
    private static String triggerContainerOnPath(Chain chain) {
        for (ChainHop hop : chain.hops()) {
            String owner = hop.toOwner();
            if (owner.startsWith("java/util/HashMap") || owner.startsWith("java/util/HashSet")
                    || owner.startsWith("java/util/Hashtable") || owner.startsWith("java/util/TreeMap")
                    || owner.startsWith("java/util/TreeSet")
                    || owner.startsWith("java/util/concurrent/PriorityQueue")) {
                return owner;
            }
        }
        return null;
    }

    /** 后段入口类能否放入容器的 key/元素槽：有序容器要求 Comparable。 */
    private boolean keySlotAccepts(Blackboard target, String container, String entryClass) {
        if (container.startsWith("java/util/TreeMap") || container.startsWith("java/util/TreeSet")
                || container.startsWith("java/util/concurrent/PriorityQueue")) {
            return target != null && target.hierarchy().isSubtypeOf(entryClass, "java/lang/Comparable");
        }
        return true;
    }

    private static boolean onPath(Chain chain, String className) {
        if (chain.entryClass().startsWith(className)) {
            return true;
        }
        for (ChainHop hop : chain.hops()) {
            if (hop.fromOwner().startsWith(className) || hop.toOwner().startsWith(className)) {
                return true;
            }
        }
        return false;
    }

    /** 组装：front 的跳（截至桥接点）+ 桥接跳 + back 的跳（去 back 的入口自跳）。 */
    private Chain compose(Chain front, Chain back, Bridge bridge) {
        List<ChainHop> hops = new ArrayList<>();
        // back 的跳（sink-first，去末位 ENTRY 自跳）
        for (int i = 0; i < back.hops().size() - 1; i++) {
            hops.add(back.hops().get(i));
        }
        // 桥接跳：front.sink → back.entry
        hops.add(new ChainHop(front.sinkClass(), front.sinkMethod(),
                back.entryClass(), back.entryMethod(),
                HopKind.DIRECT_CALL, null, "bridge-" + bridge.name().toLowerCase(), "", null));
        // front 的跳（含 ENTRY 自跳）
        hops.addAll(front.hops());
        if (hops.size() > MAX_HOPS) {
            return null;
        }
        return new Chain(back.ruleId(), back.category(), back.severity(),
                front.entryClass(), front.entryMethod(), front.entryKind(),
                back.sinkClass(), back.sinkMethod(), hops,
                front.unresolvedHops() + back.unresolvedHops(), back.sinkDescriptor(), back.sinkRole(),
                constructionPlanOf(back, front), back.sinkRisk());
    }

    /**
     * Admit a composed candidate through the typed owner before exposing its path payload.
     * Compatibility callers without a known application scope retain the historical
     * composition store; production scans use the lazy candidate route and therefore never
     * construct a rejected dependency-only composition.
     */
    Chain admitComposed(Blackboard target, ComposedProducer producer) {
        if (producer == null || target == null) {
            return null;
        }
        if (!target.applicationEntryIndex().applicationScopeKnown()) {
            Blackboard.SolverAdmissionResult result = target.admitCompatibilityCandidate(
                    producer.candidate(), producer.materializer());
            return result.accepted() ? result.chain() : null;
        }
        return admitEagerCompositionCandidate(target, producer.candidate(),
                producer.materializer());
    }

    /** Build only the typed endpoints; the bridge path remains behind the supplier. */
    ComposedProducer composedProducer(Chain front, Chain back, Bridge bridge) {
        if (bridge == null) {
            return null;
        }
        return composedProducer(front, back, () -> compose(front, back, bridge),
                bridge == Bridge.JDBC_XML);
    }

    private ComposedProducer composedProducer(Chain front, Chain back,
                                              Supplier<Chain> materializer) {
        return composedProducer(front, back, materializer, false);
    }

    private ComposedProducer composedProducer(Chain front, Chain back,
                                              Supplier<Chain> materializer,
                                              boolean declaredApplicationContinuation) {
        if (front == null || back == null || materializer == null) {
            return null;
        }
        boolean declaredFragmentContinuation = isDeclaredStaticFragmentTerminal(back);
        ApplicationEntryIndex.ProducerCandidate candidate =
                new ApplicationEntryIndex.ProducerCandidate(back.ruleId(), back.category(),
                        back.severity(), front.entryClass(), front.entryMethod(),
                        entryDescriptor(front), front.entryKind(), back.sinkClass(),
                        back.sinkMethod(), back.sinkDescriptor(), back.sinkRole(),
                        back.sinkRisk(), true,
                        declaredApplicationContinuation || declaredFragmentContinuation,
                        declaredFragmentContinuation);
        return new ComposedProducer(candidate, materializer);
    }

    /** Typed composition endpoint plus deferred bridge payload. */
    record ComposedProducer(ApplicationEntryIndex.ProducerCandidate candidate,
                            Supplier<Chain> materializer) {
        ComposedProducer {
            candidate = Objects.requireNonNull(candidate, "candidate");
            materializer = ChainMaterializer.memoize(Objects.requireNonNull(materializer, "materializer"));
        }
    }

    /** Preserve the declarative gadget plan while composing a source prefix with a fragment.
     * The back chain is normally the fragment; the front fallback keeps extension-created
     * plans visible without inventing a merged executable graph. */
    private static io.just.sast.blackboard.ObjectGraphPlan constructionPlanOf(Chain back,
                                                                                Chain front) {
        if (back != null && back.constructionPlan() != null) {
            return back.constructionPlan();
        }
        return front == null ? null : front.constructionPlan();
    }
}
