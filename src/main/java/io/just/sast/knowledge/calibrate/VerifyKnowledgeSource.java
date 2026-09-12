package io.just.sast.knowledge.calibrate;

import io.just.sast.blackboard.Blackboard;
import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.EntryChainJoinEvidence;
import io.just.sast.blackboard.Event;
import io.just.sast.blackboard.EventType;
import io.just.sast.blackboard.FindingId;
import io.just.sast.blackboard.FindingState;
import io.just.sast.blackboard.KnowledgeSource;
import io.just.sast.blackboard.Phase;
import io.just.sast.blackboard.RunProduct;
import io.just.sast.blackboard.VerificationOutcome;
import io.just.sast.blackboard.VerificationCoverage;
import io.just.sast.blackboard.VerificationSummary;
import io.just.sast.analysis.entry.ApplicationChainEvidence;
import io.just.sast.analysis.entry.ApplicationChainJoiner;
import io.just.sast.chain.ConfidenceScorer;
import io.just.sast.util.JustLogger;
import io.just.sast.verify.NestedClasspath;
import io.just.sast.verify.ParallelVerifier;
import io.just.sast.verify.PayloadConstructor;
import io.just.sast.verify.VerificationPlan;
import io.just.sast.run.InputBudget;

import java.nio.file.Path;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * 动态验证知识源（CALIBRATION priority 500）：
 * Phase 1: 构造可行性检查（快速筛选）
 * Phase 2: 并行子进程验证（预编译探针 + 4 路并行 + sink-boundary 证据）
 */
public final class VerifyKnowledgeSource implements KnowledgeSource {

    private Blackboard bb;
    private PayloadConstructor constructor;
    private URLClassLoader payloadLoader;
    private NestedClasspath payloadClasspath;

    @Override
    public String id() {
        return "verify";
    }

    @Override
    public Set<EventType> interests() {
        return Set.of(EventType.SCAN_COMPLETE);
    }

    @Override
    public Phase phase() {
        return Phase.CALIBRATION;
    }

    @Override
    public int priority() {
        return 500;
    }

    @Override
    public Set<RunProduct> requiresProducts() {
        return Set.of(RunProduct.CALIBRATED_CHAINS);
    }

    @Override
    public Set<RunProduct> providesProducts() {
        return Set.of(RunProduct.VERIFICATION_RESULTS);
    }

    @Override
    public void init(Blackboard blackboard) {
        this.bb = blackboard;
    }

    @Override
    public void onEvent(Blackboard bb, Event event) {
        if (event.type() != EventType.SCAN_COMPLETE) {
            return;
        }
        long verificationStarted = System.nanoTime();
        // Build the typed application-entry/dependency join before selecting any dynamic work.
        // This product is evidence only: unjoined static chains remain visible and are not
        // silently calibrated away.  The joined keys receive the bounded primary quota below.
        ApplicationChainEvidence applicationEvidence = ApplicationChainJoiner.build(bb);
        bb.publishFact(applicationEvidence);
        Set<String> applicationJoinedKeys = applicationEvidence.joinedChainKeys();
        List<Chain> candidates = bb.chains().stream()
                .filter(c -> bb.calibrationOf(c.key()) == null)
                .toList();
        // Dynamic verification operates on one deterministic representative per normalized
        // application finding group.  Static candidates remain untouched and are still used
        // for evidence/reporting; this list is only the light second-pass work queue.
        List<Chain> dynamicCandidates = eligibleRepresentativeChains(applicationEvidence,
                candidates);
        if (!bb.scanInputs().verify()) {
            bb.publishFact(VerificationPlan.empty(0));
            bb.publishFact(buildCoverage(bb, applicationEvidence, candidates, List.of(), List.of(),
                    false, VerificationCoverage.Status.NOT_REQUESTED));
            bb.setVerificationStatus("STATIC_ONLY");
            bb.setVerificationResourceMetrics(java.util.Map.of());
            bb.setVerificationSummary(VerificationSummary.empty(
                    "STATIC_ONLY", 0));
            bb.recordPhaseMs("verify", 0L);
            JustLogger.info("静态分析模式：验证调度已禁用，目标代码不会加载");
            return;
        }
        int budget = bb.scanInputs().verifyBudget();
        if (budget <= 0) {
            bb.publishFact(VerificationPlan.empty(budget));
            bb.publishFact(buildCoverage(bb, applicationEvidence, candidates, List.of(), List.of(),
                    false, VerificationCoverage.Status.NOT_REQUESTED));
            bb.setVerificationStatus("NOT_RUN");
            bb.setVerificationResourceMetrics(java.util.Map.of());
            bb.setVerificationSummary(VerificationSummary.empty("NOT_RUN", budget));
            bb.recordPhaseMs("verify", java.util.concurrent.TimeUnit.NANOSECONDS
                    .toMillis(System.nanoTime() - verificationStarted));
            return;
        }
        // Dynamic verification is a finite experiment.  Select a cheap, deterministic seed
        // before opening the target classpath: the old implementation reflected every unique
        // entry class even when the entry could never consume the finite child-process budget.
        // Construction remains an evidence refinement, never a soundness gate, so deferred
        // entries stay visible to static reporting and are not calibrated away.
        ParallelVerifier verifier = null;
        long verifierInitStarted = System.nanoTime();
        try {
            verifier = new ParallelVerifier(bb.scanInputs().target(), bb.scanInputs().deps(),
                    bb.scanInputs().jdkHome(), bb.scanInputs().targetMajorVersion(),
                    bb.scanInputs().safeExec(), bb.scanInputs().safeReal(),
                    bb.scanInputs().requireOsIsolation(),
                    (chain, detail, sinkReached) -> {
                        if (sinkReached) {
                            JustLogger.info("  ✓ dynamic sink evidence: {}#{} → {}.{}  [{}]",
                                    chain.entryClass().replace('/', '.'), chain.entryMethod(),
                                    chain.sinkClass().replace('/', '.'), chain.sinkMethod(), detail);
                        }
                    });
            bb.recordPhaseMs("verify.init", java.util.concurrent.TimeUnit.NANOSECONDS
                    .toMillis(System.nanoTime() - verifierInitStarted));
        } catch (RuntimeException | LinkageError verifierFailure) {
            bb.publishFact(VerificationPlan.empty(budget));
            bb.publishFact(buildCoverage(bb, applicationEvidence, candidates, List.of(), List.of(),
                    false, VerificationCoverage.Status.PARTIAL_DYNAMIC_FAILURE));
            bb.markIncomplete("VERIFY_INITIALIZATION");
            bb.setVerificationStatus("UNTESTABLE");
            bb.setVerificationResourceMetrics(java.util.Map.of());
            bb.setVerificationSummary(VerificationSummary.empty("UNTESTABLE", budget));
            JustLogger.debug("验证器初始化失败: {}", verifierFailure.getMessage());
            bb.recordPhaseMs("verify", java.util.concurrent.TimeUnit.NANOSECONDS
                    .toMillis(System.nanoTime() - verificationStarted));
            return;
        }
        // The Job Object is the only admissible child boundary. When it is unavailable, do not
        // reflectively construct target objects just to reach the same UNTESTABLE result; keep
        // the static candidates and publish the precise host limitation immediately.
        if (!verifier.osIsolationReady()) {
            bb.setVerificationResourceMetrics(java.util.Map.of());
            long selectionStarted = System.nanoTime();
            VerificationPlan plan = verifier.planChains(dynamicCandidates, budget, Set.of(),
                    applicationJoinedKeys);
            bb.publishFact(plan);
            List<Chain> selected = plan.selectedChains();
            bb.publishFact(buildCoverage(bb, applicationEvidence, candidates, selected, List.of(),
                    false, VerificationCoverage.Status.ISOLATION_UNAVAILABLE));
            bb.recordPhaseMs("verify.select", java.util.concurrent.TimeUnit.NANOSECONDS
                    .toMillis(System.nanoTime() - selectionStarted));
            String detail = verifier.isolationUnavailableDetail();
            List<ParallelVerifier.VerifyResult> blocked = selected.stream()
                    .map(verifier::isolationUnavailableResult)
                    .toList();
            for (Chain chain : selected) {
                bb.chainNote(chain.key(), "degrade:verify-untestable");
            }
            bb.setVerificationStatus(verifier.hostCapability());
            java.util.Map<String, Integer> details = new java.util.LinkedHashMap<>();
            details.put(detailKey(detail), blocked.size());
            bb.setVerificationSummary(summary(bb, verifier, selected, blocked,
                    0, 0, budget, details));
            bb.recordPhaseMs("verify", java.util.concurrent.TimeUnit.NANOSECONDS
                    .toMillis(System.nanoTime() - verificationStarted));
            verifier.cleanup();
            return;
        }
        long seedSelectionStarted = System.nanoTime();
        VerificationPlan seedPlan = verifier.planChains(dynamicCandidates, budget, Set.of(),
                applicationJoinedKeys);
        bb.publishFact(seedPlan);
        List<Chain> seedChains = seedPlan.selectedChains();
        bb.recordPhaseMs("verify.select.seed", java.util.concurrent.TimeUnit.NANOSECONDS
                .toMillis(System.nanoTime() - seedSelectionStarted));
        int constructible = 0;
        int rejected = 0;
        Set<String> constructibleKeys = new HashSet<>();
        java.util.Map<String, Integer> skipReasons = new java.util.LinkedHashMap<>();
        java.util.Map<String, PayloadConstructor.ConstructionResult> constructionByEntry =
                new java.util.HashMap<>();
        long constructionStarted = System.nanoTime();
        try {
            if (!seedChains.isEmpty()) {
                this.payloadLoader = targetClassLoader(bb);
                this.constructor = new PayloadConstructor(payloadLoader);
                for (Chain chain : seedChains) {
                    String dotted = chain.entryClass().replace('/', '.');
                    constructionByEntry.computeIfAbsent(dotted, constructor::tryConstruct);
                }
            }
            // A result is keyed by entry class, so publish it to every equivalent candidate
            // after the bounded pass.  This preserves accurate evidence for variants without
            // paying the reflection cost for entries that were never eligible for verification.
            for (Chain chain : candidates) {
                String dotted = chain.entryClass().replace('/', '.');
                PayloadConstructor.ConstructionResult result = constructionByEntry.get(dotted);
                if (result == null) {
                    bb.chainNote(chain.key(), "verify:construction-deferred");
                    continue;
                }
                switch (result.verdict()) {
                    case "CONSTRUCTIBLE" -> {
                        bb.chainNote(chain.key(), "verify:constructible");
                        constructibleKeys.add(chain.key());
                        constructible++;
                    }
                    case "PARTIALLY_CONSTRUCTIBLE" ->
                            bb.chainNote(chain.key(), "degrade:partial-construct");
                    case "SKIP" -> // 按原因类别聚合（detail 含类名，逐类输出会过长）
                            skipReasons.merge(result.detail() != null
                                    ? result.detail().split(":")[0] : "skip", 1, Integer::sum);
                    default -> {
                        bb.calibrateChain(chain.key(), "not-constructible");
                        rejected++;
                    }
                }
            }
            int distinctEntries = (int) candidates.stream().map(c -> c.entryClass().replace('/', '.'))
                    .distinct().count();
            int deferredEntries = Math.max(0, distinctEntries - constructionByEntry.size());
            if (deferredEntries > 0) {
                skipReasons.merge("budget-deferred", deferredEntries, Integer::sum);
                JustLogger.debug("构造可行性延迟 {} 个入口类型（候选 {}，种子 {}）",
                        deferredEntries, candidates.size(), seedChains.size());
            }
        } catch (RuntimeException | LinkageError constructionFailure) {
            // Construction is a per-chain capability check.  A malformed optional
            // dependency or reflective edge must not abort the verification phase or
            // discard the summary for chains that were already classified.
            bb.markIncomplete("VERIFY_CONSTRUCTION_ERROR");
            skipReasons.merge("construction-error", 1, Integer::sum);
            JustLogger.debug("构造可行性检查中断，保留已收集结果: {}",
                    constructionFailure.getMessage());
        } finally {
            closePayloadLoader();
            bb.recordPhaseMs("verify.construct", java.util.concurrent.TimeUnit.NANOSECONDS
                    .toMillis(System.nanoTime() - constructionStarted));
        }
        // 不可检查类聚合报告（抽象/不在类路径——探针能力边界可见化）
        if (!skipReasons.isEmpty()) {
            JustLogger.info("构造可行性边界：{} 项（{}）", skipReasons.values().stream().mapToInt(Integer::intValue).sum(),
                    skipReasons.entrySet().stream().map(e -> e.getKey() + "×" + e.getValue())
                            .reduce((a, b) -> a + ", " + b).orElse(""));
        }

        int confirmed = 0;
        int prefixConfirmed = 0;
        int realSinks = 0;
        int jniSinks = 0;
        int safeEffects = 0;
        int executed = 0;
        int partial = 0;
        int failed = 0;
        int untestable = 0;
        int timeout = 0;
        java.util.Map<String, Integer> verificationDetails = new java.util.LinkedHashMap<>();
        List<Chain> selectedChains = List.of();
        List<ParallelVerifier.VerifyResult> verificationResults = List.of();
        boolean attemptsLaunched = false;
        VerificationCoverage.Status coverageStatus = VerificationCoverage.Status.PARTIAL_DYNAMIC_FAILURE;
        try {
                // entryKind=source 的完整链也进入隔离探针。探针使用统一的受限默认参数
                // 适配器验证宿主是否真实执行；这不是攻击者 payload 生成。只有同一候选
                // 到达 sink canary 边界才能得到 SINK_BLOCKED。
                long finalSelectionStarted = System.nanoTime();
                VerificationPlan finalPlan = verifier.planChains(dynamicCandidates.stream()
                        .filter(c -> bb.calibrationOf(c.key()) == null).toList(), budget,
                        constructibleKeys, applicationJoinedKeys);
                bb.publishFact(finalPlan);
                List<Chain> topChains = finalPlan.selectedChains();
                bb.recordPhaseMs("verify.select.final", java.util.concurrent.TimeUnit.NANOSECONDS
                        .toMillis(System.nanoTime() - finalSelectionStarted));
                selectedChains = topChains;
                coverageStatus = topChains.isEmpty()
                        ? VerificationCoverage.Status.NO_ELIGIBLE_GROUP
                        : VerificationCoverage.Status.COMPLETE;

                JustLogger.info("子进程链级验证（{} 条 / 预算 {}，{} 路并行，入口/风险面去重≤{}/组）...",
                        topChains.size(), budget, 4, 2);

                attemptsLaunched = !topChains.isEmpty();
                List<ParallelVerifier.VerifyResult> results = verifier.verifyAll(topChains);
                verificationResults = results;
                for (var timing : verifier.phaseTimings().entrySet()) {
                    bb.recordPhaseMs("verify." + timing.getKey(), timing.getValue());
                }
                bb.setVerificationStatus(verifier.capability());
                for (int i = 0; i < results.size(); i++) {
                    ParallelVerifier.VerifyResult result = results.get(i);
                    Chain chain = topChains.get(i);
                    // The wire status is a compatibility projection.  Policy decisions must
                    // consume the closed typed status so a future wire value cannot silently
                    // become a new branch or a second semantic owner.
                    switch (result.outcomeStatus()) {
                        case PRE_SINK_CONFIRMED -> {
                            bb.chainNote(chain.key(), "verify:pre-sink-confirmed");
                            prefixConfirmed++;
                        }
                        case SINK_BLOCKED -> {
                            bb.chainNote(chain.key(), "verify:sink-blocked");
                            confirmed++;
                        }
                        case SINK_EXECUTED_SAFE -> {
                            bb.chainNote(chain.key(), "verify:sink-executed-safe");
                            realSinks++;
                        }
                        case JNI_EXECUTED_SAFE -> {
                            bb.chainNote(chain.key(), "verify:jni-executed-safe");
                            jniSinks++;
                        }
                        // Safe-exec still reaches the same canary boundary, but the observed
                        // effect belongs to Just's inert/mock adapter and must remain visibly
                        // distorted rather than being described as target sink execution.
                        case SAFE_EFFECT_OBSERVED -> {
                            bb.chainNote(chain.key(), "verify:safe-effect-observed");
                            safeEffects++;
                        }
                        // 真实触发前缀完成但未到达精确 sink 边界：保留为低于 sink 的正向证据。
                        case CONCRETE_REACHED -> {
                            bb.chainNote(chain.key(), "verify:concrete-reached");
                            executed++;
                        }
                        // 入口真实执行但未证实 sink：兼容 direct/source 旧探针结果。
                        case EXECUTED -> {
                            bb.chainNote(chain.key(), "verify:executed");
                            executed++;
                        }
                        case PARTIAL -> {
                            bb.chainNote(chain.key(), "degrade:partial-path");
                            verificationDetails.merge(detailKey(result.detail()), 1, Integer::sum);
                            partial++;
                        }
                        // 探针 FAILED 是弱否定证据（可能源于依赖缺失/构造限制等探针自身局限）：
                        // 降级保留，不一票否决
                        case FAILED -> {
                            bb.chainNote(chain.key(), "degrade:verify-failed");
                            verificationDetails.merge(detailKey(result.detail()), 1, Integer::sum);
                            failed++;
                        }
                        case TIMEOUT -> {
                            bb.chainNote(chain.key(), "degrade:verify-timeout");
                            verificationDetails.merge(detailKey(result.detail()), 1, Integer::sum);
                            timeout++;
                        }
                        case UNTESTABLE -> {
                            bb.chainNote(chain.key(), "degrade:verify-untestable");
                            verificationDetails.merge(detailKey(result.detail()), 1, Integer::sum);
                            untestable++;
                        }
                        default -> { }
                    }
                }
                // 不把另一个候选链的 gadget 内段证据提升为当前完整链的确认。
                // 只有同一 entry/sink 候选在本次子 JVM 中到达 sink 边界，才能产生
                // verify:sink-blocked；有限预算之外的链仍保留静态结果。
        } catch (Exception e) {
            coverageStatus = VerificationCoverage.Status.PARTIAL_DYNAMIC_FAILURE;
            bb.setVerificationStatus(verifier == null
                    ? "JVM_SANDBOX_UNAVAILABLE" : verifier.capability());
            JustLogger.debug("子进程验证失败: {}", e.getMessage());
        } finally {
            if (verifier != null) {
                bb.setVerificationResourceMetrics(verifier.resourceMetrics());
                long cleanupStarted = System.nanoTime();
                verifier.cleanup();
                bb.recordPhaseMs("verify.cleanup.parent", java.util.concurrent.TimeUnit.NANOSECONDS
                        .toMillis(System.nanoTime() - cleanupStarted));
            }
        }

        if (verifier != null && "NOT_RUN".equals(bb.verificationStatus())) {
            bb.setVerificationStatus(verifier.capability());
        }

        JustLogger.info("动态验证：构造可行 {} / 不可构造 {} | 子进程 PRE_SINK_CONFIRMED {} / SINK_BLOCKED {} / "
                        + "SINK_EXECUTED_SAFE {} / JNI_EXECUTED_SAFE {} / SAFE_EFFECT_OBSERVED {} / "
                        + "CONCRETE_REACHED/EXECUTED {} / PARTIAL {} / FAILED {} / TIMEOUT {} / UNTESTABLE {}",
                constructible, rejected, prefixConfirmed, confirmed, realSinks, jniSinks, safeEffects,
                executed, partial, failed, timeout, untestable);
        if (!verificationDetails.isEmpty()) {
            JustLogger.info("动态验证明细：{}", verificationDetails.entrySet().stream()
                    .map(entry -> entry.getKey() + "×" + entry.getValue())
                    .reduce((left, right) -> left + ", " + right).orElse(""));
        }
        bb.publishFact(buildCoverage(bb, applicationEvidence, candidates, selectedChains,
                verificationResults, attemptsLaunched, coverageStatus));
        bb.setVerificationSummary(summary(bb, verifier, selectedChains, verificationResults,
                constructible, rejected, budget, verificationDetails));
        bb.recordPhaseMs("verify", java.util.concurrent.TimeUnit.NANOSECONDS
                .toMillis(System.nanoTime() - verificationStarted));
    }

    /**
     * Build the honest dynamic coverage denominator and its plan/group joins.  This method is
     * deliberately kept at the calibration boundary: the verifier owns attempts, while the
     * application evidence product owns which normalized findings are eligible.  No renderer or
     * raw path count is allowed to recreate this denominator.
     */
    private static VerificationCoverage buildCoverage(
            Blackboard bb,
            ApplicationChainEvidence applicationEvidence,
            List<Chain> candidates,
            List<Chain> selected,
            List<ParallelVerifier.VerifyResult> results,
            boolean attemptsLaunched,
            VerificationCoverage.Status statusHint) {
        Map<String, List<String>> chainsByGroup = new TreeMap<>();
        Map<String, List<String>> requiredSlots = new TreeMap<>();
        Set<String> candidateKeys = new HashSet<>();
        Map<String, Chain> candidateByKey = new java.util.HashMap<>();
        if (candidates != null) {
            candidates.stream().filter(java.util.Objects::nonNull).forEach(chain -> {
                if (chain.key() != null) {
                    candidateKeys.add(chain.key());
                    candidateByKey.putIfAbsent(chain.key(), chain);
                }
            });
        }
        if (applicationEvidence != null) {
            for (Map.Entry<String, io.just.sast.blackboard.FindingState> state
                    : applicationEvidence.states().entrySet()) {
                String chainKey = state.getKey();
                if (!candidateKeys.contains(chainKey) || bb.calibrationOf(chainKey) != null
                        || !state.getValue().defaultFindingEligible()) {
                    continue;
                }
                EntryChainJoinEvidence join = joinForChain(applicationEvidence, chainKey);
                if (join == null) {
                    continue;
                }
                String groupId = findingGroupId(join, candidateByKey.get(chainKey));
                chainsByGroup.computeIfAbsent(groupId, ignored -> new ArrayList<>()).add(chainKey);
                List<String> slots = new ArrayList<>(List.of("APPLICATION_PREFIX",
                        "ENTRY_CHAIN_JOIN", "DEPENDENCY_SEGMENT", "TERMINAL_GATE"));
                if (!join.bridgeEvidenceIds().isEmpty()) {
                    slots.add("BRIDGE");
                }
                requiredSlots.merge(groupId, slots, VerifyKnowledgeSource::unionSlots);
            }
        }
        chainsByGroup.replaceAll((key, value) -> value.stream().distinct().sorted().toList());

        Map<String, List<String>> plansByGroup = new TreeMap<>();
        Map<String, List<String>> attemptedSlots = new TreeMap<>();
        Set<String> confirmed = new java.util.TreeSet<>();
        Set<String> noObservation = new java.util.TreeSet<>();
        Set<String> eligiblePlanIds = new java.util.TreeSet<>();
        Set<String> attemptedPlanIds = new java.util.TreeSet<>();
        Set<String> coveredGroups = new java.util.TreeSet<>();
        Map<String, String> deferred = new TreeMap<>();
        List<Chain> selectedChains = selected == null ? List.of() : selected;
        List<ParallelVerifier.VerifyResult> verificationResults = results == null ? List.of() : results;
        for (int index = 0; index < selectedChains.size(); index++) {
            Chain chain = selectedChains.get(index);
            if (chain == null) {
                continue;
            }
            EntryChainJoinEvidence join = joinForChain(applicationEvidence, chain.key());
            if (join == null) {
                continue;
            }
            String groupId = findingGroupId(join, chain);
            if (!chainsByGroup.containsKey(groupId)) {
                continue;
            }
            String planId = verificationPlanId(chain);
            plansByGroup.computeIfAbsent(groupId, ignored -> new ArrayList<>()).add(planId);
            eligiblePlanIds.add(planId);
            if (!attemptsLaunched || index >= verificationResults.size()) {
                continue;
            }
            attemptedPlanIds.add(planId);
            coveredGroups.add(groupId);
            attemptedSlots.put(groupId, requiredSlots.getOrDefault(groupId, List.of()));
            ParallelVerifier.VerifyResult result = verificationResults.get(index);
            if (result == null) {
                noObservation.add(groupId);
                continue;
            }
            switch (result.outcomeStatus()) {
                case SINK_BLOCKED, PRE_SINK_CONFIRMED, SINK_EXECUTED_SAFE,
                        JNI_EXECUTED_SAFE, SAFE_EFFECT_OBSERVED, CONCRETE_REACHED, EXECUTED ->
                        confirmed.add(groupId);
                case PARTIAL, FAILED, TIMEOUT, UNTESTABLE, UNKNOWN -> noObservation.add(groupId);
                default -> noObservation.add(groupId);
            }
        }
        plansByGroup.replaceAll((key, value) -> value.stream().distinct().sorted().toList());
        // A finding group is "no observation" only when none of its attempted
        // variants produced a confirming boundary.  A partial/untestable
        // alternative must not erase a confirming observation for the same
        // normalized group.
        noObservation.removeAll(confirmed);
        for (String groupId : chainsByGroup.keySet()) {
            if (!coveredGroups.contains(groupId)) {
                String reason = switch (statusHint == null ? VerificationCoverage.Status.UNKNOWN
                        : statusHint) {
                    case NOT_REQUESTED -> "NOT_REQUESTED";
                    case ISOLATION_UNAVAILABLE -> "ISOLATION_UNAVAILABLE";
                    case PARTIAL_DYNAMIC_FAILURE -> "DYNAMIC_EXECUTION_FAILURE";
                    default -> selectedChains.size() >= Math.max(0, bb.scanInputs().verifyBudget())
                            ? "BUDGET_CAP" : "PLAN_NOT_SELECTED";
                };
                deferred.put(groupId, reason);
            }
        }
        VerificationCoverage.Status status = statusHint == null
                ? VerificationCoverage.Status.UNKNOWN : statusHint;
        if (chainsByGroup.isEmpty()) {
            if (status != VerificationCoverage.Status.NOT_REQUESTED
                    && status != VerificationCoverage.Status.ISOLATION_UNAVAILABLE
                    && status != VerificationCoverage.Status.PARTIAL_DYNAMIC_FAILURE) {
                status = VerificationCoverage.Status.NO_ELIGIBLE_GROUP;
            }
        } else if (coveredGroups.size() < chainsByGroup.size()) {
            if (status != VerificationCoverage.Status.NOT_REQUESTED
                    && status != VerificationCoverage.Status.ISOLATION_UNAVAILABLE
                    && status != VerificationCoverage.Status.PARTIAL_DYNAMIC_FAILURE) {
                status = VerificationCoverage.Status.PARTIAL_DYNAMIC_BUDGET;
            }
        } else if (status == VerificationCoverage.Status.NO_ELIGIBLE_GROUP
                || status == VerificationCoverage.Status.PARTIAL_DYNAMIC_BUDGET) {
            status = VerificationCoverage.Status.COMPLETE;
        }
        VerificationCoverage coverage = new VerificationCoverage(
                VerificationCoverage.SCHEMA_VERSION, status, chainsByGroup.size(),
                coveredGroups.size(), confirmed.size(), noObservation.size(), eligiblePlanIds.size(),
                attemptedPlanIds.size(), chainsByGroup, plansByGroup, requiredSlots, attemptedSlots,
                confirmed, noObservation, deferred, "UNKNOWN");
        return coverage.withComputedDigest();
    }

    private static EntryChainJoinEvidence joinForChain(ApplicationChainEvidence evidence,
                                                        String chainKey) {
        if (evidence == null || chainKey == null || chainKey.isBlank()) {
            return null;
        }
        String id = io.just.sast.blackboard.ApplicationChainId
                .fromCanonical("chain", chainKey).value();
        return evidence.joins().get(id);
    }

    /**
     * Normalize raw paths to the dynamic verification surface.  The exact dependency segment is
     * retained in the evidence DAG and chain list, but a boundary-only verifier can be reused
     * for equivalent application site/terminal/bridge surfaces.  This is the product-level
     * finding group, not a claim that every alternate static path was dynamically executed.
     */
    private static String findingGroupId(EntryChainJoinEvidence join, Chain chain) {
        if (join == null) {
            return FindingId.fromCanonical("dynamic-group", "UNKNOWN").value();
        }
        if (chain == null) {
            return FindingId.fromCanonical("dynamic-group", join.applicationEntryAtomId(),
                    join.applicationSiteAtomId(), join.dependencySegmentId().value()).value();
        }
        String terminal = String.join("|", chain.sinkClass(), chain.sinkMethod(),
                chain.sinkDescriptor(), chain.sinkRole(), chain.sinkRisk().name());
        String bridge = join.bridgeEvidenceIds().isEmpty() ? "NO_BRIDGE" : "BRIDGE_REQUIRED";
        return FindingId.fromCanonical("dynamic-group-v2", join.applicationEntryAtomId(),
                join.applicationSiteAtomId(), terminal, bridge).value();
    }

    private static List<String> unionSlots(List<String> left, List<String> right) {
        java.util.TreeSet<String> slots = new java.util.TreeSet<>();
        if (left != null) slots.addAll(left);
        if (right != null) slots.addAll(right);
        return List.copyOf(slots);
    }

    private static List<Chain> eligibleRepresentativeChains(ApplicationChainEvidence evidence,
                                                              List<Chain> candidates) {
        if (evidence == null || candidates == null || candidates.isEmpty()) {
            return List.of();
        }
        Map<String, List<Chain>> grouped = new TreeMap<>();
        for (Chain chain : candidates) {
            if (chain == null || chain.key() == null) {
                continue;
            }
            FindingState state = evidence.states().get(chain.key());
            if (state == null || !state.defaultFindingEligible()) {
                continue;
            }
            EntryChainJoinEvidence join = joinForChain(evidence, chain.key());
            if (join == null) {
                continue;
            }
            grouped.computeIfAbsent(findingGroupId(join, chain), ignored -> new ArrayList<>())
                    .add(chain);
        }
        java.util.Comparator<Chain> representativeOrder =
                java.util.Comparator.comparingInt((Chain chain) ->
                                -ConfidenceScorer.evidenceScore(chain, null))
                        .thenComparingInt(Chain::unresolvedHops)
                        .thenComparing(Chain::key);
        List<Chain> representatives = new ArrayList<>();
        for (List<Chain> group : grouped.values()) {
            group.sort(representativeOrder);
            if (!group.isEmpty()) {
                representatives.add(group.get(0));
            }
        }
        return List.copyOf(representatives);
    }

    private static String verificationPlanId(Chain chain) {
        try {
            byte[] bytes = java.security.MessageDigest.getInstance("SHA-256")
                    .digest(chain.key().getBytes(java.nio.charset.StandardCharsets.UTF_8));
            StringBuilder result = new StringBuilder(72).append("plan-");
            for (byte value : bytes) {
                result.append(String.format(java.util.Locale.ROOT, "%02x", value & 0xff));
            }
            return result.toString();
        } catch (java.security.NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 unavailable", impossible);
        }
    }

    private static VerificationSummary summary(Blackboard bb, ParallelVerifier verifier,
                                               List<Chain> selected,
                                               List<ParallelVerifier.VerifyResult> results,
                                               int constructible, int rejected, int budget,
                                               java.util.Map<String, Integer> detailCounts) {
        java.util.Map<String, Integer> statuses = new java.util.TreeMap<>();
        List<VerificationSummary.ChainResult> items = new ArrayList<>();
        String backend = verifier == null ? "UNKNOWN" : verifier.backendId();
        String jdk = "UNKNOWN";
        String policyDigest = verifier == null ? "UNKNOWN" : verifier.policyDigest();
        String artifactHash = verifier == null ? "UNKNOWN" : verifier.artifactFingerprintForReport();
        String isolationLevel = verifier == null ? "UNKNOWN" : verifier.isolationLevel();
        List<String> isolationCapabilities = verifier == null
                ? List.of() : new ArrayList<>(verifier.isolationCapabilities());
        String attestationVersion = verifier == null ? "UNKNOWN" : verifier.attestationVersion();
        boolean sinkDistorted = false;
        boolean sandboxReady = false;
        String cleanup = "UNKNOWN";
        for (int i = 0; i < results.size(); i++) {
            ParallelVerifier.VerifyResult result = results.get(i);
            if (result == null) {
                continue;
            }
            if ("UNKNOWN".equals(jdk)) {
                jdk = result.jdk();
            }
            if (!"UNKNOWN".equals(result.backend())) {
                backend = result.backend();
            }
            if (!"UNKNOWN".equals(result.policyDigest())) {
                policyDigest = result.policyDigest();
            }
            sinkDistorted |= result.sinkDistorted();
            sandboxReady |= result.sandboxReady();
            cleanup = result.cleanup();
            VerificationOutcome outcome = result.outcome();
            // The raw status is a wire compatibility projection.  Keep policy aggregation on
            // the closed typed outcome so an unknown/future wire value cannot create a second
            // semantic branch or inflate the dynamic confidence counts.
            statuses.merge(outcome.status().name(), 1, Integer::sum);
            Chain chain = i < selected.size() ? selected.get(i) : null;
            if (chain == null) {
                continue;
            }
            List<String> notes = bb.chainNotesOf(chain.key());
            int score = ConfidenceScorer.evidenceScore(chain, notes);
            items.add(new VerificationSummary.ChainResult(i + 1, chain.key(), result.status(),
                    ConfidenceScorer.score(chain, notes), score, result.attempt(),
                    result.durationMs(), outcome, result.backend(), result.jdk(),
                    result.policyDigest(), result.sinkDistorted(), result.sandboxReady(),
                    result.cleanup()));
        }
        return new VerificationSummary(bb.verificationStatus(), budget, constructible, rejected,
                selected.size(), statuses, detailCounts, items, backend, jdk, policyDigest,
                sinkDistorted, sandboxReady, cleanup, artifactHash,
                isolationLevel, isolationCapabilities, attestationVersion);
    }

    /** 将子进程诊断压缩成稳定、有限长度的聚合键，避免日志被单条异常或类名刷屏。 */
    private static String detailKey(String detail) {
        if (detail == null || detail.isBlank()) {
            return "unknown";
        }
        String value = detail.strip().replaceAll("\\s+", " ");
        int equals = value.indexOf('=');
        if (equals > 0) {
            value = value.substring(0, equals);
        }
        return value.length() <= 96 ? value : value.substring(0, 96) + "…";
    }

    /** 构造阶段必须使用被扫描目标/依赖的类路径，不能使用扫描器自身的 ClassLoader。 */
    private URLClassLoader targetClassLoader(Blackboard blackboard) {
        List<URL> urls = new ArrayList<>();
        List<Path> inputs = new ArrayList<>();
        inputs.add(blackboard.scanInputs().target());
        inputs.addAll(blackboard.scanInputs().deps());
        try {
            // The same versioned input policy used by the static boundary must also guard
            // reflective construction.  In particular, a malformed archive or a link/reparse
            // point is not allowed to fall back to the original outer path: URLClassLoader
            // follows that path and would silently bypass the archive/link checks.  An empty
            // child loader is a fail-closed capability result; constructors then remain
            // untestable while static evidence is preserved by the caller.
            InputBudget.Tracker callerTracker = blackboard.scanInputs().inputTracker();
            InputBudget callerPolicy = callerTracker == null
                    ? InputBudget.defaults() : callerTracker.budget();
            payloadClasspath = NestedClasspath.open(inputs, callerPolicy, callerTracker);
            urls.addAll(payloadClasspath.urls());
        } catch (java.io.IOException e) {
            payloadClasspath = null;
            blackboard.markIncomplete("VERIFY_CLASSPATH_EXPANSION");
            JustLogger.debug("构造器嵌套 classpath 展开失败，fail-closed（不回退外层输入）: {}",
                    e.getMessage());
            return new URLClassLoader(new URL[0], null);
        }
        if (!urls.isEmpty()) {
            return new URLClassLoader(urls.toArray(URL[]::new), VerifyKnowledgeSource.class.getClassLoader());
        }
        return new URLClassLoader(urls.toArray(URL[]::new), VerifyKnowledgeSource.class.getClassLoader());
    }

    private void closePayloadLoader() {
        try {
            if (payloadLoader != null) {
                payloadLoader.close();
            }
        } catch (java.io.IOException e) {
            JustLogger.debug("关闭构造器类加载器失败: {}", e.getMessage());
        } finally {
            payloadLoader = null;
            if (payloadClasspath != null) {
                payloadClasspath.close();
                payloadClasspath = null;
            }
        }
    }
}
