package io.just.sast.knowledge.calibrate;

import io.just.sast.blackboard.Blackboard;
import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.Event;
import io.just.sast.blackboard.EventType;
import io.just.sast.blackboard.KnowledgeSource;
import io.just.sast.blackboard.Phase;
import io.just.sast.blackboard.VerificationSummary;
import io.just.sast.chain.ConfidenceScorer;
import io.just.sast.util.JustLogger;
import io.just.sast.verify.NestedClasspath;
import io.just.sast.verify.ParallelVerifier;
import io.just.sast.verify.PayloadConstructor;

import java.nio.file.Path;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

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
    public void init(Blackboard blackboard) {
        this.bb = blackboard;
    }

    @Override
    public void onEvent(Blackboard bb, Event event) {
        if (event.type() != EventType.SCAN_COMPLETE) {
            return;
        }
        long verificationStarted = System.nanoTime();
        if (!bb.scanInputs().verify()) {
            bb.setVerificationStatus("DISABLED");
            bb.setVerificationSummary(VerificationSummary.empty(
                    "DISABLED", bb.scanInputs().verifyBudget()));
            bb.recordPhaseMs("verify", 0L);
            JustLogger.info("动态验证已关闭（--no-verify）");
            return;
        }
        int budget = bb.scanInputs().verifyBudget();
        if (budget <= 0) {
            bb.setVerificationStatus("NOT_RUN");
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
        List<Chain> candidates = bb.chains().stream()
                .filter(c -> bb.calibrationOf(c.key()) == null)
                .toList();
        ParallelVerifier verifier = null;
        try {
            verifier = new ParallelVerifier(bb.scanInputs().target(), bb.scanInputs().deps(),
                    bb.scanInputs().jdkHome(), bb.scanInputs().targetMajorVersion(),
                    bb.scanInputs().safeExec(), bb.scanInputs().safeReal(),
                    bb.scanInputs().requireStrictIsolation(),
                    (chain, detail, sinkReached) -> {
                        if (sinkReached) {
                            JustLogger.info("  ✓ SINK_BLOCKED: {}#{} → {}.{}  [{}]",
                                    chain.entryClass().replace('/', '.'), chain.entryMethod(),
                                    chain.sinkClass().replace('/', '.'), chain.sinkMethod(), detail);
                        }
                    });
        } catch (RuntimeException | LinkageError verifierFailure) {
            bb.markIncomplete("VERIFY_INITIALIZATION");
            bb.setVerificationStatus("UNTESTABLE");
            bb.setVerificationSummary(VerificationSummary.empty("UNTESTABLE", budget));
            JustLogger.debug("验证器初始化失败: {}", verifierFailure.getMessage());
            bb.recordPhaseMs("verify", java.util.concurrent.TimeUnit.NANOSECONDS
                    .toMillis(System.nanoTime() - verificationStarted));
            return;
        }
        List<Chain> seedChains = verifier.selectChains(candidates, budget, Set.of());
        int constructible = 0;
        int rejected = 0;
        Set<String> constructibleKeys = new HashSet<>();
        java.util.Map<String, Integer> skipReasons = new java.util.LinkedHashMap<>();
        java.util.Map<String, PayloadConstructor.ConstructionResult> constructionByEntry =
                new java.util.HashMap<>();
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
        }
        // 不可检查类聚合报告（抽象/不在类路径——探针能力边界可见化）
        if (!skipReasons.isEmpty()) {
            JustLogger.info("构造可行性边界：{} 项（{}）", skipReasons.values().stream().mapToInt(Integer::intValue).sum(),
                    skipReasons.entrySet().stream().map(e -> e.getKey() + "×" + e.getValue())
                            .reduce((a, b) -> a + ", " + b).orElse(""));
        }

        int confirmed = 0;
        int safeEffects = 0;
        int executed = 0;
        int partial = 0;
        int failed = 0;
        int untestable = 0;
        int timeout = 0;
        java.util.Map<String, Integer> verificationDetails = new java.util.LinkedHashMap<>();
        List<Chain> selectedChains = List.of();
        List<ParallelVerifier.VerifyResult> verificationResults = List.of();
        try {
                // entryKind=source 的完整链也进入隔离探针。探针使用统一的受限默认参数
                // 适配器验证宿主是否真实执行；这不是攻击者 payload 生成。只有同一候选
                // 到达 sink canary 边界才能得到 SINK_BLOCKED。
                List<Chain> topChains = verifier.selectChains(
                        bb.chains().stream().filter(c -> bb.calibrationOf(c.key()) == null
                        ).toList(),
                        budget, constructibleKeys);
                selectedChains = topChains;

                JustLogger.info("子进程链级验证（{} 条 / 预算 {}，{} 路并行，入口/风险面去重≤{}/组）...",
                        topChains.size(), budget, 4, 2);

                List<ParallelVerifier.VerifyResult> results = verifier.verifyAll(topChains);
                verificationResults = results;
                bb.setVerificationStatus(verifier.capability());
                for (int i = 0; i < results.size(); i++) {
                    ParallelVerifier.VerifyResult result = results.get(i);
                    Chain chain = topChains.get(i);
                    switch (result.statusCode()) {
                        case SINK_BLOCKED -> {
                            bb.chainNote(chain.key(), "verify:sink-blocked");
                            if (!"OS_STRICT".equals(verifier.isolationLevel())) {
                                // The exact canary was reached, but this host does not provide
                                // a production OS boundary. Keep the path evidence while
                                // lowering only its safety/confidence label.
                                bb.chainNote(chain.key(), "degrade:sink-canary-non-strict-os");
                            }
                            confirmed++;
                        }
                        // Safe-exec still reaches the same canary boundary, but the observed
                        // effect belongs to Just's inert/mock adapter and must remain visibly
                        // distorted rather than being described as target sink execution.
                        case SAFE_EFFECT_OBSERVED -> {
                            bb.chainNote(chain.key(), "verify:safe-effect-observed");
                            if (!"OS_STRICT".equals(verifier.isolationLevel())) {
                                bb.chainNote(chain.key(), "degrade:sink-canary-non-strict-os");
                            }
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
            bb.setVerificationStatus(verifier == null
                    ? "JVM_SANDBOX_UNAVAILABLE" : verifier.capability());
            JustLogger.debug("子进程验证失败: {}", e.getMessage());
        } finally {
            if (verifier != null) {
                verifier.cleanup();
            }
        }

        if (verifier != null && "NOT_RUN".equals(bb.verificationStatus())) {
            bb.setVerificationStatus(verifier.capability());
        }

        JustLogger.info("动态验证：构造可行 {} / 不可构造 {} | 子进程 SINK_BLOCKED {} / SAFE_EFFECT_OBSERVED {} / "
                        + "CONCRETE_REACHED/EXECUTED {} / PARTIAL {} / FAILED {} / TIMEOUT {} / UNTESTABLE {}",
                constructible, rejected, confirmed, safeEffects, executed, partial, failed, timeout, untestable);
        if (!verificationDetails.isEmpty()) {
            JustLogger.info("动态验证明细：{}", verificationDetails.entrySet().stream()
                    .map(entry -> entry.getKey() + "×" + entry.getValue())
                    .reduce((left, right) -> left + ", " + right).orElse(""));
        }
        bb.setVerificationSummary(summary(bb, verifier, selectedChains, verificationResults,
                constructible, rejected, budget, verificationDetails));
        bb.recordPhaseMs("verify", java.util.concurrent.TimeUnit.NANOSECONDS
                .toMillis(System.nanoTime() - verificationStarted));
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
            statuses.merge(result.status(), 1, Integer::sum);
            Chain chain = i < selected.size() ? selected.get(i) : null;
            if (chain == null) {
                continue;
            }
            List<String> notes = bb.chainNotesOf(chain.key());
            int score = ConfidenceScorer.evidenceScore(chain, notes);
            items.add(new VerificationSummary.ChainResult(i + 1, chain.key(), result.status(),
                    result.detail(), ConfidenceScorer.score(chain, notes), score,
                    result.attempt(), result.durationMs(), result.evidence(), result.backend(),
                    result.jdk(), result.policyDigest(), result.sinkDistorted(),
                    result.sandboxReady(), result.cleanup()));
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
            payloadClasspath = NestedClasspath.open(inputs);
            urls.addAll(payloadClasspath.urls());
        } catch (java.io.IOException e) {
            payloadClasspath = null;
            blackboard.markIncomplete("VERIFY_CLASSPATH_EXPANSION");
            JustLogger.debug("构造器嵌套 classpath 展开失败，回退外层输入: {}", e.getMessage());
        }
        if (!urls.isEmpty()) {
            return new URLClassLoader(urls.toArray(URL[]::new), VerifyKnowledgeSource.class.getClassLoader());
        }
        for (Path input : inputs) {
            try {
                urls.add(input.toAbsolutePath().normalize().toUri().toURL());
            } catch (java.io.IOException e) {
                JustLogger.debug("构造器类路径忽略 {}: {}", input, e.getMessage());
            }
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
