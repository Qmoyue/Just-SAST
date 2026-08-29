package io.just.sast.knowledge.calibrate;

import io.just.sast.blackboard.Blackboard;
import io.just.sast.blackboard.ChainHop;
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
 * Phase 2: 并行子进程验证（预编译探针 + 4 路并行 + 实时输出 CONFIRMED 链）
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
        this.payloadLoader = targetClassLoader(blackboard);
        this.constructor = new PayloadConstructor(payloadLoader);
    }

    @Override
    public void onEvent(Blackboard bb, Event event) {
        if (event.type() != EventType.SCAN_COMPLETE) {
            return;
        }
        if (!bb.scanInputs().verify()) {
            bb.setVerificationStatus("DISABLED");
            bb.setVerificationSummary(VerificationSummary.empty(
                    "DISABLED", bb.scanInputs().verifyBudget()));
            JustLogger.info("动态验证已关闭（--no-verify）");
            return;
        }
        int constructible = 0;
        int rejected = 0;
        Set<String> constructibleKeys = new HashSet<>();
        java.util.Map<String, Integer> skipReasons = new java.util.LinkedHashMap<>();
        try {
            for (Chain chain : bb.chains()) {
                if (bb.calibrationOf(chain.key()) != null) continue;
                String dotted = chain.entryClass().replace('/', '.');
                PayloadConstructor.ConstructionResult result = constructor.tryConstruct(dotted);
                switch (result.verdict()) {
                    case "CONSTRUCTIBLE" -> {
                        bb.chainNote(chain.key(), "verify:constructible");
                        constructibleKeys.add(chain.key());
                        constructible++;
                    }
                    case "PARTIALLY_CONSTRUCTIBLE" -> bb.chainNote(chain.key(), "degrade:partial-construct");
                    case "SKIP" -> // 按原因类别聚合（detail 含类名，逐类输出会过长）
                    skipReasons.merge(result.detail() != null
                            ? result.detail().split(":")[0] : "skip", 1, Integer::sum);
                    default -> {
                        bb.calibrateChain(chain.key(), "not-constructible");
                        rejected++;
                    }
                }
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
            JustLogger.info("构造可行性：{} 类不可构造（{}）", skipReasons.values().stream().mapToInt(Integer::intValue).sum(),
                    skipReasons.entrySet().stream().map(e -> e.getKey() + "×" + e.getValue())
                            .reduce((a, b) -> a + ", " + b).orElse(""));
        }

        int confirmed = 0;
        int executed = 0;
        int partial = 0;
        int failed = 0;
        int untestable = 0;
        int timeout = 0;
        ParallelVerifier verifier = null;
        java.util.Map<String, Integer> verificationDetails = new java.util.LinkedHashMap<>();
        List<Chain> selectedChains = List.of();
        List<ParallelVerifier.VerifyResult> verificationResults = List.of();
        int budget = bb.scanInputs().verifyBudget();
        try {
                Path targetJar = bb.scanInputs().target();
                verifier = new ParallelVerifier(targetJar, bb.scanInputs().deps(),
                    bb.scanInputs().jdkHome(), bb.scanInputs().targetMajorVersion(),
                    (chain, detail, sinkReached) -> {
                        if (sinkReached) {
                            JustLogger.info("  ✓ CONFIRMED: {}#{} → {}.{}  [{}]",
                                    chain.entryClass().replace('/', '.'),
                                    chain.entryMethod(),
                                    chain.sinkClass().replace('/', '.'),
                                    chain.sinkMethod(),
                                    detail);
                        }
                    });
                // entryKind=source 的完整链也进入隔离探针。探针使用统一的受限默认参数
                // 适配器验证宿主是否真实执行；这不是攻击者 payload 生成，未建模的源输入
                // 仍只能得到 EXECUTED/PARTIAL，不能凭入口执行提升为 CONFIRMED。
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
                    switch (result.status()) {
                        case "CONFIRMED" -> {
                            bb.chainNote(chain.key(), "verify:confirmed");
                            confirmed++;
                        }
                        // 入口真实执行但未证实 sink：证据注记，不置顶（CONFIRMED 仅留给 SINK_TRIGGERED）
                        case "EXECUTED" -> {
                            bb.chainNote(chain.key(), "verify:executed");
                            executed++;
                        }
                        case "PARTIAL" -> {
                            bb.chainNote(chain.key(), "degrade:partial-path");
                            verificationDetails.merge(detailKey(result.detail()), 1, Integer::sum);
                            partial++;
                        }
                        // 探针 FAILED 是弱否定证据（可能源于依赖缺失/构造限制等探针自身局限）：
                        // 降级保留，不一票否决
                        case "FAILED" -> {
                            bb.chainNote(chain.key(), "degrade:verify-failed");
                            verificationDetails.merge(detailKey(result.detail()), 1, Integer::sum);
                            failed++;
                        }
                        case "TIMEOUT" -> {
                            bb.chainNote(chain.key(), "degrade:verify-timeout");
                            verificationDetails.merge(detailKey(result.detail()), 1, Integer::sum);
                            timeout++;
                        }
                        case "UNTESTABLE" -> {
                            bb.chainNote(chain.key(), "degrade:verify-untestable");
                            verificationDetails.merge(detailKey(result.detail()), 1, Integer::sum);
                            untestable++;
                        }
                        default -> { }
                    }
                }
                // 段归因：若源宿主自身未被选入有限验证预算，且其 gadget 内段（bridge-trigger-src
                // 桥之后的 hashCode/equals 段）已被子进程证实，则把证据附着到完整链。源宿主
                // 自身若已被验证，不重复添加段注释。
                Set<String> confirmedEntries = new java.util.HashSet<>();
                for (int i = 0; i < results.size(); i++) {
                    if ("CONFIRMED".equals(results.get(i).status())) {
                        Chain c = topChains.get(i);
                        confirmedEntries.add(c.entryClass() + "#" + c.entryMethod()
                                + "|" + c.sinkClass() + "." + c.sinkMethod());
                    }
                }
                int segment = 0;
                for (Chain chain : bb.chains()) {
                    if (!"source".equals(chain.entryKind())) {
                        continue;
                    }
                    List<String> notes = bb.chainNotesOf(chain.key());
                    if (notes.stream().anyMatch(n -> n.equals("verify:confirmed")
                            || n.equals("verify:segment-confirmed"))) {
                        continue;
                    }
                    for (ChainHop hop : chain.hops()) {
                        if (hop.reason() != null && hop.reason().equals("bridge-trigger-src")
                                && confirmedEntries.contains(hop.toOwner() + "#" + hop.toName()
                                        + "|" + chain.sinkClass() + "." + chain.sinkMethod())) {
                            bb.chainNote(chain.key(), "verify:segment-confirmed");
                            segment++;
                            JustLogger.info("段归因: {}#{} → {}.{}（内段 {}#{} 已子进程证实）",
                                    chain.entryClass(), chain.entryMethod(),
                                    chain.sinkClass(), chain.sinkMethod(),
                                    hop.toOwner(), hop.toName());
                            break;
                        }
                    }
                }
                if (segment > 0) {
                    JustLogger.info("段归因确认 {} 条完整链（内段被子进程证实）", segment);
                }
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

        JustLogger.info("动态验证：构造可行 {} / 不可构造 {} | 子进程 CONFIRMED {} / EXECUTED {} / "
                        + "PARTIAL {} / FAILED {} / TIMEOUT {} / UNTESTABLE {}",
                constructible, rejected, confirmed, executed, partial, failed, timeout, untestable);
        if (!verificationDetails.isEmpty()) {
            JustLogger.info("动态验证明细：{}", verificationDetails.entrySet().stream()
                    .map(entry -> entry.getKey() + "×" + entry.getValue())
                    .reduce((left, right) -> left + ", " + right).orElse(""));
        }
        bb.setVerificationSummary(summary(bb, selectedChains, verificationResults,
                constructible, rejected, budget, verificationDetails));
    }

    private static VerificationSummary summary(Blackboard bb, List<Chain> selected,
                                               List<ParallelVerifier.VerifyResult> results,
                                               int constructible, int rejected, int budget,
                                               java.util.Map<String, Integer> detailCounts) {
        java.util.Map<String, Integer> statuses = new java.util.TreeMap<>();
        List<VerificationSummary.ChainResult> items = new ArrayList<>();
        for (int i = 0; i < results.size(); i++) {
            ParallelVerifier.VerifyResult result = results.get(i);
            if (result == null) {
                continue;
            }
            statuses.merge(result.status(), 1, Integer::sum);
            Chain chain = i < selected.size() ? selected.get(i) : null;
            if (chain == null) {
                continue;
            }
            List<String> notes = bb.chainNotesOf(chain.key());
            int score = ConfidenceScorer.evidenceScore(chain, notes);
            items.add(new VerificationSummary.ChainResult(i + 1, chain.key(), result.status(),
                    result.detail(), ConfidenceScorer.score(chain, notes), score,
                    result.attempt(), result.durationMs()));
        }
        return new VerificationSummary(bb.verificationStatus(), budget, constructible, rejected,
                selected.size(), statuses, detailCounts, items);
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
