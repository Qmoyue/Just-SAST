package io.just.sast.knowledge.calibrate;

import io.just.sast.blackboard.Blackboard;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.Event;
import io.just.sast.blackboard.EventType;
import io.just.sast.blackboard.KnowledgeSource;
import io.just.sast.blackboard.Phase;
import io.just.sast.chain.ConfidenceScorer;
import io.just.sast.util.JustLogger;
import io.just.sast.verify.ParallelVerifier;
import io.just.sast.verify.PayloadConstructor;

import java.nio.file.Path;
import java.util.Comparator;
import java.util.List;
import java.util.Set;

/**
 * 动态验证知识源（CALIBRATION priority 500）：
 * Phase 1: 构造可行性检查（快速筛选）
 * Phase 2: 并行子进程验证（预编译探针 + 4 路并行 + 实时输出 CONFIRMED 链）
 */
public final class VerifyKnowledgeSource implements KnowledgeSource {

    private static final int MAX_SUBPROCESS_VERIFY = 20;

    private Blackboard bb;
    private PayloadConstructor constructor;

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
        this.constructor = new PayloadConstructor(VerifyKnowledgeSource.class.getClassLoader());
    }

    @Override
    public void onEvent(Blackboard bb, Event event) {
        if (event.type() != EventType.SCAN_COMPLETE) {
            return;
        }
        if (!bb.scanInputs().verify()) {
            JustLogger.info("动态验证已关闭（--no-verify）");
            return;
        }
        int constructible = 0;
        int rejected = 0;
        java.util.Map<String, Integer> skipReasons = new java.util.LinkedHashMap<>();
        for (Chain chain : bb.chains()) {
            if (bb.calibrationOf(chain.key()) != null) continue;
            String dotted = chain.entryClass().replace('/', '.');
            PayloadConstructor.ConstructionResult result = constructor.tryConstruct(dotted);
            switch (result.verdict()) {
                case "CONSTRUCTIBLE" -> {
                    bb.chainNote(chain.key(), "verify:constructible");
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
        // 不可构造类聚合报告（抽象/无无参构造/不在类路径——探针能力边界可见化）
        if (!skipReasons.isEmpty()) {
            JustLogger.info("构造可行性：{} 类不可构造（{}）", skipReasons.values().stream().mapToInt(Integer::intValue).sum(),
                    skipReasons.entrySet().stream().map(e -> e.getKey() + "×" + e.getValue())
                            .reduce((a, b) -> a + ", " + b).orElse(""));
        }

        int confirmed = 0;
        int failed = 0;
        try {
            Path targetJar = bb.scanInputs().target();
            ParallelVerifier verifier = new ParallelVerifier(targetJar, bb.scanInputs().deps(),
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
                int budget = Math.max(1, bb.scanInputs().verifyBudget());
                // entryKind=source 的完整链是组装器合成（源宿主→容器触发→gadget 段），
                // 其入口参数是攻击者载荷、探针无法构造——跳过子进程执行，走段归因路径
                List<Chain> topChains = verifier.selectChains(
                        bb.chains().stream().filter(c -> bb.calibrationOf(c.key()) == null
                                && !"source".equals(c.entryKind())).toList(),
                        budget);

                JustLogger.info("子进程链级验证（{} 条 / 预算 {}，{} 路并行，入口去重≤{}/入口）...",
                        topChains.size(), budget, 4, 2);

                List<ParallelVerifier.VerifyResult> results = verifier.verifyAll(topChains);
                for (int i = 0; i < results.size(); i++) {
                    ParallelVerifier.VerifyResult result = results.get(i);
                    Chain chain = topChains.get(i);
                    switch (result.status()) {
                        case "CONFIRMED" -> {
                            bb.chainNote(chain.key(), "verify:confirmed");
                            confirmed++;
                        }
                        // 入口真实执行但未证实 sink：证据注记，不置顶（CONFIRMED 仅留给 SINK_TRIGGERED）
                        case "EXECUTED" -> bb.chainNote(chain.key(), "verify:executed");
                        case "PARTIAL" -> bb.chainNote(chain.key(), "degrade:partial-path");
                        // 探针 FAILED 是弱否定证据（可能源于依赖缺失/构造限制等探针自身局限）：
                        // 降级保留，不一票否决
                        case "FAILED" -> {
                            bb.chainNote(chain.key(), "degrade:verify-failed");
                            failed++;
                        }
                        default -> {}
                    }
                }
                // 段归因：源宿主触发的完整链（entryKind=source）无法以合成参数端到端执行——
                // 其 gadget 内段（bridge-trigger-src 桥之后的 hashCode/equals 段）若已被子进程
                // 证实（入口方法与 sink 全等），完整链继承该动态证据
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
                verifier.cleanup();
        } catch (Exception e) {
            JustLogger.debug("子进程验证失败: {}", e.getMessage());
        }

        JustLogger.info("动态验证：构造可行 {} / 不可构造 {} | 子进程 CONFIRMED {} / FAILED {}",
                constructible, rejected, confirmed, failed);
    }
}
