package io.just.sast.knowledge.calibrate;

import io.just.sast.blackboard.Blackboard;
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
                case "SKIP" -> {}
                default -> {
                    bb.calibrateChain(chain.key(), "not-constructible");
                    rejected++;
                }
            }
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
                List<Chain> topChains = verifier.selectChains(
                        bb.chains().stream().filter(c -> bb.calibrationOf(c.key()) == null).toList(),
                        MAX_SUBPROCESS_VERIFY);

                JustLogger.info("子进程链级验证（{} 条，{} 路并行，入口去重≤{}/入口）...",
                        topChains.size(), 4, 2);

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
                verifier.cleanup();
        } catch (Exception e) {
            JustLogger.debug("子进程验证失败: {}", e.getMessage());
        }

        JustLogger.info("动态验证：构造可行 {} / 不可构造 {} | 子进程 CONFIRMED {} / FAILED {}",
                constructible, rejected, confirmed, failed);
    }
}
