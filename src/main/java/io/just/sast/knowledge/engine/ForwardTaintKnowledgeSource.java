package io.just.sast.knowledge.engine;

import io.just.sast.analysis.taint.OriginSupport;
import io.just.sast.blackboard.Blackboard;
import io.just.sast.blackboard.Event;
import io.just.sast.blackboard.EventType;
import io.just.sast.blackboard.KnowledgeSource;
import io.just.sast.blackboard.RunProduct;

import java.util.Set;

/**
 * 前向对象污点知识源（ANALYSIS 阶段）。
 * 单个 ForwardEngine 实例依次跑两轮：粗扫（类级事实）→ 精扫（接口/代理/反射精化），
 * 共享一次 buildIndexes 的索引与粗扫产出的事实（精扫以粗扫事实为初值，只做增量补充）。
 * GadgetInspector 式正向：magic entry / OIS 读种子 → 对象污点事实不动点 → sink 判定。
 */
public final class ForwardTaintKnowledgeSource implements KnowledgeSource {

    /**
     * On a large closure the refined engine contains the complete coarse transfer plus the
     * optional dispatch/reflection adapters. Running both passes would reinterpret the same
     * method summaries twice; small inputs keep the two-pass schedule for its cheap staged
     * precision behavior.
     */
    /**
     * A medium dependency closure can still be dominated by the coarse pass.  The refined
     * transfer already includes the coarse facts, so paying for two full interpretations is
     * only worthwhile for genuinely small closures where the staged precision is cheap.  Use
     * a graph-independent, power-of-two boundary so the policy is stable across artifacts and
     * cannot become a benchmark-specific branch.  The actual closure is still bounded by the
     * application-anchored demand slice before this decision is made.
     */
    private static final int SINGLE_REFINED_PASS_THRESHOLD = 4_096;

    @Override
    public String id() {
        return "forward-taint";
    }

    @Override
    public Set<EventType> interests() {
        return Set.of(EventType.SCAN_START);
    }

    @Override
    public int priority() {
        return 200;
    }

    @Override
    public Set<RunProduct> requiresProducts() {
        return Set.of(RunProduct.PROGRAM_MODEL);
    }

    @Override
    public Set<RunProduct> providesProducts() {
        return Set.of(RunProduct.ANALYSIS_CHAINS);
    }

    @Override
    public void init(Blackboard blackboard) {
        // 引擎按需创建
    }

    @Override
    public void onEvent(Blackboard bb, Event event) {
        if (event.type() != EventType.SCAN_START) {
            return;
        }
        ForwardEngine engine = new ForwardEngine(bb);
        ForwardRunMetrics.Pass completedPass = ForwardRunMetrics.Pass.UNKNOWN;
        try {
            int closureSize = bb.originSupport().entryDownstream(bb.graph()).size();
            if (closureSize > SINGLE_REFINED_PASS_THRESHOLD) {
                io.just.sast.util.JustLogger.info(
                        "前向污点：大闭包 {} 个方法，采用单次精扫（阈值 {}）",
                        closureSize, SINGLE_REFINED_PASS_THRESHOLD);
                long refinedStartedAt = System.nanoTime();
                engine.run(ForwardEngine.Options.refined());
                completedPass = ForwardRunMetrics.Pass.REFINED;
                io.just.sast.util.JustLogger.info("前向污点精扫阶段耗时 {} ms",
                        (System.nanoTime() - refinedStartedAt) / 1_000_000L);
                if (bb.originSupport().constantProofBudgetExceeded()) {
                    bb.markIncomplete("CONSTANT_PROOF_CAP:" + OriginSupport.CONSTANT_PROOF_BUDGET);
                }
                return;
            }
            long coarseStartedAt = System.nanoTime();
            engine.run(ForwardEngine.Options.coarse());
            completedPass = ForwardRunMetrics.Pass.COARSE;
            io.just.sast.util.JustLogger.info("前向污点粗扫阶段耗时 {} ms",
                    (System.nanoTime() - coarseStartedAt) / 1_000_000L);
            // A phase timeout cancels the worker with its interrupt flag.  Do not start the
            // refinement pass after cancellation: doing so used to make a timed-out coarse
            // pass continue for another large-jar traversal and delayed executor shutdown.
            if (Thread.currentThread().isInterrupted()) {
                bb.markIncomplete("FORWARD_INTERRUPTED");
                return;
            }
            long refinedStartedAt = System.nanoTime();
            engine.run(ForwardEngine.Options.refined());
            completedPass = ForwardRunMetrics.Pass.REFINED;
            io.just.sast.util.JustLogger.info("前向污点精扫阶段耗时 {} ms",
                    (System.nanoTime() - refinedStartedAt) / 1_000_000L);
            if (bb.originSupport().constantProofBudgetExceeded()) {
                bb.markIncomplete("CONSTANT_PROOF_CAP:" + OriginSupport.CONSTANT_PROOF_BUDGET);
            }
        } finally {
            bb.publishFact(ForwardRunMetrics.from(engine.stateSnapshot(), completedPass,
                    Thread.currentThread().isInterrupted()));
        }
    }
}
