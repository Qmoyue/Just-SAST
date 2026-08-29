package io.just.sast.knowledge.engine;

import io.just.sast.analysis.taint.OriginSupport;
import io.just.sast.blackboard.Blackboard;
import io.just.sast.blackboard.Event;
import io.just.sast.blackboard.EventType;
import io.just.sast.blackboard.KnowledgeSource;

import java.util.Set;

/**
 * 前向对象污点知识源（ANALYSIS 阶段）。
 * 单个 ForwardEngine 实例依次跑两轮：粗扫（类级事实）→ 精扫（接口/代理/反射精化），
 * 共享一次 buildIndexes 的索引与粗扫产出的事实（精扫以粗扫事实为初值，只做增量补充）。
 * GadgetInspector 式正向：magic entry / OIS 读种子 → 对象污点事实不动点 → sink 判定。
 */
public final class ForwardTaintKnowledgeSource implements KnowledgeSource {

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
    public void init(Blackboard blackboard) {
        // 引擎按需创建
    }

    @Override
    public void onEvent(Blackboard bb, Event event) {
        if (event.type() != EventType.SCAN_START) {
            return;
        }
        ForwardEngine engine = new ForwardEngine(bb);
        engine.run(ForwardEngine.Options.coarse());
        engine.run(ForwardEngine.Options.refined());
        if (bb.originSupport().constantProofBudgetExceeded()) {
            bb.markIncomplete("CONSTANT_PROOF_CAP:" + OriginSupport.CONSTANT_PROOF_BUDGET);
        }
    }
}
