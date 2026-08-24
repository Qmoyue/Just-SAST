package io.just.sast.blackboard;

import io.just.sast.util.JustLogger;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 黑板控制器：三阶段调度（init 串行 → 阶段屏障）。
 * - ANALYSIS：并行派发（四知识源契约自足：只读冻结图、同步写黑板、不读彼此产物），join 屏障
 * - COMPOSITION / CALIBRATION：按 priority 升序串行（跨源数据依赖：composer 消费 object-graph
 *   重根链、pruner 消费 validator 裁决）
 * init/onEvent 异常按知识源隔离（含 Error），不中断全扫。
 */
public final class Controller {

    /** 单阶段事件派生上限（有界恢复：防事件风暴）。 */
    private static final int MAX_DISPATCH = 1_000_000;

    private final Blackboard blackboard;
    private final List<KnowledgeSource> sources;

    public Controller(Blackboard blackboard, List<KnowledgeSource> sources) {
        this.blackboard = blackboard;
        this.sources = sources;
    }

    public void run() {
        // priority 升序（稳定）：同阶段执行序显式化
        List<KnowledgeSource> ordered = new ArrayList<>(sources);
        ordered.sort(Comparator.comparingInt(KnowledgeSource::priority));
        Map<Phase, Map<EventType, List<KnowledgeSource>>> subsByPhase = new EnumMap<>(Phase.class);
        for (KnowledgeSource ks : ordered) {
            try {
                ks.init(blackboard);
            } catch (Throwable e) {
                JustLogger.error("知识源 {} 初始化失败（已隔离）: {}", ks.id(), e.toString());
            }
            Map<EventType, List<KnowledgeSource>> subs =
                    subsByPhase.computeIfAbsent(ks.phase(), p -> new EnumMap<>(EventType.class));
            for (EventType type : ks.interests()) {
                subs.computeIfAbsent(type, t -> new ArrayList<>(1)).add(ks);
            }
        }
        int dispatched = 0;
        // ANALYSIS 并行：每个知识源一个任务（自足契约，合成事件直调不经队列），异常隔离，join 屏障
        dispatched += dispatchParallel(subsByPhase.getOrDefault(Phase.ANALYSIS, Map.of()));
        // COMPOSITION / CALIBRATION 串行（priority 序，跨源数据依赖）
        blackboard.publish(Event.of(EventType.SCAN_ANALYZED, -1, null));
        dispatched += drain(subsByPhase.getOrDefault(Phase.COMPOSITION, Map.of()));
        blackboard.publish(Event.of(EventType.SCAN_COMPLETE, -1, null));
        dispatched += drain(subsByPhase.getOrDefault(Phase.CALIBRATION, Map.of()));
        JustLogger.info("黑板分析完成：分发事件 {} 次，链 {} 条（校准拒绝 {} 条）",
                dispatched, blackboard.chains().size(), blackboard.calibrationCount());
    }

    /** ANALYSIS 并行派发：各知识源（去重）并发响应阶段起始事件一次，join 后丢弃队列残余（无订阅者的 CHAIN_FOUND）。 */
    private int dispatchParallel(Map<EventType, List<KnowledgeSource>> subs) {
        java.util.Set<KnowledgeSource> started = new java.util.LinkedHashSet<>();
        for (List<KnowledgeSource> ksList : subs.values()) {
            started.addAll(ksList);
        }
        if (started.isEmpty()) {
            blackboard.clearEvents();
            return 0;
        }
        CountDownLatch done = new CountDownLatch(started.size());
        AtomicInteger dispatched = new AtomicInteger();
        for (KnowledgeSource ks : started) {
            new Thread(() -> {
                try {
                    ks.onEvent(blackboard, Event.of(EventType.SCAN_START, -1, null));
                    dispatched.incrementAndGet();
                } catch (Throwable t) {
                    JustLogger.error("知识源 {} ANALYSIS 并行执行失败（已隔离）: {}", ks.id(), t.toString());
                    if (JustLogger.isDebug()) {
                        t.printStackTrace();
                    }
                } finally {
                    done.countDown();
                }
            }, "just-ks-" + ks.id()).start();
        }
        try {
            done.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        // 不清空队列：ANALYSIS 期产生的 CHAIN_FOUND 留待后续阶段投递（延迟语义见 drain）
        return dispatched.get();
    }

    /**
     * 排空事件队列，按阶段订阅表分发（订阅序 = priority 序）。
     * 当前阶段无订阅者的非屏障事件（如 ANALYSIS 期产生、CALIBRATION 才订阅的 CHAIN_FOUND）
     * 延迟回填队列，供后续阶段投递——事件机制跨阶段真实可用，不再静默丢弃。
     */
    private int drain(Map<EventType, List<KnowledgeSource>> subs) {
        int dispatched = 0;
        List<Event> deferred = new ArrayList<>();
        while (blackboard.hasEvents()) {
            if (dispatched >= MAX_DISPATCH) {
                JustLogger.warn("事件派生超上限 {}，本阶段提前结束", MAX_DISPATCH);
                blackboard.clearEvents();
                break;
            }
            Event event = blackboard.poll();
            if (event == null) {
                break;
            }
            boolean barrier = event.type() == EventType.SCAN_ANALYZED
                    || event.type() == EventType.SCAN_COMPLETE;
            List<KnowledgeSource> interested = subs.get(event.type());
            if (interested == null && !barrier) {
                deferred.add(event); // 留给后续阶段的订阅者
                continue;
            }
            if (interested == null) {
                continue; // 屏障事件无订阅者：消费掉即完成阶段切换
            }
            for (KnowledgeSource ks : interested) {
                try {
                    ks.onEvent(blackboard, event);
                    dispatched++;
                } catch (Throwable e) {
                    JustLogger.error("知识源 {} 处理事件 {} 失败（已隔离）: {}", ks.id(), event.type(), e.toString());
                    if (JustLogger.isDebug()) {
                        e.printStackTrace();
                    }
                }
            }
        }
        for (Event e : deferred) {
            blackboard.publish(e);
        }
        return dispatched;
    }
}
