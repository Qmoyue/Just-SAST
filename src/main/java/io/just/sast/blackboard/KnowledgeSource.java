package io.just.sast.blackboard;

import java.util.Set;

/**
 * 知识源接口（插件化扩展点）。
 * 知识源之间零直接调用：只读写黑板，通过阶段协作。
 * 契约：ANALYSIS 阶段知识源必须自足（经黑板分发的 RuleEngine 匹配 sink/entry，不读其他知识源产物）；
 * 控制器串行三阶段调度，知识源无需线程安全。
 * 同阶段内的执行顺序由 priority() 显式声明（小者先）——跨源数据依赖（如 pruner 消费 validator
 * 的裁决）必须落到 priority，不依赖 ServiceLoader 注册顺序。
 */
public interface KnowledgeSource {

    /** 唯一标识。 */
    String id();

    /** 关心的事件类型。 */
    Set<EventType> interests();

    /** 执行阶段，默认 ANALYSIS。 */
    default Phase phase() {
        return Phase.ANALYSIS;
    }

    /** 同阶段内执行序（小者先，默认 500；同值保持注册顺序稳定）。 */
    default int priority() {
        return 500;
    }

    /** 初始化（规则编译、索引准备）；异常由控制器隔离，不中断其他知识源。 */
    void init(Blackboard blackboard);

    /** 响应事件。 */
    void onEvent(Blackboard blackboard, Event event);
}
