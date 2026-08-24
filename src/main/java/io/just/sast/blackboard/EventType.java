package io.just.sast.blackboard;

/** 黑板事件类型（封闭集合）。 */
public enum EventType {
    /** 扫描启动：ANALYSIS 阶段知识源执行 */
    SCAN_START,
    /** 分析完成：COMPOSITION 阶段知识源执行 */
    SCAN_ANALYZED,
    /** 拼装完成：CALIBRATION 阶段知识源执行 */
    SCAN_COMPLETE,
    /** 新链产出（addChain 时发布；当前阶段无订阅者则延迟投递到后续阶段——跨阶段事件机制真实可用） */
    CHAIN_FOUND
}
