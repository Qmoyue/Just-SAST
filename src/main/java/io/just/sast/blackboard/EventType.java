package io.just.sast.blackboard;

/** 黑板事件类型（封闭集合）。 */
public enum EventType {
    /** 扫描启动：ANALYSIS 阶段知识源执行 */
    SCAN_START,
    /** 分析完成：COMPOSITION 阶段知识源执行 */
    SCAN_ANALYZED,
    /** 拼装完成：CALIBRATION 阶段知识源执行 */
    SCAN_COMPLETE,
    /** 新链产出（addChain 时发布；阶段屏障才是当前真实协作机制，此事件留作扩展点） */
    CHAIN_FOUND
}
