package io.just.sast.blackboard;

/** backward-taint 对某个 sink 的分析裁决（机器可读记录，报告层产出 sinks.csv）。 */
public record SinkOutcome(
        String ruleId, String category,
        String sinkOwner, String sinkMethod,
        String enclosingClass, String enclosingMethod,
        int chainsFound, String verdict, int steps, int unresolved, int tooLong) {}
