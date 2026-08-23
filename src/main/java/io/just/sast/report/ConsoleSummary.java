package io.just.sast.report;

import io.just.sast.blackboard.SinkOutcome;
import io.just.sast.util.JustLogger;

import java.util.LinkedHashMap;
import java.util.Map;

/** 控制台摘要（stderr）：扫描统计 + 反向引擎的逐规则过滤率。 */
public final class ConsoleSummary {

    private ConsoleSummary() {}

    public static void print(ScanStatistics stats, Map<Long, SinkOutcome> outcomes) {
        JustLogger.info("扫描完成：文件 {}，类 {}，诊断 {}，耗时 {} ms，堆内存 {} MB",
                stats.filesScanned(), stats.classesLoaded(), stats.diagnostics(),
                stats.elapsedMs(), stats.heapUsedMb());
        JustLogger.info("sink {} 个，magic entry {} 个，候选链 {} 条",
                stats.sinksMarked(), stats.magicEntries(), stats.chainsFound());
        Map<String, int[]> byRule = new LinkedHashMap<>();
        for (SinkOutcome outcome : outcomes.values()) {
            int[] counters = byRule.computeIfAbsent(outcome.ruleId(), k -> new int[2]);
            counters[0]++;
            if (outcome.chainsFound() > 0) {
                counters[1]++;
            }
        }
        for (Map.Entry<String, int[]> entry : byRule.entrySet()) {
            JustLogger.info("规则 {}：标记 {} 处，出链 {} 处（过滤率 {}%）",
                    entry.getKey(), entry.getValue()[0], entry.getValue()[1],
                    entry.getValue()[0] == 0 ? 100
                            : 100 - entry.getValue()[1] * 100 / entry.getValue()[0]);
        }
    }
}
