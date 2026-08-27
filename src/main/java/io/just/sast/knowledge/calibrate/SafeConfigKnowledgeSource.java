package io.just.sast.knowledge.calibrate;

import io.just.sast.blackboard.Blackboard;
import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.Event;
import io.just.sast.blackboard.EventType;
import io.just.sast.blackboard.KnowledgeSource;
import io.just.sast.blackboard.Phase;
import io.just.sast.cpg.graph.Node;
import io.just.sast.cpg.graph.NodeType;
import io.just.sast.model.InsnFact;
import io.just.sast.model.MethodInfo;
import io.just.sast.model.MethodRef;
import io.just.sast.util.JustLogger;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * SafeConfig 抑制知识源（CALIBRATION 阶段，借鉴 CodeQL SafeXStreamConfig/SafeKryoConfig/SafeObjectMapperConfig）。
 * 数据驱动：安全配置清单来自 source 规则的 safe-config 声明块（YAML），引擎零硬编码。
 *
 * 检测语义：同一方法体内**先**调用安全配置（白名单/注册要求/安全模式）**再**调用该框架入口
 * （按指令偏移序校验——先反序列化后配置的代码不抑制）时，该入口产生的链全部抑制——
 * 纯降噪，安全配置后的入口不构成攻击面。
 * 启发式限制：不追踪实参值（如 setRegistrationRequired(false) 无法区分），保守用于降噪。
 */
public final class SafeConfigKnowledgeSource implements KnowledgeSource {

    private Blackboard bb;

    @Override
    public String id() {
        return "safe-config";
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
        return 300;
    }

    @Override
    public void init(Blackboard blackboard) {
        this.bb = blackboard;
    }

    @Override
    public void onEvent(Blackboard bb, Event event) {
        if (event.type() != EventType.SCAN_COMPLETE) {
            return;
        }
        // 只处理带 safe-config 声明的 source 规则
        List<io.just.sast.config.Rule.SourceRule> guarded = bb.rules().sources().stream()
                .filter(src -> src.safeConfig() != null)
                .toList();
        if (guarded.isEmpty()) {
            return;
        }
        // 找安全配置先于入口调用的方法（owner#name，与链的 entry 归属同口径）
        Set<String> safeEntryKeys = findSafeConfiguredEntries(guarded);
        if (safeEntryKeys.isEmpty()) {
            return;
        }
        int rejected = 0;
        for (Chain chain : bb.chains()) {
            if (bb.calibrationOf(chain.key()) != null) {
                continue; // 已被前面校验拒绝
            }
            String entryKey = chain.entryClass() + "#" + chain.entryMethod();
            if (safeEntryKeys.contains(entryKey)) {
                bb.calibrateChain(chain.key(), "safe-config");
                rejected++;
            }
        }
        if (rejected > 0) {
            JustLogger.info("SafeConfig 抑制：{} 条链（入口方法内安全配置先于框架调用）", rejected);
        }
    }

    /** 方法体内存在"安全配置调用早于（偏移更小）该规则框架入口调用"的 owner#name 集合。 */
    private Set<String> findSafeConfiguredEntries(List<io.just.sast.config.Rule.SourceRule> guarded) {
        Set<String> result = new HashSet<>();
        var support = bb.originSupport();
        for (Node method : bb.graph().nodesOfType(NodeType.METHOD)) {
            MethodInfo info = support.methodOf(method.strProp("owner"),
                    method.strProp("name"), method.strProp("desc"));
            if (info == null) {
                continue;
            }
            // 每条规则记最早的安全配置偏移与最早的入口调用偏移
            Map<io.just.sast.config.Rule.SourceRule, int[]> offsets = new HashMap<>();
            List<InsnFact> insns = info.instructions();
            for (int idx = 0; idx < insns.size(); idx++) {
                InsnFact insn = insns.get(idx);
                if (!insn.op().isInvoke() || insn.operands().isEmpty()) {
                    continue;
                }
                if (!(insn.operands().get(0) instanceof MethodRef ref)) {
                    continue;
                }
                for (io.just.sast.config.Rule.SourceRule src : guarded) {
                    int[] pair = offsets.computeIfAbsent(src, k -> new int[] {Integer.MAX_VALUE, Integer.MAX_VALUE});
                    if (isSafeConfigCall(src.safeConfig(), ref.owner(), ref.name())) {
                        // 布尔安全开关求值：实参常量 == safe-value 才算已加固
                        // （如 Kryo.setRegistrationRequired(false) 是关闭安全模式，不是加固）
                        Boolean actual = pushedBooleanValue(info.instructions(), idx);
                        Boolean expected = src.safeConfig().safeValue();
                        boolean safe = expected == null || actual == null || actual.equals(expected);
                        if (safe) {
                            pair[0] = Math.min(pair[0], insn.offset());
                        }
                    }
                    if (src.call().matches(ref.owner(), ref.name(), ref.descriptor())) {
                        pair[1] = Math.min(pair[1], insn.offset());
                    }
                }
            }
            for (int[] pair : offsets.values()) {
                if (pair[0] < pair[1]) { // 配置先于入口
                    result.add(info.owner() + "#" + info.name());
                    break;
                }
            }
        }
        return result;
    }

    private static boolean isSafeConfigCall(io.just.sast.config.Rule.SafeConfigDecl safe, String owner, String name) {
        return owner.startsWith(safe.owner().pattern()) && safe.methods().contains(name);
    }

    /** 调用点前最近的一条整型常量推送（≤6 条内）：ICONST/BIPUSH/SIPUSH/LDC-int。无法判定为 null。 */
    private static Boolean pushedBooleanValue(List<InsnFact> insns, int invokeIdx) {
        for (int j = invokeIdx - 1; j >= 0 && j >= invokeIdx - 6; j--) {
            InsnFact f = insns.get(j);
            switch (f.op()) {
                case ICONST_0 -> {
                    return false;
                }
                case ICONST_1 -> {
                    return true;
                }
                case BIPUSH, SIPUSH, LDC -> {
                    if (!f.operands().isEmpty() && f.operands().get(0) instanceof Integer i) {
                        return i == 1;
                    }
                    return null;
                }
                default -> {
                }
            }
        }
        return null;
    }
}
