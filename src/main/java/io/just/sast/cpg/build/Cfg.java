package io.just.sast.cpg.build;

import io.just.sast.model.InsnFact;
import io.just.sast.model.MethodInfo;
import io.just.sast.model.Op;
import io.just.sast.model.SwitchRef;
import io.just.sast.model.TryCatchFact;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** 指令级 CFG 计算（纯函数，按方法惰性调用）。 */
public final class Cfg {

    private Cfg() {}

    public static Map<Integer, List<CfgEdge>> compute(MethodInfo method) {
        Map<Integer, List<CfgEdge>> edges = new HashMap<>();
        List<InsnFact> insns = method.instructions();
        int last = insns.size() - 1;
        for (InsnFact insn : insns) {
            int offset = insn.offset();
            Op op = insn.op();
            if (op == Op.UNKNOWN || op == Op.RET) {
                continue; // 未知指令不产生边；RET 从子程序返回（目标在调用方 JSR 的返回地址，无静态后继）
            }
            if (op.isReturn()) {
                continue;
            }
            List<CfgEdge> succ = edges.computeIfAbsent(offset, k -> new ArrayList<>(2));
            if (op == Op.JSR) {
                // JSR = 调用子程序后继续：JUMP 到子程序 + fall-through 到返回点（ASTORE 的返回地址由 RET 消费）
                addJump(edges, offset, insn.jumpTarget());
                if (offset < last) {
                    succ.add(new CfgEdge(offset + 1, CfgLabel.SEQ));
                }
            } else if (op.isUncondJump()) {
                addJump(edges, offset, insn.jumpTarget());
            } else if (op.isSwitch()) {
                SwitchRef sw = (SwitchRef) insn.operands().get(0);
                for (var c : sw.cases()) {
                    addJump(edges, offset, c.targetOffset());
                }
                addJump(edges, offset, sw.defaultOffset());
            } else if (op.isCondJump()) {
                if (offset < last) {
                    succ.add(new CfgEdge(offset + 1, CfgLabel.FALSE));
                }
                addJump(edges, offset, insn.jumpTarget());
            } else if (offset < last) {
                succ.add(new CfgEdge(offset + 1, CfgLabel.SEQ));
            }
        }
        // 异常边
        for (TryCatchFact tc : method.tryCatch()) {
            for (int offset = tc.start(); offset < tc.end() && offset < insns.size(); offset++) {
                if (tc.handler() >= insns.size()) {
                    continue;
                }
                edges.computeIfAbsent(offset, k -> new ArrayList<>(2))
                        .add(new CfgEdge(tc.handler(), CfgLabel.EXCEPTION));
            }
        }
        return edges;
    }

    private static void addJump(Map<Integer, List<CfgEdge>> edges, int from, int target) {
        edges.computeIfAbsent(from, k -> new ArrayList<>(2)).add(new CfgEdge(target, CfgLabel.JUMP));
    }
}
