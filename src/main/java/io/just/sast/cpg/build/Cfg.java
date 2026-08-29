package io.just.sast.cpg.build;

import io.just.sast.model.InsnFact;
import io.just.sast.model.MethodInfo;
import io.just.sast.model.Op;
import io.just.sast.model.SwitchRef;
import io.just.sast.model.TryCatchFact;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** 指令级 CFG 计算（纯函数，按方法惰性调用）。 */
public final class Cfg {

    private Cfg() {}

    /**
     * Dense CFG view for the abstract interpreter. Method offsets are normalized to dense
     * instruction indexes by the frontend, so an array-backed successor table avoids one
     * HashMap lookup per instruction and one HashMap allocation per method. The legacy Map
     * view remains available for callers and tests that need sparse iteration.
     */
    public record Indexed(List<List<CfgEdge>> successors) {
        public Indexed {
            successors = successors == null ? List.of() : List.copyOf(successors);
        }

        public List<CfgEdge> successorsAt(int offset) {
            return offset >= 0 && offset < successors.size()
                    ? successors.get(offset) : List.of();
        }
    }

    public static Map<Integer, List<CfgEdge>> compute(MethodInfo method) {
        Mutable mutable = buildMutable(method);
        Map<Integer, List<CfgEdge>> result = new HashMap<>();
        for (int offset = 0; offset < mutable.edges.size(); offset++) {
            List<CfgEdge> edges = mutable.edges.get(offset);
            if (edges != null && !edges.isEmpty()) {
                result.put(offset, List.copyOf(edges));
            }
        }
        return result;
    }

    /** Dense successor table used by ForwardOrigins; semantics are identical to compute(). */
    public static Indexed computeIndexed(MethodInfo method) {
        Mutable mutable = buildMutable(method);
        List<List<CfgEdge>> frozen = new ArrayList<>(mutable.edges.size());
        for (List<CfgEdge> edges : mutable.edges) {
            frozen.add(edges == null || edges.isEmpty() ? List.of() : List.copyOf(edges));
        }
        return new Indexed(frozen);
    }

    private static Mutable buildMutable(MethodInfo method) {
        List<InsnFact> insns = method.instructions();
        Mutable mutable = new Mutable(insns.size());
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
            List<CfgEdge> succ = mutable.at(offset);
            if (op == Op.JSR) {
                // JSR = 调用子程序后继续：JUMP 到子程序 + fall-through 到返回点（ASTORE 的返回地址由 RET 消费）
                addJump(mutable, offset, insn.jumpTarget());
                if (offset < last) {
                    succ.add(new CfgEdge(offset + 1, CfgLabel.SEQ));
                }
            } else if (op.isUncondJump()) {
                addJump(mutable, offset, insn.jumpTarget());
            } else if (op.isSwitch()) {
                SwitchRef sw = (SwitchRef) insn.operands().get(0);
                for (var c : sw.cases()) {
                    addJump(mutable, offset, c.targetOffset());
                }
                addJump(mutable, offset, sw.defaultOffset());
            } else if (op.isCondJump()) {
                if (offset < last) {
                    succ.add(new CfgEdge(offset + 1, CfgLabel.FALSE));
                }
                addJump(mutable, offset, insn.jumpTarget());
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
                mutable.at(offset).add(new CfgEdge(tc.handler(), CfgLabel.EXCEPTION));
            }
        }
        return mutable;
    }

    private static void addJump(Mutable edges, int from, int target) {
        edges.at(from).add(new CfgEdge(target, CfgLabel.JUMP));
    }

    private static final class Mutable {
        private final List<List<CfgEdge>> edges;

        private Mutable(int size) {
            edges = new ArrayList<>(Collections.nCopies(size, null));
        }

        private List<CfgEdge> at(int offset) {
            List<CfgEdge> result = edges.get(offset);
            if (result == null) {
                result = new ArrayList<>(2);
                edges.set(offset, result);
            }
            return result;
        }
    }
}
