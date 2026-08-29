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
    public static final class Indexed {
        /*
         * CSR-style storage: one offset array and two primitive edge arrays. The old public
         * successorsAt/successors views are materialized only for compatibility callers; the
         * analysis hot path uses edgeStart/edgeEnd/targetAt/labelAt without allocating a list or
         * a CfgEdge object for every instruction visit.
         */
        private final int instructionCount;
        private final int[] edgeOffsets;
        private final int[] targets;
        private final byte[] labels;
        private static final CfgLabel[] LABELS = CfgLabel.values();
        private volatile List<List<CfgEdge>> legacyView;

        public Indexed(List<List<CfgEdge>> successors) {
            List<List<CfgEdge>> safe = successors == null ? List.of() : successors;
            this.instructionCount = safe.size();
            this.edgeOffsets = new int[instructionCount + 1];
            int edgeCount = 0;
            for (int i = 0; i < instructionCount; i++) {
                List<CfgEdge> edges = safe.get(i);
                edgeCount += edges == null ? 0 : edges.size();
                edgeOffsets[i + 1] = edgeCount;
            }
            this.targets = new int[edgeCount];
            this.labels = new byte[edgeCount];
            int cursor = 0;
            for (int i = 0; i < instructionCount; i++) {
                List<CfgEdge> edges = safe.get(i);
                if (edges == null) {
                    continue;
                }
                for (CfgEdge edge : edges) {
                    targets[cursor] = edge.targetOffset();
                    labels[cursor++] = labelCode(edge.label());
                }
            }
        }

        private Indexed(int instructionCount, int[] edgeOffsets,
                        int[] targets, byte[] labels) {
            this.instructionCount = instructionCount;
            this.edgeOffsets = edgeOffsets;
            this.targets = targets;
            this.labels = labels;
        }

        public int instructionCount() {
            return instructionCount;
        }

        public int edgeCount() {
            return targets.length;
        }

        public int edgeStart(int offset) {
            return offset >= 0 && offset < instructionCount ? edgeOffsets[offset] : 0;
        }

        public int edgeEnd(int offset) {
            return offset >= 0 && offset < instructionCount ? edgeOffsets[offset + 1] : 0;
        }

        public int targetAt(int edgeIndex) {
            return targets[edgeIndex];
        }

        public CfgLabel labelAt(int edgeIndex) {
            return LABELS[labels[edgeIndex]];
        }

        public List<CfgEdge> successorsAt(int offset) {
            int start = edgeStart(offset);
            int end = edgeEnd(offset);
            if (start == end) {
                return List.of();
            }
            List<CfgEdge> result = new ArrayList<>(end - start);
            for (int i = start; i < end; i++) {
                result.add(new CfgEdge(targets[i], labelAt(i)));
            }
            return List.copyOf(result);
        }

        /** Compatibility view; analyses should use the primitive accessors above. */
        public List<List<CfgEdge>> successors() {
            List<List<CfgEdge>> view = legacyView;
            if (view != null) {
                return view;
            }
            List<List<CfgEdge>> result = new ArrayList<>(instructionCount);
            for (int i = 0; i < instructionCount; i++) {
                result.add(successorsAt(i));
            }
            view = List.copyOf(result);
            legacyView = view;
            return view;
        }

        private static byte labelCode(CfgLabel label) {
            return (byte) (label == null ? CfgLabel.SEQ.ordinal() : label.ordinal());
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
        int instructionCount = mutable.edges.size();
        int[] edgeOffsets = new int[instructionCount + 1];
        int edgeCount = 0;
        for (int i = 0; i < instructionCount; i++) {
            List<CfgEdge> edges = mutable.edges.get(i);
            edgeCount += edges == null ? 0 : edges.size();
            edgeOffsets[i + 1] = edgeCount;
        }
        int[] targets = new int[edgeCount];
        byte[] labels = new byte[edgeCount];
        int cursor = 0;
        for (List<CfgEdge> edges : mutable.edges) {
            if (edges == null) {
                continue;
            }
            for (CfgEdge edge : edges) {
                targets[cursor] = edge.targetOffset();
                labels[cursor++] = Indexed.labelCode(edge.label());
            }
        }
        return new Indexed(instructionCount, edgeOffsets, targets, labels);
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
        // 异常边：只把可能抛出异常的指令连到 handler。未知指令仍保守保留，
        // 已知不会抛异常的常量/局部/纯算术指令不再制造无意义的 handler 合流。
        for (TryCatchFact tc : method.tryCatch()) {
            for (int offset = tc.start(); offset < tc.end() && offset < insns.size(); offset++) {
                if (tc.handler() >= insns.size()) {
                    continue;
                }
                if (insns.get(offset).op().mayThrow()) {
                    mutable.at(offset).add(new CfgEdge(tc.handler(), CfgLabel.EXCEPTION));
                }
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
