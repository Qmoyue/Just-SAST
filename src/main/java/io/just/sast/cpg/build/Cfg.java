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
        private final boolean valid;
        private static final CfgLabel[] LABELS = CfgLabel.values();
        private volatile List<List<CfgEdge>> legacyView;

        public Indexed(List<List<CfgEdge>> successors) {
            List<List<CfgEdge>> safe = successors == null ? List.of() : successors;
            this.instructionCount = safe.size();
            this.valid = true;
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
                        int[] targets, byte[] labels, boolean valid) {
            this.instructionCount = instructionCount;
            this.edgeOffsets = edgeOffsets;
            this.targets = targets;
            this.labels = labels;
            this.valid = valid;
        }

        public int instructionCount() {
            return instructionCount;
        }

        public int edgeCount() {
            return targets.length;
        }

        /** Whether the table was built from a structurally valid instruction layout. */
        public boolean valid() {
            return valid;
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
        if (!validInstructionLayout(method)) {
            return Map.of();
        }
        Mutable mutable;
        try {
            mutable = buildMutable(method);
        } catch (RuntimeException malformed) {
            // The frontend normally rejects malformed operands. Keep this public compatibility
            // view total for extension callers that construct MethodInfo directly; the indexed
            // path below exposes the invalid bit so the abstract interpreter marks incomplete.
            return Map.of();
        }
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
        /*
         * The indexed representation is the hot path. Do not build the legacy
         * List<List<CfgEdge>> only to immediately copy it into CSR arrays: on a
         * large jar that temporary object graph is both measurable CPU work and a
         * peak-memory multiplier. Count and fill the same semantic edge classes in
         * two passes instead. The order is deliberately normal edges first and
         * exception edges second, matching buildMutable().
         */
        if (!validInstructionLayout(method)) {
            int count = method == null || method.instructions() == null
                    ? 0 : method.instructions().size();
            return invalid(count);
        }
        List<InsnFact> insns = method.instructions();
        int instructionCount = insns.size();
        try {
            int last = instructionCount - 1;
            int[] edgeCounts = new int[instructionCount];
            for (InsnFact insn : insns) {
                int offset = insn.offset();
                edgeCounts[offset] += normalEdgeCount(insn, offset, last);
            }
            List<TryCatchFact> tryCatch = method.tryCatch() == null
                    ? List.of() : method.tryCatch();
            for (TryCatchFact tc : tryCatch) {
                if (tc == null) {
                    return invalid(instructionCount);
                }
                for (int offset = Math.max(0, tc.start());
                     offset < tc.end() && offset < instructionCount; offset++) {
                    if (tc.handler() >= 0 && tc.handler() < instructionCount
                            && insns.get(offset).op().mayThrow()) {
                        edgeCounts[offset]++;
                    }
                }
            }

            int[] edgeOffsets = new int[instructionCount + 1];
            for (int i = 0; i < instructionCount; i++) {
                edgeOffsets[i + 1] = edgeOffsets[i] + edgeCounts[i];
            }
            int[] targets = new int[edgeOffsets[instructionCount]];
            byte[] labels = new byte[targets.length];
            int[] cursor = java.util.Arrays.copyOf(edgeOffsets, instructionCount);
            for (InsnFact insn : insns) {
                appendNormalEdges(insn, insn.offset(), last, cursor, targets, labels);
            }
            for (TryCatchFact tc : tryCatch) {
                for (int offset = Math.max(0, tc.start());
                     offset < tc.end() && offset < instructionCount; offset++) {
                    if (tc.handler() >= 0 && tc.handler() < instructionCount
                            && insns.get(offset).op().mayThrow()) {
                        appendEdge(offset, tc.handler(), CfgLabel.EXCEPTION, cursor, targets, labels);
                    }
                }
            }
            return new Indexed(instructionCount, edgeOffsets, targets, labels, true);
        } catch (RuntimeException malformed) {
            return invalid(instructionCount);
        }
    }

    private static Indexed invalid(int instructionCount) {
        int count = Math.max(0, instructionCount);
        return new Indexed(count, new int[count + 1], new int[0], new byte[0], false);
    }

    private static boolean validInstructionLayout(MethodInfo method) {
        if (method == null || method.instructions() == null) {
            return false;
        }
        List<InsnFact> insns = method.instructions();
        for (int i = 0; i < insns.size(); i++) {
            InsnFact insn = insns.get(i);
            if (insn == null || insn.op() == null || insn.offset() != i
                    || insn.operands() == null) {
                return false;
            }
        }
        return true;
    }

    private static int normalEdgeCount(InsnFact insn, int offset, int last) {
        Op op = insn.op();
        if (op == Op.UNKNOWN || op == Op.RET || op.isReturn()) {
            return 0;
        }
        if (op == Op.JSR) {
            return offset < last ? 2 : 1;
        }
        if (op.isUncondJump()) {
            return 1;
        }
        if (op.isSwitch()) {
            SwitchRef sw = (SwitchRef) insn.operands().get(0);
            return sw.cases().size() + 1;
        }
        if (op.isCondJump()) {
            return offset < last ? 2 : 1;
        }
        return offset < last ? 1 : 0;
    }

    private static void appendNormalEdges(InsnFact insn, int offset, int last,
                                          int[] cursor, int[] targets, byte[] labels) {
        Op op = insn.op();
        if (op == Op.UNKNOWN || op == Op.RET || op.isReturn()) {
            return;
        }
        if (op == Op.JSR) {
            appendEdge(offset, insn.jumpTarget(), CfgLabel.JUMP, cursor, targets, labels);
            if (offset < last) {
                appendEdge(offset, offset + 1, CfgLabel.SEQ, cursor, targets, labels);
            }
        } else if (op.isUncondJump()) {
            appendEdge(offset, insn.jumpTarget(), CfgLabel.JUMP, cursor, targets, labels);
        } else if (op.isSwitch()) {
            SwitchRef sw = (SwitchRef) insn.operands().get(0);
            for (var c : sw.cases()) {
                appendEdge(offset, c.targetOffset(), CfgLabel.JUMP, cursor, targets, labels);
            }
            appendEdge(offset, sw.defaultOffset(), CfgLabel.JUMP, cursor, targets, labels);
        } else if (op.isCondJump()) {
            if (offset < last) {
                appendEdge(offset, offset + 1, CfgLabel.FALSE, cursor, targets, labels);
            }
            appendEdge(offset, insn.jumpTarget(), CfgLabel.JUMP, cursor, targets, labels);
        } else if (offset < last) {
            appendEdge(offset, offset + 1, CfgLabel.SEQ, cursor, targets, labels);
        }
    }

    private static void appendEdge(int from, int target, CfgLabel label,
                                   int[] cursor, int[] targets, byte[] labels) {
        int index = cursor[from]++;
        targets[index] = target;
        labels[index] = Indexed.labelCode(label);
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
        List<TryCatchFact> tryCatch = method.tryCatch() == null ? List.of() : method.tryCatch();
        for (TryCatchFact tc : tryCatch) {
            if (tc == null) {
                continue;
            }
            for (int offset = tc.start(); offset < tc.end() && offset < insns.size(); offset++) {
                if (tc.handler() < 0 || tc.handler() >= insns.size()) {
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
