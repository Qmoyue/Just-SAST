package io.just.sast.cpg.build;

import io.just.sast.model.InsnFact;
import io.just.sast.model.MethodInfo;
import io.just.sast.model.Op;
import io.just.sast.model.TryCatchFact;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 紧凑的字节码语义 CPG 索引。
 *
 * <p>图核心只保留关系真正需要的节点；方法内的调用、字段、控制和分配事实以
 * offset 切片保存，CFG 仍然按需建立。CFG 缓存共享给所有分析消费者，避免同一
 * 方法在来源传播、路径证明和代理元数据分析中重复构建。索引不保存 MethodInfo，
 * 因而不会延长前端原始输入的生命周期。</p>
 */
public final class CpgIndex {

    @FunctionalInterface
    public interface CfgProvider {
        Cfg.Indexed cfg(MethodInfo method);
    }

    /** 一个方法在 CPG 中可查询的紧凑语义切片。offset 与 MethodInfo 指令下标一致。 */
    public static final class MethodSlice {
        private final String methodKey;
        private final int instructionCount;
        private final int[] callOffsets;
        private final int[] fieldReadOffsets;
        private final int[] fieldWriteOffsets;
        private final int[] controlOffsets;
        private final int[] allocationOffsets;
        private final int[] exceptionHandlerOffsets;
        private final int[] effectOffsets;

        private MethodSlice(String methodKey, int instructionCount, int[] callOffsets,
                            int[] fieldReadOffsets, int[] fieldWriteOffsets,
                            int[] controlOffsets, int[] allocationOffsets,
                            int[] exceptionHandlerOffsets, int[] effectOffsets) {
            this.methodKey = methodKey;
            this.instructionCount = instructionCount;
            this.callOffsets = callOffsets;
            this.fieldReadOffsets = fieldReadOffsets;
            this.fieldWriteOffsets = fieldWriteOffsets;
            this.controlOffsets = controlOffsets;
            this.allocationOffsets = allocationOffsets;
            this.exceptionHandlerOffsets = exceptionHandlerOffsets;
            this.effectOffsets = effectOffsets;
        }

        public String methodKey() {
            return methodKey;
        }

        public int instructionCount() {
            return instructionCount;
        }

        public int[] callOffsets() {
            return callOffsets.clone();
        }

        public int[] fieldReadOffsets() {
            return fieldReadOffsets.clone();
        }

        public int[] fieldWriteOffsets() {
            return fieldWriteOffsets.clone();
        }

        public int[] controlOffsets() {
            return controlOffsets.clone();
        }

        public int[] allocationOffsets() {
            return allocationOffsets.clone();
        }

        public int[] exceptionHandlerOffsets() {
            return exceptionHandlerOffsets.clone();
        }

        /** Offsets whose transfer can change an interprocedural/field summary. */
        public int[] effectOffsets() {
            return effectOffsets.clone();
        }

        public boolean hasCalls() {
            return callOffsets.length != 0;
        }

        public boolean hasControlFlow() {
            return controlOffsets.length != 0 || exceptionHandlerOffsets.length != 0;
        }
    }

    private final Map<String, MethodSlice> slices;
    /** CFG is a value object and is safe to share between read-only analysis consumers. */
    private final ConcurrentHashMap<String, Cfg.Indexed> cfgCache = new ConcurrentHashMap<>();

    private CpgIndex(Map<String, MethodSlice> slices) {
        this.slices = Map.copyOf(slices);
    }

    public static CpgIndex empty() {
        return new CpgIndex(Map.of());
    }

    public static Builder builder() {
        return new Builder();
    }

    public MethodSlice slice(String methodKey) {
        return slices.get(methodKey);
    }

    /**
     * Return the shared CFG for a method. A missing slice is valid for compatibility with
     * callers that construct a Blackboard directly in tests; it still benefits from the
     * same cache and does not change CFG semantics.
     */
    public Cfg.Indexed cfg(MethodInfo method) {
        if (method == null || method.instructions().isEmpty()) {
            return new Cfg.Indexed(java.util.List.of());
        }
        String key = method.owner() + "#" + method.name() + method.descriptor();
        return cfgCache.computeIfAbsent(key, ignored -> Cfg.computeIndexed(method));
    }

    public int methodCount() {
        return slices.size();
    }

    public int cfgCacheSize() {
        return cfgCache.size();
    }

    /** Single-owner builder used while CpgBuilder already walks each method. */
    public static final class Builder {
        private final Map<String, MethodSlice> slices = new LinkedHashMap<>();

        public MethodSliceBuilder start(MethodInfo method) {
            String key = method.owner() + "#" + method.name() + method.descriptor();
            return new MethodSliceBuilder(key, method.instructions().size());
        }

        private void finish(MethodSlice slice) {
            slices.put(slice.methodKey(), slice);
        }

        public CpgIndex build() {
            return new CpgIndex(slices);
        }

        public final class MethodSliceBuilder {
            private final String methodKey;
            private final int instructionCount;
            private final IntCollector calls = new IntCollector();
            private final IntCollector fieldReads = new IntCollector();
            private final IntCollector fieldWrites = new IntCollector();
            private final IntCollector controls = new IntCollector();
            private final IntCollector allocations = new IntCollector();
            private final IntCollector exceptionHandlers = new IntCollector();
            private final IntCollector effects = new IntCollector();
            private boolean finished;

            private MethodSliceBuilder(String methodKey, int instructionCount) {
                this.methodKey = methodKey;
                this.instructionCount = instructionCount;
            }

            public void accept(InsnFact insn) {
                if (finished || insn == null) {
                    throw new IllegalStateException("方法切片已结束或指令为空");
                }
                Op op = insn.op();
                if (op.isFieldWrite() || op == Op.AASTORE || op.isInvoke()
                        || (op.isReturn() && op != Op.RETURN && op != Op.ATHROW)) {
                    effects.add(insn.offset());
                }
                if (op.isInvoke()) {
                    calls.add(insn.offset());
                }
                if (op.isFieldRead()) {
                    fieldReads.add(insn.offset());
                }
                if (op.isFieldWrite()) {
                    fieldWrites.add(insn.offset());
                }
                if (op.isCondJump() || op.isUncondJump() || op.isSwitch()) {
                    controls.add(insn.offset());
                }
                if (op == Op.NEW || op == Op.NEWARRAY || op == Op.ANEWARRAY
                        || op == Op.MULTIANEWARRAY) {
                    allocations.add(insn.offset());
                }
            }

            public void accept(TryCatchFact tryCatch) {
                if (finished || tryCatch == null) {
                    throw new IllegalStateException("方法切片已结束或异常表为空");
                }
                exceptionHandlers.add(tryCatch.handler());
            }

            public MethodSlice finish() {
                if (finished) {
                    throw new IllegalStateException("方法切片重复结束");
                }
                finished = true;
                MethodSlice result = new MethodSlice(methodKey, instructionCount,
                        calls.toArray(), fieldReads.toArray(), fieldWrites.toArray(),
                        controls.toArray(), allocations.toArray(), exceptionHandlers.toArray(),
                        effects.toArray());
                Builder.this.finish(result);
                return result;
            }
        }
    }

    private static final class IntCollector {
        private int[] values = new int[8];
        private int size;

        private void add(int value) {
            if (size == values.length) {
                int[] expanded = new int[values.length << 1];
                System.arraycopy(values, 0, expanded, 0, values.length);
                values = expanded;
            }
            values[size++] = value;
        }

        private int[] toArray() {
            int[] result = new int[size];
            System.arraycopy(values, 0, result, 0, size);
            return result;
        }
    }
}
