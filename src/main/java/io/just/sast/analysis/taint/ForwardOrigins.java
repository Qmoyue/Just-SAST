package io.just.sast.analysis.taint;

import io.just.sast.cpg.build.Cfg;
import io.just.sast.cpg.build.CfgEdge;
import io.just.sast.cpg.build.CfgLabel;
import io.just.sast.model.Descriptor;
import io.just.sast.model.InsnFact;
import io.just.sast.model.InvokeDynamicRef;
import io.just.sast.model.MethodInfo;
import io.just.sast.model.MethodRef;
import io.just.sast.model.Op;
import io.just.sast.util.JustLogger;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 方法内正向抽象解释：计算每条指令执行前的栈/局部变量值来源。
 * 惰性计算 + 缓存；栈槽合并 = 来源集合并（收敛）；数组写入记录元素来源。
 *
 * 栈语义对齐 JVM 规范（精度根基）：
 * - 栈条目携带 category-2 标记：long/double 为单条目占 2 槽；
 *   POP2/DUP2/DUP2_X1/DUP2_X2/DUP_X2 按 JVM 类别语义解释（顶部或下方值为 cat-2 时按单值操作）
 * - TABLESWITCH/LOOKUPSWITCH 弹出 key
 * - 异常边进入 handler：清空栈、压入单个异常对象（Unknown），locals 保留
 * - wide 参数/存储占 2 槽（次槽来源清除）
 */
public final class ForwardOrigins {

    /** 栈槽：值来源集合 + category-2 标记（long/double 单条目）。 */
    public record Slot(Set<ValueOrigin> origins, boolean cat2) {}

    /** 某点的值来源状态。 */
    public record State(List<Slot> stack, List<Set<ValueOrigin>> locals) {

        public State merge(State other) {
            if (stack.size() != other.stack.size() && JustLogger.isDebug()) {
                JustLogger.debug("origin 栈高不一致合并：{} vs {}（保守截断到公共高度）",
                        stack.size(), other.stack.size());
            }
            List<Slot> mergedStack = new ArrayList<>();
            int depth = Math.min(stack.size(), other.stack.size());
            for (int i = 0; i < depth; i++) {
                Slot a = stack.get(i);
                Slot b = other.stack.get(i);
                mergedStack.add(new Slot(union(a.origins(), b.origins()), a.cat2() || b.cat2()));
            }
            List<Set<ValueOrigin>> mergedLocals = new ArrayList<>(locals.size());
            for (int i = 0; i < locals.size(); i++) {
                mergedLocals.add(union(locals.get(i), other.locals.get(i)));
            }
            return new State(mergedStack, mergedLocals);
        }
    }

    /** 方法级结果。 */
    public record Result(Map<Integer, State> stateBefore,
                         Map<ValueOrigin, Set<ValueOrigin>> arrayElements) {}

    private static final Slot UNKNOWN_SLOT = new Slot(Set.of(new ValueOrigin.Unknown()), false);

    private final Map<String, Long> callIdByKey;
    private final Map<String, Result> cache = new java.util.concurrent.ConcurrentHashMap<>();

    public ForwardOrigins(Map<String, Long> callIdByKey) {
        this.callIdByKey = callIdByKey;
    }

    public Result compute(MethodInfo method) {
        String key = CfgKey.of(method);
        Result cached = cache.get(key);
        if (cached != null) {
            return cached;
        }
        Result result = analyze(method);
        cache.put(key, result);
        return result;
    }

    private Result analyze(MethodInfo method) {
        Map<Integer, List<CfgEdge>> cfg = Cfg.compute(method);
        int maxLocals = maxLocals(method);
        List<Set<ValueOrigin>> initLocals = new ArrayList<>(maxLocals);
        for (int i = 0; i < maxLocals; i++) {
            initLocals.add(new LinkedHashSet<>());
        }
        List<Integer> argSlots = Descriptor.argSlots(method.descriptor(), method.isStatic());
        int slot = 0;
        for (Integer width : argSlots) {
            initLocals.get(slot).add(new ValueOrigin.Param(slot));
            slot += width;
        }

        Map<Integer, State> before = new HashMap<>();
        Map<ValueOrigin, Set<ValueOrigin>> arrayElements = new HashMap<>();
        Deque<Integer> worklist = new ArrayDeque<>();
        State entry = new State(new ArrayList<>(), initLocals);
        before.put(0, entry);
        worklist.add(0);
        while (!worklist.isEmpty()) {
            int offset = worklist.poll();
            State state = before.get(offset);
            if (state == null) {
                continue;
            }
            State out = transfer(method, method.insnAt(offset), state, arrayElements);
            for (CfgEdge edge : cfg.getOrDefault(offset, List.of())) {
                // 异常边：进入 handler 时 JVM 清空栈并压入异常对象，locals 保留
                State incoming = edge.label() == CfgLabel.EXCEPTION ? exceptionState(out) : out;
                State old = before.get(edge.targetOffset());
                State merged = old == null ? incoming : old.merge(incoming);
                if (!merged.equals(old)) {
                    before.put(edge.targetOffset(), merged);
                    worklist.add(edge.targetOffset());
                }
            }
        }
        return new Result(before, arrayElements);
    }

    private int maxLocals(MethodInfo method) {
        int max = 0;
        for (InsnFact insn : method.instructions()) {
            Op op = insn.op();
            if (op.isLoad() || op.isStore() || op == Op.IINC || op == Op.RET) {
                max = Math.max(max, insn.varIndex() + 1);
            }
        }
        return Math.max(max, Descriptor.argSlots(method.descriptor(), method.isStatic())
                .stream().mapToInt(Integer::intValue).sum());
    }

    private State transfer(MethodInfo method, InsnFact insn, State in,
                           Map<ValueOrigin, Set<ValueOrigin>> arrayElements) {
        List<Slot> stack = new ArrayList<>(in.stack());
        List<Set<ValueOrigin>> locals = new ArrayList<>(in.locals());
        Op op = insn.op();
        switch (op) {
            case NOP, GOTO, RET -> {
                // 无栈变化（RET 读局部变量表中的返回地址，CFG 中无后继）
            }
            case JSR ->
                    // 压入返回地址占位（不可控常量）；后续 ASTORE 会把它存入局部变量，RET 消费后不再传播
                    push(stack, new Slot(Set.of(new ValueOrigin.Constant("jsr-address")), false));
            case TABLESWITCH, LOOKUPSWITCH -> pop(stack); // 弹出 switch key
            case ACONST_NULL, ICONST_M1, ICONST_0, ICONST_1, ICONST_2, ICONST_3, ICONST_4, ICONST_5,
                    FCONST_0, FCONST_1, FCONST_2, BIPUSH, SIPUSH ->
                    push(stack, new Slot(Set.of(new ValueOrigin.Constant(op.name())), false));
            case LCONST_0, LCONST_1, DCONST_0, DCONST_1 ->
                    push(stack, new Slot(Set.of(new ValueOrigin.Constant(op.name())), true));
            case LDC -> push(stack, new Slot(Set.of(new ValueOrigin.Constant(insn.constant())),
                    insn.constant() instanceof Long || insn.constant() instanceof Double));
            case LLOAD, DLOAD -> push(stack, new Slot(local(locals, insn.varIndex()), true));
            case ILOAD, FLOAD, ALOAD -> push(stack, new Slot(local(locals, insn.varIndex()), false));
            case ISTORE, FSTORE, ASTORE -> locals.set(insn.varIndex(), pop(stack).origins());
            case LSTORE, DSTORE -> {
                // wide 存储占 2 槽：次槽来源一并清除
                locals.set(insn.varIndex(), pop(stack).origins());
                if (insn.varIndex() + 1 < locals.size()) {
                    locals.set(insn.varIndex() + 1, Set.of());
                }
            }
            case IINC -> locals.set(insn.varIndex(),
                    union(local(locals, insn.varIndex()), Set.of(new ValueOrigin.Insn(insn.offset()))));
            case GETFIELD -> {
                ValueOrigin receiver = canonicalReceiver(pop(stack).origins());
                push(stack, new Slot(Set.of(new ValueOrigin.FieldRead(
                        insn.fieldRef().owner(), insn.fieldRef().name(), false, receiver)),
                        isCat2(insn.fieldRef().descriptor())));
            }
            case GETSTATIC -> push(stack, new Slot(Set.of(new ValueOrigin.FieldRead(
                    insn.fieldRef().owner(), insn.fieldRef().name(), true,
                    new ValueOrigin.Unknown())), isCat2(insn.fieldRef().descriptor())));
            case PUTSTATIC -> pop(stack);
            case PUTFIELD -> {
                pop(stack);
                pop(stack);
            }
            case INVOKESTATIC, INVOKEVIRTUAL, INVOKESPECIAL, INVOKEINTERFACE, INVOKEDYNAMIC -> {
                int argc = callArgCount(insn, op);
                for (int i = 0; i < argc; i++) {
                    pop(stack);
                }
                String returnDesc = op == Op.INVOKEDYNAMIC
                        ? Descriptor.returnType(insn.operands().isEmpty() ? "()V"
                                : ((InvokeDynamicRef) insn.operands().get(0)).descriptor())
                        : Descriptor.returnType(insn.methodRef().descriptor());
                Long callId = callIdByKey.get(CfgKey.of(method) + "@" + insn.offset());
                push(stack, new Slot(Set.of(new ValueOrigin.CallResult(callId == null ? -1 : callId)),
                        isCat2(returnDesc)));
            }
            case NEW, NEWARRAY, ANEWARRAY, MULTIANEWARRAY -> {
                int pops = op == Op.NEW ? 0 : op == Op.MULTIANEWARRAY ? (Integer) insn.operands().get(1) : 1;
                for (int i = 0; i < pops; i++) {
                    pop(stack);
                }
                push(stack, new Slot(Set.of(new ValueOrigin.Insn(insn.offset())), false));
            }
            case LALOAD, DALOAD -> {
                pop(stack);
                pop(stack);
                push(stack, new Slot(Set.of(new ValueOrigin.Insn(insn.offset())), true));
            }
            case IALOAD, FALOAD, AALOAD, BALOAD, CALOAD, SALOAD -> {
                pop(stack);
                pop(stack);
                push(stack, new Slot(Set.of(new ValueOrigin.Insn(insn.offset())), false));
            }
            case IASTORE, LASTORE, FASTORE, DASTORE, AASTORE, BASTORE, CASTORE, SASTORE -> {
                Set<ValueOrigin> value = pop(stack).origins();
                pop(stack);
                Set<ValueOrigin> array = pop(stack).origins();
                for (ValueOrigin arr : array) {
                    arrayElements.computeIfAbsent(arr, k -> new LinkedHashSet<>()).addAll(value);
                }
            }
            case ARRAYLENGTH, CHECKCAST, INSTANCEOF -> {
                pop(stack);
                push(stack, new Slot(Set.of(new ValueOrigin.Insn(insn.offset())), false));
            }
            case MONITORENTER, MONITOREXIT, ATHROW -> pop(stack);
            case IRETURN, LRETURN, FRETURN, DRETURN, ARETURN -> pop(stack);
            case RETURN -> {
            }
            case POP -> pop(stack);
            case POP2 -> {
                // cat-2 顶部占 1 条目，否则为两个 cat-1
                if (top(stack).cat2()) {
                    pop(stack);
                } else {
                    pop(stack);
                    pop(stack);
                }
            }
            case DUP -> dupForm(stack, 1, 0);
            case DUP_X1 -> dupForm(stack, 1, 1);
            case DUP_X2 -> dupForm(stack, 1, valueWidthBelow(stack, 1));
            case DUP2 -> dupForm(stack, valueWidth(stack), 0);
            case DUP2_X1 -> dupForm(stack, valueWidth(stack), 1);
            case DUP2_X2 -> dupForm(stack, valueWidth(stack), valueWidthBelow(stack, valueWidth(stack)));
            case SWAP -> {
                Slot v1 = pop(stack);
                Slot v2 = pop(stack);
                push(stack, v1);
                push(stack, v2);
            }
            case LADD, LSUB, LMUL, LDIV, LREM, DADD, DSUB, DMUL, DDIV, DREM -> {
                pop(stack);
                pop(stack);
                push(stack, new Slot(Set.of(new ValueOrigin.Insn(insn.offset())), true));
            }
            case LSHL, LSHR, LUSHR -> {
                pop(stack);
                pop(stack);
                push(stack, new Slot(Set.of(new ValueOrigin.Insn(insn.offset())), true));
            }
            case IADD, FADD, ISUB, FSUB, IMUL, FMUL, IDIV, FDIV, IREM, FREM,
                    ISHL, ISHR, IUSHR, IAND, IOR, IXOR,
                    LCMP, FCMPL, FCMPG, DCMPL, DCMPG -> {
                pop(stack);
                pop(stack);
                push(stack, new Slot(Set.of(new ValueOrigin.Insn(insn.offset())), false));
            }
            case LNEG, DNEG, I2L, I2D, L2D, F2L, F2D, D2L -> {
                pop(stack);
                push(stack, new Slot(Set.of(new ValueOrigin.Insn(insn.offset())), true));
            }
            case INEG, FNEG, I2F, L2I, L2F, D2I, D2F, F2I, I2B, I2C, I2S -> {
                pop(stack);
                push(stack, new Slot(Set.of(new ValueOrigin.Insn(insn.offset())), false));
            }
            case IFEQ, IFNE, IFLT, IFGE, IFGT, IFLE, IFNULL, IFNONNULL -> pop(stack);
            case IF_ICMPEQ, IF_ICMPNE, IF_ICMPLT, IF_ICMPGE, IF_ICMPGT, IF_ICMPLE,
                    IF_ACMPEQ, IF_ACMPNE -> {
                pop(stack);
                pop(stack);
            }
            default -> {
                // 未知/未覆盖指令：不做栈变化（来源保守缺失，不制造错误来源）
            }
        }
        return new State(stack, locals);
    }

    /** 异常边目标状态：栈 = [异常对象]，locals 保留。 */
    private static State exceptionState(State out) {
        List<Slot> stack = new ArrayList<>(1);
        stack.add(new Slot(Set.of(new ValueOrigin.Unknown()), false));
        return new State(stack, out.locals());
    }

    /** 规范化 receiver：优先 Param(0)（this），否则取首个来源，保证 memo 键稳定。 */
    private static ValueOrigin canonicalReceiver(Set<ValueOrigin> set) {
        for (ValueOrigin origin : set) {
            if (origin instanceof ValueOrigin.Param p && p.slot() == 0) {
                return origin;
            }
        }
        return set.isEmpty() ? new ValueOrigin.Unknown() : set.iterator().next();
    }

    private int callArgCount(InsnFact insn, Op op) {
        if (op == Op.INVOKEDYNAMIC) {
            return Descriptor.paramCount(insn.operands().isEmpty() ? "()V"
                    : ((InvokeDynamicRef) insn.operands().get(0)).descriptor());
        }
        MethodRef ref = insn.methodRef();
        return Descriptor.paramCount(ref.descriptor()) + (op == Op.INVOKESTATIC ? 0 : 1);
    }

    /** 描述符首字符是否 category-2 类型（long/double）。 */
    private static boolean isCat2(String descriptor) {
        char c = descriptor.charAt(0);
        return c == 'J' || c == 'D';
    }

    /** 顶部值的条目宽度：cat-2 为 1 条目，cat-1 为 2 条目（DUP2 族语义）。 */
    private static int valueWidth(List<Slot> stack) {
        return top(stack).cat2() ? 1 : 2;
    }

    /** 顶部 value1（n1 条目）之下 value2 的条目宽度。 */
    private static int valueWidthBelow(List<Slot> stack, int n1) {
        int idx = stack.size() - 1 - n1;
        return idx < 0 ? 1 : (stack.get(idx).cat2() ? 1 : 2);
    }

    /**
     * JVM 复制族通用形式：弹出 value1（n1 条目）与 value2（n2 条目，可为 0），
     * 按 value1, value2, value1 顺序压回。覆盖 DUP/DUP_X1/DUP_X2/DUP2/DUP2_X1/DUP2_X2。
     */
    private static void dupForm(List<Slot> stack, int n1, int n2) {
        List<Slot> v1 = popSlots(stack, n1);
        List<Slot> v2 = popSlots(stack, n2);
        stack.addAll(v1);
        stack.addAll(v2);
        stack.addAll(v1);
    }

    private static List<Slot> popSlots(List<Slot> stack, int n) {
        if (n == 0) {
            return List.of();
        }
        List<Slot> slots = new ArrayList<>(stack.subList(stack.size() - n, stack.size()));
        for (int i = 0; i < n; i++) {
            stack.remove(stack.size() - 1);
        }
        return slots;
    }

    private static Set<ValueOrigin> local(List<Set<ValueOrigin>> locals, int var) {
        return var < locals.size() && !locals.get(var).isEmpty() ? locals.get(var) : UNKNOWN_SLOT.origins();
    }

    private static Slot top(List<Slot> stack) {
        return stack.isEmpty() ? UNKNOWN_SLOT : stack.get(stack.size() - 1);
    }

    private static Slot pop(List<Slot> stack) {
        return stack.isEmpty() ? UNKNOWN_SLOT : stack.remove(stack.size() - 1);
    }

    private static void push(List<Slot> stack, Slot slot) {
        stack.add(slot);
    }

    private static Set<ValueOrigin> union(Set<ValueOrigin> a, Set<ValueOrigin> b) {
        if (a.isEmpty()) {
            return b;
        }
        if (b.isEmpty() || a.equals(b)) {
            return a;
        }
        LinkedHashSet<ValueOrigin> merged = new LinkedHashSet<>(a);
        merged.addAll(b);
        return merged;
    }

    /** 方法缓存键。 */
    public static final class CfgKey {
        private CfgKey() {}

        public static String of(MethodInfo m) {
            return m.owner() + "#" + m.name() + m.descriptor();
        }
    }
}
