package io.just.sast.analysis.taint;

import io.just.sast.frontend.asm.FactsExtractor;
import io.just.sast.model.MethodInfo;
import io.just.sast.model.MethodRef;
import io.just.sast.model.Op;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TryCatchBlockNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertSame;

/**
 * 过程内 origin 分析契约（栈语义精度根基）：
 * category-2 单条目、POP2/DUP2 语义、异常边清栈压异常对象、参数槽初始化。
 */
class ForwardOriginsTest {

    private final ForwardOrigins origins = new ForwardOrigins(new HashMap<>());

    private static MethodInfo extract(MethodNode m) {
        ClassNode node = new ClassNode();
        node.name = "T";
        node.superName = "java/lang/Object";
        node.methods.add(m);
        return new FactsExtractor().extract(node).methods().get(0);
    }

    @Test
    void longConstantIsSingleCat2Entry() {
        // LCONST_1; POP2（弹掉单个 cat-2 值）→ 栈空；随后 LCONST_0; LCONST_1 → 2 条目
        MethodNode m = new MethodNode(0, "run", "()V", null, null);
        m.instructions.add(new InsnNode(Op.LCONST_1.code()));
        m.instructions.add(new InsnNode(Op.POP2.code()));
        m.instructions.add(new InsnNode(Op.LCONST_0.code()));
        m.instructions.add(new InsnNode(Op.LCONST_1.code()));
        m.instructions.add(new InsnNode(Op.RETURN.code()));
        ForwardOrigins.Result r = origins.compute(extract(m));
        ForwardOrigins.State afterPop2 = r.stateBefore().get(2); // LCONST_0 之前
        assertTrue(afterPop2.stack().isEmpty(), "POP2 弹掉单个 cat-2 值后栈空");
        ForwardOrigins.State twoLongs = r.stateBefore().get(4); // RETURN 之前
        assertEquals(2, twoLongs.stack().size(), "两个 long 是两个条目");
        assertTrue(twoLongs.stack().get(0).cat2() && twoLongs.stack().get(1).cat2());
    }

    @Test
    void dup2OfCat2ValueDuplicatesWholeValue() {
        // LCONST_1; DUP2 → 栈上同一个 cat-2 值出现两次（条目×2）
        MethodNode m = new MethodNode(0, "run", "()V", null, null);
        m.instructions.add(new InsnNode(Op.LCONST_1.code()));
        m.instructions.add(new InsnNode(Op.DUP2.code()));
        m.instructions.add(new InsnNode(Op.POP2.code()));
        m.instructions.add(new InsnNode(Op.POP2.code()));
        m.instructions.add(new InsnNode(Op.RETURN.code()));
        ForwardOrigins.Result r = origins.compute(extract(m));
        ForwardOrigins.State afterDup2 = r.stateBefore().get(2);
        assertEquals(2, afterDup2.stack().size(), "cat-2 的 DUP2 复制整个值（单值两条目）");
        ForwardOrigins.State end = r.stateBefore().get(4);
        assertTrue(end.stack().isEmpty(), "两次 POP2 清空");
    }

    @Test
    void paramsInitialisedAsOrigins() {
        // (ILjava/lang/String;)V 的静态方法：slot0=I（Param 0），slot1=String（Param 1）
        MethodNode m = new MethodNode(8 /*STATIC*/, "run", "(ILjava/lang/String;)V", null, null);
        m.instructions.add(new InsnNode(Op.RETURN.code()));
        ForwardOrigins.Result r = origins.compute(extract(m));
        ForwardOrigins.State entry = r.stateBefore().get(0);
        assertEquals(Set.of(new ValueOrigin.Param(0)), entry.locals().get(0));
        assertEquals(Set.of(new ValueOrigin.Param(1)), entry.locals().get(1));
    }

    @Test
    void exceptionEdgeClearsStackAndPushesUnknown() {
        // try { INVOKESTATIC } catch(E) → ASTORE 1；调用指令可能抛出异常，常量指令则不会
        MethodNode m = new MethodNode(0, "run", "()V", null, null);
        LabelNode start = new LabelNode();
        LabelNode end = new LabelNode();
        LabelNode handler = new LabelNode();
        m.instructions.add(start);
        m.instructions.add(new MethodInsnNode(Op.INVOKESTATIC.code(), "T", "mayThrow", "()V", false));
        m.instructions.add(new InsnNode(Op.RETURN.code()));
        m.instructions.add(end);
        m.instructions.add(handler);
        m.instructions.add(new VarInsnNode(Op.ASTORE.code(), 1));
        m.instructions.add(new InsnNode(Op.RETURN.code()));
        m.tryCatchBlocks.add(new TryCatchBlockNode(start, end, handler, null));
        ForwardOrigins.Result r = origins.compute(extract(m));
        // handler（ASTORE，偏移 2）执行前：栈上只有 1 个 Unknown 异常对象（JVM 清栈语义）
        ForwardOrigins.State handlerState = r.stateBefore().get(2);
        assertEquals(1, handlerState.stack().size(), "异常 handler 入口栈深为 1");
        ValueOrigin origin = handlerState.stack().get(0).origins().iterator().next();
        assertEquals(new ValueOrigin.Unknown(), origin, "handler 栈顶是 Unknown 异常对象");
    }

    @Test
    void concurrentComputeHasOneCachedResult() throws Exception {
        MethodNode m = new MethodNode(0, "run", "()V", null, null);
        m.instructions.add(new InsnNode(Op.RETURN.code()));
        MethodInfo method = extract(m);
        ExecutorService pool = Executors.newFixedThreadPool(4);
        try {
            Future<ForwardOrigins.Result> first = pool.submit(() -> origins.compute(method));
            Future<ForwardOrigins.Result> second = pool.submit(() -> origins.compute(method));
            assertSame(first.get(), second.get(),
                    "同一方法的并发 compute 必须复用同一个抽象解释结果");
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    void emptyAbstractOrNativeMethodHasNoSyntheticOffset() {
        MethodInfo method = extract(new MethodNode(0, "empty", "()V", null, null));
        ForwardOrigins.Result result = origins.compute(method);

        assertTrue(result.stateBefore().isEmpty());
        assertTrue(result.arrayElements().isEmpty());
    }

    @Test
    void reflectiveArraySetAndGetPreserveIndexedElementOrigin() {
        MethodNode m = new MethodNode(8, "run", "(Ljava/lang/Object;)Ljava/lang/Object;",
                null, null);
        m.instructions.add(new InsnNode(Op.ICONST_1.code()));
        m.instructions.add(new TypeInsnNode(Op.ANEWARRAY.code(), "java/lang/Object"));
        m.instructions.add(new VarInsnNode(Op.ASTORE.code(), 1));
        m.instructions.add(new VarInsnNode(Op.ALOAD.code(), 1));
        m.instructions.add(new InsnNode(Op.ICONST_0.code()));
        m.instructions.add(new VarInsnNode(Op.ALOAD.code(), 0));
        m.instructions.add(new MethodInsnNode(Op.INVOKESTATIC.code(), "java/lang/reflect/Array",
                "set", "(Ljava/lang/Object;ILjava/lang/Object;)V", false));
        m.instructions.add(new VarInsnNode(Op.ALOAD.code(), 1));
        m.instructions.add(new InsnNode(Op.ICONST_0.code()));
        m.instructions.add(new MethodInsnNode(Op.INVOKESTATIC.code(), "java/lang/reflect/Array",
                "get", "(Ljava/lang/Object;I)Ljava/lang/Object;", false));
        m.instructions.add(new InsnNode(Op.ARETURN.code()));

        MethodInfo method = extract(m);
        Map<String, Long> callIds = new HashMap<>();
        long nextId = 100;
        for (var insn : method.instructions()) {
            if (!insn.op().isInvoke()) {
                continue;
            }
            MethodRef ref = insn.methodRef();
            callIds.put(ForwardOrigins.CfgKey.of(method) + "@" + insn.offset(), nextId++);
        }
        ForwardOrigins.Result result = new ForwardOrigins(callIds).compute(method);
        long getId = callIds.entrySet().stream()
                .filter(entry -> entry.getKey().endsWith("@9"))
                .mapToLong(Map.Entry::getValue)
                .findFirst()
                .orElseThrow();

        assertEquals(Set.of(new ValueOrigin.Param(0)),
                result.arrayElements().get(new ValueOrigin.CallResult(getId)));
        assertTrue(result.indexedArrayElements().values().stream()
                .anyMatch(indexed -> indexed.values().stream()
                        .anyMatch(values -> values.contains(new ValueOrigin.Param(0)))));
    }
}
