package io.just.sast.cpg.build;

import io.just.sast.model.InsnFact;
import io.just.sast.model.MethodInfo;
import io.just.sast.model.Op;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Modifier;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CFG 子程序语义契约：JSR 有 JUMP 边 + fall-through 返回点后继（历史缺陷：JSR 只建 JUMP，
 * 子程序返回后的指令无入边——Java 5 及更早字节码/混淆器产出的方法传播被截断）；RET 无后继。
 */
class CfgTest {

    private static MethodInfo method(InsnFact... insns) {
        return new MethodInfo("T", "m", "()V", Modifier.PUBLIC, List.of(insns), List.of(), false);
    }

    private static InsnFact insn(int offset, Op op, Object... operands) {
        return new InsnFact(offset, op, List.of(operands));
    }

    @Test
    void jsrHasJumpAndFallThroughSuccessors() {
        // JSR sub; RETURN  ← JSR 的 fall-through 后继（RET 返回点）
        MethodInfo m = method(
                insn(0, Op.JSR, 2),
                insn(1, Op.RETURN),
                insn(2, Op.RET, 3));
        var edges = Cfg.compute(m);
        var jsrSucc = edges.get(0);
        assertEquals(2, jsrSucc.size(), "JSR 应有 JUMP + fall-through 两条后继: " + jsrSucc);
        assertTrue(jsrSucc.stream().anyMatch(e -> e.targetOffset() == 2 && e.label() == CfgLabel.JUMP));
        assertTrue(jsrSucc.stream().anyMatch(e -> e.targetOffset() == 1 && e.label() == CfgLabel.SEQ),
                "fall-through 返回点是 RET 的继续执行位置");
        // RET 无后继（返回目标在调用方 JSR 压入的返回地址，静态不可知）
        assertFalse(edges.containsKey(2), "RET 不应有静态后继");
    }

    @Test
    void gotoStillSingleJump() {
        MethodInfo m = method(
                insn(0, Op.GOTO, 2),
                insn(1, Op.NOP),
                insn(2, Op.RETURN));
        var edges = Cfg.compute(m);
        assertEquals(1, edges.get(0).size(), "GOTO 只有跳转后继: " + edges.get(0));
        assertEquals(2, edges.get(0).get(0).targetOffset());
        // GOTO 后继里不得出现 fall-through（offset 1）
        assertFalse(edges.get(0).stream().anyMatch(e -> e.targetOffset() == 1));
    }

    @Test
    void indexedViewKeepsLegacySuccessorSemantics() {
        MethodInfo m = method(
                insn(0, Op.JSR, 2),
                insn(1, Op.RETURN),
                insn(2, Op.RET, 3));
        var sparse = Cfg.compute(m);
        var indexed = Cfg.computeIndexed(m);
        assertEquals(sparse.get(0), indexed.successorsAt(0));
        assertEquals(List.of(), indexed.successorsAt(2));
        assertEquals(List.of(), indexed.successorsAt(-1));
    }
}
