package io.just.sast.chain;

import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.HopKind;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 置信度契约（javadoc 公开计分规则）：逐跳/入口/严重度/模式加分/惩罚与 evidence 因子分解。 */
class ConfidenceScorerTest {

    private static ChainHop call(String from, String to) {
        return new ChainHop(from, "m", to, "n", HopKind.DIRECT_CALL, null, "call", "()V", null);
    }

    private static ChainHop virtual(String from, String to) {
        return new ChainHop(from, "m", to, "n", HopKind.VIRTUAL_DISPATCH, null, "call", "()V", null);
    }

    private static ChainHop field(String from, String to, String f) {
        return new ChainHop(from, "m", to, "n", HopKind.FIELD_FLOW, f, "field-read", "", null);
    }

    private static ChainHop entry(String owner, String kind) {
        return new ChainHop(owner, "e", owner, "e", HopKind.ENTRY, null, kind, "", null);
    }

    private static Chain chain(List<ChainHop> hops, String entryKind, String severity, int unresolved) {
        return new Chain("R", "CODE_EXEC", severity, "app/A", "readObject", entryKind,
                "java/lang/Runtime", "exec", hops, unresolved);
    }

    @Test
    void scoreFollowsDocumentedFormula() {
        // 1 direct + 1 field + readObject(+2) + HIGH(+1) = 5 → HIGH
        Chain c = chain(List.of(call("x", "y"), field("a", "b", "f"), entry("app/A", "readObject")),
                "readObject", "HIGH", 0);
        assertEquals(5, ConfidenceScorer.evidenceScore(c, null));
        assertTrue(ConfidenceScorer.score(c, null).startsWith("FEASIBLE"), ConfidenceScorer.score(c, null));
        // toString 入口(+1)：1+1+1+1=4 → MEDIUM
        Chain t = chain(List.of(call("x", "y"), field("a", "b", "f"), entry("app/A", "toString")),
                "toString", "HIGH", 0);
        assertEquals(4, ConfidenceScorer.evidenceScore(t, null));
        assertTrue(ConfidenceScorer.score(t, null).startsWith("FEASIBLE"), ConfidenceScorer.score(t, null));
    }

    @Test
    void virtualDispatchScoresZeroButIsCounted() {
        Chain c = chain(List.of(virtual("x", "y"), virtual("y", "z"), entry("app/A", "readObject")),
                "readObject", "HIGH", 0);
        assertEquals(3, ConfidenceScorer.evidenceScore(c, null), "VIRTUAL_DISPATCH 计 0 分");
        String decomposition = ConfidenceScorer.evidenceDecomposition(c, null);
        assertTrue(decomposition.contains("virtual=2+0"), "分解串应列出 virtual 跳数： " + decomposition);
    }

    @Test
    void unresolvedIsPenalizedAndDecomposed() {
        Chain c = chain(List.of(call("x", "y"), entry("app/A", "readObject")),
                "readObject", "HIGH", 2);
        assertEquals(1 + 2 + 1 - 4, ConfidenceScorer.evidenceScore(c, null));
        String decomposition = ConfidenceScorer.evidenceDecomposition(c, null);
        assertTrue(decomposition.contains("unresolved:2-4"), "惩罚应逐项分解： " + decomposition);
    }

    @Test
    void patternBonusAndDecomposition() {
        Chain c = chain(List.of(call("x", "y"), entry("app/A", "readObject")), "readObject", "HIGH", 0);
        List<String> notes = List.of("pattern:CC6", "pattern:Rome");
        assertEquals(1 + 2 + 1 + 2 * ConfidenceScorer.PATTERN_BONUS, ConfidenceScorer.evidenceScore(c, notes));
        String decomposition = ConfidenceScorer.evidenceDecomposition(c, notes);
        assertTrue(decomposition.contains("pattern:CC6+2"), decomposition);
        assertTrue(decomposition.contains("pattern:Rome+2"), decomposition);
    }

    @Test
    void entryWeightsFollowContract() {
        // writeReplace 序列化侧入口权重 2（本轮新增契约）
        Chain c = chain(List.of(entry("app/A", "writeReplace")), "writeReplace", "LOW", 0);
        assertEquals(2, ConfidenceScorer.evidenceScore(c, null));
    }
}
