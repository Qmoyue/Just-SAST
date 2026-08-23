package io.just.sast.config;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 匹配器契约：精确串 / `~` 锚定正则 / null 安全。 */
class MatchTest {

    @Test
    void exactMatch() {
        Match m = Match.of("java/lang/Runtime");
        assertTrue(m.matches("java/lang/Runtime"));
        assertFalse(m.matches("java/lang/Runtime2"));
        assertFalse(m.matches(null));
        assertFalse(m.isRegex());
    }

    @Test
    void anchoredRegex() {
        Match m = Match.of("~" + "lookup|list|bind");
        assertTrue(m.matches("lookup"));
        assertFalse(m.matches("lookup2")); // 锚定：不部分匹配
        assertTrue(m.matches("bind"));
        assertTrue(m.isRegex());
    }

    @Test
    void quotedRegexScalarIsStripped() {
        // YAML 中 ~"a|b" 的引号进入标量后需剥掉，否则备选被拆散
        Match m = Match.of("~\"lookup|bind\"");
        assertTrue(m.matches("lookup"));
        assertTrue(m.matches("bind"));
        assertFalse(m.matches("\"lookup\""));
    }

    @Test
    void regexWithAnchorsInsideIsAllowed() {
        Match m = Match.of("~invoke.*");
        assertTrue(m.matches("invoke"));
        assertTrue(m.matches("invokeExact"));
        assertFalse(m.matches("Invokexact")); // 整体锚定仍生效
    }
}
