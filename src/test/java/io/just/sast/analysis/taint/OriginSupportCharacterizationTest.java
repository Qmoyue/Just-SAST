package io.just.sast.analysis.taint;

import io.just.sast.analysis.hierarchy.ClassHierarchy;
import io.just.sast.config.RuleEngine;
import io.just.sast.config.RuleSet;
import io.just.sast.cpg.build.FieldWriterIndex;
import io.just.sast.cpg.graph.Graph;
import io.just.sast.cpg.graph.Node;
import io.just.sast.model.MethodInfo;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Modifier;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** P2.1 characterization seam for the origin/index owner. */
class OriginSupportCharacterizationTest {

    @Test
    void emptyIndexesExposeImmutableEmptySnapshotsAndStableCacheCounters() {
        Graph graph = new Graph();
        graph.freeze();
        ClassHierarchy hierarchy = new ClassHierarchy(Map.of(), name -> null);
        OriginSupport support = new OriginSupport(graph, hierarchy,
                new RuleEngine(RuleSet.EMPTY, hierarchy), true);

        assertEquals(Set.of(), support.entryDownstream(graph));
        assertEquals(List.of(), support.reflectiveInvokeSitesOf("app/NoSuchType"));
        assertEquals(List.of(), support.javaBeanInvokeSitesOf("app/NoSuchType", "getValue"));
        assertEquals(Map.of(), support.javabeanClassSites());
        assertEquals(List.of(), support.javabeanWildcardSiteIds());
        assertEquals(0, support.forwardOriginCacheSize());
        assertEquals(0L, support.forwardOriginCacheBytesEstimate());
        assertEquals(0L, support.forwardOriginComputeCalls());
        assertEquals(0L, support.forwardOriginCacheHits());
        assertEquals(0L, support.forwardOriginAnalysisRuns());
        assertEquals(Set.of(), support.completenessReasons());

        support.clearForwardOriginCache();
        assertEquals(0, support.forwardOriginCacheSize());
    }

    @Test
    void canonicalKeysAndNullSafeLookupsRemainDeterministic() {
        Graph graph = new Graph();
        Node call = graph.addCallNode("java/io/ObjectInputStream", "readObject", "()Ljava/lang/Object;",
                "VIRTUAL", null, 3, "app/Entry", "read", "()V");
        graph.freeze();
        ClassHierarchy hierarchy = new ClassHierarchy(Map.of(), name -> null);
        OriginSupport support = new OriginSupport(graph, hierarchy,
                new RuleEngine(RuleSet.EMPTY, hierarchy), false);
        MethodInfo method = new MethodInfo("app/Entry", "read", "()V", Modifier.PUBLIC,
                List.of(), List.of(), false);

        assertEquals("app/Entry#read()V", OriginSupport.methodKey(method));
        assertEquals("app/Entry#read()V", OriginSupport.methodKeyOf("app/Entry", "read", "()V"));
        assertEquals("app/Entry#read()V", OriginSupport.methodKey(call));
        assertTrue(OriginSupport.isOisRead(call));
        assertNull(support.callNode("app/Entry#read()V", 99));
        assertNull(support.callNode(-1L));
        assertNull(support.methodOf("app/NoSuchType", "run", "()V"));
        assertFalse(support.frameworkDeserializeSourceAvailable());
    }

}
