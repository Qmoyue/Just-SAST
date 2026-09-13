package io.just.sast.model;

import io.just.sast.run.InputBudget;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ProgramUniverseContractTest {

    @Test
    void frontendFactsAndNestedListsAreDefensive() {
        List<InsnFact> instructions = new ArrayList<>();
        instructions.add(new InsnFact(0, Op.NOP, List.of()));
        List<MethodInfo> methods = new ArrayList<>();
        methods.add(new MethodInfo("app/Entry", "run", "()V", 0,
                instructions, List.of(), false));
        List<ClassInfo> classes = new ArrayList<>();
        ClassInfo entry = new ClassInfo("app/Entry", "java/lang/Object", new ArrayList<>(),
                0, methods, List.of());
        Map<String, ClassInfo> input = new LinkedHashMap<>();
        input.put(entry.internalName(), entry);
        LoadResult load = new LoadResult(input, List.of(), 1, 61);
        ProgramUniverse universe = load.programUniverse();

        instructions.clear();
        methods.clear();
        classes.clear();
        input.clear();

        assertEquals(1, universe.classCount());
        assertEquals(1, universe.methodIds().size());
        assertThrows(UnsupportedOperationException.class,
                () -> universe.classes().put("app/Other", entry));
        assertThrows(UnsupportedOperationException.class,
                () -> universe.find(TypeId.of("app/Entry")).orElseThrow().methods().clear());
    }

    @Test
    void idsAreVersionedAndLookupsAreTyped() {
        MethodInfo method = new MethodInfo("app/Entry", "run", "(I)V", 0,
                List.of(), List.of(), false);
        ClassInfo entry = new ClassInfo("app/Entry", "java/lang/Object", List.of(), 0,
                List.of(method), List.of());
        ProgramUniverse universe = ProgramUniverse.from(new LoadResult(
                Map.of(entry.internalName(), entry), List.of(), 1, 61));

        TypeId type = TypeId.of("app.Entry");
        MethodId methodId = MethodId.of(type.internalName(), "run", "(I)V");
        assertEquals("type-v1:app/Entry", type.canonical());
        assertEquals("method-v1:app/Entry#run(I)V", methodId.canonical());
        assertEquals(entry, universe.find(type).orElseThrow());
        assertEquals(method, universe.find(methodId).orElseThrow());
        assertFalse(universe.find(MethodId.of("app/Entry", "missing", "()V")).isPresent());
    }

    @Test
    void semanticDigestDoesNotDependOnInputMapOrderButChangesWithMethodShape() {
        MethodInfo first = new MethodInfo("app/Entry", "run", "()V", 0,
                List.of(new InsnFact(0, Op.RETURN, List.of())), List.of(), false);
        MethodInfo second = new MethodInfo("app/Other", "run", "()V", 0,
                List.of(new InsnFact(0, Op.RETURN, List.of())), List.of(), false);
        ClassInfo entry = new ClassInfo("app/Entry", "java/lang/Object", List.of(), 0,
                List.of(first), List.of());
        ClassInfo other = new ClassInfo("app/Other", "java/lang/Object", List.of(), 0,
                List.of(second), List.of());

        Map<String, ClassInfo> left = new LinkedHashMap<>();
        left.put(entry.internalName(), entry);
        left.put(other.internalName(), other);
        Map<String, ClassInfo> right = new LinkedHashMap<>();
        right.put(other.internalName(), other);
        right.put(entry.internalName(), entry);
        String leftDigest = ProgramUniverse.from(new LoadResult(left, List.of(), 2, 61)).semanticDigest();
        String rightDigest = ProgramUniverse.from(new LoadResult(right, List.of(), 2, 61)).semanticDigest();
        assertEquals(leftDigest, rightDigest);

        MethodInfo changed = new MethodInfo("app/Other", "run", "(Ljava/lang/Object;)V", 0,
                List.of(new InsnFact(0, Op.RETURN, List.of())), List.of(), false);
        ClassInfo changedOther = new ClassInfo("app/Other", "java/lang/Object", List.of(), 0,
                List.of(changed), List.of());
        right.put(changedOther.internalName(), changedOther);
        assertFalse(leftDigest.equals(ProgramUniverse.from(new LoadResult(right, List.of(), 2, 61))
                .semanticDigest()));
    }

    @Test
    void artifactIdentityRejectsMalformedDigestAndKeepsUnknownExplicit() {
        ArtifactProvenance artifact = new ArtifactProvenance(" app.jar ",
                ArtifactProvenance.Role.APPLICATION,
                "a".repeat(64), 42L);
        assertEquals("artifact-v1|APPLICATION|app.jar|" + "A".repeat(64) + "|42", artifact.identity());
        assertTrue(artifact.hasContentDigest());
        assertEquals("UNKNOWN", ArtifactProvenance.unknown("dep", ArtifactProvenance.Role.DEPENDENCY).sha256());
        assertThrows(IllegalArgumentException.class, () -> new ArtifactProvenance(
                "bad", ArtifactProvenance.Role.UNKNOWN, "not-a-digest", -1L));
    }

    @Test
    void classArtifactOwnershipIsPartOfSemanticIdentity() {
        MethodInfo method = new MethodInfo("app/Entry", "run", "()V", 0,
                List.of(new InsnFact(0, Op.RETURN, List.of())), List.of(), false);
        ClassInfo entry = new ClassInfo("app/Entry", "java/lang/Object", List.of(), 0,
                List.of(method), List.of());
        LoadResult load = new LoadResult(Map.of(entry.internalName(), entry), List.of(), 1, 61);
        ArtifactProvenance application = new ArtifactProvenance("app.jar",
                ArtifactProvenance.Role.APPLICATION, "b".repeat(64), 10L);
        ArtifactProvenance dependency = new ArtifactProvenance("dep.jar",
                ArtifactProvenance.Role.DEPENDENCY, "c".repeat(64), 11L);
        ProgramUniverse left = ProgramUniverse.of(load,
                Map.of("app/Entry", application), List.of(application, dependency));
        ProgramUniverse right = ProgramUniverse.of(load,
                Map.of("app/Entry", dependency), List.of(application, dependency));
        assertFalse(left.semanticDigest().equals(right.semanticDigest()));
        assertEquals(application, left.artifactFor(TypeId.of("app/Entry")).orElseThrow());
    }

    @Test
    void dependencyGraphIsCarriedAcrossTheImmutableFrontendBoundary() {
        MethodInfo method = new MethodInfo("app/Entry", "run", "()V", 0,
                List.of(new InsnFact(0, Op.RETURN, List.of())), List.of(), false);
        ClassInfo entry = new ClassInfo("app/Entry", "java/lang/Object", List.of(), 0,
                List.of(method), List.of());
        LoadResult load = new LoadResult(Map.of(entry.internalName(), entry), List.of(), 1, 61);
        ArtifactProvenance application = new ArtifactProvenance("app.jar",
                ArtifactProvenance.Role.APPLICATION, "b".repeat(64), 10L);
        DependencyGraph.Node node = new DependencyGraph.Node("sha256:app", application,
                DependencyGraph.Source.ACTUAL_APPLICATION,
                DependencyGraph.Deployment.ACTUAL_DISTRIBUTION, "example", "app", "1.0.0",
                "jar", "", "target", "", "", "", 0);
        DependencyGraph graph = new DependencyGraph(List.of(node), List.of(), Map.of());

        ProgramUniverse universe = ProgramUniverse.of(load,
                Map.of("app/Entry", application), List.of(application), graph);

        assertEquals(graph, universe.dependencyGraph());
        assertEquals(graph.semanticDigest(), universe.dependencyGraph().semanticDigest());
        assertTrue(universe.semanticDigest().matches("[0-9a-f]{64}"));
    }

    @Test
    void provenanceUsesCallerTrackerAcrossArtifacts(@TempDir Path temp) throws Exception {
        Path first = temp.resolve("first.jar");
        Path second = temp.resolve("second.jar");
        Files.write(first, new byte[] {1, 2});
        Files.write(second, new byte[] {3, 4});
        InputBudget defaults = InputBudget.defaults();
        InputBudget budget = defaults.withArchiveLimits(defaults.maxPhysicalBytes(),
                defaults.maxCompressedBytes(), 3, defaults.maxEntryBytes(),
                defaults.maxArchiveEntries(), defaults.maxArchiveNesting(),
                defaults.maxClassEntries());
        InputBudget.Tracker tracker = budget.tracker();

        ArtifactProvenance provenance = ArtifactProvenance.fromPath(
                first, ArtifactProvenance.Role.APPLICATION, budget, tracker);
        assertTrue(provenance.hasContentDigest());
        IOException failure = assertThrows(IOException.class,
                () -> ArtifactProvenance.fromPath(
                        second, ArtifactProvenance.Role.DEPENDENCY, budget, tracker));
        assertTrue(failure.getMessage().contains("exceed"), failure::getMessage);
    }
}
