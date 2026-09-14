package io.just.sast.model;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DependencyGraphContractTest {

    @Test
    void actualAndDerivedSourcesRemainDistinctAndConflictIsVisible() {
        DependencyGraph.Node application = node("app", ArtifactProvenance.Role.APPLICATION,
                DependencyGraph.Source.ACTUAL_APPLICATION,
                DependencyGraph.Deployment.ACTUAL_DISTRIBUTION, 0);
        DependencyGraph.Node embedded = node("embedded", ArtifactProvenance.Role.DEPENDENCY,
                DependencyGraph.Source.ACTUAL_EMBEDDED,
                DependencyGraph.Deployment.ACTUAL_DISTRIBUTION, -1);
        DependencyGraph.Node explicit = node("explicit", ArtifactProvenance.Role.DEPENDENCY,
                DependencyGraph.Source.ACTUAL_EXPLICIT,
                DependencyGraph.Deployment.ACTUAL_DISTRIBUTION, 1);
        DependencyGraph.Node pom = node("pom", ArtifactProvenance.Role.DEPENDENCY,
                DependencyGraph.Source.POM_DERIVED,
                DependencyGraph.Deployment.DECLARED_ENVIRONMENT, -1);

        DependencyGraph.ClassOwner appOwner = new DependencyGraph.ClassOwner(
                "app/Entry", "app", List.of("app", "explicit"),
                DependencyGraph.Resolution.CONFLICT, true);
        DependencyGraph.ClassOwner dependencyOwner = new DependencyGraph.ClassOwner(
                "gadget/Entry", "embedded", List.of("embedded"),
                DependencyGraph.Resolution.SELECTED, false);
        DependencyGraph graph = new DependencyGraph(
                List.of(application, embedded, explicit, pom),
                List.of(new DependencyGraph.Edge("app", "embedded", "embedded", "archive-entry")),
                Map.of(appOwner.className(), appOwner,
                        dependencyOwner.className(), dependencyOwner));

        assertEquals(DependencyGraph.Source.ACTUAL_APPLICATION,
                graph.node("app").orElseThrow().source());
        assertEquals(DependencyGraph.Deployment.DECLARED_ENVIRONMENT,
                graph.node("pom").orElseThrow().deployment());
        assertTrue(graph.applicationOwned("app/Entry"));
        assertFalse(graph.applicationOwned("gadget/Entry"));
        assertTrue(graph.hasConflicts());
        assertTrue(graph.semanticDigest().matches("[0-9a-f]{64}"));
    }

    @Test
    void frontendIndexesBindOnlyActualApplicationOwnership() {
        DependencyGraph.Node application = node("app", ArtifactProvenance.Role.APPLICATION,
                DependencyGraph.Source.ACTUAL_APPLICATION,
                DependencyGraph.Deployment.ACTUAL_DISTRIBUTION, 0);
        DependencyGraph.Node explicit = node("explicit", ArtifactProvenance.Role.DEPENDENCY,
                DependencyGraph.Source.ACTUAL_EXPLICIT,
                DependencyGraph.Deployment.ACTUAL_DISTRIBUTION, 1);
        DependencyGraph graph = new DependencyGraph(List.of(application, explicit), List.of(), Map.of())
                .bindClassOwners(
                        Map.of("app/Entry", 0, "gadget/Entry", 1),
                        Map.of("app/Entry", List.of(1)),
                        Set.of("app/Entry"));

        DependencyGraph.ClassOwner applicationOwner = graph.classOwner("app/Entry").orElseThrow();
        DependencyGraph.ClassOwner dependencyOwner = graph.classOwner("gadget/Entry").orElseThrow();
        assertEquals(DependencyGraph.Resolution.CONFLICT, applicationOwner.resolution());
        assertTrue(applicationOwner.applicationOwned());
        assertEquals(List.of("app", "explicit"), applicationOwner.candidateRefs());
        assertFalse(dependencyOwner.applicationOwned());
    }

    @Test
    void actualExplicitInputWinsOverTheSamePOMDerivedClass() {
        DependencyGraph.Node explicit = node("explicit", ArtifactProvenance.Role.DEPENDENCY,
                DependencyGraph.Source.ACTUAL_EXPLICIT,
                DependencyGraph.Deployment.ACTUAL_DISTRIBUTION, 1);
        DependencyGraph.Node downloaded = node("downloaded", ArtifactProvenance.Role.DEPENDENCY,
                DependencyGraph.Source.REMOTE,
                DependencyGraph.Deployment.DECLARED_ENVIRONMENT, 2);
        DependencyGraph graph = new DependencyGraph(List.of(explicit, downloaded), List.of(), Map.of())
                .bindClassOwners(Map.of("shared/Type", 1),
                        Map.of("shared/Type", List.of(2)), Set.of());

        DependencyGraph.ClassOwner owner = graph.classOwner("shared/Type").orElseThrow();
        assertEquals(List.of("explicit", "downloaded"), owner.candidateRefs());
        assertEquals("explicit", owner.selectedRef());
        assertEquals(DependencyGraph.Resolution.CONFLICT, owner.resolution());
        assertFalse(owner.applicationOwned());
    }

    @Test
    void embeddedDuplicateIsNotLostWhenItSharesTheOuterInputOrdinal() {
        DependencyGraph.Node application = node("app", ArtifactProvenance.Role.APPLICATION,
                DependencyGraph.Source.ACTUAL_APPLICATION,
                DependencyGraph.Deployment.ACTUAL_DISTRIBUTION, 0);
        DependencyGraph.Node embedded = new DependencyGraph.Node("embedded",
                new ArtifactProvenance("nested:BOOT-INF/lib/lib.jar",
                        ArtifactProvenance.Role.DEPENDENCY, "b".repeat(64), 10L),
                DependencyGraph.Source.ACTUAL_EMBEDDED,
                DependencyGraph.Deployment.ACTUAL_DISTRIBUTION, "example", "lib", "1.0.0",
                "jar", "", "nested:BOOT-INF/lib/lib.jar", "app", "", "", -1);

        DependencyGraph graph = new DependencyGraph(List.of(application, embedded), List.of(
                new DependencyGraph.Edge("app", "embedded", "embedded", "archive-entry")), Map.of())
                .bindClassOwners(Map.of("app/Entry", 0),
                        Map.of("app/Entry", List.of(0)),
                        Map.of("app/Entry", List.of("nested:BOOT-INF/lib/lib.jar")),
                        Set.of("app/Entry"));

        DependencyGraph.ClassOwner owner = graph.classOwner("app/Entry").orElseThrow();
        assertEquals(DependencyGraph.Resolution.CONFLICT, owner.resolution());
        assertEquals(List.of("app", "embedded"), owner.candidateRefs());
        assertTrue(owner.applicationOwned());
    }

    @Test
    void completedArtifactBindsSelectedNodeWhenConflictHasTheSameCoordinate() {
        String coordinate = "example:shared:1.0.0:jar:";
        DependencyGraph.Node conflict = new DependencyGraph.Node("conflict",
                new ArtifactProvenance("conflict.jar", ArtifactProvenance.Role.DEPENDENCY,
                        "a".repeat(64), 10L),
                DependencyGraph.Source.POM_DERIVED,
                DependencyGraph.Deployment.DECLARED_ENVIRONMENT, "example", "shared", "1.0.0",
                "jar", "", "maven:conflict", "", "", "", -1, "compile", false,
                DependencyGraph.Resolution.CONFLICT, "winner=" + coordinate);
        DependencyGraph.Node selected = new DependencyGraph.Node("selected",
                new ArtifactProvenance("selected.jar", ArtifactProvenance.Role.DEPENDENCY,
                        "b".repeat(64), 10L),
                DependencyGraph.Source.POM_DERIVED,
                DependencyGraph.Deployment.DECLARED_ENVIRONMENT, "example", "shared", "1.0.0",
                "jar", "", "maven:selected", "", "", "", -1, "compile", false,
                DependencyGraph.Resolution.SELECTED, "nearest-version");
        DependencyGraph graph = new DependencyGraph(List.of(conflict, selected), List.of(), Map.of());
        DependencyGraph.ArtifactBinding binding = new DependencyGraph.ArtifactBinding(coordinate,
                new ArtifactProvenance(coordinate, ArtifactProvenance.Role.DEPENDENCY,
                        "c".repeat(64), 10L),
                DependencyGraph.Source.CACHE, "local-cache", 2);

        DependencyGraph bound = graph.withCompletedArtifacts(List.of(binding));

        assertEquals(DependencyGraph.Resolution.CONFLICT,
                bound.node("conflict").orElseThrow().resolution());
        assertEquals(DependencyGraph.Source.CACHE,
                bound.node("selected").orElseThrow().source());
        assertEquals(2, bound.node("selected").orElseThrow().inputIndex());
    }

    private static DependencyGraph.Node node(String ref, ArtifactProvenance.Role role,
                                             DependencyGraph.Source source,
                                             DependencyGraph.Deployment deployment,
                                             int inputIndex) {
        return new DependencyGraph.Node(ref,
                new ArtifactProvenance(ref + ".jar", role, refDigest(ref), 10L), source,
                deployment, "example", ref, "1.0.0", "jar", "", ref, "", "", "", inputIndex);
    }

    private static String refDigest(String value) {
        return switch (value) {
            case "app" -> "a".repeat(64);
            case "embedded" -> "b".repeat(64);
            case "explicit" -> "c".repeat(64);
            case "pom" -> "d".repeat(64);
            default -> "e".repeat(64);
        };
    }
}
