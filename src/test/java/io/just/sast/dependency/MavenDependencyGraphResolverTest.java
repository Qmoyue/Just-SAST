package io.just.sast.dependency;

import io.just.sast.model.DependencyGraph;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MavenDependencyGraphResolverTest {
    @TempDir
    Path temp;

    @Test
    void buildsEffectivePomAndMediatedGraphFromRealRepository() throws Exception {
        Path repository = temp.resolve("repository");
        write(repository, "fixture/parent/1.0/parent-1.0.pom", """
                <project xmlns="http://maven.apache.org/POM/4.0.0">
                  <modelVersion>4.0.0</modelVersion>
                  <groupId>fixture</groupId><artifactId>parent</artifactId><version>1.0</version>
                  <packaging>pom</packaging>
                  <properties><common.version>2.0</common.version></properties>
                  <dependencyManagement><dependencies>
                    <dependency><groupId>fixture</groupId><artifactId>parent-managed</artifactId>
                      <version>${common.version}</version></dependency>
                  </dependencies></dependencyManagement>
                </project>
                """);
        write(repository, "fixture/bom/1.0/bom-1.0.pom", """
                <project xmlns="http://maven.apache.org/POM/4.0.0">
                  <modelVersion>4.0.0</modelVersion>
                  <groupId>fixture</groupId><artifactId>bom</artifactId><version>1.0</version>
                  <packaging>pom</packaging>
                  <dependencyManagement><dependencies>
                    <dependency><groupId>fixture</groupId><artifactId>leaf</artifactId>
                      <version>1.0</version><type>test-jar</type><classifier>tests</classifier></dependency>
                  </dependencies></dependencyManagement>
                </project>
                """);
        write(repository, "fixture/common/2.0/common-2.0.pom", pom("fixture", "common", "2.0",
                """
                <dependencies><dependency><groupId>fixture</groupId><artifactId>shared</artifactId>
                <version>1.0</version></dependency></dependencies>
                """));
        write(repository, "fixture/common/1.0/common-1.0.pom", pom("fixture", "common", "1.0", ""));
        write(repository, "fixture/shared/1.0/shared-1.0.pom", pom("fixture", "shared", "1.0", ""));
        write(repository, "fixture/leaf/1.0/leaf-1.0.pom", pom("fixture", "leaf", "1.0",
                """
                <dependencies><dependency><groupId>fixture</groupId><artifactId>leaf-transitive</artifactId>
                <version>1.0</version></dependency></dependencies>
                """));
        write(repository, "fixture/leaf-transitive/1.0/leaf-transitive-1.0.pom",
                pom("fixture", "leaf-transitive", "1.0", ""));
        write(repository, "fixture/branch/1.0/branch-1.0.pom", pom("fixture", "branch", "1.0",
                """
                <dependencies><dependency><groupId>fixture</groupId><artifactId>common</artifactId>
                <version>1.0</version></dependency><dependency><groupId>fixture</groupId>
                <artifactId>excluded</artifactId><version>1.0</version></dependency></dependencies>
                """));
        write(repository, "fixture/excluded/1.0/excluded-1.0.pom", pom("fixture", "excluded", "1.0", ""));

        Path root = temp.resolve("project/pom.xml");
        write(root.getParent(), root.getFileName().toString(), """
                <project xmlns="http://maven.apache.org/POM/4.0.0">
                  <modelVersion>4.0.0</modelVersion>
                  <parent><groupId>fixture</groupId><artifactId>parent</artifactId>
                    <version>1.0</version><relativePath/></parent>
                  <artifactId>application</artifactId>
                  <dependencyManagement><dependencies>
                    <dependency><groupId>fixture</groupId><artifactId>bom</artifactId><version>1.0</version>
                      <type>pom</type><scope>import</scope></dependency>
                  </dependencies></dependencyManagement>
                  <dependencies>
                    <dependency><groupId>fixture</groupId><artifactId>common</artifactId><version>2.0</version></dependency>
                    <dependency><groupId>fixture</groupId><artifactId>leaf</artifactId>
                      <type>test-jar</type><classifier>tests</classifier><scope>runtime</scope>
                      <optional>true</optional></dependency>
                    <dependency><groupId>fixture</groupId><artifactId>branch</artifactId>
                      <version>1.0</version><exclusions><exclusion><groupId>fixture</groupId>
                      <artifactId>excluded</artifactId></exclusion></exclusions></dependency>
                  </dependencies>
                </project>
                """);

        MavenDependencyGraphResolver.Request request = new MavenDependencyGraphResolver.Request(
                root, temp.resolve("cache"),
                List.of(MavenDependencyGraphResolver.RepositorySpec.file(repository)),
                List.of(), true);
        MavenDependencyGraphResolver.Resolution resolution;
        try (MavenDependencyGraphResolver resolver = new MavenDependencyGraphResolver()) {
            resolution = resolver.resolve(request);
        }

        assertEquals(MavenDependencyGraphResolver.Status.COMPLETE, resolution.status());
        assertEquals("fixture:application:1.0", resolution.effectivePom().coordinate());
        assertEquals("2.0", resolution.effectivePom().dependencyManagement().stream()
                .filter(value -> value.artifactId().equals("parent-managed"))
                .findFirst().orElseThrow().version());
        assertEquals("2.0", dependency(resolution, "common").version());
        MavenDependencyGraphResolver.DeclaredDependency leaf = dependency(resolution, "leaf");
        assertEquals("1.0", leaf.version());
        assertEquals("test-jar", leaf.type());
        assertEquals("tests", leaf.classifier());
        assertEquals("runtime", leaf.scope());
        assertTrue(leaf.optional());

        DependencyGraph.Node leafNode = node(resolution, "leaf", DependencyGraph.Resolution.SELECTED);
        assertEquals("test-jar", leafNode.type());
        assertEquals("tests", leafNode.classifier());
        assertEquals("runtime", leafNode.scope());
        assertTrue(leafNode.optional());
        assertTrue(resolution.graph().nodes().values().stream()
                .anyMatch(value -> value.name().equals("shared")
                        && value.version().equals("1.0")));
        assertTrue(resolution.graph().nodes().values().stream()
                .anyMatch(value -> value.name().equals("common")
                        && value.version().equals("1.0")
                        && value.resolution() == DependencyGraph.Resolution.CONFLICT));
        assertFalse(resolution.graph().nodes().values().stream()
                .anyMatch(value -> value.name().equals("excluded")));
        assertTrue(resolution.graph().edges().stream()
                .anyMatch(edge -> edge.kind().equals("conflict")
                        && edge.reason().contains("fixture:common:2.0:jar:")));
    }

    @Test
    void explicitProfileIsAppliedAndUnselectedProfileIsVisible() throws Exception {
        Path repository = temp.resolve("repository");
        write(repository, "fixture/profile-dep/1.0/profile-dep-1.0.pom",
                pom("fixture", "profile-dep", "1.0", ""));
        Path root = temp.resolve("profile/pom.xml");
        write(root.getParent(), root.getFileName().toString(), """
                <project xmlns="http://maven.apache.org/POM/4.0.0">
                  <modelVersion>4.0.0</modelVersion>
                  <groupId>fixture</groupId><artifactId>profile-root</artifactId><version>1.0</version>
                  <profiles><profile><id>enabled</id><dependencies><dependency>
                    <groupId>fixture</groupId><artifactId>profile-dep</artifactId><version>1.0</version>
                  </dependency></dependencies></profile><profile><id>not-enabled</id></profile></profiles>
                </project>
                """);

        MavenDependencyGraphResolver.Request request = new MavenDependencyGraphResolver.Request(
                root, temp.resolve("profile-cache"),
                List.of(MavenDependencyGraphResolver.RepositorySpec.file(repository)),
                List.of("enabled"), true);
        MavenDependencyGraphResolver.Resolution resolution;
        try (MavenDependencyGraphResolver resolver = new MavenDependencyGraphResolver()) {
            resolution = resolver.resolve(request);
        }

        assertEquals(MavenDependencyGraphResolver.Status.PARTIAL, resolution.status());
        assertTrue(resolution.effectivePom().activeProfileIds().contains("enabled"));
        assertTrue(resolution.effectivePom().inactiveProfileIds().contains("not-enabled"));
        assertTrue(resolution.graph().nodes().values().stream()
                .anyMatch(value -> value.name().equals("profile-dep")));
        assertTrue(resolution.problems().stream()
                .anyMatch(problem -> problem.code().equals("PROFILE_NOT_ACTIVATED")
                        && problem.detail().contains("not-enabled")));
    }

    @Test
    void missingVersionIsUnresolvedInsteadOfGuessed() throws Exception {
        Path root = temp.resolve("missing/pom.xml");
        write(root.getParent(), root.getFileName().toString(), """
                <project xmlns="http://maven.apache.org/POM/4.0.0">
                  <modelVersion>4.0.0</modelVersion>
                  <groupId>fixture</groupId><artifactId>missing-version</artifactId><version>1.0</version>
                  <dependencies><dependency><groupId>fixture</groupId><artifactId>unknown</artifactId></dependency></dependencies>
                </project>
                """);
        MavenDependencyGraphResolver.Request request = new MavenDependencyGraphResolver.Request(
                root, temp.resolve("missing-cache"), List.of(), List.of(), true);
        MavenDependencyGraphResolver.Resolution resolution;
        try (MavenDependencyGraphResolver resolver = new MavenDependencyGraphResolver()) {
            resolution = resolver.resolve(request);
        }

        assertEquals(MavenDependencyGraphResolver.Status.UNRESOLVED, resolution.status());
        assertTrue(resolution.problems().stream()
                .anyMatch(problem -> problem.code().equals("DEPENDENCY_VERSION_MISSING")));
        assertTrue(resolution.graph().nodes().values().stream()
                .anyMatch(value -> value.resolution() == DependencyGraph.Resolution.UNRESOLVED
                        && value.name().equals("unknown")));
    }

    private static MavenDependencyGraphResolver.DeclaredDependency dependency(
            MavenDependencyGraphResolver.Resolution resolution, String name) {
        return resolution.effectivePom().dependencies().stream()
                .filter(value -> value.artifactId().equals(name)).findFirst().orElseThrow();
    }

    private static DependencyGraph.Node node(MavenDependencyGraphResolver.Resolution resolution,
                                             String name, DependencyGraph.Resolution state) {
        return resolution.graph().nodes().values().stream()
                .filter(value -> value.name().equals(name) && value.resolution() == state)
                .findFirst().orElseThrow();
    }

    private static String pom(String group, String artifact, String version, String dependencies) {
        return """
                <project xmlns="http://maven.apache.org/POM/4.0.0">
                  <modelVersion>4.0.0</modelVersion>
                  <groupId>%s</groupId><artifactId>%s</artifactId><version>%s</version>
                  %s
                </project>
                """.formatted(group, artifact, version, dependencies);
    }

    private static void write(Path directory, String name, String content) throws IOException {
        Path file = directory.resolve(name);
        Files.createDirectories(file.getParent());
        Files.writeString(file, content);
    }
}
