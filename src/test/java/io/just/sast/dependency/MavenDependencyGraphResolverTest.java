package io.just.sast.dependency;

import io.just.sast.model.DependencyGraph;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
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

    @Test
    void completesRemoteJarThenReusesTheSameCompleteBytesOffline() throws Exception {
        Path repository = temp.resolve("artifact-repository");
        write(repository, "fixture/library/1.0/library-1.0.pom",
                pom("fixture", "library", "1.0", ""));
        writeJar(repository.resolve("fixture/library/1.0/library-1.0.jar"),
                "fixture/data.txt", "complete-bytes");
        Path root = temp.resolve("artifact-root/pom.xml");
        write(root.getParent(), root.getFileName().toString(), pom("fixture", "root", "1.0",
                "<dependencies><dependency><groupId>fixture</groupId>"
                        + "<artifactId>library</artifactId><version>1.0</version></dependency></dependencies>"));
        Path cache = temp.resolve("artifact-cache");
        MavenDependencyGraphResolver.Request online = new MavenDependencyGraphResolver.Request(
                root, cache, List.of(MavenDependencyGraphResolver.RepositorySpec.file(repository)),
                List.of(), false);
        MavenDependencyGraphResolver.Completion first;
        try (MavenDependencyGraphResolver resolver = new MavenDependencyGraphResolver()) {
            first = resolver.complete(online);
        }

        assertEquals(MavenDependencyGraphResolver.Status.COMPLETE, first.status());
        assertEquals(1, first.artifacts().size());
        MavenDependencyGraphResolver.ArtifactDownload downloaded = first.artifacts().get(0);
        assertEquals(DependencyGraph.Source.REMOTE, downloaded.source());
        assertEquals("fixture:library:1.0:jar:", downloaded.coordinate());
        assertTrue(Files.isRegularFile(downloaded.path()));
        String firstDigest = downloaded.sha256();

        Files.write(downloaded.path(), new byte[]{'t', 'r', 'u', 'n', 'c', 'a', 't', 'e', 'd'});
        MavenDependencyGraphResolver.Completion repaired;
        try (MavenDependencyGraphResolver resolver = new MavenDependencyGraphResolver()) {
            repaired = resolver.complete(online);
        }
        assertEquals(MavenDependencyGraphResolver.Status.PARTIAL, repaired.status());
        assertEquals(DependencyGraph.Source.REMOTE, repaired.artifacts().get(0).source());
        assertEquals(firstDigest, repaired.artifacts().get(0).sha256());
        assertTrue(repaired.resolution().problems().stream()
                .anyMatch(problem -> problem.code().equals("DEPENDENCY_CACHE_INVALID")));

        Files.delete(repository.resolve("fixture/library/1.0/library-1.0.jar"));

        MavenDependencyGraphResolver.Request offline = new MavenDependencyGraphResolver.Request(
                root, cache, List.of(MavenDependencyGraphResolver.RepositorySpec.file(repository)),
                List.of(), true);
        MavenDependencyGraphResolver.Completion second;
        try (MavenDependencyGraphResolver resolver = new MavenDependencyGraphResolver()) {
            second = resolver.complete(offline);
        }

        assertEquals(MavenDependencyGraphResolver.Status.COMPLETE, second.status());
        assertEquals(1, second.artifacts().size());
        assertEquals(DependencyGraph.Source.CACHE, second.artifacts().get(0).source());
        assertEquals(firstDigest, second.artifacts().get(0).sha256());
        assertEquals(downloaded.path(), second.artifacts().get(0).path());
        assertEquals(0L, second.networkDownloadWallMs());
    }

    @Test
    void offlineCacheMissIsExplicitAndDoesNotUseNetworkRepositories() throws Exception {
        Path repository = temp.resolve("offline-repository");
        write(repository, "fixture/library/1.0/library-1.0.pom",
                pom("fixture", "library", "1.0", ""));
        Path root = temp.resolve("offline-root/pom.xml");
        write(root.getParent(), root.getFileName().toString(), pom("fixture", "root", "1.0",
                "<dependencies><dependency><groupId>fixture</groupId>"
                        + "<artifactId>library</artifactId><version>1.0</version></dependency></dependencies>"));

        MavenDependencyGraphResolver.Request request = new MavenDependencyGraphResolver.Request(
                root, temp.resolve("offline-cache"),
                List.of(MavenDependencyGraphResolver.RepositorySpec.file(repository),
                        MavenDependencyGraphResolver.RepositorySpec.central()),
                List.of(), true);
        MavenDependencyGraphResolver.Completion completion;
        try (MavenDependencyGraphResolver resolver = new MavenDependencyGraphResolver()) {
            completion = resolver.complete(request);
        }

        assertEquals(MavenDependencyGraphResolver.Status.UNRESOLVED, completion.status());
        assertTrue(completion.artifacts().isEmpty());
        assertEquals(0L, completion.networkDownloadWallMs());
        assertTrue(completion.resolution().problems().stream()
                .anyMatch(problem -> problem.code().equals("DEPENDENCY_ARTIFACT_MISSING")
                        && problem.detail().contains("offline-cache-miss")));
    }

    @Test
    void invalidRemoteJarIsRemovedAndReportedInsteadOfEnteringCache() throws Exception {
        Path repository = temp.resolve("invalid-repository");
        write(repository, "fixture/library/1.0/library-1.0.pom",
                pom("fixture", "library", "1.0", ""));
        Path invalid = repository.resolve("fixture/library/1.0/library-1.0.jar");
        writeBytes(invalid, new byte[]{'n', 'o', 't', '-', 'a', '-', 'j', 'a', 'r'});
        Path root = temp.resolve("invalid-root/pom.xml");
        write(root.getParent(), root.getFileName().toString(), pom("fixture", "root", "1.0",
                "<dependencies><dependency><groupId>fixture</groupId>"
                        + "<artifactId>library</artifactId><version>1.0</version></dependency></dependencies>"));
        Path cache = temp.resolve("invalid-cache");
        MavenDependencyGraphResolver.Request request = new MavenDependencyGraphResolver.Request(
                root, cache, List.of(MavenDependencyGraphResolver.RepositorySpec.file(repository)),
                List.of(), false);
        MavenDependencyGraphResolver.Completion completion;
        try (MavenDependencyGraphResolver resolver = new MavenDependencyGraphResolver()) {
            completion = resolver.complete(request);
        }

        assertEquals(MavenDependencyGraphResolver.Status.UNRESOLVED, completion.status());
        assertTrue(completion.artifacts().isEmpty());
        assertTrue(completion.resolution().problems().stream()
                .anyMatch(problem -> problem.code().equals("DEPENDENCY_ARTIFACT_INVALID")
                        && problem.coordinate().equals("fixture:library:1.0:jar:")));
        assertFalse(Files.exists(cache.resolve("fixture/library/1.0/library-1.0.jar"),
                java.nio.file.LinkOption.NOFOLLOW_LINKS));
    }

    @Test
    void http404IsVisibleForTheExactArtifactAndCancellationIsExplicit() throws Exception {
        Path repository = temp.resolve("http-repository");
        write(repository, "fixture/library/1.0/library-1.0.pom",
                pom("fixture", "library", "1.0", ""));
        Path root = temp.resolve("http-root/pom.xml");
        write(root.getParent(), root.getFileName().toString(), pom("fixture", "root", "1.0",
                "<dependencies><dependency><groupId>fixture</groupId>"
                        + "<artifactId>library</artifactId><version>1.0</version></dependency></dependencies>"));
        AtomicInteger requests = new AtomicInteger();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            requests.incrementAndGet();
            exchange.sendResponseHeaders(404, -1);
            exchange.close();
        });
        server.start();
        try {
            URI url = URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/");
            MavenDependencyGraphResolver.Request request = new MavenDependencyGraphResolver.Request(
                    root, temp.resolve("http-cache"),
                    List.of(MavenDependencyGraphResolver.RepositorySpec.file(repository),
                            new MavenDependencyGraphResolver.RepositorySpec("http-fixture", url)),
                    List.of(), false);
            MavenDependencyGraphResolver.Completion completion;
            try (MavenDependencyGraphResolver resolver = new MavenDependencyGraphResolver()) {
                completion = resolver.complete(request);
            }
            assertTrue(requests.get() > 0);
            assertEquals(MavenDependencyGraphResolver.Status.UNRESOLVED, completion.status());
            assertTrue(completion.resolution().problems().stream()
                    .anyMatch(problem -> problem.coordinate().equals("fixture:library:1.0:jar:")
                            && (problem.code().equals("DEPENDENCY_ARTIFACT_MISSING")
                            || problem.code().equals("DEPENDENCY_ARTIFACT_UNRESOLVED"))
                            && problem.detail().contains("404")),
                    completion.resolution().problems().toString());

            try (MavenDependencyGraphResolver resolver = new MavenDependencyGraphResolver()) {
                assertThrows(IOException.class, () -> resolver.complete(request, () -> true));
            }
        } finally {
            server.stop(0);
        }
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

    private static void writeBytes(Path file, byte[] bytes) throws IOException {
        Files.createDirectories(file.getParent());
        Files.write(file, bytes);
    }

    private static void writeJar(Path file, String entryName, String content) throws IOException {
        Files.createDirectories(file.getParent());
        try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(file))) {
            output.putNextEntry(new JarEntry(entryName));
            output.write(content.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            output.closeEntry();
        }
    }
}
