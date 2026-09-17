package io.just.sast.dependency;

import io.just.sast.model.ArtifactProvenance;
import io.just.sast.model.DependencyGraph;
import io.just.sast.util.ArchiveLimits;
import io.just.sast.util.ArtifactFingerprint;
import org.apache.maven.model.DependencyManagement;
import org.apache.maven.model.Model;
import org.apache.maven.model.Profile;
import org.apache.maven.model.Repository;
import org.apache.maven.model.building.DefaultModelBuildingRequest;
import org.apache.maven.model.building.DefaultModelBuilderFactory;
import org.apache.maven.model.building.FileModelSource;
import org.apache.maven.model.building.ModelBuilder;
import org.apache.maven.model.building.ModelBuildingException;
import org.apache.maven.model.building.ModelBuildingRequest;
import org.apache.maven.model.building.ModelBuildingResult;
import org.apache.maven.model.building.ModelProblem;
import org.apache.maven.model.io.DefaultModelReader;
import org.apache.maven.model.resolution.InvalidRepositoryException;
import org.apache.maven.model.resolution.ModelResolver;
import org.apache.maven.model.resolution.UnresolvableModelException;
import org.apache.maven.repository.internal.MavenRepositorySystemUtils;
import org.eclipse.aether.DefaultRepositorySystemSession;
import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.artifact.Artifact;
import org.eclipse.aether.artifact.DefaultArtifact;
import org.eclipse.aether.collection.CollectRequest;
import org.eclipse.aether.collection.CollectResult;
import org.eclipse.aether.collection.DependencyCollectionException;
import org.eclipse.aether.graph.DependencyNode;
import org.eclipse.aether.impl.DefaultServiceLocator;
import org.eclipse.aether.repository.LocalRepository;
import org.eclipse.aether.repository.RemoteRepository;
import org.eclipse.aether.resolution.ArtifactDescriptorException;
import org.eclipse.aether.resolution.ArtifactRequest;
import org.eclipse.aether.resolution.ArtifactResolutionException;
import org.eclipse.aether.resolution.ArtifactResult;
import org.eclipse.aether.spi.connector.RepositoryConnectorFactory;
import org.eclipse.aether.spi.connector.transport.TransporterFactory;
import org.eclipse.aether.transfer.ArtifactNotFoundException;
import org.eclipse.aether.transfer.TransferCancelledException;
import org.eclipse.aether.transfer.TransferEvent;
import org.eclipse.aether.transfer.TransferListener;
import org.eclipse.aether.transfer.TransferResource;
import org.eclipse.aether.util.graph.manager.DependencyManagerUtils;
import org.eclipse.aether.util.graph.selector.AndDependencySelector;
import org.eclipse.aether.util.graph.selector.ExclusionDependencySelector;
import org.eclipse.aether.util.graph.selector.OptionalDependencySelector;
import org.eclipse.aether.util.graph.transformer.ConflictResolver;
import org.eclipse.aether.transport.file.FileTransporterFactory;
import org.eclipse.aether.transport.http.HttpTransporterFactory;
import org.eclipse.aether.connector.basic.BasicRepositoryConnectorFactory;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;
import java.util.Set;
import java.util.Locale;
import java.util.zip.ZipEntry;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/**
 * In-process Maven model and dependency graph owner.
 *
 * <p>The model builder is deliberately configured with no Maven settings, no user properties,
 * and {@code processPlugins=false}. Resolver receives only the repositories in the immutable
 * request. It reads POM metadata and dependency descriptors; it never starts a Maven lifecycle,
 * loads target classes, or executes a target plugin/application.</p>
 */
public final class MavenDependencyGraphResolver implements AutoCloseable {
    public static final String CENTRAL_REPOSITORY_ID = "central";
    public static final String CENTRAL_REPOSITORY_URL = "https://repo.maven.apache.org/maven2";

    public enum Status {
        COMPLETE,
        PARTIAL,
        UNRESOLVED
    }

    public enum Severity {
        WARNING,
        ERROR
    }

    /** An explicitly selected Maven repository; POM-declared repositories are not added. */
    public record RepositorySpec(String id, URI uri) {
        public RepositorySpec {
            id = text(id, "repository id");
            uri = Objects.requireNonNull(uri, "repository uri");
            if (!uri.isAbsolute()) {
                throw new IllegalArgumentException("repository URI must be absolute");
            }
            String scheme = uri.getScheme().toLowerCase(java.util.Locale.ROOT);
            if (!scheme.equals("file") && !scheme.equals("http") && !scheme.equals("https")) {
                throw new IllegalArgumentException(
                        "repository URI must use file, http or https: " + scheme);
            }
            if (uri.getUserInfo() != null || uri.getQuery() != null || uri.getFragment() != null) {
                throw new IllegalArgumentException(
                        "repository URI must not contain credentials, query or fragment");
            }
        }

        public static RepositorySpec central() {
            return new RepositorySpec(CENTRAL_REPOSITORY_ID, URI.create(CENTRAL_REPOSITORY_URL));
        }

        public static RepositorySpec file(Path root) {
            if (root == null) {
                throw new IllegalArgumentException("repository path is required");
            }
            return new RepositorySpec("file-" + Integer.toHexString(
                    root.toAbsolutePath().normalize().toString().hashCode()),
                    root.toAbsolutePath().normalize().toUri());
        }
    }

    /** All input and environment choices needed for one model/graph resolution. */
    public record Request(Path pomFile, Path localRepository, List<RepositorySpec> repositories,
                          List<String> activeProfileIds, boolean offline) {
        public Request {
            pomFile = absolute(pomFile, "pom file");
            localRepository = absolute(localRepository, "local repository");
            repositories = repositories == null || repositories.isEmpty()
                    ? List.of(RepositorySpec.central()) : List.copyOf(repositories);
            LinkedHashSet<String> repositoryIds = new LinkedHashSet<>();
            for (RepositorySpec repository : repositories) {
                Objects.requireNonNull(repository, "repository");
                if (!repositoryIds.add(repository.id())) {
                    throw new IllegalArgumentException("duplicate repository id: " + repository.id());
                }
            }
            LinkedHashSet<String> profiles = new LinkedHashSet<>();
            for (String profile : activeProfileIds == null ? List.<String>of() : activeProfileIds) {
                profiles.add(text(profile, "active profile id"));
            }
            activeProfileIds = List.copyOf(profiles);
        }

        public static Request forPom(Path pomFile, Path localRepository) {
            return new Request(pomFile, localRepository, List.of(), List.of(), false);
        }

        private static Path absolute(Path value, String field) {
            if (value == null) {
                throw new IllegalArgumentException(field + " is required");
            }
            return value.toAbsolutePath().normalize();
        }
    }

    public record Exclusion(String groupId, String artifactId) {
        public Exclusion {
            groupId = text(groupId, "exclusion groupId");
            artifactId = text(artifactId, "exclusion artifactId");
        }
    }

    /** Immutable effective-POM dependency projection; Maven model objects do not escape. */
    public record DeclaredDependency(String groupId, String artifactId, String version,
                                     String type, String classifier, String scope,
                                     boolean optional, List<Exclusion> exclusions) {
        public DeclaredDependency {
            groupId = value(groupId, "UNRESOLVED");
            artifactId = value(artifactId, "UNRESOLVED");
            version = value(version, "UNRESOLVED");
            type = value(type, "jar");
            classifier = value(classifier, "");
            scope = value(scope, "compile");
            exclusions = exclusions == null ? List.of() : List.copyOf(exclusions);
        }

        public String coordinate() {
            return groupId + ':' + artifactId + ':' + version + ':' + type + ':' + classifier;
        }

        public boolean hasConcreteVersion() {
            return !version.equals("UNRESOLVED") && !version.contains("${")
                    && !version.isBlank();
        }
    }

    public record EffectivePom(String groupId, String artifactId, String version,
                               String packaging, List<DeclaredDependency> dependencies,
                               List<DeclaredDependency> dependencyManagement,
                               List<String> declaredProfileIds, List<String> activeProfileIds,
                               List<String> inactiveProfileIds) {
        public EffectivePom {
            groupId = value(groupId, "UNRESOLVED");
            artifactId = value(artifactId, "UNRESOLVED");
            version = value(version, "UNRESOLVED");
            packaging = value(packaging, "jar");
            dependencies = dependencies == null ? List.of() : List.copyOf(dependencies);
            dependencyManagement = dependencyManagement == null
                    ? List.of() : List.copyOf(dependencyManagement);
            declaredProfileIds = immutableText(declaredProfileIds);
            activeProfileIds = immutableText(activeProfileIds);
            inactiveProfileIds = immutableText(inactiveProfileIds);
        }

        public String coordinate() {
            return groupId + ':' + artifactId + ':' + version;
        }

        private static List<String> immutableText(List<String> values) {
            if (values == null || values.isEmpty()) {
                return List.of();
            }
            return values.stream().map(value -> text(value, "profile id")).distinct().toList();
        }
    }

    public record Problem(String code, String coordinate, Severity severity, String detail) {
        public Problem {
            code = text(code, "problem code");
            coordinate = value(coordinate, "UNRESOLVED");
            severity = Objects.requireNonNull(severity, "problem severity");
            detail = value(detail, "");
        }
    }

    public record Resolution(EffectivePom effectivePom, DependencyGraph graph,
                             List<Problem> problems, Status status, boolean offline,
                             List<String> repositoryIds) {
        public Resolution {
            effectivePom = Objects.requireNonNull(effectivePom, "effectivePom");
            graph = Objects.requireNonNull(graph, "graph");
            problems = problems == null ? List.of() : List.copyOf(problems);
            status = Objects.requireNonNull(status, "status");
            repositoryIds = repositoryIds == null ? List.of() : List.copyOf(repositoryIds);
        }
    }

    /** Cooperative cancellation boundary for dependency metadata and artifact reads. */
    @FunctionalInterface
    public interface Cancellation {
        boolean isCancelled();

        static Cancellation none() {
            return () -> false;
        }
    }

    /** One complete runtime artifact selected by the effective dependency graph. */
    public record ArtifactDownload(String coordinate, Path path, DependencyGraph.Source source,
                                   String repositoryId, String sourceUrl, String sha256,
                                   long sizeBytes) {
        public ArtifactDownload {
            coordinate = text(coordinate, "artifact coordinate");
            path = absolutePath(path, "artifact path");
            if (source != DependencyGraph.Source.CACHE
                    && source != DependencyGraph.Source.REMOTE) {
                throw new IllegalArgumentException("artifact source must be CACHE or REMOTE");
            }
            repositoryId = text(repositoryId, "artifact repository id");
            sourceUrl = text(sourceUrl, "artifact source URL");
            sha256 = digestText(sha256);
            if (sizeBytes < 0L) {
                throw new IllegalArgumentException("artifact size must be non-negative");
            }
        }
    }

    /** Resolution plus validated bytes and separate resolution/network timing for one request. */
    public record Completion(Resolution resolution, List<ArtifactDownload> artifacts,
                             long resolutionWallMs, long networkDownloadWallMs,
                             long networkRequestMs, long transferredBytes) {
        public Completion {
            resolution = Objects.requireNonNull(resolution, "completion resolution");
            artifacts = artifacts == null ? List.of() : List.copyOf(artifacts);
            if (resolutionWallMs < 0L || networkDownloadWallMs < 0L
                    || networkRequestMs < 0L || transferredBytes < 0L) {
                throw new IllegalArgumentException("completion metrics must be non-negative");
            }
        }

        public Status status() {
            return resolution.status();
        }

        public List<Path> paths() {
            return artifacts.stream().map(ArtifactDownload::path).toList();
        }

        /**
         * Project the completed bytes into the immutable dependency graph.  The index is the
         * first frontend input ordinal after the explicit user dependencies; POM nodes without
         * a selected runtime artifact retain inputIndex -1 and remain environment-only facts.
         */
        public DependencyGraph environmentGraph(int firstInputIndex) {
            if (firstInputIndex < 0) {
                throw new IllegalArgumentException("first dependency input index must be non-negative");
            }
            List<DependencyGraph.ArtifactBinding> bindings = new ArrayList<>(artifacts.size());
            for (int index = 0; index < artifacts.size(); index++) {
                ArtifactDownload artifact = artifacts.get(index);
                ArtifactProvenance provenance = new ArtifactProvenance(artifact.coordinate(),
                        ArtifactProvenance.Role.DEPENDENCY, artifact.sha256(), artifact.sizeBytes());
                bindings.add(new DependencyGraph.ArtifactBinding(artifact.coordinate(),
                        provenance, artifact.source(), bindingSourceDetail(artifact),
                        firstInputIndex + index));
            }
            DependencyGraph graph = resolution.graph().withCompletedArtifacts(bindings);
            if (resolution.problems().stream().anyMatch(problem ->
                    problem.severity() == Severity.ERROR)) {
                graph = graph.withEnvironmentConditions(
                        List.of("MAVEN_DEPENDENCY_INPUT_INCOMPLETE"));
            }
            return graph;
        }

        /** Path-free identity of effective model, selected bytes, source mode and failures. */
        public String semanticIdentity() {
            StringBuilder canonical = new StringBuilder("dependency-completion-v1\n")
                    .append("status=").append(status()).append('\n')
                    .append("offline=").append(resolution.offline()).append('\n')
                    .append("repositories=").append(resolution.repositoryIds()).append('\n')
                    .append("graph=").append(resolution.graph().semanticDigest()).append('\n');
            EffectivePom pom = resolution.effectivePom();
            canonical.append("pom=").append(pom.coordinate()).append('|')
                    .append(pom.packaging()).append('\n');
            appendDependencies(canonical, "dependency", pom.dependencies());
            appendDependencies(canonical, "managed", pom.dependencyManagement());
            canonical.append("declared-profiles=").append(pom.declaredProfileIds()).append('\n')
                    .append("active-profiles=").append(pom.activeProfileIds()).append('\n')
                    .append("inactive-profiles=").append(pom.inactiveProfileIds()).append('\n');
            resolution.problems().stream()
                    .sorted(java.util.Comparator.comparing(Problem::code)
                            .thenComparing(Problem::coordinate)
                            .thenComparing(problem -> problem.severity().name()))
                    .forEach(problem -> canonical.append("problem=").append(problem.code())
                            .append('|').append(problem.coordinate()).append('|')
                            .append(problem.severity()).append('\n'));
            artifacts.stream().sorted(java.util.Comparator.comparing(ArtifactDownload::coordinate))
                    .forEach(artifact -> canonical.append("artifact=").append(artifact.coordinate())
                            .append('|').append(artifact.source()).append('|')
                            .append(artifact.repositoryId()).append('|')
                            .append(repositoryScheme(artifact.sourceUrl())).append('|')
                            .append(artifact.sha256()).append('|').append(artifact.sizeBytes())
                            .append('\n'));
            return digest(canonical.toString());
        }

        private static void appendDependencies(StringBuilder canonical, String label,
                                               List<DeclaredDependency> dependencies) {
            dependencies.stream().map(value -> value.groupId() + ':' + value.artifactId() + ':'
                    + value.version() + ':' + value.type() + ':' + value.classifier() + ':'
                    + value.scope() + ':' + value.optional() + ':' + value.exclusions())
                    .sorted().forEach(value -> canonical.append(label).append('=').append(value)
                            .append('\n'));
        }
    }

    private final RepositorySystem repositorySystem;
    private final ModelBuilder modelBuilder;

    public MavenDependencyGraphResolver() {
        DefaultServiceLocator locator = MavenRepositorySystemUtils.newServiceLocator();
        locator.addService(RepositoryConnectorFactory.class, BasicRepositoryConnectorFactory.class);
        locator.addService(TransporterFactory.class, FileTransporterFactory.class);
        locator.addService(TransporterFactory.class, HttpTransporterFactory.class);
        locator.setErrorHandler(new DefaultServiceLocator.ErrorHandler() {
            @Override
            public void serviceCreationFailed(Class<?> service, Class<?> implementation,
                                              Throwable failure) {
                throw new IllegalStateException("Maven Resolver service creation failed: "
                        + service.getName() + '/' + implementation.getName(), failure);
            }
        });
        repositorySystem = Objects.requireNonNull(locator.getService(RepositorySystem.class),
                "Maven Resolver RepositorySystem");
        modelBuilder = new DefaultModelBuilderFactory().newInstance();
    }

    /** Resolve one POM with exact repository/cache/profile choices. */
    public Resolution resolve(Request request) throws IOException {
        return resolve(request, Cancellation.none(), null);
    }

    /** Resolve the POM and complete selected runtime artifact bytes. */
    public Completion complete(Request request) throws IOException {
        return complete(request, Cancellation.none());
    }

    /** Complete dependency bytes with a cooperative cancellation boundary. */
    public Completion complete(Request request, Cancellation cancellation) throws IOException {
        Objects.requireNonNull(request, "request");
        Cancellation stop = Objects.requireNonNull(cancellation, "cancellation");
        long resolutionStartedNanos = System.nanoTime();
        checkCancelled(stop);
        TransferStats transferStats = new TransferStats(stop);
        Resolution initial = resolve(request, stop, transferStats);
        List<Problem> problems = new ArrayList<>(initial.problems());
        List<ArtifactDownload> artifacts = new ArrayList<>();
        List<RepositorySpec> usableRepositorySpecs = usableRepositories(request);
        List<RemoteRepository> repositories = remoteRepositories(usableRepositorySpecs);
        DefaultRepositorySystemSession session = newSession(request, usableRepositorySpecs,
                stop, transferStats);
        for (DependencyGraph.Node node : initial.graph().nodes().values().stream()
                .sorted(java.util.Comparator.comparing(DependencyGraph.Node::ref)).toList()) {
            checkCancelled(stop);
            if (!downloadable(node)) {
                continue;
            }
            ArtifactAttempt attempt = completeArtifact(request, node, session, repositories, stop);
            problems.addAll(attempt.problems());
            if (attempt.artifact() != null) {
                artifacts.add(attempt.artifact());
            }
        }
        List<Problem> immutableProblems = problems.stream().distinct().toList();
        Status status = completionStatus(initial, immutableProblems);
        Resolution completed = new Resolution(initial.effectivePom(), initial.graph(),
                immutableProblems, status, initial.offline(), initial.repositoryIds());
        NetworkTiming.Snapshot metrics = transferStats.snapshot();
        return new Completion(completed, artifacts, elapsedMs(resolutionStartedNanos),
                metrics.networkWallMs(),
                metrics.requestMs(), metrics.transferredBytes());
    }

    private Resolution resolve(Request request, Cancellation cancellation,
                               TransferStats transferStats) throws IOException {
        Objects.requireNonNull(request, "request");
        Cancellation stop = Objects.requireNonNull(cancellation, "cancellation");
        checkCancelled(stop);
        validateRequest(request);
        Files.createDirectories(request.localRepository());

        List<RepositorySpec> usableRepositorySpecs = usableRepositories(request);
        List<RemoteRepository> repositories = remoteRepositories(usableRepositorySpecs);
        DefaultRepositorySystemSession session = newSession(request, usableRepositorySpecs,
                stop, transferStats);
        List<Problem> problems = new ArrayList<>();
        List<String> ignoredPomRepositories = new ArrayList<>();

        Model raw = new DefaultModelReader().read(request.pomFile().toFile(), Map.of());
        checkCancelled(stop);
        Coordinates rawCoordinates = coordinates(raw);
        RepositoryModelResolver modelResolver = new RepositoryModelResolver(repositorySystem,
                session, repositories, ignoredPomRepositories);
        ModelBuildingResult modelResult = null;
        Model effective = null;
        try {
            DefaultModelBuildingRequest modelRequest = new DefaultModelBuildingRequest();
            modelRequest.setPomFile(request.pomFile().toFile());
            modelRequest.setValidationLevel(ModelBuildingRequest.VALIDATION_LEVEL_MINIMAL);
            modelRequest.setProcessPlugins(false);
            modelRequest.setTwoPhaseBuilding(false);
            modelRequest.setLocationTracking(true);
            modelRequest.setSystemProperties(modelSystemProperties());
            modelRequest.setUserProperties(new Properties());
            modelRequest.setActiveProfileIds(request.activeProfileIds());
            modelRequest.setInactiveProfileIds(List.of());
            modelRequest.setModelResolver(modelResolver);
            modelResult = modelBuilder.build(modelRequest);
            effective = modelResult.getEffectiveModel();
        } catch (ModelBuildingException failure) {
            problems.addAll(modelProblems(failure.getProblems(), rawCoordinates));
            modelResult = failure.getResult();
            if (modelResult != null) {
                effective = modelResult.getEffectiveModel();
            }
        }
        if (modelResult != null) {
            problems.addAll(modelProblems(modelResult.getProblems(), rawCoordinates));
        }
        if (!ignoredPomRepositories.isEmpty()) {
            for (String id : ignoredPomRepositories.stream().distinct().toList()) {
                problems.add(new Problem("POM_REPOSITORY_IGNORED", rawCoordinates.value(),
                        Severity.WARNING, "repository-not-authorized:" + id));
            }
        }

        EffectivePom effectivePom = effective == null
                ? unresolvedPom(raw, modelResult)
                : effectivePom(effective, raw, modelResult, problems);
        List<DeclaredDependency> unresolved = effectivePom.dependencies().stream()
                .filter(dependency -> !dependency.hasConcreteVersion())
                .toList();
        for (DeclaredDependency dependency : unresolved) {
            problems.add(new Problem("DEPENDENCY_VERSION_MISSING", dependency.coordinate(),
                    Severity.ERROR, "version-not-concrete"));
        }

        DependencyNode collectionRoot = null;
        if (effective != null && effectivePom.version().equals(effective.getVersion())
                && !effectivePom.version().equals("UNRESOLVED")) {
            CollectResult collected = collect(session, repositories, effectivePom, problems, stop);
            if (collected != null) {
                collectionRoot = collected.getRoot();
            }
        } else {
            problems.add(new Problem("ROOT_VERSION_UNRESOLVED", effectivePom.coordinate(),
                    Severity.ERROR, "root-version-not-concrete"));
        }
        if (collectionRoot == null && effective != null && effectivePom.dependencies().stream()
                .anyMatch(DeclaredDependency::hasConcreteVersion)) {
            problems.add(new Problem("DEPENDENCY_GRAPH_UNRESOLVED", effectivePom.coordinate(),
                    Severity.ERROR, "collection-root-unavailable"));
        }

        DependencyGraph graph = graph(effectivePom, collectionRoot, unresolved, problems);
        graph = graph.withEnvironmentConditions(environmentConditions(graph, effective != null,
                problems));
        List<Problem> immutableProblems = problems.stream().distinct().toList();
        Status status = status(effective, unresolved, immutableProblems);
        return new Resolution(effectivePom, graph, immutableProblems, status, request.offline(),
                request.repositories().stream().map(RepositorySpec::id).toList());
    }

    private CollectResult collect(DefaultRepositorySystemSession session,
                                  List<RemoteRepository> repositories, EffectivePom pom,
                                  List<Problem> problems, Cancellation cancellation) throws IOException {
        checkCancelled(cancellation);
        List<org.eclipse.aether.graph.Dependency> direct = aetherDependencies(
                pom.dependencies(), problems);
        List<org.eclipse.aether.graph.Dependency> managed = aetherDependencies(
                pom.dependencyManagement().stream()
                        .filter(dependency -> !(dependency.type().equals("pom")
                                && dependency.scope().equals("import"))).toList(), problems);
        Artifact rootArtifact = new DefaultArtifact(pom.groupId(), pom.artifactId(), "", "pom",
                pom.version());
        CollectRequest request = new CollectRequest();
        request.setRootArtifact(rootArtifact);
        request.setDependencies(direct);
        request.setManagedDependencies(managed);
        request.setRepositories(repositories);
        request.setRequestContext("just-pom-resolution");
        try {
            CollectResult result = repositorySystem.collectDependencies(session, request);
            checkCancelled(cancellation);
            return result;
        } catch (DependencyCollectionException failure) {
            CollectResult partial = failure.getResult();
            if (partial == null) {
                throw new IOException("Maven dependency collection returned no result", failure);
            }
            if (isCancelled(cancellation)) {
                problems.add(new Problem("DEPENDENCY_DOWNLOAD_CANCELLED", pom.coordinate(),
                        Severity.ERROR, "cancellation-requested"));
            } else {
                List<Exception> exceptions = partial.getExceptions();
                if (exceptions.isEmpty()) {
                    problems.add(new Problem("DEPENDENCY_RESOLUTION_FAILED", pom.coordinate(),
                            Severity.ERROR, detail(failure)));
                } else {
                    for (Exception exception : exceptions) {
                        problems.add(new Problem(problemCode(exception), pom.coordinate(),
                                Severity.ERROR, detail(exception)));
                    }
                }
            }
            return partial;
        }
    }

    private ArtifactAttempt completeArtifact(Request request, DependencyGraph.Node node,
                                             DefaultRepositorySystemSession session,
                                             List<RemoteRepository> repositories,
                                             Cancellation cancellation) throws IOException {
        String coordinate = nodeCoordinate(node);
        String artifactExtension = extension(node.type());
        Path expected = artifactPath(request.localRepository(), node.group(), node.name(),
                node.version(), node.classifier(), artifactExtension);
        List<Problem> problems = new ArrayList<>();
        CacheProbe cache = probeCache(expected, artifactExtension, request.localRepository());
        if (cache.artifact() != null) {
            return new ArtifactAttempt(new ArtifactDownload(coordinate, expected,
                    DependencyGraph.Source.CACHE, "local-cache", "cache://maven-local",
                    cache.artifact().sha256(), cache.artifact().sizeBytes()), problems);
        }
        if (!cache.invalidDetail().isBlank()) {
            problems.add(new Problem("DEPENDENCY_CACHE_INVALID", coordinate, Severity.WARNING,
                    cache.invalidDetail()));
        }
        if (!cache.cleanupFailure().isBlank()) {
            problems.add(new Problem("DEPENDENCY_CACHE_INVALID", coordinate, Severity.ERROR,
                    cache.cleanupFailure()));
            return new ArtifactAttempt(null, problems);
        }
        boolean explicitFileRepository = repositories.stream()
                .anyMatch(repository -> repository.getUrl().toLowerCase(Locale.ROOT)
                        .startsWith("file:"));
        if (request.offline() && !explicitFileRepository) {
            problems.add(new Problem("DEPENDENCY_ARTIFACT_MISSING", coordinate, Severity.ERROR,
                    "offline-cache-miss"));
            return new ArtifactAttempt(null, problems);
        }

        checkCancelled(cancellation);
        Artifact artifact = new DefaultArtifact(node.group(), node.name(), node.classifier(),
                artifactExtension, node.version())
                .setProperties(Map.of("maven:type", node.type()));
        ArtifactRequest artifactRequest = new ArtifactRequest(artifact, repositories,
                "just-runtime-artifact");
        ArtifactResult result;
        try {
            result = repositorySystem.resolveArtifact(session, artifactRequest);
            checkCancelled(cancellation);
        } catch (ArtifactResolutionException failure) {
            if (isCancelled(cancellation)) {
                problems.add(new Problem("DEPENDENCY_DOWNLOAD_CANCELLED", coordinate,
                        Severity.ERROR, "cancellation-requested"));
            } else {
                String transferDetail = session.getTransferListener() instanceof TransferStats stats
                        ? stats.failureDetail(artifactFileName(artifact)) : "";
                addArtifactFailure(problems, coordinate, failure, transferDetail,
                        request.offline());
            }
            return new ArtifactAttempt(null, problems);
        }
        if (!result.isResolved() || result.getArtifact() == null
                || result.getArtifact().getFile() == null) {
            List<Exception> failures = result.getExceptions();
            if (failures.isEmpty()) {
                problems.add(new Problem("DEPENDENCY_ARTIFACT_UNRESOLVED", coordinate,
                        Severity.ERROR, "resolver-returned-no-file"));
            } else {
                for (Exception failure : failures) {
                    problems.add(new Problem(problemCode(failure), coordinate, Severity.ERROR,
                            detail(failure)));
                }
            }
            return new ArtifactAttempt(null, problems);
        }

        Path resolved = result.getArtifact().getFile().toPath().toAbsolutePath().normalize();
        if (!resolved.startsWith(request.localRepository())) {
            problems.add(new Problem("DEPENDENCY_ARTIFACT_OUTSIDE_CACHE", coordinate,
                    Severity.ERROR, resolved.toString()));
            return new ArtifactAttempt(null, problems);
        }
        ValidatedArtifact validated;
        try {
            validated = validateArtifact(resolved, artifactExtension);
        } catch (IOException | RuntimeException invalid) {
            String invalidDetail = detail(invalid);
            String cleanupFailure = invalidateExact(resolved, request.localRepository());
            if (!cleanupFailure.isBlank()) {
                invalidDetail += ";cleanup=" + cleanupFailure;
            }
            problems.add(new Problem("DEPENDENCY_ARTIFACT_INVALID", coordinate,
                    Severity.ERROR, invalidDetail));
            return new ArtifactAttempt(null, problems);
        }

        boolean fromCache = result.getRepository() == null;
        DependencyGraph.Source source = fromCache
                ? DependencyGraph.Source.CACHE : DependencyGraph.Source.REMOTE;
        String repositoryId = fromCache ? "local-cache" : result.getRepository().getId();
        String sourceUrl = fromCache ? "cache://maven-local"
                : result.getRepository() instanceof RemoteRepository remote
                ? remote.getUrl() : "resolver://" + repositoryId;
        return new ArtifactAttempt(new ArtifactDownload(coordinate, resolved, source,
                repositoryId, sourceUrl, validated.sha256(), validated.sizeBytes()), problems);
    }

    private static CacheProbe probeCache(Path expected, String artifactExtension,
                                         Path localRepository) throws IOException {
        if (!Files.exists(expected, LinkOption.NOFOLLOW_LINKS)) {
            return new CacheProbe(null, "", "");
        }
        try {
            return new CacheProbe(validateArtifact(expected, artifactExtension), "", "");
        } catch (IOException | RuntimeException invalid) {
            String invalidDetail = detail(invalid);
            String cleanupFailure = invalidateExact(expected, localRepository);
            return new CacheProbe(null, invalidDetail, cleanupFailure);
        }
    }

    private static String invalidateExact(Path candidate, Path localRepository) {
        Path normalized = candidate.toAbsolutePath().normalize();
        Path root = localRepository.toAbsolutePath().normalize();
        if (!normalized.startsWith(root) || normalized.equals(root)) {
            return "cache-path-outside-local-repository";
        }
        try {
            Files.deleteIfExists(normalized);
            return "";
        } catch (IOException | RuntimeException failure) {
            return detail(failure);
        }
    }

    private static ValidatedArtifact validateArtifact(Path path, String artifactExtension)
            throws IOException {
        Path normalized = path.toAbsolutePath().normalize();
        ArchiveLimits.checkPathAncestors(normalized, io.just.sast.run.InputBudget.defaults());
        if (ArchiveLimits.isLinkOrReparsePoint(normalized)
                || !Files.isRegularFile(normalized, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("artifact-cache-entry-not-regular");
        }
        ArchiveLimits.checkContainerSize(normalized, io.just.sast.run.InputBudget.defaults());
        if (Files.size(normalized) <= 0L) {
            throw new IOException("artifact-cache-entry-empty");
        }
        String extension = value(artifactExtension, "").toLowerCase(Locale.ROOT);
        if (extension.equals("jar") || extension.equals("war")) {
            io.just.sast.run.InputBudget.Tracker tracker =
                    io.just.sast.run.InputBudget.defaults().tracker();
            try (JarFile jar = new JarFile(normalized.toFile(), false, JarFile.OPEN_READ)) {
                Enumeration<JarEntry> entries = jar.entries();
                while (entries.hasMoreElements()) {
                    ZipEntry entry = entries.nextElement();
                    if (!ArchiveLimits.safeEntryName(entry.getName(), tracker.budget())) {
                        throw new IOException("artifact-archive-entry-unsafe:" + entry.getName());
                    }
                    tracker.observe(entry);
                }
            } catch (IOException | RuntimeException invalid) {
                throw new IOException("artifact-archive-invalid", invalid);
            }
        } else if (extension.equals("pom")) {
            try {
                new DefaultModelReader().read(normalized.toFile(), Map.of());
            } catch (IOException | RuntimeException invalid) {
                throw new IOException("artifact-pom-invalid", invalid);
            }
        } else {
            throw new IOException("artifact-extension-not-supported:" + extension);
        }
        return new ValidatedArtifact(ArtifactFingerprint.sha256(normalized),
                Files.size(normalized));
    }

    private static boolean downloadable(DependencyGraph.Node node) {
        if (node.source() != DependencyGraph.Source.POM_DERIVED
                || node.deployment() != DependencyGraph.Deployment.DECLARED_ENVIRONMENT
                || node.resolution() != DependencyGraph.Resolution.SELECTED
                || node.optional()) {
            return false;
        }
        String scope = node.scope().toLowerCase(Locale.ROOT);
        if (!scope.equals("compile") && !scope.equals("runtime")) {
            return false;
        }
        String type = node.type().toLowerCase(Locale.ROOT);
        if (type.equals("pom") || type.equals("maven-plugin") || type.equals("test-jar")
                || type.equals("java-source") || type.equals("javadoc")) {
            return false;
        }
        return (extension(type).equals("jar") || extension(type).equals("war"))
                && !node.version().equals("UNRESOLVED") && !node.version().contains("${");
    }

    private static Path artifactPath(Path localRepository, String group, String artifact,
                                     String version, String classifier, String extension)
            throws IOException {
        Path root = localRepository.toAbsolutePath().normalize();
        safeCoordinatePart(group, "group");
        safeCoordinatePart(artifact, "artifact");
        safeCoordinatePart(version, "version");
        if (!classifier.isBlank()) {
            safeCoordinatePart(classifier, "classifier");
        }
        safeCoordinatePart(extension, "extension");
        Path directory = root.resolve(group.replace('.', java.io.File.separatorChar))
                .resolve(artifact).resolve(version).normalize();
        String fileName = artifact + '-' + version
                + (classifier.isBlank() ? "" : '-' + classifier) + '.' + extension;
        Path result = directory.resolve(fileName).normalize();
        if (!result.startsWith(root)) {
            throw new IOException("artifact-cache-path-escapes-local-repository");
        }
        return result;
    }

    private static void safeCoordinatePart(String value, String field) throws IOException {
        if (value == null || value.isBlank() || value.equals(".") || value.equals("..")
                || value.indexOf('/') >= 0 || value.indexOf('\\') >= 0
                || value.indexOf(':') >= 0 || value.indexOf('\0') >= 0) {
            throw new IOException("artifact-coordinate-invalid:" + field);
        }
    }

    private static String nodeCoordinate(DependencyGraph.Node node) {
        return node.group() + ':' + node.name() + ':' + node.version() + ':'
                + node.type() + ':' + node.classifier();
    }

    private static Status completionStatus(Resolution initial, List<Problem> problems) {
        if (initial.status() == Status.UNRESOLVED
                || problems.stream().anyMatch(problem -> problem.severity() == Severity.ERROR)) {
            return Status.UNRESOLVED;
        }
        return problems.isEmpty() ? Status.COMPLETE : Status.PARTIAL;
    }

    private static List<String> environmentConditions(DependencyGraph graph, boolean pomResolved,
                                                       List<Problem> problems) {
        LinkedHashSet<String> conditions = new LinkedHashSet<>();
        conditions.add(pomResolved ? "MAVEN_POM_RESOLVED" : "MAVEN_POM_MODEL_UNRESOLVED");
        graph.nodes().values().stream().sorted(java.util.Comparator.comparing(
                DependencyGraph.Node::ref)).forEach(node -> {
            String coordinate = node.coordinate();
            String scope = node.scope().toLowerCase(Locale.ROOT);
            if (scope.equals("provided") || scope.equals("system")) {
                conditions.add("MAVEN_SCOPE_" + scope.toUpperCase(Locale.ROOT) + ':' + coordinate);
            } else if (scope.equals("test")) {
                conditions.add("MAVEN_TEST_SCOPE:" + coordinate);
            }
            if (node.optional()) {
                conditions.add("MAVEN_OPTIONAL:" + coordinate);
            }
            if (node.resolution() == DependencyGraph.Resolution.CONFLICT) {
                conditions.add("MAVEN_CONFLICT:" + coordinate);
            }
            if (node.resolutionReason().contains("relocated-from=")) {
                conditions.add("MAVEN_RELOCATED:" + coordinate);
            }
        });
        if (problems != null) {
            problems.stream().sorted(java.util.Comparator.comparing(Problem::code)
                    .thenComparing(Problem::coordinate)
                    .thenComparing(problem -> problem.severity().name()))
                    .forEach(problem -> conditions.add("MAVEN_PROBLEM:" + problem.code() + ':'
                            + problem.coordinate() + ':' + problem.severity()));
        }
        return List.copyOf(conditions);
    }

    private static String bindingSourceDetail(ArtifactDownload artifact) {
        String scheme = repositoryScheme(artifact.sourceUrl());
        StringBuilder detail = new StringBuilder("maven:repository=")
                .append(artifact.repositoryId()).append(";scheme=").append(scheme);
        if (scheme.equals("http") || scheme.equals("https")) {
            detail.append(";url=").append(artifact.sourceUrl());
        } else if (scheme.equals("file")) {
            detail.append(";url=<file-repository>");
        }
        return detail.toString();
    }

    private static String repositoryScheme(String sourceUrl) {
        if (sourceUrl == null) {
            return "unknown";
        }
        int separator = sourceUrl.indexOf(':');
        if (separator <= 0) {
            return "unknown";
        }
        return sourceUrl.substring(0, separator).toLowerCase(Locale.ROOT);
    }

    private static String relocationReason(List<? extends Artifact> relocations) {
        if (relocations.isEmpty()) {
            return "";
        }
        String value = relocations.stream().map(Objects::requireNonNull).map(
                MavenDependencyGraphResolver::coordinate).sorted()
                .collect(java.util.stream.Collectors.joining(","));
        return "relocated-from=" + value;
    }

    private record ArtifactAttempt(ArtifactDownload artifact, List<Problem> problems) {
        private ArtifactAttempt {
            problems = problems == null ? List.of() : List.copyOf(problems);
        }
    }

    private record CacheProbe(ValidatedArtifact artifact, String invalidDetail,
                              String cleanupFailure) {
        private CacheProbe {
            invalidDetail = invalidDetail == null ? "" : invalidDetail;
            cleanupFailure = cleanupFailure == null ? "" : cleanupFailure;
        }
    }

    private record ValidatedArtifact(String sha256, long sizeBytes) {
    }

    private static List<org.eclipse.aether.graph.Dependency> aetherDependencies(
            List<DeclaredDependency> dependencies, List<Problem> problems) {
        List<org.eclipse.aether.graph.Dependency> result = new ArrayList<>();
        for (DeclaredDependency dependency : dependencies) {
            if (!dependency.hasConcreteVersion()) {
                continue;
            }
            if (dependency.groupId().equals("UNRESOLVED")
                    || dependency.artifactId().equals("UNRESOLVED")) {
                problems.add(new Problem("DEPENDENCY_COORDINATE_UNRESOLVED", dependency.coordinate(),
                        Severity.ERROR, "group-or-artifact-not-concrete"));
                continue;
            }
            Artifact artifact = new DefaultArtifact(dependency.groupId(), dependency.artifactId(),
                    dependency.classifier(), extension(dependency.type()), dependency.version());
            artifact = artifact.setProperties(Map.of("maven:type", dependency.type()));
            List<org.eclipse.aether.graph.Exclusion> exclusions = dependency.exclusions().stream()
                    .map(value -> new org.eclipse.aether.graph.Exclusion(value.groupId(),
                            value.artifactId(), "*", "*")).toList();
            result.add(new org.eclipse.aether.graph.Dependency(artifact, dependency.scope(),
                    dependency.optional(), exclusions));
        }
        return List.copyOf(result);
    }

    private static DependencyGraph graph(EffectivePom pom, DependencyNode collectionRoot,
                                         List<DeclaredDependency> unresolved,
                                         List<Problem> problems) {
        List<DependencyGraph.Node> nodes = new ArrayList<>();
        List<DependencyGraph.Edge> edges = new ArrayList<>();
        Map<String, String> selectedRefs = new LinkedHashMap<>();
        Map<String, String> conflictRefs = new LinkedHashMap<>();
        Map<DependencyNode, String> identityRefs = new IdentityHashMap<>();
        List<ConflictLink> conflicts = new ArrayList<>();

        String rootCoordinate = pom.coordinate() + ":pom:";
        String rootRef = "mvn:" + rootCoordinate;
        nodes.add(new DependencyGraph.Node(rootRef,
                ArtifactProvenance.unknown(rootCoordinate, ArtifactProvenance.Role.APPLICATION),
                DependencyGraph.Source.POM_DERIVED,
                DependencyGraph.Deployment.DECLARED_ENVIRONMENT, pom.groupId(), pom.artifactId(),
                pom.version(), "pom", "", "maven:pom", "", "", "", -1,
                "", false, DependencyGraph.Resolution.SELECTED, "root-pom"));
        selectedRefs.put(rootCoordinate, rootRef);

        if (collectionRoot != null) {
            if (collectionRoot.getDependency() != null) {
                throw new IllegalStateException("Maven collection root has a dependency edge");
            }
            for (DependencyNode child : collectionRoot.getChildren()) {
                project(child, rootRef, 1, nodes, edges, selectedRefs, conflictRefs,
                        identityRefs, conflicts);
            }
        }
        for (DeclaredDependency dependency : unresolved) {
            String ref = "mvn:" + dependency.coordinate() + "|unresolved:" + digest(
                    dependency.coordinate() + "|missing-version");
            nodes.add(new DependencyGraph.Node(ref,
                    ArtifactProvenance.unknown(dependency.coordinate(),
                            ArtifactProvenance.Role.DEPENDENCY),
                    DependencyGraph.Source.POM_DERIVED,
                    DependencyGraph.Deployment.DECLARED_ENVIRONMENT, dependency.groupId(),
                    dependency.artifactId(), dependency.version(), extension(dependency.type()),
                    dependency.classifier(), "maven:declared", "", "DEPENDENCY_VERSION_MISSING",
                    "version-not-concrete", -1, dependency.scope(), dependency.optional(),
                    DependencyGraph.Resolution.UNRESOLVED, "missing-version"));
            edges.add(new DependencyGraph.Edge(rootRef, ref, "pom-declared",
                    "scope=" + dependency.scope() + ";optional=" + dependency.optional()
                            + ";unresolved-version"));
        }
        for (ConflictLink conflict : conflicts) {
            String winnerRef = selectedRefs.get(conflict.winnerCoordinate());
            if (winnerRef != null && !winnerRef.equals(conflict.ref())) {
                edges.add(new DependencyGraph.Edge(conflict.ref(), winnerRef, "conflict",
                        "winner=" + conflict.winnerCoordinate()));
            }
        }
        if (nodes.isEmpty()) {
            throw new IllegalStateException("Maven dependency graph has no root");
        }
        return new DependencyGraph(nodes, edges, Map.of());
    }

    private static void project(DependencyNode node, String parentRef, int depth,
                                List<DependencyGraph.Node> nodes, List<DependencyGraph.Edge> edges,
                                Map<String, String> selectedRefs, Map<String, String> conflictRefs,
                                Map<DependencyNode, String> identityRefs,
                                List<ConflictLink> conflicts) {
        if (node == null) {
            throw new IllegalStateException("Maven dependency graph contains a null node");
        }
        Artifact artifact = Objects.requireNonNull(node.getArtifact(),
                "Maven dependency graph node artifact");
        String coordinate = coordinate(artifact);
        List<? extends Artifact> relocations = Objects.requireNonNull(node.getRelocations(),
                "Maven dependency graph relocation list");
        Object winnerValue = node.getData().get(ConflictResolver.NODE_DATA_WINNER);
        if (winnerValue != null && !(winnerValue instanceof DependencyNode)) {
            throw new IllegalStateException("Maven conflict winner has an invalid type");
        }
        DependencyNode winnerNode = (DependencyNode) winnerValue;
        String winnerCoordinate = winnerNode == null ? "" : coordinate(
                Objects.requireNonNull(winnerNode.getArtifact(), "Maven conflict winner artifact"));
        boolean conflict = winnerNode != null;
        String ref = conflict
                ? "mvn:" + coordinate + "|conflict:" + digest(winnerCoordinate)
                : "mvn:" + coordinate;
        identityRefs.put(node, ref);
        String existing = conflict ? conflictRefs.putIfAbsent(coordinate, ref)
                : selectedRefs.putIfAbsent(coordinate, ref);
        if (existing == null) {
            org.eclipse.aether.graph.Dependency dependency = node.getDependency();
            String scope = dependency == null ? "compile" : dependency.getScope();
            if (scope == null || scope.isBlank()) {
                throw new IllegalStateException("Maven dependency graph node has no scope");
            }
            boolean optional = dependency != null && dependency.isOptional();
            String managedVersion = DependencyManagerUtils.getPremanagedVersion(node);
            String relocation = relocationReason(relocations);
            String reason = conflict ? "winner=" + winnerCoordinate
                    : managedVersion == null ? "nearest-version" : "managed-version=" + managedVersion;
            if (!relocation.isBlank()) {
                reason += ';' + relocation;
            }
            DependencyGraph.Resolution resolution = conflict
                    ? DependencyGraph.Resolution.CONFLICT : DependencyGraph.Resolution.SELECTED;
            String type = artifact.getProperty("maven:type", artifact.getExtension());
            String sourceDetail = "maven:depth=" + depth + ";type=" + type;
            if (!relocation.isBlank()) {
                sourceDetail += ';' + relocation;
            }
            nodes.add(new DependencyGraph.Node(ref,
                    ArtifactProvenance.unknown(coordinate, ArtifactProvenance.Role.DEPENDENCY),
                    DependencyGraph.Source.POM_DERIVED,
                    DependencyGraph.Deployment.DECLARED_ENVIRONMENT, artifact.getGroupId(),
                    artifact.getArtifactId(), artifact.getVersion(), type,
                    artifact.getClassifier(), sourceDetail, "", "", "", -1, scope,
                    optional, resolution, reason));
            if (conflict) {
                conflicts.add(new ConflictLink(ref, winnerCoordinate));
            }
        } else {
            ref = existing;
            identityRefs.put(node, ref);
        }
        if (!parentRef.equals(ref)) {
            org.eclipse.aether.graph.Dependency dependency = node.getDependency();
            String scope = dependency == null ? "compile" : dependency.getScope();
            boolean optional = dependency != null && dependency.isOptional();
            String managedVersion = DependencyManagerUtils.getPremanagedVersion(node);
            StringBuilder reason = new StringBuilder("scope=").append(scope)
                    .append(";optional=").append(optional);
            if (managedVersion != null) {
                reason.append(";managed-version=").append(managedVersion);
            }
            edges.add(new DependencyGraph.Edge(parentRef, ref,
                    depth == 1 ? "pom-declared" : "pom-transitive", reason.toString()));
        }
        for (DependencyNode child : node.getChildren()) {
            project(child, ref, depth + 1, nodes, edges, selectedRefs, conflictRefs,
                    identityRefs, conflicts);
        }
    }

    private static EffectivePom effectivePom(Model effective, Model raw,
                                              ModelBuildingResult result, List<Problem> problems) {
        List<String> declared = raw.getProfiles().stream().map(Profile::getId)
                .filter(Objects::nonNull).filter(id -> !id.isBlank()).distinct().toList();
        List<String> active = activeProfiles(result);
        List<String> inactive = declared.stream().filter(id -> !active.contains(id)).toList();
        for (String profile : inactive) {
            problems.add(new Problem("PROFILE_NOT_ACTIVATED", effective.getId(), Severity.WARNING,
                    "profile-not-selected:" + profile));
        }
        DependencyManagement management = effective.getDependencyManagement();
        List<DeclaredDependency> declaredDependencies = declaredDependencies(effective.getDependencies());
        List<DeclaredDependency> dependencyManagement = declaredDependencies(
                management == null ? List.of() : management.getDependencies());
        return new EffectivePom(effective.getGroupId(), effective.getArtifactId(),
                effective.getVersion(), effective.getPackaging(),
                applyManagedVersions(declaredDependencies, dependencyManagement),
                dependencyManagement,
                declared, active, inactive);
    }

    private static List<DeclaredDependency> applyManagedVersions(
            List<DeclaredDependency> dependencies, List<DeclaredDependency> management) {
        if (dependencies.isEmpty() || management.isEmpty()) {
            return dependencies;
        }
        List<DeclaredDependency> result = new ArrayList<>();
        for (DeclaredDependency dependency : dependencies) {
            if (dependency.hasConcreteVersion()) {
                result.add(dependency);
                continue;
            }
            DeclaredDependency managed = management.stream()
                    .filter(candidate -> candidate.groupId().equals(dependency.groupId())
                            && candidate.artifactId().equals(dependency.artifactId())
                            && candidate.type().equals(dependency.type())
                            && candidate.classifier().equals(dependency.classifier())
                            && candidate.hasConcreteVersion())
                    .findFirst().orElse(null);
            if (managed == null) {
                result.add(dependency);
            } else {
                result.add(new DeclaredDependency(dependency.groupId(), dependency.artifactId(),
                        managed.version(), dependency.type(), dependency.classifier(),
                        dependency.scope(), dependency.optional(), dependency.exclusions()));
            }
        }
        return List.copyOf(result);
    }

    private static List<String> activeProfiles(ModelBuildingResult result) {
        if (result == null || result.getModelIds().isEmpty()) {
            return List.of();
        }
        List<Profile> active = result.getActivePomProfiles(result.getModelIds().get(0));
        if (active == null || active.isEmpty()) {
            return List.of();
        }
        return active.stream()
                .map(Profile::getId).filter(Objects::nonNull).filter(id -> !id.isBlank())
                .distinct().toList();
    }

    /**
     * Supply only the JVM/platform properties that Maven profile activation defines as
     * system context.  Passing an empty set makes Maven's built-in JDK-activated profiles
     * fail with "Failed to determine Java version"; passing the whole process property bag
     * would make resolution depend on user-specific paths and credentials.  The scanner is
     * hosted by the fixed JDK17 process, while --jdk-home remains a target-bytecode input.
     */
    private static Properties modelSystemProperties() {
        Properties result = new Properties();
        copySystemProperty(result, "java.version");
        copySystemProperty(result, "java.specification.version");
        copySystemProperty(result, "java.vendor");
        copySystemProperty(result, "java.vendor.version");
        copySystemProperty(result, "java.vm.name");
        copySystemProperty(result, "java.vm.vendor");
        copySystemProperty(result, "os.name");
        copySystemProperty(result, "os.arch");
        copySystemProperty(result, "os.version");
        copySystemProperty(result, "file.separator");
        copySystemProperty(result, "path.separator");
        copySystemProperty(result, "line.separator");
        return result;
    }

    private static void copySystemProperty(Properties target, String name) {
        String value = System.getProperty(name);
        if (value != null) {
            target.setProperty(name, value);
        }
    }

    private static List<DeclaredDependency> declaredDependencies(
            List<org.apache.maven.model.Dependency> dependencies) {
        if (dependencies == null || dependencies.isEmpty()) {
            return List.of();
        }
        List<DeclaredDependency> result = new ArrayList<>();
        for (org.apache.maven.model.Dependency dependency : dependencies) {
            List<io.just.sast.dependency.MavenDependencyGraphResolver.Exclusion> exclusions =
                    dependency.getExclusions() == null ? List.of()
                            : dependency.getExclusions().stream()
                            .map(value -> new io.just.sast.dependency.MavenDependencyGraphResolver.Exclusion(
                                    value.getGroupId(), value.getArtifactId())).toList();
            result.add(new DeclaredDependency(dependency.getGroupId(), dependency.getArtifactId(),
                    dependency.getVersion(), dependency.getType(), dependency.getClassifier(),
                    dependency.getScope(), dependency.isOptional(), exclusions));
        }
        return List.copyOf(result);
    }

    private static EffectivePom unresolvedPom(Model raw, ModelBuildingResult result) throws IOException {
        Coordinates coordinates = coordinates(raw);
        List<DeclaredDependency> dependencies = declaredDependencies(raw.getDependencies());
        return new EffectivePom(coordinates.groupId(), coordinates.artifactId(),
                coordinates.version(), raw.getPackaging(), dependencies, List.of(),
                raw.getProfiles().stream().map(Profile::getId).filter(Objects::nonNull)
                        .filter(id -> !id.isBlank()).distinct().toList(), activeProfiles(result), List.of());
    }

    private static List<Problem> modelProblems(List<ModelProblem> values, Coordinates coordinates) {
        if (values == null || values.isEmpty()) {
            return List.of();
        }
        List<Problem> result = new ArrayList<>();
        for (ModelProblem value : values) {
            String message = value.getMessage() == null ? "" : value.getMessage().toLowerCase();
            String code = message.contains("unresolvable") || message.contains("parent")
                    ? "PARENT_OR_BOM_UNRESOLVED"
                    : message.contains("version") && message.contains("missing")
                    ? "DEPENDENCY_VERSION_MISSING" : "POM_MODEL_PROBLEM";
            Severity severity = value.getSeverity() == ModelProblem.Severity.WARNING
                    ? Severity.WARNING : Severity.ERROR;
            String detail = value.getMessage();
            if (detail == null || detail.isBlank()) {
                detail = value.getException() == null ? "model-problem"
                        : value.getException().getClass().getSimpleName();
            }
            result.add(new Problem(code, coordinates.value(), severity,
                    detail));
        }
        return result;
    }

    private static Status status(Model effective, List<DeclaredDependency> unresolved,
                                 List<Problem> problems) {
        if (effective == null || !unresolved.isEmpty()
                || problems.stream().anyMatch(problem -> problem.severity() == Severity.ERROR)) {
            return Status.UNRESOLVED;
        }
        return problems.isEmpty() ? Status.COMPLETE : Status.PARTIAL;
    }

    private static List<RepositorySpec> usableRepositories(Request request) {
        if (!request.offline()) {
            return request.repositories();
        }
        return request.repositories().stream()
                .filter(repository -> repository.uri().getScheme().equalsIgnoreCase("file"))
                .toList();
    }

    private DefaultRepositorySystemSession newSession(Request request,
                                                       List<RepositorySpec> usableRepositories) {
        return newSession(request, usableRepositories, Cancellation.none(), null);
    }

    private DefaultRepositorySystemSession newSession(Request request,
                                                       List<RepositorySpec> usableRepositories,
                                                       Cancellation cancellation,
                                                       TransferStats transferStats) {
        Objects.requireNonNull(cancellation, "cancellation");
        DefaultRepositorySystemSession session = MavenRepositorySystemUtils.newSession();
        boolean networkRepositoryPresent = usableRepositories.stream()
                .anyMatch(repository -> !repository.uri().getScheme().equalsIgnoreCase("file"));
        // Resolver's offline flag rejects even explicit file transports. Offline requests only
        // retain file repositories above, so disabling the Resolver flag here cannot enable a
        // network transport: no HTTP repository is present in the session.
        session.setOffline(request.offline() && networkRepositoryPresent);
        session.setIgnoreArtifactDescriptorRepositories(true);
        session.setLocalRepositoryManager(repositorySystem.newLocalRepositoryManager(session,
                new LocalRepository(request.localRepository().toFile())));
        session.setConfigProperty(ConflictResolver.CONFIG_PROP_VERBOSE, Boolean.TRUE);
        session.setDependencySelector(new AndDependencySelector(
                new OptionalDependencySelector(), new ExclusionDependencySelector()));
        if (transferStats != null) {
            session.setTransferListener(transferStats);
        }
        return session;
    }

    private static List<RemoteRepository> remoteRepositories(List<RepositorySpec> specifications)
            throws IOException {
        List<RemoteRepository> result = new ArrayList<>();
        for (RepositorySpec specification : specifications) {
            if (specification.uri().getScheme().equalsIgnoreCase("file")) {
                Path root = Path.of(specification.uri());
                if (Files.isSymbolicLink(root) || !Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS)) {
                    throw new IOException("repository is not a real directory: " + specification.id());
                }
            }
            result.add(new RemoteRepository.Builder(specification.id(), "default",
                    specification.uri().toString()).build());
        }
        return List.copyOf(result);
    }

    private static void validateRequest(Request request) throws IOException {
        ArchiveLimits.checkPathAncestors(request.pomFile(), io.just.sast.run.InputBudget.defaults());
        if (!Files.isRegularFile(request.pomFile(), LinkOption.NOFOLLOW_LINKS)
                || Files.isSymbolicLink(request.pomFile())) {
            throw new IOException("POM is not a regular non-link file: " + request.pomFile());
        }
        ArchiveLimits.checkContainerSize(request.pomFile(), io.just.sast.run.InputBudget.defaults());
        ArchiveLimits.checkPathAncestors(request.localRepository(),
                io.just.sast.run.InputBudget.defaults());
        if (Files.exists(request.localRepository(), LinkOption.NOFOLLOW_LINKS)
                && (Files.isSymbolicLink(request.localRepository())
                || !Files.isDirectory(request.localRepository(), LinkOption.NOFOLLOW_LINKS))) {
            throw new IOException("local repository is not a real directory: "
                    + request.localRepository());
        }
    }

    private static Coordinates coordinates(Model model) throws IOException {
        String group = value(model.getGroupId(), "");
        String version = value(model.getVersion(), "");
        if (group.isBlank() && model.getParent() != null) {
            group = value(model.getParent().getGroupId(), "");
        }
        if (version.isBlank() && model.getParent() != null) {
            version = value(model.getParent().getVersion(), "");
        }
        String artifact = value(model.getArtifactId(), "");
        if (artifact.isBlank()) {
            throw new IOException("POM artifactId is required");
        }
        return new Coordinates(value(group, "UNRESOLVED"), artifact,
                value(version, "UNRESOLVED"));
    }

    private static String coordinate(Artifact artifact) {
        String classifier = artifact.getClassifier() == null ? "" : artifact.getClassifier();
        return artifact.getGroupId() + ':' + artifact.getArtifactId() + ':' + artifact.getVersion()
                + ':' + artifact.getExtension() + ':' + classifier;
    }

    private static String extension(String type) {
        return switch (value(type, "jar")) {
            case "test-jar", "maven-plugin", "ejb", "ejb-client" -> "jar";
            case "java-source", "javadoc" -> "jar";
            default -> value(type, "jar");
        };
    }

    private static String problemCode(Exception exception) {
        if (exception instanceof TransferCancelledException) {
            return "DEPENDENCY_DOWNLOAD_CANCELLED";
        }
        if (exception instanceof ArtifactNotFoundException) {
            return "DEPENDENCY_ARTIFACT_MISSING";
        }
        if (exception instanceof ArtifactDescriptorException) {
            return "DEPENDENCY_POM_MISSING";
        }
        if (exception instanceof ArtifactResolutionException) {
            return "DEPENDENCY_ARTIFACT_UNRESOLVED";
        }
        return "DEPENDENCY_RESOLUTION_FAILED";
    }

    private static void addArtifactFailure(List<Problem> problems, String coordinate,
                                           ArtifactResolutionException failure,
                                           String transferDetail, boolean offline) {
        String prefix = offline ? "offline-cache-miss;" : "";
        boolean added = false;
        for (ArtifactResult result : failure.getResults()) {
            for (Exception exception : result.getExceptions()) {
                problems.add(new Problem(problemCode(exception), coordinate, Severity.ERROR,
                        appendDetail(prefix + detail(exception), transferDetail)));
                added = true;
            }
        }
        if (!added) {
            problems.add(new Problem(problemCode(failure), coordinate, Severity.ERROR,
                    appendDetail(prefix + detail(failure), transferDetail)));
        }
    }

    private static String appendDetail(String detail, String suffix) {
        return suffix == null || suffix.isBlank() ? detail : detail + ";transfer=" + suffix;
    }

    private static String artifactFileName(Artifact artifact) {
        String classifier = artifact.getClassifier() == null ? "" : artifact.getClassifier();
        return artifact.getArtifactId() + '-' + artifact.getVersion()
                + (classifier.isBlank() ? "" : '-' + classifier) + '.' + artifact.getExtension();
    }

    private static String detail(Throwable failure) {
        Objects.requireNonNull(failure, "failure");
        StringBuilder result = new StringBuilder();
        Set<Throwable> seen = Collections.newSetFromMap(new IdentityHashMap<>());
        Throwable current = failure;
        int depth = 0;
        while (current != null && depth++ < 8 && seen.add(current)) {
            if (result.length() > 0) {
                result.append(" <- ");
            }
            result.append(current.getClass().getSimpleName());
            String message = current.getMessage();
            if (message != null && !message.isBlank()) {
                result.append(':').append(message.replace('\r', ' ').replace('\n', ' '));
            }
            current = current.getCause();
        }
        return result.toString();
    }

    private static void checkCancelled(Cancellation cancellation) throws IOException {
        if (isCancelled(cancellation)) {
            throw new IOException("DEPENDENCY_DOWNLOAD_CANCELLED");
        }
    }

    private static boolean isCancelled(Cancellation cancellation) {
        return Thread.currentThread().isInterrupted() || cancellation.isCancelled();
    }

    private static Path absolutePath(Path path, String field) {
        if (path == null) {
            throw new IllegalArgumentException(field + " is required");
        }
        return path.toAbsolutePath().normalize();
    }

    private static String digestText(String value) {
        if (value == null || !value.matches("[0-9a-fA-F]{64}")) {
            throw new IllegalArgumentException("artifact sha256 must be a 64-character digest");
        }
        return value.toLowerCase(Locale.ROOT);
    }

    /**
     * Overlap-aware timing owner for network transfers.  Request duration is additive per
     * transfer, while wall time is the union of active intervals; this keeps parallel downloads
     * from being charged twice to the network wall-clock metric.
     */
    static final class NetworkTiming {
        private final Map<String, ActiveTransfer> active = new LinkedHashMap<>();
        private final Map<String, Long> lastTransferred = new LinkedHashMap<>();
        private long networkStartedNanos = -1L;
        private long networkWallNanos;
        private long requestNanos;
        private long transferredBytes;

        synchronized void begin(String key) {
            Objects.requireNonNull(key, "transfer key");
            if (active.containsKey(key)) {
                return;
            }
            if (active.isEmpty()) {
                networkStartedNanos = System.nanoTime();
            }
            active.put(key, new ActiveTransfer(System.nanoTime()));
            lastTransferred.put(key, 0L);
        }

        synchronized void record(String key, long cumulativeBytes, long dataLength) {
            Objects.requireNonNull(key, "transfer key");
            if (!active.containsKey(key)) {
                begin(key);
            }
            long previous = lastTransferred.getOrDefault(key, 0L);
            long delta = cumulativeBytes > previous ? cumulativeBytes - previous : dataLength;
            if (delta > 0L) {
                transferredBytes += delta;
            }
            if (cumulativeBytes >= previous) {
                lastTransferred.put(key, cumulativeBytes);
            }
        }

        synchronized void finish(String key, long cumulativeBytes, long dataLength) {
            Objects.requireNonNull(key, "transfer key");
            if (!active.containsKey(key)) {
                return;
            }
            record(key, cumulativeBytes, dataLength);
            ActiveTransfer transfer = active.remove(key);
            lastTransferred.remove(key);
            requestNanos += Math.max(0L, System.nanoTime() - transfer.startedNanos());
            if (active.isEmpty() && networkStartedNanos >= 0L) {
                networkWallNanos += Math.max(0L, System.nanoTime() - networkStartedNanos);
                networkStartedNanos = -1L;
            }
        }

        synchronized Snapshot snapshot() {
            long wall = networkWallNanos;
            if (!active.isEmpty() && networkStartedNanos >= 0L) {
                wall += Math.max(0L, System.nanoTime() - networkStartedNanos);
            }
            return new Snapshot(toMillis(wall), toMillis(requestNanos), transferredBytes);
        }

        private static long toMillis(long nanos) {
            return Math.max(0L, nanos / 1_000_000L);
        }

        private record ActiveTransfer(long startedNanos) {
        }

        record Snapshot(long networkWallMs, long requestMs, long transferredBytes) {
        }
    }

    private static final class TransferStats implements TransferListener {
        private final Cancellation cancellation;
        private final Map<String, String> failures = new LinkedHashMap<>();
        private final NetworkTiming timing = new NetworkTiming();

        private TransferStats(Cancellation cancellation) {
            this.cancellation = Objects.requireNonNull(cancellation, "cancellation");
        }

        @Override
        public synchronized void transferInitiated(TransferEvent event)
                throws TransferCancelledException {
            check(event);
            begin(event);
        }

        @Override
        public synchronized void transferStarted(TransferEvent event)
                throws TransferCancelledException {
            check(event);
            begin(event);
        }

        @Override
        public synchronized void transferProgressed(TransferEvent event)
                throws TransferCancelledException {
            check(event);
            begin(event);
            record(event);
        }

        @Override
        public synchronized void transferCorrupted(TransferEvent event)
                throws TransferCancelledException {
            check(event);
            recordFailure(event);
            finish(event);
        }

        @Override
        public synchronized void transferSucceeded(TransferEvent event) {
            finish(event);
        }

        @Override
        public synchronized void transferFailed(TransferEvent event) {
            recordFailure(event);
            finish(event);
        }

        private synchronized String failureDetail(String fileName) {
            for (Map.Entry<String, String> failure : failures.entrySet()) {
                if (failure.getKey().contains(fileName)) {
                    return failure.getValue();
                }
            }
            return "";
        }

        private void recordFailure(TransferEvent event) {
            if (!network(event) || event.getException() == null) {
                return;
            }
            String failure = detail(event.getException());
            if (event.getException() instanceof ArtifactNotFoundException) {
                failure = "http-status=404;" + failure;
            }
            failures.put(key(event), failure);
        }

        private void check(TransferEvent event) throws TransferCancelledException {
            Objects.requireNonNull(event, "transfer event");
            if (isCancelled(cancellation)) {
                throw new TransferCancelledException("DEPENDENCY_DOWNLOAD_CANCELLED");
            }
        }

        private void begin(TransferEvent event) {
            if (!network(event)) {
                return;
            }
            timing.begin(key(event));
        }

        private void record(TransferEvent event) {
            if (!network(event)) {
                return;
            }
            String key = key(event);
            timing.record(key, event.getTransferredBytes(), event.getDataLength());
        }

        private void finish(TransferEvent event) {
            if (!network(event)) {
                return;
            }
            String key = key(event);
            timing.finish(key, event.getTransferredBytes(), event.getDataLength());
        }

        private static boolean network(TransferEvent event) {
            if (event.getRequestType() == TransferEvent.RequestType.PUT
                    || event.getResource() == null) {
                return false;
            }
            String url = event.getResource().getRepositoryUrl();
            return url != null && (url.toLowerCase(Locale.ROOT).startsWith("http://")
                    || url.toLowerCase(Locale.ROOT).startsWith("https://"));
        }

        private static String key(TransferEvent event) {
            TransferResource resource = Objects.requireNonNull(event.getResource(),
                    "transfer resource");
            String file = resource.getFile() == null ? "" : resource.getFile().toPath()
                    .toAbsolutePath().normalize().toString();
            return resource.getRepositoryId() + '|' + resource.getResourceName() + '|' + file;
        }

        private NetworkTiming.Snapshot snapshot() {
            return timing.snapshot();
        }
    }

    private static String digest(String value) {
        try {
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            return java.util.HexFormat.of().formatHex(digest.digest(value.getBytes(
                    java.nio.charset.StandardCharsets.UTF_8)));
        } catch (java.security.NoSuchAlgorithmException impossible) {
            throw new AssertionError(impossible);
        }
    }

    private static long elapsedMs(long startedNanos) {
        return Math.max(0L, (System.nanoTime() - startedNanos) / 1_000_000L);
    }

    private static String text(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " is required");
        }
        return value.trim();
    }

    private static String value(String value, String absent) {
        return value == null || value.isBlank() ? absent : value.trim();
    }

    @Override
    public void close() {
        repositorySystem.shutdown();
    }

    private record Coordinates(String groupId, String artifactId, String version) {
        String value() {
            return groupId + ':' + artifactId + ':' + version;
        }
    }

    private record ConflictLink(String ref, String winnerCoordinate) {
    }

    private static final class RepositoryModelResolver implements ModelResolver {
        private final RepositorySystem system;
        private final DefaultRepositorySystemSession session;
        private final List<RemoteRepository> repositories;
        private final List<String> ignoredRepositories;

        private RepositoryModelResolver(RepositorySystem system, DefaultRepositorySystemSession session,
                                        List<RemoteRepository> repositories,
                                        List<String> ignoredRepositories) {
            this.system = system;
            this.session = session;
            this.repositories = repositories;
            this.ignoredRepositories = ignoredRepositories;
        }

        @Override
        public org.apache.maven.model.building.ModelSource resolveModel(String groupId,
                                                                          String artifactId,
                                                                          String version)
                throws UnresolvableModelException {
            if (groupId == null || groupId.isBlank() || artifactId == null || artifactId.isBlank()
                    || version == null || version.isBlank() || version.contains("${")) {
                throw new UnresolvableModelException(groupId, artifactId, version,
                        "coordinates are not concrete");
            }
            Artifact artifact = new DefaultArtifact(groupId, artifactId, "", "pom", version);
            ArtifactRequest request = new ArtifactRequest(artifact, repositories, "just-model");
            try {
                ArtifactResult result = system.resolveArtifact(session, request);
                if (!result.isResolved() || result.getArtifact() == null
                        || result.getArtifact().getFile() == null) {
                    throw new UnresolvableModelException(groupId, artifactId, version,
                            "POM artifact was not resolved");
                }
                Path pom = result.getArtifact().getFile().toPath().toAbsolutePath().normalize();
                try {
                    validateArtifact(pom, "pom");
                } catch (IOException | RuntimeException invalid) {
                    String cleanup = invalidateExact(pom, localRepository(session));
                    String message = detail(invalid);
                    if (!cleanup.isBlank()) {
                        message += ";cleanup=" + cleanup;
                    }
                    throw new UnresolvableModelException(groupId, artifactId, version,
                            "POM artifact is invalid: " + message, invalid);
                }
                return new FileModelSource(pom.toFile());
            } catch (ArtifactResolutionException failure) {
                throw new UnresolvableModelException(failure, groupId, artifactId, version);
            }
        }

        @Override
        public org.apache.maven.model.building.ModelSource resolveModel(
                org.apache.maven.model.Parent parent) throws UnresolvableModelException {
            Objects.requireNonNull(parent, "parent");
            return resolveModel(parent.getGroupId(), parent.getArtifactId(), parent.getVersion());
        }

        @Override
        public org.apache.maven.model.building.ModelSource resolveModel(
                org.apache.maven.model.Dependency dependency) throws UnresolvableModelException {
            Objects.requireNonNull(dependency, "dependency");
            return resolveModel(dependency.getGroupId(), dependency.getArtifactId(),
                    dependency.getVersion());
        }

        @Override
        public void addRepository(Repository repository) throws InvalidRepositoryException {
            if (repository != null && repository.getId() != null && !repository.getId().isBlank()
                    && !isAuthorized(repository) && !isImplicitCentral(repository)) {
                ignoredRepositories.add(repository.getId());
            }
        }

        private boolean isAuthorized(Repository repository) {
            return repositories.stream().anyMatch(value -> value.getId().equals(repository.getId())
                    && value.getUrl().equals(repository.getUrl()));
        }

        private static boolean isImplicitCentral(Repository repository) {
            return CENTRAL_REPOSITORY_ID.equals(repository.getId())
                    && CENTRAL_REPOSITORY_URL.equals(repository.getUrl());
        }

        @Override
        public void addRepository(Repository repository, boolean replace)
                throws InvalidRepositoryException {
            addRepository(repository);
        }

        @Override
        public ModelResolver newCopy() {
            return new RepositoryModelResolver(system, session, repositories, ignoredRepositories);
        }

        private static Path localRepository(DefaultRepositorySystemSession session) {
            return session.getLocalRepositoryManager().getRepository().getBasedir()
                    .toPath().toAbsolutePath().normalize();
        }
    }
}
