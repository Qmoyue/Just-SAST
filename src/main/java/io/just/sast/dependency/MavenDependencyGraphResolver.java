package io.just.sast.dependency;

import io.just.sast.model.ArtifactProvenance;
import io.just.sast.model.DependencyGraph;
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
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;
import java.util.Set;

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
            if (!scheme.equals("file") && !scheme.equals("https")) {
                throw new IllegalArgumentException(
                        "repository URI must use file or https: " + scheme);
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
        Objects.requireNonNull(request, "request");
        validateRequest(request);
        Files.createDirectories(request.localRepository());

        List<RepositorySpec> usableRepositorySpecs = usableRepositories(request);
        List<RemoteRepository> repositories = remoteRepositories(usableRepositorySpecs);
        DefaultRepositorySystemSession session = newSession(request, usableRepositorySpecs);
        List<Problem> problems = new ArrayList<>();
        List<String> ignoredPomRepositories = new ArrayList<>();

        Model raw = new DefaultModelReader().read(request.pomFile().toFile(), Map.of());
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
            modelRequest.setSystemProperties(new Properties());
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
            CollectResult collected = collect(session, repositories, effectivePom, problems);
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
        List<Problem> immutableProblems = problems.stream().distinct().toList();
        Status status = status(effective, unresolved, immutableProblems);
        return new Resolution(effectivePom, graph, immutableProblems, status, request.offline(),
                request.repositories().stream().map(RepositorySpec::id).toList());
    }

    private CollectResult collect(DefaultRepositorySystemSession session,
                                  List<RemoteRepository> repositories, EffectivePom pom,
                                  List<Problem> problems) throws IOException {
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
            return repositorySystem.collectDependencies(session, request);
        } catch (DependencyCollectionException failure) {
            CollectResult partial = failure.getResult();
            if (partial == null) {
                throw new IOException("Maven dependency collection returned no result", failure);
            }
            List<Exception> exceptions = partial.getExceptions();
            if (exceptions.isEmpty()) {
                problems.add(new Problem("DEPENDENCY_RESOLUTION_FAILED", pom.coordinate(),
                        Severity.ERROR, failure.getClass().getSimpleName()));
            } else {
                for (Exception exception : exceptions) {
                    problems.add(new Problem(problemCode(exception), pom.coordinate(),
                            Severity.ERROR, exception.getClass().getSimpleName()));
                }
            }
            return partial;
        }
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
            String reason = conflict ? "winner=" + winnerCoordinate
                    : managedVersion == null ? "nearest-version" : "managed-version=" + managedVersion;
            DependencyGraph.Resolution resolution = conflict
                    ? DependencyGraph.Resolution.CONFLICT : DependencyGraph.Resolution.SELECTED;
            String type = artifact.getProperty("maven:type", artifact.getExtension());
            nodes.add(new DependencyGraph.Node(ref,
                    ArtifactProvenance.unknown(coordinate, ArtifactProvenance.Role.DEPENDENCY),
                    DependencyGraph.Source.POM_DERIVED,
                    DependencyGraph.Deployment.DECLARED_ENVIRONMENT, artifact.getGroupId(),
                    artifact.getArtifactId(), artifact.getVersion(), type,
                    artifact.getClassifier(), "maven:depth=" + depth + ";type=" + type, "", "", "", -1, scope,
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
                || problems.stream().anyMatch(problem -> problem.severity() == Severity.ERROR
                        && (problem.code().contains("UNRESOLVED")
                        || problem.code().contains("MISSING")
                        || problem.code().contains("FAILED")
                        || problem.code().contains("PROBLEM")))) {
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
        if (!Files.isRegularFile(request.pomFile(), LinkOption.NOFOLLOW_LINKS)
                || Files.isSymbolicLink(request.pomFile())) {
            throw new IOException("POM is not a regular non-link file: " + request.pomFile());
        }
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

    private static String digest(String value) {
        try {
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            return java.util.HexFormat.of().formatHex(digest.digest(value.getBytes(
                    java.nio.charset.StandardCharsets.UTF_8)));
        } catch (java.security.NoSuchAlgorithmException impossible) {
            throw new AssertionError(impossible);
        }
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
                return new FileModelSource(result.getArtifact().getFile());
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
    }
}
