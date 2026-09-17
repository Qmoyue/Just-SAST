package io.just.sast.model;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.TreeSet;

/**
 * Immutable frontend product consumed by CPG and knowledge phases.
 *
 * <p>ASM types and raw class bytes must not cross this boundary.  The class map preserves the
 * frontend's deterministic insertion order for compatibility, while semantic identity and
 * lookups are sorted by versioned {@link TypeId}/{@link MethodId} values.</p>
 */
public final class ProgramUniverse {
    public static final int MODEL_VERSION = 1;

    private final Map<String, ClassInfo> classes;
    private final Map<String, ArtifactProvenance> classArtifacts;
    private final Map<String, List<ArchiveMemberProvenance>> classProvenance;
    private final List<ArchiveMemberProvenance> archiveMembers;
    private final List<ArtifactProvenance> artifacts;
    private final DependencyGraph dependencyGraph;
    private final List<ParseDiagnostic> diagnostics;
    private final List<String> completenessReasons;
    private final int filesScanned;
    private final int targetMajorVersion;
    private final String semanticDigest;

    private ProgramUniverse(Map<String, ClassInfo> classes,
                            Map<String, ArtifactProvenance> classArtifacts,
                            Map<String, List<ArchiveMemberProvenance>> classProvenance,
                            List<ArchiveMemberProvenance> archiveMembers,
                            List<ArtifactProvenance> artifacts,
                            DependencyGraph dependencyGraph,
                            List<ParseDiagnostic> diagnostics,
                            List<String> completenessReasons,
                            int filesScanned,
                            int targetMajorVersion) {
        if (filesScanned < 0) {
            throw new IllegalArgumentException("filesScanned must be non-negative");
        }
        if (targetMajorVersion < 0) {
            throw new IllegalArgumentException("targetMajorVersion must be non-negative");
        }
        LinkedHashMap<String, ClassInfo> classCopy = new LinkedHashMap<>();
        if (classes != null) {
            for (Map.Entry<String, ClassInfo> entry : classes.entrySet()) {
                String key = Objects.requireNonNull(entry.getKey(), "class key");
                ClassInfo value = Objects.requireNonNull(entry.getValue(), "class info");
                if (!key.equals(value.internalName())) {
                    throw new IllegalArgumentException("class key does not match internal name: " + key);
                }
                classCopy.put(key, immutableClass(value));
            }
        }
        this.classes = Collections.unmodifiableMap(classCopy);
        LinkedHashMap<String, ArtifactProvenance> artifactCopy = new LinkedHashMap<>();
        if (classArtifacts != null) {
            for (Map.Entry<String, ArtifactProvenance> entry : classArtifacts.entrySet()) {
                if (classCopy.containsKey(entry.getKey()) && entry.getValue() != null) {
                    artifactCopy.put(entry.getKey(), entry.getValue());
                }
            }
        }
        this.classArtifacts = Collections.unmodifiableMap(artifactCopy);
        LinkedHashMap<String, List<ArchiveMemberProvenance>> classProvenanceCopy =
                new LinkedHashMap<>();
        if (classProvenance != null) {
            for (Map.Entry<String, List<ArchiveMemberProvenance>> entry : classProvenance.entrySet()) {
                if (classCopy.containsKey(entry.getKey()) && entry.getValue() != null
                        && entry.getValue().stream().noneMatch(Objects::isNull)) {
                    classProvenanceCopy.put(entry.getKey(), List.copyOf(entry.getValue()));
                }
            }
        }
        this.classProvenance = Collections.unmodifiableMap(classProvenanceCopy);
        if (archiveMembers == null || archiveMembers.stream().anyMatch(Objects::isNull)) {
            throw new IllegalArgumentException("archive members are invalid");
        }
        this.archiveMembers = List.copyOf(archiveMembers);
        this.artifacts = immutableDistinctArtifacts(artifacts);
        this.dependencyGraph = Objects.requireNonNull(dependencyGraph, "dependency graph");
        this.diagnostics = diagnostics == null ? List.of() : List.copyOf(diagnostics);
        this.completenessReasons = completenessReasons == null ? List.of() : List.copyOf(completenessReasons);
        this.filesScanned = filesScanned;
        this.targetMajorVersion = targetMajorVersion;
        this.semanticDigest = computeSemanticDigest();
    }

    public static ProgramUniverse from(LoadResult load) {
        Objects.requireNonNull(load, "load");
        return new ProgramUniverse(load.classes(), Map.of(), load.classProvenance(),
                load.archiveMembers(), List.of(), DependencyGraph.empty(),
                load.diagnostics(), load.completenessReasons(), load.filesScanned(),
                load.targetMajorVersion());
    }

    /** Build a universe with explicit artifact metadata without reparsing classes. */
    public static ProgramUniverse of(LoadResult load, List<ArtifactProvenance> artifacts) {
        Objects.requireNonNull(load, "load");
        return new ProgramUniverse(load.classes(), Map.of(), load.classProvenance(),
                load.archiveMembers(), artifacts, DependencyGraph.empty(),
                load.diagnostics(), load.completenessReasons(), load.filesScanned(),
                load.targetMajorVersion());
    }

    /** Build a universe with explicit class-to-artifact ownership. */
    public static ProgramUniverse of(LoadResult load,
                                     Map<String, ArtifactProvenance> classArtifacts,
                                     List<ArtifactProvenance> artifacts) {
        Objects.requireNonNull(load, "load");
        return new ProgramUniverse(load.classes(), classArtifacts, load.classProvenance(),
                load.archiveMembers(), artifacts,
                DependencyGraph.empty(), load.diagnostics(), load.completenessReasons(),
                load.filesScanned(), load.targetMajorVersion());
    }

    /** Build a universe with the single input/dependency graph owned by input preparation. */
    public static ProgramUniverse of(LoadResult load,
                                     Map<String, ArtifactProvenance> classArtifacts,
                                     List<ArtifactProvenance> artifacts,
                                     DependencyGraph dependencyGraph) {
        Objects.requireNonNull(load, "load");
        return new ProgramUniverse(load.classes(), classArtifacts, load.classProvenance(),
                load.archiveMembers(), artifacts, dependencyGraph,
                load.diagnostics(), load.completenessReasons(), load.filesScanned(),
                load.targetMajorVersion());
    }

    public Map<String, ClassInfo> classes() {
        return classes;
    }

    public List<ArtifactProvenance> artifacts() {
        return artifacts;
    }

    public Map<String, ArtifactProvenance> classArtifacts() {
        return classArtifacts;
    }

    /** Member-level provenance for every successfully loaded class with a known source. */
    public Map<String, List<ArchiveMemberProvenance>> classProvenance() {
        return classProvenance;
    }

    /** Class and nested-archive members captured by the closure/frontend boundary. */
    public List<ArchiveMemberProvenance> archiveMembers() {
        return archiveMembers;
    }

    public DependencyGraph dependencyGraph() {
        return dependencyGraph;
    }

    public List<ParseDiagnostic> diagnostics() {
        return diagnostics;
    }

    public List<String> completenessReasons() {
        return completenessReasons;
    }

    public int filesScanned() {
        return filesScanned;
    }

    public int targetMajorVersion() {
        return targetMajorVersion;
    }

    public int classCount() {
        return classes.size();
    }

    public int diagnosticCount() {
        return diagnostics.size();
    }

    public String semanticDigest() {
        return semanticDigest;
    }

    public Optional<ClassInfo> find(TypeId type) {
        return type == null ? Optional.empty() : Optional.ofNullable(classes.get(type.internalName()));
    }

    public Optional<MethodInfo> find(MethodId method) {
        if (method == null) {
            return Optional.empty();
        }
        ClassInfo owner = classes.get(method.owner().internalName());
        return owner == null ? Optional.empty() : Optional.ofNullable(
                owner.method(method.name(), method.descriptor()));
    }

    public Optional<ArtifactProvenance> artifactFor(TypeId type) {
        return type == null ? Optional.empty() : Optional.ofNullable(classArtifacts.get(type.internalName()));
    }

    public List<TypeId> typeIds() {
        return classes.keySet().stream().sorted().map(TypeId::of).toList();
    }

    public List<MethodId> methodIds() {
        return classes.values().stream().flatMap(cls -> cls.methods().stream())
                .map(MethodId::of).sorted().toList();
    }

    /** Preserve LoadResult compatibility at a typed boundary. */
    public LoadResult toLoadResult() {
        return new LoadResult(classes, diagnostics, filesScanned, targetMajorVersion,
                completenessReasons, classProvenance, archiveMembers);
    }

    private static List<ArtifactProvenance> immutableDistinctArtifacts(List<ArtifactProvenance> values) {
        if (values == null || values.isEmpty()) {
            return List.of();
        }
        LinkedHashMap<String, ArtifactProvenance> distinct = new LinkedHashMap<>();
        for (ArtifactProvenance value : values) {
            if (value != null) {
                distinct.putIfAbsent(value.identity(), value);
            }
        }
        return List.copyOf(distinct.values());
    }

    /** Deep-copy the public frontend records so only the universe boundary is immutable. */
    private static ClassInfo immutableClass(ClassInfo source) {
        List<MethodInfo> methods = source.methods() == null ? List.of()
                : source.methods().stream().map(ProgramUniverse::immutableMethod).toList();
        List<FieldInfo> fields = source.fields() == null ? List.of()
                : List.copyOf(source.fields());
        List<String> interfaces = source.interfaces() == null ? List.of()
                : List.copyOf(source.interfaces());
        return new ClassInfo(source.internalName(), source.superName(), interfaces,
                source.access(), methods, fields, source.annotationDescriptors());
    }

    private static MethodInfo immutableMethod(MethodInfo source) {
        Objects.requireNonNull(source, "method info");
        List<InsnFact> instructions = source.instructions() == null ? List.of()
                : source.instructions().stream().map(ProgramUniverse::immutableInsn).toList();
        List<TryCatchFact> tryCatch = source.tryCatch() == null ? List.of()
                : List.copyOf(source.tryCatch());
        return new MethodInfo(source.owner(), source.name(), source.descriptor(), source.access(),
                instructions, tryCatch, source.hasDebugInfo(), source.entryLine(),
                source.annotationDescriptors());
    }

    private static InsnFact immutableInsn(InsnFact source) {
        Objects.requireNonNull(source, "instruction fact");
        List<Object> operands = source.operands() == null ? List.of()
                : Collections.unmodifiableList(new ArrayList<>(source.operands()));
        return new InsnFact(source.offset(), source.op(), operands);
    }

    private String computeSemanticDigest() {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            update(digest, "program-universe-v" + MODEL_VERSION);
            update(digest, "major=" + targetMajorVersion);
            for (String className : new TreeSet<>(classes.keySet())) {
                ClassInfo cls = classes.get(className);
                update(digest, "class=" + TypeId.of(className).canonical());
                update(digest, "super=" + String.valueOf(cls.superName()));
                update(digest, "access=" + cls.access());
                for (String iface : new TreeSet<>(cls.interfaces())) {
                    update(digest, "iface=" + iface);
                }
                for (String annotation : cls.annotationDescriptors()) {
                    update(digest, "annotation=" + annotation);
                }
                cls.fields().stream().sorted(Comparator.comparing(FieldInfo::name)
                                .thenComparing(FieldInfo::descriptor))
                        .forEach(field -> update(digest, "field=" + field.owner() + '#' + field.name()
                                + ':' + field.descriptor() + ':' + field.access() + ':' + String.valueOf(field.signature())));
                cls.methods().stream().map(MethodId::of).sorted()
                        .forEach(method -> update(digest, method.canonical()));
                cls.methods().stream().sorted(Comparator.comparing(MethodInfo::name)
                                .thenComparing(MethodInfo::descriptor))
                        .forEach(method -> {
                            update(digest, "method-access=" + method.access() + ":debug="
                                    + method.hasDebugInfo() + ":line=" + method.entryLine());
                            method.annotationDescriptors().forEach(annotation ->
                                    update(digest, "method-annotation=" + annotation));
                            method.instructions().forEach(insn -> update(digest,
                                    "insn=" + insn.offset() + ':' + insn.op() + ':' + String.valueOf(insn.operands())));
                            method.tryCatch().forEach(tc -> update(digest,
                                    "try=" + tc.start() + ':' + tc.end() + ':' + tc.handler() + ':' + tc.type()));
                        });
            }
            artifacts.stream().map(ArtifactProvenance::identity).sorted()
                    .forEach(value -> update(digest, "artifact=" + value));
            classArtifacts.entrySet().stream()
                    .sorted(Map.Entry.comparingByKey())
                    .forEach(entry -> update(digest, "class-artifact="
                            + TypeId.of(entry.getKey()).canonical() + '=' + entry.getValue().identity()));
            classProvenance.entrySet().stream()
                    .sorted(Map.Entry.comparingByKey())
                    .forEach(entry -> entry.getValue().stream()
                            .map(ArchiveMemberProvenance::identity)
                            .sorted()
                            .forEach(value -> update(digest, "class-provenance="
                                    + TypeId.of(entry.getKey()).canonical() + '=' + value)));
            archiveMembers.stream().map(ArchiveMemberProvenance::identity).sorted()
                    .forEach(value -> update(digest, "archive-member=" + value));
            update(digest, "dependency-graph=" + dependencyGraph.semanticDigest());
            return hex(digest.digest());
        } catch (NoSuchAlgorithmException impossible) {
            throw new AssertionError(impossible);
        }
    }

    private static void update(MessageDigest digest, String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        digest.update(bytes);
        digest.update((byte) '\n');
    }

    private static String hex(byte[] bytes) {
        StringBuilder result = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) {
            result.append(String.format("%02x", value & 0xff));
        }
        return result.toString();
    }
}
