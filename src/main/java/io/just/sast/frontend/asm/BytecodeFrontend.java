package io.just.sast.frontend.asm;

import io.just.sast.model.ClassInfo;
import io.just.sast.model.ApplicationResourceFacts;
import io.just.sast.model.ArchiveMetadata;
import io.just.sast.model.ArchiveMemberProvenance;
import io.just.sast.model.ArtifactProvenance;
import io.just.sast.model.LoadResult;
import io.just.sast.model.ProgramUniverse;
import io.just.sast.model.ParseDiagnostic;
import io.just.sast.util.JustLogger;
import io.just.sast.util.AdaptiveParallelism;
import io.just.sast.run.InputBudget;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 字节码前端：目标 JAR/目录 → 解析为自研 model。
 * 装载顺序：target → deps → JDK——应用类优先，JDK 类只补缺（同名不遮蔽应用类）。
 * 单类解析失败不中断全扫，记录诊断。
 */
public final class BytecodeFrontend {

    /**
     * Closed state for the aggregate input-budget context carried by {@link Inputs}.
     *
     * <p>The distinction is intentionally observable without making callers infer it from a
     * nullable tracker and a compatibility boolean.  A local tracker still permits bounded
     * parsing, but it cannot claim ownership of the scan-wide budget used by the production
     * streaming path.</p>
     */
    public enum CallerContextStatus {
        CALLER_OWNED,
        LOCAL_TRACKER,
        MISSING
    }

    private final JarReader jarReader = new JarReader();
    private final InputBudget inputBudget;
    /** ASM 的输入是只读的；每个 worker 使用自己的 reader，避免共享可变 extractor 状态。 */
    private final ThreadLocal<ClassFileReader> classFileReaders =
            ThreadLocal.withInitial(ClassFileReader::new);

    /** 前端是纯解析阶段，允许使用较高并行度；分析阶段另有独立的并行配额。 */
    private static final int MAX_PARSE_WORKERS = 16;
    private static final int PARALLEL_PARSE_THRESHOLD = 64;
    /** 原始 class bytes 的上界；解析结果本身仍由后续 CPG 阶段持有。 */
    private static final int STREAM_BATCH_SIZE = 64;

    public BytecodeFrontend() {
        this(InputBudget.defaults());
    }

    /** Construct a frontend with one immutable policy for every archive/class parse. */
    public BytecodeFrontend(InputBudget budget) {
        this.inputBudget = budget == null ? InputBudget.defaults() : budget;
    }

    /** 已读取但尚未解析的目标输入；用于 JDK 切片先解析应用，再复用同一批字节。 */
    public record Inputs(List<ClassBytes> classes, List<ParseDiagnostic> diagnostics,
                         List<String> completenessReasons, InputBudget.Tracker tracker,
                         boolean callerContextProvided,
                         Map<String, List<ArchiveMemberProvenance>> classProvenance,
                         List<ArchiveMemberProvenance> archiveMembers) {
        public Inputs {
            classes = classes == null ? List.of() : List.copyOf(classes);
            diagnostics = diagnostics == null ? List.of() : List.copyOf(diagnostics);
            completenessReasons = completenessReasons == null ? List.of() : List.copyOf(completenessReasons);
            // A legacy caller can construct the five-argument record directly.  Never let a
            // null tracker plus a forged flag claim scan-wide accounting; load(Inputs) would
            // otherwise create a fresh local budget while reporting a complete context.
            callerContextProvided = callerContextProvided && tracker != null;
            classProvenance = immutableClassProvenance(classProvenance);
            archiveMembers = immutableArchiveMembers(archiveMembers);
        }

        /** Compatibility constructor for callers that do not own an aggregate input budget. */
        public Inputs(List<ClassBytes> classes, List<ParseDiagnostic> diagnostics,
                      List<String> completenessReasons) {
            this(classes, diagnostics, completenessReasons, null, false, Map.of(), List.of());
        }

        /** Compatibility constructor for callers that explicitly provide the five legacy fields. */
        public Inputs(List<ClassBytes> classes, List<ParseDiagnostic> diagnostics,
                      List<String> completenessReasons, InputBudget.Tracker tracker,
                      boolean callerContextProvided) {
            this(classes, diagnostics, completenessReasons, tracker, callerContextProvided,
                    Map.of(), List.of());
        }

        /**
         * Source-compatible four-argument constructor. A supplied tracker is caller-owned only
         * when the caller explicitly marks that context; the legacy overload remains partial
         * rather than silently claiming scan-wide accounting.
         */
        public Inputs(List<ClassBytes> classes, List<ParseDiagnostic> diagnostics,
                      List<String> completenessReasons, InputBudget.Tracker tracker) {
            this(classes, diagnostics, completenessReasons, tracker, tracker != null,
                    Map.of(), List.of());
        }

        /**
         * Returns the typed caller-context state used by reports and compatibility diagnostics.
         * The result is derived from the normalized record state, so a forged
         * {@code callerContextProvided=true} with a null tracker remains {@link
         * CallerContextStatus#MISSING}.
         */
        public CallerContextStatus callerContextStatus() {
            if (callerContextProvided) {
                return CallerContextStatus.CALLER_OWNED;
            }
            return tracker == null ? CallerContextStatus.MISSING : CallerContextStatus.LOCAL_TRACKER;
        }
    }

    /**
     * Result of the one-pass target/dependency load with an explicit application scope.
     * The set contains only successfully parsed classes emitted by the first target artifact;
     * dependency and JDK classes are never inferred to be application-owned by position in the
     * final merged class map.
     */
    public record ScopedLoad(LoadResult load, java.util.Set<String> applicationClassNames,
                             Map<String, Integer> classArtifactIndexes,
                             Map<String, List<Integer>> duplicateArtifactIndexes,
                             Map<String, List<String>> artifactDetails,
                             Map<String, ArchiveMetadata> archiveMetadata,
                             Map<String, List<ArchiveMemberProvenance>> classProvenance,
                             List<ArchiveMemberProvenance> archiveMembers,
                             List<Integer> unparseableArtifactIndexes,
                             ApplicationResourceFacts applicationResourceFacts) {
        public ScopedLoad {
            load = load == null ? new LoadResult(Map.of(), List.of(), 0, 0) : load;
            applicationClassNames = applicationClassNames == null ? java.util.Set.of()
                    : java.util.Set.copyOf(applicationClassNames);
            classArtifactIndexes = classArtifactIndexes == null ? Map.of()
                    : Map.copyOf(classArtifactIndexes);
            if (classArtifactIndexes.values().stream().anyMatch(index -> index == null || index < 0)) {
                throw new IllegalArgumentException("class artifact indexes must be non-negative");
            }
            Map<String, List<Integer>> duplicateCopy = new LinkedHashMap<>();
            if (duplicateArtifactIndexes != null) {
                for (Map.Entry<String, List<Integer>> entry : duplicateArtifactIndexes.entrySet()) {
                    if (entry.getKey() == null || entry.getValue() == null
                            || entry.getValue().stream().anyMatch(index -> index == null || index < 0)) {
                        throw new IllegalArgumentException("duplicate artifact indexes are invalid");
                    }
                    duplicateCopy.put(entry.getKey(), List.copyOf(entry.getValue()));
                }
            }
            duplicateArtifactIndexes = Map.copyOf(duplicateCopy);
            Map<String, List<String>> detailCopy = new LinkedHashMap<>();
            if (artifactDetails != null) {
                for (Map.Entry<String, List<String>> entry : artifactDetails.entrySet()) {
                    if (entry.getKey() == null || entry.getValue() == null
                            || entry.getValue().stream().anyMatch(value -> value == null
                            || value.isBlank())) {
                        throw new IllegalArgumentException("artifact details are invalid");
                    }
                    detailCopy.put(entry.getKey(), List.copyOf(entry.getValue()));
                }
            }
            artifactDetails = Map.copyOf(detailCopy);
            Map<String, ArchiveMetadata> metadataCopy = new LinkedHashMap<>();
            if (archiveMetadata != null) {
                for (Map.Entry<String, ArchiveMetadata> entry : archiveMetadata.entrySet()) {
                    if (entry.getKey() == null || entry.getKey().isBlank()
                            || entry.getValue() == null) {
                        throw new IllegalArgumentException("archive metadata is invalid");
                    }
                    metadataCopy.put(entry.getKey(), entry.getValue());
                }
            }
            archiveMetadata = Map.copyOf(metadataCopy);
            classProvenance = immutableClassProvenance(classProvenance);
            archiveMembers = immutableArchiveMembers(archiveMembers);
            if (unparseableArtifactIndexes == null) {
                unparseableArtifactIndexes = List.of();
            } else {
                if (unparseableArtifactIndexes.stream().anyMatch(index -> index == null || index < 0)) {
                    throw new IllegalArgumentException("unparseable artifact indexes are invalid");
                }
                unparseableArtifactIndexes = List.copyOf(unparseableArtifactIndexes);
            }
            applicationResourceFacts = applicationResourceFacts == null
                    ? ApplicationResourceFacts.empty() : applicationResourceFacts;
        }

        /** Compatibility constructor for callers interested only in application scope. */
        public ScopedLoad(LoadResult load, java.util.Set<String> applicationClassNames) {
            this(load, applicationClassNames, Map.of(), Map.of(), Map.of(),
                    Map.of(), Map.of(), List.of(), List.of(), ApplicationResourceFacts.empty());
        }

        /** Compatibility constructor for callers that do not consume embedded provenance. */
        public ScopedLoad(LoadResult load, java.util.Set<String> applicationClassNames,
                          Map<String, Integer> classArtifactIndexes,
                          Map<String, List<Integer>> duplicateArtifactIndexes) {
            this(load, applicationClassNames, classArtifactIndexes, duplicateArtifactIndexes,
                    Map.of(), Map.of(), Map.of(), List.of(), List.of(),
                    ApplicationResourceFacts.empty());
        }
    }

    public LoadResult load(List<Path> targets) {
        return loadStreaming(targets);
    }

    /** load 的扩展：extraClassBytes 参与解析（如 --jdk 全量 JDK 类，仅填充 target/deps 未覆盖的名字）。 */
    public LoadResult load(List<Path> targets, List<ClassBytes> extraClassBytes) {
        return load(loadStreaming(targets), extraClassBytes);
    }

    /**
     * 流式读取并按固定批次解析目标。兼容入口 {@link #read(List)} 仍保留给需要原始
     * 输入的扩展点，但正式扫描不再先建立整个工件的 ClassBytes 列表；这会显著缩短
     * fat jar 原始 byte[] 的存活时间，也避免为每个 class 提交一个长期挂起的 Future。
     */
    public LoadResult loadStreaming(List<Path> targets) {
        return loadStreaming(targets, 0);
    }

    /** Load using a target JDK feature for multi-release archive selection. */
    public LoadResult loadStreaming(List<Path> targets, int targetFeature) {
        return loadStreaming(targets, targetFeature, null);
    }

    /**
     * Load target/dependency inputs while charging every archive and filesystem entry to the
     * caller-owned tracker.  The compatibility overload above deliberately creates a fresh
     * tracker; the scan pipeline passes its one scan-wide tracker so a second frontend entry
     * cannot reset aggregate limits between target and dependency artifacts.
     */
    public LoadResult loadStreaming(List<Path> targets, int targetFeature,
                                     InputBudget.Tracker callerTracker) {
        return loadStreamingInternal(targets, targetFeature, callerTracker, false, null).load();
    }

    /**
     * One-pass load that also records the successfully parsed class names from the application
     * target.  This is the provenance input for the demand-driven entry index; it avoids the
     * former ChainComposer re-read of the target artifact and does not retain raw bytes.
     */
    public ScopedLoad loadStreamingWithApplicationScope(List<Path> targets, int targetFeature,
                                                         InputBudget.Tracker callerTracker) {
        return loadStreamingInternal(targets, targetFeature, callerTracker, true, null);
    }

    /**
     * One-pass load with input identities frozen by the scan boundary.  The list must contain
     * one direct provenance value per target/dependency input; JDK provenance is not part of this
     * argument because JDK classes enter through the separate JDK source.
     */
    public ScopedLoad loadStreamingWithApplicationScope(List<Path> targets, int targetFeature,
                                                         InputBudget.Tracker callerTracker,
                                                         List<ArtifactProvenance> artifactInputs) {
        return loadStreamingInternal(targets, targetFeature, callerTracker, true,
                artifactInputs);
    }

    private ScopedLoad loadStreamingInternal(List<Path> targets, int targetFeature,
                                              InputBudget.Tracker callerTracker,
                                              boolean captureApplicationScope,
                                              List<ArtifactProvenance> artifactInputs) {
        InputBudget.Tracker inputTracker = callerTracker == null
                ? inputBudget.tracker() : callerTracker;
        if (artifactInputs != null && targets != null && artifactInputs.size() < targets.size()) {
            throw new IllegalArgumentException("direct artifact provenance is incomplete");
        }
        try (ParsingSession session = new ParsingSession(inputTracker)) {
            StreamingAccumulator accumulator = new StreamingAccumulator(session,
                    captureApplicationScope, artifactInputs);
            if (targets == null) {
                return accumulator.scopedResult();
            }
            for (int artifactIndex = 0; artifactIndex < targets.size(); artifactIndex++) {
                Path target = targets.get(artifactIndex);
                accumulator.setArtifactIndex(artifactIndex);
                accumulator.addRootMember(artifactIndex, target);
                try {
                    JarReader.StreamResult stream = jarReader.streamDetailedWithResources(target,
                    accumulator::accept, captureApplicationScope
                                    ? accumulator::acceptResource : null,
                            targetFeature, inputBudget, inputTracker,
                            artifactRole(artifactIndex));
                    accumulator.addReasons(stream.completenessReasons());
                    accumulator.addMetadata(stream.archiveMetadata());
                    accumulator.addArchiveMembers(stream.archiveMembers());
                    if (stream.classesEmitted() == 0
                            && stream.completenessReasons().contains("ARCHIVE_CORRUPT")) {
                        accumulator.markUnparseableArtifact(artifactIndex);
                    }
                } catch (IOException e) {
                    String origin = target == null ? "<null>" : target.toString();
                    accumulator.diagnostics.add(new ParseDiagnostic(origin, e.getMessage()));
                    accumulator.markUnparseableArtifact(artifactIndex);
                    JustLogger.error("读取输入失败 {}: {}", origin, e.getMessage());
                }
                // Keep artifact ownership aligned with the synchronous reader callback.  A
                // flush at the boundary also shortens the lifetime of the preceding artifact's
                // raw byte batch without creating a new parsing session or executor.
                accumulator.flush();
            }
            return accumulator.scopedResult();
        }
    }

    /**
     * Typed frontend entry point.  The returned universe contains immutable class facts and
     * report-safe content identities for the requested artifacts; no raw bytes escape.
     */
    public ProgramUniverse loadUniverse(List<Path> targets) {
        return loadUniverse(targets, 0);
    }

    /** Load an immutable universe using the selected multi-release/JDK feature. */
    public ProgramUniverse loadUniverse(List<Path> targets, int targetFeature) {
        return loadUniverse(targets, targetFeature, null);
    }

    /** Typed universe load using a caller-owned aggregate input tracker. */
    public ProgramUniverse loadUniverse(List<Path> targets, int targetFeature,
                                        InputBudget.Tracker callerTracker) {
        List<ArtifactProvenance> provenance = new ArrayList<>();
        if (targets != null) {
            for (Path target : targets) {
                try {
                    provenance.add(ArtifactProvenance.fromPath(target,
                            ArtifactProvenance.Role.UNKNOWN, inputBudget, callerTracker));
                } catch (IOException failure) {
                    // Keep parsing output usable, but make the missing identity explicit in
                    // the immutable model instead of silently inventing a digest.
                    String name = target == null || target.getFileName() == null
                            ? "<unknown>" : target.getFileName().toString();
                    provenance.add(ArtifactProvenance.unknown(name, ArtifactProvenance.Role.UNKNOWN));
                }
            }
        }
        LoadResult result = loadStreamingInternal(targets, targetFeature, callerTracker, false,
                provenance).load();
        return ProgramUniverse.of(result, provenance);
    }

    /** 读取输入文件但不解析，供调用方在不重复读取/解析目标的情况下规划外部类切片。 */
    public Inputs read(List<Path> targets) {
        return read(targets, 0);
    }

    /** Read raw class inputs using a target JDK feature for multi-release selection. */
    public Inputs read(List<Path> targets, int targetFeature) {
        return read(targets, targetFeature, null);
    }

    /** Read raw class inputs using a caller-owned aggregate tracker. */
    public Inputs read(List<Path> targets, int targetFeature,
                       InputBudget.Tracker callerTracker) {
        List<ParseDiagnostic> diagnostics = new ArrayList<>();
        List<String> completenessReasons = new ArrayList<>();
        List<ClassBytes> inputs = new ArrayList<>();
        List<ArchiveMemberProvenance> archiveMembers = new ArrayList<>();
        InputBudget.Tracker inputTracker = callerTracker == null
                ? inputBudget.tracker() : callerTracker;
        for (Path target : targets) {
            try {
                JarReader.ReadResult read = jarReader.readDetailed(target, targetFeature,
                        inputBudget, inputTracker);
                completenessReasons.addAll(read.completenessReasons());
                inputs.addAll(read.classes());
                archiveMembers.addAll(read.archiveMembers());
            } catch (IOException e) {
                diagnostics.add(new ParseDiagnostic(target.toString(), e.getMessage()));
                JustLogger.error("读取输入失败 {}: {}", target, e.getMessage());
            }
        }
        return new Inputs(inputs, diagnostics,
                List.copyOf(new java.util.LinkedHashSet<>(completenessReasons)), inputTracker,
                callerTracker != null, classProvenance(inputs), archiveMembers);
    }

    /** 解析已经读取的目标输入。目标类本身先入图，保留输入顺序和诊断顺序。 */
    public LoadResult load(Inputs input) {
        return loadInternal(input, input == null ? null : input.tracker(),
                input != null && input.callerContextProvided());
    }

    /**
     * Parse a previously read batch while retaining its caller-owned aggregate tracker.  The
     * explicit overload is useful for legacy {@link Inputs} values constructed without a
     * tracker; production read→load paths carry the tracker in the value itself.
     */
    public LoadResult load(Inputs input, InputBudget.Tracker callerTracker) {
        return loadInternal(input, callerTracker, callerTracker != null
                || (input != null && input.callerContextProvided()));
    }

    private LoadResult loadInternal(Inputs input, InputBudget.Tracker callerTracker,
                                    boolean callerContextProvided) {
        if (input == null) {
            return new LoadResult(Map.of(), List.of(), 0, 0, List.of("NULL_INPUTS"));
        }
        Map<String, ClassInfo> classes = new LinkedHashMap<>();
        List<ParseDiagnostic> diagnostics = new ArrayList<>(input.diagnostics());
        LinkedHashSet<String> completenessReasons = new LinkedHashSet<>(input.completenessReasons());
        // The source-compatible three-argument Inputs constructor predates the scan-wide
        // tracker.  Keep it usable for extensions, but make the missing aggregate capability
        // explicit instead of silently presenting a fresh local budget as production-safe.
        if (!callerContextProvided) {
            completenessReasons.add("INPUT_BUDGET_CALLER_CONTEXT_MISSING");
        }
        List<ParsedClass> parsed = parse(input.classes(), callerTracker);
        int maxMajor = 0;
        for (ParsedClass result : parsed) {
            if (result.diagnostic() != null) {
                diagnostics.add(result.diagnostic());
                continue;
            }
            if (classes.putIfAbsent(result.className(), result.info()) != null) {
                completenessReasons.add("DUPLICATE_CLASS:" + result.className());
            }
            maxMajor = Math.max(maxMajor, result.majorVersion());
        }
        Map<String, List<ArchiveMemberProvenance>> classProvenance = mergeClassProvenance(
                input.classProvenance(), classProvenance(input.classes()), classes);
        return new LoadResult(classes, List.copyOf(diagnostics), input.classes().size(), maxMajor,
                List.copyOf(completenessReasons), classProvenance, input.archiveMembers());
    }

    /** 在已有目标结果上追加外部类，避免 JDK 切片规划时再次解析目标类。 */
    public LoadResult load(LoadResult base, List<ClassBytes> extraClassBytes) {
        return load(base, extraClassBytes, null);
    }

    /** Append external classes while charging the same scan-owned tracker as the base load. */
    public LoadResult load(LoadResult base, List<ClassBytes> extraClassBytes,
                           InputBudget.Tracker callerTracker) {
        if (extraClassBytes == null || extraClassBytes.isEmpty()) {
            return base;
        }
        Map<String, ClassInfo> classes = new LinkedHashMap<>(base.classes());
        List<ParseDiagnostic> diagnostics = new ArrayList<>(base.diagnostics());
        LinkedHashSet<String> completenessReasons = new LinkedHashSet<>(base.completenessReasons());
        Map<String, List<ArchiveMemberProvenance>> classProvenance =
                new LinkedHashMap<>(base.classProvenance());
        List<ArchiveMemberProvenance> archiveMembers = new ArrayList<>(base.archiveMembers());
        archiveMembers.addAll(memberSnapshot(extraClassBytes));
        if (callerTracker == null) {
            completenessReasons.add("INPUT_BUDGET_CALLER_CONTEXT_MISSING");
        }
        for (ParsedClass result : parse(extraClassBytes, callerTracker)) {
            // 应用类优先；与旧的 target + extra 装载契约一致，重复 extra 也不产生新诊断。
            if (classes.containsKey(result.className())) {
                completenessReasons.add("DUPLICATE_CLASS:" + result.className());
                continue;
            }
            if (result.diagnostic() != null) {
                diagnostics.add(result.diagnostic());
                continue;
            }
            classes.putIfAbsent(result.className(), result.info());
        }
        mergeClassProvenanceInto(classProvenance, classProvenance(extraClassBytes), classes);
        return new LoadResult(classes, List.copyOf(diagnostics),
                base.filesScanned() + extraClassBytes.size(), base.targetMajorVersion(),
                List.copyOf(completenessReasons), classProvenance, archiveMembers);
    }

    /** 目标输入 + 外部类的兼容入口。 */
    public LoadResult load(Inputs input, List<ClassBytes> extraClassBytes) {
        InputBudget.Tracker tracker = input == null ? null : input.tracker();
        LoadResult base = loadInternal(input, tracker,
                input != null && input.callerContextProvided());
        return load(base, extraClassBytes, input != null && input.callerContextProvided()
                ? tracker : null);
    }

    private List<ParsedClass> parse(List<ClassBytes> inputs) {
        return parse(inputs, null);
    }

    private List<ParsedClass> parse(List<ClassBytes> inputs, InputBudget.Tracker callerTracker) {
        InputBudget.Tracker tracker = callerTracker == null
                ? inputBudget.tracker() : callerTracker;
        try (ParsingSession session = new ParsingSession(tracker)) {
            return session.parse(inputs);
        }
    }

    private List<ParsedClass> parseSequential(List<ClassBytes> inputs,
                                              InputBudget.Tracker tracker) {
        List<ParsedClass> result = new ArrayList<>(inputs.size());
        for (int i = 0; i < inputs.size(); i++) {
                result.add(parseOne(inputs.get(i), tracker));
        }
        return result;
    }

    private List<ParsedClass> parseParallel(List<ClassBytes> inputs, ExecutorService executor,
                                            InputBudget.Tracker tracker) {
        List<Future<ParsedClass>> futures = new ArrayList<>(inputs.size());
        for (int i = 0; i < inputs.size(); i++) {
            final int index = i;
            futures.add(executor.submit(() -> parseOne(inputs.get(index), tracker)));
        }
        List<ParsedClass> result = new ArrayList<>(inputs.size());
        for (Future<ParsedClass> future : futures) {
            try {
                result.add(future.get());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("前端解析被中断", e);
            } catch (ExecutionException e) {
                Throwable cause = e.getCause() != null ? e.getCause() : e;
                throw new IllegalStateException("前端解析 worker 失败", cause);
            }
        }
        return result;
    }

    private ParsedClass parseOne(ClassBytes bytes, InputBudget.Tracker tracker) {
        try {
            if (bytes == null || bytes.bytes() == null || bytes.className() == null) {
                throw new IllegalArgumentException("missing class input metadata");
            }
            ClassInfo info = classFileReaders.get().read(bytes.bytes(), inputBudget, tracker);
            if (!bytes.className().equals(info.internalName())) {
                return new ParsedClass(bytes.className(), ClassFileReader.majorOf(bytes.bytes()), null,
                        new ParseDiagnostic(bytes.origin(), "CLASS_NAME_MISMATCH: expected "
                                + bytes.className() + ", actual " + info.internalName()));
            }
            return new ParsedClass(bytes.className(), ClassFileReader.majorOf(bytes.bytes()), info, null);
        } catch (Exception e) {
            String origin = bytes == null ? "<null>" : bytes.origin();
            String className = bytes == null ? "<null>" : bytes.className();
            return new ParsedClass(className, 0, null,
                    new ParseDiagnostic(origin, e.getClass().getSimpleName() + ": " + e.getMessage()));
        }
    }

    /** 单个扫描的有界前端累加器；flush 后立即丢弃本批次原始 bytes。 */
    private final class StreamingAccumulator {
        private final ParsingSession parsingSession;
        private final boolean captureApplicationScope;
        private final List<ArtifactProvenance> artifactInputs;
        private final Map<String, ClassInfo> classes = new LinkedHashMap<>();
        private final List<ParseDiagnostic> diagnostics = new ArrayList<>();
        private final LinkedHashSet<String> completenessReasons = new LinkedHashSet<>();
        private final LinkedHashSet<String> applicationClassNames = new LinkedHashSet<>();
        private final Map<String, Integer> classArtifactIndexes = new LinkedHashMap<>();
        private final Map<String, List<Integer>> duplicateArtifactIndexes = new LinkedHashMap<>();
        private final Map<String, List<String>> artifactDetails = new LinkedHashMap<>();
        private final Map<String, ArchiveMetadata> archiveMetadata = new LinkedHashMap<>();
        private final Map<String, List<ArchiveMemberProvenance>> classProvenance =
                new LinkedHashMap<>();
        private final List<ArchiveMemberProvenance> archiveMembers = new ArrayList<>();
        private final LinkedHashSet<Integer> unparseableArtifactIndexes = new LinkedHashSet<>();
        private final ApplicationResourceParser.Collector resourceCollector =
                new ApplicationResourceParser.Collector(inputBudget);
        private final List<ClassBytes> batch = new ArrayList<>(STREAM_BATCH_SIZE);
        private int filesScanned;
        private int maxMajor;
        private int artifactIndex;

        private StreamingAccumulator(ParsingSession parsingSession, boolean captureApplicationScope,
                                     List<ArtifactProvenance> artifactInputs) {
            this.parsingSession = parsingSession;
            this.captureApplicationScope = captureApplicationScope;
            this.artifactInputs = artifactInputs == null ? null : List.copyOf(artifactInputs);
        }

        private void setArtifactIndex(int artifactIndex) {
            this.artifactIndex = Math.max(0, artifactIndex);
        }

        private void accept(ClassBytes bytes) {
            batch.add(bytes);
            filesScanned++;
            if (batch.size() >= STREAM_BATCH_SIZE) {
                flush();
            }
        }

        private void addReasons(List<String> reasons) {
            if (reasons != null) {
                completenessReasons.addAll(reasons);
            }
        }

        private void addMetadata(Map<String, ArchiveMetadata> metadata) {
            if (metadata == null) {
                return;
            }
            for (Map.Entry<String, ArchiveMetadata> entry : metadata.entrySet()) {
                ArchiveMetadata previous = archiveMetadata.putIfAbsent(entry.getKey(), entry.getValue());
                if (previous != null && !previous.equals(entry.getValue())) {
                    throw new IllegalArgumentException("archive metadata origin collision: "
                            + entry.getKey());
                }
            }
        }

        private void addArchiveMembers(List<ArchiveMemberProvenance> members) {
            if (members != null) {
                archiveMembers.addAll(members);
            }
        }

        private void addRootMember(int artifactIndex, Path target) {
            if (artifactInputs == null) {
                return;
            }
            if (artifactIndex < 0 || artifactIndex >= artifactInputs.size()) {
                throw new IllegalArgumentException("direct artifact provenance index is invalid");
            }
            ArtifactProvenance artifact = artifactInputs.get(artifactIndex);
            if (artifact == null) {
                throw new IllegalArgumentException("direct artifact provenance is null");
            }
            String logicalName = artifact.logicalName();
            if (target == null && logicalName.isBlank()) {
                throw new IllegalArgumentException("direct artifact logical name is missing");
            }
            archiveMembers.add(ArchiveMemberProvenance.fromKnownHash(logicalName, logicalName,
                    "<root>", artifact.sha256(), artifactRole(artifactIndex), "",
                    ArchiveMemberProvenance.Kind.ARCHIVE));
        }

        private void markUnparseableArtifact(int artifactIndex) {
            unparseableArtifactIndexes.add(artifactIndex);
        }

        private void acceptResource(String path, byte[] bytes, String origin) {
            if (captureApplicationScope && artifactIndex == 0) {
                resourceCollector.accept(path, bytes);
            }
        }

        private void flush() {
            if (batch.isEmpty()) {
                return;
            }
            List<ParsedClass> parsedClasses = parsingSession.parse(batch);
            for (int i = 0; i < parsedClasses.size(); i++) {
                ParsedClass parsed = parsedClasses.get(i);
                if (parsed.diagnostic() != null) {
                    diagnostics.add(parsed.diagnostic());
                    continue;
                }
                ArchiveMemberProvenance member = batch.get(i).provenance();
                if (member != null) {
                    classProvenance.computeIfAbsent(parsed.className(), ignored ->
                            new ArrayList<>()).add(member);
                }
                if (captureApplicationScope && artifactIndex == 0
                        && isApplicationArtifactClass(batch.get(i))) {
                    applicationClassNames.add(parsed.className());
                }
                String artifactDetail = embeddedArtifactDetail(batch.get(i).origin());
                if (classes.putIfAbsent(parsed.className(), parsed.info()) != null) {
                    completenessReasons.add("DUPLICATE_CLASS:" + parsed.className());
                    duplicateArtifactIndexes.computeIfAbsent(parsed.className(), ignored ->
                            new ArrayList<>()).add(artifactIndex);
                } else {
                    classArtifactIndexes.put(parsed.className(), artifactIndex);
                }
                if (artifactDetail != null) {
                    artifactDetails.computeIfAbsent(parsed.className(), ignored ->
                            new ArrayList<>()).add(artifactDetail);
                }
                maxMajor = Math.max(maxMajor, parsed.majorVersion());
            }
            batch.clear();
        }

        private LoadResult result() {
            List<ArchiveMemberProvenance> finalizedMembers = finalizeMembers();
            Map<String, List<ArchiveMemberProvenance>> finalizedClassProvenance =
                    finalizeClassProvenance(finalizedMembers);
            return new LoadResult(classes, List.copyOf(diagnostics), filesScanned, maxMajor,
                    List.copyOf(completenessReasons), finalizedClassProvenance,
                    finalizedMembers);
        }

        private ScopedLoad scopedResult() {
            LoadResult load = result();
            return new ScopedLoad(load, applicationClassNames, classArtifactIndexes,
                    duplicateArtifactIndexes, artifactDetails, archiveMetadata,
                    load.classProvenance(), load.archiveMembers(),
                    List.copyOf(unparseableArtifactIndexes), resourceCollector.finish());
        }

        private List<ArchiveMemberProvenance> finalizeMembers() {
            Map<String, ArchiveMetadata> parsed = new LinkedHashMap<>(archiveMetadata);
            List<ArchiveMemberProvenance> result = new ArrayList<>(archiveMembers.size());
            for (ArchiveMemberProvenance member : archiveMembers) {
                String coordinate = exactCoordinate(parsed.get(member.logicalArtifact()));
                result.add(coordinate.isBlank() ? member : member.withCoordinate(coordinate));
            }
            return List.copyOf(result);
        }

        private Map<String, List<ArchiveMemberProvenance>> finalizeClassProvenance(
                List<ArchiveMemberProvenance> finalizedMembers) {
            Map<String, ArchiveMemberProvenance> byContent = new LinkedHashMap<>();
            for (ArchiveMemberProvenance member : finalizedMembers) {
                byContent.putIfAbsent(member.contentIdentity(), member);
            }
            Map<String, List<ArchiveMemberProvenance>> result = new LinkedHashMap<>();
            for (Map.Entry<String, List<ArchiveMemberProvenance>> entry : classProvenance.entrySet()) {
                List<ArchiveMemberProvenance> values = new ArrayList<>();
                for (ArchiveMemberProvenance member : entry.getValue()) {
                    values.add(byContent.getOrDefault(member.contentIdentity(), member));
                }
                result.put(entry.getKey(), List.copyOf(values));
            }
            return result;
        }
    }

    private static boolean isApplicationArtifactClass(ClassBytes bytes) {
        if (bytes == null || bytes.origin() == null) {
            return true;
        }
        String origin = bytes.origin().replace('\\', '/').toLowerCase(java.util.Locale.ROOT);
        // JarReader retains the physical nested path in origin.  A class below any nested
        // library layout belongs to an embedded dependency, never to the application execution
        // scope, even though it was read from the first target file.
        return !origin.contains("!boot-inf/lib/") && !origin.contains("!web-inf/lib/")
                && !origin.contains("!lib/");
    }

    /** Convert an embedded class origin into the same path-free logical detail used by reports. */
    private static String embeddedArtifactDetail(String origin) {
        if (origin == null || origin.isBlank()) {
            return null;
        }
        String normalized = origin.replace('\\', '/');
        for (String marker : List.of("!BOOT-INF/lib/", "!WEB-INF/lib/", "!lib/")) {
            int start = normalized.indexOf(marker);
            if (start >= 0) {
                int nameStart = start + 1;
                int end = normalized.indexOf('!', nameStart);
                String name = end < 0 ? normalized.substring(nameStart)
                        : normalized.substring(nameStart, end);
                return "nested:" + name;
            }
        }
        return null;
    }

    private static ArchiveMemberProvenance.Role artifactRole(int artifactIndex) {
        return artifactIndex == 0 ? ArchiveMemberProvenance.Role.ROOT
                : ArchiveMemberProvenance.Role.EXPLICIT_DEPENDENCY;
    }

    private static String exactCoordinate(ArchiveMetadata metadata) {
        if (metadata == null || metadata.pomProperties().size() != 1) {
            return "";
        }
        return metadata.pomProperties().get(0).coordinate();
    }

    private static Map<String, List<ArchiveMemberProvenance>> immutableClassProvenance(
            Map<String, List<ArchiveMemberProvenance>> values) {
        if (values == null || values.isEmpty()) {
            return Map.of();
        }
        Map<String, List<ArchiveMemberProvenance>> copy = new LinkedHashMap<>();
        for (Map.Entry<String, List<ArchiveMemberProvenance>> entry : values.entrySet()) {
            if (entry.getKey() == null || entry.getKey().isBlank()
                    || entry.getValue() == null
                    || entry.getValue().stream().anyMatch(value -> value == null)) {
                throw new IllegalArgumentException("class provenance is invalid");
            }
            copy.put(entry.getKey(), List.copyOf(entry.getValue()));
        }
        return Map.copyOf(copy);
    }

    private static List<ArchiveMemberProvenance> immutableArchiveMembers(
            List<ArchiveMemberProvenance> values) {
        if (values == null || values.isEmpty()) {
            return List.of();
        }
        if (values.stream().anyMatch(value -> value == null)) {
            throw new IllegalArgumentException("archive members must not contain null entries");
        }
        return List.copyOf(values);
    }

    private static Map<String, List<ArchiveMemberProvenance>> classProvenance(
            List<ClassBytes> values) {
        Map<String, List<ArchiveMemberProvenance>> result = new LinkedHashMap<>();
        if (values == null) {
            return result;
        }
        for (ClassBytes value : values) {
            if (value == null || value.className() == null || value.className().isBlank()
                    || value.provenance() == null) {
                continue;
            }
            result.computeIfAbsent(value.className(), ignored -> new ArrayList<>())
                    .add(value.provenance());
        }
        return result;
    }

    private static List<ArchiveMemberProvenance> memberSnapshot(List<ClassBytes> values) {
        List<ArchiveMemberProvenance> result = new ArrayList<>();
        if (values != null) {
            for (ClassBytes value : values) {
                if (value != null && value.provenance() != null) {
                    result.add(value.provenance());
                }
            }
        }
        return result;
    }

    private static Map<String, List<ArchiveMemberProvenance>> mergeClassProvenance(
            Map<String, List<ArchiveMemberProvenance>> first,
            Map<String, List<ArchiveMemberProvenance>> second,
            Map<String, ClassInfo> classes) {
        Map<String, List<ArchiveMemberProvenance>> result = new LinkedHashMap<>();
        mergeClassProvenanceInto(result, first, classes);
        mergeClassProvenanceInto(result, second, classes);
        return result;
    }

    private static void mergeClassProvenanceInto(
            Map<String, List<ArchiveMemberProvenance>> target,
            Map<String, List<ArchiveMemberProvenance>> values,
            Map<String, ClassInfo> classes) {
        if (values == null) {
            return;
        }
        for (Map.Entry<String, List<ArchiveMemberProvenance>> entry : values.entrySet()) {
            if (entry.getKey() == null || !classes.containsKey(entry.getKey())
                    || entry.getValue() == null) {
                continue;
            }
            List<ArchiveMemberProvenance> destination = target.computeIfAbsent(entry.getKey(),
                    ignored -> new ArrayList<>());
            for (ArchiveMemberProvenance member : entry.getValue()) {
                if (member != null && destination.stream().noneMatch(existing ->
                        existing.contentIdentity().equals(member.contentIdentity()))) {
                    destination.add(member);
                }
            }
        }
    }

    /**
     * One parsing session owns one adaptive lease and, when useful, one executor. Streaming
     * input still flushes bounded batches so raw class bytes do not accumulate, but the
     * scheduler must not recreate threads for every flush. The session is scoped to one
     * frontend operation and is closed before analysis starts.
     */
    private final class ParsingSession implements AutoCloseable {
        private final InputBudget.Tracker tracker;
        private AdaptiveParallelism.Lease lease;
        private ExecutorService executor;
        private int workers = 1;

        private ParsingSession(InputBudget.Tracker tracker) {
            this.tracker = tracker == null ? inputBudget.tracker() : tracker;
        }

        private List<ParsedClass> parse(List<ClassBytes> inputs) {
            if (inputs == null || inputs.isEmpty()) {
                return List.of();
            }
            ensureParallelism(inputs.size());
            if (executor == null || workers <= 1 || inputs.size() < PARALLEL_PARSE_THRESHOLD) {
                return parseSequential(inputs, tracker);
            }
            return parseParallel(inputs, executor, tracker);
        }

        private void ensureParallelism(int taskCount) {
            if (executor != null || taskCount < PARALLEL_PARSE_THRESHOLD) {
                return;
            }
            int available = Math.max(1, Runtime.getRuntime().availableProcessors());
            int cap = Math.min(MAX_PARSE_WORKERS, available);
            AdaptiveParallelism.Decision decision = AdaptiveParallelism.choose(taskCount, cap);
            lease = AdaptiveParallelism.reserve(decision);
            workers = lease.workers();
            if (workers > 1) {
                executor = Executors.newFixedThreadPool(workers,
                        new NamedThreadFactory("just-frontend-"));
            }
        }

        @Override
        public void close() {
            if (executor != null) {
                executor.shutdown();
                try {
                    if (!executor.awaitTermination(1, java.util.concurrent.TimeUnit.SECONDS)) {
                        executor.shutdownNow();
                    }
                } catch (InterruptedException e) {
                    executor.shutdownNow();
                    Thread.currentThread().interrupt();
                }
                executor = null;
            }
            if (lease != null) {
                lease.close();
                lease = null;
            }
        }
    }

    /**
     * 解析结果不再持有原始 class bytes。此前每个 Future 都把输入 byte[] 继续挂在
     * ParsedClass 上，直到整个批次和 max-major 统计结束；大型 fat jar 会因此把
     * 读取阶段的峰值延长到 CPG 构建前。major 在 worker 内读取一次即可，ClassInfo
     * 是后续阶段唯一需要的前端产物。
     */
    private record ParsedClass(String className, int majorVersion,
                               ClassInfo info, ParseDiagnostic diagnostic) {
    }

    private static final class NamedThreadFactory implements ThreadFactory {
        private final String prefix;
        private final AtomicInteger sequence = new AtomicInteger();

        private NamedThreadFactory(String prefix) {
            this.prefix = prefix;
        }

        @Override
        public Thread newThread(Runnable task) {
            Thread thread = new Thread(task, prefix + sequence.incrementAndGet());
            thread.setDaemon(true);
            return thread;
        }
    }
}
