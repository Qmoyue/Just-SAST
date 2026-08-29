package io.just.sast.frontend.asm;

import io.just.sast.model.ClassInfo;
import io.just.sast.model.LoadResult;
import io.just.sast.model.ParseDiagnostic;
import io.just.sast.util.JustLogger;
import io.just.sast.util.AdaptiveParallelism;

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

    private final JarReader jarReader = new JarReader();
    /** ASM 的输入是只读的；每个 worker 使用自己的 reader，避免共享可变 extractor 状态。 */
    private final ThreadLocal<ClassFileReader> classFileReaders =
            ThreadLocal.withInitial(ClassFileReader::new);

    /** 前端是纯解析阶段，允许使用较高并行度；分析阶段另有独立的并行配额。 */
    private static final int MAX_PARSE_WORKERS = 16;
    private static final int PARALLEL_PARSE_THRESHOLD = 64;
    /** 原始 class bytes 的上界；解析结果本身仍由后续 CPG 阶段持有。 */
    private static final int STREAM_BATCH_SIZE = 64;

    /** 已读取但尚未解析的目标输入；用于 JDK 切片先解析应用，再复用同一批字节。 */
    public record Inputs(List<ClassBytes> classes, List<ParseDiagnostic> diagnostics,
                         List<String> completenessReasons) {
        public Inputs {
            classes = classes == null ? List.of() : List.copyOf(classes);
            diagnostics = diagnostics == null ? List.of() : List.copyOf(diagnostics);
            completenessReasons = completenessReasons == null ? List.of() : List.copyOf(completenessReasons);
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
        try (ParsingSession session = new ParsingSession()) {
            StreamingAccumulator accumulator = new StreamingAccumulator(session);
            if (targets == null) {
                return accumulator.result();
            }
            for (Path target : targets) {
                try {
                    JarReader.StreamResult stream = jarReader.streamDetailed(target,
                            accumulator::accept);
                    accumulator.addReasons(stream.completenessReasons());
                } catch (IOException e) {
                    accumulator.diagnostics.add(new ParseDiagnostic(target.toString(), e.getMessage()));
                    JustLogger.error("读取输入失败 {}: {}", target, e.getMessage());
                }
            }
            accumulator.flush();
            return accumulator.result();
        }
    }

    /** 读取输入文件但不解析，供调用方在不重复读取/解析目标的情况下规划外部类切片。 */
    public Inputs read(List<Path> targets) {
        List<ParseDiagnostic> diagnostics = new ArrayList<>();
        List<String> completenessReasons = new ArrayList<>();
        List<ClassBytes> inputs = new ArrayList<>();
        for (Path target : targets) {
            try {
                JarReader.ReadResult read = jarReader.readDetailed(target);
                completenessReasons.addAll(read.completenessReasons());
                inputs.addAll(read.classes());
            } catch (IOException e) {
                diagnostics.add(new ParseDiagnostic(target.toString(), e.getMessage()));
                JustLogger.error("读取输入失败 {}: {}", target, e.getMessage());
            }
        }
        return new Inputs(inputs, diagnostics,
                List.copyOf(new java.util.LinkedHashSet<>(completenessReasons)));
    }

    /** 解析已经读取的目标输入。目标类本身先入图，保留输入顺序和诊断顺序。 */
    public LoadResult load(Inputs input) {
        Map<String, ClassInfo> classes = new LinkedHashMap<>();
        List<ParseDiagnostic> diagnostics = new ArrayList<>(input.diagnostics());
        List<ParsedClass> parsed = parse(input.classes());
        int maxMajor = 0;
        for (ParsedClass result : parsed) {
            if (result.diagnostic() != null) {
                diagnostics.add(result.diagnostic());
                continue;
            }
            classes.putIfAbsent(result.className(), result.info());
            maxMajor = Math.max(maxMajor, result.majorVersion());
        }
        return new LoadResult(classes, List.copyOf(diagnostics), input.classes().size(), maxMajor,
                input.completenessReasons());
    }

    /** 在已有目标结果上追加外部类，避免 JDK 切片规划时再次解析目标类。 */
    public LoadResult load(LoadResult base, List<ClassBytes> extraClassBytes) {
        if (extraClassBytes == null || extraClassBytes.isEmpty()) {
            return base;
        }
        Map<String, ClassInfo> classes = new LinkedHashMap<>(base.classes());
        List<ParseDiagnostic> diagnostics = new ArrayList<>(base.diagnostics());
        for (ParsedClass result : parse(extraClassBytes)) {
            // 应用类优先；与旧的 target + extra 装载契约一致，重复 extra 也不产生新诊断。
            if (classes.containsKey(result.className())) {
                continue;
            }
            if (result.diagnostic() != null) {
                diagnostics.add(result.diagnostic());
                continue;
            }
            classes.putIfAbsent(result.className(), result.info());
        }
        return new LoadResult(classes, List.copyOf(diagnostics),
                base.filesScanned() + extraClassBytes.size(), base.targetMajorVersion(),
                base.completenessReasons());
    }

    /** 目标输入 + 外部类的兼容入口。 */
    public LoadResult load(Inputs input, List<ClassBytes> extraClassBytes) {
        return load(load(input), extraClassBytes);
    }

    private List<ParsedClass> parse(List<ClassBytes> inputs) {
        try (ParsingSession session = new ParsingSession()) {
            return session.parse(inputs);
        }
    }

    private List<ParsedClass> parseSequential(List<ClassBytes> inputs) {
        List<ParsedClass> result = new ArrayList<>(inputs.size());
        for (int i = 0; i < inputs.size(); i++) {
                result.add(parseOne(inputs.get(i)));
        }
        return result;
    }

    private List<ParsedClass> parseParallel(List<ClassBytes> inputs, ExecutorService executor) {
        List<Future<ParsedClass>> futures = new ArrayList<>(inputs.size());
        for (int i = 0; i < inputs.size(); i++) {
            final int index = i;
            futures.add(executor.submit(() -> parseOne(inputs.get(index))));
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

    private ParsedClass parseOne(ClassBytes bytes) {
        try {
            ClassInfo info = classFileReaders.get().read(bytes.bytes());
            return new ParsedClass(bytes.className(), ClassFileReader.majorOf(bytes.bytes()), info, null);
        } catch (Exception e) {
            return new ParsedClass(bytes.className(), 0, null,
                    new ParseDiagnostic(bytes.origin(), e.getClass().getSimpleName() + ": " + e.getMessage()));
        }
    }

    /** 单个扫描的有界前端累加器；flush 后立即丢弃本批次原始 bytes。 */
    private final class StreamingAccumulator {
        private final ParsingSession parsingSession;
        private final Map<String, ClassInfo> classes = new LinkedHashMap<>();
        private final List<ParseDiagnostic> diagnostics = new ArrayList<>();
        private final LinkedHashSet<String> completenessReasons = new LinkedHashSet<>();
        private final List<ClassBytes> batch = new ArrayList<>(STREAM_BATCH_SIZE);
        private int filesScanned;
        private int maxMajor;

        private StreamingAccumulator(ParsingSession parsingSession) {
            this.parsingSession = parsingSession;
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

        private void flush() {
            if (batch.isEmpty()) {
                return;
            }
            for (ParsedClass parsed : parsingSession.parse(batch)) {
                if (parsed.diagnostic() != null) {
                    diagnostics.add(parsed.diagnostic());
                    continue;
                }
                classes.putIfAbsent(parsed.className(), parsed.info());
                maxMajor = Math.max(maxMajor, parsed.majorVersion());
            }
            batch.clear();
        }

        private LoadResult result() {
            return new LoadResult(classes, List.copyOf(diagnostics), filesScanned, maxMajor,
                    List.copyOf(completenessReasons));
        }
    }

    /**
     * One parsing session owns one adaptive lease and, when useful, one executor. Streaming
     * input still flushes bounded batches so raw class bytes do not accumulate, but the
     * scheduler must not recreate threads for every flush. The session is scoped to one
     * frontend operation and is closed before analysis starts.
     */
    private final class ParsingSession implements AutoCloseable {
        private AdaptiveParallelism.Lease lease;
        private ExecutorService executor;
        private int workers = 1;

        private List<ParsedClass> parse(List<ClassBytes> inputs) {
            if (inputs == null || inputs.isEmpty()) {
                return List.of();
            }
            ensureParallelism(inputs.size());
            if (executor == null || workers <= 1 || inputs.size() < PARALLEL_PARSE_THRESHOLD) {
                return parseSequential(inputs);
            }
            return parseParallel(inputs, executor);
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
