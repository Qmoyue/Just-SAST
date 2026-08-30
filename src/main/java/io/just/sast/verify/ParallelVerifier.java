package io.just.sast.verify;

import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.HopKind;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Set;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.UUID;
import io.just.sast.util.AdaptiveParallelism;

/**
 * 并行链级验证器：沿链 FIELD_FLOW 跳构造完整对象图 → 子进程执行 → sink 特异性判定。
 * 入口类去重（同一入口最多 2 条链），4 路并行，探针在 fat jar 中零逐链编译。
 */
public final class ParallelVerifier {

    /** Closed verifier lifecycle; the serialized string remains for report compatibility. */
    public enum VerifyStatus {
        SINK_BLOCKED, CONCRETE_REACHED, EXECUTED, PARTIAL, FAILED, TIMEOUT, UNTESTABLE, UNKNOWN;

        static VerifyStatus from(String value) {
            if (value == null) {
                return UNKNOWN;
            }
            try {
                return valueOf(value);
            } catch (IllegalArgumentException ignored) {
                return UNKNOWN;
            }
        }
    }

    public record VerifyResult(String chainKey, String status, String detail,
                               int attempt, long durationMs, String evidence) {
        public VerifyResult(String chainKey, String status, String detail) {
            this(chainKey, status, detail, 1, 0L, defaultEvidence(status, detail));
        }

        public VerifyResult(String chainKey, String status, String detail,
                            int attempt, long durationMs) {
            this(chainKey, status, detail, attempt, durationMs, defaultEvidence(status, detail));
        }

        public VerifyResult {
            chainKey = chainKey == null ? "" : chainKey;
            status = status == null ? "UNKNOWN" : status;
            detail = detail == null ? "" : detail;
            attempt = Math.max(1, attempt);
            durationMs = Math.max(0L, durationMs);
            evidence = evidence == null || evidence.isBlank()
                    ? defaultEvidence(status, detail) : evidence;
        }

        public VerifyStatus statusCode() {
            return VerifyStatus.from(status);
        }

        private static String defaultEvidence(String status, String detail) {
            return switch (VerifyStatus.from(status)) {
                case SINK_BLOCKED -> "SINK_CANARY_BOUNDARY";
                case CONCRETE_REACHED -> "CONCRETE_TRIGGER";
                case EXECUTED -> "ENTRY_RETURNED";
                case PARTIAL -> "PARTIAL_PATH";
                case TIMEOUT -> "PROCESS_TIMEOUT";
                case UNTESTABLE -> detail != null && detail.startsWith("SANDBOX_UNAVAILABLE")
                        ? "SANDBOX_UNAVAILABLE"
                        : detail != null && detail.startsWith("CANARY_ARTIFACT_MISSING")
                        ? "VERIFIER_ARTIFACT_MISSING" : "VERIFIER_CAPABILITY_LIMIT";
                case FAILED -> "NO_TRIGGER";
                default -> "UNKNOWN";
            };
        }
    }

    public interface ConfirmCallback {
        void onConfirmed(Chain chain, String detail, boolean sinkReached);
    }

    private static final int TIMEOUT_SECONDS = 8;
    private static final int MAX_PARALLELISM = 4;
    private static final int MAX_PER_ENTRY = 2;
    private static final int MAX_OUTPUT_BYTES = 64 * 1024;
    private static final int FUTURE_GRACE_SECONDS = 3;

    private final Path targetJar;
    private final List<Path> deps;
    private final Path ownJar;
    private final Path targetJdkHome;
    private final int targetMajorVersion;
    private final ConfirmCallback callback;
    /** 共享的有界 fat JAR/WAR classpath 展开；所有链复用同一只读结果。 */
    private volatile NestedClasspath expandedClasspath;
    /** Classes defined by the primary artifact (not its nested dependency libraries). */
    private volatile Set<String> targetDefinedClasses;
    /** 本验证器产生的待清理产物：sink canary bootstrap jar。 */
    private final List<Path> ownArtifacts = java.util.Collections.synchronizedList(new ArrayList<>());
    private volatile Path bootstrapJar;
    private volatile Path legacyBootstrapJar;
    /** 实际子 JVM 能力，而非仅由 CLI 的 verify 开关推断的请求状态。 */
    private volatile String capability = "NOT_RUN";

    public ParallelVerifier(Path targetJar, List<Path> deps, ConfirmCallback callback) {
        this(targetJar, deps, null, 0, callback);
    }

    public ParallelVerifier(Path targetJar, List<Path> deps, Path targetJdkHome,
                            ConfirmCallback callback) {
        this(targetJar, deps, targetJdkHome, 0, callback);
    }

    public ParallelVerifier(Path targetJar, List<Path> deps, Path targetJdkHome,
                            int targetMajorVersion, ConfirmCallback callback) {
        this.targetJar = targetJar.toAbsolutePath().normalize();
        this.deps = deps != null ? deps : List.of();
        this.targetJdkHome = targetJdkHome == null ? null
                : targetJdkHome.toAbsolutePath().normalize();
        this.targetMajorVersion = targetMajorVersion;
        this.callback = callback;
        this.ownJar = locateOwnJar();
    }

    private record RuntimeSelection(Path javaHome, Path probeJar, int feature, String reason) {
        boolean available() {
            return javaHome != null && probeJar != null;
        }
    }

    /** 子进程 classpath：探针 jar + 目标 jar + 全部依赖（依赖中的 gadget 类可解析）。 */
    static String classpathOf(Path ownJar, Path targetJar, List<Path> deps) {
        StringBuilder cp = new StringBuilder(ownJar.toString());
        cp.append(File.pathSeparator).append(targetJar);
        for (Path dep : deps != null ? deps : List.<Path>of()) {
            cp.append(File.pathSeparator).append(dep.toAbsolutePath().normalize());
        }
        return cp.toString();
    }

    /**
     * 选择要验证的链：结构证据、构造可行性和危险 sink 加权，并加入两项通用覆盖
     * 证据——主工件定义的入口类，以及可由容器真实触发的入口。动态预算有限时，
     * 只按全局分数会被依赖库内部的高分噪声占满，主工件的真实 gadget 反而永远进不了
     * 子进程；入口覆盖是扫描语义的一部分，不是任何 benchmark 的特判。预算的前四分之一
     * （至少一条）先从主工件入口中按同一证据排序取样，余量再回到全局排序，保证有限预算
     * 既覆盖实际攻击面，也不会让应用类的低质量候选吞掉全部验证槽位。
     * 同一入口/风险家族最多保留两条链，保持每次选择有界且可复现；不同风险家族
     * 不互相挤占（例如反射 sink 不会被两个通用执行器变体完全遮蔽）。
     */
    public List<Chain> selectChains(List<Chain> candidates, int maxTotal) {
        return selectChains(candidates, maxTotal, Set.of());
    }

    /**
     * 选择验证预算时优先使用已经通过通用对象构造检查的入口，同时保留结构证据排序。
     * 构造检查只按类/字段结构工作，不识别任何 benchmark 名称，因此不会把验证预算
     * 绑定到某个项目或 payload。旧重载保留给扩展点和测试，默认不提供构造提示。
     */
    public List<Chain> selectChains(List<Chain> candidates, int maxTotal,
                                    Set<String> constructibleKeys) {
        if (candidates == null || candidates.isEmpty() || maxTotal <= 0) {
            return List.of();
        }
        Set<String> constructible = constructibleKeys == null ? Set.of() : constructibleKeys;
        List<Chain> sorted = new ArrayList<>(candidates);
        sorted.sort(Comparator.comparingInt((Chain chain) -> probePriority(chain, constructible)).reversed()
                // Blackboard insertion can race between independent analysis workers. A stable
                // chain key keeps the finite verification budget reproducible without changing
                // which evidence is preferred.
                .thenComparing(Chain::key));
        Map<String, Integer> entryCount = new HashMap<>();
        List<Chain> selected = new ArrayList<>();
        Set<String> selectedKeys = new java.util.HashSet<>();
        int primaryBudget = Math.min(maxTotal, Math.max(1, maxTotal / 4));
        for (Chain chain : sorted) {
            if (selected.size() >= primaryBudget || !targetDefines(chain.entryClass())) {
                continue;
            }
            String entryKey = verificationQuotaKey(chain);
            int count = entryCount.getOrDefault(entryKey, 0);
            if (count >= MAX_PER_ENTRY) {
                continue;
            }
            entryCount.merge(entryKey, 1, Integer::sum);
            selected.add(chain);
            selectedKeys.add(chain.key());
        }
        for (Chain chain : sorted) {
            if (selectedKeys.contains(chain.key())) {
                continue;
            }
            String entryKey = verificationQuotaKey(chain);
            int count = entryCount.getOrDefault(entryKey, 0);
            if (count >= MAX_PER_ENTRY) continue;
            entryCount.merge(entryKey, 1, Integer::sum);
            selected.add(chain);
            if (selected.size() >= maxTotal) break;
        }
        return selected;
    }

    /**
     * 探测优先级：结构性证据分之上叠加 sink 危险类别加权——同等证据下，
     * 指向 JNDI/命令执行/类定义/反射调用的链优先消耗验证预算（预算有限时的价值排序）。
     */
    int probePriority(Chain chain) {
        return probePriority(chain, Set.of());
    }

    private int probePriority(Chain chain, Set<String> constructibleKeys) {
        int score = io.just.sast.chain.ConfidenceScorer.evidenceScore(chain, null);
        if (constructibleKeys.contains(chain.key())) {
            // A constructible entry is not proof of exploitability, but it removes a known
            // probe-side obstacle. Give it a bounded preference without overwhelming sink
            // severity or structural evidence.
            score += 8;
        }
        if (chain.unresolvedHops() == 0) {
            score += 1;
        } else {
            // Unresolved reflective hops are precisely the cases where a bounded child
            // probe can distinguish a real object shape from a static over-approximation.
            // Give them enough priority to enter the finite verification budget, while
            // keeping the result only as evidence (never as automatic confirmation).
            score += 8;
        }
        if (targetDefines(chain.entryClass())) {
            // The primary artifact is the analyst's actual attack surface. Keep this bounded
            // and below the constructibility bonus so an impossible application entry cannot
            // outrank a sound library chain solely because it is application-defined.
            score += 12;
        }
        if (isTriggerEntry(chain.entryKind())) {
            // hash/equals/comparator/serialization/proxy callbacks are real object-graph
            // triggers, while direct framework sources are only ordinary method probes.
            score += 4;
        }
        if (chain.hops().stream().anyMatch(hop -> "bridge-trigger-src".equals(hop.reason()))) {
            // A source-host chain carries a concrete semantic callback edge. Prefer a small
            // number of these complete paths in the finite probe budget so the source frame
            // itself can participate in canary proof; inner-segment attribution remains the
            // fallback when a source input cannot be safely adapted.
            score += 10;
            for (ChainHop hop : chain.hops()) {
                if (!"bridge-trigger-src".equals(hop.reason())) {
                    continue;
                }
                if (targetDefines(hop.toOwner())) {
                    score += 12;
                }
                score += switch (hop.toName()) {
                    case "hashCode" -> 12;
                    case "equals" -> 10;
                    case "compareTo" -> 8;
                    case "compare" -> 7;
                    case "toString" -> 5;
                    default -> 0;
                };
                break;
            }
        }
        // Dynamic verification is a finite experiment, not another longest-path search.
        // Prefer compact paths so a long generic framework plumbing chain cannot crowd out a
        // shorter path to the same attack surface.  The bound is deliberately small: static
        // discovery remains complete within its own analysis caps and this only orders probes.
        score += Math.max(0, 6 - Math.min(6, chain.hops().size() / 4));
        score += sinkProbeBonus(chain.sinkClass());
        return score;
    }

    /**
     * Generic sink-impact ordering for the finite child-process budget.  The larger weights
     * make direct reflective/JNDI/command/class-definition paths visible before generic
     * executor or logging plumbing, while the canary still decides confirmation.  These are
     * sink capability families, never target or benchmark names.
     */
    static int sinkProbeBonus(String sinkClass) {
        String sc = sinkClass == null ? "" : sinkClass;
        if (sc.startsWith("javax/naming/") || sc.contains("/jndi/")) {
            return 8;
        }
        if (sc.startsWith("java/lang/Runtime") || sc.startsWith("java/lang/ProcessBuilder")) {
            return 8;
        }
        if (sc.startsWith("com/sun/org/apache/xalan") || sc.startsWith("javax/xml/transform")
                || sc.startsWith("java/net/URLClassLoader") || sc.equals("java/lang/Class")) {
            return 7;
        }
        if (sc.startsWith("java/lang/reflect/")) {
            return 6;
        }
        if (sc.startsWith("java/net/")) {
            return 4;
        }
        if (sc.startsWith("java/io/") || sc.startsWith("java/nio/file/")) {
            return 2;
        }
        return 0;
    }

    private static String verificationQuotaKey(Chain chain) {
        return chain.entryClass() + "#" + chain.entryMethod()
                + "#" + sinkRiskFamily(chain.sinkClass());
    }

    /** Collapse equivalent sink implementations so finite verification keeps risk diversity. */
    static String sinkRiskFamily(String sinkClass) {
        String sc = sinkClass == null ? "" : sinkClass;
        if (sc.startsWith("javax/naming/") || sc.contains("/jndi/")) {
            return "jndi";
        }
        if (sc.startsWith("java/lang/Runtime") || sc.startsWith("java/lang/ProcessBuilder")) {
            return "command";
        }
        if (sc.startsWith("com/sun/org/apache/xalan") || sc.startsWith("javax/xml/transform")
                || sc.startsWith("java/net/URLClassLoader") || sc.equals("java/lang/Class")) {
            return "class-definition";
        }
        if (sc.startsWith("java/lang/reflect/")) {
            return "reflection";
        }
        if (sc.startsWith("java/net/")) {
            return "network";
        }
        if (sc.startsWith("java/io/") || sc.startsWith("java/nio/file/")) {
            return "filesystem";
        }
        return "other";
    }

    private static boolean isTriggerEntry(String entryKind) {
        return switch (entryKind == null ? "" : entryKind) {
            case "readObject", "readObjectNoData", "readExternal", "readResolve",
                    "writeReplace", "hashCode", "equals", "compareTo", "compare",
                    "proxyInvoke" -> true;
            default -> false;
        };
    }

    /**
     * Read the primary artifact's class names once.  Nested BOOT-INF/WEB-INF libraries are
     * intentionally excluded: they are dependencies and are already represented by their own
     * static evidence.  A directory input is handled without opening a ZIP.
     */
    private boolean targetDefines(String internalName) {
        if (internalName == null || internalName.isBlank()) {
            return false;
        }
        Set<String> classes = targetDefinedClasses;
        if (classes == null) {
            synchronized (this) {
                classes = targetDefinedClasses;
                if (classes == null) {
                    classes = loadTargetDefinedClasses();
                    targetDefinedClasses = classes;
                }
            }
        }
        return classes.contains(internalName);
    }

    private Set<String> loadTargetDefinedClasses() {
        Set<String> result = new java.util.HashSet<>();
        try {
            if (Files.isDirectory(targetJar)) {
                try (var stream = Files.walk(targetJar)) {
                    stream.filter(Files::isRegularFile)
                            .map(targetJar::relativize)
                            .map(Path::toString)
                            .map(value -> value.replace(File.separatorChar, '/'))
                            .filter(value -> value.endsWith(".class"))
                            .map(value -> value.substring(0, value.length() - 6))
                            .forEach(result::add);
                }
                return Set.copyOf(result);
            }
            if (!Files.isRegularFile(targetJar)) {
                return Set.of();
            }
            try (java.util.jar.JarFile jar = new java.util.jar.JarFile(targetJar.toFile())) {
                var entries = jar.entries();
                while (entries.hasMoreElements()) {
                    String name = entries.nextElement().getName();
                    String className = primaryArtifactClass(name);
                    if (className != null) {
                        result.add(className);
                    }
                }
            }
        } catch (Exception | LinkageError ignored) {
            // Coverage is an optional ranking signal. A malformed/remote archive must not
            // disable verification or turn a static candidate into a rejection.
        }
        return Set.copyOf(result);
    }

    private static String primaryArtifactClass(String name) {
        if (name == null || !name.endsWith(".class")) {
            return null;
        }
        String value = name;
        if (value.startsWith("BOOT-INF/classes/")) {
            value = value.substring("BOOT-INF/classes/".length());
        } else if (value.startsWith("WEB-INF/classes/")) {
            value = value.substring("WEB-INF/classes/".length());
        } else if (value.indexOf('/') >= 0 && !value.startsWith("META-INF/")) {
            // Root-level classes are valid ordinary JAR entries. Nested library entries are
            // deliberately ignored because their prefix is BOOT-INF/lib/ or WEB-INF/lib/.
            if (value.startsWith("BOOT-INF/") || value.startsWith("WEB-INF/")) {
                return null;
            }
        }
        if (value.startsWith("META-INF/")) {
            return null;
        }
        return value.substring(0, value.length() - ".class".length());
    }

    /** 批量并行验证。 */
    public List<VerifyResult> verifyAll(List<Chain> chains) {
        if (chains == null || chains.isEmpty()) {
            capability = "NOT_RUN";
            return List.of();
        }
        AdaptiveParallelism.Decision decision = AdaptiveParallelism.choose(chains.size(), MAX_PARALLELISM);
        AdaptiveParallelism.Lease lease = AdaptiveParallelism.reserve(decision);
        ExecutorService pool = Executors.newFixedThreadPool(Math.min(lease.workers(), chains.size()));
        try {
            List<VerifyResult> first = runBatch(chains, pool, 1);
            List<Integer> retryIndexes = new ArrayList<>();
            List<Chain> retryChains = new ArrayList<>();
            for (int i = 0; i < first.size(); i++) {
                VerifyResult result = first.get(i);
                if (retryable(result)) {
                    retryIndexes.add(i);
                    retryChains.add(chains.get(i));
                }
            }
            // 只重试进程/调度超时。运行时不可用、沙箱不可用、输出超限等结果是
            // 确定性状态；重试只会把验证预算翻倍而不会增加证据。
            List<VerifyResult> retryResults = runBatch(retryChains, pool, 2);
            for (int i = 0; i < retryIndexes.size(); i++) {
                int originalIndex = retryIndexes.get(i);
                VerifyResult retry = retryResults.get(i);
                if (retry != null && !"verification-future-timeout".equals(retry.detail())) {
                    first.set(originalIndex, retry);
                }
            }
            updateCapability(first);
            return first;
        } finally {
            pool.shutdownNow();
            try {
                pool.awaitTermination(2, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
            }
            lease.close();
        }
    }

    public String capability() {
        return capability;
    }

    private void updateCapability(List<VerifyResult> results) {
        if (results == null || results.isEmpty()) {
            capability = "NOT_RUN";
            return;
        }
        boolean sandboxUnavailable = false;
        boolean runtimeUnavailable = false;
        for (VerifyResult result : results) {
            if (result == null) {
                continue;
            }
            if (result.statusCode() != VerifyStatus.UNTESTABLE) {
                // A child that reached PARTIAL/FAILED/TIMEOUT crossed the sandbox
                // installation point; the result is evidence about the target run.
                capability = "JVM_SANDBOX";
                return;
            }
            String detail = result.detail() == null ? "" : result.detail();
            if (detail.startsWith("SANDBOX_UNAVAILABLE")) {
                sandboxUnavailable = true;
            }
            if (detail.contains("no-compatible-jdk")
                    || detail.contains("runtime-jdk-too-old")
                    || detail.contains("verifier-artifact-missing")
                    || detail.contains("CANARY_ARTIFACT_MISSING")) {
                runtimeUnavailable = true;
            }
        }
        if (sandboxUnavailable) {
            capability = "JVM_SANDBOX_UNAVAILABLE";
        } else if (runtimeUnavailable) {
            capability = "JVM_RUNTIME_UNAVAILABLE";
        } else {
            capability = "UNTESTABLE";
        }
    }

    private static boolean retryable(VerifyResult result) {
        return result != null && (result.statusCode() == VerifyStatus.TIMEOUT
                || (result.statusCode() == VerifyStatus.UNTESTABLE
                && "verification-future-timeout".equals(result.detail())));
    }

    private record IndexedResult(int index, VerifyResult result) {
    }

    /**
     * 完成队列收集一批 fork 任务。单个验证器内部已有进程级硬超时；这里的 grace 只防止
     * Future/线程异常造成永久等待。结果槽按输入序号填充，避免完成顺序影响报告确定性。
     */
    private List<VerifyResult> runBatch(List<Chain> chains, ExecutorService pool, int attempt) {
        if (chains.isEmpty()) {
            return List.of();
        }
        ExecutorCompletionService<IndexedResult> completion = new ExecutorCompletionService<>(pool);
        Map<Future<IndexedResult>, Integer> pending = new HashMap<>();
        List<VerifyResult> results = new ArrayList<>(Collections.nCopies(chains.size(), null));
        for (int i = 0; i < chains.size(); i++) {
            final int index = i;
            Future<IndexedResult> future = completion.submit(
                    () -> new IndexedResult(index, verifyOne(chains.get(index), attempt)));
            pending.put(future, index);
        }
        while (!pending.isEmpty()) {
            Future<IndexedResult> future;
            try {
                future = completion.poll(TIMEOUT_SECONDS + FUTURE_GRACE_SECONDS, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
            if (future == null) {
                break;
            }
            Integer expectedIndex = pending.remove(future);
            if (expectedIndex == null) {
                continue;
            }
            try {
                IndexedResult completed = future.get();
                results.set(completed.index(), completed.result());
            } catch (Exception e) {
                Chain chain = chains.get(expectedIndex);
                results.set(expectedIndex, new VerifyResult(chain.key(), "UNTESTABLE",
                        e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage(),
                        attempt, 0L));
            }
        }
        for (Map.Entry<Future<IndexedResult>, Integer> entry : pending.entrySet()) {
            entry.getKey().cancel(true);
            int index = entry.getValue();
            Chain chain = chains.get(index);
            results.set(index, new VerifyResult(chain.key(), "UNTESTABLE", "verification-future-timeout",
                    attempt, (long) (TIMEOUT_SECONDS + FUTURE_GRACE_SECONDS) * 1000));
        }
        return results;
    }

    /** 入口类型 → 探针模式（触发忠实：hashCode 经 HashMap.put、compareTo 经两元素 TreeSet、
     * Comparator.compare 经 Comparator 容器、equals 经 List.contains、readObject 族经序列化往返、
     * 代理经 newProxyInstance）。 */
    static String modeOf(String entryKind) {
        return switch (entryKind) {
            case "proxyInvoke" -> "PROXY";
            case "readObject", "readObjectNoData", "readExternal", "readResolve" -> "SERIAL";
            case "hashCode" -> "TRIGGER_HASH";
            case "compareTo" -> "TRIGGER_COMPARETO";
            case "compare" -> "TRIGGER_COMPARATOR";
            case "equals" -> "TRIGGER_CONTAINS";
            // Framework deserialization bridges are ordinary object-input boundaries. Invoke
            // them with bounded in-memory values rather than the zero-argument DIRECT path;
            // this is generic for setter/reader signatures and does not assume a target name.
            case "source", "deserialize", "deserialization" -> "SOURCE";
            default -> "DIRECT";
        };
    }

    private VerifyResult verifyOne(Chain chain, int attempt) {
        long started = System.nanoTime();
        VerifyResult result = verifyOneInternal(chain);
        return new VerifyResult(result.chainKey(), result.status(), result.detail(),
                attempt,
                Math.max(result.durationMs(),
                        TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)),
                result.evidence());
    }

    private VerifyResult verifyOneInternal(Chain chain) {
        Path isoDir = null;
        Process proc = null;
        try {
            RuntimeSelection runtime = selectRuntime();
            if (!runtime.available()) {
                return new VerifyResult(chain.key(), "UNTESTABLE", runtime.reason());
            }
            String entryDotted = chain.entryClass().replace('/', '.');
            String entryMethod = chain.entryMethod();
            String mode = modeOf(chain.entryKind());
            String entryDescriptor = entryDescriptor(chain);

            String sinkDescriptor = sinkDescriptor(chain);
            String sinkTarget = chain.sinkClass().replace('/', '.') + "." + chain.sinkMethod()
                    + (sinkDescriptor.isEmpty() ? "" : "|" + sinkDescriptor);
            Path javaExecPath = javaExecutable(runtime.javaHome());
            String javaExec = javaExecPath.toString();
            List<Path> classpath = runtimeClasspath(runtime.probeJar());
            String cp = runtime.probeJar().toAbsolutePath().normalize().toString();
            String targetCp = classpath.stream()
                    .filter(entry -> !entry.toAbsolutePath().normalize()
                            .equals(runtime.probeJar().toAbsolutePath().normalize()))
                    .map(Path::toString)
                    .collect(java.util.stream.Collectors.joining(File.pathSeparator));
            Path canaryBootstrap = runtime.feature() < 17
                    ? legacyBootstrapCanaryJar(runtime.probeJar()) : bootstrapCanaryJar();
            if (!Files.isRegularFile(canaryBootstrap)) {
                // A passive fallback would turn a missing canary artifact into an apparently
                // successful child run. Dynamic verification is evidence-producing, so fail
                // closed before any target class is loaded when the exact boundary is absent.
                return new VerifyResult(chain.key(), "UNTESTABLE",
                        "CANARY_ARTIFACT_MISSING:" + canaryBootstrap);
            }

            // sink canary 插桩：本链 sink 方法入口注入门卫调用（见 SinkCanaryAgent）；
            // 门卫按调用栈判定，JVM/探针基础设施的同名调用被放行
            String agentSpec = chain.sinkClass() + "#" + chain.sinkMethod()
                    + (sinkDescriptor.isEmpty() ? "" : "#" + sinkDescriptor);
            String entrySpec = entryDotted + "#" + entryMethod;
            // The result marker and the bytecode canary share one per-child capability token.
            String protocolToken = UUID.randomUUID().toString();
            FieldDependencyPlan plan = FieldDependencyPlan.from(
                    chain, mode);

            // 沙箱参数：隔离工作目录/tmpdir/home、净化环境、子 JVM 限核与内存上限；
            // fork-per-chain 保持类隔离——静态状态不跨链污染。SecurityManager 只在 JDK
            // 17--23 可用时启用；JDK 24+ 的探针会安全地报告不可验证，不执行目标代码。
            isoDir = Files.createTempDirectory("just-verify-");
            Path isoTmp = Files.createDirectories(isoDir.resolve("tmp"));
            List<String> command = new ArrayList<>();
            command.add(javaExec);
            command.add("-Xmx256m");
            command.add("-XX:+ExitOnOutOfMemoryError");
            command.add("-XX:+DisableAttachMechanism");
            command.add("-XX:MaxDirectMemorySize=64m");
            // ActiveProcessorCount was added after the Java 8 line. Do not pass an unknown
            // VM option to the legacy verifier; SerialGC still bounds helper GC threads there.
            if (runtime.feature() >= 10) {
                command.add("-XX:ActiveProcessorCount=1");
            }
            command.add("-Xss1m");
            command.add("-XX:+UseSerialGC");
            command.add(runtime.feature() >= 8
                    ? "-XX:MaxMetaspaceSize=128m" : "-XX:MaxPermSize=128m");
            if (securityManagerFlagSupported(runtime.feature())) {
                command.add("-Djava.security.manager=allow");
            }
            command.add("-Djava.io.tmpdir=" + isoTmp);
            command.add("-Duser.dir=" + isoDir);
            command.add("-Duser.home=" + isoDir);
            command.add("-Duser.name=just-sandbox");
            command.add("-Duser.language=en");
            command.add("-Duser.country=US");
            command.add("-Djava.util.prefs.userRoot=" + isoDir.resolve("prefs"));
            command.add("-Djava.util.prefs.systemRoot=" + isoDir.resolve("system-prefs"));
            command.add("-Djust.verify.sanitized-env=true");
            command.add("-Djava.awt.headless=true");
            command.add("-Djava.net.useSystemProxies=false");
            // The probe jar must remain in the launcher loader for the agent/main class, but
            // target classes are loaded through a separate URLClassLoader. Tell the probe which
            // classpath entry to omit so target code cannot resolve Just helper classes through
            // its context loader.
            command.add("-Djust.verify.probe-jar=" + runtime.probeJar().toAbsolutePath());
            command.add("-Djust.verify.target-cp=" + targetCp);
            if (runtime.feature() < 17) {
                // The Java 17 scanner jar cannot be loaded by an old target JVM. The separate
                // verifier8 artifact contains only Java 8-compatible probe/agent classes.
                command.add("-javaagent:" + runtime.probeJar().toAbsolutePath()
                        + "=" + canaryBootstrap + "|"
                        + entrySpec + "|" + agentSpec + "|" + protocolToken);
            } else {
                command.add("-javaagent:" + runtime.probeJar().toAbsolutePath() + "="
                        + canaryBootstrap + "|" + entrySpec + "|" + agentSpec + "|"
                        + protocolToken);
            }
            command.add("-cp");
            command.add(cp);
            command.add(runtime.feature() < 17
                    ? "io.just.sast.verify.legacy.LegacyChainVerifyProbe"
                    : "io.just.sast.verify.ChainVerifyProbe");
            command.add(entryDotted + "|" + entryMethod + "|" + mode + "|" + entryDescriptor);
            command.add(plan.encodedFieldsForProbe());
            command.add(sinkTarget);
            // An unresolved reflective target is a request for a bounded, sink-derived
            // data shape in the child probe. It is an internal protocol bit, not a public
            // scanner option; the probe still treats every value as inert in-memory data.
            command.add(chain.unresolvedHops() > 0 ? "UNRESOLVED" : "");
            // Source-host chains carry a semantic trigger edge. The probe may use it to
            // build an in-memory callback collection for the source boundary; this is a
            // verification adapter only and never writes an attacker payload artifact.
            command.add(sourceTriggerSpec(chain));
            // The result marker is correlated per child attempt. Target stdout/stderr is
            // diagnostic only and cannot be parsed as a verification state.
            command.add(protocolToken);
            ProcessBuilder pb = new ProcessBuilder(command);
            pb.directory(isoDir.toFile());
            pb.redirectErrorStream(true);
            pb.environment().clear();
            pb.environment().putAll(sanitizedEnvironment(System.getenv(),
                    runtime.javaHome(), isoDir, isoTmp));
            proc = pb.start();
            OutputCapture capture = new OutputCapture(proc.getInputStream(), MAX_OUTPUT_BYTES);
            Thread outputReader = new Thread(capture, "just-verify-output");
            outputReader.setDaemon(true);
            outputReader.start();
            // 先 waitFor 再读输出：子 JVM 挂起且未关 stdout 时，readAllBytes 会永久阻塞，
            // 超时判定必须先行；独立 reader 同时排空管道，目标即使刷屏也不会把验证器卡在
            // OS 管道上，内存只保留有界诊断。
            boolean finished = proc.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            if (!finished) {
                killProcessTree(proc);
                outputReader.join(1_000L);
                return new VerifyResult(chain.key(), "TIMEOUT", TIMEOUT_SECONDS + "s");
            }
            outputReader.join(1_000L);
            String output = capture.text();
            if (capture.overflow()) {
                return new VerifyResult(chain.key(), "UNTESTABLE", "probe-output-limit");
            }
            // redirectErrorStream 合并了 stderr。只接受带本次 token 的 probe marker；目标
            // 工件可以任意写 stdout/stderr，普通文本永远不能升级为动态证据。
            String firstLine = null;
            String firstAny = null;
            for (String line : output.split("\\R")) {
                String trimmed = line.strip();
                if (trimmed.isEmpty()) {
                    continue;
                }
                if (firstAny == null) {
                    firstAny = trimmed;
                }
                String status = authenticatedStatus(trimmed, protocolToken);
                if (status != null) {
                    firstLine = status;
                    break;
                }
            }
            if (firstLine == null) firstLine = "";
            if (firstLine.startsWith("SINK_BLOCKED") || firstLine.startsWith("SINK_TRIGGERED")) {
                if (callback != null) callback.onConfirmed(chain, firstLine, true);
                return new VerifyResult(chain.key(), "SINK_BLOCKED", "SINK_CANARY_BOUNDARY",
                        1, 0L, "SINK_CANARY_BOUNDARY");
            }
            if (firstLine.startsWith("CONCRETE_REACHED")) {
                return new VerifyResult(chain.key(), "CONCRETE_REACHED", firstLine,
                        1, 0L, "CONCRETE_TRIGGER");
            }
            if (firstLine.startsWith("EXECUTED")) {
                // 入口方法真实调用且正常返回——链可执行，但未证伪/证实 sink 到达
                return new VerifyResult(chain.key(), "EXECUTED", firstLine);
            }
            if (firstLine.startsWith("PARTIAL_PATH")) {
                return new VerifyResult(chain.key(), "PARTIAL", firstLine);
            }
            if (firstLine.startsWith("SANDBOX_UNAVAILABLE")) {
                return new VerifyResult(chain.key(), "UNTESTABLE", firstLine);
            }
            if (firstLine.startsWith("UNTESTABLE")) {
                return new VerifyResult(chain.key(), "UNTESTABLE", firstLine);
            }
            int exit = proc.exitValue();
            if (exit != 0) {
                return new VerifyResult(chain.key(), "PARTIAL",
                        "exit=" + exit + " probe-no-authenticated-status"
                                + (firstAny == null ? "" : " diagnostic=" + firstAny));
            }
            return new VerifyResult(chain.key(), "FAILED",
                    "no-authenticated-probe-status"
                            + (firstAny == null ? "" : " diagnostic=" + firstAny));

        } catch (Exception e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            return new VerifyResult(chain.key(), "UNTESTABLE",
                    e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName());
        } finally {
            // A target is denied Runtime.exec/ProcessBuilder, but a library can still create
            // an already-running descendant before the permission gate is consulted. Always
            // perform the bounded cleanup pass after normal exit as well as on timeout; the
            // cleanup routine only invokes taskkill while the root is alive, avoiding PID reuse
            // races for an already-reaped process.
            if (proc != null) {
                killProcessTree(proc);
            }
            // 每条链一个隔离 cwd/tmp；不能只清理共享的 fat-jar 展开目录，否则批量扫描会
            // 在系统临时目录留下大量 just-verify-* 目录。
            deleteQuietly(isoDir);
        }
    }

    /** Extract only a status emitted by the probe for this exact child attempt. */
    static String authenticatedStatus(String line, String token) {
        if (line == null || token == null || token.isBlank()) {
            return null;
        }
        String prefix = "JUST_VERIFY_V1:" + token + ":";
        if (!line.startsWith(prefix)) {
            return null;
        }
        String status = line.substring(prefix.length());
        return isProtocolStatus(status) ? status : null;
    }

    private static boolean isProtocolStatus(String status) {
        return status.startsWith("SINK_BLOCKED") || status.startsWith("SINK_TRIGGERED")
                || status.startsWith("CONCRETE_REACHED") || status.startsWith("EXECUTED")
                || status.startsWith("SANDBOX_UNAVAILABLE") || status.startsWith("UNTESTABLE")
                || status.startsWith("PARTIAL_PATH");
    }

    /** 优先使用 Chain 的真实 sink 描述符；兼容旧构造的 Chain 时从调用跳回退推断。 */
    private static String sinkDescriptor(Chain chain) {
        if (chain.sinkDescriptor() != null && !chain.sinkDescriptor().isEmpty()) {
            return chain.sinkDescriptor();
        }
        for (ChainHop hop : chain.hops()) {
            if (chain.sinkClass().equals(hop.toOwner()) && chain.sinkMethod().equals(hop.toName())
                    && hop.desc() != null && !hop.desc().isEmpty()) {
                return hop.desc();
            }
        }
        return "";
    }

    /** 入口跳携带真实描述符；没有时保持旧链构造的兼容行为。 */
    private static String entryDescriptor(Chain chain) {
        for (ChainHop hop : chain.hops()) {
            if (hop.kind() == HopKind.ENTRY
                    && chain.entryClass().equals(hop.toOwner())
                    && chain.entryMethod().equals(hop.toName())
                    && hop.desc() != null && !hop.desc().isEmpty()) {
                return hop.desc();
            }
        }
        return "";
    }

    /** Encode a source-host trigger edge for the safe in-memory source adapter. */
    static String sourceTriggerSpec(Chain chain) {
        if (chain == null || !isSourceEntryKind(chain.entryKind())) {
            return "";
        }
        ChainHop trigger = null;
        ChainHop source = null;
        int triggerIndex = -1;
        for (int i = 0; i < chain.hops().size(); i++) {
            ChainHop hop = chain.hops().get(i);
            if ("bridge-trigger-src".equals(hop.reason())) {
                trigger = hop;
                triggerIndex = i;
            } else if ("bridge-source-deserialize".equals(hop.reason())) {
                source = hop;
            }
        }
        if (trigger == null || source == null) {
            // A direct framework source is represented by an ordinary call edge rather than
            // the synthetic source-host bridge.  Still carry the parsed source boundary to
            // the child so a String/byte[] parameter can receive a valid, bounded in-memory
            // stream (for example Kryo.readClassAndObject or ObjectInputStream.readObject).
            // The adapter class is a JDK collection, never a target gadget, and the callback
            // is inert; no benchmark or application name is consulted here.
            ChainHop directSource = null;
            int directSourceIndex = -1;
            // Hops are stored sink→entry and a source seed is not necessarily represented by
            // an explicit entry→source call edge.  Keep the last parsed OIS/Kryo read edge,
            // which is the one closest to the source boundary in that ordering.
            for (int i = 0; i < chain.hops().size(); i++) {
                ChainHop hop = chain.hops().get(i);
                if (isDirectSourceMethod(hop.toOwner(), hop.toName())) {
                    directSource = hop;
                    directSourceIndex = i;
                } else if (isDirectSourceMethod(hop.fromOwner(), hop.fromName())) {
                    directSource = new ChainHop(hop.fromOwner(), hop.fromName(),
                            hop.fromOwner(), hop.fromName(), hop.kind(), hop.field(),
                            hop.reason(), hop.desc(), hop.argOrdinal());
                    directSourceIndex = i;
                }
            }
            if (directSource == null) {
                return "";
            }
            ChainHop callback = callbackAfterSource(chain.hops(), directSourceIndex);
            if (callback != null) {
                String kind = callbackKind(callback.toName());
                return String.join("|", callback.toOwner(), callback.toName(), kind,
                        directSource.toOwner(), directSource.toName(),
                        directSource.desc() == null ? "" : directSource.desc(), "", "");
            }
            return String.join("|", "java/util/ArrayList", "toString", "toString",
                    directSource.toOwner(), directSource.toName(),
                    directSource.desc() == null ? "" : directSource.desc(), "", "");
        }
        String kind = switch (trigger.toName()) {
            case "hashCode" -> "hashCode";
            case "equals" -> "equals";
            case "compareTo" -> "compareTo";
            case "compare" -> "compare";
            case "toString" -> "toString";
            default -> "";
        };
        if (kind.isEmpty()) {
            return "";
        }
        // Hops are stored sink -> entry. The nearest ordinary hop before the source bridge
        // describes the first downstream object that the callback must reach (for example a
        // bean wrapper after an EqualsBean). Carry only that semantic boundary to the child;
        // the adapter remains bounded and does not need package/benchmark knowledge.
        ChainHop downstream = null;
        if (triggerIndex > 0) {
            for (int i = triggerIndex - 1; i >= 0; i--) {
                ChainHop candidate = chain.hops().get(i);
                if (!"bridge-source-deserialize".equals(candidate.reason())
                        && !"bridge-trigger-src".equals(candidate.reason())) {
                    downstream = candidate;
                    break;
                }
            }
        }
        String downstreamOwner = downstream == null ? "" : downstream.toOwner();
        String downstreamMethod = downstream == null ? "" : downstream.toName();
        return String.join("|", trigger.toOwner(), trigger.toName(), kind,
                source.toOwner(), source.toName(), source.desc() == null ? "" : source.desc(),
                downstreamOwner == null ? "" : downstreamOwner,
                downstreamMethod == null ? "" : downstreamMethod);
    }

    /**
     * Recover the first callback immediately downstream of a direct source from the reverse
     * path. This is the small reusable part of JDD's IOCD-guided construction: the source
     * adapter can serialize a callback object in a matching inert container instead of always
     * serializing an unrelated ArrayList. If no callback is represented, the conservative
     * generic adapter remains in use.
     */
    private static ChainHop callbackAfterSource(List<ChainHop> hops, int sourceIndex) {
        if (hops == null || sourceIndex <= 0) {
            return null;
        }
        for (int i = sourceIndex - 1; i >= 0; i--) {
            ChainHop candidate = hops.get(i);
            if (callbackKind(candidate.toName()) != null
                    && candidate.toOwner() != null && !candidate.toOwner().isBlank()) {
                return candidate;
            }
            if (callbackKind(candidate.fromName()) != null
                    && candidate.fromOwner() != null && !candidate.fromOwner().isBlank()) {
                return new ChainHop(candidate.toOwner(), candidate.toName(),
                        candidate.fromOwner(), candidate.fromName(), candidate.kind(),
                        candidate.field(), candidate.reason(), candidate.desc(), candidate.argOrdinal());
            }
        }
        return null;
    }

    private static String callbackKind(String method) {
        if (method == null) {
            return null;
        }
        return switch (method) {
            case "hashCode", "equals", "compareTo", "compare", "toString" -> method;
            default -> null;
        };
    }

    private static boolean isSourceEntryKind(String entryKind) {
        return switch (entryKind == null ? "" : entryKind) {
            case "source", "deserialize", "deserialization" -> true;
            default -> false;
        };
    }

    private static boolean isDirectSourceMethod(String owner, String method) {
        if (owner == null || method == null) {
            return false;
        }
        if (owner.equals("java/io/ObjectInputStream")) {
            return method.equals("readObject") || method.equals("readUnshared")
                    || method.equals("readFields");
        }
        return owner.startsWith("com/esotericsoftware/kryo/")
                && method.startsWith("read");
    }


    /** 统一构造子进程 classpath；展开只做一次，避免每条链重复扫描/解包。 */
    private List<Path> runtimeClasspath(Path probeJar) throws java.io.IOException {
        NestedClasspath cached = expandedClasspath;
        if (cached != null) {
            return cached.entries();
        }
        synchronized (this) {
            cached = expandedClasspath;
            if (cached == null) {
                List<Path> inputs = new ArrayList<>();
                inputs.add(probeJar);
                inputs.add(targetJar);
                inputs.addAll(deps);
                cached = NestedClasspath.open(inputs);
                expandedClasspath = cached;
            }
            return cached.entries();
        }
    }

    private static Path locateOwnJar() {
        try {
            return Path.of(ParallelVerifier.class.getProtectionDomain()
                    .getCodeSource().getLocation().toURI()).toAbsolutePath();
        } catch (Exception e) {
            return Path.of(".");
        }
    }

    /** JDK 24 起 -Djava.security.manager=allow 本身就是启动错误，不能盲目传入。 */
    static boolean securityManagerFlagSupported() {
        return Runtime.version().feature() < 24;
    }

    private static boolean securityManagerFlagSupported(int feature) {
        return feature >= 17 && feature < 24;
    }

    private RuntimeSelection selectRuntime() {
        int required = requiredFeature(targetMajorVersion);
        int currentFeature = Runtime.version().feature();
        Path currentHome = Paths.get(System.getProperty("java.home", "."))
                .toAbsolutePath().normalize();

        if (targetJdkHome != null && Files.isRegularFile(javaExecutable(targetJdkHome))) {
            int requestedFeature = jdkFeature(targetJdkHome);
            if (requestedFeature > 0 && requestedFeature >= required) {
                Path probe = probeJarFor(requestedFeature);
                if (probe != null) {
                    return new RuntimeSelection(targetJdkHome, probe, requestedFeature,
                            "requested-target-jdk");
                }
                return new RuntimeSelection(null, null, requestedFeature,
                        "verifier-artifact-missing");
            }
            // A JDK older than the target class version cannot even load the target. If the
            // scanner JVM can, use it as a transparent compatibility fallback and let the
            // report retain its existing JDK approximation reason.
            if (currentFeature >= required) {
                Path probe = probeJarFor(currentFeature);
                if (probe != null) {
                    return new RuntimeSelection(currentHome, probe, currentFeature,
                            "requested-jdk-too-old-fallback-runtime");
                }
            }
            return new RuntimeSelection(null, null, requestedFeature,
                    "no-compatible-jdk");
        }
        if (currentFeature < required) {
            return new RuntimeSelection(null, null, currentFeature, "runtime-jdk-too-old");
        }
        Path probe = probeJarFor(currentFeature);
        return probe == null
                ? new RuntimeSelection(null, null, currentFeature, "verifier-artifact-missing")
                : new RuntimeSelection(currentHome, probe, currentFeature, "runtime-jdk");
    }

    private Path probeJarFor(int feature) {
        if (feature < 17) {
            Path legacy = ownJar.resolveSibling("just-sast-0.2.0-verify8.jar");
            return Files.isRegularFile(legacy) ? legacy : null;
        }
        return Files.isRegularFile(ownJar) ? ownJar : null;
    }

    private static Path javaExecutable(Path javaHome) {
        Path unix = javaHome.resolve("bin").resolve("java");
        Path windows = javaHome.resolve("bin").resolve("java.exe");
        return Files.isRegularFile(windows) ? windows : unix;
    }

    private static int requiredFeature(int major) {
        return major >= 45 ? Math.max(1, major - 44) : 0;
    }

    /** JDK 9+ and legacy JDK distributions both ship a release metadata file. */
    static int jdkFeature(Path javaHome) {
        Path release = javaHome.resolve("release");
        if (Files.isRegularFile(release)) {
            try {
                for (String line : Files.readAllLines(release, StandardCharsets.UTF_8)) {
                    if (!line.startsWith("JAVA_VERSION=")) {
                        continue;
                    }
                    String value = line.substring("JAVA_VERSION=".length())
                            .replace("\"", "").trim();
                    if (value.startsWith("1.")) {
                        value = value.substring(2);
                    }
                    int dot = value.indexOf('.');
                    int dash = value.indexOf('-');
                    int end = value.length();
                    if (dot >= 0) end = Math.min(end, dot);
                    if (dash >= 0) end = Math.min(end, dash);
                    return Integer.parseInt(value.substring(0, end));
                }
            } catch (Exception ignored) {
                // Fall through to the executable/current runtime check.
            }
        }
        Path current = Paths.get(System.getProperty("java.home", "."))
                .toAbsolutePath().normalize();
        return current.equals(javaHome.toAbsolutePath().normalize())
                ? Runtime.version().feature() : -1;
    }

    /** 子进程不继承调用者的密钥、代理、构建工具和注入 JVM 参数，只保留启动所需环境。 */
    static Map<String, String> sanitizedEnvironment(Map<String, String> parent,
                                                    Path javaHome, Path isoDir, Path isoTmp) {
        Map<String, String> result = new HashMap<>();
        String osName = System.getProperty("os.name", "").toLowerCase(java.util.Locale.ROOT);
        if (osName.contains("win")) {
            copyIfPresent(parent, result, "SystemRoot");
            copyIfPresent(parent, result, "SystemDrive");
            copyIfPresent(parent, result, "WINDIR");
            // 绝对 java 路径已用于启动；这个最小 PATH 只供 JVM 自身的 DLL/工具查找，
            // 不携带用户目录和包管理器凭据路径。
            result.put("PATH", javaHome.resolve("bin").toString());
            result.put("TEMP", isoTmp.toString());
            result.put("TMP", isoTmp.toString());
            result.put("USERPROFILE", isoDir.toString());
        } else {
            result.put("PATH", "/usr/bin:/bin");
            result.put("HOME", isoDir.toString());
            result.put("TMPDIR", isoTmp.toString());
            result.put("TEMP", isoTmp.toString());
            result.put("TMP", isoTmp.toString());
        }
        result.put("NO_COLOR", "1");
        result.put("LANG", "C");
        return Map.copyOf(result);
    }

    private static void copyIfPresent(Map<String, String> parent, Map<String, String> result, String key) {
        if (parent != null) {
            String value = parent.get(key);
            if (value != null && !value.isBlank()) {
                result.put(key, value);
            }
        }
    }

    /** 子进程可能绕过 Java 级门产生后代；超时/收尾时先终止后代再终止根进程。 */
    static void killProcessTree(Process process) {
        if (process == null) {
            return;
        }
        try {
            ProcessHandle root = process.toHandle();
            List<ProcessHandle> snapshot = new ArrayList<>();
            root.descendants().forEach(snapshot::add);
            // ProcessHandle.descendants() is a snapshot and can miss a child that is being
            // spawned during timeout cleanup. Windows' built-in tree termination closes that
            // race for the root PID; the ProcessHandle path remains the portable fallback.
            if (isWindows() && process.isAlive()) {
                try {
                    Process taskkill = new ProcessBuilder("taskkill", "/PID",
                            Long.toString(root.pid()), "/T", "/F")
                            .redirectErrorStream(true).start();
                    taskkill.waitFor(1, TimeUnit.SECONDS);
                } catch (IOException | InterruptedException ignored) {
                    if (ignored instanceof InterruptedException) {
                        Thread.currentThread().interrupt();
                    }
                }
            }
            snapshot.forEach(child -> {
                try {
                    child.destroyForcibly();
                } catch (RuntimeException ignored) {
                }
            });
            // Re-snapshot after taskkill: descendants created in the small timeout-cleanup
            // window are not necessarily present in the first snapshot.
            root.descendants().forEach(child -> {
                try {
                    child.destroyForcibly();
                } catch (RuntimeException ignored) {
                }
            });
            if (process.isAlive()) {
                process.destroyForcibly();
            }
            process.waitFor(1, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (RuntimeException ignored) {
            try {
                if (process.isAlive()) {
                    process.destroyForcibly();
                }
            } catch (RuntimeException ignoredAgain) {
            }
        }
    }

    private static boolean isWindows() {
        return System.getProperty("os.name", "")
                .toLowerCase(Locale.ROOT).contains("win");
    }

    /** 有界 stdout/stderr 收集器：持续排空管道，避免恶意目标通过输出造成阻塞。 */
    private static final class OutputCapture implements Runnable {
        private final java.io.InputStream input;
        private final int limit;
        private final java.io.ByteArrayOutputStream output = new java.io.ByteArrayOutputStream();
        private volatile boolean overflow;

        private OutputCapture(java.io.InputStream input, int limit) {
            this.input = input;
            this.limit = limit;
        }

        @Override
        public void run() {
            byte[] buffer = new byte[8192];
            try {
                for (int read; (read = input.read(buffer)) >= 0; ) {
                    synchronized (output) {
                        int remaining = limit - output.size();
                        if (remaining > 0) {
                            output.write(buffer, 0, Math.min(remaining, read));
                        }
                        if (read > remaining) {
                            overflow = true;
                        }
                    }
                }
            } catch (java.io.IOException ignored) {
                // 进程被强杀时关闭管道是正常收尾，不改变已有超时/不可验证结论。
            }
        }

        private String text() {
            synchronized (output) {
                return output.toString(StandardCharsets.UTF_8);
            }
        }

        private boolean overflow() {
            return overflow;
        }
    }

    /**
     * sink canary 的最小 bootstrap jar（仅含 SinkReachedError.class）：插桩 java.base sink
     * 时标记类必须对 bootstrap 可见。从自身 jar/class 目录提取类文件现场生成，进程内缓存。
     */
    private Path bootstrapCanaryJar() {
        Path jar = bootstrapJar;
        if (jar != null) {
            return jar;
        }
        synchronized (this) {
            if (bootstrapJar != null) {
                return bootstrapJar;
            }
            try {
                String marker = "/io/just/sast/verify/boot/SinkReachedError.class";
                String gate = "/io/just/sast/verify/boot/SinkCanaryGate.class";
                try (var in = ParallelVerifier.class.getResourceAsStream(marker);
                     var gin = ParallelVerifier.class.getResourceAsStream(gate)) {
                    if (in == null || gin == null) {
                        // 资源缺失（异常构建）：返回不存在路径，由调用方 fail closed
                        return Path.of(System.getProperty("java.io.tmpdir"), "just-missing-boot.jar");
                    }
                    Path out = Files.createTempFile("just-canary-boot-", ".jar");
                    try (var zip = new java.util.zip.ZipOutputStream(
                            Files.newOutputStream(out))) {
                        zip.putNextEntry(new java.util.zip.ZipEntry(
                                "io/just/sast/verify/boot/SinkReachedError.class"));
                        in.transferTo(zip);
                        zip.closeEntry();
                        zip.putNextEntry(new java.util.zip.ZipEntry(
                                "io/just/sast/verify/boot/SinkCanaryGate.class"));
                        gin.transferTo(zip);
                        zip.closeEntry();
                    }
                    ownArtifacts.add(out);
                    bootstrapJar = out;
                    return out;
                }
            } catch (Exception e) {
                return Path.of(System.getProperty("java.io.tmpdir"), "just-missing-boot.jar");
            }
        }
    }

    public void cleanup() {
        List<Path> artifacts;
        synchronized (ownArtifacts) {
            artifacts = new ArrayList<>(ownArtifacts);
            ownArtifacts.clear();
        }
        bootstrapJar = null;
        legacyBootstrapJar = null;
        for (Path p : artifacts) {
            deleteQuietly(p);
        }
        NestedClasspath cp = expandedClasspath;
        expandedClasspath = null;
        targetDefinedClasses = null;
        if (cp != null) {
            cp.close();
        }
    }

    /**
     * The legacy agent itself must stay in the application loader: verify8 also contains its
     * package-private ASM transformer.  Only the two dependency-free canary classes belong to
     * bootstrap, otherwise the JVM may load the transformer from bootstrap and fail with an
     * IllegalAccessError before the probe starts.
     */
    private Path legacyBootstrapCanaryJar(Path probeJar) {
        Path cached = legacyBootstrapJar;
        if (cached != null) {
            return cached;
        }
        synchronized (this) {
            if (legacyBootstrapJar != null) {
                return legacyBootstrapJar;
            }
            try (java.util.jar.JarFile source = new java.util.jar.JarFile(probeJar.toFile())) {
                String gate = "io/just/sast/verify/legacy/LegacySinkCanaryGate.class";
                String marker = "io/just/sast/verify/legacy/LegacySinkReachedError.class";
                java.util.jar.JarEntry gateEntry = source.getJarEntry(gate);
                java.util.jar.JarEntry markerEntry = source.getJarEntry(marker);
                if (gateEntry == null || markerEntry == null) {
                    return Path.of(System.getProperty("java.io.tmpdir"),
                            "just-missing-legacy-canary-boot.jar");
                }
                Path out = Files.createTempFile("just-legacy-canary-boot-", ".jar");
                try (var zip = new java.util.zip.ZipOutputStream(Files.newOutputStream(out))) {
                    copyJarEntry(source, markerEntry, zip);
                    copyJarEntry(source, gateEntry, zip);
                }
                ownArtifacts.add(out);
                legacyBootstrapJar = out;
                return out;
            } catch (Exception e) {
                return Path.of(System.getProperty("java.io.tmpdir"),
                        "just-missing-legacy-canary-boot.jar");
            }
        }
    }

    private static void copyJarEntry(java.util.jar.JarFile source,
                                     java.util.jar.JarEntry entry,
                                     java.util.zip.ZipOutputStream zip) throws java.io.IOException {
        zip.putNextEntry(new java.util.zip.ZipEntry(entry.getName()));
        try (var input = source.getInputStream(entry)) {
            input.transferTo(zip);
        }
        zip.closeEntry();
    }

    private static void deleteQuietly(Path p) {
        if (p == null || !Files.exists(p)) {
            return;
        }
        if (Files.isDirectory(p)) {
            try (var walk = Files.walk(p)) {
                walk.sorted(Comparator.reverseOrder()).forEach(ParallelVerifier::deleteFileQuietly);
            } catch (Exception ignored) {
            }
        } else {
            deleteFileQuietly(p);
        }
    }

    private static void deleteFileQuietly(Path p) {
        try {
            Files.deleteIfExists(p);
        } catch (Exception ignored) {
        }
    }
}
