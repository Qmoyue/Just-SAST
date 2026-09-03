package io.just.sast.verify;

import io.just.sast.blackboard.Chain;
import io.just.sast.chain.ChainRanking;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.HopKind;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Set;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.LongAdder;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import io.just.sast.util.AdaptiveParallelism;
import io.just.sast.util.ArtifactFingerprint;

/**
 * 并行链级验证器：沿链 FIELD_FLOW 跳构造完整对象图 → 子进程执行 → sink 特异性判定。
 * 入口类去重（同一入口最多 2 条链），4 路并行，探针在 fat jar 中零逐链编译。
 */
public final class ParallelVerifier {

    /** Closed verifier lifecycle; the serialized string remains for report compatibility. */
    public enum VerifyStatus {
        SINK_BLOCKED, PRE_SINK_CONFIRMED, SINK_EXECUTED_SAFE, JNI_EXECUTED_SAFE, SAFE_EFFECT_OBSERVED,
        CONCRETE_REACHED, EXECUTED, PARTIAL, FAILED, TIMEOUT, UNTESTABLE, UNKNOWN;

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
                               int attempt, long durationMs, String evidence,
                               String backend, String jdk, String policyDigest,
                               boolean sinkDistorted, boolean sandboxReady,
                               String cleanup, String requestedMode, String effectiveMode,
                               String fallback, String verificationScope, String sinkRisk,
                               boolean terminalExecuted, String stopReason,
                               String lastConfirmedStage) {
        public VerifyResult(String chainKey, String status, String detail) {
            this(chainKey, status, detail, 1, 0L, defaultEvidence(status, detail));
        }

        public VerifyResult(String chainKey, String status, String detail,
                            int attempt, long durationMs) {
            this(chainKey, status, detail, attempt, durationMs, defaultEvidence(status, detail));
        }

        public VerifyResult(String chainKey, String status, String detail,
                            int attempt, long durationMs, String evidence) {
            this(chainKey, status, detail, attempt, durationMs, evidence,
                    "UNKNOWN", "UNKNOWN", "UNKNOWN", false, false, "UNKNOWN");
        }

        /** Compatibility constructor for the pre-schema runtime metadata shape. */
        public VerifyResult(String chainKey, String status, String detail,
                            int attempt, long durationMs, String evidence,
                            String backend, String jdk, String policyDigest,
                            boolean sinkDistorted, boolean sandboxReady,
                            String cleanup) {
            this(chainKey, status, detail, attempt, durationMs, evidence, backend, jdk,
                    policyDigest, sinkDistorted, sandboxReady, cleanup,
                    field(detail, "requested_mode", "UNKNOWN"),
                    field(detail, "effective_mode", "UNKNOWN"),
                    field(detail, "fallback", "none"), defaultScope(status), "UNKNOWN",
                    defaultTerminalExecuted(status), defaultStopReason(status, detail),
                    defaultLastStage(status));
        }

        public VerifyResult {
            chainKey = chainKey == null ? "" : chainKey;
            status = status == null ? "UNKNOWN" : status;
            detail = detail == null ? "" : detail;
            attempt = Math.max(1, attempt);
            durationMs = Math.max(0L, durationMs);
            evidence = evidence == null || evidence.isBlank()
                    ? defaultEvidence(status, detail) : evidence;
            backend = normalize(backend);
            jdk = normalize(jdk);
            policyDigest = normalize(policyDigest);
            cleanup = normalize(cleanup);
            requestedMode = normalize(requestedMode);
            effectiveMode = normalize(effectiveMode);
            fallback = normalize(fallback);
            verificationScope = normalize(verificationScope);
            sinkRisk = normalize(sinkRisk);
            stopReason = normalize(stopReason);
            lastConfirmedStage = normalize(lastConfirmedStage);
        }

        private static String normalize(String value) {
            return value == null || value.isBlank() ? "UNKNOWN" : value;
        }

        public VerifyStatus statusCode() {
            return VerifyStatus.from(status);
        }

        private static String defaultEvidence(String status, String detail) {
            return switch (VerifyStatus.from(status)) {
                case SINK_BLOCKED -> "SINK_CANARY_BOUNDARY";
                case PRE_SINK_CONFIRMED -> "PREFIX_CHAIN_CONFIRMED";
                case SINK_EXECUTED_SAFE -> "REAL_SINK_BODY_SAFE_ARGUMENTS";
                case JNI_EXECUTED_SAFE -> "JNI_LOAD_CALLBACK_SAFE_FIXTURE";
                case SAFE_EFFECT_OBSERVED -> "SAFE_EFFECT_OBSERVED";
                case CONCRETE_REACHED -> "CONCRETE_TRIGGER";
                case EXECUTED -> "ENTRY_RETURNED";
                case PARTIAL -> "PARTIAL_PATH";
                case TIMEOUT -> "PROCESS_TIMEOUT";
                case UNTESTABLE -> detail != null && detail.startsWith("SANDBOX_UNAVAILABLE")
                        ? "SANDBOX_UNAVAILABLE"
                        : detail != null && detail.startsWith("PROCESS_OOM")
                        ? "PROCESS_OOM"
                        : detail != null && detail.startsWith("PROBE_OUTPUT_LIMIT")
                        ? "PROBE_OUTPUT_LIMIT"
                        : detail != null && detail.startsWith("CANARY_ARTIFACT_MISSING")
                        ? "VERIFIER_ARTIFACT_MISSING" : "VERIFIER_CAPABILITY_LIMIT";
                case FAILED -> "NO_TRIGGER";
                default -> "UNKNOWN";
            };
        }

        private static String field(String detail, String name, String fallback) {
            if (detail == null) {
                return fallback;
            }
            String marker = name + "=";
            int start = detail.indexOf(marker);
            if (start < 0) {
                return fallback;
            }
            start += marker.length();
            int end = detail.indexOf(';', start);
            String value = end < 0 ? detail.substring(start) : detail.substring(start, end);
            return value.isBlank() ? fallback : value;
        }

        private static String defaultScope(String status) {
            return switch (VerifyStatus.from(status)) {
                case SINK_BLOCKED -> "BOUNDARY_ONLY";
                case PRE_SINK_CONFIRMED -> "PREFIX_ONLY";
                case SINK_EXECUTED_SAFE, JNI_EXECUTED_SAFE -> "TERMINAL_EXECUTED_SAFE";
                default -> "NONE";
            };
        }

        private static boolean defaultTerminalExecuted(String status) {
            VerifyStatus code = VerifyStatus.from(status);
            return code == VerifyStatus.SINK_EXECUTED_SAFE || code == VerifyStatus.JNI_EXECUTED_SAFE;
        }

        private static String defaultStopReason(String status, String detail) {
            return switch (VerifyStatus.from(status)) {
                case SINK_BLOCKED -> "SINK_BOUNDARY_CANARY";
                case PRE_SINK_CONFIRMED -> "HIGH_RISK_SINK";
                case SINK_EXECUTED_SAFE, JNI_EXECUTED_SAFE -> "SAFE_TERMINAL_RETURNED";
                case SAFE_EFFECT_OBSERVED -> "ADAPTER_EFFECT_ONLY";
                case TIMEOUT -> "PROCESS_TIMEOUT";
                case UNTESTABLE -> detail != null && detail.startsWith("SANDBOX_UNAVAILABLE")
                        ? "SANDBOX_UNAVAILABLE" : "UNTESTABLE";
                default -> "NONE";
            };
        }

        private static String defaultLastStage(String status) {
            return switch (VerifyStatus.from(status)) {
                case SINK_BLOCKED -> "SINK_BOUNDARY";
                case PRE_SINK_CONFIRMED -> "PRE_SINK";
                case SINK_EXECUTED_SAFE, JNI_EXECUTED_SAFE -> "SINK_RETURNED";
                case SAFE_EFFECT_OBSERVED -> "ADAPTER_EFFECT";
                case CONCRETE_REACHED -> "CONCRETE_TRIGGER";
                case EXECUTED -> "ENTRY_RETURNED";
                default -> "NONE";
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
    private static final String RESULT_CHANNEL_PREFIX = "JUST_VERIFY_RESULT_V1:";
    private static final int RESULT_SECRET_HEX_LENGTH = 64;
    private final SafeSinkAdapter.Mode sinkMode;
    private final String policyDigest;
    /** Fixed-size child protocol binding; the report keeps the readable composite policy. */
    private final String policyBindingDigest;
    /** Kept as an explicit policy bit for CLI/cache identity; Job Object is always the default. */
    private final boolean requireOsIsolation;

    private final Path targetJar;
    private final List<Path> deps;
    private final Path ownJar;
    private final Path targetJdkHome;
    private final int targetMajorVersion;
    private final ConfirmCallback callback;
    /** The selected first-tier OS boundary; SAFE_REAL normally starts at the light tier. */
    private final OsIsolation.Backend isolationBackend;
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
    /** Artifact identity is computed once per verifier and bound into every child attempt. */
    private volatile String artifactFingerprint;
    /** Runtime probing is immutable for one verifier; avoid re-reading release metadata per chain. */
    private volatile RuntimeSelection selectedRuntime;
    /** Candidate-local native indexes are small and reusable; failures are never cached. */
    private final Map<String, String> nativeIndexCache = new java.util.LinkedHashMap<>();
    /** One owner for dynamic phase/resource observations; it is not part of the scan state. */
    private final VerificationTelemetry telemetry = new VerificationTelemetry();

    /** Launcher-owned identities carried by the authenticated probe protocol. */
    static record ProtocolIdentity(String token, String runId, String chainFingerprint,
                                   String sinkFingerprint, String nonce,
                                   String artifactFingerprint) {
    }

    public ParallelVerifier(Path targetJar, List<Path> deps, ConfirmCallback callback) {
        this(targetJar, deps, null, 0, callback);
    }

    public ParallelVerifier(Path targetJar, List<Path> deps, Path targetJdkHome,
                            ConfirmCallback callback) {
        this(targetJar, deps, targetJdkHome, 0, callback);
    }

    public ParallelVerifier(Path targetJar, List<Path> deps, Path targetJdkHome,
                            int targetMajorVersion, ConfirmCallback callback) {
        this(targetJar, deps, targetJdkHome, targetMajorVersion, false, callback);
    }

    public ParallelVerifier(Path targetJar, List<Path> deps, Path targetJdkHome,
                            int targetMajorVersion, boolean safeExec,
                            ConfirmCallback callback) {
        this(targetJar, deps, targetJdkHome, targetMajorVersion, safeExec, false,
                false, callback);
    }

    public ParallelVerifier(Path targetJar, List<Path> deps, Path targetJdkHome,
                            int targetMajorVersion, boolean safeExec,
                            boolean requireOsIsolation,
                            ConfirmCallback callback) {
        this(targetJar, deps, targetJdkHome, targetMajorVersion, safeExec, false,
                requireOsIsolation, callback);
    }

    /** Explicit adapter mode; SAFE_REAL is intentionally separate from historical SAFE_EXEC. */
    public ParallelVerifier(Path targetJar, List<Path> deps, Path targetJdkHome,
                            int targetMajorVersion, boolean safeExec, boolean safeReal,
                            boolean requireOsIsolation,
                            ConfirmCallback callback) {
        this.targetJar = targetJar.toAbsolutePath().normalize();
        this.deps = deps != null ? deps : List.of();
        this.targetJdkHome = targetJdkHome == null ? null
                : targetJdkHome.toAbsolutePath().normalize();
        this.targetMajorVersion = targetMajorVersion;
        this.callback = callback;
        this.ownJar = locateOwnJar();
        this.sinkMode = safeReal ? SafeSinkAdapter.Mode.SAFE_REAL
                : safeExec ? SafeSinkAdapter.Mode.SAFE_EXEC : SafeSinkAdapter.Mode.BOUNDARY;
        // The default and only real-call tier is the cheap process/resource boundary. The
        // explicit CLI bit is retained for policy/cache identity and does not select another
        // runner.
        this.requireOsIsolation = requireOsIsolation;
        this.isolationBackend = OsIsolation.select(this.ownJar);
        this.policyDigest = SafeSinkAdapter.policyDigest(this.sinkMode)
                + ";os=" + isolationBackend.policyDigest()
                + ";attestation=" + isolationBackend.attestationVersion()
                + ";loopback=" + (this.sinkMode == SafeSinkAdapter.Mode.SAFE_REAL)
                + ";require_os=" + this.requireOsIsolation;
        this.policyBindingDigest = policyDigestOf(this.policyDigest);
    }

    private record RuntimeSelection(Path javaHome, Path probeJar, int feature, String reason) {
        boolean available() {
            return javaHome != null && probeJar != null;
        }
    }

    /** Per-child phase observations; values are published only after the child is closed. */
    private static final class AttemptTiming {
        private final Map<String, Long> values = new HashMap<>();

        void add(String name, long durationNanos) {
            if (name == null || name.isBlank()) {
                return;
            }
            long millis = Math.max(0L, durationNanos) / 1_000_000L;
            values.merge(name, millis, ParallelVerifier::saturatedAdd);
        }

        void addMillis(String name, long millis) {
            if (name == null || name.isBlank()) {
                return;
            }
            values.merge(name, Math.max(0L, millis), ParallelVerifier::saturatedAdd);
        }
    }

    /**
     * Owns the verifier's optional telemetry without leaking counters into the execution state.
     * The hot path still uses the same concurrent adders and one thread-local attempt object;
     * this type only makes their lifetime and aggregation rules explicit.
     */
    private static final class VerificationTelemetry {
        private final Map<String, LongAdder> phaseTotals = new ConcurrentHashMap<>();
        private final Map<String, LongAdder> resourceTotals = new ConcurrentHashMap<>();
        private final Map<String, AtomicLong> resourceMaxima = new ConcurrentHashMap<>();
        private final LongAdder cleanupSuccesses = new LongAdder();
        private final LongAdder cleanupFailures = new LongAdder();
        private final ThreadLocal<AttemptTiming> currentAttempt = new ThreadLocal<>();

        AttemptTiming beginAttempt() {
            AttemptTiming timing = new AttemptTiming();
            currentAttempt.set(timing);
            return timing;
        }

        void endAttempt() {
            currentAttempt.remove();
        }

        void publishAttempt(AttemptTiming timing) {
            if (timing == null) {
                return;
            }
            for (Map.Entry<String, Long> entry : timing.values.entrySet()) {
                phaseTotals.computeIfAbsent(entry.getKey(), ignored -> new LongAdder())
                        .add(Math.max(0L, entry.getValue()));
            }
        }

        void recordAttemptPhase(String name, long started) {
            AttemptTiming timing = currentAttempt.get();
            if (timing != null) {
                timing.add(name, System.nanoTime() - started);
            }
        }

        void recordGlobalPhase(String name, long durationNanos) {
            if (name != null && !name.isBlank()) {
                phaseTotals.computeIfAbsent(name, ignored -> new LongAdder())
                        .add(Math.max(0L, durationNanos) / 1_000_000L);
            }
        }

        Map<String, Long> phases() {
            Map<String, Long> result = new TreeMap<>();
            phaseTotals.forEach((name, value) -> result.put(name, Math.max(0L, value.sum())));
            return Collections.unmodifiableMap(result);
        }

        void addResourceTotal(String name, long value) {
            if (name != null && !name.isBlank() && value >= 0L) {
                resourceTotals.computeIfAbsent(name, ignored -> new LongAdder()).add(value);
            }
        }

        void addResourceMax(String name, long value) {
            if (name != null && !name.isBlank() && value >= 0L) {
                resourceMaxima.computeIfAbsent(name, ignored -> new AtomicLong())
                        .accumulateAndGet(value, Math::max);
            }
        }

        void recordCleanup(boolean cleaned) {
            if (cleaned) {
                cleanupSuccesses.increment();
            } else {
                cleanupFailures.increment();
            }
        }

        Map<String, Long> resources() {
            Map<String, Long> result = new TreeMap<>();
            resourceTotals.forEach((name, value) -> result.put(name, Math.max(0L, value.sum())));
            resourceMaxima.forEach((name, value) -> result.put(name, Math.max(0L, value.get())));
            long success = cleanupSuccesses.sum();
            long failure = cleanupFailures.sum();
            long attempts = saturatedAdd(success, failure);
            result.put("cleanup_successes", success);
            result.put("cleanup_failures", failure);
            result.put("cleanup_rate_milli", attempts == 0L
                    ? 1000L : Math.min(1000L, (success * 1000L) / attempts));
            return Collections.unmodifiableMap(result);
        }
    }

    /**
     * Low-frequency process-tree sampler used only while a child attempt is alive.  Job Object
     * accounting exposes total/active processes but not a peak process count; this sampler fills
     * that one reporting gap without adding a resident service or another process.
     */
    private static final class ProcessTreeMonitor implements AutoCloseable {
        private static final long SAMPLE_MILLIS = 100L;
        private final ProcessHandle root;
        private final AtomicLong peak = new AtomicLong(1L);
        private volatile boolean running = true;
        private final Thread sampler;

        private ProcessTreeMonitor(Process process) {
            this.root = process.toHandle();
            sample();
            sampler = new Thread(() -> {
                while (running) {
                    sample();
                    try {
                        Thread.sleep(SAMPLE_MILLIS);
                    } catch (InterruptedException interrupted) {
                        Thread.currentThread().interrupt();
                        return;
                    }
                }
            }, "just-verify-resource");
            sampler.setDaemon(true);
            sampler.start();
        }

        private void sample() {
            long count = liveProcessCount(root);
            if (count >= 0L) {
                peak.accumulateAndGet(count, Math::max);
            }
        }

        private long peak() {
            return peak.get();
        }

        @Override
        public void close() {
            running = false;
            sampler.interrupt();
            try {
                sampler.join(250L);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
            }
            sample();
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
        // A knowledge source may publish equivalent candidates from concurrent workers.  A
        // key-indexed snapshot removes duplicate work before the finite budget is applied;
        // TreeMap also makes the input iteration order irrelevant.
        Map<String, Chain> unique = new TreeMap<>();
        for (Chain candidate : candidates) {
            if (candidate != null) {
                String key = candidate.key();
                Chain previous = unique.get(key);
                if (previous == null || equivalentCandidateOrder(candidate, previous) < 0) {
                    unique.put(key, candidate);
                }
            }
        }
        List<Chain> sorted = new ArrayList<>(unique.values());
        Comparator<Chain> ranking = ChainRanking.comparator(Map.of(), Map.of(), constructible);
        Map<Chain, Integer> probePriority = new java.util.IdentityHashMap<>();
        for (Chain chain : sorted) {
            // probePriority() is intentionally richer than the report tuple, but it is still
            // invariant during this selection pass.  Precompute it so finite-budget sorting
            // does not repeatedly rescan every hop for the same candidate.
            probePriority.put(chain, probePriority(chain, constructible));
        }
        sorted.sort(ranking
                .thenComparingInt(chain -> -probePriority.getOrDefault(chain, 0))
                .thenComparing(chain -> chain.key() == null ? "" : chain.key()));
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

    private static int equivalentCandidateOrder(Chain left, Chain right) {
        int unresolved = Integer.compare(left.unresolvedHops(), right.unresolvedHops());
        if (unresolved != 0) {
            return unresolved;
        }
        return candidateTieKey(left).compareTo(candidateTieKey(right));
    }

    private static String candidateTieKey(Chain chain) {
        return String.valueOf(chain.entryClass()) + "|" + String.valueOf(chain.entryMethod())
                + "|" + String.valueOf(chain.sinkClass()) + "|" + String.valueOf(chain.sinkMethod())
                + "|" + chain.hops().size();
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

    /**
     * Build a small native-method index for the owners already present in this candidate.  JNI
     * calls are normally outside the selected {@code System.load*} sink, so discovering only
     * declarations in the currently transformed class misses the common caller/native-owner
     * split.  The index is candidate-local and bounded; it does not walk every class in a large
     * dependency closure and therefore keeps SAFE_REAL's extra work proportional to the chain.
     */
    private String nativeIndexForCandidate(Chain chain, String targetClasspath) {
        StringBuilder key = new StringBuilder(targetClasspath == null ? "" : targetClasspath);
        key.append('|').append(chain == null ? "" : chain.entryClass())
                .append('|').append(chain == null ? "" : chain.sinkClass());
        if (chain != null) {
            for (ChainHop hop : chain.hops()) {
                key.append('|').append(hop.fromOwner()).append('|').append(hop.toOwner());
            }
        }
        String cacheKey = sha256Hex(key.toString());
        synchronized (nativeIndexCache) {
            String cached = nativeIndexCache.get(cacheKey);
            if (cached != null) return cached;
        }
        String computed = nativeIndexFor(chain, targetClasspath);
        if (!computed.isEmpty()) {
            synchronized (nativeIndexCache) {
                if (nativeIndexCache.size() >= 32) {
                    String eldest = nativeIndexCache.keySet().iterator().next();
                    nativeIndexCache.remove(eldest);
                }
                nativeIndexCache.put(cacheKey, computed);
            }
        }
        return computed;
    }

    private static String nativeIndexFor(Chain chain, String targetClasspath) {
        if (chain == null || targetClasspath == null || targetClasspath.isBlank()) {
            return "";
        }
        java.util.TreeSet<String> owners = new java.util.TreeSet<>();
        addNativeOwner(owners, chain.entryClass());
        addNativeOwner(owners, chain.sinkClass());
        for (ChainHop hop : chain.hops()) {
            addNativeOwner(owners, hop.fromOwner());
            addNativeOwner(owners, hop.toOwner());
        }
        if (owners.isEmpty()) return "";

        java.util.TreeSet<String> methods = new java.util.TreeSet<>();
        String separator = java.util.regex.Pattern.quote(File.pathSeparator);
        for (String classpathEntry : targetClasspath.split(separator, -1)) {
            if (methods.size() >= 256 || classpathEntry == null || classpathEntry.isBlank()) {
                break;
            }
            Path root;
            try {
                root = Path.of(classpathEntry).toAbsolutePath().normalize();
            } catch (RuntimeException invalidPath) {
                continue;
            }
            if (Files.isDirectory(root, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
                for (String owner : owners) {
                    if (methods.size() >= 256) break;
                    Path classFile = root.resolve(owner + ".class").normalize();
                    if (!classFile.startsWith(root)
                            || !Files.isRegularFile(classFile,
                            java.nio.file.LinkOption.NOFOLLOW_LINKS)) continue;
                    try (InputStream input = Files.newInputStream(classFile)) {
                        collectNativeMethods(owner, input, methods);
                    } catch (IOException | RuntimeException ignored) {
                        // A missing optional class must remain a bounded coverage limitation.
                    }
                }
                continue;
            }
            if (!Files.isRegularFile(root, java.nio.file.LinkOption.NOFOLLOW_LINKS)) continue;
            try (java.util.jar.JarFile jar = new java.util.jar.JarFile(root.toFile())) {
                for (String owner : owners) {
                    if (methods.size() >= 256) break;
                    String entryName = findClassEntry(jar, owner);
                    if (entryName == null) continue;
                    try (InputStream input = jar.getInputStream(jar.getJarEntry(entryName))) {
                        collectNativeMethods(owner, input, methods);
                    } catch (IOException | RuntimeException ignored) {
                        // A malformed dependency does not make an unrelated candidate unsafe.
                    }
                }
            } catch (IOException | RuntimeException ignored) {
                // The child still uses the exact same-class index and reports limitations.
            }
        }
        return String.join(",", methods);
    }

    private static void addNativeOwner(Set<String> owners, String owner) {
        if (owner == null || owner.isBlank()) return;
        String value = owner.replace('.', '/');
        if (value.startsWith("/") || value.endsWith("/") || value.contains("..")
                || !value.matches("[A-Za-z0-9_$\\/]+")) return;
        owners.add(value);
    }

    private static String findClassEntry(java.util.jar.JarFile jar, String owner) {
        for (String name : new String[]{owner + ".class", "BOOT-INF/classes/" + owner + ".class",
                "WEB-INF/classes/" + owner + ".class"}) {
            if (jar.getJarEntry(name) != null) return name;
        }
        return null;
    }

    private static void collectNativeMethods(String owner, InputStream input,
                                             Set<String> methods) throws IOException {
        byte[] bytes = input.readNBytes(8 * 1024 * 1024);
        if (bytes.length == 0) return;
        new ClassReader(bytes).accept(new ClassVisitor(Opcodes.ASM9) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                                              String signature, String[] exceptions) {
                if ((access & Opcodes.ACC_NATIVE) != 0 && methods.size() < 256) {
                    methods.add(owner + "#" + name + "#" + descriptor);
                }
                return null;
            }
        }, ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
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
            List<VerifyResult> first = runBatch(chains, pool, 1, lease.workers());
            List<Integer> retryIndexes = new ArrayList<>();
            List<Chain> retryChains = new ArrayList<>();
            if (Boolean.parseBoolean(System.getProperty("just.verify.retry-timeouts", "false"))) {
                for (int i = 0; i < first.size(); i++) {
                    VerifyResult result = first.get(i);
                    if (retryable(result)) {
                        retryIndexes.add(i);
                        retryChains.add(chains.get(i));
                    }
                }
                // Timeouts are not retried by default: retrying makes duration and results depend
                // on scheduler pressure. Operators can opt in when diagnosing a noisy host.
                List<VerifyResult> retryResults = runBatch(retryChains, pool, 2, lease.workers());
                for (int i = 0; i < retryIndexes.size(); i++) {
                    int originalIndex = retryIndexes.get(i);
                    VerifyResult retry = retryResults.get(i);
                    if (retry != null && !"verification-future-timeout".equals(retry.detail())) {
                        first.set(originalIndex, retry);
                    }
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

    /** Aggregated per-attempt timing work for the opt-in performance report. */
    public Map<String, Long> phaseTimings() {
        return telemetry.phases();
    }

    /**
     * Aggregated runner resource observations.  Peak values use a maximum across attempts;
     * child CPU and scratch bytes are additive.  Missing platform observations are omitted
     * instead of being reported as zero.
     */
    public Map<String, Long> resourceMetrics() {
        return telemetry.resources();
    }

    private void recordResourceTotal(String name, long value) {
        telemetry.addResourceTotal(name, value);
    }

    private void recordResourceMax(String name, long value) {
        telemetry.addResourceMax(name, value);
    }

    /** Capability represented by the selected host backend before a child attempt runs. */
    public String hostCapability() {
        return capabilityForReadyBackend();
    }

    /** Structured verifier capability metadata used by all reporters. */
    public String backendId() {
        return isolationBackend.id();
    }

    public String backendReason() {
        return isolationBackend.reason();
    }

    public String policyDigest() {
        return policyDigest;
    }

    public String policyMode() {
        return sinkMode == SafeSinkAdapter.Mode.SAFE_REAL
                ? "LIGHT_SAFE_CALL" : sinkMode.name();
    }

    public String isolationLevel() {
        return isolationBackend.level().name();
    }

    /** Version of the parent-attached runner proof carried by every ready event. */
    public String attestationVersion() {
        return isolationBackend.attestationVersion();
    }

    public Set<String> isolationCapabilities() {
        java.util.TreeSet<String> sorted = new java.util.TreeSet<>(isolationBackend.capabilities());
        return java.util.Collections.unmodifiableSet(sorted);
    }

    public boolean requireOsIsolation() {
        return requireOsIsolation;
    }

    /** True only when the selected Job Object backend has passed its production contract. */
    public boolean osIsolationReady() {
        return isolationBackend.available() && isolationBackend.productionReady();
    }

    /** Stable per-chain detail used when the Job Object backend is unavailable. */
    public String isolationUnavailableDetail() {
        return "SANDBOX_UNAVAILABLE:JOB_OBJECT_REQUIRED:"
                + isolationBackend.level().name() + isolationReason(isolationBackend);
    }

    /**
     * Build the report-only result used when process-boundary verification is rejected before a child
     * JVM is started.  Keeping the host policy metadata here prevents the preflight path from
     * silently manufacturing per-chain UNKNOWN backend/effect fields.
     */
    public VerifyResult isolationUnavailableResult(Chain chain) {
        return new VerifyResult(chain.key(), "UNTESTABLE", isolationUnavailableDetail(), 1, 0L,
                "SANDBOX_UNAVAILABLE", backendId(), runtimeLabel(selectRuntime()), policyDigest(),
                false, false, "NOT_STARTED");
    }

    private String capabilityForReadyBackend() {
        return switch (isolationBackend.level()) {
            case PROCESS_RESOURCE -> "PROCESS_RESOURCE";
            case NONE -> "OS_ISOLATION_UNAVAILABLE";
        };
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
                // The child cannot produce any non-UNTESTABLE result until the parent has
                // attached the OS backend and released the authenticated ready marker. This
                // is stronger than the former JVM-only label and prevents FAILED/TIMEOUT from
                // being mistaken for a successful Java SecurityManager installation.
                capability = capabilityForReadyBackend();
                return;
            }
            String detail = result.detail() == null ? "" : result.detail();
            if (detail.startsWith("SANDBOX_UNAVAILABLE")) {
                sandboxUnavailable = true;
            }
            if (detail.contains("no-compatible-jdk")
                    || detail.contains("target-jdk-executable-missing")
                    || detail.contains("target-jdk-feature-unknown")
                    || detail.contains("target-jdk-too-old")
                    || detail.contains("runtime-jdk-too-old")
                    || detail.contains("verifier-artifact-missing")
                    || detail.contains("CANARY_ARTIFACT_MISSING")) {
                runtimeUnavailable = true;
            }
        }
        if (sandboxUnavailable) {
            capability = "OS_ISOLATION_UNAVAILABLE";
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
    private List<VerifyResult> runBatch(List<Chain> chains, ExecutorService pool, int attempt,
                                        int workers) {
        if (chains.isEmpty()) {
            return List.of();
        }
        ExecutorCompletionService<IndexedResult> completion = new ExecutorCompletionService<>(pool);
        Map<Future<IndexedResult>, Integer> pending = new HashMap<>();
        List<VerifyResult> results = new ArrayList<>(Collections.nCopies(chains.size(), null));
        for (int i = 0; i < chains.size(); i++) {
            final int index = i;
            final long queuedAt = System.nanoTime();
            Future<IndexedResult> future = completion.submit(
                    () -> {
                        recordGlobalPhase("queue", System.nanoTime() - queuedAt);
                        return new IndexedResult(index, verifyOne(chains.get(index), attempt));
                    });
            pending.put(future, index);
        }
        // The process-level timeout belongs to each child, but the collector has one batch
        // deadline.  Polling the full timeout once per unfinished future made a noisy batch
        // cost N * (timeout + grace) seconds even after every worker had already been cancelled.
        // A single monotonic deadline bounds the whole batch while preserving the input-indexed
        // result order and the explicit opt-in retry policy.
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(
                batchTimeoutSecondsForRun(chains.size(), workers));
        while (!pending.isEmpty()) {
            Future<IndexedResult> future;
            try {
                long remaining = deadline - System.nanoTime();
                if (remaining <= 0L) {
                    break;
                }
                future = completion.poll(remaining, TimeUnit.NANOSECONDS);
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
                results.set(expectedIndex, enrich(new VerifyResult(chain.key(), "UNTESTABLE",
                        e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage(),
                        attempt, 0L)));
            }
        }
        for (Map.Entry<Future<IndexedResult>, Integer> entry : pending.entrySet()) {
            entry.getKey().cancel(true);
            int index = entry.getValue();
            Chain chain = chains.get(index);
            results.set(index, enrich(new VerifyResult(chain.key(), "UNTESTABLE",
                    "verification-future-timeout", attempt,
                    (long) batchTimeoutSecondsForRun(chains.size(), workers) * 1000)));
        }
        return results;
    }

    /**
     * Bound the collector by the number of worker waves, not by one child timeout.
     *
     * <p>The old deadline was {@code childTimeout + grace} for the whole queue.  With a
     * four-worker verifier, the fifth queued candidate could therefore be marked as a future
     * timeout while the first four candidates were still legitimately running.  That made
     * dynamic evidence depend on queue length and scheduler pressure, and it wasted the finite
     * verification budget.  The child timeout remains unchanged; this only gives every queued
     * candidate one bounded wave and adds one grace period for collector cleanup.</p>
     */
    static int batchTimeoutSeconds(int chainCount, int workers) {
        return batchTimeoutSeconds(chainCount, workers, 1);
    }

    /**
     * Collector budget for a run whose worker can execute a bounded two-step policy. A light
     * SAFE_REAL attempt may consume one child timeout, then the boundary attempt gets its own
     * timeout. The legacy overload intentionally keeps its one-attempt contract for callers
     * that only run a single verification mode.
     */
    static int batchTimeoutSeconds(int chainCount, int workers, int maxTierAttempts) {
        int tasks = Math.max(0, chainCount);
        if (tasks == 0) {
            return 0;
        }
        int parallelism = Math.max(1, workers);
        int waves = (tasks + parallelism - 1) / parallelism;
        int attempts = Math.max(1, maxTierAttempts);
        long seconds = (long) TIMEOUT_SECONDS * waves * attempts + FUTURE_GRACE_SECONDS;
        return seconds > Integer.MAX_VALUE ? Integer.MAX_VALUE : (int) seconds;
    }

    private int batchTimeoutSecondsForRun(int chainCount, int workers) {
        int maxTierAttempts = sinkMode == SafeSinkAdapter.Mode.SAFE_REAL ? 2 : 1;
        return batchTimeoutSeconds(chainCount, workers, maxTierAttempts);
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
        AttemptTiming timing = telemetry.beginAttempt();
        try {
            VerifyResult result = verifyOneInternal(chain);
            if (result == null) {
                result = new VerifyResult(chain.key(), "UNKNOWN", "verifier-returned-null");
            }
            VerifyResult timed = copyResult(result, result.detail(), attempt,
                    Math.max(result.durationMs(),
                            TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)));
            recordDetailTimings(timing, timed.detail());
            telemetry.publishAttempt(timing);
            return enrich(timed, chain);
        } finally {
            telemetry.endAttempt();
        }
    }

    private void recordDetailTimings(AttemptTiming timing, String detail) {
        if (timing == null || detail == null || detail.isBlank()) {
            return;
        }
        for (String phase : List.of("class_load_ms", "real_call_ms", "prefix_stop_ms")) {
            long value = detailField(detail, phase);
            if (value >= 0L) {
                timing.addMillis(phase.substring(0, phase.length() - 3), value);
            }
        }
    }

    private static long detailField(String detail, String field) {
        String marker = ";" + field + "=";
        int start = detail.indexOf(marker);
        if (start < 0) {
            return -1L;
        }
        start += marker.length();
        int end = detail.indexOf(';', start);
        String value = end < 0 ? detail.substring(start) : detail.substring(start, end);
        try {
            return Math.max(0L, Long.parseLong(value));
        } catch (NumberFormatException ignored) {
            return -1L;
        }
    }

    private void recordAttemptPhase(String name, long started) {
        telemetry.recordAttemptPhase(name, started);
    }

    private void recordGlobalPhase(String name, long durationNanos) {
        telemetry.recordGlobalPhase(name, durationNanos);
    }

    /** Add the immutable per-attempt policy context before a result reaches the blackboard. */
    private VerifyResult enrich(VerifyResult result) {
        return enrich(result, null);
    }

    private VerifyResult enrich(VerifyResult result, Chain chain) {
        RuntimeSelection runtime = selectRuntime();
        // Readiness is authenticated by the child protocol, not inferred from a non-error
        // status. In particular FAILED/TIMEOUT must not advertise that the Java policy was
        // installed when the child may have died before its ready marker was observed.
        boolean ready = result != null && result.sandboxReady();
        boolean distorted = ready && result.sinkDistorted();
        String detail = result == null ? "unknown-result" : sanitizeDetail(result.detail());
        String resultBackend = result == null ? "UNKNOWN" : result.backend();
        if (resultBackend == null || resultBackend.isBlank() || "UNKNOWN".equals(resultBackend)) {
            resultBackend = backendId();
        }
        String resultPolicy = result == null ? "UNKNOWN" : result.policyDigest();
        if (resultPolicy == null || resultPolicy.isBlank() || "UNKNOWN".equals(resultPolicy)) {
            resultPolicy = policyDigest();
        }
        return new VerifyResult(result == null ? "" : result.chainKey(),
                result == null ? "UNKNOWN" : result.status(),
                detail,
                result == null ? 1 : result.attempt(),
                result == null ? 0L : result.durationMs(),
                result == null ? "UNKNOWN" : result.evidence(),
                resultBackend, runtimeLabel(runtime), resultPolicy, distorted, ready,
                result == null ? "UNKNOWN" : result.cleanup(),
                result == null ? "UNKNOWN" : result.requestedMode(),
                result == null ? "UNKNOWN" : result.effectiveMode(),
                result == null ? "none" : result.fallback(),
                result == null ? "NONE" : result.verificationScope(),
                chain == null || chain.sinkRisk() == null
                        ? result == null ? "UNKNOWN" : result.sinkRisk()
                        : chain.sinkRisk().name(),
                result != null && result.terminalExecuted(),
                result == null ? "UNKNOWN" : result.stopReason(),
                result == null ? "UNKNOWN" : result.lastConfirmedStage());
    }

    /** Result carrying the child-authenticated boundary state into the parent enrichment step. */
    private VerifyResult authenticatedResult(Chain chain, String status, String detail,
                                             String evidence, boolean sinkDistorted,
                                             boolean sandboxReady) {
        return authenticatedResult(chain, status, detail, evidence, sinkDistorted,
                sandboxReady, isolationBackend, policyDigest());
    }

    private VerifyResult authenticatedResult(Chain chain, String status, String detail,
                                             String evidence, boolean sinkDistorted,
                                             boolean sandboxReady, OsIsolation.Backend backend,
                                             String attemptPolicyDigest) {
        return new VerifyResult(chain.key(), status, detail, 1, 0L, evidence,
                backend == null ? "UNKNOWN" : backend.id(), "UNKNOWN",
                attemptPolicyDigest == null ? "UNKNOWN" : attemptPolicyDigest,
                sinkDistorted, sandboxReady, "CLEANUP_BEST_EFFORT");
    }

    private static String tierName(OsIsolation.Backend backend) {
        return backend != null && backend.available() ? "LIGHT_SAFE_CALL" : "UNAVAILABLE";
    }

    private static VerifyResult decorate(VerifyResult result, String requestedTier,
                                         String effectiveTier, String fallbackReason) {
        if (result == null) {
            return null;
        }
        String detail = result.detail() == null ? "" : result.detail();
        if (detail.startsWith("requested_mode=")) {
            return result;
        }
        String requested = requestedTier == null || requestedTier.isBlank()
                ? "UNKNOWN" : requestedTier;
        String effective = effectiveTier == null || effectiveTier.isBlank()
                ? "UNKNOWN" : effectiveTier;
        String fallback = fallbackReason == null || fallbackReason.isBlank()
                ? "none" : sanitizeTierReason(fallbackReason);
        String decoratedDetail = "requested_mode=" + requested
                + ";effective_mode=" + effective
                + ";fallback=" + fallback + ";" + detail;
        return copyResult(result, decoratedDetail, result.attempt(), result.durationMs(),
                requested, effective, fallback);
    }

    private static VerifyResult copyResult(VerifyResult result, String detail,
                                           int attempt, long durationMs) {
        return copyResult(result, detail, attempt, durationMs,
                result.requestedMode(), result.effectiveMode(), result.fallback());
    }

    private static VerifyResult copyResult(VerifyResult result, String detail,
                                           int attempt, long durationMs,
                                           String requestedMode, String effectiveMode,
                                           String fallback) {
        return new VerifyResult(result.chainKey(), result.status(), detail, attempt, durationMs,
                result.evidence(), result.backend(), result.jdk(), result.policyDigest(),
                result.sinkDistorted(), result.sandboxReady(), result.cleanup(),
                requestedMode, effectiveMode, fallback, result.verificationScope(),
                result.sinkRisk(), result.terminalExecuted(), result.stopReason(),
                result.lastConfirmedStage());
    }

    static boolean infrastructureFailure(VerifyResult result) {
        if (result == null) {
            return true;
        }
        if (result.statusCode() == VerifyStatus.TIMEOUT) {
            return true;
        }
        if (result.statusCode() != VerifyStatus.UNTESTABLE) {
            return false;
        }
        String detail = rawDetail(result.detail());
        return detail.startsWith("SANDBOX_UNAVAILABLE")
                || detail.startsWith("PROTOCOL_AUTHENTICATION_FAILED")
                || detail.startsWith("PROBE_OUTPUT_LIMIT")
                || detail.startsWith("PROCESS_OOM")
                || detail.startsWith("verification-future-timeout")
                || detail.startsWith("target-timeout")
                || detail.startsWith("SAFE_NATIVE_FIXTURE_UNAVAILABLE")
                || detail.startsWith("SAFE_NATIVE_FIXTURE_ROOT_UNAVAILABLE")
                || detail.startsWith("CANARY_ARTIFACT_MISSING")
                || detail.startsWith("UNTESTABLE: CANARY_AGENT_NOT_READY")
                || detail.startsWith("UNTESTABLE: REAL_SINK_AGENT_NOT_READY")
                || detail.startsWith("UNTESTABLE: PROTOCOL_BINDING_NOT_READY")
                || detail.startsWith("UNTESTABLE: REAL_SINK_EVIDENCE_INCOMPLETE")
                || detail.startsWith("UNTESTABLE: SAFE_NATIVE_FIXTURE_CONFIGURATION_FAILED");
    }

    static boolean boundaryOnlyFailure(VerifyResult result) {
        return result != null
                && rawDetail(result.detail()).startsWith("SAFE_SANITIZER_UNAVAILABLE");
    }

    static String stableFailure(VerifyResult result) {
        if (result == null || result.detail() == null || result.detail().isBlank()) {
            return "unknown";
        }
        if (result.statusCode() == VerifyStatus.TIMEOUT) {
            return "PROCESS_TIMEOUT";
        }
        String detail = rawDetail(result.detail());
        if (detail.startsWith("UNTESTABLE: REAL_SINK_EVIDENCE_INCOMPLETE")) {
            return sanitizeTierReason("UNTESTABLE:REAL_SINK_EVIDENCE_INCOMPLETE_loaded="
                    + fieldValue(detail, "loaded") + "_arguments="
                    + fieldValue(detail, "arguments"));
        }
        int semicolon = detail.indexOf(';');
        if (semicolon >= 0) {
            detail = detail.substring(0, semicolon);
        }
        return sanitizeTierReason(detail);
    }

    private static String fieldValue(String detail, String field) {
        String marker = ";" + field + "=";
        int start = detail.indexOf(marker);
        if (start < 0) {
            return "unknown";
        }
        start += marker.length();
        int end = detail.indexOf(';', start);
        return end < 0 ? detail.substring(start) : detail.substring(start, end);
    }

    /** Remove the report-only tier prefix without confusing its fallback value for the cause. */
    static String rawDetail(String detail) {
        if (detail == null || !detail.startsWith("requested_mode=")) {
            return detail == null ? "" : detail;
        }
        int first = detail.indexOf(';');
        int second = first < 0 ? -1 : detail.indexOf(';', first + 1);
        int third = second < 0 ? -1 : detail.indexOf(';', second + 1);
        return third < 0 ? detail : detail.substring(third + 1);
    }

    private static String sanitizeTierReason(String value) {
        if (value == null || value.isBlank()) {
            return "unknown";
        }
        String sanitized = value.replaceAll("[^A-Za-z0-9_.=:-]", "_");
        return sanitized.length() > 160 ? sanitized.substring(0, 160) : sanitized;
    }

    private static String runtimeLabel(RuntimeSelection runtime) {
        if (runtime == null) {
            return "UNKNOWN";
        }
        // Reports are portable identities, not host inventory.  The selected feature and
        // reason are enough to reproduce the decision without leaking a user's JDK path.
        return "feature=" + runtime.feature() + ";selection=" + runtime.reason();
    }

    /**
     * Execute the two-step lightweight policy. A safe real call is attempted once; only an
     * infrastructure/sanitizer failure may fall back to the exact boundary canary. There is no
     * stronger hidden runner and a semantic negative is never retried with a different shape.
     */
    private VerifyResult verifyOneInternal(Chain chain) {
        if (sinkMode != SafeSinkAdapter.Mode.SAFE_REAL) {
            return decorate(verifyOneInternal(chain, isolationBackend, sinkMode, sinkMode.name(),
                    sinkMode.name(), "none"), sinkMode.name(), sinkMode.name(), "none");
        }

        String requested = "LIGHT_SAFE_CALL";
        OsIsolation.Backend first = isolationBackend;
        if (chain.sinkRisk() == io.just.sast.blackboard.SinkRisk.HIGH_RISK_TERMINAL) {
            // The exact sink boundary is still instrumented, but the target terminal method is
            // never entered. This gives high-risk chains a real prefix experiment without
            // pretending that a class load, native load, lookup or evaluator was executed.
            VerifyResult prefix = verifyOneInternal(chain, first, SafeSinkAdapter.Mode.BOUNDARY,
                    requested, "PREFIX_ONLY", "none");
            return prefixOnlyResult(prefix, chain);
        }
        VerifyResult result = verifyOneInternal(chain, first, SafeSinkAdapter.Mode.SAFE_REAL,
                requested, tierName(first), "none");
        if (!infrastructureFailure(result)) {
            if (boundaryOnlyFailure(result)) {
                String fallbackReason = stableFailure(result);
                VerifyResult boundary = verifyOneInternal(chain, first,
                        SafeSinkAdapter.Mode.BOUNDARY, requested, "BOUNDARY",
                        fallbackReason);
                return boundary == null
                        ? decorate(result, requested, "BOUNDARY", fallbackReason)
                        : decorate(boundary, requested, "BOUNDARY", fallbackReason);
            }
            return decorate(result, requested, tierName(first), "none");
        }

        String fallbackReason = stableFailure(result);
        // The only fallback is the same Job Object-backed boundary canary. If the runner itself
        // is unavailable, this second call remains UNTESTABLE and cannot start an uncontained
        // target JVM.
        VerifyResult boundary = verifyOneInternal(chain, first,
                SafeSinkAdapter.Mode.BOUNDARY, requested, "BOUNDARY", fallbackReason);
        if (boundary == null) {
            return decorate(result, requested, "BOUNDARY", fallbackReason);
        }
        return decorate(boundary, requested, "BOUNDARY", fallbackReason);
    }

    private static VerifyResult prefixOnlyResult(VerifyResult result, Chain chain) {
        if (result == null || result.statusCode() != VerifyStatus.SINK_BLOCKED) {
            return result;
        }
        String detail = result.detail() == null ? "" : result.detail();
        String raw = rawDetail(detail);
        String decorated = "requested_mode=LIGHT_SAFE_CALL;effective_mode=PREFIX_ONLY;"
                + "fallback=none;" + raw;
        return new VerifyResult(result.chainKey(), "PRE_SINK_CONFIRMED", decorated,
                result.attempt(), result.durationMs(), "PREFIX_CHAIN_CONFIRMED",
                result.backend(), result.jdk(), result.policyDigest(), false,
                result.sandboxReady(), result.cleanup(), "LIGHT_SAFE_CALL", "PREFIX_ONLY",
                "none", "PREFIX_ONLY", chain.sinkRisk().name(), false,
                "HIGH_RISK_SINK", "PRE_SINK");
    }

    private VerifyResult verifyOneInternal(Chain chain, OsIsolation.Backend backend,
                                           SafeSinkAdapter.Mode attemptMode,
                                           String requestedTier, String effectiveTier,
                                           String fallbackReason) {
        Path isoDir = null;
        Path nativeRoot = null;
        Process proc = null;
        ProcessTreeMonitor processMonitor = null;
        OsIsolation.Session isolationSession = null;
        long runnerStarted = 0L;
        try {
            RuntimeSelection runtime = selectRuntime();
            if (!runtime.available()) {
                return decorate(new VerifyResult(chain.key(), "UNTESTABLE", runtime.reason()),
                        requestedTier, effectiveTier, fallbackReason);
            }
            if (backend == null || !backend.available()) {
                return decorate(new VerifyResult(chain.key(), "UNTESTABLE",
                        "SANDBOX_UNAVAILABLE:OS_BACKEND_REQUIRED:"
                                + (backend == null ? "missing" : backend.reason())),
                        requestedTier, effectiveTier, fallbackReason);
            }
            // Every target child, including the boundary canary, must be attached to the single
            // Job Object backend. A JVM policy is only defense in depth and never replaces it.
            JdkRuntimePolicy runtimePolicy = JdkRuntimePolicy.forFeature(runtime.feature());
            if (!runtimePolicy.admissible(backend.productionReady())) {
                return decorate(new VerifyResult(chain.key(), "UNTESTABLE",
                        "SANDBOX_UNAVAILABLE:JOB_OBJECT_REQUIRED:jdk=" + runtime.feature()
                                + ":reason=" + runtimePolicy.reason()),
                        requestedTier, effectiveTier, fallbackReason);
            }
            String attemptPolicyDigest = policyDigestFor(attemptMode, backend);
            String attemptPolicyBindingDigest = policyDigestOf(attemptPolicyDigest);
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
            String cp = probeClasspath(runtime.probeJar());
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
                return decorate(new VerifyResult(chain.key(), "UNTESTABLE",
                        "CANARY_ARTIFACT_MISSING:" + canaryBootstrap, 1, 0L,
                        "VERIFIER_ARTIFACT_MISSING", backend.id(), runtimeLabel(runtime),
                        policyDigestFor(attemptMode, backend), false, false,
                        "NOT_STARTED"), requestedTier, effectiveTier, fallbackReason);
            }

            // sink canary 插桩：本链 sink 方法入口注入门卫调用（见 SinkCanaryAgent）；
            // 门卫按调用栈判定，JVM/探针基础设施的同名调用被放行
            String agentSpec = chain.sinkClass() + "#" + chain.sinkMethod()
                    + (sinkDescriptor.isEmpty() ? "" : "#" + sinkDescriptor);
            String entrySpec = entryDotted + "#" + entryMethod
                    + (entryDescriptor.isEmpty() ? "" : "#" + entryDescriptor);
            // The result marker and the bytecode canary share one per-child capability token.
            String protocolToken = UUID.randomUUID().toString();
            String resultChannelSecret = sha256Hex(UUID.randomUUID().toString() + "|"
                    + UUID.randomUUID());
            ProtocolIdentity protocolIdentity;
            try {
                protocolIdentity = new ProtocolIdentity(protocolToken, UUID.randomUUID().toString(),
                        sha256Hex(chain.key()),
                        sha256Hex(chain.sinkClass() + "#" + chain.sinkMethod() + "#"
                                + sinkDescriptor),
                        UUID.randomUUID().toString().replace("-", ""),
                        artifactFingerprint());
            } catch (IOException | RuntimeException fingerprintFailure) {
                return decorate(new VerifyResult(chain.key(), "UNTESTABLE",
                        "ARTIFACT_FINGERPRINT_UNAVAILABLE:"
                                + fingerprintFailure.getClass().getSimpleName(), 1, 0L,
                        "VERIFIER_CAPABILITY_LIMIT", backend.id(), runtimeLabel(runtime),
                        policyDigestFor(attemptMode, backend), false, false,
                        "NOT_STARTED"), requestedTier, effectiveTier, fallbackReason);
            }
            FieldDependencyPlan plan = FieldDependencyPlan.from(
                    chain, mode);

            // 隔离工作目录/tmpdir/home、净化环境、子 JVM 限核与内存上限；fork-per-chain
            // 保持类隔离——静态状态不跨链污染。Job Object 是唯一 OS 边界。
            isoDir = Files.createTempDirectory("just-verify-");
            SafeSinkAdapter.Policy sinkPolicy;
            try {
                sinkPolicy = switch (attemptMode) {
                    case SAFE_EXEC -> SafeSinkAdapter.safeExecution(isoDir);
                    case SAFE_REAL -> SafeSinkAdapter.safeRealExecution(isoDir);
                    case BOUNDARY -> SafeSinkAdapter.boundary();
                };
            } catch (IllegalArgumentException policyFailure) {
                return decorate(new VerifyResult(chain.key(), "UNTESTABLE",
                        "SAFE_SINK_POLICY_INVALID:" + policyFailure.getMessage()),
                        requestedTier, effectiveTier, fallbackReason);
            }
            SafeSinkAdapter.Decision sinkDecision = SafeSinkAdapter.preflight(sinkPolicy,
                    new SafeSinkAdapter.Sink(chain.category(), chain.sinkClass(),
                            chain.sinkMethod(), sinkDescriptor), null).decision();
            SafeSinkAdapter.RealPlan realPlan = SafeSinkAdapter.realPlan(
                    new SafeSinkAdapter.Sink(chain.category(), chain.sinkClass(),
                            chain.sinkMethod(), sinkDescriptor));
            if (attemptMode == SafeSinkAdapter.Mode.SAFE_REAL
                    && (!realPlan.permitted() || !sinkDecision.targetSinkSelected())) {
                return decorate(new VerifyResult(chain.key(), "UNTESTABLE",
                        "SAFE_SANITIZER_UNAVAILABLE:" + realPlan.reason()),
                        requestedTier, effectiveTier, fallbackReason);
            }
            String nativeIndex = attemptMode == SafeSinkAdapter.Mode.SAFE_REAL
                    ? nativeIndexForCandidate(chain, targetCp) : "";
            Path isoTmp = Files.createDirectories(isoDir.resolve("tmp"));
            if (attemptMode == SafeSinkAdapter.Mode.SAFE_REAL
                    && realPlan.kind() == SafeSinkAdapter.RealSinkKind.NATIVE_FIXTURE) {
                Path parent = isoDir.getParent();
                if (parent == null) {
                    return decorate(new VerifyResult(chain.key(), "UNTESTABLE",
                            "SAFE_NATIVE_FIXTURE_ROOT_UNAVAILABLE"),
                            requestedTier, effectiveTier, fallbackReason);
                }
                nativeRoot = Files.createTempDirectory(parent, "just-native-")
                        .toAbsolutePath().normalize();
                if (!prepareNativeFixture(nativeRoot)) {
                    return decorate(new VerifyResult(chain.key(), "UNTESTABLE",
                            "SAFE_NATIVE_FIXTURE_UNAVAILABLE"),
                            requestedTier, effectiveTier, fallbackReason);
                }
            }
            Path resultChannelFile = isoDir.resolve("verification.result");
            Path isolationReady = isoDir.resolve("isolation.ready");
            String isolationToken = UUID.randomUUID().toString();
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
            command.add("-Djust.verify.isolation-ready=" + isolationReady.toAbsolutePath());
            command.add("-Djust.verify.isolation-token=" + isolationToken);
            command.add("-Djust.verify.backend=" + backend.id());
            command.add("-Djust.verify.isolation-level=" + backend.level().name());
            command.add("-Djust.verify.isolation-policy-digest="
                    + attemptPolicyBindingDigest);
            command.add("-Djust.verify.attestation-version="
                    + backend.attestationVersion());
            command.add("-Djust.verify.loopback="
                    + (attemptMode == SafeSinkAdapter.Mode.SAFE_REAL));
            command.add("-Djava.io.tmpdir=" + isoTmp);
            command.add("-Duser.dir=" + isoDir);
            command.add("-Duser.home=" + isoDir);
            command.add("-Duser.name=just-sandbox");
            command.add("-Duser.language=en");
            command.add("-Duser.country=US");
            command.add("-Djava.util.prefs.userRoot=" + isoDir.resolve("prefs"));
            command.add("-Djava.util.prefs.systemRoot=" + isoDir.resolve("system-prefs"));
            command.add("-Djust.verify.sanitized-env=true");
            command.add("-Djust.verify.sink-mode=" + attemptMode.name());
            command.add("-Djust.verify.sink-policy-digest=" + sinkPolicy.digest());
            command.add("-Djust.verify.sink-disposition=" + sinkDecision.disposition().name());
            command.add("-Djust.verify.real-kind=" + realPlan.kind().name());
            command.add("-Djust.verify.run-id=" + protocolIdentity.runId());
            command.add("-Djust.verify.chain-fingerprint=" + protocolIdentity.chainFingerprint());
            command.add("-Djust.verify.sink-fingerprint=" + protocolIdentity.sinkFingerprint());
            command.add("-Djust.verify.nonce=" + protocolIdentity.nonce());
            command.add("-Djust.verify.artifact-fingerprint=" + protocolIdentity.artifactFingerprint());
            command.add("-Djust.verify.result-file=" + resultChannelFile.toAbsolutePath());
            String sinkCategory = chain.category() == null ? ""
                    : chain.category().replace('\n', '_').replace('\r', '_');
            if (sinkCategory.length() > 96) {
                sinkCategory = sinkCategory.substring(0, 96);
            }
            command.add("-Djust.verify.sink-category=" + sinkCategory);
            command.add("-Djust.verify.safe-scratch=" + isoTmp.toAbsolutePath());
            command.add("-Djust.verify.safe-java=" + javaExecPath.toAbsolutePath());
            if (attemptMode == SafeSinkAdapter.Mode.SAFE_REAL) {
                // System.loadLibrary resolves only the verifier-owned fixture.  The directory
                // is known before the VM starts, so the JDK's native search path is initialized
                // without mutating ClassLoader internals after target code is loaded. Native
                // fixtures live outside the writable scratch tree; the OS runner mounts/grants
                // this separate root read-only.
                if (realPlan.kind() == SafeSinkAdapter.RealSinkKind.NATIVE_FIXTURE
                        && nativeRoot != null) {
                    command.add("-Djust.verify.native-scratch=" + nativeRoot);
                    command.add("-Djava.library.path=" + nativeRoot);
                }
            }
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
                        + entrySpec + "|" + agentSpec + "|" + protocolToken + "|"
                        + protocolIdentity.runId() + "|" + protocolIdentity.chainFingerprint() + "|"
                        + protocolIdentity.sinkFingerprint() + "|" + protocolIdentity.nonce() + "|"
                        + protocolIdentity.artifactFingerprint() + "|" + attemptMode.name() + "|"
                        + realPlan.kind().name() + "|" + isoTmp.toAbsolutePath() + "|"
                        + (nativeRoot == null ? "" : nativeRoot.toAbsolutePath()) + "|"
                        + nativeIndex);
            } else {
                command.add("-javaagent:" + runtime.probeJar().toAbsolutePath() + "="
                        + canaryBootstrap + "|" + entrySpec + "|" + agentSpec + "|"
                        + protocolToken + "|" + protocolIdentity.runId() + "|"
                        + protocolIdentity.chainFingerprint() + "|" + protocolIdentity.sinkFingerprint() + "|"
                        + protocolIdentity.nonce() + "|" + protocolIdentity.artifactFingerprint()
                        + "|" + attemptMode.name() + "|" + realPlan.kind().name() + "|"
                        + isoTmp.toAbsolutePath() + "|" + javaExecPath.toAbsolutePath() + "|"
                        + (nativeRoot == null ? "" : nativeRoot.toAbsolutePath()) + "|"
                        + nativeIndex);
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
            // Keep the attestation token at the historical arg5 position.  The graph plan is
            // an optional extension field after it so old probe launchers and the current
            // parent remain wire-compatible while the child can reject malformed plans.
            command.add(protocolToken);
            // Declarative object-shape evidence is data-only. The child parses it with a
            // length/count-bounded decoder and applies only typed field/proxy operations.
            command.add(chain.constructionPlan() == null
                    ? "" : chain.constructionPlan().encodedForProbe());
            List<String> launchCommand = backend.command(command, isoDir);
            ProcessBuilder pb = new ProcessBuilder(launchCommand);
            pb.directory(isoDir.toFile());
            pb.redirectErrorStream(true);
            pb.environment().clear();
            pb.environment().putAll(sanitizedEnvironment(System.getenv(), runtime.javaHome(),
                    isoDir, isoTmp));
            runnerStarted = System.nanoTime();
            proc = pb.start();
            try {
                processMonitor = new ProcessTreeMonitor(proc);
            } catch (RuntimeException ignored) {
                // The resource sampler is telemetry only; failure to create its daemon thread
                // must not change an already valid dynamic attempt.
                processMonitor = null;
            }
            try {
                isolationSession = backend.attach(proc);
                // The secret travels over the child's standard input, never in argv, a system
                // property, or the environment. The probe consumes and closes stdin before it
                // loads target classes. A target can still write arbitrary stdout, but it
                // cannot forge a result-file frame without this one-time secret.
                sendResultChannelSecret(proc, resultChannelSecret);
                Files.writeString(isolationReady, isolationToken, StandardCharsets.US_ASCII,
                        java.nio.file.StandardOpenOption.CREATE_NEW,
                        java.nio.file.StandardOpenOption.WRITE);
                recordAttemptPhase("runner_startup", runnerStarted);
            } catch (IOException | RuntimeException isolationFailure) {
                return decorate(new VerifyResult(chain.key(), "UNTESTABLE",
                        "SANDBOX_UNAVAILABLE:OS_ATTACH_OR_HANDSHAKE:"
                                + isolationFailure.getClass().getSimpleName(), 1, 0L,
                        "SANDBOX_UNAVAILABLE", backend.id(), runtimeLabel(runtime),
                        attemptPolicyDigest, false, false, "CLEANUP_BEST_EFFORT"),
                        requestedTier, effectiveTier, fallbackReason);
            }
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
                ProtocolEvidence timeoutProtocol = protocolEvidence(resultChannelFile,
                        protocolIdentity, resultChannelSecret);
                boolean ready = protocolReady(timeoutProtocol, backend, attemptPolicyBindingDigest);
                return authenticatedResult(chain, "TIMEOUT", TIMEOUT_SECONDS + "s",
                        "PROCESS_TIMEOUT", false, ready,
                        backend, attemptPolicyDigest);
            }
            outputReader.join(1_000L);
            String output = capture.text();
            if (capture.overflow()) {
                ProtocolEvidence overflowProtocol = protocolEvidence(resultChannelFile,
                        protocolIdentity, resultChannelSecret);
                boolean ready = protocolReady(overflowProtocol, backend, attemptPolicyBindingDigest);
                return authenticatedResult(chain, "UNTESTABLE", "PROBE_OUTPUT_LIMIT",
                        "VERIFIER_CAPABILITY_LIMIT", false, ready, backend, attemptPolicyDigest);
            }
            // ExitOnOutOfMemoryError intentionally terminates the child without a terminal
            // protocol frame.  Treat the diagnostic only as a negative resource outcome: an
            // untrusted target's text can never create a positive status, but retaining the
            // reason prevents OOM from being mistaken for an ordinary no-trigger result.
            if (outOfMemoryDiagnostic(output)) {
                ProtocolEvidence oomProtocol = protocolEvidence(resultChannelFile,
                        protocolIdentity, resultChannelSecret);
                boolean ready = protocolReady(oomProtocol, backend, attemptPolicyBindingDigest);
                return authenticatedResult(chain, "UNTESTABLE", "PROCESS_OOM",
                        "PROCESS_OOM", false, ready, backend, attemptPolicyDigest);
            }
            // redirectErrorStream 合并了 stderr。只接受带本次 token 的 probe marker；目标
            // 工件可以任意写 stdout/stderr，普通文本永远不能升级为动态证据。
            String firstAny = firstDiagnostic(output);
            // Never use merged stdout/stderr for a positive result. It is intentionally
            // attacker-controlled because the target runs in the same JVM as the probe.
            ProtocolEvidence protocol = protocolEvidence(resultChannelFile, protocolIdentity,
                    resultChannelSecret);
            if (!protocol.bindingValid()) {
                return decorate(new VerifyResult(chain.key(), "UNTESTABLE",
                        "PROTOCOL_AUTHENTICATION_FAILED:IDENTITY_MISMATCH", 1, 0L,
                        "VERIFIER_CAPABILITY_LIMIT", backend.id(),
                        runtimeLabel(runtime), attemptPolicyDigest, false, false,
                        "CLEANUP_BEST_EFFORT"), requestedTier, effectiveTier, fallbackReason);
            }
            if (!protocol.ready()) {
                return decorate(new VerifyResult(chain.key(), "UNTESTABLE",
                        "SANDBOX_UNAVAILABLE:READY_EVENT_MISSING"
                                + (protocol.terminal() == null ? "" : ": observed=" + protocol.terminal()),
                        1, 0L, "SANDBOX_UNAVAILABLE", backend.id(), runtimeLabel(runtime),
                        attemptPolicyDigest, false, false, "CLEANUP_BEST_EFFORT"),
                        requestedTier, effectiveTier, fallbackReason);
            }
            if (!protocol.validOrder()) {
                return decorate(new VerifyResult(chain.key(), "UNTESTABLE",
                        "SANDBOX_UNAVAILABLE:READY_EVENT_ORDER_INVALID", 1, 0L,
                        "SANDBOX_UNAVAILABLE", backend.id(), runtimeLabel(runtime),
                        attemptPolicyDigest, false, false, "CLEANUP_BEST_EFFORT"),
                        requestedTier, effectiveTier, fallbackReason);
            }
            if (!backend.id().equals(protocol.readyBackend())) {
                return decorate(new VerifyResult(chain.key(), "UNTESTABLE",
                        "SANDBOX_UNAVAILABLE:READY_BACKEND_MISMATCH", 1, 0L,
                        "SANDBOX_UNAVAILABLE", backend.id(), runtimeLabel(runtime),
                        attemptPolicyDigest, false, false, "CLEANUP_BEST_EFFORT"),
                        requestedTier, effectiveTier, fallbackReason);
            }
            if (!attemptPolicyBindingDigest.equals(protocol.readyPolicyDigest())) {
                return decorate(new VerifyResult(chain.key(), "UNTESTABLE",
                        "SANDBOX_UNAVAILABLE:READY_POLICY_MISMATCH", 1, 0L,
                        "SANDBOX_UNAVAILABLE", backend.id(), runtimeLabel(runtime),
                        attemptPolicyDigest, false, false, "CLEANUP_BEST_EFFORT"),
                        requestedTier, effectiveTier, fallbackReason);
            }
            if (!backend.attestationVersion().equals(protocol.attestationVersion())) {
                return decorate(new VerifyResult(chain.key(), "UNTESTABLE",
                        "SANDBOX_UNAVAILABLE:READY_ATTESTATION_MISMATCH", 1, 0L,
                        "SANDBOX_UNAVAILABLE", backend.id(), runtimeLabel(runtime),
                        attemptPolicyDigest, false, false, "CLEANUP_BEST_EFFORT"),
                        requestedTier, effectiveTier, fallbackReason);
            }
            boolean ready = protocolReady(protocol, backend, attemptPolicyBindingDigest);
            if (attemptMode == SafeSinkAdapter.Mode.SAFE_REAL && !ready) {
                return authenticatedResult(chain, "UNTESTABLE",
                        "SANDBOX_UNAVAILABLE:READY_ATTESTATION_INCOMPLETE",
                        "SANDBOX_UNAVAILABLE", false, false, backend, attemptPolicyDigest);
            }
            String firstLine = protocol.terminal() == null ? "" : protocol.terminal();
            if (firstLine.startsWith("JNI_EXECUTED_SAFE")) {
                if (attemptMode == SafeSinkAdapter.Mode.SAFE_REAL
                        && !realEvidenceComplete(firstLine, realPlan.kind().name(),
                        nativeFixtureDigest(nativeFixtureResource()))) {
                    return authenticatedResult(chain, "UNTESTABLE",
                            "REAL_EVIDENCE_INCOMPLETE:JNI", "VERIFIER_CAPABILITY_LIMIT",
                            false, ready, backend, attemptPolicyDigest);
                }
                if (callback != null) callback.onConfirmed(chain, firstLine, true);
                return authenticatedResult(chain, "JNI_EXECUTED_SAFE", firstLine,
                        "JNI_LOAD_CALLBACK_SAFE_FIXTURE", true, ready, backend,
                        attemptPolicyDigest);
            }
            if (firstLine.startsWith("SINK_EXECUTED_SAFE")) {
                if (attemptMode == SafeSinkAdapter.Mode.SAFE_REAL
                        && !realEvidenceComplete(firstLine, realPlan.kind().name(),
                        nativeFixtureDigest(nativeFixtureResource()))) {
                    return authenticatedResult(chain, "UNTESTABLE",
                            "REAL_EVIDENCE_INCOMPLETE:SINK", "VERIFIER_CAPABILITY_LIMIT",
                            false, ready, backend, attemptPolicyDigest);
                }
                if (callback != null) callback.onConfirmed(chain, firstLine, true);
                return authenticatedResult(chain, "SINK_EXECUTED_SAFE", firstLine,
                        "REAL_SINK_BODY_SAFE_ARGUMENTS", true, ready, backend,
                        attemptPolicyDigest);
            }
            if (firstLine.startsWith("SAFE_EFFECT_OBSERVED")) {
                return authenticatedResult(chain, "SAFE_EFFECT_OBSERVED", firstLine,
                        "SAFE_EFFECT_OBSERVED", true, ready, backend, attemptPolicyDigest);
            }
            if (firstLine.startsWith("SINK_BLOCKED") || firstLine.startsWith("SINK_TRIGGERED")) {
                if (callback != null) callback.onConfirmed(chain, firstLine, true);
                String detail = firstLine.isBlank() ? "SINK_CANARY_BOUNDARY" : firstLine;
                String evidence = firstLine.contains("adapter=")
                        ? "SINK_CANARY_BOUNDARY_ADAPTER" : "SINK_CANARY_BOUNDARY";
                // The canary throws before the target sink body.  This is the genuine
                // boundary evidence, not an adapter distortion.
                return authenticatedResult(chain, "SINK_BLOCKED", detail, evidence, false, ready,
                        backend, attemptPolicyDigest);
            }
            if (firstLine.startsWith("CONCRETE_REACHED")) {
                return authenticatedResult(chain, "CONCRETE_REACHED", firstLine,
                        "CONCRETE_TRIGGER", false, ready, backend, attemptPolicyDigest);
            }
            if (firstLine.startsWith("EXECUTED")) {
                // 入口方法真实调用且正常返回——链可执行，但未证伪/证实 sink 到达
                return authenticatedResult(chain, "EXECUTED", firstLine,
                        "ENTRY_RETURNED", false, ready, backend, attemptPolicyDigest);
            }
            if (firstLine.startsWith("PARTIAL_PATH")) {
                return authenticatedResult(chain, "PARTIAL", firstLine,
                        "PARTIAL_PATH", false, ready, backend, attemptPolicyDigest);
            }
            if (firstLine.startsWith("SANDBOX_UNAVAILABLE")) {
                return authenticatedResult(chain, "UNTESTABLE", firstLine,
                        "SANDBOX_UNAVAILABLE", false, ready, backend, attemptPolicyDigest);
            }
            if (firstLine.startsWith("UNTESTABLE")) {
                return authenticatedResult(chain, "UNTESTABLE", firstLine,
                        "VERIFIER_CAPABILITY_LIMIT", false, ready, backend, attemptPolicyDigest);
            }
            int exit = proc.exitValue();
            if (exit != 0) {
                return authenticatedResult(chain, "PARTIAL",
                        "exit=" + exit + " probe-no-authenticated-status"
                                + (firstAny == null ? "" : " diagnostic=" + firstAny),
                        "PARTIAL_PATH", false, ready, backend, attemptPolicyDigest);
            }
            return authenticatedResult(chain, "FAILED",
                    "no-authenticated-probe-status"
                            + (firstAny == null ? "" : " diagnostic=" + firstAny),
                    "NO_TRIGGER", false, ready, backend, attemptPolicyDigest);

        } catch (Exception e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            return decorate(new VerifyResult(chain.key(), "UNTESTABLE",
                    e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName(),
                    1, 0L, "VERIFIER_CAPABILITY_LIMIT",
                    backend == null ? "UNKNOWN" : backend.id(), "UNKNOWN",
                    backend == null ? "UNKNOWN" : policyDigestFor(attemptMode, backend),
                    false, false, "CLEANUP_BEST_EFFORT"),
                    requestedTier, effectiveTier, fallbackReason);
        } finally {
            long cleanupStarted = System.nanoTime();
            // A target is denied Runtime.exec/ProcessBuilder, but a library can still create
            // an already-running descendant before the permission gate is consulted. Always
            // perform the bounded cleanup pass after normal exit as well as on timeout; the
            // cleanup routine only invokes taskkill while the root is alive, avoiding PID reuse
            // races for an already-reaped process.
            if (proc != null) {
                killProcessTree(proc);
            }
            if (isolationSession != null) {
                OsIsolation.ResourceMetrics metrics = isolationSession.metrics();
                recordResourceMax("child_peak_rss_mb", metrics.peakRssMb());
                recordResourceMax("child_peak_job_memory_mb", metrics.peakJobMemoryMb());
                recordResourceTotal("child_user_cpu_ms", metrics.userCpuMs());
                recordResourceMax("child_processes_total", metrics.totalProcesses());
                recordResourceMax("child_processes_active", metrics.activeProcesses());
            }
            if (processMonitor != null) {
                processMonitor.close();
                recordResourceMax("child_process_peak", processMonitor.peak());
            }
            recordResourceMax("uncollected_processes", liveProcessCount(
                    proc == null ? null : proc.toHandle()));
            long scratchBytes = saturatedDirectorySize(isoDir);
            long nativeBytes = saturatedDirectorySize(nativeRoot);
            recordResourceTotal("scratch_bytes", scratchBytes < 0L || nativeBytes < 0L
                    ? -1L : saturatedAdd(scratchBytes, nativeBytes));
            if (isolationSession != null) {
                isolationSession.close();
            }
            // 每条链一个隔离 cwd/tmp；不能只清理共享的 fat-jar 展开目录，否则批量扫描会
            // 在系统临时目录留下大量 just-verify-* 目录。
            deleteQuietly(isoDir);
            deleteQuietly(nativeRoot);
            boolean cleaned = !existsNoFollow(isoDir) && !existsNoFollow(nativeRoot);
            telemetry.recordCleanup(cleaned
                    && liveProcessCount(proc == null ? null : proc.toHandle()) == 0L);
            recordAttemptPhase("cleanup", cleanupStarted);
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

    /**
     * Validate the minimum authenticated facts required for a SAFE_REAL positive result.
     * The result channel proves that the frame was emitted by this probe, but it does not make
     * an incomplete frame meaningful. In particular, a before-call event, a body entry, or a
     * native load request alone is not a successful real-sink observation.
     */
    static boolean realEvidenceComplete(String status, String realKind) {
        return realEvidenceComplete(status, realKind, null);
    }

    static boolean realEvidenceComplete(String status, String realKind,
                                        String expectedNativeDigest) {
        if (status == null || realKind == null) {
            return false;
        }
        boolean jni = status.startsWith("JNI_EXECUTED_SAFE:");
        boolean sink = status.startsWith("SINK_EXECUTED_SAFE:");
        if (!jni && !sink) {
            return false;
        }
        Map<String, String> fields = new HashMap<>();
        int separator = status.indexOf(':');
        if (separator < 0 || separator == status.length() - 1) {
            return false;
        }
        for (String item : status.substring(separator + 1).split(";", -1)) {
            int equals = item.indexOf('=');
            if (equals > 0 && equals < item.length() - 1) {
                fields.put(item.substring(0, equals), item.substring(equals + 1));
            }
        }
        if (!"1".equals(fields.get("loaded"))
                || !"1".equals(fields.get("arguments"))) {
            return false;
        }
        if (jni) {
            String digest = fields.get("native_digest");
            return "NATIVE_FIXTURE".equals(realKind)
                    && "1".equals(fields.get("call"))
                    && "1".equals(fields.get("attempted"))
                    && "1".equals(fields.get("native_load"))
                    && "1".equals(fields.get("native_call"))
                    && fields.get("native_spec") != null
                    && !fields.get("native_spec").isBlank()
                    && digest != null
                    && digest.matches("[0-9a-fA-F]{64}")
                    && (expectedNativeDigest == null || !expectedNativeDigest.isBlank()
                    && expectedNativeDigest.equalsIgnoreCase(digest));
        }
        if ("APPLICATION_BODY".equals(realKind)) {
            return "1".equals(fields.get("body"))
                    && "1".equals(fields.get("body_returned"));
        }
        return fields.containsKey("call")
                && "1".equals(fields.get("call"))
                && "1".equals(fields.get("attempted"));
    }

    static record ProtocolEvidence(boolean ready, boolean validOrder,
                                   boolean bindingValid, String readyBackend,
                                   String readyPolicyDigest, boolean jobReady,
                                   String attestationVersion,
                                   String terminal) {
        ProtocolEvidence(boolean ready, boolean validOrder, boolean bindingValid,
                         String readyBackend, String terminal) {
            this(ready, validOrder, bindingValid, readyBackend, "", false, "", terminal);
        }

        ProtocolEvidence(boolean ready, boolean validOrder, boolean bindingValid,
                         String readyBackend, String readyPolicyDigest, String terminal) {
            this(ready, validOrder, bindingValid, readyBackend, readyPolicyDigest,
                    false, "", terminal);
        }
    }

    private boolean protocolReady(ProtocolEvidence evidence) {
        return protocolReady(evidence, isolationBackend, policyBindingDigest);
    }

    private boolean protocolReady(ProtocolEvidence evidence, OsIsolation.Backend backend,
                                  String bindingDigest) {
        return evidence != null && evidence.bindingValid() && evidence.ready()
                && evidence.validOrder()
                && backend != null
                && backend.id().equals(evidence.readyBackend())
                && bindingDigest != null && bindingDigest.equals(evidence.readyPolicyDigest())
                && backend.attestationVersion().equals(evidence.attestationVersion())
                && (!backend.id().startsWith("WINDOWS_") || evidence.jobReady());
    }

    /**
     * Parse the child-owned channel independently from target diagnostics. Readiness is a
     * protocol event, not an inference from the marker file or process exit; a terminal event
     * emitted before readiness invalidates the entire attempt.
     */
    static ProtocolEvidence protocolEvidence(String output, String token) {
        boolean ready = false;
        boolean validOrder = true;
        String readyBackend = "";
        String readyPolicyDigest = "";
        boolean jobReady = false;
        String attestationVersion = "";
        String terminal = null;
        if (output == null) {
            return new ProtocolEvidence(false, false, true, "", null);
        }
        for (String line : output.split("\\R")) {
            String status = authenticatedStatus(line.strip(), token);
            if (status == null) {
                continue;
            }
            if (status.startsWith("SANDBOX_READY")) {
                if (ready) {
                    validOrder = false;
                }
                ready = true;
                ReadyPayload readyPayload = readyPayload(status);
                readyBackend = readyPayload.backend();
                readyPolicyDigest = readyPayload.policyDigest();
                jobReady = readyPayload.jobReady();
                attestationVersion = readyPayload.attestationVersion();
                continue;
            }
            if (!ready) {
                validOrder = false;
            }
            if (terminal == null) {
                terminal = status;
            }
        }
        return new ProtocolEvidence(ready, validOrder, true, readyBackend,
                readyPolicyDigest, jobReady, attestationVersion, terminal);
    }

    /** Parse only the V2 channel bound to this exact chain, sink and artifact attempt. */
    static ProtocolEvidence protocolEvidence(String output, ProtocolIdentity expected) {
        boolean ready = false;
        boolean validOrder = true;
        boolean allFramesValid = true;
        String readyBackend = "";
        String readyPolicyDigest = "";
        boolean jobReady = false;
        String attestationVersion = "";
        String terminal = null;
        if (output == null || expected == null) {
            return new ProtocolEvidence(false, false, false, "", null);
        }
        boolean sawBoundPrefix = false;
        for (String raw : output.split("\\R")) {
            String line = raw.strip();
            if (!line.startsWith("JUST_VERIFY_V2:")) {
                continue;
            }
            sawBoundPrefix = true;
            ProtocolFrame frame = parseProtocolFrame(line, expected);
            if (frame == null) {
                allFramesValid = false;
                continue;
            }
            String status = frame.status();
            if (status.startsWith("SANDBOX_READY")) {
                if (ready) {
                    validOrder = false;
                }
                ready = true;
                ReadyPayload readyPayload = readyPayload(status);
                readyBackend = readyPayload.backend();
                readyPolicyDigest = readyPayload.policyDigest();
                jobReady = readyPayload.jobReady();
                attestationVersion = readyPayload.attestationVersion();
                continue;
            }
            if (!ready) {
                validOrder = false;
            }
            if (terminal != null) {
                validOrder = false;
            }
            if (terminal == null) {
                terminal = status;
            }
        }
        boolean bindingValid = sawBoundPrefix && allFramesValid;
        return new ProtocolEvidence(ready, validOrder, bindingValid, readyBackend,
                readyPolicyDigest, jobReady, attestationVersion, terminal);
    }

    /** Read and authenticate the probe-owned result file; target stdout is never sufficient. */
    static ProtocolEvidence protocolEvidence(Path resultFile, ProtocolIdentity expected,
                                              String secret) {
        if (resultFile == null || expected == null || !validResultSecret(secret)) {
            return new ProtocolEvidence(false, false, false, "", null);
        }
        try {
            if (!Files.isRegularFile(resultFile, java.nio.file.LinkOption.NOFOLLOW_LINKS)
                    || io.just.sast.util.ArchiveLimits.isLinkOrReparsePoint(resultFile)
                    || Files.size(resultFile) > MAX_OUTPUT_BYTES) {
                return new ProtocolEvidence(false, false, false, "", null);
            }
            StringBuilder frames = new StringBuilder();
            for (String raw : Files.readString(resultFile, StandardCharsets.US_ASCII)
                    .split("\\R")) {
                String line = raw.strip();
                if (line.isEmpty()) {
                    continue;
                }
                int macStart = RESULT_CHANNEL_PREFIX.length();
                if (!line.startsWith(RESULT_CHANNEL_PREFIX)) {
                    return new ProtocolEvidence(false, false, false, "", null);
                }
                int macEnd = line.indexOf(':', macStart);
                if (macEnd <= macStart) {
                    return new ProtocolEvidence(false, false, false, "", null);
                }
                String mac = line.substring(macStart, macEnd);
                String frame = line.substring(macEnd + 1);
                if (!mac.matches("[0-9a-fA-F]{64}")
                        || !MessageDigest.isEqual(mac.toLowerCase(Locale.ROOT)
                        .getBytes(StandardCharsets.US_ASCII), resultMac(secret, frame)
                        .getBytes(StandardCharsets.US_ASCII))) {
                    return new ProtocolEvidence(false, false, false, "", null);
                }
                if (frames.length() > 0) {
                    frames.append('\n');
                }
                frames.append(frame);
            }
            return protocolEvidence(frames.toString(), expected);
        } catch (IOException | RuntimeException failure) {
            return new ProtocolEvidence(false, false, false, "", null);
        }
    }

    private static boolean validResultSecret(String secret) {
        return secret != null && secret.matches("[0-9a-fA-F]{" + RESULT_SECRET_HEX_LENGTH + "}");
    }

    /** Deterministic HMAC helper shared by the parent parser and probe-channel contract tests. */
    static String resultMac(String secret, String frame) {
        if (!validResultSecret(secret) || frame == null) {
            return "";
        }
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.US_ASCII), "HmacSHA256"));
            return hex(mac.doFinal(frame.getBytes(StandardCharsets.UTF_8)));
        } catch (java.security.GeneralSecurityException impossible) {
            return "";
        }
    }

    private static void sendResultChannelSecret(Process process, String secret) throws IOException {
        if (process == null || !validResultSecret(secret)) {
            throw new IOException("result-channel-secret-invalid");
        }
        try (OutputStream input = process.getOutputStream()) {
            input.write((secret + "\n").getBytes(StandardCharsets.US_ASCII));
            input.flush();
        }
    }

    private record ReadyPayload(String backend, String policyDigest, boolean jobReady,
                                String attestationVersion) {
    }

    private static ReadyPayload readyPayload(String status) {
        int colon = status == null ? -1 : status.indexOf(':');
        String payload = colon < 0 ? "" : status.substring(colon + 1).strip();
        String backend = "";
        String policy = "";
        boolean job = false;
        String attestation = "";
        String[] fields = payload.split("\\|", -1);
        if (fields.length > 0) {
            backend = fields[0].strip();
        }
        for (int i = 1; i < fields.length; i++) {
            int equals = fields[i].indexOf('=');
            if (equals <= 0) {
                continue;
            }
            String key = fields[i].substring(0, equals).strip();
            String value = fields[i].substring(equals + 1).strip();
            switch (key) {
                case "policy" -> policy = value;
                case "job" -> job = "1".equals(value)
                        || "true".equalsIgnoreCase(value);
                case "attestation" -> attestation = value;
                default -> { }
            }
        }
        return new ReadyPayload(backend, policy, job, attestation);
    }

    private record ProtocolFrame(String status) {
    }

    private static ProtocolFrame parseProtocolFrame(String line, ProtocolIdentity expected) {
        String prefix = "JUST_VERIFY_V2:";
        String[] fields = line.substring(prefix.length()).split(":", 7);
        if (fields.length != 7 || !expected.token().equals(fields[0])
                || !expected.runId().equals(fields[1])
                || !expected.chainFingerprint().equals(fields[2])
                || !expected.sinkFingerprint().equals(fields[3])
                || !expected.nonce().equals(fields[4])
                || !expected.artifactFingerprint().equals(fields[5])
                || !isProtocolStatus(fields[6])) {
            return null;
        }
        return new ProtocolFrame(fields[6]);
    }

    private static String firstDiagnostic(String output) {
        if (output == null) {
            return null;
        }
        List<String> diagnostics = new ArrayList<>();
        for (String line : output.split("\\R")) {
            String trimmed = line.strip();
            if (!trimmed.isEmpty() && !trimmed.startsWith("JUST_VERIFY_V1:")
                    && !trimmed.startsWith("JUST_VERIFY_V2:")) {
                diagnostics.add(trimmed);
            }
        }
        if (diagnostics.isEmpty()) {
            return null;
        }
        int from = Math.max(0, diagnostics.size() - 8);
        String value = String.join(" | ", diagnostics.subList(from, diagnostics.size()));
        return value.length() > 2048 ? value.substring(value.length() - 2048) : value;
    }

    /** Keep shareable reports path-free while retaining stable capability/error categories. */
    private String sanitizeDetail(String detail) {
        String value = detail == null ? "" : detail;
        List<Path> knownPaths = new ArrayList<>();
        knownPaths.add(targetJar);
        if (targetJdkHome != null) {
            knownPaths.add(targetJdkHome);
        }
        knownPaths.add(ownJar);
        for (Path path : knownPaths) {
            if (path != null) {
                value = value.replace(path.toString(), "<path>");
            }
        }
        for (Path dependency : deps) {
            if (dependency != null) {
                value = value.replace(dependency.toAbsolutePath().normalize().toString(), "<path>");
            }
        }
        return value.replaceAll("(?i)(?:[A-Z]:[\\\\/]|/)(?:[^\\s;|,\\]\\[()]+[\\\\/])*[^\\s;|,\\]\\[()]*",
                "<path>");
    }

    static boolean outOfMemoryDiagnostic(String output) {
        if (output == null || output.isBlank()) {
            return false;
        }
        String lower = output.toLowerCase(Locale.ROOT);
        return lower.contains("outofmemoryerror")
                || lower.contains("java heap space")
                || lower.contains("gc overhead limit exceeded")
                || lower.contains("unable to create native thread");
    }

    private static boolean isProtocolStatus(String status) {
        return status.startsWith("SANDBOX_READY") || status.startsWith("SINK_BLOCKED")
                || status.startsWith("SINK_TRIGGERED")
                || status.startsWith("SINK_EXECUTED_SAFE")
                || status.startsWith("JNI_EXECUTED_SAFE")
                || status.startsWith("SAFE_EFFECT_OBSERVED")
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
                int callbackIndex = callbackIndexAfterSource(chain.hops(), directSourceIndex);
                String downstreamOwners = downstreamOwnerCandidates(chain.hops(), callbackIndex,
                        chain.sinkClass());
                String downstreamMethod = downstreamOwners.isEmpty() || callbackIndex <= 0
                        ? "" : safe(chain.hops().get(callbackIndex - 1).toName());
                return String.join("|", callback.toOwner(), callback.toName(), kind,
                        directSource.toOwner(), directSource.toName(),
                        directSource.desc() == null ? "" : directSource.desc(),
                        downstreamOwners, downstreamMethod);
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
        String downstreamOwner = downstreamOwnerCandidates(chain.hops(), triggerIndex,
                chain.sinkClass());
        String downstreamMethod = downstreamOwner.isEmpty() || triggerIndex <= 0
                ? "" : safe(chain.hops().get(triggerIndex - 1).toName());
        return String.join("|", trigger.toOwner(), trigger.toName(), kind,
                source.toOwner(), source.toName(), source.desc() == null ? "" : source.desc(),
                downstreamOwner, downstreamMethod);
    }

    /**
     * Recover the first callback immediately downstream of a direct source from the reverse
     * path. This is the small reusable part of JDD's IOCD-guided construction: the source
     * adapter can serialize a callback object in a matching inert container instead of always
     * serializing an unrelated ArrayList. If no callback is represented, the conservative
     * generic adapter remains in use.
     */
    private static ChainHop callbackAfterSource(List<ChainHop> hops, int sourceIndex) {
        int index = callbackIndexAfterSource(hops, sourceIndex);
        if (index < 0) {
            return null;
        }
        ChainHop candidate = hops.get(index);
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
        return null;
    }

    private static int callbackIndexAfterSource(List<ChainHop> hops, int sourceIndex) {
        if (hops == null || sourceIndex <= 0) {
            return -1;
        }
        for (int i = sourceIndex - 1; i >= 0; i--) {
            ChainHop candidate = hops.get(i);
            if ((callbackKind(candidate.toName()) != null
                    && candidate.toOwner() != null && !candidate.toOwner().isBlank())
                    || (callbackKind(candidate.fromName()) != null
                    && candidate.fromOwner() != null && !candidate.fromOwner().isBlank())) {
                return i;
            }
        }
        return -1;
    }

    /**
     * Carry a bounded declared-to-concrete receiver trail to the child. Interface owners are
     * common in reflective gadget paths (for example a Templates API backed by an implementation
     * class), so the child needs the nearby concrete candidate without knowing a benchmark name.
     */
    private static String downstreamOwnerCandidates(List<ChainHop> hops, int boundaryIndex,
                                                    String sinkOwner) {
        if (hops == null || boundaryIndex <= 0) {
            return "";
        }
        List<String> owners = new ArrayList<>();
        for (int i = boundaryIndex - 1; i >= 0 && owners.size() < 8; i--) {
            ChainHop candidate = hops.get(i);
            if (candidate == null || "bridge-source-deserialize".equals(candidate.reason())
                    || "bridge-trigger-src".equals(candidate.reason())) {
                continue;
            }
            String owner = safe(candidate.toOwner());
            if (!owner.isBlank() && !owner.equals(sinkOwner) && !owners.contains(owner)) {
                owners.add(owner);
            }
        }
        return String.join(",", owners);
    }

    private static String safe(String value) {
        return value == null ? "" : value;
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

    /**
     * The packaged verifier is self-contained, while the lifecycle test-probe JAR is a
     * deliberately small classifier. Keep the agent usable in {@code mvn test} by adding the
     * ASM code source used by the parent test runtime when the classifier does not contain it.
     * This entry is on the launcher class path only; {@code target-cp} remains isolated from it
     * through the explicit application loader.
     */
    private static String probeClasspath(Path probeJar) {
        List<String> entries = new ArrayList<>();
        addClasspathEntry(entries, probeJar);
        try {
            Class<?> asm = Class.forName("org.objectweb.asm.ClassVisitor", false,
                    ParallelVerifier.class.getClassLoader());
            if (asm.getProtectionDomain() != null
                    && asm.getProtectionDomain().getCodeSource() != null) {
                Path location = Path.of(asm.getProtectionDomain().getCodeSource()
                        .getLocation().toURI());
                addClasspathEntry(entries, location);
            }
        } catch (Exception | LinkageError ignored) {
            // A packaged shaded verifier does not need an external ASM code source.
        }
        return String.join(File.pathSeparator, entries);
    }

    private static void addClasspathEntry(List<String> entries, Path path) {
        if (path == null) {
            return;
        }
        String value = path.toAbsolutePath().normalize().toString();
        if (!entries.contains(value)) {
            entries.add(value);
        }
    }

    private static Path locateOwnJar() {
        try {
            Path location = Path.of(ParallelVerifier.class.getProtectionDomain()
                    .getCodeSource().getLocation().toURI()).toAbsolutePath().normalize();
            if (Files.isRegularFile(location)) {
                return location;
            }
            // Surefire and IDEs load the verifier from target/classes. Resolve the
            // lifecycle-produced probe artifacts beside that directory so test runs use the
            // same agent-capable contract as the packaged CLI instead of silently degrading
            // every dynamic case to verifier-artifact-missing.
            Path target = location.getParent();
            if (target != null) {
                // Prefer the shaded release artifact when it exists: the Windows/Linux
                // launcher is part of the single-JAR contract and the lifecycle test probe
                // intentionally contains only the verifier classes.  The test probe remains
                // the fallback for a `mvn test` run before package has produced the release JAR.
                for (String name : List.of("just-sast-0.2.0.jar",
                        "just-sast-0.2.0-testprobe.jar")) {
                    Path candidate = target.resolve(name);
                    if (Files.isRegularFile(candidate)) {
                        return candidate;
                    }
                }
            }
            return location;
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

    /** Java 8--23 can install the probe's deny-by-default manager programmatically. */
    static boolean securityManagerSupported(int feature) {
        return feature >= 8 && feature < 24;
    }

    private static String isolationReason(OsIsolation.Backend backend) {
        if (backend == null || backend.reason() == null || backend.reason().isBlank()) {
            return "";
        }
        String reason = backend.reason().replaceAll("[^A-Za-z0-9_.=-]", "_");
        return ":reason=" + (reason.length() > 128 ? reason.substring(0, 128) : reason);
    }

    private RuntimeSelection selectRuntime() {
        RuntimeSelection cached = selectedRuntime;
        if (cached != null) {
            return cached;
        }
        synchronized (this) {
            cached = selectedRuntime;
            if (cached == null) {
                cached = selectRuntimeUncached();
                selectedRuntime = cached;
            }
            return cached;
        }
    }

    private RuntimeSelection selectRuntimeUncached() {
        int required = requiredFeature(targetMajorVersion);
        int currentFeature = Runtime.version().feature();
        Path currentHome = Paths.get(System.getProperty("java.home", "."))
                .toAbsolutePath().normalize();

        if (targetJdkHome != null) {
            Path requestedJava = javaExecutable(targetJdkHome);
            if (!Files.isRegularFile(requestedJava)) {
                return new RuntimeSelection(null, null, 0,
                        "target-jdk-executable-missing");
            }
            int requestedFeature = jdkFeature(targetJdkHome);
            if (requestedFeature <= 0) {
                return new RuntimeSelection(null, null, requestedFeature,
                        "target-jdk-feature-unknown");
            }
            if (requestedFeature < required) {
                // An explicit target runtime is part of the scan identity.  Falling back to
                // the scanner JDK changes the JRT/API surface while leaving the user-visible
                // target selection unchanged, so it is never a valid dynamic result.
                return new RuntimeSelection(null, null, requestedFeature,
                        "target-jdk-too-old");
            }
            Path probe = probeJarFor(requestedFeature);
            if (probe == null) {
                return new RuntimeSelection(null, null, requestedFeature,
                        "verifier-artifact-missing");
            }
            return new RuntimeSelection(targetJdkHome, probe, requestedFeature,
                    "requested-target-jdk");
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
            if (Files.isRegularFile(legacy)) {
                return legacy;
            }
            // During tests the parent may have been loaded from target/classes while the
            // verifier JAR is produced in target. Keep the lookup deterministic and allow
            // an explicit package-first run to use the same artifact.
            Path parent = ownJar.getParent();
            if (parent != null) {
                legacy = parent.resolve("just-sast-0.2.0-verify8.jar");
                if (Files.isRegularFile(legacy)) {
                    return legacy;
                }
            }
            return null;
        }
        if (Files.isRegularFile(ownJar)) {
            return ownJar;
        }
        return null;
    }

    private static Path javaExecutable(Path javaHome) {
        Path unix = javaHome.resolve("bin").resolve("java");
        Path windows = javaHome.resolve("bin").resolve("java.exe");
        Path candidate = Files.isRegularFile(windows) ? windows : unix;
        try {
            return Files.isRegularFile(candidate) ? candidate.toRealPath() : candidate;
        } catch (IOException | RuntimeException ignored) {
            return candidate;
        }
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

    private static long liveProcessCount(ProcessHandle root) {
        if (root == null) {
            return 0L;
        }
        try {
            long count = root.isAlive() ? 1L : 0L;
            return saturatedAdd(count, root.descendants().filter(ProcessHandle::isAlive).count());
        } catch (RuntimeException ignored) {
            return -1L;
        }
    }

    private static long saturatedDirectorySize(Path path) {
        if (path == null || !existsNoFollow(path)) {
            return 0L;
        }
        try (var walk = Files.walk(path)) {
            long total = 0L;
            for (Path item : (Iterable<Path>) walk::iterator) {
                if (!Files.isRegularFile(item, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
                    continue;
                }
                try {
                    total = saturatedAdd(total, Math.max(0L, Files.size(item)));
                } catch (IOException ignored) {
                    return -1L;
                }
            }
            return total;
        } catch (IOException | RuntimeException ignored) {
            return -1L;
        }
    }

    private static boolean existsNoFollow(Path path) {
        return path != null && Files.exists(path, java.nio.file.LinkOption.NOFOLLOW_LINKS);
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
                for (int read; ; ) {
                    read = input.read(buffer);
                    if (read < 0) {
                        break;
                    }
                    if (read == 0) {
                        // InputStream is permitted to make no progress. A hostile or
                        // instrumented child must not turn output draining into a busy loop.
                        int one = input.read();
                        if (one < 0) {
                            break;
                        }
                        buffer[0] = (byte) one;
                        read = 1;
                    }
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
     * Bootstrap-visible canary/gate classes.  Boundary mode needs the marker only; SAFE_REAL
     * additionally emits calls to SinkExecutionGate from target bytecode, so the execution gate
     * and its typed SafeObject helper must live in the same bootstrap-only artifact.  Extract
     * the small immutable set from the probe code source and cache it per verifier.
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
                String executionGate = "/io/just/sast/verify/boot/SinkExecutionGate.class";
                String safeObject = "/io/just/sast/verify/boot/SinkExecutionGate$SafeObject.class";
                try (var in = ParallelVerifier.class.getResourceAsStream(marker);
                     var gin = ParallelVerifier.class.getResourceAsStream(gate);
                     var ein = ParallelVerifier.class.getResourceAsStream(executionGate);
                     var sin = ParallelVerifier.class.getResourceAsStream(safeObject)) {
                    if (in == null || gin == null || ein == null || sin == null) {
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
                        zip.putNextEntry(new java.util.zip.ZipEntry(
                                "io/just/sast/verify/boot/SinkExecutionGate.class"));
                        ein.transferTo(zip);
                        zip.closeEntry();
                        zip.putNextEntry(new java.util.zip.ZipEntry(
                                "io/just/sast/verify/boot/SinkExecutionGate$SafeObject.class"));
                        sin.transferTo(zip);
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
     * package-private ASM transformer. Only the immutable canary and execution-gate classes
     * belong to bootstrap, otherwise the JVM may load the transformer from bootstrap and fail
     * with an IllegalAccessError before the probe starts.
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
                String gate = "io/just/sast/verify/boot/SinkCanaryGate.class";
                String marker = "io/just/sast/verify/boot/SinkReachedError.class";
                String executionGate = "io/just/sast/verify/boot/SinkExecutionGate.class";
                String safeObject = "io/just/sast/verify/boot/SinkExecutionGate$SafeObject.class";
                java.util.jar.JarEntry gateEntry = source.getJarEntry(gate);
                java.util.jar.JarEntry markerEntry = source.getJarEntry(marker);
                java.util.jar.JarEntry executionGateEntry = source.getJarEntry(executionGate);
                java.util.jar.JarEntry safeObjectEntry = source.getJarEntry(safeObject);
                if (gateEntry == null || markerEntry == null
                        || executionGateEntry == null || safeObjectEntry == null) {
                    return Path.of(System.getProperty("java.io.tmpdir"),
                            "just-missing-legacy-canary-boot.jar");
                }
                Path out = Files.createTempFile("just-legacy-canary-boot-", ".jar");
                try (var zip = new java.util.zip.ZipOutputStream(Files.newOutputStream(out))) {
                    copyJarEntry(source, markerEntry, zip);
                    copyJarEntry(source, gateEntry, zip);
                    copyJarEntry(source, executionGateEntry, zip);
                    copyJarEntry(source, safeObjectEntry, zip);
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
        for (int attempt = 0; attempt < 4; attempt++) {
            if (p == null || !Files.exists(p, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
                return;
            }
            if (Files.isDirectory(p, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
                try (var walk = Files.walk(p)) {
                    walk.sorted(Comparator.reverseOrder())
                            .forEach(ParallelVerifier::deleteFileQuietly);
                } catch (Exception ignored) {
                }
            } else {
                deleteFileQuietly(p);
            }
            if (!Files.exists(p, java.nio.file.LinkOption.NOFOLLOW_LINKS)
                    || !isWindows() || attempt == 3) {
                return;
            }
            try {
                Thread.sleep(25L);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                return;
            }
        }
    }

    private static void deleteFileQuietly(Path p) {
        try {
            Files.deleteIfExists(p);
        } catch (Exception ignored) {
        }
    }

    private static long saturatedAdd(long left, long right) {
        return Long.MAX_VALUE - left < right ? Long.MAX_VALUE : left + right;
    }

    private synchronized String artifactFingerprint() throws IOException {
        if (artifactFingerprint != null) {
            return artifactFingerprint;
        }
        artifactFingerprint = ArtifactFingerprint.sha256(targetJar);
        return artifactFingerprint;
    }

    /** Materialize the fixed native fixture before the target child receives its read-only root. */
    private static boolean prepareNativeFixture(Path nativeRoot) {
        String resource = nativeFixtureResource();
        String expected = nativeFixtureDigest(resource);
        if (resource.isBlank() || expected.isBlank() || nativeRoot == null
                || !Files.isDirectory(nativeRoot, java.nio.file.LinkOption.NOFOLLOW_LINKS)
                || io.just.sast.util.ArchiveLimits.isLinkOrReparsePoint(nativeRoot)) {
            return false;
        }
        Path output = nativeRoot.resolve(nativeFileName(resource)).normalize();
        if (!output.startsWith(nativeRoot) || Files.exists(output,
                java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
            return false;
        }
        boolean success = false;
        try (InputStream input = ParallelVerifier.class.getResourceAsStream(resource)) {
            if (input == null) return false;
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            long copied = 0L;
            try (OutputStream stream = Files.newOutputStream(output,
                    java.nio.file.StandardOpenOption.CREATE_NEW,
                    java.nio.file.StandardOpenOption.WRITE)) {
                byte[] buffer = new byte[32 * 1024];
                for (int read; (read = input.read(buffer)) >= 0; ) {
                    if (read == 0) continue;
                    copied += read;
                    if (copied > 16L * 1024L * 1024L) return false;
                    digest.update(buffer, 0, read);
                    stream.write(buffer, 0, read);
                }
            }
            success = copied > 0L && expected.equalsIgnoreCase(hex(digest.digest()))
                    && Files.isRegularFile(output, java.nio.file.LinkOption.NOFOLLOW_LINKS);
            return success;
        } catch (IOException | NoSuchAlgorithmException | RuntimeException failure) {
            return false;
        } finally {
            if (!success) deleteFileQuietly(output);
        }
    }

    private static String nativeFixtureResource() {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        String arch = System.getProperty("os.arch", "").toLowerCase(Locale.ROOT);
        String platform = os.contains("win") ? "windows" : os.contains("linux") ? "linux"
                : os.contains("mac") || os.contains("darwin") ? "macos" : "";
        String cpu = arch.contains("amd64") || arch.contains("x86_64") || arch.contains("x64")
                ? "x86-64" : arch.contains("aarch64") || arch.contains("arm64")
                ? "aarch64" : arch.matches("i[3-6]86") || arch.equals("x86") ? "x86" : "";
        if (platform.isBlank() || cpu.isBlank()) return "";
        return "/native/" + platform + "-" + cpu + "/" + System.mapLibraryName("just-safe-jni");
    }

    private static String nativeFileName(String resource) {
        int slash = resource.lastIndexOf('/');
        return slash < 0 ? resource : resource.substring(slash + 1);
    }

    private static String nativeFixtureDigest(String resource) {
        if ("/native/windows-x86-64/just-safe-jni.dll".equals(resource)) {
            return "9BEC06088563F4F6D33D91BB04DF4F05BF1C53FD38939B6C7600F4BF036C0506";
        }
        return "";
    }

    /** Stable identity for the persistent verification summary; failures remain explicit. */
    public String artifactFingerprintForReport() {
        try {
            return artifactFingerprint();
        } catch (IOException | RuntimeException failure) {
            return "UNAVAILABLE:" + failure.getClass().getSimpleName();
        }
    }

    private static String sha256Hex(String value) {
        try {
            return hex(java.security.MessageDigest.getInstance("SHA-256")
                    .digest((value == null ? "" : value).getBytes(StandardCharsets.UTF_8)));
        } catch (java.security.NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("required SHA-256 digest unavailable", impossible);
        }
    }

    private static String hex(byte[] bytes) {
        StringBuilder result = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) {
            result.append(String.format(Locale.ROOT, "%02x", value & 0xff));
        }
        return result.toString();
    }

    private static String policyDigestOf(String policy) {
        try {
            byte[] digest = java.security.MessageDigest.getInstance("SHA-256")
                    .digest(policy.getBytes(StandardCharsets.UTF_8));
            StringBuilder result = new StringBuilder(digest.length * 2);
            for (byte value : digest) {
                result.append(String.format(Locale.ROOT, "%02x", value & 0xff));
            }
            return result.toString();
        } catch (java.security.NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("required SHA-256 digest unavailable", impossible);
        }
    }

    private static String policyDigestFor(SafeSinkAdapter.Mode mode,
                                          OsIsolation.Backend backend) {
        SafeSinkAdapter.Mode effectiveMode = mode == null
                ? SafeSinkAdapter.Mode.BOUNDARY : mode;
        if (backend == null) {
            return SafeSinkAdapter.policyDigest(effectiveMode) + ";os=UNKNOWN";
        }
        return SafeSinkAdapter.policyDigest(effectiveMode)
                + ";os=" + backend.policyDigest()
                + ";attestation=" + backend.attestationVersion()
                + ";loopback=" + (effectiveMode == SafeSinkAdapter.Mode.SAFE_REAL)
                + ";job_object=" + (backend.level() == OsIsolation.Level.PROCESS_RESOURCE);
    }
}
