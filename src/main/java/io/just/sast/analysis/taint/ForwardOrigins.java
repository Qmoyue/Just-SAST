package io.just.sast.analysis.taint;

import io.just.sast.cpg.build.Cfg;
import io.just.sast.cpg.build.CfgEdge;
import io.just.sast.cpg.build.CfgLabel;
import io.just.sast.cpg.build.CpgIndex;
import io.just.sast.model.Descriptor;
import io.just.sast.model.InsnFact;
import io.just.sast.model.InvokeDynamicRef;
import io.just.sast.model.MethodInfo;
import io.just.sast.model.MethodRef;
import io.just.sast.model.Op;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.AbstractMap;
import java.util.AbstractSet;
import java.util.Arrays;
import java.util.Collections;
import java.util.Deque;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.FutureTask;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.atomic.LongAdder;
import java.util.concurrent.atomic.AtomicLong;
import java.util.IdentityHashMap;

/**
 * 方法内正向抽象解释：计算每条指令执行前的栈/局部变量值来源。
 * 惰性计算 + 缓存；栈槽合并 = 来源集合并（收敛）；数组写入记录元素来源。
 *
 * 栈语义对齐 JVM 规范（精度根基）：
 * - 栈条目携带 category-2 标记：long/double 为单条目占 2 槽；
 *   POP2/DUP2/DUP2_X1/DUP2_X2/DUP_X2 按 JVM 类别语义解释（顶部或下方值为 cat-2 时按单值操作）
 * - TABLESWITCH/LOOKUPSWITCH 弹出 key
 * - 异常边进入 handler：清空栈、压入单个异常对象（Unknown），locals 保留
 * - wide 参数/存储占 2 槽（次槽来源清除）
 */
public final class ForwardOrigins {

    @FunctionalInterface
    interface CallIdLookup {
        Long find(String methodKey, int offset);
    }

    /** 栈槽：值来源集合 + category-2 标记（long/double 单条目）。 */
    public record Slot(Set<ValueOrigin> origins, boolean cat2) {}

    /** 某点的值来源状态。 */
    public static final class State {
        /*
         * A state exists for every reachable instruction.  Keeping two ArrayList objects
         * (and their backing arrays) in every state made large methods disproportionately
         * expensive.  The public List accessors remain for compatibility, while the retained
         * representation is two compact arrays.  Views are created only when a caller asks
         * for them and are never used by the transfer hot path.
         */
        private final Slot[] stack;
        private final Set<ValueOrigin>[] locals;
        private final boolean originsTruncated;
        /**
         * Cached content fingerprint used as a negative equality filter at CFG joins. State
         * equality is still deep after a match, so hash collisions are harmless; the important
         * case is avoiding repeated Set.equals scans when two states differ in one origin. The
         * fingerprint is content-based (not identity-based), preserving the public equals/hash
         * contract even when equivalent origin sets were allocated independently.
         */
        private final int equalityFingerprint;
        private transient List<Slot> stackView;
        private transient List<Set<ValueOrigin>> localsView;

        @SuppressWarnings("unchecked")
        public State(List<Slot> stack, List<Set<ValueOrigin>> locals) {
            this.stack = freezeStack(stack);
            this.locals = freezeLocals(locals);
            this.originsTruncated = false;
            this.equalityFingerprint = contentFingerprint(this.stack, this.locals, false);
        }

        private State(Slot[] stack, Set<ValueOrigin>[] locals) {
            this(stack, locals, false);
        }

        private State(Slot[] stack, Set<ValueOrigin>[] locals, boolean originsTruncated) {
            // All callers of this constructor create fresh arrays and only pass immutable
            // origin sets from an existing State or union().  The public List constructor
            // above remains defensive; the transfer hot path must not deep-copy every
            // origin set at every CFG merge.
            this.stack = stack == null ? new Slot[0] : stack;
            this.locals = locals == null ? emptyLocals() : locals;
            this.originsTruncated = originsTruncated;
            this.equalityFingerprint = contentFingerprint(this.stack, this.locals,
                    originsTruncated);
        }

        @SuppressWarnings("unchecked")
        private static Set<ValueOrigin>[] emptyLocals() {
            return (Set<ValueOrigin>[]) new Set<?>[0];
        }

        public List<Slot> stack() {
            List<Slot> view = stackView;
            if (view != null) {
                return view;
            }
            view = stack.length == 0 ? List.of()
                    : Collections.unmodifiableList(Arrays.asList(stack));
            stackView = view;
            return view;
        }

        public List<Set<ValueOrigin>> locals() {
            List<Set<ValueOrigin>> view = localsView;
            if (view != null) {
                return view;
            }
            view = locals.length == 0 ? List.of()
                    : Collections.unmodifiableList(Arrays.asList(locals));
            localsView = view;
            return view;
        }

        private Slot[] stackArray() {
            return stack;
        }

        private Set<ValueOrigin>[] localsArray() {
            return locals;
        }

        boolean originsTruncated() {
            return originsTruncated;
        }

        public State merge(State other) {
            if (other == null) {
                return this;
            }
            if (equals(other)) {
                return this;
            }
            int stackCount = Math.max(stack.length, other.stack.length);
            Slot[] mergedStack = new Slot[stackCount];
            boolean truncated = originsTruncated || other.originsTruncated;
            boolean changed = stackCount != stack.length || truncated != originsTruncated;
            for (int i = 0; i < stackCount; i++) {
                Slot a = i < stack.length ? stack[i] : UNKNOWN_SLOT;
                Slot b = i < other.stack.length ? other.stack[i] : UNKNOWN_SLOT;
                if (a == b && a.cat2() == b.cat2()) {
                    mergedStack[i] = a;
                    continue;
                }
                OriginUnion union = boundedUnion(a.origins(), b.origins());
                truncated |= union.truncated();
                boolean cat2 = a.cat2() || b.cat2();
                if (union.values() == a.origins() && cat2 == a.cat2()) {
                    mergedStack[i] = a;
                } else {
                    mergedStack[i] = new Slot(union.values(), cat2);
                    changed = true;
                }
            }
            int localCount = Math.max(locals.length, other.locals.length);
            @SuppressWarnings("unchecked")
            Set<ValueOrigin>[] mergedLocals = (Set<ValueOrigin>[]) new Set<?>[localCount];
            changed |= localCount != locals.length;
            for (int i = 0; i < localCount; i++) {
                Set<ValueOrigin> a = i < locals.length ? locals[i] : UNKNOWN_ORIGINS;
                Set<ValueOrigin> b = i < other.locals.length ? other.locals[i] : UNKNOWN_ORIGINS;
                if (a == b) {
                    mergedLocals[i] = a;
                    continue;
                }
                OriginUnion union = boundedUnion(a, b);
                truncated |= union.truncated();
                if (union.values() == a) {
                    mergedLocals[i] = a;
                } else {
                    mergedLocals[i] = union.values();
                    changed = true;
                }
            }
            changed |= truncated != originsTruncated;
            if (!changed) {
                return this;
            }
            return new State(mergedStack, mergedLocals, truncated);
        }

        private static Slot[] freezeStack(List<Slot> values) {
            return values == null ? new Slot[0]
                    : freezeStack(values.toArray(new Slot[0]));
        }

        private static Slot[] freezeStack(Slot[] values) {
            if (values == null || values.length == 0) {
                return new Slot[0];
            }
            Slot[] copy = new Slot[values.length];
            for (int i = 0; i < values.length; i++) {
                Slot value = values[i];
                copy[i] = value == null ? UNKNOWN_SLOT
                        : new Slot(freezeOrigins(value.origins()), value.cat2());
            }
            return copy;
        }

        @SuppressWarnings("unchecked")
        private static Set<ValueOrigin>[] freezeLocals(List<Set<ValueOrigin>> values) {
            return values == null ? new Set[0]
                    : freezeLocals(values.toArray(new Set[0]));
        }

        @SuppressWarnings("unchecked")
        private static Set<ValueOrigin>[] freezeLocals(Set<ValueOrigin>[] values) {
            if (values == null || values.length == 0) {
                return (Set<ValueOrigin>[]) new Set<?>[0];
            }
            Set<ValueOrigin>[] copy = (Set<ValueOrigin>[]) new Set<?>[values.length];
            for (int i = 0; i < values.length; i++) {
                copy[i] = freezeOrigins(values[i]);
            }
            return copy;
        }

        @Override
        public boolean equals(Object object) {
            if (this == object) {
                return true;
            }
            if (!(object instanceof State other)) {
                return false;
            }
            if (equalityFingerprint != other.equalityFingerprint) {
                return false;
            }
            return Arrays.equals(stack, other.stack) && Arrays.equals(locals, other.locals)
                    && originsTruncated == other.originsTruncated;
        }

        @Override
        public int hashCode() {
            return equalityFingerprint;
        }

        private static int contentFingerprint(Slot[] stack, Set<ValueOrigin>[] locals,
                                              boolean originsTruncated) {
            return 31 * (31 * Arrays.hashCode(stack) + Arrays.hashCode(locals))
                    + Boolean.hashCode(originsTruncated);
        }
    }

    /** 方法级结果。 */
    public record Result(Map<Integer, State> stateBefore,
                         Map<ValueOrigin, Set<ValueOrigin>> arrayElements,
                         Map<ValueOrigin, Map<Integer, Set<ValueOrigin>>> indexedArrayElements,
                         boolean incomplete,
                         Set<String> incompleteReasons) {

        public Result {
            stateBefore = freezeStates(stateBefore);
            arrayElements = freezeArrayElements(arrayElements);
            indexedArrayElements = freezeIndexedArrayElements(indexedArrayElements);
            incompleteReasons = incompleteReasons == null ? Set.of() : Set.copyOf(incompleteReasons);
            incomplete = incomplete || !incompleteReasons.isEmpty();
        }

        public Result(Map<Integer, State> stateBefore,
                      Map<ValueOrigin, Set<ValueOrigin>> arrayElements) {
            this(stateBefore, arrayElements, Map.of(), false, Set.of());
        }

        public Result(Map<Integer, State> stateBefore,
                      Map<ValueOrigin, Set<ValueOrigin>> arrayElements,
                      Map<ValueOrigin, Map<Integer, Set<ValueOrigin>>> indexedArrayElements) {
            this(stateBefore, arrayElements, indexedArrayElements, false, Set.of());
        }
    }

    private static final Set<ValueOrigin> UNKNOWN_ORIGINS =
            Set.of(new ValueOrigin.Unknown());
    private static final Slot UNKNOWN_SLOT = new Slot(UNKNOWN_ORIGINS, false);

    private static Set<ValueOrigin> freezeOrigins(Set<ValueOrigin> values) {
        if (values == null || values.isEmpty()) {
            return Set.of();
        }
        LinkedHashSet<ValueOrigin> copy = new LinkedHashSet<>();
        for (ValueOrigin value : ValueOriginOrder.sorted(values)) {
            if (value != null) {
                copy.add(value);
            }
        }
        return copy.isEmpty() ? Set.of() : Collections.unmodifiableSet(copy);
    }

    private static Map<Integer, State> freezeStates(Map<Integer, State> values) {
        if (values == null || values.isEmpty()) {
            return Map.of();
        }
        List<Integer> keys = new ArrayList<>();
        for (Integer key : values.keySet()) {
            if (key != null) {
                keys.add(key);
            }
        }
        Collections.sort(keys);
        Map<Integer, State> copy = new java.util.LinkedHashMap<>();
        for (Integer key : keys) {
            State state = values.get(key);
            if (state != null) {
                copy.put(key, state);
            }
        }
        return Collections.unmodifiableMap(copy);
    }

    private static Map<ValueOrigin, Set<ValueOrigin>> freezeArrayElements(
            Map<ValueOrigin, Set<ValueOrigin>> values) {
        if (values == null || values.isEmpty()) {
            return Map.of();
        }
        Map<ValueOrigin, Set<ValueOrigin>> copy = new HashMap<>();
        for (Map.Entry<ValueOrigin, Set<ValueOrigin>> entry : values.entrySet()) {
            if (entry.getKey() != null) {
                copy.put(entry.getKey(), freezeOrigins(entry.getValue()));
            }
        }
        return Collections.unmodifiableMap(copy);
    }

    private static Map<ValueOrigin, Map<Integer, Set<ValueOrigin>>> freezeIndexedArrayElements(
            Map<ValueOrigin, Map<Integer, Set<ValueOrigin>>> values) {
        if (values == null || values.isEmpty()) {
            return Map.of();
        }
        Map<ValueOrigin, Map<Integer, Set<ValueOrigin>>> copy = new HashMap<>();
        for (Map.Entry<ValueOrigin, Map<Integer, Set<ValueOrigin>>> entry : values.entrySet()) {
            if (entry.getKey() == null || entry.getValue() == null) {
                continue;
            }
            Map<Integer, Set<ValueOrigin>> byIndex = new HashMap<>();
            for (Map.Entry<Integer, Set<ValueOrigin>> indexed : entry.getValue().entrySet()) {
                if (indexed.getKey() != null) {
                    byIndex.put(indexed.getKey(), freezeOrigins(indexed.getValue()));
                }
            }
            copy.put(entry.getKey(), Collections.unmodifiableMap(byIndex));
        }
        return Collections.unmodifiableMap(copy);
    }

    /**
     * Forward state is a memoization aid, never a semantic source of truth. Keeping every
     * result is unsafe for dependency-heavy fat jars: a few hundred thousand short methods
     * are enough to retain millions of immutable Slot/ValueOrigin objects, while a handful of
     * long methods dominate the remaining footprint. Admit only compact results and evict
     * old entries in bounded batches; an evicted method is simply interpreted again.
     */
    static final int MAX_CACHE_ENTRIES = 16_384;
    static final int MAX_CACHE_BURST = 256;
    static final int MAX_CACHED_INSTRUCTIONS = 256;
    static final int MAX_CACHED_STATES = 512;
    static final int MAX_CACHED_ARRAYS = 128;
    /**
     * A merge is a may-origin union.  Without a per-value bound, branch-heavy library
     * methods turn every later merge and equality check into a scan of an ever-growing set.
     * The retained prefix is useful for path discovery; the State flag makes the loss of
     * alternatives an explicit completeness boundary instead of a silent false proof.
     */
    static final int MAX_ORIGIN_SET = 512;
    /** Hard work bound for one method; partial states remain useful but are explicitly marked. */
    static final int MAX_METHOD_WORK = 100_000;

    private final CallIdLookup callIdLookup;
    private final java.util.concurrent.ConcurrentHashMap<String, Result> cache =
            new java.util.concurrent.ConcurrentHashMap<>();
    /**
     * In-flight summaries are coordinated outside the cache map.  A CHM
     * {@code computeIfAbsent} mapping function runs while holding a bin lock;
     * freezing a large CFG state under that lock can block every other sink
     * worker on one hot method.  FutureTask keeps one owner per key without
     * retaining the map monitor during interpretation, and also gives waiters
     * an interruptible wait.
     */
    private final java.util.concurrent.ConcurrentHashMap<String, FutureTask<Result>> inFlight =
            new java.util.concurrent.ConcurrentHashMap<>();
    /** Admission order is bounded by the number of admitted keys, not by cache hits. */
    private final ConcurrentLinkedQueue<String> cacheOrder = new ConcurrentLinkedQueue<>();
    private final java.util.concurrent.ConcurrentHashMap<String, Boolean> admittedKeys =
            new java.util.concurrent.ConcurrentHashMap<>();
    private final Object cacheTrimLock = new Object();
    private final CpgIndex.CfgProvider cfgProvider;
    private final LongAdder analysisRuns = new LongAdder();
    /**
     * The scan-wide cache avoids re-interpreting a method, but its string-keyed concurrent
     * lookup is still expensive when a backward sink trace revisits one method millions of
     * times.  This bounded identity cache is local to the calling worker, so the hot path skips
     * key construction and CHM bookkeeping without retaining an unbounded copy per thread.
     */
    /*
     * Keep the cache at the original bounded size.  A 32K experiment did not produce a
     * repeatable wall-time win and increased worker-local heap; an unproven capacity increase
     * is not an acceptable performance optimization.  The useful hot-path optimization is the
     * identity fast path above and the caller-side reuse of already computed origin results.
     */
    private static final int MAX_THREAD_LOCAL_CACHE_ENTRIES = 8_192;
    private final AtomicLong cacheGeneration = new AtomicLong();
    private final ConcurrentLinkedQueue<LocalCache> metricCaches = new ConcurrentLinkedQueue<>();
    private final ThreadLocal<LocalCache> localCaches = ThreadLocal.withInitial(() -> {
        LocalCache cache = new LocalCache();
        metricCaches.add(cache);
        return cache;
    });

    private static final class LocalCache {
        private long generation = Long.MIN_VALUE;
        private final IdentityHashMap<MethodInfo, Result> values = new IdentityHashMap<>();
        /**
         * The canonical cache is keyed by a structural string so independent CPG views can
         * share a summary.  Rebuilding that string on every local-cache miss is measurable in
         * large reverse traces. Keep the bounded key beside the bounded identity result cache;
         * it is evicted with the same method and never becomes a second unbounded index.
         */
        private final IdentityHashMap<MethodInfo, String> keys = new IdentityHashMap<>();
        /** FIFO admission order; evict a bounded prefix instead of flushing all hot summaries. */
        private final Deque<MethodInfo> admissionOrder = new ArrayDeque<>();
        private MethodInfo lastMethod;
        private Result lastResult;
        /** Metrics are read after the scan; keeping them thread-local avoids an atomic hot path. */
        private long computeCalls;
        private long cacheHits;
    }

    public ForwardOrigins(Map<String, Long> callIdByKey) {
        this(callIdByKey, Cfg::computeIndexed);
    }

    public ForwardOrigins(Map<String, Long> callIdByKey, CpgIndex.CfgProvider cfgProvider) {
        this((methodKey, offset) -> callIdByKey == null ? null
                : callIdByKey.get(methodKey + "@" + offset), cfgProvider);
    }

    /** Package-local constructor used by the frozen CPG graph to avoid a string-key lookup
     * for every invoke instruction in forward interpretation. */
    ForwardOrigins(CallIdLookup callIdLookup, CpgIndex.CfgProvider cfgProvider) {
        this.callIdLookup = callIdLookup == null ? (methodKey, offset) -> null : callIdLookup;
        this.cfgProvider = cfgProvider == null ? Cfg::computeIndexed : cfgProvider;
    }

    public Result compute(MethodInfo method) {
        LocalCache local = localCaches.get();
        local.computeCalls++;
        long generation = cacheGeneration.get();
        if (local.generation != generation) {
            local.values.clear();
            local.keys.clear();
            local.admissionOrder.clear();
            local.lastMethod = null;
            local.lastResult = null;
            local.generation = generation;
        }
        if (method != null) {
            if (method == local.lastMethod && local.lastResult != null) {
                local.cacheHits++;
                return local.lastResult;
            }
            Result localResult = local.values.get(method);
            if (localResult != null) {
                local.cacheHits++;
                local.lastMethod = method;
                local.lastResult = localResult;
                return localResult;
            }
        }
        String localKey = method == null ? null : local.keys.get(method);
        final String key = localKey == null ? CfgKey.of(method) : localKey;
        Result result = cache.get(key);
        if (result != null) {
            local.cacheHits++;
        }
        if (result == null) {
            FutureTask<Result> task = new FutureTask<>(() -> analyze(method, key));
            FutureTask<Result> owner = inFlight.putIfAbsent(key, task);
            boolean ownsTask = owner == null;
            if (ownsTask) {
                owner = task;
                task.run();
            }
            try {
                result = owner.get();
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                return interruptedResult();
            } catch (ExecutionException failure) {
                Throwable cause = failure.getCause();
                if (cause instanceof Error error) {
                    throw error;
                }
                return incompleteResult("ANALYSIS_FAILURE");
            } finally {
                if (ownsTask) {
                    inFlight.remove(key, task);
                }
            }
            if (cacheable(method, result)) {
                Result previous = cache.putIfAbsent(key, result);
                if (previous != null) {
                    result = previous;
                }
            }
        }
        if (!cacheable(method, result)) {
            cache.remove(key, result);
            admittedKeys.remove(key);
            return result;
        }
        if (method != null && local.values.size() >= MAX_THREAD_LOCAL_CACHE_ENTRIES) {
            int evictions = Math.max(1, MAX_THREAD_LOCAL_CACHE_ENTRIES / 8);
            while (evictions-- > 0 && !local.admissionOrder.isEmpty()) {
                MethodInfo victim = local.admissionOrder.removeFirst();
                local.values.remove(victim);
                local.keys.remove(victim);
            }
        }
        if (method != null) {
            local.keys.put(method, key);
            Result previous = local.values.put(method, result);
            if (previous == null) {
                local.admissionOrder.addLast(method);
            }
            local.lastMethod = method;
            local.lastResult = result;
        }
        if (admittedKeys.putIfAbsent(key, Boolean.TRUE) == null) {
            cacheOrder.offer(key);
        }
        trimCacheIfNeeded();
        return result;
    }

    /** Number of retained forward summaries, exposed for scan telemetry and tests. */
    int cacheSize() {
        return cache.size();
    }

    long computeCalls() {
        long total = 0L;
        for (LocalCache cache : metricCaches) {
            total += cache.computeCalls;
        }
        return total;
    }

    long cacheHits() {
        long total = 0L;
        for (LocalCache cache : metricCaches) {
            total += cache.cacheHits;
        }
        return total;
    }

    long analysisRuns() {
        return analysisRuns.sum();
    }

    /** Release retained method summaries once reports no longer need semantic analysis. */
    void clearCache() {
        cache.clear();
        admittedKeys.clear();
        cacheOrder.clear();
        inFlight.clear();
        cacheGeneration.incrementAndGet();
    }

    private static Result interruptedResult() {
        return incompleteResult("INTERRUPTED");
    }

    private static Result incompleteResult(String reason) {
        return new Result(Map.of(), Map.of(), Map.of(), true, Set.of(reason));
    }

    private static boolean cacheable(MethodInfo method, Result result) {
        if (method == null || result == null) {
            return false;
        }
        // Interruptions and computation failures are transient and must never poison a later
        // caller.  Deterministic bounded summaries (for example ORIGIN_SET_CAP) are safe to
        // memoize as partial data: callers receive the same conservative facts, while the
        // explicit reason keeps them from being mistaken for a complete proof.
        if (result.incomplete() && (result.incompleteReasons().contains("INTERRUPTED")
                || result.incompleteReasons().contains("ANALYSIS_FAILURE"))) {
            return false;
        }
        // Size is deliberately not used as a binary admission gate.  A large but frequently
        // requested summary is cheaper and safer to retain once than to reinterpret for every
        // sink; the entry cap above bounds retention, while incomplete summaries never become
        // proofs.  The legacy size constants remain as documentation for future weighted
        // admission, not as a source of repeated work.
        return true;
    }

    private void trimCacheIfNeeded() {
        if (cache.size() <= MAX_CACHE_ENTRIES + MAX_CACHE_BURST) {
            return;
        }
        synchronized (cacheTrimLock) {
            while (cache.size() > MAX_CACHE_ENTRIES) {
                String victim = cacheOrder.poll();
                if (victim == null) {
                    // A concurrent admission can briefly make the queue lag the map. Remove
                    // one arbitrary retained result rather than allowing unbounded growth;
                    // eviction order has no effect on analysis semantics.
                    Iterator<String> iterator = cache.keySet().iterator();
                    if (!iterator.hasNext()) {
                        break;
                    }
                    victim = iterator.next();
                }
                cache.remove(victim);
                admittedKeys.remove(victim);
            }
        }
    }

    private Result analyze(MethodInfo method, String methodKey) {
        analysisRuns.increment();
        // Abstract/native methods can be present in the resolved class model and be reachable
        // through a declaration edge, but they have no bytecode body. There is no offset 0 to
        // interpret; an empty immutable result is the precise summary and keeps callers from
        // manufacturing a synthetic instruction state.
        if (method.instructions().isEmpty()) {
            return new Result(Map.of(), Map.of(), Map.of());
        }
        Set<String> incompleteReasons = new LinkedHashSet<>();
        validateInstructionLayout(method, incompleteReasons);
        Cfg.Indexed cfg = cfgProvider.cfg(method);
        if (cfg == null || cfg.instructionCount() != method.instructions().size()) {
            markIncomplete(incompleteReasons, "CFG_SHAPE_MISMATCH");
        } else if (!cfg.valid()) {
            markIncomplete(incompleteReasons, "CFG_BUILD_INVALID");
        }
        if (cfg == null) {
            return new Result(Map.of(), Map.of(), Map.of(), true, incompleteReasons);
        }
        int maxLocals = maxLocals(method);
        List<Set<ValueOrigin>> initLocals = new ArrayList<>(maxLocals);
        for (int i = 0; i < maxLocals; i++) {
            initLocals.add(new LinkedHashSet<>());
        }
        List<Integer> argSlots = Descriptor.argSlots(method.descriptor(), method.isStatic());
        int slot = 0;
        for (Integer width : argSlots) {
            initLocals.get(slot).add(new ValueOrigin.Param(slot));
            slot += width;
        }

        State[] before = new State[method.instructions().size()];
        Map<ValueOrigin, Set<ValueOrigin>> arrayElements = new HashMap<>();
        Map<ValueOrigin, Map<Integer, Set<ValueOrigin>>> indexedArrayElements = new HashMap<>();
        Deque<Integer> worklist = new ArrayDeque<>();
        State entry = new State(new ArrayList<>(), initLocals);
        before[0] = entry;
        worklist.add(0);
        int work = 0;
        analysis:
        while (!worklist.isEmpty()) {
            if (Thread.currentThread().isInterrupted()) {
                markIncomplete(incompleteReasons, "INTERRUPTED");
                break;
            }
            if (++work > MAX_METHOD_WORK) {
                markIncomplete(incompleteReasons, "METHOD_WORK_CAP:" + MAX_METHOD_WORK);
                break;
            }
            int offset = worklist.poll();
            State state = offset >= 0 && offset < before.length ? before[offset] : null;
            if (state == null) {
                continue;
            }
            State out = transfer(method, methodKey, method.insnAt(offset), state, arrayElements,
                    indexedArrayElements, incompleteReasons);
            if (state.originsTruncated() || out.originsTruncated()) {
                markIncomplete(incompleteReasons, "ORIGIN_SET_CAP:" + MAX_ORIGIN_SET);
            }
            for (int edgeIndex = cfg.edgeStart(offset); edgeIndex < cfg.edgeEnd(offset); edgeIndex++) {
                if (Thread.currentThread().isInterrupted()) {
                    markIncomplete(incompleteReasons, "INTERRUPTED");
                    break analysis;
                }
                CfgLabel edgeLabel = cfg.labelAt(edgeIndex);
                // 异常边：进入 handler 时 JVM 清空栈并压入异常对象，locals 保留
                State incoming = edgeLabel == CfgLabel.EXCEPTION ? exceptionState(out) : out;
                if (incoming.originsTruncated()) {
                    markIncomplete(incompleteReasons, "ORIGIN_SET_CAP:" + MAX_ORIGIN_SET);
                }
                int target = cfg.targetAt(edgeIndex);
                if (target < 0 || target >= before.length) {
                    markIncomplete(incompleteReasons, "CFG_TARGET_OUT_OF_RANGE");
                    continue;
                }
                State old = before[target];
                if (old != null && !sameShape(old, incoming)) {
                    markIncomplete(incompleteReasons, "STATE_MERGE_SHAPE_MISMATCH");
                }
                State merged = old == null ? incoming : old.merge(incoming);
                if (!merged.equals(old)) {
                    before[target] = merged;
                    worklist.add(target);
                }
            }
        }
        return new Result(new DenseStateMap(before), arrayElements, indexedArrayElements,
                !incompleteReasons.isEmpty(), incompleteReasons);
    }

    private static void validateInstructionLayout(MethodInfo method, Set<String> reasons) {
        for (int i = 0; i < method.instructions().size(); i++) {
            InsnFact insn = method.instructions().get(i);
            if (insn == null || insn.op() == null || insn.offset() != i) {
                markIncomplete(reasons, "INSTRUCTION_LAYOUT_INVALID");
                continue;
            }
            if (insn.op() == Op.UNKNOWN) {
                markIncomplete(reasons, "UNKNOWN_OPCODE");
            }
        }
    }

    private static boolean sameShape(State left, State right) {
        return left.stackArray().length == right.stackArray().length
                && left.localsArray().length == right.localsArray().length;
    }

    private static void markIncomplete(Set<String> reasons, String reason) {
        if (reasons.size() < 64) {
            reasons.add(reason);
        } else if (!reasons.contains("INCOMPLETE_REASON_CAP")) {
            reasons.removeIf(value -> !"INCOMPLETE_REASON_CAP".equals(value));
            reasons.add("INCOMPLETE_REASON_CAP");
        }
    }

    private int maxLocals(MethodInfo method) {
        int max = 0;
        for (InsnFact insn : method.instructions()) {
            Op op = insn.op();
            if (op.isLoad() || op.isStore() || op == Op.IINC || op == Op.RET) {
                max = Math.max(max, insn.varIndex() + 1);
            }
        }
        return Math.max(max, Descriptor.argSlots(method.descriptor(), method.isStatic())
                .stream().mapToInt(Integer::intValue).sum());
    }

    private State transfer(MethodInfo method, String methodKey, InsnFact insn, State in,
                           Map<ValueOrigin, Set<ValueOrigin>> arrayElements,
                           Map<ValueOrigin, Map<Integer, Set<ValueOrigin>>> indexedArrayElements,
                           Set<String> incompleteReasons) {
        Op originalOp = insn.op();
        // These instructions have no abstract-state effect. Returning the immutable input
        // state avoids two list copies and a pair of backing arrays on the overwhelmingly
        // common straight-line no-op/terminal path. The successor walk remains unchanged.
        if (originalOp == Op.NOP || originalOp == Op.GOTO
                || originalOp == Op.RET || originalOp == Op.RETURN) {
            return in;
        }
        List<Slot> stack = new ArrayList<>(Arrays.asList(in.stackArray()));
        List<Set<ValueOrigin>> locals = new ArrayList<>(Arrays.asList(in.localsArray()));
        Op op = originalOp;
        switch (op) {
            case NOP, GOTO, RET -> {
                // 无栈变化（RET 读局部变量表中的返回地址，CFG 中无后继）
            }
            case JSR ->
                    // 压入返回地址占位（不可控常量）；后续 ASTORE 会把它存入局部变量，RET 消费后不再传播
                    push(stack, new Slot(Set.of(new ValueOrigin.Constant("jsr-address")), false));
            case TABLESWITCH, LOOKUPSWITCH -> pop(stack, incompleteReasons); // 弹出 switch key
            case ACONST_NULL, ICONST_M1, ICONST_0, ICONST_1, ICONST_2, ICONST_3, ICONST_4, ICONST_5,
                    FCONST_0, FCONST_1, FCONST_2 ->
                    push(stack, new Slot(Set.of(new ValueOrigin.Constant(op.name())), false));
            case BIPUSH, SIPUSH ->
                    push(stack, new Slot(Set.of(new ValueOrigin.Constant(insn.operands().get(0))), false));
            case LCONST_0, LCONST_1, DCONST_0, DCONST_1 ->
                    push(stack, new Slot(Set.of(new ValueOrigin.Constant(op.name())), true));
            case LDC -> push(stack, new Slot(Set.of(new ValueOrigin.Constant(insn.constant())),
                    insn.constant() instanceof Long || insn.constant() instanceof Double));
            case LLOAD, DLOAD -> push(stack, new Slot(local(locals, insn.varIndex()), true));
            case ILOAD, FLOAD, ALOAD -> push(stack, new Slot(local(locals, insn.varIndex()), false));
            case ISTORE, FSTORE, ASTORE -> storeLocal(locals, insn.varIndex(),
                    pop(stack, incompleteReasons).origins(), incompleteReasons);
            case LSTORE, DSTORE -> {
                // wide 存储占 2 槽：次槽来源一并清除
                storeLocal(locals, insn.varIndex(), pop(stack, incompleteReasons).origins(), incompleteReasons);
                if (insn.varIndex() + 1 < locals.size()) {
                    locals.set(insn.varIndex() + 1, Set.of());
                }
            }
            case IINC -> storeLocal(locals, insn.varIndex(),
                    union(local(locals, insn.varIndex()), Set.of(new ValueOrigin.Insn(insn.offset()))),
                    incompleteReasons);
            case GETFIELD -> {
                ValueOrigin receiver = canonicalReceiver(pop(stack, incompleteReasons).origins());
                push(stack, new Slot(Set.of(new ValueOrigin.FieldRead(
                        insn.fieldRef().owner(), insn.fieldRef().name(), insn.fieldRef().descriptor(),
                        false, receiver)),
                        isCat2(insn.fieldRef().descriptor())));
            }
            case GETSTATIC -> push(stack, new Slot(Set.of(new ValueOrigin.FieldRead(
                    insn.fieldRef().owner(), insn.fieldRef().name(), insn.fieldRef().descriptor(), true,
                    new ValueOrigin.Unknown())), isCat2(insn.fieldRef().descriptor())));
            case PUTSTATIC -> pop(stack, incompleteReasons);
            case PUTFIELD -> {
                pop(stack, incompleteReasons);
                pop(stack, incompleteReasons);
            }
            case INVOKESTATIC, INVOKEVIRTUAL, INVOKESPECIAL, INVOKEINTERFACE, INVOKEDYNAMIC -> {
                int argc = callArgCount(insn, op);
                MethodRef methodRef = op == Op.INVOKEDYNAMIC || insn.operands().isEmpty()
                        ? null : insn.methodRef();
                if (op != Op.INVOKEDYNAMIC && isReflectiveArraySet(methodRef)) {
                    recordReflectiveArrayWrite(stack, indexedArrayElements, arrayElements);
                }
                Long callId = callIdLookup.find(methodKey, insn.offset());
                ValueOrigin.CallResult result = new ValueOrigin.CallResult(callId == null ? -1 : callId);
                if (op != Op.INVOKEDYNAMIC && isReflectiveArrayGet(methodRef)) {
                    recordReflectiveArrayRead(stack, result, indexedArrayElements, arrayElements);
                }
                for (int i = 0; i < argc; i++) {
                    pop(stack, incompleteReasons);
                }
                String returnDesc = op == Op.INVOKEDYNAMIC
                        ? Descriptor.returnType(insn.operands().isEmpty() ? "()V"
                                : ((InvokeDynamicRef) insn.operands().get(0)).descriptor())
                        : Descriptor.returnType(insn.methodRef().descriptor());
                // A void invocation produces no stack value.  Keeping a synthetic result
                // here shifts every later receiver/argument slot and makes constructor
                // initialized fields look unknown (NEW; DUP; <init>; PUTSTATIC is the
                // smallest visible example).
                if (!"V".equals(returnDesc)) {
                    push(stack, new Slot(Set.of(result), isCat2(returnDesc)));
                }
            }
            case NEW, NEWARRAY, ANEWARRAY, MULTIANEWARRAY -> {
                int pops = op == Op.NEW ? 0 : op == Op.MULTIANEWARRAY ? (Integer) insn.operands().get(1) : 1;
                for (int i = 0; i < pops; i++) {
                    pop(stack, incompleteReasons);
                }
                push(stack, new Slot(Set.of(new ValueOrigin.Insn(insn.offset())), false));
            }
            case LALOAD, DALOAD -> {
                pop(stack, incompleteReasons);
                pop(stack, incompleteReasons);
                push(stack, new Slot(Set.of(new ValueOrigin.Insn(insn.offset())), true));
            }
            case AALOAD -> {
                Set<ValueOrigin> indices = pop(stack, incompleteReasons).origins();
                Set<ValueOrigin> arrays = pop(stack, incompleteReasons).origins();
                ValueOrigin result = new ValueOrigin.Insn(insn.offset());
                recordArrayRead(arrays, indices, result, indexedArrayElements, arrayElements);
                push(stack, new Slot(Set.of(result), false));
            }
            case IALOAD, FALOAD, BALOAD, CALOAD, SALOAD -> {
                pop(stack, incompleteReasons);
                pop(stack, incompleteReasons);
                push(stack, new Slot(Set.of(new ValueOrigin.Insn(insn.offset())), false));
            }
            case IASTORE, LASTORE, FASTORE, DASTORE, AASTORE, BASTORE, CASTORE, SASTORE -> {
                Set<ValueOrigin> value = pop(stack, incompleteReasons).origins();
                Set<ValueOrigin> index = pop(stack, incompleteReasons).origins();
                Set<ValueOrigin> array = pop(stack, incompleteReasons).origins();
                for (ValueOrigin arr : array) {
                    arrayElements.computeIfAbsent(arr, k -> new LinkedHashSet<>()).addAll(value);
                    Integer constantIndex = constantIndex(index);
                    if (constantIndex != null) {
                        indexedArrayElements.computeIfAbsent(arr, k -> new HashMap<>())
                                .computeIfAbsent(constantIndex, k -> new LinkedHashSet<>())
                                .addAll(value);
                    }
                }
            }
            case ARRAYLENGTH, CHECKCAST, INSTANCEOF -> {
                pop(stack, incompleteReasons);
                push(stack, new Slot(Set.of(new ValueOrigin.Insn(insn.offset())), false));
            }
            case MONITORENTER, MONITOREXIT, ATHROW -> pop(stack, incompleteReasons);
            case IRETURN, LRETURN, FRETURN, DRETURN, ARETURN -> pop(stack, incompleteReasons);
            case RETURN -> {
            }
            case POP -> pop(stack, incompleteReasons);
            case POP2 -> {
                // cat-2 顶部占 1 条目，否则为两个 cat-1
                if (top(stack, incompleteReasons).cat2()) {
                    pop(stack, incompleteReasons);
                } else {
                    pop(stack, incompleteReasons);
                    pop(stack, incompleteReasons);
                }
            }
            case DUP -> dupForm(stack, 1, 0, incompleteReasons);
            case DUP_X1 -> dupForm(stack, 1, 1, incompleteReasons);
            case DUP_X2 -> dupForm(stack, 1, valueWidthBelow(stack, 1, incompleteReasons), incompleteReasons);
            case DUP2 -> dupForm(stack, valueWidth(stack, incompleteReasons), 0, incompleteReasons);
            case DUP2_X1 -> dupForm(stack, valueWidth(stack, incompleteReasons), 1, incompleteReasons);
            case DUP2_X2 -> dupForm(stack, valueWidth(stack, incompleteReasons),
                    valueWidthBelow(stack, valueWidth(stack, incompleteReasons), incompleteReasons),
                    incompleteReasons);
            case SWAP -> {
                Slot v1 = pop(stack, incompleteReasons);
                Slot v2 = pop(stack, incompleteReasons);
                push(stack, v1);
                push(stack, v2);
            }
            case LADD, LSUB, LMUL, LDIV, LREM, DADD, DSUB, DMUL, DDIV, DREM,
                    LAND, LOR, LXOR -> {
                pop(stack, incompleteReasons);
                pop(stack, incompleteReasons);
                push(stack, new Slot(Set.of(new ValueOrigin.Insn(insn.offset())), true));
            }
            case LSHL, LSHR, LUSHR -> {
                pop(stack, incompleteReasons);
                pop(stack, incompleteReasons);
                push(stack, new Slot(Set.of(new ValueOrigin.Insn(insn.offset())), true));
            }
            case IADD, FADD, ISUB, FSUB, IMUL, FMUL, IDIV, FDIV, IREM, FREM,
                    ISHL, ISHR, IUSHR, IAND, IOR, IXOR,
                    LCMP, FCMPL, FCMPG, DCMPL, DCMPG -> {
                pop(stack, incompleteReasons);
                pop(stack, incompleteReasons);
                push(stack, new Slot(Set.of(new ValueOrigin.Insn(insn.offset())), false));
            }
            case LNEG, DNEG, I2L, I2D, L2D, F2L, F2D, D2L -> {
                pop(stack, incompleteReasons);
                push(stack, new Slot(Set.of(new ValueOrigin.Insn(insn.offset())), true));
            }
            case INEG, FNEG, I2F, L2I, L2F, D2I, D2F, F2I, I2B, I2C, I2S -> {
                pop(stack, incompleteReasons);
                push(stack, new Slot(Set.of(new ValueOrigin.Insn(insn.offset())), false));
            }
            case IFEQ, IFNE, IFLT, IFGE, IFGT, IFLE, IFNULL, IFNONNULL -> pop(stack, incompleteReasons);
            case IF_ICMPEQ, IF_ICMPNE, IF_ICMPLT, IF_ICMPGE, IF_ICMPGT, IF_ICMPLE,
                    IF_ACMPEQ, IF_ACMPNE -> {
                pop(stack, incompleteReasons);
                pop(stack, incompleteReasons);
            }
            default -> {
                // Unknown/no-model is an analysis boundary. A silent no-op can turn a
                // malformed or newly introduced opcode into a false complete proof.
                markIncomplete(incompleteReasons, "UNMODELED_OPCODE:" + op.name());
            }
        }
        return new State(stack.toArray(new Slot[0]), locals.toArray(new Set[0]),
                in.originsTruncated());
    }

    private static Integer constantIndex(Set<ValueOrigin> origins) {
        for (ValueOrigin origin : origins) {
            if (!(origin instanceof ValueOrigin.Constant constant)) {
                continue;
            }
            Object value = constant.value();
            if (value instanceof Number number) {
                return number.intValue();
            }
            if (value instanceof String opcode) {
                return switch (opcode) {
                    case "ICONST_M1" -> -1;
                    case "ICONST_0" -> 0;
                    case "ICONST_1" -> 1;
                    case "ICONST_2" -> 2;
                    case "ICONST_3" -> 3;
                    case "ICONST_4" -> 4;
                    case "ICONST_5" -> 5;
                    default -> null;
                };
            }
        }
        return null;
    }

    /**
     * java.lang.reflect.Array mutates arrays through ordinary calls rather than AASTORE.
     * Treating these calls as opaque loses the element identity used by reflection-heavy
     * gadgets; the summary is still monotone (writes are unioned), so unknown aliases remain
     * conservative instead of being overwritten.
     */
    private static boolean isReflectiveArraySet(MethodRef ref) {
        return ref != null && "java/lang/reflect/Array".equals(ref.owner())
                && "set".equals(ref.name())
                && "(Ljava/lang/Object;ILjava/lang/Object;)V".equals(ref.descriptor());
    }

    private static boolean isReflectiveArrayGet(MethodRef ref) {
        return ref != null && "java/lang/reflect/Array".equals(ref.owner())
                && "get".equals(ref.name())
                && "(Ljava/lang/Object;I)Ljava/lang/Object;".equals(ref.descriptor());
    }

    private static void recordReflectiveArrayWrite(List<Slot> stack,
                                                   Map<ValueOrigin, Map<Integer, Set<ValueOrigin>>> indexed,
                                                   Map<ValueOrigin, Set<ValueOrigin>> aggregate) {
        if (stack.size() < 3) {
            return;
        }
        Set<ValueOrigin> arrays = stack.get(stack.size() - 3).origins();
        Set<ValueOrigin> indices = stack.get(stack.size() - 2).origins();
        Set<ValueOrigin> values = stack.get(stack.size() - 1).origins();
        Integer index = constantIndex(indices);
        for (ValueOrigin array : arrays) {
            aggregate.computeIfAbsent(array, ignored -> new LinkedHashSet<>()).addAll(values);
            if (index != null) {
                indexed.computeIfAbsent(array, ignored -> new HashMap<>())
                        .computeIfAbsent(index, ignored -> new LinkedHashSet<>())
                        .addAll(values);
            }
        }
    }

    /**
     * Preserve the element provenance of an ordinary reference-array read. The previous
     * transfer treated AALOAD as an opaque instruction, so a value stored into an array by a
     * deserialization callback disappeared at the first read. A constant index gets the
     * precise bucket; an unknown index receives the aggregate element set. If the array was
     * supplied from outside the method, retain the array origin as a conservative unknown
     * element rather than claiming the read is constant.
     */
    private static void recordArrayRead(Set<ValueOrigin> arrays, Set<ValueOrigin> indices,
                                        ValueOrigin result,
                                        Map<ValueOrigin, Map<Integer, Set<ValueOrigin>>> indexed,
                                        Map<ValueOrigin, Set<ValueOrigin>> aggregate) {
        if (arrays == null || arrays.isEmpty() || result == null) {
            return;
        }
        Integer index = constantIndex(indices == null ? Set.of() : indices);
        Set<ValueOrigin> values = new LinkedHashSet<>();
        for (ValueOrigin array : arrays) {
            Map<Integer, Set<ValueOrigin>> byIndex = indexed.get(array);
            if (index != null && byIndex != null && byIndex.containsKey(index)) {
                values.addAll(byIndex.get(index));
            } else {
                values.addAll(aggregate.getOrDefault(array, Set.of()));
            }
            if (values.isEmpty()) {
                values.add(array);
            }
        }
        if (!values.isEmpty()) {
            aggregate.computeIfAbsent(result, ignored -> new LinkedHashSet<>()).addAll(values);
        }
    }

    private static void recordReflectiveArrayRead(List<Slot> stack, ValueOrigin.CallResult result,
                                                  Map<ValueOrigin, Map<Integer, Set<ValueOrigin>>> indexed,
                                                  Map<ValueOrigin, Set<ValueOrigin>> aggregate) {
        if (stack.size() < 2 || result.callNodeId() < 0) {
            return;
        }
        Set<ValueOrigin> arrays = stack.get(stack.size() - 2).origins();
        Set<ValueOrigin> indices = stack.get(stack.size() - 1).origins();
        Integer index = constantIndex(indices);
        Set<ValueOrigin> values = new LinkedHashSet<>();
        for (ValueOrigin array : arrays) {
            Map<Integer, Set<ValueOrigin>> byIndex = indexed.get(array);
            if (index != null && byIndex != null && byIndex.containsKey(index)) {
                values.addAll(byIndex.get(index));
            } else {
                values.addAll(aggregate.getOrDefault(array, Set.of()));
            }
            // A serialized/externally supplied array has no local element map. Its
            // container is still the conservative origin of an unknown element.
            if (values.isEmpty()) {
                values.add(array);
            }
        }
        if (!values.isEmpty()) {
            aggregate.computeIfAbsent(result, ignored -> new LinkedHashSet<>()).addAll(values);
        }
    }

    /** 异常边目标状态：栈 = [异常对象]，locals 保留。 */
    private static State exceptionState(State out) {
        // State owns immutable array references; transfer always clones them before mutation.
        // Share locals here instead of materializing a compatibility List and copying it back.
        return new State(new Slot[]{UNKNOWN_SLOT}, out.localsArray(), out.originsTruncated());
    }

    /** 规范化 receiver：优先 Param(0)（this），否则取首个来源，保证 memo 键稳定。 */
    private static ValueOrigin canonicalReceiver(Set<ValueOrigin> set) {
        for (ValueOrigin origin : set) {
            if (origin instanceof ValueOrigin.Param p && p.slot() == 0) {
                return origin;
            }
        }
        return set.isEmpty() ? new ValueOrigin.Unknown() : set.iterator().next();
    }

    private int callArgCount(InsnFact insn, Op op) {
        if (op == Op.INVOKEDYNAMIC) {
            return Descriptor.paramCount(insn.operands().isEmpty() ? "()V"
                    : ((InvokeDynamicRef) insn.operands().get(0)).descriptor());
        }
        MethodRef ref = insn.methodRef();
        if (ref == null || ref.descriptor() == null) {
            return 0;
        }
        return Descriptor.paramCount(ref.descriptor()) + (op == Op.INVOKESTATIC ? 0 : 1);
    }

    /** 描述符首字符是否 category-2 类型（long/double）。 */
    private static boolean isCat2(String descriptor) {
        if (descriptor == null || descriptor.isEmpty()) {
            return false;
        }
        char c = descriptor.charAt(0);
        return c == 'J' || c == 'D';
    }

    /** 顶部值的条目宽度：cat-2 为 1 条目，cat-1 为 2 条目（DUP2 族语义）。 */
    private static int valueWidth(List<Slot> stack, Set<String> reasons) {
        return top(stack, reasons).cat2() ? 1 : 2;
    }

    /** 顶部 value1（n1 条目）之下 value2 的条目宽度。 */
    private static int valueWidthBelow(List<Slot> stack, int n1, Set<String> reasons) {
        int idx = stack.size() - 1 - n1;
        if (idx < 0) {
            markIncomplete(reasons, "STACK_UNDERFLOW");
            return 1;
        }
        return stack.get(idx).cat2() ? 1 : 2;
    }

    /**
     * JVM 复制族通用形式：弹出 value1（n1 条目）与 value2（n2 条目，可为 0），
     * 按 value1, value2, value1 顺序压回。覆盖 DUP/DUP_X1/DUP_X2/DUP2/DUP2_X1/DUP2_X2。
     */
    private static void dupForm(List<Slot> stack, int n1, int n2, Set<String> reasons) {
        List<Slot> v1 = popSlots(stack, n1, reasons);
        List<Slot> v2 = popSlots(stack, n2, reasons);
        stack.addAll(v1);
        stack.addAll(v2);
        stack.addAll(v1);
    }

    private static List<Slot> popSlots(List<Slot> stack, int n, Set<String> reasons) {
        if (n == 0) {
            return List.of();
        }
        if (n < 0 || n > stack.size()) {
            markIncomplete(reasons, "STACK_UNDERFLOW");
            n = Math.max(0, Math.min(n, stack.size()));
        }
        List<Slot> slots = new ArrayList<>(stack.subList(stack.size() - n, stack.size()));
        for (int i = 0; i < n; i++) {
            stack.remove(stack.size() - 1);
        }
        return slots;
    }

    private static Set<ValueOrigin> local(List<Set<ValueOrigin>> locals, int var) {
        return var >= 0 && var < locals.size() && !locals.get(var).isEmpty()
                ? locals.get(var) : UNKNOWN_SLOT.origins();
    }

    private static Slot top(List<Slot> stack, Set<String> reasons) {
        if (stack.isEmpty()) {
            markIncomplete(reasons, "STACK_UNDERFLOW");
            return UNKNOWN_SLOT;
        }
        return stack.get(stack.size() - 1);
    }

    private static Slot pop(List<Slot> stack, Set<String> reasons) {
        if (stack.isEmpty()) {
            markIncomplete(reasons, "STACK_UNDERFLOW");
            return UNKNOWN_SLOT;
        }
        return stack.remove(stack.size() - 1);
    }

    private static void storeLocal(List<Set<ValueOrigin>> locals, int index,
                                   Set<ValueOrigin> origins, Set<String> reasons) {
        if (index < 0 || index >= locals.size()) {
            markIncomplete(reasons, "LOCAL_INDEX_OUT_OF_RANGE");
            return;
        }
        locals.set(index, origins == null ? Set.of(new ValueOrigin.Unknown()) : origins);
    }

    private static void push(List<Slot> stack, Slot slot) {
        stack.add(slot);
    }

    private record OriginUnion(Set<ValueOrigin> values, boolean truncated) {
    }

    private static OriginUnion boundedUnion(Set<ValueOrigin> a, Set<ValueOrigin> b) {
        if (Thread.currentThread().isInterrupted()) {
            return new OriginUnion(truncatedUnion(a, b), true);
        }
        if (a == null || a.isEmpty()) {
            return boundedSingle(b);
        }
        if (b == null || b.isEmpty()) {
            return boundedSingle(a);
        }
        if (a == b && a.size() <= MAX_ORIGIN_SET) {
            return new OriginUnion(a, false);
        }
        long combined = (long) a.size() + b.size();
        if (combined <= MAX_ORIGIN_SET) {
            // Reuse the already immutable superset whenever possible.  The previous code
            // always asked the smaller/older set whether it contained the newer set; that
            // check is guaranteed to fail when b is larger and then allocates a merged set
            // even when b already contains a.  Besides the allocation, the failed probe was
            // visible as a large containsAll/hashCode hotspot in branch-heavy dependencies.
            // Keeping the larger set preserves the same may-origin union and deterministic
            // iteration order; only the allocation strategy changes.
            if (a.size() >= b.size() && a.containsAll(b)) {
                return new OriginUnion(a, false);
            }
            if (b.size() > a.size() && b.containsAll(a)) {
                return new OriginUnion(b, false);
            }
            LinkedHashSet<ValueOrigin> merged = new LinkedHashSet<>(a);
            merged.addAll(b);
            return new OriginUnion(Collections.unmodifiableSet(merged), false);
        }
        return new OriginUnion(truncatedUnion(a, b), true);
    }

    private static OriginUnion boundedSingle(Set<ValueOrigin> values) {
        if (values == null || values.isEmpty() || values.size() <= MAX_ORIGIN_SET) {
            return new OriginUnion(values == null ? Set.of() : values, false);
        }
        return new OriginUnion(truncatedUnion(values, Set.of()), true);
    }

    private static Set<ValueOrigin> truncatedUnion(Set<ValueOrigin> first,
                                                   Set<ValueOrigin> second) {
        LinkedHashSet<ValueOrigin> retained = new LinkedHashSet<>(MAX_ORIGIN_SET);
        appendBounded(retained, first);
        appendBounded(retained, second);
        return Collections.unmodifiableSet(retained);
    }

    private static void appendBounded(LinkedHashSet<ValueOrigin> retained,
                                      Set<ValueOrigin> values) {
        if (values == null || retained.size() >= MAX_ORIGIN_SET) {
            return;
        }
        for (ValueOrigin value : values) {
            if (value != null) {
                retained.add(value);
            }
            if (retained.size() >= MAX_ORIGIN_SET) {
                return;
            }
        }
    }

    private static Set<ValueOrigin> union(Set<ValueOrigin> a, Set<ValueOrigin> b) {
        return boundedUnion(a, b).values();
    }

    /**
     * Dense offset lookup for stateBefore.  CFG offsets are normalized to dense instruction
     * indices by the frontend contract, so a HashMap<Integer,State> only adds boxed keys and
     * table entries without adding lookup semantics.  entrySet is retained for compatibility
     * with diagnostic consumers, but the analysis hot path uses get(offset).
     */
    private static final class DenseStateMap extends AbstractMap<Integer, State> {
        private final State[] states;
        private final int size;

        private DenseStateMap(State[] states) {
            this.states = states;
            int count = 0;
            for (State state : states) {
                if (state != null) {
                    count++;
                }
            }
            this.size = count;
        }

        @Override
        public State get(Object key) {
            if (!(key instanceof Number number)) {
                return null;
            }
            int offset = number.intValue();
            return offset >= 0 && offset < states.length ? states[offset] : null;
        }

        @Override
        public boolean containsKey(Object key) {
            if (!(key instanceof Number number)) {
                return false;
            }
            int offset = number.intValue();
            return offset >= 0 && offset < states.length && states[offset] != null;
        }

        @Override
        public int size() {
            return size;
        }

        @Override
        public Set<Entry<Integer, State>> entrySet() {
            return new AbstractSet<>() {
                @Override
                public Iterator<Entry<Integer, State>> iterator() {
                    return new Iterator<>() {
                        private int next = find(0);

                        private int find(int start) {
                            int index = start;
                            while (index < states.length && states[index] == null) {
                                index++;
                            }
                            return index;
                        }

                        @Override
                        public boolean hasNext() {
                            return next < states.length;
                        }

                        @Override
                        public Entry<Integer, State> next() {
                            int current = next;
                            next = find(current + 1);
                            return Map.entry(current, states[current]);
                        }
                    };
                }

                @Override
                public int size() {
                    return DenseStateMap.this.size;
                }
            };
        }
    }

    /** 方法缓存键。 */
    public static final class CfgKey {
        private CfgKey() {}

        public static String of(MethodInfo m) {
            return m.owner() + "#" + m.name() + m.descriptor();
        }
    }
}
