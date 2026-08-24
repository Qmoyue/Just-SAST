package io.just.sast.verify;

import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.HopKind;

import java.io.File;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.*;

/**
 * 并行链级验证器：沿链 FIELD_FLOW 跳构造完整对象图 → 子进程执行 → sink 特异性判定。
 * 入口类去重（同一入口最多 2 条链），4 路并行，探针在 fat jar 中零逐链编译。
 */
public final class ParallelVerifier {

    public record VerifyResult(String chainKey, String status, String detail) {}

    public interface ConfirmCallback {
        void onConfirmed(Chain chain, String detail, boolean sinkReached);
    }

    private static final int TIMEOUT_SECONDS = 8;
    private static final int PARALLELISM = 4;
    private static final int MAX_PER_ENTRY = 2;

    private final Path targetJar;
    private final List<Path> deps;
    private final Path ownJar;
    private final ConfirmCallback callback;

    public ParallelVerifier(Path targetJar, List<Path> deps, ConfirmCallback callback) {
        this.targetJar = targetJar.toAbsolutePath().normalize();
        this.deps = deps != null ? deps : List.of();
        this.callback = callback;
        this.ownJar = locateOwnJar();
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

    /** 选择要验证的链：按置信度降序 + 入口类去重（同一入口最多 2 条不同 sink）。 */
    public List<Chain> selectChains(List<Chain> candidates, int maxTotal) {
        List<Chain> sorted = new ArrayList<>(candidates);
        sorted.sort((a, b) -> Integer.compare(
                io.just.sast.chain.ConfidenceScorer.evidenceScore(b, null),
                io.just.sast.chain.ConfidenceScorer.evidenceScore(a, null)));
        Map<String, Integer> entryCount = new HashMap<>();
        List<Chain> selected = new ArrayList<>();
        for (Chain chain : sorted) {
            String entryKey = chain.entryClass() + "#" + chain.entryMethod();
            int count = entryCount.getOrDefault(entryKey, 0);
            if (count >= MAX_PER_ENTRY) continue;
            entryCount.merge(entryKey, 1, Integer::sum);
            selected.add(chain);
            if (selected.size() >= maxTotal) break;
        }
        return selected;
    }

    /** 批量并行验证。 */
    public List<VerifyResult> verifyAll(List<Chain> chains) {
        List<VerifyResult> results = new ArrayList<>();
        ExecutorService pool = Executors.newFixedThreadPool(Math.min(PARALLELISM, chains.size()));
        try {
            List<Future<VerifyResult>> futures = new ArrayList<>();
            for (Chain chain : chains) {
                futures.add(pool.submit(() -> verifyOne(chain)));
            }
            for (Future<VerifyResult> f : futures) {
                try {
                    results.add(f.get(TIMEOUT_SECONDS + 3, TimeUnit.SECONDS));
                } catch (Exception e) {
                    results.add(new VerifyResult("", "UNTESTABLE", e.getMessage()));
                }
            }
        } finally {
            pool.shutdown();
        }
        return results;
    }

    private VerifyResult verifyOne(Chain chain) {
        try {
            String entryDotted = chain.entryClass().replace('/', '.');
            String entryMethod = chain.entryMethod();
            String mode = switch (chain.entryKind()) {
                case "proxyInvoke" -> "PROXY";
                case "readObject", "readObjectNoData", "readExternal", "readResolve" -> "SERIAL";
                default -> "DIRECT";
            };

            // 提取 FIELD_FLOW 跳（构造对象图用）
            StringBuilder hopDesc = new StringBuilder();
            for (ChainHop hop : chain.hops()) {
                if (hop.kind() == HopKind.FIELD_FLOW && hop.field() != null) {
                    if (hopDesc.length() > 0) hopDesc.append(',');
                    hopDesc.append(hop.fromOwner()).append('.')
                           .append(hop.field()).append('=').append(hop.toOwner());
                }
            }

            String sinkTarget = chain.sinkClass().replace('/', '.') + "." + chain.sinkMethod();
            String java = System.getProperty("java.home") + File.separator + "bin" + File.separator + "java";
            String cp = classpathOf(ownJar, targetJar, deps);

            ProcessBuilder pb = new ProcessBuilder(java, "-cp", cp,
                    "io.just.sast.verify.ChainVerifyProbe",
                    entryDotted + "|" + entryMethod + "|" + mode,
                    hopDesc.toString(),
                    sinkTarget);
            pb.redirectErrorStream(true);
            Process proc = pb.start();
            // 先 waitFor 再读输出：子 JVM 挂起且未关 stdout 时，readAllBytes 会永久阻塞，
            // 超时判定必须先行。探针输出为单行（远小于 OS 管道容量），进程退出后读取即达 EOF。
            boolean finished = proc.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            if (!finished) {
                proc.destroyForcibly();
                return new VerifyResult(chain.key(), "TIMEOUT", TIMEOUT_SECONDS + "s");
            }
            String output = new String(proc.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            String[] lines = output.strip().split("\\R");
            String firstLine = lines.length > 0 ? lines[0] : "";

            if (firstLine.startsWith("SINK_TRIGGERED")) {
                if (callback != null) callback.onConfirmed(chain, firstLine, true);
                return new VerifyResult(chain.key(), "CONFIRMED", "SINK_REACHED");
            }
            if (firstLine.equals("EXECUTED")) {
                // 入口方法真实调用且正常返回——链可执行，但未证伪/证实 sink 到达
                return new VerifyResult(chain.key(), "EXECUTED", "executed");
            }
            if (firstLine.startsWith("PARTIAL_PATH")) {
                return new VerifyResult(chain.key(), "PARTIAL", firstLine);
            }
            int exit = proc.exitValue();
            if (exit != 0) {
                return new VerifyResult(chain.key(), "PARTIAL",
                        "exit=" + exit + " " + firstLine);
            }
            return new VerifyResult(chain.key(), "FAILED", "no trigger");

        } catch (Exception e) {
            return new VerifyResult(chain.key(), "UNTESTABLE",
                    e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName());
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

    public void cleanup() {
    }
}
