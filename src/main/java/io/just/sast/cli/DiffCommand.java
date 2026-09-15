package io.just.sast.cli;

import io.just.sast.report.CanonicalReportReader;
import io.just.sast.run.RunOutcome;
import io.just.sast.run.InputBudget;
import java.util.concurrent.Callable;
import java.io.IOException;

import picocli.CommandLine.Command;
import picocli.CommandLine.Parameters;

import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * C2: diff 子命令——对比两次扫描的 canonical report.json，报告新增/消失/变更链。
 * Semgrep --baseline / CodeQL baseline 模式的本地版。
 *
 * 读取规范 report.json 的 typed chain 快照；格式化、排序和链组序号不参与身份。
 * 链身份键 = rule_id + 入口类/方法/描述符/种类 + sink 类/方法/描述符——不含 chain_id 序号（组序号随排序变化，
 * 两次扫描只要发现相同链集合与语义，diff 应报告零差异）。
 */
@Command(name = "diff", description = "对比两次扫描结果，报告链变更")
public final class DiffCommand implements Callable<Integer> {

    private final InputBudget inputBudget;

    public DiffCommand() {
        this(InputBudget.defaults());
    }

    /** Package contract seam: production CLI uses defaults; tests may prove aggregate limits. */
    DiffCommand(InputBudget inputBudget) {
        this.inputBudget = inputBudget == null ? InputBudget.defaults() : inputBudget;
    }

    @Parameters(index = "0", paramLabel = "<old-dir>", description = "旧扫描输出目录")
    Path oldDir;

    @Parameters(index = "1", paramLabel = "<new-dir>", description = "新扫描输出目录")
    Path newDir;

    @Override
    public Integer call() {
        Map<String, String> oldChains;
        Map<String, String> newChains;
        InputBudget policy = inputBudget;
        InputBudget.Tracker tracker = policy.tracker();
        try {
            oldChains = readChains(canonicalReport(oldDir), oldDir, policy, tracker);
            newChains = readChains(canonicalReport(newDir), newDir, policy, tracker);
        } catch (IllegalArgumentException e) {
            System.err.println("[just:error] " + e.getMessage());
            return RunOutcome.usage("DIFF_INPUT_INVALID", e.getMessage()).exitCode();
        } catch (IOException e) {
            String message = e.getMessage() == null ? "DIFF_READ_FAILURE" : e.getMessage();
            if (message.startsWith("DIFF_INPUT_LIMIT")
                    || message.startsWith("CANONICAL_REPORT_INPUT_LIMIT")) {
                System.err.println("[just:error] " + message);
                return RunOutcome.usage("DIFF_INPUT_LIMIT", "diff input exceeds shared budget").exitCode();
            }
            System.err.println("[just:error] 读取扫描结果失败: " + e.getClass().getSimpleName());
            return RunOutcome.failed("DIFF_READ_FAILURE", e.getClass().getSimpleName()).exitCode();
        } catch (Exception e) {
            System.err.println("[just:error] 读取扫描结果失败: " + e);
            return RunOutcome.failed("DIFF_READ_FAILURE", e.getClass().getSimpleName()).exitCode();
        }

        Set<String> added = new TreeSet<>(newChains.keySet());
        added.removeAll(oldChains.keySet());
        Set<String> removed = new TreeSet<>(oldChains.keySet());
        removed.removeAll(newChains.keySet());
        Set<String> changed = new TreeSet<>();
        for (Map.Entry<String, String> e : newChains.entrySet()) {
            String oldFingerprint = oldChains.get(e.getKey());
            if (oldFingerprint != null && !oldFingerprint.equals(e.getValue())) {
                changed.add(e.getKey());
            }
        }
        System.out.println("=== 扫描结果差异 ===");
        System.out.println("新增链: " + added.size());
        for (String c : added) {
            System.out.println("  + " + c);
        }
        System.out.println("消失链: " + removed.size());
        for (String c : removed) {
            System.out.println("  - " + c);
        }
        System.out.println("变更链: " + changed.size());
        for (String c : changed) {
            System.out.println("  ~ " + c);
        }
        System.out.println("不变链: " + (newChains.size() - added.size() - changed.size()));
        return RunOutcome.success().exitCode();
    }

    /** Resolve only the current canonical report; retired CSV artifacts are not an input path. */
    private static Path canonicalReport(Path dir) {
        if (dir == null) {
            throw new IllegalArgumentException("scan report directory is required");
        }
        return dir.resolve("report.json");
    }

    /** Read canonical identities and static semantic projections; an empty file is not a scan. */
    private Map<String, String> readChains(Path report, Path dir, InputBudget policy,
                                           InputBudget.Tracker tracker) throws IOException {
        if (!Files.isRegularFile(report, LinkOption.NOFOLLOW_LINKS)) {
            throw new IllegalArgumentException("目录缺少 report.json（不是扫描输出目录）: "
                    + dir.toAbsolutePath());
        }
        CanonicalReportReader.Snapshot snapshot = new CanonicalReportReader().read(report, policy,
                tracker);
        Map<String, String> map = new LinkedHashMap<>();
        for (CanonicalReportReader.ChainRecord chain : snapshot.chains()) {
            if (map.put(chain.identity(), chain.semanticFingerprint()) != null) {
                throw new IllegalArgumentException("report.json 存在重复链身份: " + chain.identity());
            }
        }
        return map;
    }
}
