package io.just.sast.cli;
import java.util.concurrent.Callable;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

/**
 * C2: diff 子命令——对比两次扫描的 findings.csv，报告新增/消失/变更链。
 * Semgrep --baseline / CodeQL baseline 模式的本地版。
 */
@Command(name = "diff", description = "对比两次扫描结果，报告链变更")
public final class DiffCommand implements Callable<Integer> {

    @Parameters(index = "0", paramLabel = "<old-dir>", description = "旧扫描输出目录")
    Path oldDir;

    @Parameters(index = "1", paramLabel = "<new-dir>", description = "新扫描输出目录")
    Path newDir;

    @Override
    public Integer call() throws Exception {
        Map<String, String> oldChains = readChains(oldDir.resolve("findings.csv"));
        Map<String, String> newChains = readChains(newDir.resolve("findings.csv"));

        Set<String> added = new TreeSet<>(newChains.keySet());
        added.removeAll(oldChains.keySet());
        Set<String> removed = new TreeSet<>(oldChains.keySet());
        removed.removeAll(newChains.keySet());
        Set<String> changed = new TreeSet<>();
        for (String key : newChains.keySet()) {
            if (oldChains.containsKey(key) && !oldChains.get(key).equals(newChains.get(key))) {
                changed.add(key);
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
        return ExitCode.OK.code();
    }

    private Map<String, String> readChains(Path csv) throws Exception {
        Map<String, String> map = new LinkedHashMap<>();
        if (!Files.exists(csv)) {
            return map;
        }
        List<String> lines = Files.readAllLines(csv, java.nio.charset.StandardCharsets.UTF_8);
        for (int i = 1; i < lines.size(); i++) {
            String line = lines.get(i);
            String[] parts = line.split(",", 5);
            if (parts.length >= 4) {
                map.put(parts[1] + "|" + parts[7] + "." + parts[8] + "->" + parts[10] + "." + parts[11], line);
            }
        }
        return map;
    }
}
