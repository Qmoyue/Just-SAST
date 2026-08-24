package io.just.sast.cli;

import java.util.concurrent.Callable;

import picocli.CommandLine.Command;
import picocli.CommandLine.Parameters;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * C2: diff 子命令——对比两次扫描的 findings.csv，报告新增/消失/变更链。
 * Semgrep --baseline / CodeQL baseline 模式的本地版。
 *
 * 解析为 RFC 4180（带引号字段可含逗号/转义引号）；列按表头名定位（不依赖列序）。
 * 链身份键 = 入口类#方法 + sink类#方法 + rule_id——不含 chain_id 序号（组序号随排序变化，
 * 两次扫描只要发现相同链集合与语义，diff 应报告零差异）。
 */
@Command(name = "diff", description = "对比两次扫描结果，报告链变更")
public final class DiffCommand implements Callable<Integer> {

    /** 身份列：构成链的唯一标识。 */
    private static final String[] IDENTITY_COLUMNS = {"rule_id", "entry_class", "entry_method", "sink_class", "sink_method"};
    /** 语义列：身份之外参与"变更"判定的字段。 */
    private static final String[] SEMANTIC_COLUMNS = {"category", "severity", "confidence", "confidence_score",
            "chain_length", "unresolved_hops", "variant_count", "patterns", "path", "evidence", "verify"};

    @Parameters(index = "0", paramLabel = "<old-dir>", description = "旧扫描输出目录")
    Path oldDir;

    @Parameters(index = "1", paramLabel = "<new-dir>", description = "新扫描输出目录")
    Path newDir;

    @Override
    public Integer call() {
        Map<String, String> oldChains;
        Map<String, String> newChains;
        try {
            oldChains = readChains(oldDir.resolve("findings.csv"), oldDir);
            newChains = readChains(newDir.resolve("findings.csv"), newDir);
        } catch (IllegalArgumentException e) {
            System.err.println("[just:error] " + e.getMessage());
            return ExitCode.USAGE.code();
        } catch (Exception e) {
            System.err.println("[just:error] 读取扫描结果失败: " + e);
            return ExitCode.INTERNAL.code();
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
        return ExitCode.OK.code();
    }

    /** 读 findings.csv 为 身份键 → 语义指纹。目录缺 findings.csv 是用法错误（显式报错，不当空集）。 */
    private Map<String, String> readChains(Path csv, Path dir) throws Exception {
        if (!Files.exists(csv)) {
            throw new IllegalArgumentException("目录缺少 findings.csv（不是扫描输出目录）: " + dir.toAbsolutePath());
        }
        List<String> lines = Files.readAllLines(csv, StandardCharsets.UTF_8);
        Map<String, String> map = new LinkedHashMap<>();
        int[] identityIdx = null;
        int[] semanticIdx = null;
        for (String line : lines) {
            List<String> fields = parseCsvLine(line);
            if (fields.isEmpty()) {
                continue;
            }
            if (identityIdx == null) {
                identityIdx = indexOf(fields, IDENTITY_COLUMNS);
                if (identityIdx == null) {
                    throw new IllegalArgumentException("findings.csv 表头缺少身份列: " + csv.toAbsolutePath());
                }
                semanticIdx = indexOf(fields, SEMANTIC_COLUMNS);
                continue; // 表头行
            }
            String identity = joinAt(fields, identityIdx);
            if (identity == null) {
                continue; // 缺身份列的畸形行
            }
            map.put(identity, joinAt(fields, semanticIdx));
        }
        return map;
    }

    /** 按表头名定位列下标；任一列缺失返回 null（调用方按畸形行跳过/报错）。 */
    private static int[] indexOf(List<String> header, String[] names) {
        int[] idx = new int[names.length];
        for (int i = 0; i < names.length; i++) {
            int at = header.indexOf(names[i]);
            if (at < 0) {
                return null;
            }
            idx[i] = at;
        }
        return idx;
    }

    private static String joinAt(List<String> fields, int[] idx) {
        if (idx == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < idx.length; i++) {
            if (idx[i] >= fields.size()) {
                return null;
            }
            if (i > 0) {
                sb.append('|');
            }
            sb.append(fields.get(idx[i]));
        }
        return sb.toString();
    }

    /** RFC 4180 单行解析：双引号包裹的字段可含逗号与转义引号（""）。 */
    static List<String> parseCsvLine(String line) {
        List<String> fields = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        boolean inQuotes = false;
        boolean started = false;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (inQuotes) {
                if (c == '"') {
                    if (i + 1 < line.length() && line.charAt(i + 1) == '"') {
                        cur.append('"');
                        i++;
                    } else {
                        inQuotes = false;
                    }
                } else {
                    cur.append(c);
                }
            } else if (c == '"') {
                inQuotes = true;
                started = true;
            } else if (c == ',') {
                fields.add(cur.toString());
                cur.setLength(0);
                started = false;
            } else {
                if (c == '\uFEFF' && fields.isEmpty() && cur.length() == 0) {
                    continue; // UTF-8 BOM（首行首字符）
                }
                cur.append(c);
                started = true;
            }
        }
        if (started || !fields.isEmpty()) {
            fields.add(cur.toString());
        }
        return fields;
    }
}
