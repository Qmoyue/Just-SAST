package io.just.sast.regression;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 回归守卫（V1，Semgrep --test 模式——锚点级断言而非全量评分）：
 * Gleipner basic/depth/polymorphism 三个代表性类别的锚点链签名进 mvn test。
 * 锚点漂移（如 Dog 9→6）即红——CI 级守卫，替代事后手动检查。
 * 本地有 Gleipner 基准时才运行（benchmark/ 不入库）。
 */
class GleipnerAnchorTest {

    @Test
    void basicAnchorsHold(@TempDir Path tmp) throws Exception {
        Path jar = Path.of("benchmark/Gleipner/chains/target/gleipner.chains-1.0-basic.jar");
        Assumptions.assumeTrue(Files.exists(jar), "本地无 Gleipner 基准");
        io.just.sast.cli.ScanPipeline.ScanResult result = io.just.sast.cli.ScanPipeline.run(
                jar, null, tmp.resolve("basic"),
                Path.of("benchmark/Gleipner/just-rules.yaml"),
                false, true, null, true);
        List<String> entries = Files.readAllLines(tmp.resolve("basic/chains.csv")).stream()
                .skip(1).map(l -> l.split(",")).filter(f -> f.length > 4)
                .map(f -> f[2] + ";" + f[3]).toList();
        assertTrue(entries.stream().anyMatch(e -> e.contains("BasicTriggerGadget")),
                "basic_001 锚点丢失: " + entries);
        assertTrue(entries.stream().anyMatch(e -> e.contains("BasicLinkGadget")),
                "basic_002 锚点丢失");
    }

    @Test
    void depthAnchorsHold(@TempDir Path tmp) throws Exception {
        Path jar = Path.of("benchmark/Gleipner/chains/target/gleipner.chains-1.0-depth.jar");
        Assumptions.assumeTrue(Files.exists(jar), "本地无 Gleipner 基准");
        io.just.sast.cli.ScanPipeline.run(jar, null, tmp.resolve("depth"),
                Path.of("benchmark/Gleipner/just-rules.yaml"), false, true, null, true);
        List<String> entries = Files.readAllLines(tmp.resolve("depth/chains.csv")).stream()
                .skip(1).map(l -> l.split(",")).filter(f -> f.length > 4)
                .map(f -> f[2]).toList();
        long found = entries.stream().filter(e -> e.contains("Depth_0")).distinct().count();
        assertTrue(found >= 15, "depth 锚点数 " + found + " < 15（历史稳定 ≥15，漂移即红）");
    }

    @Test
    void polymorphismAnchorsHold(@TempDir Path tmp) throws Exception {
        Path jar = Path.of("benchmark/Gleipner/chains/target/gleipner.chains-1.0-polymorphism.jar");
        Assumptions.assumeTrue(Files.exists(jar), "本地无 Gleipner 基准");
        io.just.sast.cli.ScanPipeline.run(jar, null, tmp.resolve("poly"),
                Path.of("benchmark/Gleipner/just-rules.yaml"), false, true, null, true);
        List<String> entries = Files.readAllLines(tmp.resolve("poly/chains.csv")).stream()
                .skip(1).map(l -> l.split(",")).filter(f -> f.length > 4)
                .map(f -> f[2]).toList();
        long found = entries.stream().filter(e -> e.contains("Polymorphism_0")).distinct().count();
        assertTrue(found >= 12, "polymorphism 锚点数 " + found + " < 12（历史 ≥12）");
    }
}
