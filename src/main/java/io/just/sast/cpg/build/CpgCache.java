package io.just.sast.cpg.build;

import io.just.sast.model.ClassInfo;
import io.just.sast.model.LoadResult;
import io.just.sast.model.ParseDiagnostic;
import io.just.sast.util.JustLogger;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

/**
 * B2: CPG 缓存——LoadResult 序列化到 .just-cpg 文件，同 jar 重扫跳过 ASM 解析。
 * 缓存 key = jar 文件路径 + 大小 + 最后修改时间。
 */
public final class CpgCache {

    private record CacheKey(String path, long size, long mtime) implements Serializable {}

    public static Path cacheFileFor(Path jar) {
        return jar.resolveSibling(jar.getFileName() + ".just-cpg");
    }

    public static LoadResult tryLoad(Path jar) {
        Path cache = cacheFileFor(jar);
        if (!Files.exists(cache)) {
            return null;
        }
        try (ObjectInputStream in = new ObjectInputStream(new BufferedInputStream(Files.newInputStream(cache)))) {
            CacheKey key = (CacheKey) in.readObject();
            if (key.path().equals(jar.toAbsolutePath().toString())
                    && key.size() == Files.size(jar)
                    && key.mtime() == Files.getLastModifiedTime(jar).toMillis()) {
                @SuppressWarnings("unchecked")
                Map<String, ClassInfo> classes = (Map<String, ClassInfo>) in.readObject();
                @SuppressWarnings("unchecked")
                List<ParseDiagnostic> diags = (List<ParseDiagnostic>) in.readObject();
                int files = in.readInt();
                int major = in.readInt();
                JustLogger.info("CPG 缓存命中：{} 个类（跳过 ASM 解析）", classes.size());
                return new LoadResult(classes, diags, files, major);
            }
            return null; // stale
        } catch (Exception e) {
            return null; // 缓存损坏，静默重建
        }
    }

    public static void save(Path jar, LoadResult result) {
        Path cache = cacheFileFor(jar);
        try (ObjectOutputStream out = new ObjectOutputStream(
                new BufferedOutputStream(Files.newOutputStream(cache)))) {
            out.writeObject(new CacheKey(jar.toAbsolutePath().toString(),
                    Files.size(jar), Files.getLastModifiedTime(jar).toMillis()));
            out.writeObject(result.classes());
            out.writeObject(result.diagnostics());
            out.writeInt(result.filesScanned());
            out.writeInt(result.targetMajorVersion());
        } catch (Exception e) {
            JustLogger.debug("CPG 缓存写入失败: {}", e.getMessage());
        }
    }
}
