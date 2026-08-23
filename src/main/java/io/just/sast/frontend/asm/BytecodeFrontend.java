package io.just.sast.frontend.asm;

import io.just.sast.model.ClassInfo;
import io.just.sast.model.LoadResult;
import io.just.sast.model.ParseDiagnostic;
import io.just.sast.util.JustLogger;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 字节码前端：目标 JAR/目录 → 解析为自研 model。
 * 装载顺序：target → deps → JDK——应用类优先，JDK 类只补缺（同名不遮蔽应用类）。
 * 单类解析失败不中断全扫，记录诊断。
 */
public final class BytecodeFrontend {

    private final JarReader jarReader = new JarReader();
    private final ClassFileReader classFileReader = new ClassFileReader();

    public LoadResult load(List<Path> targets) {
        return load(targets, List.of());
    }

    /** load 的扩展：extraClassBytes 参与解析（如 --jdk 全量 JDK 类，仅填充 target/deps 未覆盖的名字）。 */
    public LoadResult load(List<Path> targets, List<ClassBytes> extraClassBytes) {
        List<ParseDiagnostic> diagnostics = new ArrayList<>();
        Map<String, ClassInfo> classes = new LinkedHashMap<>();
        int files = 0;
        int maxMajor = 0;
        for (Path target : targets) {
            try {
                for (ClassBytes cb : jarReader.read(target)) {
                    files++;
                    try {
                        ClassInfo info = classFileReader.read(cb.bytes());
                        classes.putIfAbsent(info.internalName(), info);
                        maxMajor = Math.max(maxMajor, ClassFileReader.majorOf(cb.bytes()));
                    } catch (Exception e) {
                        diagnostics.add(new ParseDiagnostic(cb.origin(), e.getClass().getSimpleName() + ": " + e.getMessage()));
                    }
                }
            } catch (IOException e) {
                diagnostics.add(new ParseDiagnostic(target.toString(), e.getMessage()));
                JustLogger.error("读取输入失败 {}: {}", target, e.getMessage());
            }
        }
        for (ClassBytes cb : extraClassBytes) {
            files++;
            if (classes.containsKey(cb.className())) {
                continue; // 应用类优先，JDK 类不遮蔽
            }
            try {
                classes.putIfAbsent(cb.className(), classFileReader.read(cb.bytes()));
            } catch (Exception e) {
                diagnostics.add(new ParseDiagnostic(cb.origin(), e.getClass().getSimpleName() + ": " + e.getMessage()));
            }
        }
        return new LoadResult(classes, List.copyOf(diagnostics), files, maxMajor);
    }
}
