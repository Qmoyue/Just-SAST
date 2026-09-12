package io.just.sast.model;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** 前端加载结果。targetMajorVersion 为目标 jar 中 class 文件的最大 major 版本（0=未知）。 */
public record LoadResult(Map<String, ClassInfo> classes, List<ParseDiagnostic> diagnostics,
                         int filesScanned, int targetMajorVersion,
                         List<String> completenessReasons) {

    public LoadResult {
        Map<String, ClassInfo> classCopy = new LinkedHashMap<>();
        if (classes != null) {
            for (Map.Entry<String, ClassInfo> entry : classes.entrySet()) {
                if (entry.getKey() == null || entry.getValue() == null) {
                    throw new IllegalArgumentException("classes must not contain null entries");
                }
                classCopy.put(entry.getKey(), entry.getValue());
            }
        }
        classes = Collections.unmodifiableMap(classCopy);
        diagnostics = diagnostics == null ? List.of() : List.copyOf(diagnostics);
        completenessReasons = completenessReasons == null ? List.of() : List.copyOf(completenessReasons);
        if (filesScanned < 0) {
            throw new IllegalArgumentException("filesScanned must be non-negative");
        }
        if (targetMajorVersion < 0) {
            throw new IllegalArgumentException("targetMajorVersion must be non-negative");
        }
    }

    /** 兼容前端扩展点：没有读取器完整性信息时视为空集合。 */
    public LoadResult(Map<String, ClassInfo> classes, List<ParseDiagnostic> diagnostics,
                      int filesScanned, int targetMajorVersion) {
        this(classes, diagnostics, filesScanned, targetMajorVersion, List.of());
    }

    public int classCount() {
        return classes.size();
    }

    public int diagnosticCount() {
        return diagnostics.size();
    }

    /** Typed immutable boundary consumed by downstream phases. */
    public ProgramUniverse programUniverse() {
        return ProgramUniverse.from(this);
    }
}
