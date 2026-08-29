package io.just.sast.model;

import java.util.List;
import java.util.Map;

/** 前端加载结果。targetMajorVersion 为目标 jar 中 class 文件的最大 major 版本（0=未知）。 */
public record LoadResult(Map<String, ClassInfo> classes, List<ParseDiagnostic> diagnostics,
                         int filesScanned, int targetMajorVersion,
                         List<String> completenessReasons) {

    public LoadResult {
        completenessReasons = completenessReasons == null ? List.of() : List.copyOf(completenessReasons);
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
}
