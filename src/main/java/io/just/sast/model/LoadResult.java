package io.just.sast.model;

import io.just.sast.model.ClassInfo;

import java.util.List;
import java.util.Map;

/** 前端加载结果。targetMajorVersion 为目标 jar 中 class 文件的最大 major 版本（0=未知）。 */
public record LoadResult(Map<String, ClassInfo> classes, List<ParseDiagnostic> diagnostics,
                         int filesScanned, int targetMajorVersion) {

    public int classCount() {
        return classes.size();
    }

    public int diagnosticCount() {
        return diagnostics.size();
    }
}
