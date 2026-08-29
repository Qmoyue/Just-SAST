package io.just.sast.cpg.build;

import io.just.sast.cpg.graph.Graph;

/** CPG 构建产物。 */
public record BuiltCpg(Graph graph, FieldWriterIndex fieldWriters, CpgIndex index) {

    /** 兼容直接构造 CPG 构建产物的调用方。 */
    public BuiltCpg(Graph graph, FieldWriterIndex fieldWriters) {
        this(graph, fieldWriters, CpgIndex.empty());
    }
}
