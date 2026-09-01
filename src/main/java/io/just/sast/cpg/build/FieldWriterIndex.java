package io.just.sast.cpg.build;

import io.just.sast.cpg.graph.Node;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** 字段写入点索引：(声明 owner, name, descriptor, static) → 写入点。 */
public final class FieldWriterIndex {

    /** 字段写入点。 */
    public record Writer(String ownerClass, String methodOwner, String methodName, String methodDesc,
                         int insnOffset, String fieldDescriptor, boolean isStatic) {}

    private record FieldKey(String owner, String name, String descriptor, boolean isStatic) {}

    private final Map<FieldKey, List<Writer>> writers = new HashMap<>();

    public void add(String fieldOwner, String fieldName, String fieldDescriptor,
                    String ownerClass,
                    String methodOwner, String methodName, String methodDesc,
                    int insnOffset, boolean isStatic) {
        FieldKey key = key(fieldOwner, fieldName, fieldDescriptor, isStatic);
        writers.computeIfAbsent(key, k -> new ArrayList<>(1))
                .add(new Writer(ownerClass, methodOwner, methodName, methodDesc, insnOffset,
                        fieldDescriptor, isStatic));
    }

    /** Compatibility overload for older KnowledgeSource extensions that predate descriptors. */
    public void add(String fieldOwner, String fieldName, String ownerClass,
                    String methodOwner, String methodName, String methodDesc,
                    int insnOffset, boolean isStatic) {
        add(fieldOwner, fieldName, "", ownerClass, methodOwner, methodName, methodDesc,
                insnOffset, isStatic);
    }

    /** Exact field identity lookup; hidden fields and static/instance variants stay separate. */
    public List<Writer> writersOf(String fieldOwner, String fieldName,
                                  String fieldDescriptor, boolean isStatic) {
        if (fieldDescriptor == null || fieldDescriptor.isBlank()) {
            return writersOf(fieldOwner, fieldName);
        }
        List<Writer> list = writers.get(key(fieldOwner, fieldName, fieldDescriptor, isStatic));
        return list == null ? List.of() : sortedCopy(list);
    }

    /** Compatibility view for extensions that only know owner/name; never used by core flow. */
    public List<Writer> writersOf(String fieldOwner, String fieldName) {
        List<Writer> result = new ArrayList<>();
        for (Map.Entry<FieldKey, List<Writer>> entry : writers.entrySet()) {
            FieldKey key = entry.getKey();
            if (key.owner().equals(fieldOwner) && key.name().equals(fieldName)) {
                result.addAll(entry.getValue());
            }
        }
        return sortedCopy(result);
    }

    public int fieldCount() {
        return writers.size();
    }

    private static FieldKey key(String owner, String name, String descriptor, boolean isStatic) {
        return new FieldKey(owner == null ? "" : owner, name == null ? "" : name,
                descriptor == null ? "" : descriptor, isStatic);
    }

    private static List<Writer> sortedCopy(List<Writer> source) {
        List<Writer> result = new ArrayList<>(source);
        result.sort(java.util.Comparator.comparing(Writer::ownerClass)
                .thenComparing(Writer::methodOwner)
                .thenComparing(Writer::methodName)
                .thenComparing(Writer::methodDesc)
                .thenComparingInt(Writer::insnOffset));
        return List.copyOf(result);
    }
}
