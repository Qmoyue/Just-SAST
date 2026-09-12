package io.just.sast.model;

import java.lang.reflect.Modifier;
import java.util.List;

/** 类事实。 */
public record ClassInfo(
        String internalName,
        String superName,
        List<String> interfaces,
        int access,
        List<MethodInfo> methods,
        List<FieldInfo> fields,
        List<String> annotationDescriptors) {

    /** Compatibility constructor for model producers predating annotation retention. */
    public ClassInfo(String internalName, String superName, List<String> interfaces, int access,
                     List<MethodInfo> methods, List<FieldInfo> fields) {
        this(internalName, superName, interfaces, access, methods, fields, List.of());
    }

    public ClassInfo {
        annotationDescriptors = annotationDescriptors == null ? List.of()
                : annotationDescriptors.stream().filter(value -> value != null && !value.isBlank())
                .map(String::trim).distinct().sorted().toList();
    }

    public boolean isInterface() {
        return Modifier.isInterface(access);
    }

    public MethodInfo method(String name, String descriptor) {
        for (MethodInfo m : methods) {
            if (m.name().equals(name) && m.descriptor().equals(descriptor)) {
                return m;
            }
        }
        return null;
    }

    public FieldInfo field(String name) {
        for (FieldInfo f : fields) {
            if (f.name().equals(name)) {
                return f;
            }
        }
        return null;
    }

    /**
     * Java serialization uses this marker to replace the default field set.  The actual
     * ObjectStreamField contents are runtime data, so callers must treat any inference based
     * on this method as an explicitly approximate object-graph edge.
     */
    public boolean hasSerialPersistentFields() {
        return fields.stream().anyMatch(field ->
                "serialPersistentFields".equals(field.name())
                        && field.isStatic()
                        && "[Ljava/io/ObjectStreamField;".equals(field.descriptor()));
    }
}
