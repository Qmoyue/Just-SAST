package io.just.sast.model;

import java.lang.reflect.Modifier;

/** 字段事实。 */
public record FieldInfo(String owner, String name, String descriptor, int access,
                        Object constantValue, String signature) {

    /** Compatibility constructor for model users that do not carry generic metadata. */
    public FieldInfo(String owner, String name, String descriptor, int access,
                     Object constantValue) {
        this(owner, name, descriptor, access, constantValue, null);
    }

    /** Compatibility constructor for model users that do not carry ConstantValue metadata. */
    public FieldInfo(String owner, String name, String descriptor, int access) {
        this(owner, name, descriptor, access, null);
    }

    public boolean isStatic() {
        return Modifier.isStatic(access);
    }

    /**
     * Return object types appearing inside a generic field signature.  This deliberately
     * parses only the type-argument portion; the erased field type itself is not returned.
     * It is a small model-layer parser so the knowledge phase does not depend on ASM.
     * Wildcards, generic arrays and nested type arguments are handled conservatively.
     */
    public java.util.List<String> genericReferenceTypes() {
        if (signature == null || signature.isBlank()) {
            return java.util.List.of();
        }
        java.util.LinkedHashSet<String> result = new java.util.LinkedHashSet<>();
        int genericDepth = 0;
        for (int i = 0; i < signature.length(); i++) {
            char current = signature.charAt(i);
            if (current == '<') {
                genericDepth++;
                continue;
            }
            if (current == '>') {
                genericDepth = Math.max(0, genericDepth - 1);
                continue;
            }
            if (current != 'L' || genericDepth <= 0) {
                continue;
            }
            int end = i + 1;
            while (end < signature.length() && signature.charAt(end) != ';'
                    && signature.charAt(end) != '<') {
                end++;
            }
            if (end > signature.length()) {
                break;
            }
            String type = signature.substring(i + 1, end);
            if (!type.isBlank()) {
                result.add(type);
            }
            // Keep a nested '<' in the scan so its type arguments are visited as well;
            // an ordinary ';' terminates the current class type.
            if (end < signature.length() && signature.charAt(end) == ';') {
                i = end;
            } else {
                i = Math.max(i, end - 1);
            }
        }
        return java.util.List.copyOf(result);
    }
}
