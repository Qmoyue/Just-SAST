package io.just.sast.cpg.build;

import io.just.sast.cpg.graph.Graph;
import io.just.sast.cpg.graph.NodeType;
import io.just.sast.model.LoadResult;
import io.just.sast.model.ProgramUniverse;
import io.just.sast.model.ClassInfo;
import io.just.sast.model.FieldRef;
import io.just.sast.model.InsnFact;
import io.just.sast.model.InvokeDynamicRef;
import io.just.sast.model.MethodInfo;
import io.just.sast.model.MethodRef;
import io.just.sast.model.Op;
import io.just.sast.model.TypeRef;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/** CPG 构建：METHOD/CALL 核心节点、字段写入索引和紧凑方法语义切片。 */
public final class CpgBuilder {

    /**
     * A binding API often receives its target class as a Class literal immediately before the
     * invocation (for example Jackson's readValue(String, Class)).  Retain only a small,
     * deterministic local window at the CPG seam; this is a typed hint for entry/site joining,
     * not a claim that arbitrary strings or class names are runtime-controlled.
     */
    private static final int CLASS_LITERAL_HINT_WINDOW = 6;
    /**
     * Keep a bounded string window for configuration calls whose value is supplied as a
     * constant (for example Fastjson's ParserConfig.addAccept).  This is deliberately a
     * frontend fact, just like classLiteralHints; downstream code must treat it as a typed
     * configuration hint and never as proof that an arbitrary runtime string is constant.
     */
    private static final int STRING_LITERAL_HINT_WINDOW = 6;

    public BuiltCpg build(LoadResult load) {
        return build(load == null ? null : load.programUniverse());
    }

    /** Build from the immutable frontend product; ASM must not be visible past this seam. */
    public BuiltCpg build(ProgramUniverse universe) {
        if (universe == null) {
            throw new IllegalArgumentException("program universe must not be null");
        }
        Graph graph = new Graph();
        FieldWriterIndex fieldWriters = new FieldWriterIndex();
        CpgIndex.Builder index = CpgIndex.builder();
        for (ClassInfo cls : universe.classes().values()) {
            for (MethodInfo method : cls.methods()) {
                var methodNode = graph.methodNode(method.owner(), method.name(), method.descriptor(), false);
                // Annotation type descriptors are stable frontend facts used by the
                // application-entry index.  Keep them as immutable metadata at the CPG seam;
                // route values and arbitrary annotation payloads deliberately do not cross it.
                methodNode.propsNote("methodAnnotationDescriptors", method.annotationDescriptors());
                methodNode.propsNote("classAnnotationDescriptors", cls.annotationDescriptors());
                methodNode.propsNote("methodAccess", method.access());
                methodNode.propsNote("classAccess", cls.access());
                methodNode.propsNote("classSuperName", cls.superName() == null ? "" : cls.superName());
                methodNode.propsNote("classInterfaces", cls.interfaces());
                CpgIndex.Builder.MethodSliceBuilder slice = index.start(method);
                for (InsnFact insn : method.instructions()) {
                    slice.accept(insn);
                    Op op = insn.op();
                    if (op.isInvoke()) {
                        addCall(graph, insn, cls.internalName(), method);
                    } else if (op.isFieldWrite()) {
                        FieldRef ref = insn.fieldRef();
                        fieldWriters.add(ref.owner(), ref.name(), ref.descriptor(), cls.internalName(),
                                method.owner(), method.name(), method.descriptor(),
                                insn.offset(), op == Op.PUTSTATIC);
                    } else if (op == Op.AASTORE && insn.offset() >= 3) {
                        // 数组字段写入（窗口近似）：javac 规范形态 [.. GETFIELD f][idx][value][AASTORE]
                        // ——GETFIELD 恰在 AASTORE 前 3 条。c.f[i]=v 的污点经字段粒度回溯（反向引擎）。
                        InsnFact arrayField = method.instructions().get(insn.offset() - 3);
                        if (arrayField.op() == Op.GETFIELD) {
                            FieldRef ref = arrayField.fieldRef();
                            fieldWriters.add(ref.owner(), ref.name(), ref.descriptor(), cls.internalName(),
                                    method.owner(), method.name(), method.descriptor(),
                                    insn.offset(), false);
                        }
                    }
                }
                for (var tryCatch : method.tryCatch()) {
                    slice.accept(tryCatch);
                }
                slice.finish();
            }
        }
        return new BuiltCpg(graph, fieldWriters, index.build());
    }

    private static void addCall(Graph graph, InsnFact insn, String clsName, MethodInfo enclosing) {
        String owner;
        String name;
        String desc;
        String invokeKind;
        Object indy = null;
        if (insn.op() == Op.INVOKEDYNAMIC) {
            InvokeDynamicRef ref = (InvokeDynamicRef) insn.operands().get(0);
            owner = ref.bootstrap().owner();
            name = ref.name();
            desc = ref.descriptor();
            invokeKind = "DYNAMIC";
            indy = ref;
        } else {
            MethodRef ref = insn.methodRef();
            owner = ref.owner();
            name = ref.name();
            desc = ref.descriptor();
            invokeKind = kindOf(insn.op());
        }
        var call = graph.addCallNode(owner, name, desc, invokeKind, indy, insn.offset(),
                enclosing.owner(), enclosing.name(), enclosing.descriptor());
        List<String> classLiteralHints = classLiteralHints(enclosing, insn.offset());
        if (!classLiteralHints.isEmpty()) {
            call.propsNote("classLiteralHints", classLiteralHints);
        }
        List<String> stringLiteralHints = stringLiteralHints(enclosing, insn.offset());
        if (!stringLiteralHints.isEmpty()) {
            call.propsNote("stringLiteralHints", stringLiteralHints);
        }
    }

    private static List<String> classLiteralHints(MethodInfo enclosing, int callOffset) {
        if (enclosing == null || callOffset <= 0) {
            return List.of();
        }
        int start = Math.max(0, callOffset - CLASS_LITERAL_HINT_WINDOW);
        Set<String> hints = new LinkedHashSet<>();
        for (int index = callOffset - 1; index >= start; index--) {
            InsnFact candidate = enclosing.instructions().get(index);
            if (candidate.op() != Op.LDC) {
                continue;
            }
            Object constant = candidate.constant();
            if (!(constant instanceof TypeRef type)) {
                continue;
            }
            String descriptor = type.descriptor();
            if (descriptor == null || descriptor.length() < 3
                    || !descriptor.startsWith("L") || !descriptor.endsWith(";")) {
                continue;
            }
            String internalName = descriptor.substring(1, descriptor.length() - 1);
            if (!internalName.isBlank() && internalName.indexOf('.') < 0) {
                hints.add(internalName);
            }
        }
        return hints.isEmpty() ? List.of() : List.copyOf(hints);
    }

    private static List<String> stringLiteralHints(MethodInfo enclosing, int callOffset) {
        if (enclosing == null || callOffset <= 0) {
            return List.of();
        }
        int start = Math.max(0, callOffset - STRING_LITERAL_HINT_WINDOW);
        Set<String> hints = new LinkedHashSet<>();
        for (int index = callOffset - 1; index >= start; index--) {
            InsnFact candidate = enclosing.instructions().get(index);
            if (candidate.op() != Op.LDC || !(candidate.constant() instanceof String value)) {
                continue;
            }
            if (!value.isBlank() && value.length() <= 512) {
                hints.add(value);
            }
        }
        return hints.isEmpty() ? List.of() : List.copyOf(hints);
    }

    private static String kindOf(Op op) {
        return switch (op) {
            case INVOKESTATIC -> "STATIC";
            case INVOKESPECIAL -> "SPECIAL";
            case INVOKEVIRTUAL -> "VIRTUAL";
            case INVOKEINTERFACE -> "INTERFACE";
            default -> "DYNAMIC";
        };
    }

    public static String methodKey(String owner, String name, String desc) {
        return owner + "#" + name + desc;
    }
}
